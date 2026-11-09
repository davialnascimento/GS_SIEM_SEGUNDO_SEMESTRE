import ipaddress
import logging
import os
from datetime import datetime
from pathlib import Path

from bson import ObjectId
from bson.errors import InvalidId
from flask import Flask, jsonify, request
from pymongo import MongoClient, DESCENDING
from pymongo.errors import PyMongoError
from werkzeug.exceptions import HTTPException

from auth import token_obrigatorio
import re      # parser/normalização de logs
import regras      # regras estáticas
import detector    # detecção por comportamento
import ml          # scoring de ML

# ---------------------------------------------------------------- config
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024        # 5 MB por requisição
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
LOGS_DIR = Path(os.environ.get("LOGS_DIR", "./logs")).resolve()
MAX_LOTE = 5000

db = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)["siem"]
eventos_col = db["eventos"]
alertas_col = db["alertas"]
ip_info_col = db["ip_info"]        # geolocalização / enriquecimento
ip_score_col = db["ip_scores"]     # score de ML por IP

SEVERIDADES = {"baixa", "media", "alta", "critica"}


# ---------------------------------------------------------------- utilidades
class ErroValidacao(Exception):
    """Erro de entrada do cliente (vira 400)."""


def serializar(doc):
    if doc is None:
        return None
    doc = dict(doc)
    if "_id" in doc:
        doc["_id"] = str(doc["_id"])
    for k, v in doc.items():
        if isinstance(v, datetime):
            doc[k] = v.isoformat()
    return doc


def validar_ip(valor: str) -> str:
    try:
        return str(ipaddress.ip_address(valor))
    except ValueError:
        raise ErroValidacao("IP inválido")


def parse_data(nome: str):
    valor = request.args.get(nome)
    if valor is None:
        return None
    try:
        return datetime.fromisoformat(valor)
    except ValueError:
        raise ErroValidacao(f"'{nome}' deve estar em formato ISO 8601")


def paginacao():
    try:
        pagina = int(request.args.get("pagina", 1))
        por_pagina = int(request.args.get("por_pagina", 20))
    except ValueError:
        raise ErroValidacao("'pagina' e 'por_pagina' devem ser inteiros")
    if pagina < 1 or not 1 <= por_pagina <= 100:
        raise ErroValidacao("'pagina' >= 1 e 'por_pagina' entre 1 e 100")
    return pagina, por_pagina


def object_id(valor: str) -> ObjectId:
    try:
        return ObjectId(valor)
    except (InvalidId, TypeError):
        raise ErroValidacao("ID inválido")


def corpo_json() -> dict:
    dados = request.get_json(silent=True)
    if not isinstance(dados, dict):
        raise ErroValidacao("Corpo deve ser um JSON objeto")
    return dados


# ---------------------------------------------------------------- eventos
@app.get("/api/eventos")
def listar_eventos():
    pagina, por_pagina = paginacao()
    filtro = {}

    if (ip := request.args.get("ip")):
        filtro["ip"] = validar_ip(ip)
    if (tipo := request.args.get("tipo")):
        filtro["tipo"] = tipo
    if (sev := request.args.get("severidade")):
        if sev not in SEVERIDADES:
            raise ErroValidacao(f"severidade deve ser uma de {sorted(SEVERIDADES)}")
        filtro["severidade"] = sev

    desde, ate = parse_data("desde"), parse_data("ate")
    if desde or ate:
        filtro["timestamp"] = {}
        if desde:
            filtro["timestamp"]["$gte"] = desde
        if ate:
            filtro["timestamp"]["$lte"] = ate

    total = eventos_col.count_documents(filtro)
    cursor = (eventos_col.find(filtro)
              .sort("timestamp", DESCENDING)
              .skip((pagina - 1) * por_pagina)
              .limit(por_pagina))

    return jsonify({
        "pagina": pagina,
        "por_pagina": por_pagina,
        "total": total,
        "itens": [serializar(d) for d in cursor],
    })


# ---------------------------------------------------------------- alertas
@app.get("/api/alertas")
def listar_alertas():
    pagina, por_pagina = paginacao()
    filtro = {}
    if (sev := request.args.get("severidade")):
        if sev not in SEVERIDADES:
            raise ErroValidacao(f"severidade deve ser uma de {sorted(SEVERIDADES)}")
        filtro["severidade"] = sev

    total = alertas_col.count_documents(filtro)
    cursor = (alertas_col.find(filtro)
              .sort("criado_em", DESCENDING)
              .skip((pagina - 1) * por_pagina)
              .limit(por_pagina))
    return jsonify({
        "pagina": pagina, "por_pagina": por_pagina, "total": total,
        "itens": [serializar(d) for d in cursor],
    })


@app.get("/api/alertas/<id>")
def obter_alerta(id):
    alerta = alertas_col.find_one({"_id": object_id(id)})
    if alerta is None:
        return jsonify({"erro": "Alerta não encontrado"}), 404
    return jsonify(serializar(alerta))


@app.post("/api/alertas")
@token_obrigatorio
def criar_alerta():
    dados = corpo_json()

    titulo = dados.get("titulo")
    severidade = dados.get("severidade")
    if not isinstance(titulo, str) or not titulo.strip() or len(titulo) > 200:
        raise ErroValidacao("'titulo' obrigatório (até 200 caracteres)")
    if severidade not in SEVERIDADES:
        raise ErroValidacao(f"'severidade' deve ser uma de {sorted(SEVERIDADES)}")

    alerta = {
        "titulo": titulo.strip(),
        "severidade": severidade,
        "descricao": str(dados.get("descricao", ""))[:2000],
        "origem": "manual",
        "criado_em": datetime.now(),
    }
    if dados.get("ip"):
        alerta["ip"] = validar_ip(str(dados["ip"]))

    res = alertas_col.insert_one(alerta)
    return jsonify({"id": str(res.inserted_id)}), 201


# ---------------------------------------------------------------- análise
@app.post("/api/analisar")
@token_obrigatorio
def analisar():
    dados = corpo_json()
    caminho, lote = dados.get("caminho"), dados.get("eventos")

    if (caminho is None) == (lote is None):
        raise ErroValidacao("Envie 'caminho' OU 'eventos', não ambos")

    if caminho is not None:
        if not isinstance(caminho, str):
            raise ErroValidacao("'caminho' deve ser texto")
        arquivo = (LOGS_DIR / caminho).resolve()
        # impede path traversal (../../etc/passwd)
        if not arquivo.is_relative_to(LOGS_DIR):
            raise ErroValidacao("Caminho não permitido")
        if not arquivo.is_file():
            return jsonify({"erro": "Arquivo não encontrado"}), 404
        eventos = re.ler_log(str(arquivo))
    else:
        if not isinstance(lote, list) or not lote:
            raise ErroValidacao("'eventos' deve ser uma lista não vazia")
        if len(lote) > MAX_LOTE:
            raise ErroValidacao(f"Máximo de {MAX_LOTE} eventos por lote")
        if not all(isinstance(e, dict) for e in lote):
            raise ErroValidacao("Cada evento deve ser um objeto")
        eventos = re.normalizar(lote)

    # núcleo -> regras -> detector -> ML
    alertas = list(regras.aplicar(eventos)) + list(detector.detectar(eventos))
    scores = ml.pontuar(eventos)            # esperado: {ip: score}

    agora = datetime.now()
    if eventos:
        eventos_col.insert_many(eventos)
    for a in alertas:
        a.setdefault("criado_em", agora)
        a.setdefault("origem", "automatico")
    if alertas:
        alertas_col.insert_many(alertas)
    for ip, score in scores.items():
        ip_score_col.update_one(
            {"ip": ip}, {"$set": {"score": score, "atualizado_em": agora}}, upsert=True)

    por_sev = {}
    for a in alertas:
        por_sev[a["severidade"]] = por_sev.get(a["severidade"], 0) + 1

    return jsonify({
        "eventos_processados": len(eventos),
        "alertas_gerados": len(alertas),
        "alertas_por_severidade": por_sev,
        "ips_pontuados": len(scores),
    })


# ---------------------------------------------------------------- busca por IP
@app.get("/api/ip/<ip>")
def buscar_ip(ip):
    ip = validar_ip(ip)

    eventos = list(eventos_col.find({"ip": ip}).sort("timestamp", DESCENDING).limit(100))
    alertas = list(alertas_col.find({"ip": ip}).sort("criado_em", DESCENDING).limit(100))
    info = ip_info_col.find_one({"ip": ip}, {"_id": 0})
    score = ip_score_col.find_one({"ip": ip}, {"_id": 0})

    if not (eventos or alertas or info or score):
        return jsonify({"erro": "Nenhum dado para este IP"}), 404

    return jsonify({
        "ip": ip,
        "eventos": [serializar(e) for e in eventos],
        "alertas": [serializar(a) for a in alertas],
        "enriquecimento": serializar(info),
        "score_ml": serializar(score),
    })


# ---------------------------------------------------------------- erros
@app.errorhandler(ErroValidacao)
def erro_validacao(e):
    return jsonify({"erro": str(e)}), 400


@app.errorhandler(PyMongoError)
def erro_banco(e):
    log.exception("Erro no MongoDB")                 # detalhe só no log
    return jsonify({"erro": "Serviço temporariamente indisponível"}), 503


@app.errorhandler(HTTPException)
def erro_http(e):                                    # 404, 405, 413...
    return jsonify({"erro": e.name}), e.code


@app.errorhandler(Exception)
def erro_generico(e):
    log.exception("Erro não tratado")
    return jsonify({"erro": "Erro interno"}), 500


if __name__ == "__main__":
    app.run(debug=False)