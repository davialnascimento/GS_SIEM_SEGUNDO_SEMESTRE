"""
Repositorio MongoDB - eventos e alertas (Modulo B).

Configuracao por variaveis de ambiente (nunca no codigo):
    MONGO_URI  (padrao: mongodb://localhost:27017)
    MONGO_DB   (padrao: securapy)

Dentro do docker-compose, use MONGO_URI=mongodb://mongo:27017
(o host e o NOME DO SERVICO, nao localhost).
"""

import functools
import ipaddress
import logging
import os
from datetime import datetime

from bson import ObjectId
from bson.errors import InvalidId
from pymongo import ASCENDING, DESCENDING, MongoClient
from pymongo.errors import PyMongoError

log = logging.getLogger(__name__)

FORMATO_TS = "%Y-%m-%d %H:%M:%S"
TAMANHO_MAX = 100


class RepositorioErro(Exception):
    """Falha de banco. A mensagem e segura para exibir ao cliente da API."""


_client = None


def _get_db():
    global _client
    if _client is None:
        uri = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
        _client = MongoClient(uri, serverSelectionTimeoutMS=3000)
    return _client[os.environ.get("MONGO_DB", "securapy")]


def _protegido(func):
    """Converte erros do PyMongo em RepositorioErro, sem vazar detalhes."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except PyMongoError as erro:
            log.error("Erro MongoDB em %s: %s", func.__name__, erro)
            raise RepositorioErro("Falha ao acessar o banco de dados.") from erro
    return wrapper


# ---------------------------------------------------------------- helpers

def _para_datetime(valor):
    if isinstance(valor, datetime):
        return valor
    if isinstance(valor, str):
        try:
            return datetime.strptime(valor, FORMATO_TS)
        except ValueError:
            return datetime.fromisoformat(valor)  # ValueError se invalido
    raise ValueError("Data invalida.")


def _normalizar(doc):
    """Copia o documento e converte timestamp (str) para datetime."""
    novo = dict(doc)
    try:
        novo["timestamp"] = _para_datetime(novo.get("timestamp"))
    except ValueError:
        log.warning("Timestamp invalido, gravado como None: %s", doc.get("timestamp"))
        novo["timestamp"] = None
    if isinstance(novo.get("severidade"), str):
        novo["severidade"] = novo["severidade"].strip().upper()
    return novo


def _serializar(doc):
    """Documento Mongo -> dict pronto para JSON (API/dashboard)."""
    saida = dict(doc)
    if "_id" in saida:
        saida["_id"] = str(saida["_id"])
    if isinstance(saida.get("timestamp"), datetime):
        saida["timestamp"] = saida["timestamp"].strftime(FORMATO_TS)
    return saida


def validar_ip(ip):
    """Levanta ValueError se o IP for malformado (API deve responder 400)."""
    try:
        return str(ipaddress.ip_address(str(ip).strip()))
    except ValueError:
        raise ValueError("IP invalido.")


def _montar_filtro(fonte=None, tipo=None, ip=None, inicio=None, fim=None,
                   severidade=None):
    filtro = {}
    if fonte:
        filtro["fonte"] = str(fonte)
    if tipo:
        filtro["tipo"] = str(tipo)
    if ip:
        filtro["ip"] = validar_ip(ip)
    if severidade:
        filtro["severidade"] = str(severidade).strip().upper()
    if inicio or fim:
        periodo = {}
        if inicio:
            periodo["$gte"] = _para_datetime(inicio)
        if fim:
            periodo["$lte"] = _para_datetime(fim)
        filtro["timestamp"] = periodo
    return filtro


def _paginar(colecao, filtro, pagina, tamanho, ordem):
    try:
        pagina, tamanho = int(pagina), int(tamanho)
    except (TypeError, ValueError):
        raise ValueError("Paginacao invalida.")
    if pagina < 1 or not 1 <= tamanho <= TAMANHO_MAX:
        raise ValueError("Paginacao invalida.")
    total = colecao.count_documents(filtro)
    cursor = (colecao.find(filtro).sort(ordem)
              .skip((pagina - 1) * tamanho).limit(tamanho))
    return {
        "itens": [_serializar(d) for d in cursor],
        "total": total,
        "pagina": pagina,
        "tamanho": tamanho,
    }


# ---------------------------------------------------------------- escrita

@_protegido
def criar_indices():
    db = _get_db()
    db.eventos.create_index([("ip", ASCENDING)])
    db.eventos.create_index([("timestamp", ASCENDING)])
    db.alertas.create_index([("ip", ASCENDING)])
    db.alertas.create_index([("timestamp", ASCENDING)])
    db.alertas.create_index([("severidade", ASCENDING)])


@_protegido
def salvar_eventos(eventos, substituir=False):
    """Grava eventos. substituir=True limpa a colecao antes (ingestao idempotente)."""
    db = _get_db()
    if substituir:
        db.eventos.delete_many({})
    docs = [_normalizar(e) for e in eventos]
    if not docs:
        return 0
    return len(db.eventos.insert_many(docs).inserted_ids)


@_protegido
def salvar_alertas(alertas, substituir=False):
    db = _get_db()
    if substituir:
        db.alertas.delete_many({})
    docs = [_normalizar(a) for a in alertas]
    if not docs:
        return 0
    return len(db.alertas.insert_many(docs).inserted_ids)


@_protegido
def salvar_alerta(alerta):
    """Grava um unico alerta e retorna o id (str). Usado por POST /api/alertas."""
    resultado = _get_db().alertas.insert_one(_normalizar(alerta))
    return str(resultado.inserted_id)


# ---------------------------------------------------------------- leitura

@_protegido
def buscar_eventos(fonte=None, tipo=None, ip=None, inicio=None, fim=None,
                   pagina=1, tamanho=20):
    filtro = _montar_filtro(fonte, tipo, ip, inicio, fim)
    return _paginar(_get_db().eventos, filtro, pagina, tamanho,
                    [("timestamp", DESCENDING)])


@_protegido
def buscar_alertas(severidade=None, ip=None, inicio=None, fim=None,
                   pagina=1, tamanho=20):
    filtro = _montar_filtro(ip=ip, inicio=inicio, fim=fim, severidade=severidade)
    return _paginar(_get_db().alertas, filtro, pagina, tamanho,
                    [("timestamp", DESCENDING)])


@_protegido
def buscar_alerta_por_id(alerta_id):
    """Retorna o alerta ou None. ValueError se o id for malformado (-> 400)."""
    try:
        oid = ObjectId(alerta_id)
    except (InvalidId, TypeError):
        raise ValueError("Id invalido.")
    doc = _get_db().alertas.find_one({"_id": oid})
    return _serializar(doc) if doc else None


@_protegido
def eventos_do_ip(ip):
    ip = validar_ip(ip)
    cursor = _get_db().eventos.find({"ip": ip}).sort("timestamp", ASCENDING)
    return [_serializar(d) for d in cursor]


@_protegido
def alertas_do_ip(ip):
    ip = validar_ip(ip)
    cursor = _get_db().alertas.find({"ip": ip}).sort("timestamp", ASCENDING)
    return [_serializar(d) for d in cursor]


# ------------------------------------------------------------- agregacoes

@_protegido
def top_ips(n=5):
    """[{'ip': ..., 'total': N}, ...] ordenado por quantidade de eventos."""
    pipeline = [
        {"$group": {"_id": "$ip", "total": {"$sum": 1}}},
        {"$sort": {"total": -1, "_id": 1}},
        {"$limit": int(n)},
        {"$project": {"_id": 0, "ip": "$_id", "total": 1}},
    ]
    return list(_get_db().eventos.aggregate(pipeline))


@_protegido
def contagem_por_severidade():
    pipeline = [{"$group": {"_id": "$severidade", "total": {"$sum": 1}}}]
    return {d["_id"]: d["total"] for d in _get_db().alertas.aggregate(pipeline)}


@_protegido
def contagem_por_fonte():
    pipeline = [{"$group": {"_id": "$fonte", "total": {"$sum": 1}}}]
    return {d["_id"]: d["total"] for d in _get_db().eventos.aggregate(pipeline)}