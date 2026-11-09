import hashlib
from datetime import datetime, timedelta
from functools import wraps
from secrets import token_urlsafe

import mysql.connector
from flask import Flask, jsonify, request, g
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

VALIDADE_MINUTOS = 30


def get_db():
    return mysql.connector.connect(
        host="", user="", password="", database="")


def hash_token(token:  str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ---------- Autenticação ----------
def token_obrigatorio(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        cabecalho = request.headers.get("Authorization", "")

        # 1) Não enviou token -> 401
        if not cabecalho:
            return jsonify({"erro": "Token não informado"}), 401

        # 2) Formato inválido -> 400
        partes = cabecalho.split()
        if len(partes) != 2 or partes[0].lower() != "bearer":
            return jsonify({"erro": "Token inválido"}), 400
        token = partes[1]

        conexao = get_db()
        try:
            cur = conexao.cursor(dictionary=True)
            cur.execute(
                """SELECT u.id, u.nome, u.nivel_acesso, t.expira_em
                   FROM tokens t JOIN usuarios u ON u.id = t.usuario_id
                   WHERE t.token_hash = %s""",
                (hash_token(token),),
            )
            registro = cur.fetchone()
        finally:
            conexao.close()

        # 3) Existe o formato, mas não bate com nenhum token -> 400 amigável
        if registro is None:
            return jsonify({"erro": "Token incorreto. Faça login novamente."}), 400

        # 4) Expirado -> 400 amigável
        if registro["expira_em"] < datetime.now():
            return jsonify({"erro": "Seu token expirou. Faça login novamente."}), 400

        g.usuario = registro  # disponível dentro da rota
        return f(*args, **kwargs)
    return wrapper


# ---------- Login ----------
@app.route("/api/login", methods=["POST"])
def login():
    dados = request.get_json(silent=True) or {}
    email = dados.get("email")
    senha = dados.get("senha")
    if not email or not senha:
        return jsonify({"erro": "email e senha obrigatórios"}), 400

    conexao = get_db()
    try:
        cur = conexao.cursor(dictionary=True)
        cur.execute("SELECT id, senha_hash FROM usuarios WHERE email = %s", (email,))
        usuario = cur.fetchone()

        # mesma mensagem para email errado e senha errada
        if usuario is None or not check_password_hash(usuario["senha_hash"], senha):
            return jsonify({"erro": "Email ou senha incorretos"}), 401

        # apaga tokens antigos: só existe 1 token válido por usuário
        cur.execute("DELETE FROM tokens WHERE usuario_id = %s", (usuario["id"],))

        token = token_urlsafe(32)
        expira_em = datetime.now() + timedelta(minutes=VALIDADE_MINUTOS)
        cur.execute(
            "INSERT INTO tokens (usuario_id, token_hash, expira_em) VALUES (%s, %s, %s)",
            (usuario["id"], hash_token(token), expira_em),
        )
        conexao.commit()
    finally:
        conexao.close()

    return jsonify({"token": token, "expira_em": expira_em.isoformat()})


# ---------- Rotas protegidas ----------
@app.route("/api/usuarios", methods=["GET"])
@token_obrigatorio
def listar():
    conexao = get_db()
    try:
        cur = conexao.cursor(dictionary=True)
        cur.execute("SELECT id, nome, email, nivel_acesso FROM usuarios")
        return jsonify(cur.fetchall())
    finally:
        conexao.close()


@app.route("/api/usuarios", methods=["POST"])
@token_obrigatorio
def criar():
    dados = request.get_json(silent=True) or {}
    if not all(k in dados for k in ("nome", "email", "senha")):
        return jsonify({"erro": "nome, email e senha obrigatórios"}), 400

    conexao = get_db()
    try:
        cur = conexao.cursor()
        cur.execute(
            "INSERT INTO usuarios (nome, email, senha_hash) VALUES (%s, %s, %s)",
            (dados["nome"], dados["email"], generate_password_hash(dados["senha"])),
        )
        conexao.commit()
    finally:
        conexao.close()
    return jsonify({"mensagem": "usuário criado"}), 201


if __name__ == "__main__":
    app.run(debug=True)