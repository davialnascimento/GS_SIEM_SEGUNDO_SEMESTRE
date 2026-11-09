"""
Repositorio MySQL - usuarios e permissoes (Modulo B).

Configuracao por variaveis de ambiente:
    MYSQL_HOST (padrao localhost; no compose use o nome do servico, ex: mysql)
    MYSQL_PORT (padrao 3306)
    MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE (padrao securapy)

TODAS as queries usam parametros (%s). Nunca concatene entrada do usuario no SQL.
"""

import logging
import os
import re
from contextlib import contextmanager

import mysql.connector
from mysql.connector import Error, errorcode
from werkzeug.security import check_password_hash, generate_password_hash

log = logging.getLogger(__name__)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
CAMPOS_PUBLICOS = "id, nome, email, nivel_acesso, criado_em"


class UsuarioErro(Exception):
    """Base. Mensagens seguras para exibir ao cliente."""


class EmailDuplicado(UsuarioErro):
    pass


class DadosInvalidos(UsuarioErro):
    pass


class BancoIndisponivel(UsuarioErro):
    pass


# Hash descartavel: autenticar() sempre faz uma verificacao de senha, mesmo
# com usuario inexistente (tempo de resposta parecido, anti-enumeracao).
_HASH_FALSO = generate_password_hash("senha-inexistente")


@contextmanager
def _cursor(commit=False):
    try:
        conexao = mysql.connector.connect(
            host=os.environ.get("MYSQL_HOST", "localhost"),
            port=int(os.environ.get("MYSQL_PORT", "3306")),
            user=os.environ.get("MYSQL_USER", "root"),
            password=os.environ.get("MYSQL_PASSWORD", ""),
            database=os.environ.get("MYSQL_DATABASE", "securapy"),
            connection_timeout=5,
        )
    except Error as erro:
        log.error("Falha ao conectar no MySQL: %s", erro)
        raise BancoIndisponivel("Banco de usuarios indisponivel.") from erro
    try:
        cursor = conexao.cursor(dictionary=True)
        yield cursor
        if commit:
            conexao.commit()
    finally:
        conexao.close()


def _validar(nome=None, email=None, senha=None, nivel=None):
    if nome is not None and not (1 <= len(str(nome).strip()) <= 100):
        raise DadosInvalidos("Nome invalido.")
    if email is not None and not EMAIL_RE.match(str(email).strip()):
        raise DadosInvalidos("Email invalido.")
    if senha is not None and len(str(senha)) < 8:
        raise DadosInvalidos("A senha deve ter ao menos 8 caracteres.")
    if nivel is not None:
        if isinstance(nivel, bool) or not isinstance(nivel, int) or not 1 <= nivel <= 5:
            raise DadosInvalidos("Nivel de acesso deve ser um inteiro de 1 a 5.")


def inicializar_banco():
    sql = """
        CREATE TABLE IF NOT EXISTS usuarios (
            id INT AUTO_INCREMENT PRIMARY KEY,
            nome VARCHAR(100) NOT NULL,
            email VARCHAR(255) NOT NULL UNIQUE,
            senha_hash VARCHAR(255) NOT NULL,
            nivel_acesso TINYINT NOT NULL,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT chk_nivel CHECK (nivel_acesso BETWEEN 1 AND 5)
        )
    """
    try:
        with _cursor(commit=True) as cur:
            cur.execute(sql)
    except Error as erro:
        log.error("Erro ao criar tabela: %s", erro)
        raise BancoIndisponivel("Banco de usuarios indisponivel.") from erro


def criar_usuario(nome, email, senha, nivel_acesso=1):
    _validar(nome, email, senha, nivel_acesso)
    senha_hash = generate_password_hash(senha)
    try:
        with _cursor(commit=True) as cur:
            cur.execute(
                "INSERT INTO usuarios (nome, email, senha_hash, nivel_acesso) "
                "VALUES (%s, %s, %s, %s)",
                (nome.strip(), email.strip().lower(), senha_hash, nivel_acesso),
            )
            return cur.lastrowid
    except Error as erro:
        if erro.errno == errorcode.ER_DUP_ENTRY:
            raise EmailDuplicado("Email ja cadastrado.") from erro
        log.error("Erro ao criar usuario: %s", erro)
        raise BancoIndisponivel("Erro ao acessar o banco de usuarios.") from erro


def buscar_usuario_por_id(usuario_id):
    try:
        with _cursor() as cur:
            cur.execute(f"SELECT {CAMPOS_PUBLICOS} FROM usuarios WHERE id = %s",
                        (usuario_id,))
            return cur.fetchone()
    except Error as erro:
        log.error("Erro ao buscar usuario: %s", erro)
        raise BancoIndisponivel("Erro ao acessar o banco de usuarios.") from erro


def buscar_usuario_por_email(email):
    try:
        with _cursor() as cur:
            cur.execute(f"SELECT {CAMPOS_PUBLICOS} FROM usuarios WHERE email = %s",
                        (str(email).strip().lower(),))
            return cur.fetchone()
    except Error as erro:
        log.error("Erro ao buscar usuario: %s", erro)
        raise BancoIndisponivel("Erro ao acessar o banco de usuarios.") from erro


def listar_usuarios():
    try:
        with _cursor() as cur:
            cur.execute(f"SELECT {CAMPOS_PUBLICOS} FROM usuarios ORDER BY id")
            return cur.fetchall()
    except Error as erro:
        log.error("Erro ao listar usuarios: %s", erro)
        raise BancoIndisponivel("Erro ao acessar o banco de usuarios.") from erro


def atualizar_usuario(usuario_id, nome=None, nivel_acesso=None):
    """Atualiza nome e/ou nivel. Retorna True se alguma linha mudou."""
    _validar(nome=nome, nivel=nivel_acesso)
    # Os nomes das colunas abaixo sao fixos no codigo; so os VALORES vem do usuario.
    sets, valores = [], []
    if nome is not None:
        sets.append("nome = %s")
        valores.append(nome.strip())
    if nivel_acesso is not None:
        sets.append("nivel_acesso = %s")
        valores.append(nivel_acesso)
    if not sets:
        raise DadosInvalidos("Nada para atualizar.")
    valores.append(usuario_id)
    try:
        with _cursor(commit=True) as cur:
            cur.execute(f"UPDATE usuarios SET {', '.join(sets)} WHERE id = %s",
                        tuple(valores))
            return cur.rowcount > 0
    except Error as erro:
        log.error("Erro ao atualizar usuario: %s", erro)
        raise BancoIndisponivel("Erro ao acessar o banco de usuarios.") from erro


def deletar_usuario(usuario_id):
    try:
        with _cursor(commit=True) as cur:
            cur.execute("DELETE FROM usuarios WHERE id = %s", (usuario_id,))
            return cur.rowcount > 0
    except Error as erro:
        log.error("Erro ao deletar usuario: %s", erro)
        raise BancoIndisponivel("Erro ao acessar o banco de usuarios.") from erro


def autenticar(email, senha):
    """
    Retorna o usuario (sem hash) se as credenciais forem validas, senao None.
    Mesmo retorno para 'usuario inexistente' e 'senha errada' (anti-enumeracao).
    """
    try:
        with _cursor() as cur:
            cur.execute(
                "SELECT id, nome, email, nivel_acesso, senha_hash "
                "FROM usuarios WHERE email = %s",
                (str(email).strip().lower(),),
            )
            linha = cur.fetchone()
    except Error as erro:
        log.error("Erro na autenticacao: %s", erro)
        raise BancoIndisponivel("Erro ao acessar o banco de usuarios.") from erro

    hash_alvo = linha["senha_hash"] if linha else _HASH_FALSO
    senha_ok = check_password_hash(hash_alvo, str(senha))
    if not linha or not senha_ok:
        return None
    linha.pop("senha_hash")
    return linha