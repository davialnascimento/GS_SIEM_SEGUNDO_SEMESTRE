"""Integridade do modelo: SHA-256 do arquivo .pkl (reaproveita hashlib do 1º sem).

Por que isto importa: joblib/pickle EXECUTAM código ao carregar um arquivo.
Um .pkl adulterado pode rodar código malicioso (OWASP A08 — falhas de
integridade de software e dados). Por isso o hash é conferido ANTES do load.
"""
import hashlib
import hmac
from pathlib import Path

PASTA = Path(__file__).resolve().parent
MODELO_PATH = PASTA / "modelo.pkl"
HASH_PATH = PASTA / "modelo.pkl.sha256"
METRICAS_PATH = PASTA / "relatorio_metricas.txt"


class IntegridadeError(Exception):
    """O modelo não confere com o hash registrado (ou o hash não existe)."""


def calcular_sha256(caminho):
    """SHA-256 do arquivo, lido em blocos (funciona com arquivos grandes)."""
    h = hashlib.sha256()
    with open(caminho, "rb") as f:
        for bloco in iter(lambda: f.read(8192), b""):
            h.update(bloco)
    return h.hexdigest()


def registrar_hash(modelo_path=MODELO_PATH, hash_path=HASH_PATH):
    """Calcula e grava o hash do modelo. Devolve o hash."""
    digest = calcular_sha256(modelo_path)
    Path(hash_path).write_text(digest + "\n", encoding="utf-8")
    return digest


def verificar_integridade(modelo_path=MODELO_PATH, hash_path=HASH_PATH):
    """True se o hash do arquivo confere com o registrado; False caso contrário."""
    modelo_path, hash_path = Path(modelo_path), Path(hash_path)
    if not modelo_path.exists() or not hash_path.exists():
        return False
    esperado = hash_path.read_text(encoding="utf-8").strip()
    atual = calcular_sha256(modelo_path)
    return hmac.compare_digest(esperado, atual)
