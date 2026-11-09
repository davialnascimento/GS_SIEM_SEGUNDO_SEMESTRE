"""Classificação de risco por IP (Módulo C — C2, C3, C4).

Interface para os outros módulos (API, dashboard, LLM):

    from ml.classificar import pontuar
    scores = pontuar(ameacas)
    # {"185.220.101.1": {"score": 0.98, "nivel": "ALTO", "rotulo": "ataque"}, ...}
    # O dict já vem ORDENADO do maior para o menor risco.

`ameacas` é {ip: {features}} — o resumo de ameaças do Módulo A. Aceita os
nomes n_fails / n_portas_distintas / na_blacklist / n_web_erros (ou aliases
como fails, portas, blacklist; listas/sets de portas contam pelo tamanho).
Se tiver só a lista de eventos, use pontuar_eventos(eventos).
"""
import logging

import joblib

from ml.features import FEATURES, extrair_features, normalizar_features
from ml.integridade import (HASH_PATH, MODELO_PATH, IntegridadeError,
                            verificar_integridade)

logger = logging.getLogger(__name__)

LIMIAR_ALTO = 0.70
LIMIAR_MEDIO = 0.40
LIMIAR_ATAQUE = 0.50

_cache = {"modelo": None}


def carregar_modelo(modelo_path=MODELO_PATH, hash_path=HASH_PATH):
    """Carrega o modelo SOMENTE se o SHA-256 conferir (C4).

    Levanta IntegridadeError se o arquivo foi alterado ou o hash não existe.
    Nunca chama joblib.load em um arquivo não verificado.
    """
    if not verificar_integridade(modelo_path, hash_path):
        logger.critical("ALERTA: integridade do modelo NÃO confere (%s).", modelo_path)
        raise IntegridadeError(
            "Modelo ausente, sem hash registrado ou adulterado. "
            "Rode 'python -m ml.treinar' para gerar um modelo confiável.")
    return joblib.load(modelo_path)


def _modelo():
    if _cache["modelo"] is None:
        _cache["modelo"] = carregar_modelo()
    return _cache["modelo"]


def limpar_cache():
    """Descarta o modelo em memória (força nova verificação de hash)."""
    _cache["modelo"] = None


def nivel_de_risco(score):
    if score >= LIMIAR_ALTO:
        return "ALTO"
    if score >= LIMIAR_MEDIO:
        return "MEDIO"
    return "BAIXO"


def pontuar(ameacas, modelo=None):
    """{ip: features} -> {ip: {score, nivel, rotulo}}, ordenado por score desc."""
    if not ameacas:
        return {}
    modelo = modelo if modelo is not None else _modelo()
    ips = list(ameacas)
    X = [normalizar_features(ameacas[ip]) for ip in ips]
    classes = list(modelo.classes_)
    probas = modelo.predict_proba(X)[:, classes.index(1)]

    resultado = {
        ip: {
            "score": round(float(p), 4),
            "nivel": nivel_de_risco(p),
            "rotulo": "ataque" if p >= LIMIAR_ATAQUE else "normal",
        }
        for ip, p in zip(ips, probas)
    }
    return dict(sorted(resultado.items(), key=lambda kv: -kv[1]["score"]))


def pontuar_eventos(eventos, blacklist=None, modelo=None):
    """Atalho: lista de eventos -> extrai features por IP -> pontua."""
    return pontuar(extrair_features(eventos, blacklist), modelo=modelo)


if __name__ == "__main__":
    # Demonstração dos cenários C2, C3 e C4
    logging.basicConfig(level=logging.INFO)
    print("C4 — integridade OK?", verificar_integridade())
    demo = {
        "185.220.101.1": {"n_fails": 10, "n_portas_distintas": 7, "na_blacklist": 1, "n_web_erros": 0},
        "192.168.1.10": {"n_fails": 0, "n_portas_distintas": 1, "na_blacklist": 0, "n_web_erros": 1},
    }
    for ip, r in pontuar(demo).items():
        print(f"{ip:<16} score={r['score']:.2f}  nivel={r['nivel']:<5} rotulo={r['rotulo']}")
