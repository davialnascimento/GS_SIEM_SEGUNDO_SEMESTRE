"""Extração de features por IP.

Este arquivo é compartilhado por treinar.py e classificar.py, para que o
treino e a classificação usem EXATAMENTE as mesmas features, na mesma ordem.

Features (uma linha por IP):
    n_fails             nº de falhas de login (auth.log)
    n_portas_distintas  nº de portas distintas tentadas (firewall.log)
    na_blacklist        1 se o IP está na blacklist, 0 caso contrário
    n_web_erros         nº de requisições web com status >= 400 (web_access.log)
"""
from collections import defaultdict

FEATURES = ["n_fails", "n_portas_distintas", "na_blacklist", "n_web_erros"]

# AJUSTE: use a mesma blacklist do núcleo (Módulo A) se ela for diferente.
BLACKLIST_PADRAO = {"185.220.101.1", "91.240.118.172", "45.33.32.156"}

# Nomes alternativos aceitos para cada feature. Isso permite que pontuar()
# receba o resumo de ameaças do Módulo A sem exigir um formato rígido.
ALIASES = {
    "n_fails": ("n_fails", "fails", "falhas", "tentativas_falhas", "total_fails"),
    "n_portas_distintas": ("n_portas_distintas", "portas_distintas", "portas", "n_portas"),
    "na_blacklist": ("na_blacklist", "blacklist", "em_blacklist"),
    "n_web_erros": ("n_web_erros", "web_erros", "erros_web"),
}


def _primeiro(dados, nomes, padrao=None):
    """Devolve o valor da primeira chave existente em `nomes`."""
    for nome in nomes:
        if nome in dados and dados[nome] is not None:
            return dados[nome]
    return padrao


def _como_numero(valor):
    """Converte bool, str, lista/set (usa o tamanho) ou número em float."""
    if isinstance(valor, (list, set, tuple, dict)):
        return float(len(valor))
    if isinstance(valor, bool):
        return float(valor)
    if isinstance(valor, str):
        return 1.0 if valor.strip().lower() in ("true", "sim", "yes", "1") else _tentar_float(valor)
    return _tentar_float(valor)


def _tentar_float(valor):
    try:
        return float(valor)
    except (TypeError, ValueError):
        return 0.0


def normalizar_features(dados):
    """Dict de um IP (com qualquer alias aceito) -> lista na ordem de FEATURES."""
    return [_como_numero(_primeiro(dados, ALIASES[f], 0)) for f in FEATURES]


def extrair_features(eventos, blacklist=None):
    """Converte a lista de eventos (Módulo A) em {ip: {feature: valor}}.

    Os campos do evento são lidos de forma tolerante (ip/ip_origem/src_ip,
    fonte, porta, status...). Eventos sem IP são ignorados, e um evento
    malformado nunca derruba a extração.
    """
    blacklist = BLACKLIST_PADRAO if blacklist is None else set(blacklist)
    fails = defaultdict(int)
    portas = defaultdict(set)
    erros_web = defaultdict(int)
    ips = set()

    for ev in eventos:
        if not isinstance(ev, dict):
            continue
        ip = _primeiro(ev, ("ip", "ip_origem", "src_ip", "source_ip", "origem"))
        if not ip:
            continue
        ip = str(ip)
        ips.add(ip)
        fonte = str(_primeiro(ev, ("fonte", "source"), "")).lower()
        texto = " ".join(str(v) for v in ev.values()).upper()

        if "FAIL" in texto or "FALHA" in texto:
            fails[ip] += 1

        porta = _primeiro(ev, ("porta", "dport", "dst_port", "porta_destino"))
        if porta is not None and ("firewall" in fonte or not fonte):
            portas[ip].add(str(porta))

        if "web" in fonte:
            status = _tentar_float(_primeiro(ev, ("status", "codigo", "status_code"), 0))
            if status >= 400:
                erros_web[ip] += 1

    return {
        ip: {
            "n_fails": fails[ip],
            "n_portas_distintas": len(portas[ip]),
            "na_blacklist": int(ip in blacklist),
            "n_web_erros": erros_web[ip],
        }
        for ip in ips
    }
