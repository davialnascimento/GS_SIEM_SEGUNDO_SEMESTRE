"""
Modulo 3 - Detector de Anomalias
Analisa o conjunto de eventos para identificar padroes de ataque
que so ficam visiveis quando multiplos eventos sao correlacionados.

Desenvolvido por: Maick

Detecta:
- Brute Force: muitas tentativas de login falhas do mesmo IP
- Port Scan: mesmo IP tentando acessar muitas portas distintas
- IPs em Blacklist: IPs conhecidamente maliciosos presentes nos logs
"""

from collections import defaultdict


def _extrair_campo(evento, campo, detalhes_key="detalhes"):
    """Tenta obter um campo do evento diretamente; se ausente, extrai de 'detalhes'."""
    valor = evento.get(campo)
    if not valor:
        for parte in evento.get(detalhes_key, "").split():
            if parte.startswith(f"{campo}="):
                valor = parte.split("=", 1)[1]
                break
    return valor


def detectar_brute_force(eventos, threshold=5):
    """
    Identifica IPs com muitas tentativas de login falhas.
    Agrupa falhas por IP e contabiliza os usuarios tentados.

    Retorna dict: {ip: {"tentativas": N, "usuarios": [...], "severidade": "..."}}
    Apenas IPs com tentativas >= threshold sao incluidos.
    """
    contagem = defaultdict(lambda: {"tentativas": 0, "usuarios": set()})

    for evento in eventos:
        if evento.get("fonte") == "auth" and evento.get("tipo") == "FAIL":
            ip = evento.get("ip")
            contagem[ip]["tentativas"] += 1
            # Extrai usuario do campo direto ou dos detalhes
            usuario = _extrair_campo(evento, "usuario")
            if usuario:
                contagem[ip]["usuarios"].add(usuario)

    resultado = {}
    for ip, dados in contagem.items():
        n = dados["tentativas"]
        if n >= threshold:
            if n > 20:
                severidade = "CRITICA"
            elif n >= 10:
                severidade = "ALTA"
            elif n >= 5:
                severidade = "MEDIA"
            else:
                severidade = "BAIXA"

            resultado[ip] = {
                "tentativas": n,
                "usuarios": list(dados["usuarios"]),
                "severidade": severidade
            }

    return resultado


def detectar_port_scan(eventos, threshold=3):
    """
    Detecta varredura de portas observando bloqueios do firewall.
    Um IP que tenta acessar muitas portas distintas esta fazendo port scan.

    Retorna dict: {ip: {"portas": [...], "quantidade": N, "severidade": "..."}}
    Apenas IPs com portas unicas >= threshold sao incluidos.
    """
    portas_por_ip = defaultdict(set)

    for evento in eventos:
        if evento.get("fonte") == "firewall" and evento.get("tipo") == "BLOCK":
            ip = evento.get("ip")
            # Extrai dport do campo direto ou dos detalhes
            dport = _extrair_campo(evento, "dport")
            if ip and dport:
                portas_por_ip[ip].add(dport)

    resultado = {}
    for ip, portas in portas_por_ip.items():
        quantidade = len(portas)
        if quantidade >= threshold:
            if quantidade > 10:
                severidade = "CRITICA"
            elif quantidade >= 6:
                severidade = "ALTA"
            else:
                severidade = "MEDIA"

            resultado[ip] = {
                "portas": sorted(list(portas)),
                "quantidade": quantidade,
                "severidade": severidade
            }

    return resultado


def verificar_blacklist(eventos, blacklist):
    """
    Cruza os IPs dos logs com uma lista de IPs maliciosos conhecidos.

    Retorna tupla:
        - set de IPs maliciosos encontrados nos logs
        - dict {ip: contagem_de_eventos} para cada IP malicioso
    """
    contagem_por_ip = defaultdict(int)
    for evento in eventos:
        ip = evento.get("ip")
        if ip:
            contagem_por_ip[ip] += 1

    blacklist_set = set(blacklist)
    ips_maliciosos = {ip for ip in contagem_por_ip if ip in blacklist_set}
    contagem_maliciosos = {ip: contagem_por_ip[ip] for ip in ips_maliciosos}

    return ips_maliciosos, contagem_maliciosos


def gerar_resumo_ameacas(brute, scan, blacklist):
    """
    Consolida os achados dos tres detectores em uma lista unificada.
    IPs que aparecem em multiplas deteccoes recebem pontuacao mais alta.

    Retorna lista de dicts ordenada por pontuacao decrescente.
    Cada dict contem: ip, deteccoes, pontuacao, severidade.

    Parametros:
        brute     -- dict retornado por detectar_brute_force
        scan      -- dict retornado por detectar_port_scan
        blacklist -- tupla (set_ips, dict_contagem) retornada por verificar_blacklist,
                     ou set/lista/frozenset de IPs maliciosos
    """
    MAPA_SEVERIDADE = {"CRITICA": 4, "ALTA": 3, "MEDIA": 2, "BAIXA": 1}
    MAPA_INVERSO = {v: k for k, v in MAPA_SEVERIDADE.items()}

    # Normaliza blacklist: aceita tupla de verificar_blacklist ou set/lista direto
    if isinstance(blacklist, tuple):
        blacklist_ips = set(blacklist[0])  # (set_ips, contagem) -> pega o set
    else:
        blacklist_ips = set(blacklist)

    todos_ips = set(brute.keys()) | set(scan.keys()) | blacklist_ips

    resumo = []
    for ip in todos_ips:
        deteccoes = []
        niveis = []

        if ip in brute:
            deteccoes.append("brute_force")
            niveis.append(MAPA_SEVERIDADE[brute[ip]["severidade"]])

        if ip in scan:
            deteccoes.append("port_scan")
            niveis.append(MAPA_SEVERIDADE[scan[ip]["severidade"]])

        if ip in blacklist_ips:
            deteccoes.append("blacklist")
            niveis.append(3)

        pontuacao = sum(niveis)
        quantidade = len(deteccoes)
        nivel_base = max(niveis) if niveis else 1

        if quantidade >= 3:
            nivel_final = 4
        elif quantidade == 2:
            nivel_final = min(nivel_base + 1, 4)
        else:
            nivel_final = nivel_base

        resumo.append({
            "ip": ip,
            "deteccoes": deteccoes,
            "pontuacao": pontuacao,
            "severidade": MAPA_INVERSO[nivel_final]
        })

    resumo.sort(key=lambda x: x["pontuacao"], reverse=True)
    return resumo