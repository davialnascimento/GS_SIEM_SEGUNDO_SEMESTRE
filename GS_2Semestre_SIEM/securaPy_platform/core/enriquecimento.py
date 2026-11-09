"""
Modulo 5 - Enriquecimento de IPs
Adiciona contexto geografico e organizacional aos IPs suspeitos
consultando a API publica do ipinfo.io.

Desenvolvido por: Caique

Classifica IPs em privados (rede interna) e publicos, consultando
apenas os publicos para economizar requisicoes.
"""

import ipaddress
import requests
from requests.exceptions import Timeout, ConnectionError, HTTPError, RequestException

IPINFO_URL = "https://ipinfo.io/{ip}/json"


def eh_ip_privado(ip):
    """
    Verifica se um endereco IP pertence a uma faixa de rede privada (RFC 1918).
    IPs privados nao precisam ser consultados na API externa.

    Retorna True se privado, False se publico.
    """
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def validar_ip(ip):
    """Verifica se o endereco IP tem formato valido."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def consultar_ip(ip, cache):
    """
    Consulta a API do ipinfo.io para obter dados de geolocalizacao do IP.
    Usa cache para nao repetir consultas ao mesmo IP.

    Retorna dict com: ip, privado, cidade, regiao, pais, org, hostname
    """
    # Se ja consultamos esse IP, retorna do cache sem fazer nova requisicao
    if ip in cache:
        return cache[ip]

    # IPs invalidos retornam dados padrao sem consultar a API
    if not validar_ip(ip):
        return {"ip": ip, "erro": "IP invalido"}

    # IPs privados nao precisam de consulta externa
    if eh_ip_privado(ip):
        resultado = {
            "ip": ip,
            "privado": True,
            "pais": "Rede Interna",
            "cidade": "-",
            "regiao": "-",
            "org": "-",
            "hostname": "-"
        }
        cache[ip] = resultado
        return resultado

    # Consulta a API externa para IPs publicos
    try:
        resposta = requests.get(IPINFO_URL.format(ip=ip), timeout=5)

        # Trata limite de requisicoes da API gratuita
        if resposta.status_code == 429:
            return {"ip": ip, "erro": "Limite de requisicoes excedido (API)"}

        resposta.raise_for_status()
        dados = resposta.json()

        resultado = {
            "ip": ip,
            "privado": False,
            "pais": dados.get("country", "Desconhecido"),
            "cidade": dados.get("city", "Desconhecido"),
            "regiao": dados.get("region", "Desconhecido"),
            "org": dados.get("org", "Desconhecido"),
            "hostname": dados.get("hostname", "-")
        }

        cache[ip] = resultado
        return resultado

    except Timeout:
        return {"ip": ip, "erro": "Timeout na consulta"}
    except ConnectionError:
        return {"ip": ip, "erro": "Sem conexao com a API"}
    except HTTPError as erro:
        return {"ip": ip, "erro": str(erro)}
    except RequestException as erro:
        return {"ip": ip, "erro": str(erro)}


def enriquecer_alertas(alertas, cache):
    """
    Adiciona informacoes de geolocalizacao a cada alerta.
    IPs repetidos usam o cache para evitar consultas duplicadas.

    Retorna os mesmos alertas com campo adicional 'geolocalizacao'.
    """
    # Coleta IPs unicos para minimizar consultas
    ips_unicos = {alerta.get("ip") for alerta in alertas if alerta.get("ip")}

    # Consulta cada IP unico uma vez
    dados_por_ip = {}
    for ip in ips_unicos:
        dados_por_ip[ip] = consultar_ip(ip, cache)

    # Distribui os dados pelos alertas
    alertas_enriquecidos = []
    for alerta in alertas:
        ip = alerta.get("ip")
        if ip:
            alerta_enriquecido = {**alerta, "geolocalizacao": dados_por_ip.get(ip, {})}
            alertas_enriquecidos.append(alerta_enriquecido)

    return alertas_enriquecidos


def exibir_enriquecimento(dados_ip):
    """Exibe as informacoes de um IP de forma legivel no terminal."""
    print("\n===== INFORMACOES DO IP =====")
    privado = dados_ip.get("privado", False)
    print(f"{'IP:':<15} {dados_ip.get('ip', '-')}")
    print(f"{'Tipo:':<15} {'Rede Interna' if privado else 'IP Publico'}")

    if not privado:
        print(f"{'Pais:':<15} {dados_ip.get('pais', '-')}")
        print(f"{'Cidade:':<15} {dados_ip.get('cidade', '-')}")
        print(f"{'Regiao:':<15} {dados_ip.get('regiao', '-')}")
        print(f"{'Organizacao:':<15} {dados_ip.get('org', '-')}")
        print(f"{'Hostname:':<15} {dados_ip.get('hostname', '-')}")

    if "erro" in dados_ip:
        print(f"{'Erro:':<15} {dados_ip['erro']}")

    print("=============================")