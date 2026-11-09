"""
Modulo 1 - Coletor de Logs
Responsavel por ler arquivos de log de diferentes fontes (auth, firewall, web),
parsear cada linha e normalizar os eventos em um formato padronizado de dicionario.

Desenvolvido por: Maick

Formato padronizado de evento:
{
    "timestamp": "2025-02-20 08:15:01",
    "fonte": "auth",
    "tipo": "FAIL",
    "ip": "185.220.101.1",
    "detalhes": "usuario=admin",
    "linha_original": "..."
}
"""

import os


def parsear_linha_auth(linha):
    """Extrai campos de logs de autenticacao (usuario, ip, tipo)."""
    try:
        partes = linha.strip().split()
        if len(partes) < 5:
            return None

        timestamp = f"{partes[0]} {partes[1]}"
        tipo = partes[2]
        usuario = ""
        ip = ""

        # Percorre as partes buscando chave=valor
        for parte in partes[3:]:
            if parte.startswith("usuario="):
                usuario = parte.split("=", 1)[1]
            elif parte.startswith("ip="):
                ip = parte.split("=", 1)[1]

        if not ip or not tipo:
            return None

        return {
            "timestamp": timestamp,
            "fonte": "auth",
            "tipo": tipo,
            "ip": ip,
            "usuario": usuario,
            "detalhes": f"usuario={usuario}",
            "linha_original": linha.strip()
        }
    except Exception:
        return None


def parsear_linha_firewall(linha):
    """Extrai campos de logs de firewall (proto, src, dport)."""
    try:
        partes = linha.strip().split()
        if len(partes) < 6:
            return None

        timestamp = f"{partes[0]} {partes[1]}"
        tipo = partes[2]
        proto = ""
        src = ""
        dst = ""
        dport = ""

        for parte in partes[3:]:
            if parte.startswith("proto="):
                proto = parte.split("=", 1)[1]
            elif parte.startswith("src="):
                src = parte.split("=", 1)[1]
            elif parte.startswith("dst="):
                dst = parte.split("=", 1)[1]
            elif parte.startswith("dport="):
                dport = parte.split("=", 1)[1]

        if not src:
            return None

        return {
            "timestamp": timestamp,
            "fonte": "firewall",
            "tipo": tipo,
            "ip": src,
            "dport": dport,
            "detalhes": f"proto={proto} dst={dst} dport={dport}",
            "linha_original": linha.strip()
        }
    except Exception:
        return None


def parsear_linha_web(linha):
    """Extrai campos de logs de acesso web (metodo, url, ip, status)."""
    try:
        partes = linha.strip().split()
        if len(partes) < 6:
            return None

        timestamp = f"{partes[0]} {partes[1]}"
        metodo = partes[2]
        url = ""
        ip = ""
        status = ""

        for parte in partes[3:]:
            if parte.startswith("url="):
                url = parte.split("=", 1)[1]
            elif parte.startswith("ip="):
                ip = parte.split("=", 1)[1]
            elif parte.startswith("status="):
                status = parte.split("=", 1)[1]

        if not ip:
            return None

        return {
            "timestamp": timestamp,
            "fonte": "web",
            "tipo": metodo,
            "ip": ip,
            "url": url,
            "status": status,
            "detalhes": f"url={url} status={status}",
            "linha_original": linha.strip()
        }
    except Exception:
        return None


def carregar_log(caminho_arquivo, fonte):
    """
    Le um arquivo de log e retorna lista de eventos normalizados.
    Trata erros de arquivo inexistente, linhas malformadas e arquivo vazio.
    """
    eventos = []

    # Dicionario de parsers para facilitar a escolha por fonte
    parsers = {
        "auth": parsear_linha_auth,
        "firewall": parsear_linha_firewall,
        "web": parsear_linha_web
    }

    parser = parsers.get(fonte)
    if not parser:
        print(f"[AVISO] Fonte desconhecida: '{fonte}'")
        return eventos

    try:
        with open(caminho_arquivo, "r", encoding="utf-8") as arquivo:
            linhas = arquivo.readlines()

        if not linhas:
            print(f"[INFO] Arquivo vazio: {caminho_arquivo}")
            return []

        for numero, linha in enumerate(linhas, start=1):
            linha_limpa = linha.strip()

            # Ignora linhas em branco silenciosamente
            if not linha_limpa:
                continue

            evento = parser(linha_limpa)
            if evento:
                eventos.append(evento)
            else:
                print(f"[AVISO] Linha {numero} com formato invalido em '{caminho_arquivo}': {linha_limpa}")

    except FileNotFoundError:
        print(f"[ERRO] Arquivo nao encontrado: '{caminho_arquivo}'")
    except Exception as erro:
        print(f"[ERRO] Falha ao ler '{caminho_arquivo}': {erro}")

    return eventos


def carregar_todos_os_logs(pasta_logs):
    """
    Varre a pasta de logs e unifica os eventos de todos os arquivos conhecidos.
    Retorna lista com todos os eventos das 3 fontes.
    """
    todos_eventos = []

    # Mapeia nome do arquivo para sua fonte correspondente
    mapa_fontes = {
        "auth.log": "auth",
        "firewall.log": "firewall",
        "web_access.log": "web"
    }

    try:
        if not os.path.exists(pasta_logs):
            print(f"[ERRO] Pasta de logs nao encontrada: '{pasta_logs}'")
            return []

        arquivos = os.listdir(pasta_logs)

        for nome in sorted(arquivos):
            fonte = mapa_fontes.get(nome)
            if fonte:
                caminho = os.path.join(pasta_logs, nome)
                eventos = carregar_log(caminho, fonte)
                todos_eventos.extend(eventos)
                print(f"[OK] {len(eventos)} evento(s) carregado(s) de '{nome}'")

    except Exception as erro:
        print(f"[ERRO] Falha ao acessar pasta '{pasta_logs}': {erro}")

    return todos_eventos