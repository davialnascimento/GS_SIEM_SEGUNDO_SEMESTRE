"""
Modulo 2 - Motor de Regras
Carrega regras de um arquivo JSON e avalia cada evento,
gerando alertas quando uma regra e violada.

Desenvolvido por: Amanda

Niveis de severidade:
    >= 9: CRITICA
    >= 7: ALTA
    >= 5: MEDIA
    >= 3: BAIXA
     < 3: INFO
"""

import json


def carregar_regras(caminho_config):
    """
    Le o arquivo regras.json e retorna apenas as regras ativas
    Trata erros de arquivo inexistente e JSON malformado
    """
    try:
        with open(caminho_config, "r", encoding="utf-8") as arquivo:
            dados = json.load(arquivo)

        # Suporta tanto {"regras": [...]} quanto lista direta [...]
        if isinstance(dados, dict):
            regras = dados.get("regras", [])
        else:
            regras = dados

        # Filtra apenas regras com "ativa": true
        regras_ativas = [r for r in regras if r.get("ativa", False)]
        print(f"[REGRAS] {len(regras_ativas)} regra(s) ativa(s) carregada(s).")
        return regras_ativas

    except FileNotFoundError:
        print(f"[ERRO] Arquivo de regras nao encontrado: {caminho_config}")
        return []
    except json.JSONDecodeError as erro:
        print(f"[ERRO] JSON invalido em '{caminho_config}': {erro}")
        return []


def classificar_severidade(pontuacao):
    """
    Converte uma pontuacao numerica em nivel de severidade textual
    """
    if pontuacao >= 9:
        return "CRITICA"
    elif pontuacao >= 7:
        return "ALTA"
    elif pontuacao >= 5:
        return "MEDIA"
    elif pontuacao >= 3:
        return "BAIXA"
    else:
        return "INFO"


def avaliar_regra(regra, evento):
    """
    Avalia se um evento viola uma regra especifica
    Retorna um dicionario de alerta se violou, ou None caso contrario
    """
    # A fonte do evento precisa bater com a fonte da regra
    if evento.get("fonte") != regra.get("fonte"):
        return None

    condicao = regra.get("condicao")
    detalhes = evento.get("detalhes", "")
    url = ""

    # R001 - Login com usuario privilegiado
    if condicao == "usuario_privilegiado":
        usuario = ""
        for parte in detalhes.split():
            if parte.startswith("usuario="):
                usuario = parte.split("=", 1)[1]
                break
        if usuario not in regra.get("usuarios_alvo", []):
            return None
        descricao = f"Tentativa de login com usuario privilegiado: {usuario}"

    # R002 - Acesso a porta critica bloqueado
    elif condicao == "porta_critica":
        if evento.get("tipo") != "BLOCK":
            return None
        porta = None
        for parte in detalhes.split():
            if parte.startswith("dport="):
                try:
                    porta = int(parte.split("=", 1)[1])
                except ValueError:
                    return None
                break
        if porta is None or porta not in regra.get("portas_criticas", []):
            return None
        descricao = f"Acesso bloqueado na porta critica {porta}"

    # R003 - Tentativa de Path Traversal
    elif condicao == "path_traversal":
        for parte in detalhes.split():
            if parte.startswith("url="):
                url = parte.split("=", 1)[1]
                break
        if not any(padrao in url for padrao in regra.get("padroes", [])):
            return None
        descricao = f"Tentativa de path traversal detectada: {url}"

    # R004 - Tentativa de XSS
    elif condicao == "xss":
        for parte in detalhes.split():
            if parte.startswith("url="):
                url = parte.split("=", 1)[1]
                break
        if not any(padrao in url for padrao in regra.get("padroes", [])):
            return None
        descricao = f"Tentativa de XSS detectada na URL: {url}"

    # R005 - Reconhecimento Web
    elif condicao == "reconhecimento":
        for parte in detalhes.split():
            if parte.startswith("url="):
                url = parte.split("=", 1)[1]
                break
        urls_suspeitas = regra.get("urls_suspeitas", [])
        if not any(suspeita in url for suspeita in urls_suspeitas):
            return None
        descricao = f"Acesso a URL de reconhecimento: {url}"

    else:
        return None  # Condicao desconhecida, ignora

    severidade = classificar_severidade(regra.get("severidade_base", 0))
    return {
        "timestamp": evento.get("timestamp", ""),
        "regra_id": regra.get("id", ""),
        "regra_nome": regra.get("nome", ""),
        "severidade": severidade,
        "ip": evento.get("ip", ""),
        "descricao": descricao
    }


def aplicar_regras(eventos, regras):
    """
    Aplica todas as regras ativas a todos os eventos
    Um mesmo evento pode gerar multiplos alertas se violar varias regras
    """
    alertas = []
    for evento in eventos:
        for regra in regras:
            resultado = avaliar_regra(regra, evento)
            if resultado is not None:
                alertas.append(resultado)
    print(f"[REGRAS] {len(alertas)} alerta(s) gerado(s).")
    return alertas