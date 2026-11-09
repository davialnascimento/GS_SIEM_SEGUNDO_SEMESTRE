"""
Modulo 6 - Dashboard CLI e Relatorios
Interface interativa do SIEM com menu, filtros, busca por IP,
ranking de ameacas e exportacao de relatorios em JSON.

Desenvolvido por: Caique
"""

import json
import os
from collections import Counter
from datetime import datetime


def exibir_menu():
    """
    Exibe o menu principal do SecuraPy e retorna a opcao escolhida.
    Valida a entrada: retorna -1 se o usuario digitar algo invalido.
    """
    print("""
╔══════════════════════════════════════════╗
║         SecuraPy SIEM — Menu             ║
╠══════════════════════════════════════════╣
║  1. Carregar e processar logs            ║
║  2. Resumo geral                         ║
║  3. Filtrar eventos                      ║
║  4. Buscar IP                            ║
║  5. Top 10 IPs suspeitos                 ║
║  6. Ver alertas por severidade           ║
║  7. Enriquecer IPs suspeitos             ║
║  8. Exportar relatorio JSON              ║
║  9. Iniciar servidor de alertas          ║
║  0. Sair                                 ║
╚══════════════════════════════════════════╝""")

    try:
        return int(input("Escolha uma opcao: ").strip())
    except ValueError:
        return -1


def resumo_geral(eventos, alertas):
    """
    Exibe contadores gerais: eventos por fonte e alertas por severidade.
    """
    total_eventos = len(eventos)
    total_alertas = len(alertas)

    # Conta eventos agrupados por fonte
    fontes = Counter(evento.get("fonte", "desconhecida") for evento in eventos)

    # Conta alertas agrupados por severidade
    severidades = Counter(alerta.get("severidade", "desconhecida") for alerta in alertas)

    print("\n===== RESUMO GERAL =====")
    print(f"Total de eventos : {total_eventos}")
    print(f"Total de alertas : {total_alertas}")

    print("\n--- Eventos por fonte ---")
    for fonte, quantidade in sorted(fontes.items()):
        print(f"  {fonte:<12}: {quantidade}")

    print("\n--- Alertas por severidade ---")
    ordem = ["CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO"]
    for nivel in ordem:
        if nivel in severidades:
            print(f"  {nivel:<10}: {severidades[nivel]}")
    print("========================")


def filtrar_eventos(eventos, fonte=None, tipo=None, ip=None):
    """
    Filtra eventos pelos criterios fornecidos.
    Criterios com valor None sao ignorados (sem filtro para aquele campo).
    """
    return [
        evento for evento in eventos
        if (fonte is None or evento.get("fonte") == fonte)
        and (tipo is None or evento.get("tipo") == tipo)
        and (ip is None or evento.get("ip") == ip)
    ]


def buscar_ip(ip, eventos, alertas, cache_enriquecimento):
    """
    Exibe relatorio completo de um IP: eventos, alertas e geolocalizacao.
    """
    eventos_do_ip = [e for e in eventos if e.get("ip") == ip]
    alertas_do_ip = [a for a in alertas if a.get("ip") == ip]
    enriquecimento = cache_enriquecimento.get(ip)

    print(f"\n===== BUSCA: {ip} =====")
    print(f"Eventos encontrados : {len(eventos_do_ip)}")
    print(f"Alertas encontrados : {len(alertas_do_ip)}")

    if eventos_do_ip:
        print("\n--- Eventos ---")
        for ev in eventos_do_ip[:10]:  # Mostra ate 10
            print(f"  [{ev.get('timestamp')}] {ev.get('fonte')} | {ev.get('tipo')} | {ev.get('detalhes')}")

    if alertas_do_ip:
        print("\n--- Alertas ---")
        for al in alertas_do_ip:
            print(f"  [{al.get('severidade')}] {al.get('regra_nome')} - {al.get('descricao')}")

    if enriquecimento:
        print("\n--- Geolocalizacao ---")
        privado = enriquecimento.get("privado", False)
        print(f"  Tipo    : {'Rede Interna' if privado else 'IP Publico'}")
        if not privado:
            print(f"  Pais    : {enriquecimento.get('pais', '-')}")
            print(f"  Cidade  : {enriquecimento.get('cidade', '-')}")
            print(f"  Org     : {enriquecimento.get('org', '-')}")

    print("=" * (len(ip) + 14))


def top_ips(eventos, n=10):
    """
    Retorna e exibe os N IPs com mais eventos registrados.
    """
    ips = [evento.get("ip") for evento in eventos if evento.get("ip")]
    ranking = Counter(ips).most_common(n)

    print(f"\n===== TOP {n} IPs =====")
    for posicao, (ip, quantidade) in enumerate(ranking, start=1):
        print(f"  {posicao:02}. {ip:<20} {quantidade} evento(s)")
    print("===================")

    return ranking


def exportar_relatorio_json(dados, caminho):
    """
    Salva um relatorio completo em JSON formatado.
    Cria o diretorio de saida automaticamente se nao existir.

    O relatorio inclui:
        - gerado_em: timestamp de geracao
        - total_eventos: quantidade de eventos processados
        - total_alertas: quantidade de alertas gerados
        - dados: payload completo passado pelo chamador
    """
    # Garante que o diretorio de saida existe
    diretorio = os.path.dirname(caminho)
    if diretorio:
        os.makedirs(diretorio, exist_ok=True)

    # Mescla os dados recebidos com o timestamp de geracao
    # Nao embrulha em "dados" para que as chaves fiquem acessiveis diretamente
    relatorio = {"gerado_em": datetime.now().isoformat()}
    if isinstance(dados, dict):
        relatorio.update(dados)
    else:
        relatorio["dados"] = dados

    with open(caminho, "w", encoding="utf-8") as arquivo:
        json.dump(relatorio, arquivo, indent=2, ensure_ascii=False, default=str)

    print(f"\n[OK] Relatorio exportado: {caminho}")


def exibir_tabela(dados, colunas):
    """
    Exibe uma lista de dicionarios como tabela formatada no terminal.
    """
    if not dados:
        print("Nenhum dado encontrado.")
        return

    largura = 22
    cabecalho = "".join(coluna.upper().ljust(largura) for coluna in colunas)
    separador = "-" * len(cabecalho)

    print("\n" + cabecalho)
    print(separador)
    for item in dados:
        linha = "".join(str(item.get(coluna, "-")).ljust(largura) for coluna in colunas)
        print(linha)