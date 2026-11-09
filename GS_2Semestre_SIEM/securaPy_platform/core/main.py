"""
SecuraPy SIEM - Ponto de Entrada Principal
Integra todos os modulos: coletor, regras, detector, enriquecimento,
servidor de alertas e relatorios em um menu interativo.

Desenvolvido por: Caique e Amanda
"""

from coletor import carregar_todos_os_logs
from regras import carregar_regras, aplicar_regras
from detector import (
    detectar_brute_force,
    detectar_port_scan,
    verificar_blacklist,
    gerar_resumo_ameacas
)
from enriquecimento import enriquecer_alertas, consultar_ip, exibir_enriquecimento
from relatorios import (
    exibir_menu,
    resumo_geral,
    filtrar_eventos,
    buscar_ip,
    top_ips,
    exportar_relatorio_json,
    exibir_tabela
)

# Configuracoes globais
PASTA_LOGS = "logs"
ARQUIVO_REGRAS = "config/regras.json"
BLACKLIST = {
    "185.220.101.1",
    "45.33.32.156",
    "91.240.118.172",
    "23.94.5.100"
}


def main():
    eventos = []
    alertas = []
    resumo = []
    cache_enriquecimento = {}

    print("=" * 50)
    print("       SecuraPy SIEM - Coding for Security")
    print("=" * 50)

    while True:
        opcao = exibir_menu()

        # --- Opcao 1: Carregar e processar todos os logs ---
        if opcao == 1:
            print("\n[*] Carregando logs...")
            eventos = carregar_todos_os_logs(PASTA_LOGS)

            if not eventos:
                print("[AVISO] Nenhum evento carregado. Verifique a pasta 'logs/'.")
                continue

            print(f"[*] Total de eventos carregados: {len(eventos)}")

            print("\n[*] Carregando regras de deteccao...")
            regras = carregar_regras(ARQUIVO_REGRAS)

            print("\n[*] Aplicando regras aos eventos...")
            alertas = aplicar_regras(eventos, regras)

            print("\n[*] Executando deteccao de anomalias...")
            brute = detectar_brute_force(eventos)
            scan = detectar_port_scan(eventos)

            # verificar_blacklist retorna (set_ips_encontrados, dict_contagem)
            blacklist_resultado = verificar_blacklist(eventos, BLACKLIST)
            blacklist_encontrada, contagem_blacklist = blacklist_resultado

            # gerar_resumo_ameacas aceita a tupla diretamente
            resumo = gerar_resumo_ameacas(brute, scan, blacklist_resultado)

            print(f"\n[OK] Processamento concluido!")
            print(f"     IPs suspeitos identificados: {len(resumo)}")
            if blacklist_encontrada:
                print(f"     IPs da blacklist nos logs: {len(blacklist_encontrada)} ({', '.join(blacklist_encontrada)})")
            if resumo:
                print("     Ameacas detectadas:")
                for ameaca in resumo[:5]:
                    print(f"       [{ameaca['severidade']}] {ameaca['ip']} - {', '.join(ameaca['deteccoes'])}")

        # --- Opcao 2: Resumo geral ---
        elif opcao == 2:
            if not eventos:
                print("\n[AVISO] Carregue os logs primeiro (opcao 1).")
                continue
            resumo_geral(eventos, alertas)

        # --- Opcao 3: Filtrar eventos ---
        elif opcao == 3:
            if not eventos:
                print("\n[AVISO] Carregue os logs primeiro (opcao 1).")
                continue

            print("\nFiltrar por (pressione Enter para ignorar o filtro):")
            fonte = input("  Fonte (auth/firewall/web): ").strip() or None
            tipo = input("  Tipo (FAIL/BLOCK/GET/etc): ").strip() or None
            ip_filtro = input("  IP: ").strip() or None

            resultado = filtrar_eventos(eventos, fonte=fonte, tipo=tipo, ip=ip_filtro)
            print(f"\n{len(resultado)} evento(s) encontrado(s).")
            exibir_tabela(resultado, ["timestamp", "fonte", "tipo", "ip", "detalhes"])

        # --- Opcao 4: Buscar IP ---
        elif opcao == 4:
            if not eventos:
                print("\n[AVISO] Carregue os logs primeiro (opcao 1).")
                continue
            ip_busca = input("\nDigite o IP a buscar: ").strip()
            buscar_ip(ip_busca, eventos, alertas, cache_enriquecimento)
            dados_geo = consultar_ip(ip_busca, cache_enriquecimento)
            exibir_enriquecimento(dados_geo)

        # --- Opcao 5: Top 10 IPs ---
        elif opcao == 5:
            if not eventos:
                print("\n[AVISO] Carregue os logs primeiro (opcao 1).")
                continue
            top_ips(eventos, n=10)

        # --- Opcao 6: Alertas por severidade ---
        elif opcao == 6:
            if not alertas:
                print("\n[AVISO] Carregue os logs primeiro (opcao 1).")
                continue
            nivel = input("\nDigite a severidade (CRITICA/ALTA/MEDIA/BAIXA/INFO): ").strip().upper()
            filtrados = [a for a in alertas if a.get("severidade") == nivel]
            print(f"\n{len(filtrados)} alerta(s) com severidade {nivel}:")
            exibir_tabela(filtrados, ["timestamp", "ip", "regra_nome", "descricao"])

        # --- Opcao 7: Enriquecer IPs suspeitos ---
        elif opcao == 7:
            if not alertas:
                print("\n[AVISO] Carregue os logs primeiro (opcao 1).")
                continue
            print("\n[*] Enriquecendo IPs suspeitos com geolocalizacao...")
            alertas = enriquecer_alertas(alertas, cache_enriquecimento)
            print(f"[OK] {len(cache_enriquecimento)} IP(s) consultado(s).")

            if resumo:
                for ameaca in resumo[:3]:
                    ip = ameaca.get("ip")
                    if ip in cache_enriquecimento:
                        exibir_enriquecimento(cache_enriquecimento[ip])

        # --- Opcao 8: Exportar relatorio JSON ---
        elif opcao == 8:
            if not eventos:
                print("\n[AVISO] Carregue os logs primeiro (opcao 1).")
                continue
            nome_arquivo = f"relatorio_{__import__('datetime').datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            caminho = f"saida/{nome_arquivo}"
            dados = {
                "total_eventos": len(eventos),
                "total_alertas": len(alertas),
                "alertas": alertas,
                "resumo_ameacas": resumo
            }
            exportar_relatorio_json(dados, caminho)

        # --- Opcao 9: Iniciar servidor de alertas ---
        elif opcao == 9:
            print("\n[*] Iniciando servidor de alertas em segundo plano...")
            print("    Conecte clientes com: python cliente_alertas.py")
            try:
                from servidor_alertas import iniciar_servidor
                import threading
                thread_servidor = threading.Thread(target=iniciar_servidor, daemon=True)
                thread_servidor.start()
                print("[OK] Servidor iniciado na porta 9999.")

                if alertas:
                    import time
                    time.sleep(1)
                    from servidor_alertas import broadcast_alerta
                    print(f"[*] Transmitindo {len(alertas)} alerta(s)...")
                    for alerta in alertas:
                        broadcast_alerta(alerta)
                        time.sleep(0.1)
                    print("[OK] Alertas transmitidos.")
            except Exception as erro:
                print(f"[ERRO] Nao foi possivel iniciar o servidor: {erro}")

        # --- Opcao 0: Sair ---
        elif opcao == 0:
            print("\nEncerrando SecuraPy, boa férias bara e ate logo!")
            break

        else:
            print("\n[AVISO] Opcao invalida. Tente novamente.")


if __name__ == "__main__":
    main()