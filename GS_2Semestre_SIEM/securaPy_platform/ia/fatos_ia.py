"""Respostas sobre IPs com dados factuais calculados pelo VioTrace.

O LLM escolhe apenas IDs de recomendações previamente aprovadas. Eventos,
contagens, portas e detecções são extraídos do relatório, nunca do texto livre.
"""
import json

ACOES = {
    "B01": "Revisar os acessos privilegiados e habilitar MFA nas contas críticas.",
    "B02": "Aplicar limites de tentativas de autenticação e alertas para falhas repetidas.",
    "P01": "Revisar regras de firewall e restringir portas não necessárias.",
    "P02": "Inspecionar os logs de rede e monitorar novas tentativas de varredura.",
    "L01": "Validar a origem e a validade da entrada na blacklist local antes de bloquear definitivamente o IP.",
    "G01": "Correlacionar os registros com outros sistemas e documentar as evidências antes de agir.",
}


def _inteiro(valor):
    try:
        return int(valor)
    except (ValueError, TypeError):
        return None


def acoes_permitidas(contexto):
    correlacoes = contexto.get("deteccoes_correlacionadas") or {}
    permitidas = ["G01"]
    if correlacoes.get("brute_force_detectado"):
        permitidas.extend(["B01", "B02"])
    if correlacoes.get("port_scan_detectado"):
        permitidas.extend(["P01", "P02"])
    if correlacoes.get("blacklist_confirmada"):
        permitidas.append("L01")
    return permitidas


def resumo_verificado(contexto):
    """Usa contagens agregadas do backend; não interpreta livremente logs."""
    ip = contexto.get("ip_em_analise") or "não especificado"
    total = contexto.get("eventos_do_recorte", 0)
    alertas = contexto.get("alertas_de_regras_do_recorte", 0)
    partes = [
        f"**Análise verificada — IP {ip}**",
        "Fonte: relatório histórico de laboratório (não é monitoramento ao vivo).",
        f"- **Eventos associados:** {total} (não são todos tentativas de login).",
        f"- **Alertas por regras:** {alertas} (não confundir com detecções correlacionadas).",
    ]
    if contexto.get("eventos_disponiveis", False):
        por_fonte = contexto.get("eventos_por_fonte") or {}
        linhas = ", ".join(f"{fonte}: {qtd}" for fonte, qtd in sorted(por_fonte.items()))
        partes.append(f"- **Eventos por fonte:** {linhas or 'nenhum' }.")
        partes.append(f"- **Falhas de autenticação:** {contexto.get('falhas_autenticacao', 0)}.")
        partes.append(f"- **Bloqueios de firewall:** {contexto.get('bloqueios_firewall', 0)}.")
    else:
        partes.append("- **Detalhamento por fonte:** indisponível neste relatório.")

    correlacoes = contexto.get("deteccoes_correlacionadas") or {}
    if "brute_force_detectado" not in correlacoes:
        partes.append("- **Brute force:** dados de correlação indisponíveis.")
    elif correlacoes.get("brute_force_detectado"):
        bruto = correlacoes.get("brute_force_detalhes") or {}
        qtd = _inteiro(bruto.get("tentativas"))
        usuarios = bruto.get("usuarios") if isinstance(bruto.get("usuarios"), list) else []
        parte = f"{qtd} falhas de autenticação correlacionadas" if qtd is not None else "detectado pelo motor de correlação"
        if usuarios:
            parte += f"; contas tentadas: {', '.join(str(u) for u in usuarios[:15])}"
        partes.append("- **Brute force:** " + parte + ".")
    else:
        partes.append("- **Brute force:** não identificado pelas regras de correlação atuais.")

    if "port_scan_detectado" not in correlacoes:
        partes.append("- **Port scan:** dados de correlação indisponíveis.")
    elif correlacoes.get("port_scan_detectado"):
        scan = correlacoes.get("port_scan_detalhes") or {}
        portas = scan.get("portas") if isinstance(scan.get("portas"), list) else []
        qtd = _inteiro(scan.get("quantidade"))
        n = qtd if qtd is not None else len(portas)
        detalhe = f"{n} portas distintas de destino" if n else "detectado pelo motor de correlação"
        if portas:
            detalhe += "; portas: " + ", ".join(map(str, portas[:30]))
        partes.append("- **Port scan:** " + detalhe + "; são conexões, não tentativas de login.")
    else:
        partes.append("- **Port scan:** não identificado pelas regras de correlação atuais.")

    if "blacklist_confirmada" not in correlacoes:
        partes.append("- **Blacklist:** dados indisponíveis.")
    elif correlacoes["blacklist_confirmada"]:
        partes.append("- **Blacklist:** IP presente na lista LOCAL configurada no laboratório; isso, isoladamente, não prova atividade maliciosa externa.")
    else:
        partes.append("- **Blacklist:** IP não consta na lista local utilizada nesta análise.")
    return "\n".join(partes)


def resposta_ip(contexto, resposta_modelo):
    """Exibe evidências determinísticas e seleciona somente ações reconhecidas."""
    permitidas = acoes_permitidas(contexto)
    selecionadas = []
    try:
        objeto = json.loads(resposta_modelo)
        ids = objeto.get("acoes", []) if isinstance(objeto, dict) else []
        if isinstance(ids, list):
            selecionadas = [x for x in ids if isinstance(x, str) and x in permitidas]
    except (TypeError, ValueError):
        pass
    selecionadas = list(dict.fromkeys(selecionadas))[:5]
    if not selecionadas:
        selecionadas = permitidas[:5]
    linhas = [resumo_verificado(contexto), "", "**Medidas defensivas recomendadas**"]
    linhas.extend(f"{i}. {ACOES[acao]}" for i, acao in enumerate(selecionadas, 1))
    linhas.append("\nAs correlações representam indícios técnicos; confirme os registros antes de bloquear ou atribuir responsabilidade.")
    return "\n".join(linhas)
