"""
Testes de Integracao Ponta a Ponta

Testa o fluxo completo do SIEM:
  carregar logs -> aplicar regras -> detectar anomalias ->
  enriquecer IPs -> gerar relatorio

Estes testes simulam o uso real do sistema integrando todos os modulos.
"""

import os
import json
import pytest
from unittest.mock import patch, MagicMock

from coletor import carregar_todos_os_logs
from regras import carregar_regras, aplicar_regras
from detector import (
    detectar_brute_force,
    detectar_port_scan,
    verificar_blacklist,
    gerar_resumo_ameacas,
)
from enriquecimento import eh_ip_privado, enriquecer_alertas
from relatorios import (
    filtrar_eventos,
    top_ips,
    exportar_relatorio_json,
)


BLACKLIST = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}


# ============================================================
# Fluxo 1: Carregar -> Regras -> Alertas
# ============================================================

class TestFluxoCarregarEAnalisar:
    """Testa o fluxo principal: carregar logs e aplicar regras."""

    def test_carregar_e_aplicar_regras(self, pasta_logs, caminho_regras):
        """Fluxo completo: carregar logs, carregar regras, aplicar regras."""
        # 1. Carregar todos os logs
        eventos = carregar_todos_os_logs(pasta_logs)
        assert len(eventos) == 58  # 23 + 17 + 18

        # 2. Carregar regras
        regras = carregar_regras(caminho_regras)
        assert len(regras) == 5  # 5 regras ativas

        # 3. Aplicar regras
        alertas = aplicar_regras(eventos, regras)
        assert len(alertas) > 0  # deve gerar alertas

        # 4. Verificar que alertas tem campos corretos
        for alerta in alertas:
            assert "timestamp" in alerta
            assert "regra_id" in alerta
            assert "severidade" in alerta
            assert "ip" in alerta

    def test_regras_detectam_todos_os_ataques(self, pasta_logs, caminho_regras):
        """As regras devem detectar os ataques presentes nos logs de teste."""
        eventos = carregar_todos_os_logs(pasta_logs)
        regras = carregar_regras(caminho_regras)
        alertas = aplicar_regras(eventos, regras)

        # Coleta quais regras dispararam
        regras_disparadas = {a["regra_id"] for a in alertas}

        # R001: deve disparar (admin, root, sa, oracle nos logs)
        assert "R001" in regras_disparadas, "R001 (usuario privilegiado) nao disparou"

        # R002: deve disparar (portas criticas bloqueadas)
        assert "R002" in regras_disparadas, "R002 (porta critica) nao disparou"

        # R003: deve disparar (../../etc/passwd no web log)
        assert "R003" in regras_disparadas, "R003 (path traversal) nao disparou"

        # R004: deve disparar (<script> no web log)
        assert "R004" in regras_disparadas, "R004 (XSS) nao disparou"

        # R005: deve disparar (/wp-admin, /phpmyadmin, /shell.php no web log)
        assert "R005" in regras_disparadas, "R005 (reconhecimento) nao disparou"


# ============================================================
# Fluxo 2: Detectar anomalias
# ============================================================

class TestFluxoDeteccao:
    """Testa o fluxo de deteccao de anomalias sobre os dados reais."""

    def test_deteccao_completa(self, pasta_logs):
        """Fluxo de deteccao: brute force, port scan, blacklist, resumo."""
        eventos = carregar_todos_os_logs(pasta_logs)

        # Detectar brute force
        brute = detectar_brute_force(eventos)
        assert "185.220.101.1" in brute  # 10+ FAILs
        assert brute["185.220.101.1"]["tentativas"] >= 10

        # Detectar port scan
        scan = detectar_port_scan(eventos)
        assert "185.220.101.1" in scan  # 7 portas
        assert scan["185.220.101.1"]["quantidade"] >= 5

        # Verificar blacklist
        bl_ips, bl_contagem = verificar_blacklist(eventos, BLACKLIST)
        assert "185.220.101.1" in bl_ips
        assert "45.33.32.156" in bl_ips
        assert "91.240.118.172" in bl_ips
        assert "23.94.5.100" not in bl_ips  # nao aparece nos logs

        # Gerar resumo
        resumo = gerar_resumo_ameacas(brute, scan, (bl_ips, bl_contagem))
        assert len(resumo) > 0

        # IP mais critico deve ser 185.220.101.1 (aparece nas 3 deteccoes)
        assert resumo[0]["ip"] == "185.220.101.1"
        assert len(resumo[0]["deteccoes"]) == 3


# ============================================================
# Fluxo 3: Enriquecimento
# ============================================================

class TestFluxoEnriquecimento:
    """Testa o fluxo de enriquecimento de IPs."""

    def test_ips_dos_logs_classificados_corretamente(self, pasta_logs):
        """IPs dos logs devem ser classificados como privados ou publicos."""
        eventos = carregar_todos_os_logs(pasta_logs)
        ips_unicos = {e["ip"] for e in eventos}

        # IPs que devem ser privados
        for ip in ["192.168.1.10", "192.168.1.45", "192.168.1.20", "10.0.0.5"]:
            if ip in ips_unicos:
                assert eh_ip_privado(ip), f"{ip} deveria ser privado"

        # IPs que devem ser publicos
        for ip in ["185.220.101.1", "91.240.118.172", "45.33.32.156"]:
            if ip in ips_unicos:
                assert not eh_ip_privado(ip), f"{ip} deveria ser publico"


# ============================================================
# Fluxo 4: Filtros e relatorios
# ============================================================

class TestFluxoRelatorios:
    """Testa o fluxo de filtros e geracao de relatorios."""

    def test_filtrar_e_top_ips(self, pasta_logs):
        """Filtrar eventos e gerar top IPs."""
        eventos = carregar_todos_os_logs(pasta_logs)

        # Filtrar apenas FAILs de auth
        fails = filtrar_eventos(eventos, fonte="auth", tipo="FAIL")
        assert len(fails) > 0
        assert all(e["fonte"] == "auth" and e["tipo"] == "FAIL" for e in fails)

        # Top IPs
        ranking = top_ips(eventos, n=5)
        assert len(ranking) <= 5
        assert ranking[0][0] == "185.220.101.1"  # mais ativo

    def test_exportar_relatorio_completo(self, pasta_logs, caminho_regras, pasta_temporaria):
        """Fluxo completo ate exportar relatorio JSON."""
        # Carregar e processar
        eventos = carregar_todos_os_logs(pasta_logs)
        regras = carregar_regras(caminho_regras)
        alertas = aplicar_regras(eventos, regras)
        brute = detectar_brute_force(eventos)
        scan = detectar_port_scan(eventos)
        bl_ips, bl_contagem = verificar_blacklist(eventos, BLACKLIST)
        resumo = gerar_resumo_ameacas(brute, scan, (bl_ips, bl_contagem))

        # Montar relatorio
        relatorio = {
            "total_eventos": len(eventos),
            "total_alertas": len(alertas),
            "fontes": {
                "auth": len(filtrar_eventos(eventos, fonte="auth")),
                "firewall": len(filtrar_eventos(eventos, fonte="firewall")),
                "web": len(filtrar_eventos(eventos, fonte="web")),
            },
            "top_ips": top_ips(eventos, n=5),
            "ameacas": [
                {
                    "ip": a["ip"],
                    "deteccoes": list(a["deteccoes"]) if isinstance(a["deteccoes"], (set, list)) else a["deteccoes"],
                    "pontuacao": a["pontuacao"],
                    "severidade": a["severidade"],
                }
                for a in resumo
            ],
        }

        # Exportar
        caminho = os.path.join(pasta_temporaria, "relatorio_teste.json")
        exportar_relatorio_json(relatorio, caminho)

        # Verificar arquivo
        assert os.path.exists(caminho)
        with open(caminho, "r") as f:
            dados = json.load(f)
        assert dados["total_eventos"] == 58
        assert dados["total_alertas"] > 0
        assert len(dados["ameacas"]) > 0


# ============================================================
# Fluxo 5: Busca por IP (ponta a ponta)
# ============================================================

class TestFluxoBuscaIp:
    """Testa busca de um IP especifico com todas as informacoes."""

    def test_ip_malicioso_completo(self, pasta_logs, caminho_regras):
        """Buscar 185.220.101.1 deve retornar dados de todas as fontes."""
        eventos = carregar_todos_os_logs(pasta_logs)
        regras = carregar_regras(caminho_regras)
        alertas = aplicar_regras(eventos, regras)

        # Filtrar por IP
        ip_alvo = "185.220.101.1"
        eventos_ip = filtrar_eventos(eventos, ip=ip_alvo)
        alertas_ip = [a for a in alertas if a["ip"] == ip_alvo]

        # Deve ter eventos de multiplas fontes
        fontes = {e["fonte"] for e in eventos_ip}
        assert len(fontes) >= 2  # auth + firewall no minimo

        # Deve ter alertas
        assert len(alertas_ip) > 0

        # Deve ser classificado como publico
        assert not eh_ip_privado(ip_alvo)

    def test_ip_interno_sem_alertas(self, pasta_logs, caminho_regras):
        """IP interno (192.168.1.10) nao deve gerar alertas de regras."""
        eventos = carregar_todos_os_logs(pasta_logs)
        regras = carregar_regras(caminho_regras)
        alertas = aplicar_regras(eventos, regras)

        ip_alvo = "192.168.1.10"
        alertas_ip = [a for a in alertas if a["ip"] == ip_alvo]
        assert len(alertas_ip) == 0  # IP interno com atividade normal

        # Deve ser classificado como privado
        assert eh_ip_privado(ip_alvo)


# ============================================================
# Fluxo 6: Consistencia dos dados
# ============================================================

class TestConsistenciaDados:
    """Testa que os dados sao consistentes ao longo de todo o pipeline."""

    def test_todos_alertas_referem_eventos_reais(self, pasta_logs, caminho_regras):
        """Todo IP em um alerta deve existir nos eventos carregados."""
        eventos = carregar_todos_os_logs(pasta_logs)
        regras = carregar_regras(caminho_regras)
        alertas = aplicar_regras(eventos, regras)

        ips_eventos = {e["ip"] for e in eventos}
        for alerta in alertas:
            assert alerta["ip"] in ips_eventos, \
                f"Alerta refere IP {alerta['ip']} que nao esta nos eventos"

    def test_todos_ips_brute_force_sao_do_auth(self, pasta_logs):
        """IPs detectados em brute force devem ter eventos de auth."""
        eventos = carregar_todos_os_logs(pasta_logs)
        brute = detectar_brute_force(eventos)

        ips_auth = {e["ip"] for e in eventos if e["fonte"] == "auth" and e["tipo"] == "FAIL"}
        for ip in brute:
            assert ip in ips_auth, f"IP {ip} detectado como brute force mas nao tem FAILs no auth"

    def test_todos_ips_port_scan_sao_do_firewall(self, pasta_logs):
        """IPs detectados em port scan devem ter eventos de firewall."""
        eventos = carregar_todos_os_logs(pasta_logs)
        scan = detectar_port_scan(eventos)

        ips_fw = {e["ip"] for e in eventos if e["fonte"] == "firewall" and e["tipo"] == "BLOCK"}
        for ip in scan:
            assert ip in ips_fw, f"IP {ip} detectado como port scan mas nao tem BLOCKs no firewall"

    def test_severidades_validas(self, pasta_logs, caminho_regras):
        """Todas as severidades devem ser uma das 5 validas."""
        eventos = carregar_todos_os_logs(pasta_logs)
        regras = carregar_regras(caminho_regras)
        alertas = aplicar_regras(eventos, regras)

        severidades_validas = {"CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO"}
        for alerta in alertas:
            assert alerta["severidade"] in severidades_validas, \
                f"Severidade invalida: {alerta['severidade']}"
