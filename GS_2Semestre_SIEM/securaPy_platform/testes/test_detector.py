"""
Testes do Modulo 3 - Detector de Anomalias

Testa: deteccao de brute force, port scan, verificacao de blacklist,
e geracao de resumo consolidado de ameacas.
"""

import pytest
from detector import (
    detectar_brute_force,
    detectar_port_scan,
    verificar_blacklist,
    gerar_resumo_ameacas,
)


# ============================================================
# Testes de detectar_brute_force
# ============================================================

class TestDetectarBruteForce:
    """Testes para deteccao de ataques de forca bruta."""

    def test_retorna_dicionario(self, eventos_completos):
        """Deve retornar um dicionario."""
        resultado = detectar_brute_force(eventos_completos)
        assert isinstance(resultado, dict)

    def test_detecta_ip_com_11_falhas(self, eventos_completos):
        """185.220.101.1 tem 11 FAILs, deve ser detectado (threshold padrao=5)."""
        resultado = detectar_brute_force(eventos_completos)
        assert "185.220.101.1" in resultado

    def test_detecta_ip_com_5_falhas(self, eventos_completos):
        """91.240.118.172 tem 5 FAILs, deve ser detectado (threshold=5)."""
        resultado = detectar_brute_force(eventos_completos)
        assert "91.240.118.172" in resultado

    def test_nao_detecta_abaixo_threshold(self, eventos_completos):
        """45.33.32.156 tem 3 FAILs, abaixo do threshold padrao de 5."""
        resultado = detectar_brute_force(eventos_completos)
        assert "45.33.32.156" not in resultado

    def test_nao_detecta_ips_internos(self, eventos_completos):
        """IPs internos com login OK nao devem aparecer."""
        resultado = detectar_brute_force(eventos_completos)
        assert "192.168.1.10" not in resultado
        assert "192.168.1.45" not in resultado

    def test_contagem_tentativas(self, eventos_completos):
        """Deve contar corretamente o numero de tentativas."""
        resultado = detectar_brute_force(eventos_completos)
        assert resultado["185.220.101.1"]["tentativas"] == 11

    def test_lista_usuarios_tentados(self, eventos_completos):
        """Deve listar quais usuarios foram tentados (sem duplicatas)."""
        resultado = detectar_brute_force(eventos_completos)
        usuarios = resultado["185.220.101.1"]["usuarios"]
        # Pode ser set ou list, mas deve conter os usuarios unicos
        assert "admin" in usuarios
        assert "root" in usuarios

    def test_severidade_alta_para_muitas_tentativas(self, eventos_completos):
        """IP com >10 tentativas deve ter severidade ALTA ou CRITICA."""
        resultado = detectar_brute_force(eventos_completos)
        sev = resultado["185.220.101.1"]["severidade"]
        assert sev in ("ALTA", "CRITICA")

    def test_threshold_customizado(self, eventos_completos):
        """Com threshold=10, apenas 185.220.101.1 (11 FAILs) deve aparecer."""
        resultado = detectar_brute_force(eventos_completos, threshold=10)
        assert "185.220.101.1" in resultado
        assert "91.240.118.172" not in resultado

    def test_threshold_1_detecta_todos(self, eventos_completos):
        """Com threshold=1, todos os IPs com pelo menos 1 FAIL aparecem."""
        resultado = detectar_brute_force(eventos_completos, threshold=1)
        assert len(resultado) >= 3  # pelo menos 3 IPs com FAILs

    def test_ignora_eventos_ok(self, eventos_completos):
        """Eventos com tipo OK nao devem ser contados."""
        resultado = detectar_brute_force(eventos_completos)
        for ip in resultado:
            assert resultado[ip]["tentativas"] > 0

    def test_ignora_eventos_firewall(self, eventos_completos):
        """Eventos de firewall nao devem ser considerados."""
        resultado = detectar_brute_force(eventos_completos)
        # Se so olha auth, IPs que so aparecem no firewall nao devem estar aqui
        # (a menos que tambem tenham FAILs no auth)
        for ip, dados in resultado.items():
            assert dados["tentativas"] > 0

    def test_lista_vazia_retorna_dict_vazio(self):
        """Lista vazia deve retornar dicionario vazio."""
        resultado = detectar_brute_force([])
        assert resultado == {}


# ============================================================
# Testes de detectar_port_scan
# ============================================================

class TestDetectarPortScan:
    """Testes para deteccao de port scanning."""

    def test_retorna_dicionario(self, eventos_completos):
        """Deve retornar um dicionario."""
        resultado = detectar_port_scan(eventos_completos)
        assert isinstance(resultado, dict)

    def test_detecta_ip_com_7_portas(self, eventos_completos):
        """185.220.101.1 tentou 7 portas, deve ser detectado."""
        resultado = detectar_port_scan(eventos_completos)
        assert "185.220.101.1" in resultado

    def test_detecta_ip_com_3_portas(self, eventos_completos):
        """91.240.118.172 tentou 3 portas, deve ser detectado (threshold=3)."""
        resultado = detectar_port_scan(eventos_completos)
        assert "91.240.118.172" in resultado

    def test_nao_detecta_abaixo_threshold(self, eventos_completos):
        """45.33.32.156 tentou apenas 2 portas, abaixo do threshold."""
        resultado = detectar_port_scan(eventos_completos)
        assert "45.33.32.156" not in resultado

    def test_portas_sao_unicas(self, eventos_completos):
        """As portas registradas devem ser unicas (sem duplicatas)."""
        resultado = detectar_port_scan(eventos_completos)
        if "185.220.101.1" in resultado:
            portas = resultado["185.220.101.1"]["portas"]
            # Pode ser set ou list, mas nao deve ter duplicatas
            assert len(portas) == len(set(portas))

    def test_quantidade_portas(self, eventos_completos):
        """Deve contar corretamente o numero de portas unicas."""
        resultado = detectar_port_scan(eventos_completos)
        assert resultado["185.220.101.1"]["quantidade"] == 7

    def test_severidade_para_muitas_portas(self, eventos_completos):
        """IP com 7 portas deve ter severidade ALTA ou superior."""
        resultado = detectar_port_scan(eventos_completos)
        sev = resultado["185.220.101.1"]["severidade"]
        assert sev in ("ALTA", "CRITICA")

    def test_ignora_allow(self, eventos_completos):
        """Eventos ALLOW nao devem ser contados como port scan."""
        resultado = detectar_port_scan(eventos_completos)
        assert "192.168.1.10" not in resultado

    def test_threshold_customizado(self, eventos_completos):
        """Com threshold=5, apenas 185.220.101.1 (7 portas) deve aparecer."""
        resultado = detectar_port_scan(eventos_completos, threshold=5)
        assert "185.220.101.1" in resultado
        assert "91.240.118.172" not in resultado

    def test_lista_vazia_retorna_dict_vazio(self):
        """Lista vazia deve retornar dicionario vazio."""
        resultado = detectar_port_scan([])
        assert resultado == {}


# ============================================================
# Testes de verificar_blacklist
# ============================================================

class TestVerificarBlacklist:
    """Testes para verificacao de IPs contra blacklist."""

    def test_retorna_tupla(self, eventos_completos, blacklist):
        """Deve retornar uma tupla com 2 elementos."""
        resultado = verificar_blacklist(eventos_completos, blacklist)
        assert isinstance(resultado, tuple)
        assert len(resultado) == 2

    def test_encontra_ips_da_blacklist(self, eventos_completos, blacklist):
        """Deve encontrar IPs que estao nos eventos E na blacklist."""
        ips_encontrados, _ = verificar_blacklist(eventos_completos, blacklist)
        assert "185.220.101.1" in ips_encontrados
        assert "45.33.32.156" in ips_encontrados
        assert "91.240.118.172" in ips_encontrados

    def test_nao_encontra_ip_ausente_dos_logs(self, eventos_completos, blacklist):
        """IP da blacklist que nao aparece nos logs nao deve ser retornado."""
        ips_encontrados, _ = verificar_blacklist(eventos_completos, blacklist)
        assert "23.94.5.100" not in ips_encontrados  # esta na blacklist mas nao nos logs

    def test_ips_internos_nao_na_blacklist(self, eventos_completos, blacklist):
        """IPs internos nao devem aparecer como encontrados na blacklist."""
        ips_encontrados, _ = verificar_blacklist(eventos_completos, blacklist)
        assert "192.168.1.10" not in ips_encontrados
        assert "10.0.0.5" not in ips_encontrados

    def test_contagem_por_ip(self, eventos_completos, blacklist):
        """Deve contar quantos eventos cada IP malicioso gerou."""
        _, contagem = verificar_blacklist(eventos_completos, blacklist)
        assert isinstance(contagem, dict)
        # 185.220.101.1 aparece em auth + firewall + web = muitos eventos
        assert contagem["185.220.101.1"] > 10

    def test_usa_intersecao_de_sets(self, eventos_completos, blacklist):
        """O resultado deve ser a intersecao entre IPs dos logs e blacklist."""
        ips_encontrados, _ = verificar_blacklist(eventos_completos, blacklist)
        assert isinstance(ips_encontrados, set)

    def test_blacklist_vazia(self, eventos_completos):
        """Blacklist vazia deve retornar set vazio."""
        ips_encontrados, contagem = verificar_blacklist(eventos_completos, set())
        assert len(ips_encontrados) == 0

    def test_eventos_vazios(self, blacklist):
        """Eventos vazios deve retornar set vazio."""
        ips_encontrados, contagem = verificar_blacklist([], blacklist)
        assert len(ips_encontrados) == 0


# ============================================================
# Testes de gerar_resumo_ameacas
# ============================================================

class TestGerarResumoAmeacas:
    """Testes para geracao de resumo consolidado de ameacas."""

    @pytest.fixture
    def dados_deteccao(self, eventos_completos, blacklist):
        """Gera dados de deteccao simulados para testar o resumo."""
        # Simulando resultados esperados das deteccoes
        brute_force = {
            "185.220.101.1": {"tentativas": 11, "usuarios": {"admin", "root", "test", "sa"}, "severidade": "ALTA"},
            "91.240.118.172": {"tentativas": 5, "usuarios": {"admin", "root", "guest"}, "severidade": "MEDIA"},
        }
        port_scan = {
            "185.220.101.1": {"portas": {22, 23, 445, 8080, 3306, 21, 139}, "quantidade": 7, "severidade": "ALTA"},
            "91.240.118.172": {"portas": {3389, 22, 445}, "quantidade": 3, "severidade": "MEDIA"},
        }
        blacklist_resultado = (
            {"185.220.101.1", "45.33.32.156", "91.240.118.172"},
            {"185.220.101.1": 18, "45.33.32.156": 5, "91.240.118.172": 8},
        )
        return brute_force, port_scan, blacklist_resultado

    def test_retorna_lista(self, dados_deteccao):
        """Deve retornar uma lista."""
        brute, scan, bl = dados_deteccao
        resultado = gerar_resumo_ameacas(brute, scan, bl)
        assert isinstance(resultado, list)

    def test_contem_todos_ips_suspeitos(self, dados_deteccao):
        """Deve conter todos os IPs que apareceram em qualquer deteccao."""
        brute, scan, bl = dados_deteccao
        resultado = gerar_resumo_ameacas(brute, scan, bl)
        ips = {r["ip"] for r in resultado}
        assert "185.220.101.1" in ips
        assert "91.240.118.172" in ips
        assert "45.33.32.156" in ips

    def test_ip_com_3_deteccoes_mais_grave(self, dados_deteccao):
        """185.220.101.1 (brute+scan+blacklist) deve ter maior pontuacao."""
        brute, scan, bl = dados_deteccao
        resultado = gerar_resumo_ameacas(brute, scan, bl)
        # O primeiro da lista (ordenada) deve ser o mais critico
        assert resultado[0]["ip"] == "185.220.101.1"

    def test_lista_deteccoes(self, dados_deteccao):
        """Cada ameaca deve listar em quais deteccoes apareceu."""
        brute, scan, bl = dados_deteccao
        resultado = gerar_resumo_ameacas(brute, scan, bl)
        ip_185 = next(r for r in resultado if r["ip"] == "185.220.101.1")
        assert "brute_force" in ip_185["deteccoes"]
        assert "port_scan" in ip_185["deteccoes"]
        assert "blacklist" in ip_185["deteccoes"]

    def test_ordenado_por_pontuacao(self, dados_deteccao):
        """Lista deve estar ordenada por pontuacao decrescente."""
        brute, scan, bl = dados_deteccao
        resultado = gerar_resumo_ameacas(brute, scan, bl)
        for i in range(len(resultado) - 1):
            assert resultado[i]["pontuacao"] >= resultado[i + 1]["pontuacao"]

    def test_cada_ameaca_tem_campos(self, dados_deteccao):
        """Cada ameaca deve ter: ip, deteccoes, pontuacao, severidade."""
        brute, scan, bl = dados_deteccao
        resultado = gerar_resumo_ameacas(brute, scan, bl)
        campos = ["ip", "deteccoes", "pontuacao", "severidade"]
        for ameaca in resultado:
            for campo in campos:
                assert campo in ameaca, f"Campo '{campo}' ausente em ameaca {ameaca.get('ip', '?')}"

    def test_tudo_vazio(self):
        """Todas as deteccoes vazias devem retornar lista vazia."""
        resultado = gerar_resumo_ameacas({}, {}, (set(), {}))
        assert resultado == []
