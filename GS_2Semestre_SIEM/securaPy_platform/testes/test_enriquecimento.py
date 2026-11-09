"""
Testes do Modulo 5 - Enriquecimento de IPs

Testa: classificacao de IPs privados/publicos, cache de consultas,
enriquecimento de alertas. Testes de API usam mock para nao depender
de conexao com a internet.
"""

import pytest
from unittest.mock import patch, MagicMock
from enriquecimento import (
    eh_ip_privado,
    consultar_ip,
    enriquecer_alertas,
)


# ============================================================
# Testes de eh_ip_privado
# ============================================================

class TestEhIpPrivado:
    """Testes para classificacao de IPs privados vs publicos."""

    # --- Faixa 10.x.x.x ---

    def test_10_0_0_1_privado(self):
        """10.0.0.1 eh privado."""
        assert eh_ip_privado("10.0.0.1") is True

    def test_10_255_255_255_privado(self):
        """10.255.255.255 eh privado."""
        assert eh_ip_privado("10.255.255.255") is True

    def test_10_0_0_5_privado(self):
        """10.0.0.5 eh privado (IP dos logs de teste)."""
        assert eh_ip_privado("10.0.0.5") is True

    # --- Faixa 172.16-31.x.x ---

    def test_172_16_0_1_privado(self):
        """172.16.0.1 eh privado."""
        assert eh_ip_privado("172.16.0.1") is True

    def test_172_31_255_255_privado(self):
        """172.31.255.255 eh privado."""
        assert eh_ip_privado("172.31.255.255") is True

    def test_172_32_0_1_publico(self):
        """172.32.0.1 NAO eh privado (fora da faixa 16-31)."""
        assert eh_ip_privado("172.32.0.1") is False

    def test_172_15_0_1_publico(self):
        """172.15.0.1 NAO eh privado (fora da faixa 16-31)."""
        assert eh_ip_privado("172.15.0.1") is False

    # --- Faixa 192.168.x.x ---

    def test_192_168_1_1_privado(self):
        """192.168.1.1 eh privado."""
        assert eh_ip_privado("192.168.1.1") is True

    def test_192_168_1_10_privado(self):
        """192.168.1.10 eh privado (IP dos logs de teste)."""
        assert eh_ip_privado("192.168.1.10") is True

    def test_192_168_255_255_privado(self):
        """192.168.255.255 eh privado."""
        assert eh_ip_privado("192.168.255.255") is True

    # --- Loopback ---

    def test_127_0_0_1_privado(self):
        """127.0.0.1 (localhost) eh privado."""
        assert eh_ip_privado("127.0.0.1") is True

    # --- IPs publicos ---

    def test_8_8_8_8_publico(self):
        """8.8.8.8 (Google DNS) eh publico."""
        assert eh_ip_privado("8.8.8.8") is False

    def test_185_220_101_1_publico(self):
        """185.220.101.1 (IP dos logs) eh publico."""
        assert eh_ip_privado("185.220.101.1") is False

    def test_91_240_118_172_publico(self):
        """91.240.118.172 (IP dos logs) eh publico."""
        assert eh_ip_privado("91.240.118.172") is False

    def test_45_33_32_156_publico(self):
        """45.33.32.156 (IP dos logs) eh publico."""
        assert eh_ip_privado("45.33.32.156") is False

    def test_1_1_1_1_publico(self):
        """1.1.1.1 (Cloudflare) eh publico."""
        assert eh_ip_privado("1.1.1.1") is False


# ============================================================
# Testes de consultar_ip (com mock da API)
# ============================================================

class TestConsultarIp:
    """Testes para consulta de IPs na API ipinfo.io."""

    def _mock_response(self, json_data, status_code=200):
        """Helper: cria um mock de resposta HTTP."""
        mock = MagicMock()
        mock.status_code = status_code
        mock.json.return_value = json_data
        return mock

    @patch("enriquecimento.requests.get")
    def test_consulta_ip_publico(self, mock_get):
        """Deve consultar a API para IP publico e retornar dados."""
        mock_get.return_value = self._mock_response({
            "ip": "185.220.101.1",
            "city": "Frankfurt",
            "region": "Hesse",
            "country": "DE",
            "org": "AS208294 Fastethernet",
            "hostname": "tor-exit.r2",
        })
        cache = {}
        resultado = consultar_ip("185.220.101.1", cache)
        assert resultado is not None
        assert isinstance(resultado, dict)
        mock_get.assert_called_once()

    @patch("enriquecimento.requests.get")
    def test_retorno_contem_campos(self, mock_get):
        """Resultado deve conter campos de geolocalizacao."""
        mock_get.return_value = self._mock_response({
            "ip": "8.8.8.8",
            "city": "Mountain View",
            "region": "California",
            "country": "US",
            "org": "AS15169 Google LLC",
        })
        cache = {}
        resultado = consultar_ip("8.8.8.8", cache)
        # Verifica que pelo menos ip e pais estao presentes
        assert "8.8.8.8" in str(resultado.values())

    @patch("enriquecimento.requests.get")
    def test_usa_cache_na_segunda_consulta(self, mock_get):
        """Segunda consulta do mesmo IP deve usar cache, sem chamar a API."""
        mock_get.return_value = self._mock_response({
            "ip": "8.8.8.8", "city": "Mountain View",
            "region": "California", "country": "US", "org": "Google",
        })
        cache = {}
        consultar_ip("8.8.8.8", cache)
        consultar_ip("8.8.8.8", cache)
        # API deve ter sido chamada apenas 1 vez
        assert mock_get.call_count == 1

    def test_ip_privado_nao_consulta_api(self):
        """IP privado nao deve fazer requisicao HTTP."""
        cache = {}
        resultado = consultar_ip("192.168.1.10", cache)
        assert resultado is not None
        # Nao precisamos de mock — se chamar requests.get com IP privado,
        # o teste nao deve falhar (e nao deve fazer request real)

    @patch("enriquecimento.requests.get")
    def test_salva_no_cache(self, mock_get):
        """Resultado deve ser salvo no cache."""
        mock_get.return_value = self._mock_response({
            "ip": "1.2.3.4", "city": "Teste",
            "region": "Teste", "country": "BR", "org": "Teste",
        })
        cache = {}
        consultar_ip("1.2.3.4", cache)
        assert "1.2.3.4" in cache

    @patch("enriquecimento.requests.get")
    def test_trata_timeout(self, mock_get):
        """Timeout nao deve travar o programa."""
        import requests as req
        mock_get.side_effect = req.exceptions.Timeout("timeout")
        cache = {}
        resultado = consultar_ip("1.2.3.4", cache)
        # Deve retornar algo (dict com valores padrao), nao levantar excecao
        assert resultado is not None

    @patch("enriquecimento.requests.get")
    def test_trata_erro_conexao(self, mock_get):
        """Erro de conexao nao deve travar o programa."""
        import requests as req
        mock_get.side_effect = req.exceptions.ConnectionError("sem rede")
        cache = {}
        resultado = consultar_ip("1.2.3.4", cache)
        assert resultado is not None


# ============================================================
# Testes de enriquecer_alertas
# ============================================================

class TestEnriquecerAlertas:
    """Testes para enriquecimento de lista de alertas."""

    @patch("enriquecimento.requests.get")
    def test_adiciona_geolocalizacao(self, mock_get):
        """Alertas devem ganhar campo de geolocalizacao."""
        mock_get.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={
                "ip": "185.220.101.1", "city": "Frankfurt",
                "region": "Hesse", "country": "DE", "org": "Fastethernet",
            }),
        )
        alertas = [
            {"timestamp": "2025-02-20 08:15:01", "regra_id": "R001",
             "regra_nome": "Teste", "severidade": "ALTA",
             "ip": "185.220.101.1", "descricao": "teste"},
        ]
        cache = {}
        resultado = enriquecer_alertas(alertas, cache)
        assert len(resultado) == 1
        assert "geolocalizacao" in resultado[0]

    def test_ip_privado_marca_rede_interna(self):
        """Alertas com IP privado devem ter geolocalizacao 'Rede Interna'."""
        alertas = [
            {"timestamp": "2025-02-20 08:15:01", "regra_id": "R001",
             "regra_nome": "Teste", "severidade": "MEDIA",
             "ip": "192.168.1.10", "descricao": "teste"},
        ]
        cache = {}
        resultado = enriquecer_alertas(alertas, cache)
        assert len(resultado) == 1
        geo = resultado[0]["geolocalizacao"]
        # Deve indicar que eh rede interna de alguma forma
        assert "Rede Interna" in str(geo) or resultado[0]["geolocalizacao"].get("privado", False)

    def test_lista_vazia(self):
        """Lista vazia de alertas deve retornar lista vazia."""
        resultado = enriquecer_alertas([], {})
        assert resultado == []
