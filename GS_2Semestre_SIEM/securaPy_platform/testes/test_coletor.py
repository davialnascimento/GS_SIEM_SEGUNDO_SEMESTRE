"""
Testes do Modulo 1 - Coletor de Logs

Testa: parsing de cada formato de log, normalizacao de eventos,
tratamento de erros (arquivo inexistente, linhas invalidas, arquivo vazio),
carregamento unificado de multiplas fontes.
"""

import os
import pytest
from coletor import (
    parsear_linha_auth,
    parsear_linha_firewall,
    parsear_linha_web,
    carregar_log,
    carregar_todos_os_logs,
)


# ============================================================
# Testes de parsear_linha_auth
# ============================================================

class TestParsearLinhaAuth:
    """Testes para parsing de linhas do auth.log."""

    def test_linha_fail_retorna_dict(self, linha_auth_fail):
        """Linha FAIL deve retornar dicionario com todos os campos."""
        resultado = parsear_linha_auth(linha_auth_fail)
        assert resultado is not None
        assert isinstance(resultado, dict)

    def test_linha_fail_campos_obrigatorios(self, linha_auth_fail):
        """O dict retornado deve conter todas as chaves obrigatorias."""
        resultado = parsear_linha_auth(linha_auth_fail)
        campos = ["timestamp", "fonte", "tipo", "ip", "detalhes", "linha_original"]
        for campo in campos:
            assert campo in resultado, f"Campo '{campo}' ausente no resultado"

    def test_linha_fail_timestamp(self, linha_auth_fail):
        """O timestamp deve ser extraido corretamente (data + hora)."""
        resultado = parsear_linha_auth(linha_auth_fail)
        assert resultado["timestamp"] == "2025-02-20 08:15:01"

    def test_linha_fail_fonte(self, linha_auth_fail):
        """A fonte deve ser 'auth'."""
        resultado = parsear_linha_auth(linha_auth_fail)
        assert resultado["fonte"] == "auth"

    def test_linha_fail_tipo(self, linha_auth_fail):
        """O tipo deve ser 'FAIL'."""
        resultado = parsear_linha_auth(linha_auth_fail)
        assert resultado["tipo"] == "FAIL"

    def test_linha_fail_ip(self, linha_auth_fail):
        """O IP deve ser extraido corretamente."""
        resultado = parsear_linha_auth(linha_auth_fail)
        assert resultado["ip"] == "185.220.101.1"

    def test_linha_fail_detalhes_contem_usuario(self, linha_auth_fail):
        """Os detalhes devem conter 'usuario=admin'."""
        resultado = parsear_linha_auth(linha_auth_fail)
        assert "usuario=admin" in resultado["detalhes"]

    def test_linha_fail_linha_original(self, linha_auth_fail):
        """A linha original deve ser preservada."""
        resultado = parsear_linha_auth(linha_auth_fail)
        assert resultado["linha_original"] == linha_auth_fail

    def test_linha_ok(self, linha_auth_ok):
        """Linha OK deve ser parseada com tipo 'OK' e IP correto."""
        resultado = parsear_linha_auth(linha_auth_ok)
        assert resultado is not None
        assert resultado["tipo"] == "OK"
        assert resultado["ip"] == "192.168.1.10"
        assert "usuario=carlos" in resultado["detalhes"]

    def test_linha_invalida_retorna_none(self):
        """Linha sem formato valido deve retornar None."""
        resultado = parsear_linha_auth("isso nao eh um log valido")
        assert resultado is None

    def test_linha_vazia_retorna_none(self):
        """Linha vazia deve retornar None."""
        resultado = parsear_linha_auth("")
        assert resultado is None

    def test_linha_parcial_retorna_none(self):
        """Linha com formato parcial deve retornar None."""
        resultado = parsear_linha_auth("2025-02-20 08:15:01 FAIL")
        assert resultado is None


# ============================================================
# Testes de parsear_linha_firewall
# ============================================================

class TestParsearLinhaFirewall:
    """Testes para parsing de linhas do firewall.log."""

    def test_linha_block_retorna_dict(self, linha_firewall_block):
        """Linha BLOCK deve retornar dicionario."""
        resultado = parsear_linha_firewall(linha_firewall_block)
        assert resultado is not None
        assert isinstance(resultado, dict)

    def test_linha_block_campos_obrigatorios(self, linha_firewall_block):
        """Deve conter todos os campos obrigatorios."""
        resultado = parsear_linha_firewall(linha_firewall_block)
        campos = ["timestamp", "fonte", "tipo", "ip", "detalhes", "linha_original"]
        for campo in campos:
            assert campo in resultado, f"Campo '{campo}' ausente"

    def test_linha_block_timestamp(self, linha_firewall_block):
        """Timestamp deve ser extraido corretamente."""
        resultado = parsear_linha_firewall(linha_firewall_block)
        assert resultado["timestamp"] == "2025-02-20 08:10:02"

    def test_linha_block_fonte(self, linha_firewall_block):
        """Fonte deve ser 'firewall'."""
        resultado = parsear_linha_firewall(linha_firewall_block)
        assert resultado["fonte"] == "firewall"

    def test_linha_block_tipo(self, linha_firewall_block):
        """Tipo deve ser 'BLOCK'."""
        resultado = parsear_linha_firewall(linha_firewall_block)
        assert resultado["tipo"] == "BLOCK"

    def test_linha_block_ip_origem(self, linha_firewall_block):
        """O IP deve ser o de origem (src), nao o destino."""
        resultado = parsear_linha_firewall(linha_firewall_block)
        assert resultado["ip"] == "185.220.101.1"

    def test_linha_block_detalhes_contem_dport(self, linha_firewall_block):
        """Detalhes devem conter a porta destino."""
        resultado = parsear_linha_firewall(linha_firewall_block)
        assert "dport=22" in resultado["detalhes"]

    def test_linha_allow(self, linha_firewall_allow):
        """Linha ALLOW deve ser parseada com tipo correto."""
        resultado = parsear_linha_firewall(linha_firewall_allow)
        assert resultado is not None
        assert resultado["tipo"] == "ALLOW"
        assert resultado["ip"] == "192.168.1.10"

    def test_linha_invalida_retorna_none(self):
        """Linha invalida deve retornar None."""
        resultado = parsear_linha_firewall("texto aleatorio")
        assert resultado is None

    def test_linha_vazia_retorna_none(self):
        """Linha vazia deve retornar None."""
        resultado = parsear_linha_firewall("")
        assert resultado is None


# ============================================================
# Testes de parsear_linha_web
# ============================================================

class TestParsearLinhaWeb:
    """Testes para parsing de linhas do web_access.log."""

    def test_linha_get_retorna_dict(self, linha_web_get):
        """Linha GET deve retornar dicionario."""
        resultado = parsear_linha_web(linha_web_get)
        assert resultado is not None
        assert isinstance(resultado, dict)

    def test_linha_get_campos_obrigatorios(self, linha_web_get):
        """Deve conter todos os campos obrigatorios."""
        resultado = parsear_linha_web(linha_web_get)
        campos = ["timestamp", "fonte", "tipo", "ip", "detalhes", "linha_original"]
        for campo in campos:
            assert campo in resultado, f"Campo '{campo}' ausente"

    def test_linha_get_timestamp(self, linha_web_get):
        """Timestamp deve ser extraido corretamente."""
        resultado = parsear_linha_web(linha_web_get)
        assert resultado["timestamp"] == "2025-02-20 08:20:01"

    def test_linha_get_fonte(self, linha_web_get):
        """Fonte deve ser 'web'."""
        resultado = parsear_linha_web(linha_web_get)
        assert resultado["fonte"] == "web"

    def test_linha_get_tipo_metodo_http(self, linha_web_get):
        """Tipo deve ser o metodo HTTP (GET)."""
        resultado = parsear_linha_web(linha_web_get)
        assert resultado["tipo"] == "GET"

    def test_linha_get_ip(self, linha_web_get):
        """IP deve ser extraido corretamente."""
        resultado = parsear_linha_web(linha_web_get)
        assert resultado["ip"] == "192.168.1.10"

    def test_linha_get_detalhes_contem_url(self, linha_web_get):
        """Detalhes devem conter a URL acessada."""
        resultado = parsear_linha_web(linha_web_get)
        assert "url=/index.html" in resultado["detalhes"]

    def test_linha_get_detalhes_contem_status(self, linha_web_get):
        """Detalhes devem conter o status code."""
        resultado = parsear_linha_web(linha_web_get)
        assert "status=200" in resultado["detalhes"]

    def test_linha_xss_preserva_caracteres_especiais(self, linha_web_xss):
        """Linha com XSS deve preservar os caracteres <script> nos detalhes."""
        resultado = parsear_linha_web(linha_web_xss)
        assert resultado is not None
        assert "<script>" in resultado["detalhes"]
        assert resultado["ip"] == "45.33.32.156"

    def test_linha_traversal(self, linha_web_traversal):
        """Linha com path traversal deve ser parseada corretamente."""
        resultado = parsear_linha_web(linha_web_traversal)
        assert resultado is not None
        assert "../" in resultado["detalhes"]
        assert resultado["ip"] == "91.240.118.172"

    def test_linha_invalida_retorna_none(self):
        """Linha invalida deve retornar None."""
        resultado = parsear_linha_web("nao eh log web")
        assert resultado is None

    def test_linha_vazia_retorna_none(self):
        """Linha vazia deve retornar None."""
        resultado = parsear_linha_web("")
        assert resultado is None


# ============================================================
# Testes de carregar_log
# ============================================================

class TestCarregarLog:
    """Testes para leitura e carregamento de arquivos de log."""

    def test_carregar_auth_log(self, pasta_logs):
        """Deve carregar auth.log e retornar lista de eventos."""
        caminho = os.path.join(pasta_logs, "auth.log")
        resultado = carregar_log(caminho, "auth")
        assert isinstance(resultado, list)
        assert len(resultado) == 23  # 23 linhas no auth.log

    def test_carregar_firewall_log(self, pasta_logs):
        """Deve carregar firewall.log corretamente."""
        caminho = os.path.join(pasta_logs, "firewall.log")
        resultado = carregar_log(caminho, "firewall")
        assert isinstance(resultado, list)
        assert len(resultado) == 17  # 17 linhas no firewall.log

    def test_carregar_web_log(self, pasta_logs):
        """Deve carregar web_access.log corretamente."""
        caminho = os.path.join(pasta_logs, "web_access.log")
        resultado = carregar_log(caminho, "web")
        assert isinstance(resultado, list)
        assert len(resultado) == 18  # 18 linhas no web_access.log

    def test_todos_eventos_sao_dicts(self, pasta_logs):
        """Todos os eventos retornados devem ser dicionarios."""
        caminho = os.path.join(pasta_logs, "auth.log")
        resultado = carregar_log(caminho, "auth")
        for evento in resultado:
            assert isinstance(evento, dict)

    def test_arquivo_inexistente_retorna_lista_vazia(self):
        """Arquivo inexistente deve retornar lista vazia, sem travar."""
        resultado = carregar_log("/caminho/que/nao/existe.log", "auth")
        assert resultado == []

    def test_arquivo_vazio_retorna_lista_vazia(self, criar_arquivo_log):
        """Arquivo vazio deve retornar lista vazia."""
        caminho = criar_arquivo_log("vazio.log", "")
        resultado = carregar_log(caminho, "auth")
        assert resultado == []

    def test_linhas_invalidas_sao_ignoradas(self, criar_arquivo_log):
        """Linhas mal formatadas devem ser ignoradas, validas devem funcionar."""
        conteudo = (
            "2025-02-20 08:15:01 FAIL usuario=admin ip=1.2.3.4\n"
            "linha invalida sem formato\n"
            "2025-02-20 08:15:03 OK usuario=carlos ip=192.168.1.10\n"
        )
        caminho = criar_arquivo_log("misto.log", conteudo)
        resultado = carregar_log(caminho, "auth")
        assert len(resultado) == 2  # apenas as 2 linhas validas

    def test_fonte_correta_em_todos_eventos(self, pasta_logs):
        """Todos os eventos devem ter o campo 'fonte' correto."""
        caminho = os.path.join(pasta_logs, "auth.log")
        resultado = carregar_log(caminho, "auth")
        for evento in resultado:
            assert evento["fonte"] == "auth"


# ============================================================
# Testes de carregar_todos_os_logs
# ============================================================

class TestCarregarTodosOsLogs:
    """Testes para carregamento unificado de todos os logs."""

    def test_retorna_lista(self, pasta_logs):
        """Deve retornar uma lista."""
        resultado = carregar_todos_os_logs(pasta_logs)
        assert isinstance(resultado, list)

    def test_carrega_todas_as_fontes(self, pasta_logs):
        """Deve conter eventos das 3 fontes: auth, firewall, web."""
        resultado = carregar_todos_os_logs(pasta_logs)
        fontes = {evento["fonte"] for evento in resultado}
        assert "auth" in fontes
        assert "firewall" in fontes
        assert "web" in fontes

    def test_total_de_eventos(self, pasta_logs):
        """Total deve ser a soma dos 3 arquivos (23 + 17 + 18 = 58)."""
        resultado = carregar_todos_os_logs(pasta_logs)
        assert len(resultado) == 58

    def test_pasta_inexistente_retorna_lista_vazia(self):
        """Pasta inexistente deve retornar lista vazia."""
        resultado = carregar_todos_os_logs("/pasta/que/nao/existe")
        assert resultado == []

    def test_ignora_arquivos_nao_log(self, pasta_temporaria):
        """Deve ignorar arquivos que nao sao .log."""
        # Cria um .log e um .txt na mesma pasta
        with open(os.path.join(pasta_temporaria, "auth.log"), "w") as f:
            f.write("2025-02-20 08:15:01 FAIL usuario=admin ip=1.2.3.4\n")
        with open(os.path.join(pasta_temporaria, "notas.txt"), "w") as f:
            f.write("isso nao eh log\n")
        resultado = carregar_todos_os_logs(pasta_temporaria)
        assert len(resultado) >= 1
        for evento in resultado:
            assert evento["fonte"] in ("auth", "firewall", "web")
