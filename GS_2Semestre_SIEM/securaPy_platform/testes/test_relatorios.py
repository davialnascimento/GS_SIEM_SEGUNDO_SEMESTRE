"""
Testes do Modulo 6 - Dashboard CLI e Relatorios

Testa: filtros de eventos, top IPs, exportacao JSON,
resumo geral e exibicao de tabelas.
"""

import os
import json
import pytest
from relatorios import (
    filtrar_eventos,
    top_ips,
    exportar_relatorio_json,
    resumo_geral,
    exibir_menu,
    exibir_tabela,
)


# ============================================================
# Testes de filtrar_eventos
# ============================================================

class TestFiltrarEventos:
    """Testes para filtragem de eventos por criterios."""

    def test_filtrar_por_fonte_auth(self, eventos_completos):
        """Filtrar por fonte='auth' deve retornar apenas eventos de auth."""
        resultado = filtrar_eventos(eventos_completos, fonte="auth")
        assert all(e["fonte"] == "auth" for e in resultado)
        assert len(resultado) > 0

    def test_filtrar_por_fonte_firewall(self, eventos_completos):
        """Filtrar por fonte='firewall' deve retornar apenas eventos de firewall."""
        resultado = filtrar_eventos(eventos_completos, fonte="firewall")
        assert all(e["fonte"] == "firewall" for e in resultado)

    def test_filtrar_por_fonte_web(self, eventos_completos):
        """Filtrar por fonte='web' deve retornar apenas eventos de web."""
        resultado = filtrar_eventos(eventos_completos, fonte="web")
        assert all(e["fonte"] == "web" for e in resultado)

    def test_filtrar_por_tipo_fail(self, eventos_completos):
        """Filtrar por tipo='FAIL' deve retornar apenas FAILs."""
        resultado = filtrar_eventos(eventos_completos, tipo="FAIL")
        assert all(e["tipo"] == "FAIL" for e in resultado)
        assert len(resultado) > 0

    def test_filtrar_por_tipo_block(self, eventos_completos):
        """Filtrar por tipo='BLOCK' deve retornar apenas BLOCKs."""
        resultado = filtrar_eventos(eventos_completos, tipo="BLOCK")
        assert all(e["tipo"] == "BLOCK" for e in resultado)

    def test_filtrar_por_ip(self, eventos_completos):
        """Filtrar por IP especifico deve retornar apenas eventos desse IP."""
        resultado = filtrar_eventos(eventos_completos, ip="185.220.101.1")
        assert all(e["ip"] == "185.220.101.1" for e in resultado)
        assert len(resultado) > 0

    def test_filtrar_por_fonte_e_tipo(self, eventos_completos):
        """Filtrar por fonte E tipo (ambos os criterios juntos)."""
        resultado = filtrar_eventos(eventos_completos, fonte="auth", tipo="FAIL")
        assert all(e["fonte"] == "auth" and e["tipo"] == "FAIL" for e in resultado)

    def test_filtrar_por_fonte_tipo_e_ip(self, eventos_completos):
        """Filtrar por todos os criterios simultaneamente."""
        resultado = filtrar_eventos(eventos_completos, fonte="auth", tipo="FAIL", ip="185.220.101.1")
        assert all(
            e["fonte"] == "auth" and e["tipo"] == "FAIL" and e["ip"] == "185.220.101.1"
            for e in resultado
        )

    def test_sem_filtros_retorna_todos(self, eventos_completos):
        """Sem nenhum filtro, deve retornar todos os eventos."""
        resultado = filtrar_eventos(eventos_completos)
        assert len(resultado) == len(eventos_completos)

    def test_filtro_sem_match(self, eventos_completos):
        """Filtro que nao encontra nada deve retornar lista vazia."""
        resultado = filtrar_eventos(eventos_completos, ip="999.999.999.999")
        assert resultado == []

    def test_lista_vazia(self):
        """Filtrar lista vazia deve retornar lista vazia."""
        resultado = filtrar_eventos([])
        assert resultado == []


# ============================================================
# Testes de top_ips
# ============================================================

class TestTopIps:
    """Testes para ranking de IPs mais ativos."""

    def test_retorna_lista(self, eventos_completos):
        """Deve retornar uma lista."""
        resultado = top_ips(eventos_completos)
        assert isinstance(resultado, list)

    def test_retorna_tuplas(self, eventos_completos):
        """Cada item deve ser uma tupla (ip, contagem)."""
        resultado = top_ips(eventos_completos)
        for item in resultado:
            assert isinstance(item, tuple)
            assert len(item) == 2

    def test_ordenado_decrescente(self, eventos_completos):
        """Lista deve estar ordenada por contagem decrescente."""
        resultado = top_ips(eventos_completos)
        for i in range(len(resultado) - 1):
            assert resultado[i][1] >= resultado[i + 1][1]

    def test_ip_mais_ativo_primeiro(self, eventos_completos):
        """O IP com mais eventos deve ser o primeiro."""
        resultado = top_ips(eventos_completos)
        # 185.220.101.1 aparece em auth + firewall + web = mais eventos
        assert resultado[0][0] == "185.220.101.1"

    def test_limita_a_n(self, eventos_completos):
        """Deve respeitar o limite N."""
        resultado = top_ips(eventos_completos, n=3)
        assert len(resultado) <= 3

    def test_n_maior_que_total(self, eventos_completos):
        """Se N > total de IPs, retorna todos."""
        resultado = top_ips(eventos_completos, n=100)
        assert len(resultado) > 0

    def test_lista_vazia(self):
        """Lista vazia deve retornar lista vazia."""
        resultado = top_ips([])
        assert resultado == []


# ============================================================
# Testes de exportar_relatorio_json
# ============================================================

class TestExportarRelatorioJson:
    """Testes para exportacao de relatorios em JSON."""

    def test_cria_arquivo(self, pasta_temporaria):
        """Deve criar o arquivo JSON."""
        caminho = os.path.join(pasta_temporaria, "relatorio.json")
        dados = {"total_eventos": 58, "alertas": []}
        exportar_relatorio_json(dados, caminho)
        assert os.path.exists(caminho)

    def test_conteudo_valido(self, pasta_temporaria):
        """Arquivo criado deve conter JSON valido."""
        caminho = os.path.join(pasta_temporaria, "relatorio.json")
        dados = {"total_eventos": 58, "alertas": ["teste"]}
        exportar_relatorio_json(dados, caminho)
        with open(caminho, "r") as f:
            conteudo = json.load(f)
        assert conteudo["total_eventos"] == 58

    def test_cria_diretorio_se_necessario(self, pasta_temporaria):
        """Deve criar subdiretorios que nao existam."""
        caminho = os.path.join(pasta_temporaria, "sub", "pasta", "relatorio.json")
        dados = {"teste": True}
        exportar_relatorio_json(dados, caminho)
        assert os.path.exists(caminho)

    def test_json_formatado(self, pasta_temporaria):
        """JSON deve ser formatado com indentacao (indent=2)."""
        caminho = os.path.join(pasta_temporaria, "relatorio.json")
        dados = {"chave": "valor"}
        exportar_relatorio_json(dados, caminho)
        with open(caminho, "r") as f:
            conteudo = f.read()
        assert "\n" in conteudo  # formatado, nao em uma linha so

    def test_suporta_caracteres_especiais(self, pasta_temporaria):
        """Deve suportar acentos e caracteres especiais (ensure_ascii=False)."""
        caminho = os.path.join(pasta_temporaria, "relatorio.json")
        dados = {"descricao": "Tentativa de invasao detectada"}
        exportar_relatorio_json(dados, caminho)
        with open(caminho, "r") as f:
            conteudo = f.read()
        assert "invasao" in conteudo  # nao deve estar escapado


# ============================================================
# Testes de resumo_geral (verifica que nao trava)
# ============================================================

class TestResumoGeral:
    """Testes para exibicao de resumo geral."""

    def test_nao_trava_com_dados(self, eventos_completos, capsys):
        """Deve executar sem erros e imprimir algo."""
        alertas = [
            {"severidade": "CRITICA", "ip": "1.2.3.4"},
            {"severidade": "ALTA", "ip": "5.6.7.8"},
            {"severidade": "ALTA", "ip": "1.2.3.4"},
        ]
        resumo_geral(eventos_completos, alertas)
        capturado = capsys.readouterr()
        assert len(capturado.out) > 0  # imprimiu algo

    def test_nao_trava_com_dados_vazios(self, capsys):
        """Deve executar sem erros mesmo com listas vazias."""
        resumo_geral([], [])
        # Se nao lancou excecao, passou


# ============================================================
# Testes de exibir_menu
# ============================================================

class TestExibirMenu:
    """Testes para exibicao do menu e captura de opcao."""

    def test_opcao_valida(self, monkeypatch, capsys):
        """Deve retornar int quando usuario digita numero valido."""
        monkeypatch.setattr("builtins.input", lambda _="": "1")
        resultado = exibir_menu()
        assert resultado == 1

    def test_opcao_zero(self, monkeypatch):
        """Deve aceitar opcao 0 (sair)."""
        monkeypatch.setattr("builtins.input", lambda _="": "0")
        resultado = exibir_menu()
        assert resultado == 0

    def test_opcao_invalida(self, monkeypatch):
        """Entrada invalida deve retornar -1."""
        monkeypatch.setattr("builtins.input", lambda _="": "abc")
        resultado = exibir_menu()
        assert resultado == -1


# ============================================================
# Testes de exibir_tabela
# ============================================================

class TestExibirTabela:
    """Testes para exibicao de tabela formatada."""

    def test_nao_trava(self, capsys):
        """Deve executar sem erros."""
        dados = [
            {"ip": "1.2.3.4", "eventos": 10},
            {"ip": "5.6.7.8", "eventos": 5},
        ]
        exibir_tabela(dados, ["ip", "eventos"])
        capturado = capsys.readouterr()
        assert "1.2.3.4" in capturado.out

    def test_lista_vazia(self, capsys):
        """Lista vazia deve exibir mensagem, nao travar."""
        exibir_tabela([], ["ip", "eventos"])
        # Se nao lancou excecao, passou
