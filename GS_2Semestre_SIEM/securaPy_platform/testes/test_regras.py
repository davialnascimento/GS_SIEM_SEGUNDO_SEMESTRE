"""
Testes do Modulo 2 - Motor de Regras

Testa: carregamento de configuracao JSON, classificacao de severidade,
avaliacao de cada tipo de regra, aplicacao de regras a listas de eventos.
"""

import os
import json
import pytest
from regras import (
    carregar_regras,
    classificar_severidade,
    avaliar_regra,
    aplicar_regras,
)


# ============================================================
# Testes de carregar_regras
# ============================================================

class TestCarregarRegras:
    """Testes para carregamento de regras do arquivo JSON."""

    def test_carrega_arquivo_valido(self, caminho_regras):
        """Deve carregar regras do arquivo regras.json do projeto."""
        resultado = carregar_regras(caminho_regras)
        assert isinstance(resultado, list)
        assert len(resultado) > 0

    def test_todas_regras_sao_dicts(self, caminho_regras):
        """Cada regra deve ser um dicionario."""
        resultado = carregar_regras(caminho_regras)
        for regra in resultado:
            assert isinstance(regra, dict)

    def test_regras_tem_campos_obrigatorios(self, caminho_regras):
        """Cada regra deve ter id, nome, fonte, condicao, severidade_base."""
        resultado = carregar_regras(caminho_regras)
        campos = ["id", "nome", "fonte", "condicao", "severidade_base"]
        for regra in resultado:
            for campo in campos:
                assert campo in regra, f"Regra {regra.get('id', '?')} sem campo '{campo}'"

    def test_carrega_5_regras(self, caminho_regras):
        """Deve carregar exatamente 5 regras ativas."""
        resultado = carregar_regras(caminho_regras)
        assert len(resultado) == 5

    def test_arquivo_inexistente_retorna_lista_vazia(self):
        """Arquivo inexistente deve retornar lista vazia."""
        resultado = carregar_regras("/caminho/invalido/regras.json")
        assert resultado == []

    def test_json_invalido_retorna_lista_vazia(self, criar_arquivo_log):
        """JSON malformado deve retornar lista vazia."""
        caminho = criar_arquivo_log("regras_quebrado.json", "{isso nao eh json valido")
        resultado = carregar_regras(caminho)
        assert resultado == []

    def test_filtra_regras_inativas(self, criar_regras_json):
        """Regras com 'ativa': false devem ser filtradas."""
        regras = [
            {"id": "R001", "nome": "Ativa", "fonte": "auth", "condicao": "teste",
             "severidade_base": 5, "ativa": True},
            {"id": "R002", "nome": "Inativa", "fonte": "auth", "condicao": "teste",
             "severidade_base": 5, "ativa": False},
        ]
        caminho = criar_regras_json(regras)
        resultado = carregar_regras(caminho)
        assert len(resultado) == 1
        assert resultado[0]["id"] == "R001"

    def test_todas_inativas_retorna_lista_vazia(self, criar_regras_json):
        """Se todas as regras estiverem inativas, retorna lista vazia."""
        regras = [
            {"id": "R001", "nome": "Inativa", "fonte": "auth", "condicao": "teste",
             "severidade_base": 5, "ativa": False},
        ]
        caminho = criar_regras_json(regras)
        resultado = carregar_regras(caminho)
        assert resultado == []


# ============================================================
# Testes de classificar_severidade
# ============================================================

class TestClassificarSeveridade:
    """Testes para conversao de pontuacao em nivel de severidade."""

    def test_critica(self):
        """Pontuacao >= 9 deve retornar CRITICA."""
        assert classificar_severidade(9) == "CRITICA"
        assert classificar_severidade(10) == "CRITICA"
        assert classificar_severidade(15) == "CRITICA"

    def test_alta(self):
        """Pontuacao >= 7 e < 9 deve retornar ALTA."""
        assert classificar_severidade(7) == "ALTA"
        assert classificar_severidade(8) == "ALTA"
        assert classificar_severidade(8.9) == "ALTA"

    def test_media(self):
        """Pontuacao >= 5 e < 7 deve retornar MEDIA."""
        assert classificar_severidade(5) == "MEDIA"
        assert classificar_severidade(6) == "MEDIA"
        assert classificar_severidade(6.9) == "MEDIA"

    def test_baixa(self):
        """Pontuacao >= 3 e < 5 deve retornar BAIXA."""
        assert classificar_severidade(3) == "BAIXA"
        assert classificar_severidade(4) == "BAIXA"

    def test_info(self):
        """Pontuacao < 3 deve retornar INFO."""
        assert classificar_severidade(2) == "INFO"
        assert classificar_severidade(1) == "INFO"
        assert classificar_severidade(0) == "INFO"


# ============================================================
# Testes de avaliar_regra
# ============================================================

class TestAvaliarRegra:
    """Testes para avaliacao de uma regra contra um evento."""

    # --- R001: Usuario Privilegiado ---

    def test_r001_detecta_admin(self, regras_teste, evento_auth_fail):
        """R001 deve disparar para usuario=admin."""
        regra = regras_teste[0]  # R001
        resultado = avaliar_regra(regra, evento_auth_fail)
        assert resultado is not None

    def test_r001_alerta_tem_campos(self, regras_teste, evento_auth_fail):
        """Alerta gerado deve ter todos os campos obrigatorios."""
        regra = regras_teste[0]
        resultado = avaliar_regra(regra, evento_auth_fail)
        campos = ["timestamp", "regra_id", "regra_nome", "severidade", "ip", "descricao"]
        for campo in campos:
            assert campo in resultado, f"Campo '{campo}' ausente no alerta"

    def test_r001_alerta_severidade_correta(self, regras_teste, evento_auth_fail):
        """R001 tem severidade_base 6, que deve ser classificada como MEDIA."""
        regra = regras_teste[0]
        resultado = avaliar_regra(regra, evento_auth_fail)
        assert resultado["severidade"] == "MEDIA"

    def test_r001_alerta_ip_correto(self, regras_teste, evento_auth_fail):
        """Alerta deve conter o IP do evento."""
        regra = regras_teste[0]
        resultado = avaliar_regra(regra, evento_auth_fail)
        assert resultado["ip"] == "185.220.101.1"

    def test_r001_ignora_usuario_normal(self, regras_teste, evento_auth_ok):
        """R001 nao deve disparar para usuario=carlos (nao privilegiado)."""
        regra = regras_teste[0]
        resultado = avaliar_regra(regra, evento_auth_ok)
        assert resultado is None

    def test_r001_ignora_fonte_errada(self, regras_teste, evento_firewall_block):
        """R001 (auth) nao deve avaliar eventos de firewall."""
        regra = regras_teste[0]
        resultado = avaliar_regra(regra, evento_firewall_block)
        assert resultado is None

    # --- R002: Porta Critica ---

    def test_r002_detecta_porta_22(self, regras_teste, evento_firewall_block):
        """R002 deve disparar para BLOCK na porta 22."""
        regra = regras_teste[1]  # R002
        resultado = avaliar_regra(regra, evento_firewall_block)
        assert resultado is not None

    def test_r002_severidade_alta(self, regras_teste, evento_firewall_block):
        """R002 tem severidade_base 7, classificada como ALTA."""
        regra = regras_teste[1]
        resultado = avaliar_regra(regra, evento_firewall_block)
        assert resultado["severidade"] == "ALTA"

    def test_r002_ignora_porta_normal(self, regras_teste):
        """R002 nao deve disparar para portas nao criticas (ex: 80)."""
        regra = regras_teste[1]
        evento = {
            "timestamp": "2025-02-20 08:10:03",
            "fonte": "firewall",
            "tipo": "BLOCK",
            "ip": "1.2.3.4",
            "detalhes": "proto=TCP dst=10.0.0.1 dport=80",
            "linha_original": "...",
        }
        resultado = avaliar_regra(regra, evento)
        assert resultado is None

    # --- R003: Path Traversal ---

    def test_r003_detecta_traversal(self, regras_teste, evento_web_traversal):
        """R003 deve disparar para URL com ../."""
        regra = regras_teste[2]  # R003
        resultado = avaliar_regra(regra, evento_web_traversal)
        assert resultado is not None

    def test_r003_severidade_critica(self, regras_teste, evento_web_traversal):
        """R003 tem severidade_base 9, classificada como CRITICA."""
        regra = regras_teste[2]
        resultado = avaliar_regra(regra, evento_web_traversal)
        assert resultado["severidade"] == "CRITICA"

    def test_r003_ignora_url_normal(self, regras_teste, evento_web_normal):
        """R003 nao deve disparar para URL normal (/index.html)."""
        regra = regras_teste[2]
        resultado = avaliar_regra(regra, evento_web_normal)
        assert resultado is None

    # --- R004: XSS ---

    def test_r004_detecta_xss(self, regras_teste, evento_web_xss):
        """R004 deve disparar para URL com <script>."""
        regra = regras_teste[3]  # R004
        resultado = avaliar_regra(regra, evento_web_xss)
        assert resultado is not None

    def test_r004_severidade_alta(self, regras_teste, evento_web_xss):
        """R004 tem severidade_base 8, classificada como ALTA."""
        regra = regras_teste[3]
        resultado = avaliar_regra(regra, evento_web_xss)
        assert resultado["severidade"] == "ALTA"

    # --- R005: Reconhecimento ---

    def test_r005_detecta_wp_admin(self, regras_teste, evento_web_recon):
        """R005 deve disparar para acesso a /wp-admin."""
        regra = regras_teste[4]  # R005
        resultado = avaliar_regra(regra, evento_web_recon)
        assert resultado is not None

    def test_r005_severidade_media(self, regras_teste, evento_web_recon):
        """R005 tem severidade_base 5, classificada como MEDIA."""
        regra = regras_teste[4]
        resultado = avaliar_regra(regra, evento_web_recon)
        assert resultado["severidade"] == "MEDIA"

    def test_r005_ignora_url_normal(self, regras_teste, evento_web_normal):
        """R005 nao deve disparar para /index.html."""
        regra = regras_teste[4]
        resultado = avaliar_regra(regra, evento_web_normal)
        assert resultado is None


# ============================================================
# Testes de aplicar_regras
# ============================================================

class TestAplicarRegras:
    """Testes para aplicacao de todas as regras em listas de eventos."""

    def test_retorna_lista(self, regras_teste, evento_auth_fail):
        """Deve retornar uma lista."""
        resultado = aplicar_regras([evento_auth_fail], regras_teste)
        assert isinstance(resultado, list)

    def test_gera_alerta_para_evento_suspeito(self, regras_teste, evento_auth_fail):
        """Evento com usuario=admin deve gerar pelo menos 1 alerta."""
        resultado = aplicar_regras([evento_auth_fail], regras_teste)
        assert len(resultado) >= 1

    def test_nao_gera_alerta_para_evento_normal(self, regras_teste, evento_web_normal):
        """Evento normal (/index.html de IP interno) nao deve gerar alertas."""
        resultado = aplicar_regras([evento_web_normal], regras_teste)
        assert len(resultado) == 0

    def test_evento_pode_violar_multiplas_regras(self, regras_teste, evento_web_traversal):
        """Path traversal com /etc/passwd pode disparar R003 (traversal)."""
        resultado = aplicar_regras([evento_web_traversal], regras_teste)
        assert len(resultado) >= 1

    def test_multiplos_eventos_multiplos_alertas(self, regras_teste,
                                                  evento_auth_fail,
                                                  evento_firewall_block,
                                                  evento_web_xss):
        """3 eventos suspeitos devem gerar ao menos 3 alertas."""
        eventos = [evento_auth_fail, evento_firewall_block, evento_web_xss]
        resultado = aplicar_regras(eventos, regras_teste)
        assert len(resultado) >= 3

    def test_lista_vazia_de_eventos(self, regras_teste):
        """Lista vazia de eventos deve retornar lista vazia de alertas."""
        resultado = aplicar_regras([], regras_teste)
        assert resultado == []

    def test_lista_vazia_de_regras(self, evento_auth_fail):
        """Lista vazia de regras deve retornar lista vazia de alertas."""
        resultado = aplicar_regras([evento_auth_fail], [])
        assert resultado == []
