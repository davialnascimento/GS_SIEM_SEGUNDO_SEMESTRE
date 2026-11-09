"""
Fixtures compartilhadas por todos os testes.
Fornece dados de teste padronizados: eventos, alertas, regras, caminhos.
"""

import os
import sys
import json
import pytest
import tempfile
import shutil

# Adiciona o diretorio raiz do projeto ao path para imports funcionarem
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ============================================================
# Caminhos
# ============================================================

@pytest.fixture
def pasta_projeto():
    """Retorna o caminho raiz do projeto securaPy."""
    return os.path.join(os.path.dirname(__file__), "..")


@pytest.fixture
def pasta_logs(pasta_projeto):
    """Retorna o caminho da pasta de logs do projeto."""
    return os.path.join(pasta_projeto, "logs")


@pytest.fixture
def caminho_regras(pasta_projeto):
    """Retorna o caminho do arquivo regras.json."""
    return os.path.join(pasta_projeto, "config", "regras.json")


@pytest.fixture
def pasta_temporaria():
    """Cria uma pasta temporaria para testes e limpa depois."""
    pasta = tempfile.mkdtemp()
    yield pasta
    shutil.rmtree(pasta)


# ============================================================
# Dados de teste — Linhas de log
# ============================================================

@pytest.fixture
def linha_auth_fail():
    return "2025-02-20 08:15:01 FAIL usuario=admin ip=185.220.101.1"


@pytest.fixture
def linha_auth_ok():
    return "2025-02-20 08:15:03 OK usuario=carlos ip=192.168.1.10"


@pytest.fixture
def linha_firewall_block():
    return "2025-02-20 08:10:02 BLOCK proto=TCP src=185.220.101.1 dst=10.0.0.1 dport=22"


@pytest.fixture
def linha_firewall_allow():
    return "2025-02-20 08:10:01 ALLOW proto=TCP src=192.168.1.10 dst=10.0.0.1 dport=443"


@pytest.fixture
def linha_web_get():
    return "2025-02-20 08:20:01 GET url=/index.html ip=192.168.1.10 status=200"


@pytest.fixture
def linha_web_xss():
    return "2025-02-20 08:20:15 GET url=/search?q=<script>alert(1)</script> ip=45.33.32.156 status=400"


@pytest.fixture
def linha_web_traversal():
    return "2025-02-20 08:20:08 GET url=/../../etc/passwd ip=91.240.118.172 status=400"


# ============================================================
# Dados de teste — Eventos normalizados
# ============================================================

@pytest.fixture
def evento_auth_fail():
    return {
        "timestamp": "2025-02-20 08:15:01",
        "fonte": "auth",
        "tipo": "FAIL",
        "ip": "185.220.101.1",
        "detalhes": "usuario=admin",
        "linha_original": "2025-02-20 08:15:01 FAIL usuario=admin ip=185.220.101.1",
    }


@pytest.fixture
def evento_auth_ok():
    return {
        "timestamp": "2025-02-20 08:15:03",
        "fonte": "auth",
        "tipo": "OK",
        "ip": "192.168.1.10",
        "detalhes": "usuario=carlos",
        "linha_original": "2025-02-20 08:15:03 OK usuario=carlos ip=192.168.1.10",
    }


@pytest.fixture
def evento_firewall_block():
    return {
        "timestamp": "2025-02-20 08:10:02",
        "fonte": "firewall",
        "tipo": "BLOCK",
        "ip": "185.220.101.1",
        "detalhes": "proto=TCP dst=10.0.0.1 dport=22",
        "linha_original": "2025-02-20 08:10:02 BLOCK proto=TCP src=185.220.101.1 dst=10.0.0.1 dport=22",
    }


@pytest.fixture
def evento_web_normal():
    return {
        "timestamp": "2025-02-20 08:20:01",
        "fonte": "web",
        "tipo": "GET",
        "ip": "192.168.1.10",
        "detalhes": "url=/index.html status=200",
        "linha_original": "2025-02-20 08:20:01 GET url=/index.html ip=192.168.1.10 status=200",
    }


@pytest.fixture
def evento_web_xss():
    return {
        "timestamp": "2025-02-20 08:20:15",
        "fonte": "web",
        "tipo": "GET",
        "ip": "45.33.32.156",
        "detalhes": "url=/search?q=<script>alert(1)</script> status=400",
        "linha_original": "2025-02-20 08:20:15 GET url=/search?q=<script>alert(1)</script> ip=45.33.32.156 status=400",
    }


@pytest.fixture
def evento_web_traversal():
    return {
        "timestamp": "2025-02-20 08:20:08",
        "fonte": "web",
        "tipo": "GET",
        "ip": "91.240.118.172",
        "detalhes": "url=/../../etc/passwd status=400",
        "linha_original": "2025-02-20 08:20:08 GET url=/../../etc/passwd ip=91.240.118.172 status=400",
    }


@pytest.fixture
def evento_web_recon():
    return {
        "timestamp": "2025-02-20 08:20:18",
        "fonte": "web",
        "tipo": "GET",
        "ip": "91.240.118.172",
        "detalhes": "url=/wp-admin status=404",
        "linha_original": "2025-02-20 08:20:18 GET url=/wp-admin ip=91.240.118.172 status=404",
    }


# ============================================================
# Lista de eventos para testes de detector e relatorios
# ============================================================

@pytest.fixture
def eventos_completos():
    """Lista de eventos simulando o carregamento completo dos 3 logs."""
    return [
        # Auth - brute force de 185.220.101.1 (10 FAILs)
        {"timestamp": "2025-02-20 08:15:01", "fonte": "auth", "tipo": "FAIL", "ip": "185.220.101.1", "detalhes": "usuario=admin", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:15:02", "fonte": "auth", "tipo": "FAIL", "ip": "185.220.101.1", "detalhes": "usuario=root", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:15:06", "fonte": "auth", "tipo": "FAIL", "ip": "185.220.101.1", "detalhes": "usuario=test", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:15:08", "fonte": "auth", "tipo": "FAIL", "ip": "185.220.101.1", "detalhes": "usuario=admin", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:15:16", "fonte": "auth", "tipo": "FAIL", "ip": "185.220.101.1", "detalhes": "usuario=admin", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:15:18", "fonte": "auth", "tipo": "FAIL", "ip": "185.220.101.1", "detalhes": "usuario=root", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:15:22", "fonte": "auth", "tipo": "FAIL", "ip": "185.220.101.1", "detalhes": "usuario=admin", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:15:28", "fonte": "auth", "tipo": "FAIL", "ip": "185.220.101.1", "detalhes": "usuario=sa", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:15:33", "fonte": "auth", "tipo": "FAIL", "ip": "185.220.101.1", "detalhes": "usuario=root", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:15:38", "fonte": "auth", "tipo": "FAIL", "ip": "185.220.101.1", "detalhes": "usuario=admin", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:15:40", "fonte": "auth", "tipo": "FAIL", "ip": "185.220.101.1", "detalhes": "usuario=root", "linha_original": "..."},
        # Auth - 91.240.118.172 (5 FAILs)
        {"timestamp": "2025-02-20 08:15:05", "fonte": "auth", "tipo": "FAIL", "ip": "91.240.118.172", "detalhes": "usuario=admin", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:15:12", "fonte": "auth", "tipo": "FAIL", "ip": "91.240.118.172", "detalhes": "usuario=root", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:15:20", "fonte": "auth", "tipo": "FAIL", "ip": "91.240.118.172", "detalhes": "usuario=guest", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:15:30", "fonte": "auth", "tipo": "FAIL", "ip": "91.240.118.172", "detalhes": "usuario=admin", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:15:45", "fonte": "auth", "tipo": "FAIL", "ip": "91.240.118.172", "detalhes": "usuario=admin", "linha_original": "..."},
        # Auth - 45.33.32.156 (3 FAILs)
        {"timestamp": "2025-02-20 08:15:15", "fonte": "auth", "tipo": "FAIL", "ip": "45.33.32.156", "detalhes": "usuario=admin", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:15:35", "fonte": "auth", "tipo": "FAIL", "ip": "45.33.32.156", "detalhes": "usuario=test", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:15:48", "fonte": "auth", "tipo": "FAIL", "ip": "45.33.32.156", "detalhes": "usuario=oracle", "linha_original": "..."},
        # Auth - OKs (internos)
        {"timestamp": "2025-02-20 08:15:03", "fonte": "auth", "tipo": "OK", "ip": "192.168.1.10", "detalhes": "usuario=carlos", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:15:10", "fonte": "auth", "tipo": "OK", "ip": "192.168.1.45", "detalhes": "usuario=ana", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:15:25", "fonte": "auth", "tipo": "OK", "ip": "10.0.0.5", "detalhes": "usuario=bruno", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:15:42", "fonte": "auth", "tipo": "OK", "ip": "192.168.1.20", "detalhes": "usuario=diana", "linha_original": "..."},
        # Firewall - 185.220.101.1 (7 portas: 22,23,445,8080,3306,21,139)
        {"timestamp": "2025-02-20 08:10:02", "fonte": "firewall", "tipo": "BLOCK", "ip": "185.220.101.1", "detalhes": "proto=TCP dst=10.0.0.1 dport=22", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:10:06", "fonte": "firewall", "tipo": "BLOCK", "ip": "185.220.101.1", "detalhes": "proto=TCP dst=10.0.0.1 dport=23", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:10:10", "fonte": "firewall", "tipo": "BLOCK", "ip": "185.220.101.1", "detalhes": "proto=TCP dst=10.0.0.1 dport=445", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:10:18", "fonte": "firewall", "tipo": "BLOCK", "ip": "185.220.101.1", "detalhes": "proto=TCP dst=10.0.0.1 dport=8080", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:10:22", "fonte": "firewall", "tipo": "BLOCK", "ip": "185.220.101.1", "detalhes": "proto=TCP dst=10.0.0.1 dport=3306", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:10:30", "fonte": "firewall", "tipo": "BLOCK", "ip": "185.220.101.1", "detalhes": "proto=TCP dst=10.0.0.1 dport=21", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:10:35", "fonte": "firewall", "tipo": "BLOCK", "ip": "185.220.101.1", "detalhes": "proto=TCP dst=10.0.0.1 dport=139", "linha_original": "..."},
        # Firewall - 91.240.118.172 (3 portas: 3389, 22, 445)
        {"timestamp": "2025-02-20 08:10:05", "fonte": "firewall", "tipo": "BLOCK", "ip": "91.240.118.172", "detalhes": "proto=TCP dst=10.0.0.1 dport=3389", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:10:20", "fonte": "firewall", "tipo": "BLOCK", "ip": "91.240.118.172", "detalhes": "proto=TCP dst=10.0.0.1 dport=22", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:10:33", "fonte": "firewall", "tipo": "BLOCK", "ip": "91.240.118.172", "detalhes": "proto=TCP dst=10.0.0.1 dport=445", "linha_original": "..."},
        # Firewall - 45.33.32.156 (2 portas: 1433, 5432)
        {"timestamp": "2025-02-20 08:10:12", "fonte": "firewall", "tipo": "BLOCK", "ip": "45.33.32.156", "detalhes": "proto=TCP dst=10.0.0.1 dport=1433", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:10:28", "fonte": "firewall", "tipo": "BLOCK", "ip": "45.33.32.156", "detalhes": "proto=TCP dst=10.0.0.1 dport=5432", "linha_original": "..."},
        # Firewall - ALLOWs (internos)
        {"timestamp": "2025-02-20 08:10:01", "fonte": "firewall", "tipo": "ALLOW", "ip": "192.168.1.10", "detalhes": "proto=TCP dst=10.0.0.1 dport=443", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:10:03", "fonte": "firewall", "tipo": "ALLOW", "ip": "192.168.1.45", "detalhes": "proto=TCP dst=10.0.0.1 dport=80", "linha_original": "..."},
        # Web - eventos normais
        {"timestamp": "2025-02-20 08:20:01", "fonte": "web", "tipo": "GET", "ip": "192.168.1.10", "detalhes": "url=/index.html status=200", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:20:10", "fonte": "web", "tipo": "GET", "ip": "192.168.1.45", "detalhes": "url=/index.html status=200", "linha_original": "..."},
        # Web - ataques
        {"timestamp": "2025-02-20 08:20:08", "fonte": "web", "tipo": "GET", "ip": "91.240.118.172", "detalhes": "url=/../../etc/passwd status=400", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:20:15", "fonte": "web", "tipo": "GET", "ip": "45.33.32.156", "detalhes": "url=/search?q=<script>alert(1)</script> status=400", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:20:18", "fonte": "web", "tipo": "GET", "ip": "91.240.118.172", "detalhes": "url=/wp-admin status=404", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:20:20", "fonte": "web", "tipo": "GET", "ip": "91.240.118.172", "detalhes": "url=/phpmyadmin status=404", "linha_original": "..."},
        {"timestamp": "2025-02-20 08:20:28", "fonte": "web", "tipo": "GET", "ip": "45.33.32.156", "detalhes": "url=/shell.php status=404", "linha_original": "..."},
    ]


@pytest.fixture
def blacklist():
    """Blacklist padrao para testes."""
    return {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}


@pytest.fixture
def regras_teste():
    """Lista de regras para testes (equivalente ao regras.json)."""
    return [
        {
            "id": "R001",
            "nome": "Login com Usuario Privilegiado",
            "descricao": "Tentativa de login com usuario root, admin, sa ou oracle",
            "fonte": "auth",
            "condicao": "usuario_privilegiado",
            "usuarios_alvo": ["root", "admin", "sa", "oracle", "administrator"],
            "severidade_base": 6,
            "ativa": True,
        },
        {
            "id": "R002",
            "nome": "Acesso a Porta Critica Bloqueado",
            "descricao": "Firewall bloqueou acesso a portas sensiveis",
            "fonte": "firewall",
            "condicao": "porta_critica",
            "portas_criticas": [22, 23, 3389, 445, 3306, 5432, 1433],
            "severidade_base": 7,
            "ativa": True,
        },
        {
            "id": "R003",
            "nome": "Tentativa de Path Traversal",
            "descricao": "URL contem padroes de path traversal (../)",
            "fonte": "web",
            "condicao": "path_traversal",
            "padroes": ["../", "..\\", "/etc/passwd", "/etc/shadow"],
            "severidade_base": 9,
            "ativa": True,
        },
        {
            "id": "R004",
            "nome": "Tentativa de XSS",
            "descricao": "URL contem padroes de Cross-Site Scripting",
            "fonte": "web",
            "condicao": "xss",
            "padroes": ["<script>", "javascript:", "onerror=", "onload="],
            "severidade_base": 8,
            "ativa": True,
        },
        {
            "id": "R005",
            "nome": "Reconhecimento Web",
            "descricao": "Acesso a URLs comuns de reconhecimento",
            "fonte": "web",
            "condicao": "reconhecimento",
            "urls_suspeitas": ["/wp-admin", "/phpmyadmin", "/shell.php", "/.env", "/admin", "/wp-login.php"],
            "severidade_base": 5,
            "ativa": True,
        },
    ]


# ============================================================
# Helpers para criacao de arquivos temporarios de teste
# ============================================================

@pytest.fixture
def criar_arquivo_log(pasta_temporaria):
    """Factory fixture: cria um arquivo de log temporario com conteudo customizado."""
    def _criar(nome, conteudo):
        caminho = os.path.join(pasta_temporaria, nome)
        with open(caminho, "w") as f:
            f.write(conteudo)
        return caminho
    return _criar


@pytest.fixture
def criar_regras_json(pasta_temporaria):
    """Factory fixture: cria um arquivo regras.json temporario."""
    def _criar(regras, nome="regras.json"):
        caminho = os.path.join(pasta_temporaria, nome)
        with open(caminho, "w") as f:
            json.dump({"regras": regras}, f)
        return caminho
    return _criar
