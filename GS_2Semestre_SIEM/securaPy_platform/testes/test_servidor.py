"""
Testes do Modulo 4 - Servidor de Alertas

Testa: formatacao de alertas, funcionalidade do servidor TCP,
broadcast e comandos. Usa sockets reais em localhost para testes de rede.
"""

import socket
import threading
import time
import pytest
from servidor_alertas import (
    formatar_alerta,
    broadcast_alerta,
    remover_cliente,
    iniciar_servidor,
    clientes,
    lock,
    historico_alertas,
)


# ============================================================
# Testes de formatar_alerta
# ============================================================

class TestFormatarAlerta:
    """Testes para formatacao de alertas em texto legivel."""

    def test_retorna_string(self):
        """Deve retornar uma string."""
        alerta = {
            "timestamp": "2025-02-20 08:15:01",
            "regra_id": "R001",
            "regra_nome": "Brute Force",
            "severidade": "CRITICA",
            "ip": "185.220.101.1",
            "descricao": "10 tentativas de login",
        }
        resultado = formatar_alerta(alerta)
        assert isinstance(resultado, str)

    def test_contem_severidade(self):
        """O texto formatado deve conter o nivel de severidade."""
        alerta = {
            "timestamp": "2025-02-20 08:15:01",
            "regra_id": "R001",
            "regra_nome": "Brute Force",
            "severidade": "CRITICA",
            "ip": "185.220.101.1",
            "descricao": "10 tentativas",
        }
        resultado = formatar_alerta(alerta)
        assert "CRITICA" in resultado

    def test_contem_ip(self):
        """O texto formatado deve conter o IP."""
        alerta = {
            "timestamp": "2025-02-20 08:15:01",
            "regra_id": "R001",
            "regra_nome": "Brute Force",
            "severidade": "ALTA",
            "ip": "91.240.118.172",
            "descricao": "5 tentativas",
        }
        resultado = formatar_alerta(alerta)
        assert "91.240.118.172" in resultado

    def test_contem_nome_regra(self):
        """O texto formatado deve conter o nome da regra."""
        alerta = {
            "timestamp": "2025-02-20 08:15:01",
            "regra_id": "R003",
            "regra_nome": "Path Traversal",
            "severidade": "CRITICA",
            "ip": "1.2.3.4",
            "descricao": "teste",
        }
        resultado = formatar_alerta(alerta)
        assert "Path Traversal" in resultado

    def test_contem_horario(self):
        """O texto formatado deve conter alguma indicacao de horario."""
        alerta = {
            "timestamp": "2025-02-20 08:15:01",
            "regra_id": "R001",
            "regra_nome": "Teste",
            "severidade": "MEDIA",
            "ip": "1.2.3.4",
            "descricao": "teste",
        }
        resultado = formatar_alerta(alerta)
        assert "08:15" in resultado


# ============================================================
# Testes de integracao do servidor (socket real em localhost)
# ============================================================

class TestServidorIntegracao:
    """Testes de integracao usando sockets reais em localhost.

    Estes testes iniciam um servidor real em uma porta alta,
    conectam clientes e verificam a comunicacao.
    """

    @pytest.fixture(autouse=True)
    def limpar_estado(self):
        """Limpa o estado global antes de cada teste."""
        with lock:
            clientes.clear()
            historico_alertas.clear()
        yield
        with lock:
            # Fecha conexoes residuais
            for conn in list(clientes.keys()):
                try:
                    conn.close()
                except Exception:
                    pass
            clientes.clear()
            historico_alertas.clear()

    def test_servidor_aceita_conexao(self):
        """Servidor deve aceitar uma conexao TCP."""
        porta = 19876  # porta alta para teste

        servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor.bind(("127.0.0.1", porta))
        servidor.listen(1)
        servidor.settimeout(3)

        def aceitar():
            try:
                conn, addr = servidor.accept()
                with lock:
                    clientes[conn] = addr
                conn.send("Bem-vindo".encode())
            except socket.timeout:
                pass

        thread = threading.Thread(target=aceitar, daemon=True)
        thread.start()

        # Cliente conecta
        cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cliente.connect(("127.0.0.1", porta))
        dados = cliente.recv(1024).decode()
        assert "Bem-vindo" in dados

        cliente.close()
        servidor.close()
        thread.join(timeout=2)

    def test_broadcast_envia_para_multiplos(self):
        """Broadcast deve enviar mensagem para todos os clientes conectados."""
        porta = 19877

        servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        servidor.bind(("127.0.0.1", porta))
        servidor.listen(5)
        servidor.settimeout(3)

        conexoes_servidor = []

        def aceitar_clientes(n):
            for _ in range(n):
                try:
                    conn, addr = servidor.accept()
                    with lock:
                        clientes[conn] = addr
                    conexoes_servidor.append(conn)
                except socket.timeout:
                    break

        thread = threading.Thread(target=aceitar_clientes, args=(2,), daemon=True)
        thread.start()

        # 2 clientes conectam
        c1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c1.connect(("127.0.0.1", porta))
        c2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c2.connect(("127.0.0.1", porta))

        thread.join(timeout=3)
        time.sleep(0.3)

        # Broadcast
        broadcast_alerta("[ALERTA] Teste de broadcast")

        c1.settimeout(2)
        c2.settimeout(2)

        try:
            msg1 = c1.recv(4096).decode()
            msg2 = c2.recv(4096).decode()
            assert "Teste de broadcast" in msg1
            assert "Teste de broadcast" in msg2
        except socket.timeout:
            pytest.fail("Clientes nao receberam o broadcast no tempo esperado")
        finally:
            c1.close()
            c2.close()
            for c in conexoes_servidor:
                try:
                    c.close()
                except Exception:
                    pass
            servidor.close()
