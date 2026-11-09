"""
Modulo 4a - Servidor de Alertas em Tempo Real
Servidor TCP que aceita conexoes de multiplos clientes e
faz broadcast de alertas de seguranca para todos.

Desenvolvido por: Amanda

Comandos suportados:
    /status    - quantos clientes conectados e alertas na sessao
    /historico - ultimos 10 alertas
    /sair      - desconecta do servidor
"""

import socket
import threading
from datetime import datetime

HOST = "0.0.0.0"
PORTA = 9999
MAX_CLIENTES = 10

# Estado global compartilhado entre threads
clientes = {}
lock = threading.Lock()
historico_alertas = []


def formatar_alerta(alerta_dict):
    """
    Converte um dicionario de alerta em string legivel para o terminal
    Formato: [HH:MM:SS] [SEVERIDADE] Regra - IP - Descricao
    """
    timestamp = alerta_dict.get("timestamp", "")
    hora = timestamp.split(" ")[-1] if " " in timestamp else timestamp
    severidade = alerta_dict.get("severidade", "INFO")
    regra_nome = alerta_dict.get("regra_nome", "Alerta")
    ip = alerta_dict.get("ip", "N/A")
    descricao = alerta_dict.get("descricao", "")

    return f"[{hora}] [{severidade}] {regra_nome} - {ip} - {descricao}"


def broadcast_alerta(alerta):
    """
    Envia um alerta para todos os clientes conectados
    Se o alerta for dicionario, formata antes de enviar
    Clientes que falharem sao removidos automaticamente
    """
    global historico_alertas

    mensagem = formatar_alerta(alerta) if isinstance(alerta, dict) else str(alerta)
    historico_alertas.append(mensagem)

    # Coleta a lista de conexoes com lock para evitar problemas de concorrencia
    with lock:
        conexoes = list(clientes.keys())

    clientes_com_falha = []
    for conexao in conexoes:
        try:
            conexao.send((mensagem + "\n").encode())
        except (ConnectionResetError, BrokenPipeError, OSError):
            clientes_com_falha.append(conexao)

    # Remove clientes que nao responderam
    for conexao in clientes_com_falha:
        remover_cliente(conexao)

    if conexoes:
        print(f"[BROADCAST] Alerta enviado para {len(conexoes)} cliente(s): {mensagem}")


def remover_cliente(conexao):
    """
    Remove um cliente da lista e fecha sua conexao com seguranca
    """
    with lock:
        endereco = clientes.pop(conexao, None)

    if endereco:
        print(f"[SERVIDOR] Cliente desconectado: {endereco[0]}:{endereco[1]}")

    try:
        conexao.close()
    except OSError:
        pass


def tratar_cliente(conexao, endereco):
    """
    Gerencia a comunicacao com um cliente individual
    Roda em thread separada para nao bloquear o servidor
    """
    # Registra o novo cliente
    with lock:
        clientes[conexao] = endereco

    print(f"[SERVIDOR] Cliente conectado: {endereco[0]}:{endereco[1]}")

    # Mensagem de boas-vindas
    boas_vindas = (
        "=== SecuraPy SIEM - Console de Monitoramento ===\n"
        f"Conectado em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        "Comandos: /status  /historico  /sair\n"
        "-------------------------------------------------\n"
    )
    try:
        conexao.send(boas_vindas.encode())
    except (ConnectionResetError, BrokenPipeError, OSError):
        remover_cliente(conexao)
        return

    # Loop de recepcao de comandos do cliente
    try:
        while True:
            dados = conexao.recv(1024).decode("utf-8", errors="replace").strip()

            if not dados:
                break  # Cliente fechou a conexao

            if dados == "/sair":
                try:
                    conexao.send("Ate logo! Desconectando...\n".encode())
                except OSError:
                    pass
                break

            elif dados == "/status":
                with lock:
                    total_clientes = len(clientes)
                total_alertas = len(historico_alertas)
                resposta = f"Clientes conectados: {total_clientes} | Alertas na sessao: {total_alertas}\n"
                conexao.send(resposta.encode())

            elif dados == "/historico":
                ultimos = historico_alertas[-10:]
                if ultimos:
                    resposta = "--- Ultimos alertas ---\n" + "\n".join(ultimos) + "\n-----------------------\n"
                else:
                    resposta = "Nenhum alerta registrado ainda.\n"
                conexao.send(resposta.encode())

            else:
                conexao.send(f"Comando desconhecido: '{dados}'. Use /status, /historico ou /sair\n".encode())

    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        remover_cliente(conexao)


def iniciar_servidor(host=HOST, porta=PORTA):
    """
    Inicia o servidor TCP e fica aguardando conexoes
    Cada cliente e tratado em uma thread separada
    """
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        servidor.bind((host, porta))
        servidor.listen(MAX_CLIENTES)
        print("=== Servidor de Alertas SecuraPy ===")
        print(f"Rodando em {host}:{porta}")
        print("Aguardando conexoes... (Ctrl+C para encerrar)\n")

        while True:
            try:
                conexao, endereco = servidor.accept()
                thread = threading.Thread(
                    target=tratar_cliente,
                    args=(conexao, endereco),
                    daemon=True
                )
                thread.start()
            except OSError:
                break

    except KeyboardInterrupt:
        print("\n[SERVIDOR] Encerrando servidor...")
    finally:
        servidor.close()
        print("[SERVIDOR] Encerrado.")


if __name__ == "__main__":
    iniciar_servidor()