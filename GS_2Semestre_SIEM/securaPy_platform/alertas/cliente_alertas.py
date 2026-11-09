"""
Modulo 4b - Cliente de Alertas
Conecta ao servidor e recebe notificacoes de seguranca em tempo real.

Desenvolvido por: Amanda

Comandos: /status, /historico, /sair
"""

import socket
import threading

HOST = "127.0.0.1"
PORTA = 9999


def receber_alertas(cliente):
    """
    Thread que fica escutando o servidor e exibe mensagens no terminal
    Roda em paralelo com o loop de input do usuario
    """
    while True:
        try:
            dados = cliente.recv(4096).decode("utf-8", errors="replace")
            if not dados:
                print("\n[CLIENTE] Servidor desconectou.")
                break
            print(dados, end="", flush=True)
        except (ConnectionResetError, BrokenPipeError, OSError):
            print("\n[CLIENTE] Conexao encerrada.")
            break


def conectar_servidor(host=HOST, porta=PORTA):
    """
    Conecta ao servidor de alertas e inicia a interacao.
    Usa uma thread separada para receber mensagens enquanto o
    usuario pode digitar comandos normalmente
    """
    try:
        cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cliente.connect((host, porta))
        print(f"Conectado ao SecuraPy SIEM ({host}:{porta})")
        print("Comandos disponiveis: /status, /historico, /sair\n")

        # Thread de recepcao - daemon para encerrar junto com o programa
        thread = threading.Thread(
            target=receber_alertas,
            args=(cliente,),
            daemon=True
        )
        thread.start()

        # Loop principal - le comandos do usuario e envia ao servidor
        while True:
            try:
                comando = input(">> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[CLIENTE] Encerrando...")
                break

            if not comando:
                continue

            try:
                cliente.send((comando + "\n").encode())
            except (ConnectionResetError, BrokenPipeError, OSError):
                print("[CLIENTE] Erro ao enviar. Conexao perdida.")
                break

            if comando == "/sair":
                break

    except ConnectionRefusedError:
        print(f"[ERRO] Nao foi possivel conectar em {host}:{porta}.")
        print("Verifique se o servidor esta rodando: python servidor_alertas.py")
    except OSError as erro:
        print(f"[ERRO] Falha de conexao: {erro}")
    finally:
        try:
            cliente.close()
        except OSError:
            pass
        print("[CLIENTE] Desconectado.")


if __name__ == "__main__":
    conectar_servidor()