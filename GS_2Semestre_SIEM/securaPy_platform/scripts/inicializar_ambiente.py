"""Configuração inicial segura do VioTrace para uma cópia recém-clonada.

- Cria api/credenciais.json apenas se ele não existir.
- Opcionalmente copia relatório histórico de amostra para api/dados/.
- Não sobrescreve contas, convites ou relatórios existentes.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import os
import re
import secrets
import shutil
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / 'api'
SEGURANCA = BACKEND / 'seguranca.py'
CREDENCIAIS = BACKEND / 'credenciais.json'
RELATORIO = BACKEND / 'dados' / 'relatorio.json'
SAIDA = ROOT / 'saida'


def inicializar_admin() -> None:
    if not SEGURANCA.is_file():
        raise SystemExit('api/seguranca.py ausente: instale o VioTrace integrado antes.')

    if CREDENCIAIS.exists():
        print('[OK] Administrador já configurado. Credenciais preservadas.')
        return

    print('Configuração inicial do administrador (senha não aparecerá no terminal).')
    usuario = input('Usuário (3-32 caracteres, letras/números/._-): ').strip()
    if not re.fullmatch(r'[A-Za-z0-9._-]{3,32}', usuario):
        raise SystemExit('Usuário inválido; nenhum arquivo foi criado.')

    senha = getpass.getpass('Senha (12-128 caracteres): ')
    confirmacao = getpass.getpass('Confirme a senha: ')
    if not (12 <= len(senha) <= 128) or senha != confirmacao:
        raise SystemExit('Senhas inválidas ou diferentes; nenhum arquivo foi criado.')

    sal = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', senha.encode('utf-8'), sal, 600_000)
    registro = {'usuario': usuario, 'sal': sal.hex(), 'hash': digest.hex()}

    # 'x' cria exclusivamente; nunca sobrescreve credenciais existentes.
    try:
        with CREDENCIAIS.open('x', encoding='utf-8') as arq:
            json.dump(registro, arq, ensure_ascii=False, indent=2)
    except FileExistsError:
        print('[AVISO] Credenciais criadas por outro processo; arquivo preservado.')
        return
    print('[OK] Conta administrativa criada localmente (hash PBKDF2).')


def inicializar_relatorio() -> None:
    if RELATORIO.exists():
        print('[OK] Relatório privado já existe. Preservado.')
        return
    candidatos = sorted(SAIDA.glob('relatorio_*.json'), key=lambda p: p.stat().st_mtime, reverse=True) if SAIDA.is_dir() else []
    valido = None
    for arquivo in candidatos:
        try:
            dados = json.loads(arquivo.read_text(encoding='utf-8'))
            if isinstance(dados, dict) and isinstance(dados.get('alertas'), list):
                valido = arquivo
                break
        except (OSError, ValueError):
            continue
    RELATORIO.parent.mkdir(parents=True, exist_ok=True)
    if valido:
        shutil.copy2(valido, RELATORIO)
        print(f'[OK] Relatório histórico de amostra instalado de: {valido.name}')
        return

    # Clone novo sem relatórios gerados: processar logs sintéticos já fornecidos.
    secura = ROOT / 'core'
    try:
        if str(secura) not in sys.path:
            sys.path.insert(0, str(secura))
        from coletor import carregar_todos_os_logs
        from regras import carregar_regras, aplicar_regras
        from detector import (detectar_brute_force, detectar_port_scan,
                              verificar_blacklist, gerar_resumo_ameacas)

        eventos = carregar_todos_os_logs(str(ROOT / 'logs'))
        regras = carregar_regras(str(ROOT / 'config' / 'regras.json'))
        if not eventos or not regras:
            raise ValueError('Logs ou regras não disponíveis.')
        alertas = aplicar_regras(eventos, regras)
        brute = detectar_brute_force(eventos)
        port_scan = detectar_port_scan(eventos)
        blacklist = verificar_blacklist(eventos, {
            '185.220.101.1', '45.33.32.156', '91.240.118.172', '23.94.5.100'
        })
        correlacoes = gerar_resumo_ameacas(brute, port_scan, blacklist)
        dados = {
            'origem': 'bootstrap_logs_sinteticos',
            'gerado_em': datetime.now().isoformat(timespec='seconds'),
            'total_eventos': len(eventos),
            'total_alertas': len(alertas),
            'eventos': eventos,
            'alertas': alertas,
            'resumo_ameacas': correlacoes,
            'deteccoes': {
                'brute_force': brute, 'port_scan': port_scan,
                'ips_blacklist': sorted(blacklist[0]),
                'contagem_blacklist': blacklist[1],
            },
            'fontes': dict(Counter(e.get('fonte', '-') for e in eventos)),
            'regras_ativas': len(regras),
        }
        RELATORIO.write_text(json.dumps(dados, ensure_ascii=False, indent=2, default=str), encoding='utf-8')
        print(f'[OK] Relatório sintético gerado dos logs: {len(eventos)} eventos, {len(alertas)} alertas.')
    except (OSError, ImportError, ValueError, TypeError, KeyError) as e:
        print('[AVISO] Não foi possível inicializar relatório de exemplo:', e)
        print('        Verifique os logs sintéticos em logs/ e suas dependências.')


def main() -> None:
    if not BACKEND.is_dir() or not (ROOT / 'web' / 'react').is_dir():
        raise SystemExit('Estrutura VioTrace incompleta. Execute o script no projeto integrado.')
    inicializar_admin()
    inicializar_relatorio()
    print('Pronto. Inicie o backend FastAPI e o frontend Vite.')


if __name__ == '__main__':
    main()
