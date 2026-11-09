"""Alerta para arquivos sensíveis já rastreados pelo Git.

Esta verificação não substitui uma revisão de segurança do código e do histórico Git.
"""
from __future__ import annotations
import fnmatch
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PADROES = [
    'securaPy_platform/api/credenciais.json',
    'securaPy_platform/api/usuarios.json',
    'securaPy_platform/api/convites.json',
    'securaPy_platform/api/dados/*',
    'securaPy_platform/web/react/node_modules/*',
    'securaPy_platform/web/react/dist/*',
    'securaPy_platform/saida/*',
    'securaPy_platform/*.backup*',
    'securaPy_platform/**/*.backup*',
    'evidencias_entrega/*',
    'backend_ia/credenciais.json',
    'backend_ia/usuarios.json',
    'backend_ia/convites.json',
    'backend_ia/dados/*',
    'frontend/public/relatorio.json',
    'frontend/node_modules/*',
    'frontend/dist/*',
    'frontend/.viotrace_ux_backups/*',
    'securaPy/saida/*',
    '**/.env', '*.env', '*.pem', '*.p12', '*.pfx', '*.key',
]


def principal() -> int:
    if not shutil.which('git'):
        print('[ERRO] Git não encontrado. Instale Git for Windows.')
        return 2
    repo = subprocess.run(
        ['git', 'rev-parse', '--show-toplevel'],
        cwd=ROOT, capture_output=True, text=True
    )
    if repo.returncode:
        print('[ERRO] Nao foi possivel localizar a raiz do repositorio Git.')
        return 2
    result = subprocess.run(
        ['git', 'ls-files', '-z'],
        cwd=repo.stdout.strip(), capture_output=True
    )
    if result.returncode:
        print('[ERRO] Não foi possível consultar arquivos rastreados pelo Git.')
        return 2
    caminhos = [p.replace('\\', '/') for p in result.stdout.decode('utf-8', errors='replace').split('\0') if p]
    riscos = [p for p in caminhos if any(fnmatch.fnmatch(p, pat) for pat in PADROES)]
    print(f'Arquivos rastreados analisados: {len(caminhos)}')
    if not caminhos:
        print('[ERRO] Git retornou zero arquivos rastreados. Revisar a verificacao.')
        return 2
    if riscos:
        print('[ATENÇÃO] Arquivos potencialmente privados rastreados pelo Git:')
        for caminho in riscos:
            print(' -', caminho)
        print('Verifique a necessidade de retirar do índice (git rm --cached ...) e trocar credenciais expostas.')
        return 1
    print('[OK] Nenhum caminho sensível conhecido encontrado entre os arquivos rastreados.')
    print('[NOTA] Revise manualmente os conteúdos e o histórico: esta checagem é baseada em nomes, não em segredos.')
    return 0


if __name__ == '__main__':
    raise SystemExit(principal())
