# VioTrace — SecuraPy Platform

Plataforma de monitoramento e análise de eventos de segurança,
desenvolvida para a Global Solution da FIAP.

## Tecnologias

- Python
- FastAPI
- React e Vite
- Ollama (modelo llama3.2:3b)
- Comunicação TCP
- Pytest

## Estrutura

- core/ — Coleta, regras, detecção e relatórios
- db/ — Integração com bancos de dados (pendente)
- ml/ — Machine Learning (pendente)
- api/ — API REST, autenticação e segurança web
- ia/ — VIX, análise factual e integração LLM
- web/react/ — Dashboard e interface visual
- alertas/ — Servidor e cliente TCP
- logs/ — Logs de demonstração
- config/ — Regras de segurança
- testes/ — Testes automatizados
- scripts/ — Inicialização e verificações

## Requisitos

- Python com pip
- Node.js e npm
- Ollama instalado localmente

## Instalação do backend

Na pasta securaPy_platform:

    py -m pip install -r requirements.txt
    py -m pip install pytest

Para preparar um ambiente recém-clonado:

    py scripts/inicializar_ambiente.py

O inicializador cria a conta administrativa quando necessário
e prepara um relatório de demonstração a partir dos logs.

## Iniciar o Ollama

    ollama pull llama3.2:3b

O serviço Ollama deve estar disponível em:

    http://127.0.0.1:11434

## Iniciar o backend

    cd api
    py -m uvicorn app:app --host 127.0.0.1 --port 8001

API:

    http://127.0.0.1:8001

Documentação Swagger:

    http://127.0.0.1:8001/docs

## Iniciar o frontend

Em outro terminal, na pasta securaPy_platform:

    cd web/react
    npm ci
    npm run dev -- --host 127.0.0.1 --port 5174 --strictPort

Acessar:

    http://127.0.0.1:5174

O proxy do Vite está configurado para a API na porta 8001.

## Executar testes

Na pasta securaPy_platform:

    py -m pytest -q
    py scripts/testar_modulos_eg.py
    py scripts/testar_chat_flexivel.py

Resultados da validação local em 08/11/2026:

- Núcleo SecuraPy: 197 testes aprovados
- Módulos E/G: 10 testes aprovados
- Chat VIX: 8 testes aprovados
- Frontend: lint e build aprovados

## Segurança

Não publicar:
- credenciais.json
- usuarios.json
- convites.json
- arquivos .env
- relatórios privados
- backups e logs de auditoria privados

Antes de publicar, executar:

    py scripts/conferir_publicacao.py

Essa verificação não substitui auditoria dos arquivos e do
histórico Git.

## Situação do desenvolvimento

A versão reorganizada foi validada localmente em execução,
incluindo autenticação, dashboard, alertas e VIX.

Ainda pendentes:
- Integração real de MongoDB/MySQL (módulo B)
- Implementação de Machine Learning (módulo C)
- Containerização com Docker (módulo F)
- Validação de instalação em clone limpo

A interface atual utiliza FastAPI e React, em vez da combinação
Flask e Jinja2 sugerida no enunciado.

## Assistente VIX

A VIX é a assistente virtual do VioTrace.

Ela permite:
- Conversas gerais
- Análise de evidências do SIEM
- Investigação de endereços IP
- Classificação defensiva de eventos
- Exibição de avatares e estados visuais

As respostas sobre o SIEM utilizam as evidências disponíveis
no relatório local.
