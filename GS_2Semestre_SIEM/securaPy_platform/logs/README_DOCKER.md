# SecuraPy com Docker

Plataforma completa (API Flask + MongoDB + MySQL) com um comando, idêntica em qualquer máquina.

## Arquivos

| Arquivo | Função |
| --- | --- |
| `Dockerfile` | Empacota a API Python (python:3.12-slim, gunicorn, usuário não-root, HEALTHCHECK) |
| `docker-compose.yml` | Sobe `api`, `mongo` e `mysql` na rede `securapy-net`, com healthchecks e volumes |
| `docker/mysql/init.sql` | Cria as tabelas `usuarios` e `tokens` na primeira subida |
| `requirements-docker.txt` | Dependências reais da API (Flask, PyMongo, MySQL connector, gunicorn) |
| `scripts/verificar_docker.py` | Verificação via SDK docker-py |
| `.env.example` | Senhas e porta (opcional; há defaults de laboratório) |

## Executar

    docker compose up --build -d

## Cenários de teste

**F1 — os 3 serviços sobem e se comunicam**

    docker compose up --build -d
    docker compose ps          # 3 serviços "running"/"healthy"
    curl http://localhost:5000/health
    # {"mongo":"ok","mysql":"ok","status":"ok"}  <- a API alcançou os dois bancos pelo nome do serviço

**F2 — status via SDK**

    pip install docker
    python scripts/verificar_docker.py

**F3 — API responde 200 dentro do compose**

    docker compose exec api python -c "import urllib.request as u; print(u.urlopen('http://127.0.0.1:5000/health').status)"
    # 200   (o script de F2 também faz essa checagem)

## Notas

- Dentro do compose o host dos bancos é o **nome do serviço** (`mongo`, `mysql`), nunca `localhost`.
- Mongo e MySQL não publicam portas no host; só a API (`API_PORT`, padrão 5000).
- Parar: `docker compose down` (mantém dados) · `docker compose down -v` (apaga volumes).
- Se mudar a senha do MySQL depois da primeira subida, rode `docker compose down -v`: o `init` só roda em volume novo.
