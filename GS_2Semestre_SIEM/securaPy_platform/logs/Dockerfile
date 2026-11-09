# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # api/app.py faz "import regras", "import detector", "import ml":
    # /app/core e /app entram no path para resolver esses módulos.
    PYTHONPATH=/app/core:/app \
    LOGS_DIR=/app/logs \
    PORT=5000

WORKDIR /app

# Camada de dependências separada: só reconstrói se requirements mudar
COPY requirements-docker.txt .
RUN pip install -r requirements-docker.txt

# Código da aplicação
COPY . .

# Usuário sem privilégios
RUN useradd --system --no-create-home --uid 10001 securapy \
    && chown -R securapy:securapy /app
USER securapy

EXPOSE 5000

# Sem curl na imagem slim: usa Python para checar a rota /health
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
  CMD python -c "import os,urllib.request as u; u.urlopen('http://127.0.0.1:%s/health' % os.environ.get('PORT','5000'), timeout=4)" || exit 1

CMD ["sh", "-c", "exec gunicorn --chdir /app/api --bind 0.0.0.0:${PORT} --workers 2 --access-logfile - app:app"]
