FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY minitor ./minitor

# Nodes don't need root. /keys holds the directory's public key and nodes'
# identity keys, shared through a volume (see docker-compose.yml).
RUN useradd --create-home --uid 10001 minitor \
    && mkdir /keys && chown minitor:minitor /keys
USER minitor
