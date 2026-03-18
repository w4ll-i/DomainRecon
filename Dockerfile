# =============================================================================
# DomainRecon v6.0 - Dockerfile (standalone, tout en un)
# =============================================================================

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV ENV=production

WORKDIR /app

RUN pip install --upgrade pip

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY frontend/ ./frontend/

RUN mkdir -p /app/data /app/data/screenshots

EXPOSE 8000

# Lance la migration v6.0 (idempotente) puis démarre le serveur
CMD ["sh", "-c", "python backend/migrate_v6.py && uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --workers 1"]
