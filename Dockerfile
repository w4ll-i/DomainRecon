# =============================================================================
# DomainRecon - Dockerfile
# =============================================================================

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV ENV=production

WORKDIR /app

RUN pip install --upgrade pip

# gcc + libssl-dev requis pour certaines dépendances (cryptography, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libssl-dev curl wget unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei binary (latest release)
RUN NUCLEI_VERSION=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4 | sed 's/v//') \
    && wget -q "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
       -O /tmp/nuclei.zip \
    && unzip -q /tmp/nuclei.zip nuclei -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei \
    && rm /tmp/nuclei.zip

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY frontend/ ./frontend/

RUN mkdir -p /app/data /app/data/screenshots /root/nuclei-templates

EXPOSE 8000

CMD ["sh", "-c", "python backend/migrate.py && uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --workers 1"]
