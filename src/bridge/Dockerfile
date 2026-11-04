FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client && rm -rf /var/lib/apt/lists/*
COPY app ./app
EXPOSE 8090
CMD ["sh", "-c", "uvicorn app.main:app --host 127.0.0.1 --port ${BRIDGE_PORT:-8090} --proxy-headers --forwarded-allow-ips=127.0.0.1"]
