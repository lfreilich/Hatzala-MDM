FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client && rm -rf /var/lib/apt/lists/*
# apkeep (EFF, MIT) downloads APKs from Google Play for the Play Store page. Pinned by checksum.
ADD --checksum=sha256:badd7ad9fa7d2f32abe01eaf33b7ff086361a95bbc000a33bf44b630d4bf2140 \
    https://github.com/EFForg/apkeep/releases/download/1.1.0/apkeep-x86_64-unknown-linux-gnu /usr/local/bin/apkeep
RUN chmod 755 /usr/local/bin/apkeep
COPY app ./app
EXPOSE 8090
CMD ["sh", "-c", "uvicorn app.main:app --host 127.0.0.1 --port ${BRIDGE_PORT:-8090} --proxy-headers --forwarded-allow-ips=127.0.0.1"]
