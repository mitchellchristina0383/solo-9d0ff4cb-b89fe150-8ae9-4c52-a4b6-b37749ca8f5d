FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

RUN mkdir -p /data/certs
ENV CERT_DATA_DIR=/data/certs \
    PYTHONUNBUFFERED=1

EXPOSE 8000 8443
