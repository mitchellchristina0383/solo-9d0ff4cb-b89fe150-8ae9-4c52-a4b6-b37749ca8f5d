#!/usr/bin/env bash
# 无 Docker 环境下的本地启动脚本（自测/演示用）。
# 生产部署请使用 docker compose up --build。
set -euo pipefail

cd "$(dirname "$0")"
DATA_DIR="$(pwd)/data/certs"
export CERT_DATA_DIR="$DATA_DIR"
export CERT_POLL_INTERVAL="${CERT_POLL_INTERVAL:-0.5}"
mkdir -p "$DATA_DIR"

cleanup() {
  kill "${MGMT_PID:-}" "${TLS_PID:-}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 &
MGMT_PID=$!
python -m app.tls_service &
TLS_PID=$!

echo "管理接口:  http://127.0.0.1:8000/docs"
echo "HTTPS 服务: https://127.0.0.1:8443/  (curl -k)"
wait
