#!/usr/bin/env bash
# One-time local setup: signing keys + deploy/.env with random secrets. Never commit the output.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p keys
command -v openssl >/dev/null || { echo "openssl required"; exit 1; }
[ -f keys/ec-signing.pem ]  || openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out keys/ec-signing.pem
[ -f keys/rsa-signing.pem ] || openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out keys/rsa-signing.pem
chmod 0644 keys/*.pem   # readable by the container's non-root user (local dev only)
if [ ! -f .env ]; then
  {
    echo "MSSQL_SA_PASSWORD=Dev_$(openssl rand -hex 12)!Aa1"
    echo "AUTH_CSRF_KEY=$(openssl rand -base64 32)"
  } > .env
fi
echo "keys and deploy/.env ready"
