#!/usr/bin/env bash
set -u

# Scenariu: activitate de retea.
# Acest script genereaza incercari de conexiune HTTP si TCP,
# pentru a verifica daca agentul capteaza evenimentele de tip
# network_connection_attempt si le asociaza cu procesul care le-a initiat.

echo "[scenario] Activitate de retea"

curl -s -o /dev/null http://example.com || true
curl -s -o /dev/null http://127.0.0.1:8080/api/edr/events || true

python3 - <<'PY'
import socket

targets = [
    ("127.0.0.1", 8080),
    ("127.0.0.1", 9999),
]

for host, port in targets:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect((host, port))
    except Exception:
        pass
    finally:
        s.close()
PY

echo "[scenario] Conexiune catre port 4444"

python3 -m http.server 4444 --bind 127.0.0.1 > /tmp/edr_http_4444.log 2>&1 &
SERVER_PID=$!

sleep 1
curl -m 2 http://127.0.0.1:4444/ > /dev/null 2>&1 || true
sleep 2

kill "$SERVER_PID" 2>/dev/null || true