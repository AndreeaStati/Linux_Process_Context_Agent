#!/usr/bin/env bash
set -u

# Scenariu: executie a unui fisier din directorul /tmp.
# Acest comportament poate fi considerat suspect, deoarece atacatorii
# folosesc frecvent directoare temporare pentru rularea de scripturi
# sau binare descarcate pe sistem.

echo "[scenario] Executie din director temporar /tmp"

TMP_BIN="/tmp/edr_tmp_exec"

cp /bin/sleep "$TMP_BIN"
chmod +x "$TMP_BIN"

"$TMP_BIN" 5 &
TMP_PID=$!

sleep 1

wait "$TMP_PID"

rm -f "$TMP_BIN"
