#!/usr/bin/env bash
set -u

# Scenariu: executie a unui fisier din directorul /tmp.
# Acest comportament poate fi considerat suspect, deoarece atacatorii
# folosesc frecvent directoare temporare pentru rularea de scripturi
# sau binare descarcate pe sistem.

echo "[scenario] Executie din director temporar /tmp"

TMP_BIN="/tmp/edr_test_exec_$$"

cat > "$TMP_BIN" <<'EOF'
#!/usr/bin/env bash
echo "EDR temp execution test"
whoami
EOF

chmod +x "$TMP_BIN"

"$TMP_BIN" test_argument_1 test_argument_2

rm -f "$TMP_BIN"