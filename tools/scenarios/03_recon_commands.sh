#!/usr/bin/env bash
set -u

# Scenariu: comenzi de recunoastere locala.
# Acest script ruleaza comenzi folosite pentru colectarea de informatii
# despre utilizator, sistem, procese si configuratia de retea.
# Comenzile sunt legitime, dar pot aparea si in faze initiale ale unui atac.

echo "[scenario] Comenzi de recunoastere locala"

whoami
id
uname -a
hostname
ps aux | head -n 5
ip addr show | head -n 20
ip route show

timeout 3s tail -f /etc/passwd > /dev/null 2>&1 || true
bash -c "whoami" > /dev/null 2>&1 || true