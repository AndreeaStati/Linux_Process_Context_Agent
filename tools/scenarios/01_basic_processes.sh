#!/usr/bin/env bash
set -u

# Scenariu: executii normale de procese.
# Acest script genereaza evenimente simple de tip process_started,
# utile pentru verificarea functionarii de baza a agentului.

echo "[scenario] Executii normale de procese"

/bin/true
whoami
id
hostname
uname -a