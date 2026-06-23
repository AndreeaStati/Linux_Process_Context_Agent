#!/usr/bin/env bash
set -u

# Scenariu general: rularea tuturor scenariilor de test.
# Acest script executa pe rand scenariile controlate pentru procese,
# executie din /tmp, recunoastere locala si activitate de retea.
# Este util pentru demonstrarea rapida a pipeline-ului agentului.

echo "[*] Rulez toate scenariile de test EDR..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

bash "$SCRIPT_DIR/01_basic_processes.sh"
bash "$SCRIPT_DIR/02_temp_execution.sh"
bash "$SCRIPT_DIR/03_recon_commands.sh"
bash "$SCRIPT_DIR/04_network_activity.sh"

echo "[*] Scenariile de test s-au terminat."