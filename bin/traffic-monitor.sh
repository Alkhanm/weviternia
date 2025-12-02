#!/usr/bin/env bash
set -euo pipefail

# BASE_DIR = /opt/traffic-monitor (quando instalado)
# Calcula baseado na localização deste script
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"

ANALYZER="$BASE_DIR/bin/traffic-analyzer.sh"
BYTES="$BASE_DIR/bin/traffic-bytes.sh"
DASHBOARD="$BASE_DIR/src/traffic-dashboard.js"

log() {
  echo "[traffic-monitor] $*"
}

stop_children() {
  log "Encerrando processos filhos..."
  [[ -n "${analyzer_pid:-}"  ]] && kill "$analyzer_pid"  2>/dev/null || true
  [[ -n "${bytes_pid:-}"     ]] && kill "$bytes_pid"     2>/dev/null || true
  [[ -n "${dashboard_pid:-}" ]] && kill "$dashboard_pid" 2>/dev/null || true
}

trap 'log "Sinal recebido, encerrando..."; stop_children; wait || true; exit 0' TERM INT

log "BASE_DIR = $BASE_DIR"
log "ANALYZER = $ANALYZER"
log "BYTES    = $BYTES"
log "DASHBOARD= $DASHBOARD"

log "Iniciando traffic-analyzer..."
"$ANALYZER" &
analyzer_pid=$!
log "traffic-analyzer.sh PID=$analyzer_pid"

log "Iniciando traffic-bytes..."
"$BYTES" &
bytes_pid=$!
log "traffic-bytes.sh PID=$bytes_pid"

log "Iniciando traffic-dashboard (Node)..."
node "$DASHBOARD" &
dashboard_pid=$!
log "traffic-dashboard.js PID=$dashboard_pid"

# Espera o primeiro filho encerrar
wait -n
log "Um dos processos encerrou. Encerrando os demais..."
stop_children
wait || true
log "traffic-monitor finalizado."
