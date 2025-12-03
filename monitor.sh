#!/usr/bin/env bash
set -euo pipefail

# BASE_DIR = /opt/traffic-monitor (quando instalado)
# Calcula baseado na localização deste script (bin/monitor.sh -> ..)
BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"

ANALYZER="$BASE_DIR/bin/analyzer.sh"
BYTES="$BASE_DIR/bin/bytes.sh"
API_SERVER="$BASE_DIR/server/server.js"

# Tenta achar o node no PATH (Node 22+ instalado via NodeSource)
NODE_BIN="$(command -v node || true)"

if [[ -z "$NODE_BIN" ]]; then
  echo "[traffic-monitor] ERRO: 'node' não encontrado no PATH."
  echo "[traffic-monitor] Instale Node.js 22+ e tente novamente."
  exit 1
fi

log() {
  echo "[traffic-monitor] $*"
}

stop_children() {
  log "Encerrando processos filhos..."
  [[ -n "${analyzer_pid:-}" ]] && kill "$analyzer_pid"  2>/dev/null || true
  [[ -n "${bytes_pid:-}"    ]] && kill "$bytes_pid"     2>/dev/null || true
  [[ -n "${api_pid:-}"      ]] && kill "$api_pid"       2>/dev/null || true
}

trap 'log "Sinal recebido, encerrando..."; stop_children; wait || true; exit 0' TERM INT

log "BASE_DIR   = $BASE_DIR"
log "ANALYZER   = $ANALYZER"
log "BYTES      = $BYTES"
log "API_SERVER = $API_SERVER"
log "NODE_BIN   = $NODE_BIN"

# -----------------------------------------------------------------------------
# Inicia analyzer (tcpdump -> traffic-domains.log)
# -----------------------------------------------------------------------------
log "Iniciando traffic-analyzer..."
"$ANALYZER" &
analyzer_pid=$!
log "analyzer.sh PID=$analyzer_pid"

# -----------------------------------------------------------------------------
# Inicia bytes (tcpdump -> traffic-bytes.json)
# -----------------------------------------------------------------------------
log "Iniciando traffic-bytes..."
"$BYTES" &
bytes_pid=$!
log "bytes.sh PID=$bytes_pid"

# -----------------------------------------------------------------------------
# Inicia API HTTP (logs/bytes/ignored-domains + opcionalmente estático)
# -----------------------------------------------------------------------------
if [[ ! -f "$API_SERVER" ]]; then
  log "ERRO: API_SERVER não encontrado em $API_SERVER"
  stop_children
  exit 1
fi

log "Iniciando traffic API (Node)..."
"$NODE_BIN" "$API_SERVER" &
api_pid=$!
log "server.js PID=$api_pid"

# -----------------------------------------------------------------------------
# Espera o primeiro filho morrer e mata o resto
# -----------------------------------------------------------------------------
wait -n
log "Um dos processos encerrou. Encerrando os demais..."
stop_children
wait || true
log "traffic-monitor finalizado."
