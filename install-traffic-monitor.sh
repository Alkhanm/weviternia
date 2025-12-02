#!/usr/bin/env bash
set -euo pipefail

# Garante que está rodando em bash (e não /bin/sh)
if [[ -z "${BASH_VERSION:-}" ]]; then
  echo "Use bash para rodar este instalador, por exemplo:" >&2
  echo "  bash install-traffic-monitor.sh" >&2
  exit 1
fi

# Diretório onde está este script (origem do projeto)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Caminhos de destino no sistema
BIN_DIR="/usr/local/bin"
DASHBOARD_DIR="/opt/traffic-dashboard"
CONFIG_DIR="/etc/traffic-monitor"
LOG_DIR="/var/log/traffic-domains"
SERVICE_FILE="/etc/systemd/system/traffic-monitor.service"

# Usuário dono lógico do projeto (quem chamou o sudo)
TARGET_USER="${SUDO_USER:-$USER}"

require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "Este script precisa ser executado como root (sudo)." >&2
    exit 1
  fi
  if [[ -z "$TARGET_USER" ]]; then
    echo "Não foi possível determinar o usuário alvo (TARGET_USER)." >&2
    exit 1
  fi
}

log() {
  echo "[install] $*"
}

create_dirs() {
  log "Criando diretórios de destino, se necessário"

  # Config: se for symlink antigo, remove e cria diretório real
  if [[ -L "$CONFIG_DIR" ]]; then
    rm -f "$CONFIG_DIR"
  fi
  mkdir -p "$CONFIG_DIR"

  # Logs: se for symlink antigo, remove e cria diretório real
  if [[ -L "$LOG_DIR" ]]; then
    rm -f "$LOG_DIR"
  fi
  mkdir -p "$LOG_DIR"

  # Painel web
  mkdir -p "$DASHBOARD_DIR"
}

copy_scripts() {
  log "Copiando scripts para $BIN_DIR"

  if [[ -d "$SCRIPT_DIR/bin" ]]; then
    # Atualiza/instala os scripts principais
    if [[ -f "$SCRIPT_DIR/bin/traffic-analyzer.sh" ]]; then
      install -m 0755 "$SCRIPT_DIR/bin/traffic-analyzer.sh" "$BIN_DIR/traffic-analyzer.sh"
      chown "$TARGET_USER":"$TARGET_USER" "$BIN_DIR/traffic-analyzer.sh"
      log "  - traffic-analyzer.sh -> $BIN_DIR/traffic-analyzer.sh"
    fi

    if [[ -f "$SCRIPT_DIR/bin/traffic-bytes.sh" ]]; then
      install -m 0755 "$SCRIPT_DIR/bin/traffic-bytes.sh" "$BIN_DIR/traffic-bytes.sh"
      chown "$TARGET_USER":"$TARGET_USER" "$BIN_DIR/traffic-bytes.sh"
      log "  - traffic-bytes.sh    -> $BIN_DIR/traffic-bytes.sh"
    fi
  else
    log "  - Aviso: não há diretório bin/ na pasta do projeto"
  fi
}

copy_dashboard() {
  log "Copiando painel web para $DASHBOARD_DIR"

  if [[ -d "$SCRIPT_DIR/src" ]]; then
    # Copia tudo de src/ para /opt/traffic-dashboard
    cp -a "$SCRIPT_DIR/src/." "$DASHBOARD_DIR/"
    chown -R "$TARGET_USER":"$TARGET_USER" "$DASHBOARD_DIR"
    log "  - Arquivos HTML/CSS/JS atualizados em $DASHBOARD_DIR"
  else
    log "  - Aviso: não há diretório src/ na pasta do projeto"
  fi
}

copy_config() {
  log "Configurando /etc/traffic-monitor"

  if [[ -d "$SCRIPT_DIR/config" ]]; then
    # Só cria ignore-domains.txt se ainda não existir
    if [[ -f "$SCRIPT_DIR/config/ignore-domains.txt" && ! -f "$CONFIG_DIR/ignore-domains.txt" ]]; then
      cp "$SCRIPT_DIR/config/ignore-domains.txt" "$CONFIG_DIR/ignore-domains.txt"
      chown "$TARGET_USER":"$TARGET_USER" "$CONFIG_DIR/ignore-domains.txt"
      log "  - ignore-domains.txt criado em $CONFIG_DIR"
    else
      log "  - Mantendo ignore-domains.txt existente (se houver)"
    fi
  else
    log "  - Aviso: não há diretório config/ na pasta do projeto"
  fi
}

generate_wrapper() {
  log "Gerando / atualizando wrapper /usr/local/bin/traffic-monitor.sh"

  cat > "$BIN_DIR/traffic-monitor.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

ANALYZER="/usr/local/bin/traffic-analyzer.sh"
BYTES="/usr/local/bin/traffic-bytes.sh"
DASHBOARD_JS="/opt/traffic-dashboard/traffic-dashboard.js"

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

log "Iniciando traffic-analyzer..."
"$ANALYZER" &
analyzer_pid=$!
log "traffic-analyzer.sh PID=$analyzer_pid"

log "Iniciando traffic-bytes..."
"$BYTES" &
bytes_pid=$!
log "traffic-bytes.sh PID=$bytes_pid"

log "Iniciando traffic-dashboard (Node)..."
node "$DASHBOARD_JS" &
dashboard_pid=$!
log "traffic-dashboard.js PID=$dashboard_pid"

# Espera o primeiro filho encerrar
wait -n
log "Um dos processos encerrou. Encerrando os demais..."
stop_children
wait || true
log "traffic-monitor finalizado."
EOF

  chmod 0755 "$BIN_DIR/traffic-monitor.sh"
  chown "$TARGET_USER":"$TARGET_USER" "$BIN_DIR/traffic-monitor.sh"
  log "  - traffic-monitor.sh -> $BIN_DIR/traffic-monitor.sh"
}

create_service() {
  log "Criando/atualizando service em $SERVICE_FILE"

  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Traffic Monitor (analyzer + bytes + web dashboard)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/bin/bash /usr/local/bin/traffic-monitor.sh
WorkingDirectory=/opt/traffic-dashboard
Restart=on-failure
RestartSec=5

# Para rodar como usuário normal, descomente (e configure capacidades do tcpdump/tshark):
#User=$TARGET_USER
#Group=$TARGET_USER

[Install]
WantedBy=multi-user.target
EOF

  log "  - Service escrito em $SERVICE_FILE"

  log "Recarregando systemd..."
  systemctl daemon-reload

  log "Habilitando service traffic-monitor..."
  systemctl enable traffic-monitor.service || log "  - Aviso: não foi possível habilitar (enable)."

  log "Iniciando/reiniciando service traffic-monitor..."
  systemctl restart traffic-monitor.service || log "  - Aviso: não foi possível iniciar (restart)."
}

main() {
  require_root
  log "Usuário alvo (dono lógico): $TARGET_USER"

  create_dirs
  copy_scripts
  copy_dashboard
  copy_config
  generate_wrapper
  create_service

  log "Concluído!"
  log "Scripts em:      $BIN_DIR (traffic-analyzer.sh, traffic-bytes.sh, traffic-monitor.sh)"
  log "Painel em:       $DASHBOARD_DIR (index.html, style.css, traffic-dashboard.js, ...)"
  log "Config em:       $CONFIG_DIR (ignore-domains.txt)"
  log "Logs em:         $LOG_DIR (preservados)"
  log "Service:         traffic-monitor.service (habilitado e iniciado)"
}

main "$@"
