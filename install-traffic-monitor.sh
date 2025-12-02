#!/usr/bin/env bash
set -euo pipefail

# Diretório onde está este script (origem do projeto)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Caminhos alvo (novo layout)
BASE_DIR="/opt/traffic-monitor"
BIN_DIR="$BASE_DIR/bin"
LOG_DIR="$BASE_DIR/logs"
CONFIG_DIR="$BASE_DIR/config"
SRC_DIR="$BASE_DIR/src"

# Caminhos "padrão" externos
OLD_CONFIG_DIR="/etc/traffic-monitor"
OLD_LOG_DIR="/var/log/traffic-domains"
OLD_BIN_DIR="/usr/local/bin"
SERVICE_FILE="/etc/systemd/system/traffic-monitor.service"

# Nome dos scripts
SCRIPTS=(
  "traffic-analyzer.sh"
  "traffic-bytes.sh"
  "traffic-monitor.sh"
)

# Usuário dono do projeto (quem chamou o sudo)
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

clean_target_layout() {
  log "Removendo layout anterior (se existir) em $BASE_DIR"
  rm -rf "$BASE_DIR"
}

create_layout() {
  log "Criando estrutura em $BASE_DIR"
  mkdir -p "$BIN_DIR" "$LOG_DIR" "$CONFIG_DIR" "$SRC_DIR"
}

copy_project_files() {
  log "Copiando arquivos do projeto de $SCRIPT_DIR para $BASE_DIR"

  # bin
  if [[ -d "$SCRIPT_DIR/bin" ]]; then
    log "  - Copiando bin/"
    cp -a "$SCRIPT_DIR/bin/." "$BIN_DIR/"
  else
    log "  - Aviso: não há diretório bin/ em $SCRIPT_DIR"
  fi

  # config
  if [[ -d "$SCRIPT_DIR/config" ]]; then
    log "  - Copiando config/"
    cp -a "$SCRIPT_DIR/config/." "$CONFIG_DIR/"
  else
    log "  - Aviso: não há diretório config/ em $SCRIPT_DIR (criado vazio)"
  fi

  # src (painel web)
  if [[ -d "$SCRIPT_DIR/src" ]]; then
    log "  - Copiando src/"
    cp -a "$SCRIPT_DIR/src/." "$SRC_DIR/"
  else
    log "  - Aviso: não há diretório src/ em $SCRIPT_DIR"
  fi

  # logs: em instalação limpa, apenas garante diretório
  log "  - Garantindo diretório de logs em $LOG_DIR"
  mkdir -p "$LOG_DIR"
}

create_symlinks() {
  log "Criando symlinks padrão (sobrescrevendo se existirem)"

  # /etc/traffic-monitor -> /opt/traffic-monitor/config
  rm -rf "$OLD_CONFIG_DIR"
  ln -s "$CONFIG_DIR" "$OLD_CONFIG_DIR"
  log "  - $OLD_CONFIG_DIR -> $CONFIG_DIR"

  # /var/log/traffic-domains -> /opt/traffic-monitor/logs
  rm -rf "$OLD_LOG_DIR"
  ln -s "$LOG_DIR" "$OLD_LOG_DIR"
  log "  - $OLD_LOG_DIR -> $LOG_DIR"

  # /usr/local/bin/traffic-*.sh -> /opt/traffic-monitor/bin/traffic-*.sh
  for s in "${SCRIPTS[@]}"; do
    local target="$BIN_DIR/$s"
    local link="$OLD_BIN_DIR/$s"

    if [[ ! -f "$target" ]]; then
      log "  - Aviso: $target não existe, não cria symlink $link"
      continue
    fi

    rm -f "$link"
    ln -s "$target" "$link"
    log "  - $link -> $target"
  done
}

fix_permissions() {
  log "Ajustando permissões em $BASE_DIR para o usuário $TARGET_USER"

  # Dono do projeto é o usuário "normal"
  chown -R "$TARGET_USER":"$TARGET_USER" "$BASE_DIR"

  # Scripts executáveis pro dono
  if compgen -G "$BIN_DIR/traffic-*.sh" > /dev/null; then
    chmod u+x "$BIN_DIR"/traffic-*.sh
  fi

  # Opcional: deixar o servidor Node executável
  if [[ -f "$SRC_DIR/traffic-dashboard.js" ]]; then
    chmod u+x "$SRC_DIR/traffic-dashboard.js"
  fi
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
ExecStart=/usr/local/bin/traffic-monitor.sh
WorkingDirectory=/opt/traffic-monitor
Restart=on-failure
RestartSec=5

# Se quiser rodar como usuário normal (pode exigir capabilities no tshark/tcpdump), descomente:
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
  log "Usuário alvo (dono do projeto): $TARGET_USER"
  clean_target_layout
  create_layout
  copy_project_files
  create_symlinks
  fix_permissions
  create_service

  log "Concluído!"
  log "Projeto em:   $BASE_DIR"
  log "Scripts via:  /usr/local/bin/traffic-monitor.sh (e demais)"
  log "Configs em:   $CONFIG_DIR (linkado em /etc/traffic-monitor)"
  log "Logs em:      $LOG_DIR (linkado em /var/log/traffic-domains)"
  log "Service:      traffic-monitor.service (habilitado e iniciado)"
}

main "$@"

