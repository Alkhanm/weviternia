#!/usr/bin/env bash
set -euo pipefail

### CONFIG BÁSICA ###########################################

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

APP_DIR="$SCRIPT_DIR/app"
SERVER_DIR="$SCRIPT_DIR/server"

INSTALL_DIR="/opt/traffic-monitor"
BIN_DIR="$INSTALL_DIR/bin"
LOG_DIR="$INSTALL_DIR/logs"
CONFIG_DIR="$INSTALL_DIR/config"
WEB_DIR="$INSTALL_DIR/web"
RUNTIME_SERVER_DIR="$INSTALL_DIR/server"

SERVICE_NAME="traffic-monitor.service"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME"
LOGROTATE_FILE="/etc/logrotate.d/traffic-monitor"

NODE_BIN="$(command -v node || true)"

if [[ -z "$NODE_BIN" ]]; then
  echo "[install] ERRO: node não encontrado no PATH."
  exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
  echo "[install] Este script precisa ser executado como root (sudo)."
  exit 1
fi

RUNTIME_OWNER="${SUDO_USER:-$USER}"

echo "[install] Dono dos arquivos em $INSTALL_DIR será: $RUNTIME_OWNER"

### 1. LIMPAR INSTALAÇÕES ANTIGAS (SEM APAGAR LOGS) #########

echo "[install] Limpando instalação antiga em $INSTALL_DIR (mantendo logs e config)..."

# Não apagamos INSTALL_DIR inteiro, nem LOG_DIR nem CONFIG_DIR.
# Só limpamos binários, frontend e backend antigos.
if [[ -d "$BIN_DIR" ]]; then
  rm -rf "$BIN_DIR"
fi

if [[ -d "$WEB_DIR" ]]; then
  rm -rf "$WEB_DIR"
fi

if [[ -d "$RUNTIME_SERVER_DIR" ]]; then
  rm -rf "$RUNTIME_SERVER_DIR"
fi

echo "[install] Removendo symlink antigo de /etc/traffic-monitor (se existir)..."
rm -rf /etc/traffic-monitor || true

echo "[install] Removendo links antigos em /usr/local/bin (se existirem)..."
rm -f /usr/local/bin/traffic-analyzer  || true
rm -f /usr/local/bin/traffic-bytes     || true
rm -f /usr/local/bin/traffic-monitor   || true

echo "[install] Removendo service antigo (se existir)..."
rm -f "$SERVICE_FILE" || true
systemctl daemon-reload || true

### 2. BUILD DO FRONTEND (VITE) #############################

echo "[install] Build do frontend (Vue + Vite)..."
cd "$APP_DIR"
npm install
npm run build

### 3. BUILD DO BACKEND (server TypeScript) #################

echo "[install] Build do backend (server TypeScript)..."
cd "$SERVER_DIR"
npm install
npm run build

### 4. CRIAR ESTRUTURA EM /opt/traffic-monitor ##############

echo "[install] Criando diretórios em $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$BIN_DIR"
mkdir -p "$LOG_DIR"        # se já existir, mantém logs
mkdir -p "$CONFIG_DIR"     # mantém config existente
mkdir -p "$WEB_DIR"
mkdir -p "$RUNTIME_SERVER_DIR"

### 5. COPIAR ARQUIVOS DO FRONTEND BUILDADO #################

echo "[install] Copiando frontend (dist) para $WEB_DIR..."
cp -r "$APP_DIR/dist/." "$WEB_DIR/"

### 6. COPIAR BACKEND COMPILADO #############################

echo "[install] Copiando backend compilado para $RUNTIME_SERVER_DIR..."
cp "$SERVER_DIR/dist/src/server.js" "$RUNTIME_SERVER_DIR/server.js"

### 7. COPIAR SCRIPTS SHELL PARA BIN ########################

echo "[install] Copiando scripts shell para $BIN_DIR..."
cp "$SCRIPT_DIR/analyzer.sh" "$BIN_DIR/analyzer.sh"
cp "$SCRIPT_DIR/bytes.sh"    "$BIN_DIR/bytes.sh"
cp "$SCRIPT_DIR/monitor.sh"  "$BIN_DIR/monitor.sh"

chmod +x "$BIN_DIR/analyzer.sh" "$BIN_DIR/bytes.sh" "$BIN_DIR/monitor.sh"

### 8. CRIAR SYMLINKS DE COMPATIBILIDADE ####################

echo "[install] Criando symlink de logs: /var/log/traffic-domains -> $LOG_DIR"
ln -sfn "$LOG_DIR" /var/log/traffic-domains

echo "[install] Criando symlink de config: /etc/traffic-monitor -> $CONFIG_DIR"
ln -sfn "$CONFIG_DIR" /etc/traffic-monitor

echo "[install] Criando aliases em /usr/local/bin..."
ln -sfn "$BIN_DIR/analyzer.sh" /usr/local/bin/traffic-analyzer
ln -sfn "$BIN_DIR/bytes.sh"    /usr/local/bin/traffic-bytes
ln -sfn "$BIN_DIR/monitor.sh"  /usr/local/bin/traffic-monitor

### 9. AJUSTAR PERMISSÕES ###################################

echo "[install] Ajustando dono dos arquivos em $INSTALL_DIR para $RUNTIME_OWNER..."
chown -R "$RUNTIME_OWNER":"$RUNTIME_OWNER" "$INSTALL_DIR"

### 10. CRIAR SYSTEMD SERVICE ###############################

echo "[install] Criando service $SERVICE_NAME..."

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Traffic Monitor (analyzer + bytes + API)
After=network.target

[Service]
Type=simple
WorkingDirectory=$INSTALL_DIR
ExecStart=$BIN_DIR/monitor.sh
Restart=always
RestartSec=5
User=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

echo "[install] Recarregando systemd..."
systemctl daemon-reload

echo "[install] Habilitando service para iniciar com o sistema..."
systemctl enable "$SERVICE_NAME"

### 11. CONFIGURAR LOGROTATE ###############################

echo "[install] Criando/atualizando config do logrotate em $LOGROTATE_FILE..."

cat > "$LOGROTATE_FILE" <<'EOF'
/var/log/traffic-domains/traffic-domains.log \
/var/log/traffic-domains/traffic-bytes.json {
    daily
    rotate 30
    missingok
    notifempty
    dateext
    dateformat -%Y%m%d
    sharedscripts
    postrotate
        systemctl restart traffic-monitor.service >/dev/null 2>&1 || true
    endscript
}
EOF

echo
echo "[install] Instalação concluída."
echo "Para iniciar agora, rode:"
echo "  sudo systemctl start $SERVICE_NAME"
echo
echo "Frontend estático em:        $WEB_DIR"
echo "Backend Node (server.js):    $RUNTIME_SERVER_DIR/server.js"
echo "Logs (preservados) em:       $LOG_DIR"
echo "Config em:                   $CONFIG_DIR"
echo "Logrotate em:                $LOGROTATE_FILE"
