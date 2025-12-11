#!/usr/bin/env bash

# Interface da LAN
IFACE="enx00e04c68054d"

# Faixa dos clientes internos (ajuste se mudar sua LAN)
LAN_REGEX="^192\.168\.1\."

LOG_DIR="/var/log/traffic-domains"
LOG_FILE="$LOG_DIR/traffic-domains.log"

# Arquivo de domínios a ignorar (um regex por linha)
IGNORE_FILE="${IGNORE_FILE:-/etc/traffic-monitor/ignore-domains.txt}"

mkdir -p "$LOG_DIR"

echo "[traffic-analyzer] Escutando interface: $IFACE"
echo "[traffic-analyzer] Clientes LAN (regex): $LAN_REGEX"
echo "[traffic-analyzer] Log: $LOG_FILE"
echo "[traffic-analyzer] Mode: tshark DNS/TLS/HTTP host"
echo "[traffic-analyzer] Arquivo de ignore: $IGNORE_FILE"

exec tshark -i "$IFACE" -n -l \
  -T fields \
  -e frame.time_epoch \
  -e ip.src \
  -e ip.dst \
  -e dns.qry.name \
  -e tls.handshake.extensions_server_name \
  -e http.host \
  -Y "dns.qry.name or tls.handshake.extensions_server_name or http.host" 2>/dev/null | \
awk -v lanre="$LAN_REGEX" -v logfile="$LOG_FILE" -v ignore_file="$IGNORE_FILE" '
BEGIN {
  FS = "\t";  # tshark -T fields separa por TAB

  n_ignore = 0;
  last_ignore_reload = 0;

  if (ignore_file != "") {
    load_ignore_file(ignore_file);
    last_ignore_reload = systime();
  }
}

# Carrega (ou recarrega) a lista de domínios ignorados
# Cada linha do arquivo pode ser:
#   - vazia  -> ignorada
#   - começando com # -> comentário
#   - senão, é um regex a ser aplicado ao domínio
function load_ignore_file(file,   line) {
  n_ignore = 0;
  delete ignore_patterns;

  if (file == "") return;

  while ((getline line < file) > 0) {
    # tira comentário
    sub(/#.*/, "", line);
    # trim
    gsub(/^ +| +$/, "", line);
    if (line == "") continue;

    n_ignore++;
    ignore_patterns[n_ignore] = line;
  }
  close(file);
}

# Retorna 1 se o domínio deve ser ignorado
function should_ignore_domain(d,   i) {
  if (d == "") return 0;
  for (i = 1; i <= n_ignore; i++) {
    if (d ~ ignore_patterns[i]) {
      return 1;
    }
  }
  return 0;
}

# Esperamos pelo menos: epoch, ip.src, ip.dst
NF >= 3 {
  ts_epoch = $1;
  src      = $2;
  dst      = $3;
  dns_name = (NF >= 4 ? $4 : "");
  tls_sni  = (NF >= 5 ? $5 : "");
  http_host= (NF >= 6 ? $6 : "");

  ts_epoch_int = int(ts_epoch + 0);

  # Recarrega o arquivo de ignores a cada 10 segundos (aprox)
  if (ignore_file != "") {
    now = systime();
    if (now - last_ignore_reload >= 10) {
      load_ignore_file(ignore_file);
      last_ignore_reload = now;
    }
  }

  # Decide domínio e fonte
  domain = "";
  fonte  = "";

  if (dns_name != "") {
    domain = dns_name;
    fonte  = "DNS";
  } else if (tls_sni != "") {
    domain = tls_sni;
    fonte  = "TLS";
  } else if (http_host != "") {
    domain = http_host;
    fonte  = "HTTP";
  } else {
    next;
  }

  # Filtro de domínios ignorados
  if (should_ignore_domain(domain)) {
    next;
  }

  # Decide cliente (LAN) x remoto
  client = "";
  remote = "";

  if (src ~ lanre && !(dst ~ lanre)) {
    client = src;
    remote = dst;
  } else if (dst ~ lanre && !(src ~ lanre)) {
    client = dst;
    remote = src;
  } else if (src ~ lanre && dst ~ lanre) {
    client = src;
    remote = dst;
  } else {
    next;
  }

  host = domain;

  # DEDUPE: 1 log por chave a cada 1s
  key = client "|" host "|" remote "|" fonte;
  if (key in last_ts) {
    if (ts_epoch_int - last_ts[key] <= 1) {
      next;
    }
  }
  last_ts[key] = ts_epoch_int;

  # Converte epoch -> horário
  cmd_date = "date -d @" ts_epoch_int " \"+%Y-%m-%d %H:%M:%S\"";
  cmd_date | getline ts_str;
  close(cmd_date);

  # [+] TS | CLIENTE → HOST (REMOTE) | fonte=DNS/TLS/HTTP
  line_out = sprintf("[+] %s | %s → %s (%s) | fonte=%s",
                     ts_str, client, host, remote, fonte);

  print line_out >> logfile;
  fflush(logfile);
}
'
