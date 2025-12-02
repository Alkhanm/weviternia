#!/usr/bin/env bash

# Interface da LAN (ajuste se precisar)
IFACE="enx00e04c68054d"

# Faixa dos clientes internos (regex)
LAN_REGEX="^192\\.168\\.3\\."

LOG_DIR="/var/log/traffic-domains"
LOG_FILE="$LOG_DIR/traffic-domains.log"

IGNORE_FILE="/etc/traffic-monitor/ignore-domains.txt"

mkdir -p "$LOG_DIR"

echo "[traffic-analyzer] Usando interface: $IFACE"
echo "[traffic-analyzer] Clientes LAN: $LAN_REGEX"
echo "[traffic-analyzer] Log: $LOG_FILE"
echo "[traffic-analyzer] Ignore file: $IGNORE_FILE"

# tshark:
# -i IFACE
# -l                  : line-buffer
# -T fields           : saída em colunas
# -e frame.time_epoch : epoch
# -e ip.src/ip.dst
# -e dns.qry.name
# -e http.host
# -e tls.handshake.extensions_server_name
exec tshark -i "$IFACE" \
  -l \
  -T fields \
  -e frame.time_epoch \
  -e ip.src \
  -e ip.dst \
  -e dns.qry.name \
  -e http.host \
  -e tls.handshake.extensions_server_name \
  2>/dev/null | \
awk -v lanre="$LAN_REGEX" -v logfile="$LOG_FILE" -v ignorefile="$IGNORE_FILE" '
BEGIN {
  FS = "\t";
  last_reload = 0;
  IGNORE_RELOAD_INTERVAL = 10;   # segundos
}

function reload_ignore(   line, f, n) {
  delete ignore_patterns;
  ignore_count = 0;

  if (ignorefile == "") return;

  while ((getline line < ignorefile) > 0) {
    gsub(/\r/, "", line);
    sub(/#.*/, "", line); # remove comentários
    line = trim(line);
    if (line == "") continue;
    ignore_patterns[++ignore_count] = line;
  }
  close(ignorefile);
}

function trim(s) {
  sub(/^[ \t\r\n]+/, "", s);
  sub(/[ \t\r\n]+$/, "", s);
  return s;
}

function should_ignore(domain, host, remote,   i, p) {
  for (i = 1; i <= ignore_count; i++) {
    p = ignore_patterns[i];
    if (p == "") continue;
    if (domain ~ p) return 1;
    if (host   ~ p) return 1;
    if (remote ~ p) return 1;
  }
  return 0;
}

# Converte epoch inteiro para string de data/hora
function format_ts(epoch,   cmd, out) {
  cmd = "date -d @" epoch " \"+%Y-%m-%d %H:%M:%S\"";
  cmd | getline out;
  close(cmd);
  if (out == "") out = epoch;
  return out;
}

/^/ {
  # recarrega ignore periodicamente
  now = systime();
  if (now - last_reload >= IGNORE_RELOAD_INTERVAL) {
    reload_ignore();
    last_reload = now;
  }

  if (NF < 3) next;

  ts_epoch_full = $1;
  src = $2;
  dst = $3;

  dns_name = (NF >= 4 ? $4 : "");
  http_host = (NF >= 5 ? $5 : "");
  tls_sni = (NF >= 6 ? $6 : "");

  src = trim(src);
  dst = trim(dst);

  if (src == "" || dst == "") next;

  client = "";
  remote = "";

  if (src ~ lanre && !(dst ~ lanre)) {
    client = src;
    remote = dst;
  } else if (dst ~ lanre && !(src ~ lanre)) {
    client = dst;
    remote = src;
  } else {
    # ou não é tráfego LAN <-> WAN, ou LAN <-> LAN
    next;
  }

  # decide domínio e fonte
  domain = "";
  fonte  = "";

  dns_name = trim(dns_name);
  http_host = trim(http_host);
  tls_sni = trim(tls_sni);

  if (dns_name != "") {
    domain = dns_name;
    fonte = "DNS";
  } else if (http_host != "") {
    domain = http_host;
    fonte = "HTTP";
  } else if (tls_sni != "") {
    domain = tls_sni;
    fonte = "TLS-SNI";
  } else {
    # sem domínio explícito, podemos logar só IP se quisermos
    domain = "";
    fonte = "IP";
  }

  # aplica ignore
  if (should_ignore(domain, domain, remote)) {
    next;
  }

  # deduplicação: chave por segundo + client + remote + dominio + fonte
  ts_int = int(ts_epoch_full + 0.5);
  key = ts_int "|" client "|" remote "|" domain "|" fonte;
  if (key in last_seen && last_seen[key] == ts_int) {
    next;
  }
  last_seen[key] = ts_int;

  ts_str = format_ts(ts_int);

  if (domain != "") {
    line_out = sprintf("[+] %s | %s → %s (%s) | fonte=%s", ts_str, client, domain, remote, fonte);
  } else {
    line_out = sprintf("[+] %s | %s → %s (%s)", ts_str, client, remote, remote);
  }

  print line_out >> logfile;
  fflush(logfile);
}
'

