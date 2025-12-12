#!/usr/bin/env bash

# Interface da LAN
IFACE="enx00e04c68054d"

# Faixa dos clientes internos (ajuste se mudar sua LAN)
LAN_REGEX="^192\.168\.1\."

# Gateway/DNS local para deduplicação
GATEWAY_IP="192.168.1.1"

LOG_DIR="/var/log/traffic-domains"
LOG_FILE="$LOG_DIR/traffic-domains.log"

# Arquivo de domínios a ignorar (um regex por linha)
IGNORE_FILE="${IGNORE_FILE:-/etc/traffic-monitor/ignore-domains.txt}"

# Arquivo de clientes a ignorar (um regex por linha)
IGNORE_CLIENTS_FILE="${IGNORE_CLIENTS_FILE:-/etc/traffic-monitor/ignore-clients.txt}"

# Arquivo de mapeamento de Nomes (Formato: IP Hostname)
HOSTS_MAP_FILE="${HOSTS_MAP_FILE:-/etc/traffic-monitor/lan-hosts.txt}"

mkdir -p "$LOG_DIR"

echo "[traffic-analyzer] Escutando interface: $IFACE"
echo "[traffic-analyzer] Clientes LAN (regex): $LAN_REGEX"
echo "[traffic-analyzer] Log: $LOG_FILE"
echo "[traffic-analyzer] Map de Hosts: $HOSTS_MAP_FILE"

exec tshark -i "$IFACE" -n -l \
  -T fields \
  -e frame.time_epoch \
  -e ip.src \
  -e ip.dst \
  -e dns.qry.name \
  -e tls.handshake.extensions_server_name \
  -e http.host \
  -Y "dns.qry.name or tls.handshake.extensions_server_name or http.host" 2>/dev/null | \
awk -v lanre="$LAN_REGEX" \
    -v gateway_ip="$GATEWAY_IP" \
    -v logfile="$LOG_FILE" \
    -v ignore_file="$IGNORE_FILE" \
    -v ignore_clients_file="$IGNORE_CLIENTS_FILE" \
    -v hosts_map_file="$HOSTS_MAP_FILE" '
BEGIN {
  FS = "\t";
  
  # Janela de tempo para agrupar DNS + TLS/HTTP (segundos)
  GROUP_WINDOW = 5
  
  # Arrays para controle
  delete dns_cache
  delete dns_remote
  delete last_log
  delete ip_to_name
  
  # Timers de recarga
  last_ignore_reload = 0;
  last_ignore_clients_reload = 0;
  last_hosts_reload = 0;

  # Carregamento inicial
  if (ignore_file != "") load_ignore_file(ignore_file);
  if (ignore_clients_file != "") load_ignore_clients(ignore_clients_file);
  if (hosts_map_file != "") load_hosts_map(hosts_map_file);
  
  now_ts = systime();
  last_ignore_reload = now_ts;
  last_ignore_clients_reload = now_ts;
  last_hosts_reload = now_ts;
}

# --- FUNÇÕES DE CARREGAMENTO ---

function load_ignore_file(file,   line) {
  n_ignore = 0;
  delete ignore_patterns;
  if (file == "") return;
  while ((getline line < file) > 0) {
    sub(/#.*/, "", line); gsub(/^ +| +$/, "", line);
    if (line != "") ignore_patterns[++n_ignore] = line;
  }
  close(file);
}

function load_ignore_clients(file,   line) {
  n_ignore_clients = 0;
  delete ignore_clients;
  if (file == "") return;
  while ((getline line < file) > 0) {
    sub(/#.*/, "", line); gsub(/^ +| +$/, "", line);
    if (line != "") ignore_clients[++n_ignore_clients] = line;
  }
  close(file);
}

function load_hosts_map(file,   line, fields, n) {
  delete ip_to_name;
  if (file == "") return;
  while ((getline line < file) > 0) {
    sub(/#.*/, "", line); gsub(/^ +| +$/, "", line);
    if (line == "") continue;
    
    n = split(line, fields, /[ \t]+/);
    if (n >= 2) {
      ip_to_name[fields[1]] = fields[2];
    }
  }
  close(file);
}

# --- FUNÇÕES AUXILIARES ---

function should_ignore_domain(d,   i) {
  if (d == "") return 0;
  for (i = 1; i <= n_ignore; i++) if (d ~ ignore_patterns[i]) return 1;
  return 0;
}

function should_ignore_client(ip,   i) {
  for (i = 1; i <= n_ignore_clients; i++) if (ip ~ ignore_clients[i]) return 1;
  return 0;
}

# ALTERADO: Sempre retorna o formato "IP (Identificador)"
# Se não houver hostname, o identificador será o próprio IP.
function resolve_client_name(ip) {
  if (ip in ip_to_name) {
    return ip " (" ip_to_name[ip] ")";
  } else {
    return ip " (" ip ")";
  }
}

function write_log(ts_str, client_ip, host, remote, fonte, is_dns_gateway) {
  client_display = resolve_client_name(client_ip);

  if (is_dns_gateway) {
    line_out = sprintf("[+] %s | %s → %s (via DNS: %s) | fonte=%s",
                       ts_str, client_display, host, remote, fonte);
  } else {
    line_out = sprintf("[+] %s | %s → %s (%s) | fonte=%s",
                       ts_str, client_display, host, remote, fonte);
  }
  
  print line_out >> logfile;
  fflush(logfile);
}

function cleanup_dns_cache(now,   key, parts, c_ip, d_dom, d_rem, cmd_d, t_s) {
  for (key in dns_cache) {
    if (now - dns_cache[key] > GROUP_WINDOW) {
      split(key, parts, SUBSEP);
      c_ip = parts[1];
      d_dom = parts[2];
      d_rem = dns_remote[key];
      
      cmd_d = "date -d @" dns_cache[key] " \"+%Y-%m-%d %H:%M:%S\"";
      cmd_d | getline t_s;
      close(cmd_d);
      
      write_log(t_s, c_ip, d_dom, d_rem, "DNS", 1);
      
      delete dns_cache[key];
      delete dns_remote[key];
    }
  }
}

# --- PROCESSAMENTO PRINCIPAL ---
NF >= 3 {
  ts_epoch = $1;
  src      = $2;
  dst      = $3;
  dns_name = (NF >= 4 ? $4 : "");
  tls_sni  = (NF >= 5 ? $5 : "");
  http_host= (NF >= 6 ? $6 : "");

  ts_epoch_int = int(ts_epoch + 0);
  now = systime();

  # Recargas periódicas (10s)
  if (ignore_file != "" && now - last_ignore_reload >= 10) {
    load_ignore_file(ignore_file); last_ignore_reload = now;
  }
  if (ignore_clients_file != "" && now - last_ignore_clients_reload >= 10) {
    load_ignore_clients(ignore_clients_file); last_ignore_clients_reload = now;
  }
  if (hosts_map_file != "" && now - last_hosts_reload >= 10) {
    load_hosts_map(hosts_map_file); last_hosts_reload = now;
  }

  # Identificação do Domínio e Fonte
  domain = ""; fonte  = "";
  if (dns_name != "") { domain = dns_name; fonte = "DNS"; }
  else if (tls_sni != "") { domain = tls_sni; fonte = "TLS"; }
  else if (http_host != "") { domain = http_host; fonte = "HTTP"; }
  else { next; }

  if (should_ignore_domain(domain)) next;

  # Identificação Cliente vs Remoto
  client = ""; remote = "";
  if (src ~ lanre && !(dst ~ lanre)) { client = src; remote = dst; }
  else if (dst ~ lanre && !(src ~ lanre)) { client = dst; remote = src; }
  else if (src ~ lanre && dst ~ lanre) { client = src; remote = dst; }
  else { next; }
  
  if (should_ignore_client(client)) next;

  cleanup_dns_cache(ts_epoch_int);

  # Deduplicação / Cache DNS
  if (fonte == "DNS" && remote == gateway_ip) {
    key = client SUBSEP domain;
    dns_cache[key] = ts_epoch_int;
    dns_remote[key] = remote;
    next;
  }
  else if (fonte == "TLS" || fonte == "HTTP") {
    key = client SUBSEP domain;
    if (key in dns_cache) {
      delete dns_cache[key];
      delete dns_remote[key];
    }
  }

  cmd_date = "date -d @" ts_epoch_int " \"+%Y-%m-%d %H:%M:%S\"";
  cmd_date | getline ts_str;
  close(cmd_date);

  key = client "|" domain "|" remote "|" fonte;
  if (key in last_log) {
    if (ts_epoch_int - last_log[key] <= 1) next;
  }
  last_log[key] = ts_epoch_int;

  write_log(ts_str, client, domain, remote, fonte, 0);
}

END {
  now = systime();
  for (key in dns_cache) {
    split(key, parts, SUBSEP);
    c_ip = parts[1];
    d_dom = parts[2];
    d_rem = dns_remote[key];
    
    cmd_d = "date -d @" dns_cache[key] " \"+%Y-%m-%d %H:%M:%S\"";
    cmd_d | getline t_s;
    close(cmd_d);
    
    write_log(t_s, c_ip, d_dom, d_rem, "DNS", 1);
  }
}
'