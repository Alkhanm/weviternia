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

mkdir -p "$LOG_DIR"

echo "[traffic-analyzer] Escutando interface: $IFACE"
echo "[traffic-analyzer] Clientes LAN (regex): $LAN_REGEX"
echo "[traffic-analyzer] Log: $LOG_FILE"
echo "[traffic-analyzer] Gateway para deduplicação: $GATEWAY_IP"
echo "[traffic-analyzer] Arquivo de ignore de domínios: $IGNORE_FILE"
echo "[traffic-analyzer] Arquivo de ignore de clientes: $IGNORE_CLIENTS_FILE"

exec tshark -i "$IFACE" -n -l \
  -T fields \
  -e frame.time_epoch \
  -e ip.src \
  -e ip.dst \
  -e dns.qry.name \
  -e tls.handshake.extensions_server_name \
  -e http.host \
  -Y "dns.qry.name or tls.handshake.extensions_server_name or http.host" 2>/dev/null | \
awk -v lanre="$LAN_REGEX" -v gateway_ip="$GATEWAY_IP" -v logfile="$LOG_FILE" -v ignore_file="$IGNORE_FILE" -v ignore_clients_file="$IGNORE_CLIENTS_FILE" '
BEGIN {
  FS = "\t";  # tshark -T fields separa por TAB
  
  # Janela de tempo para agrupar DNS + TLS/HTTP (segundos)
  GROUP_WINDOW = 5
  
  # Arrays para controle
  delete dns_cache  # Cache de consultas DNS recentes: dns_cache[client,domain] = timestamp
  delete dns_remote # IP remoto da consulta DNS: dns_remote[client,domain] = remote_ip
  delete last_log   # Último log por chave para deduplicação básica
  
  n_ignore = 0;
  last_ignore_reload = 0;

  if (ignore_file != "") {
    load_ignore_file(ignore_file);
    last_ignore_reload = systime();
  }
  
  n_ignore_clients = 0;
  last_ignore_clients_reload = 0;
  
  if (ignore_clients_file != "") {
    load_ignore_clients(ignore_clients_file);
    last_ignore_clients_reload = systime();
  }
}

# Carrega (ou recarrega) a lista de domínios ignorados
function load_ignore_file(file,   line) {
  n_ignore = 0;
  delete ignore_patterns;

  if (file == "") return;

  while ((getline line < file) > 0) {
    sub(/#.*/, "", line);
    gsub(/^ +| +$/, "", line);
    if (line == "") continue;

    n_ignore++;
    ignore_patterns[n_ignore] = line;
  }
  close(file);
}

# Carrega (ou recarrega) a lista de clientes ignorados
function load_ignore_clients(file,   line) {
  n_ignore_clients = 0;
  delete ignore_clients;

  if (file == "") return;

  while ((getline line < file) > 0) {
    sub(/#.*/, "", line);
    gsub(/^ +| +$/, "", line);
    if (line == "") continue;

    n_ignore_clients++;
    ignore_clients[n_ignore_clients] = line;
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

# Retorna 1 se o cliente (IP) deve ser ignorado
function should_ignore_client(ip,   i) {
  for (i = 1; i <= n_ignore_clients; i++) {
    if (ip ~ ignore_clients[i]) {
      return 1;
    }
  }
  return 0;
}

# Função para registrar log
function write_log(ts_str, client, host, remote, fonte, is_dns_gateway) {
  # Formata a saída
  if (is_dns_gateway) {
    line_out = sprintf("[+] %s | %s → %s (via DNS: %s) | fonte=%s",
                       ts_str, client, host, remote, fonte);
  } else {
    line_out = sprintf("[+] %s | %s → %s (%s) | fonte=%s",
                       ts_str, client, host, remote, fonte);
  }
  
  print line_out >> logfile;
  fflush(logfile);
}

# Limpa cache DNS antigo (mais velho que GROUP_WINDOW)
function cleanup_dns_cache(now,   key) {
  for (key in dns_cache) {
    if (now - dns_cache[key] > GROUP_WINDOW) {
      # Loga consultas DNS que não tiveram conexão subsequente
      split(key, parts, SUBSEP);
      client = parts[1];
      domain = parts[2];
      remote = dns_remote[key];
      
      # Converte timestamp
      cmd_date = "date -d @" dns_cache[key] " \"+%Y-%m-%d %H:%M:%S\"";
      cmd_date | getline ts_str;
      close(cmd_date);
      
      write_log(ts_str, client, domain, remote, "DNS", 1);
      
      # Remove do cache
      delete dns_cache[key];
      delete dns_remote[key];
    }
  }
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

  # Recarrega o arquivo de ignores a cada 10 segundos
  if (ignore_file != "") {
    now = systime();
    if (now - last_ignore_reload >= 10) {
      load_ignore_file(ignore_file);
      last_ignore_reload = now;
    }
  }
  
  # Recarrega o arquivo de ignores de clientes a cada 10 segundos
  if (ignore_clients_file != "") {
    now = systime();
    if (now - last_ignore_clients_reload >= 10) {
      load_ignore_clients(ignore_clients_file);
      last_ignore_clients_reload = now;
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
  
  # Filtro de clientes ignorados
  if (should_ignore_client(client)) {
    next;
  }

  # Limpa cache DNS antigo
  cleanup_dns_cache(ts_epoch_int);

  # Lógica de deduplicação inteligente
  if (fonte == "DNS" && remote == gateway_ip) {
    # É uma consulta DNS para o gateway - armazena no cache
    key = client SUBSEP domain;
    dns_cache[key] = ts_epoch_int;
    dns_remote[key] = remote;
    
    # NÃO loga imediatamente - aguarda possível conexão TLS/HTTP
    next;
  }
  else if (fonte == "TLS" || fonte == "HTTP") {
    # É uma conexão TLS/HTTP - verifica se há consulta DNS recente
    key = client SUBSEP domain;
    
    if (key in dns_cache) {
      # Encontrou consulta DNS recente para o mesmo domínio/cliente
      # Remove do cache (não vamos logar a consulta DNS separadamente)
      delete dns_cache[key];
      delete dns_remote[key];
      
      # Loga a conexão TLS/HTTP normalmente
      # (já está configurado para logar abaixo)
    }
  }

  # Converte epoch -> horário
  cmd_date = "date -d @" ts_epoch_int " \"+%Y-%m-%d %H:%M:%S\"";
  cmd_date | getline ts_str;
  close(cmd_date);

  # Deduplicação básica: 1 log por chave a cada 1s (mantido do original)
  key = client "|" domain "|" remote "|" fonte;
  if (key in last_log) {
    if (ts_epoch_int - last_log[key] <= 1) {
      next;
    }
  }
  last_log[key] = ts_epoch_int;

  # Loga o evento
  write_log(ts_str, client, domain, remote, fonte, 0);
}

END {
  # No final, loga quaisquer consultas DNS pendentes no cache
  now = systime();
  for (key in dns_cache) {
    split(key, parts, SUBSEP);
    client = parts[1];
    domain = parts[2];
    remote = dns_remote[key];
    
    cmd_date = "date -d @" dns_cache[key] " \"+%Y-%m-%d %H:%M:%S\"";
    cmd_date | getline ts_str;
    close(cmd_date);
    
    write_log(ts_str, client, domain, remote, "DNS", 1);
  }
}
'