#!/usr/bin/env bash

# Interface que "enxerga" a LAN
IFACE="enx00e04c68054d"

# Regex para identificar clientes LAN (ajuste se precisar)
LAN_REGEX="^192\\.168\\.3\\."

# Arquivo de saída com os contadores
OUTFILE="/var/log/traffic-domains/traffic-bytes.json"

# Intervalo (segundos) para gravar o JSON
FLUSH_INTERVAL=5

# Garante que o diretório existe
mkdir -p "$(dirname "$OUTFILE")"

echo "[traffic-bytes] Escutando na interface: $IFACE"
echo "[traffic-bytes] Clientes LAN: $LAN_REGEX"
echo "[traffic-bytes] Saída JSON: $OUTFILE (flush a cada ${FLUSH_INTERVAL}s)"

# -n   : sem resolver nome
# -tt  : timestamp epoch
# -q   : saída compacta
# -l   : line-buffered
# ip   : só tráfego IP
exec tcpdump -i "$IFACE" -n -tt -q -l ip 2>/dev/null | \
awk -v lanre="$LAN_REGEX" -v outfile="$OUTFILE" -v flush_interval="$FLUSH_INTERVAL" '
BEGIN {
  last_flush = systime();
}

# Exemplo:
# 1732831324.123456 IP 192.168.3.17.54778 > 157.240.12.174.443: tcp 1448

/^([0-9]+\.[0-9]+) IP / {
  src = $3;  # 192.168.3.17.54778
  dst = $5;  # 157.240.12.174.443:

  # Remove ":" do final e a porta
  gsub(/:$/, "", dst);
  sub(/\.[0-9]+$/, "", src);
  sub(/\.[0-9]+$/, "", dst);

  # Descobre o tamanho do pacote (último número "puro" depois de tcp/udp/icmp)
  size = 0;
  for (i = NF; i >= 1; i--) {
    if ($i ~ /^[0-9]+$/) {
      size = $i + 0;
      break;
    }
    if ($i == "tcp" || $i == "udp" || $i == "icmp") {
      break;
    }
  }
  if (size <= 0) next;

  is_src_client = (src ~ lanre);
  is_dst_client = (dst ~ lanre);

  # cliente -> internet
  if (is_src_client) {
    bytes_out[src]   += size;
    bytes_total[src] += size;
  }

  # internet -> cliente
  if (is_dst_client) {
    bytes_in[dst]    += size;
    bytes_total[dst] += size;
  }

  now = systime();
  if (now - last_flush >= flush_interval) {
    dump_json(outfile);
    last_flush = now;
  }
}

function dump_json(file,    first, c, mb_in, mb_out, mb_total, ts) {
  ts = strftime("%Y-%m-%d %H:%M:%S");
  printf("{\"updated_at\":\"%s\",\"clients\":{", ts) > file;
  first = 1;
  for (c in bytes_total) {
    if (!first) printf(",") > file;
    first = 0;
    mb_in    = bytes_in[c]   / 1048576.0;
    mb_out   = bytes_out[c]  / 1048576.0;
    mb_total = bytes_total[c]/ 1048576.0;
    printf("\"%s\":{", c) > file;
    printf("\"bytes_in\":%d,",   bytes_in[c]) > file;
    printf("\"bytes_out\":%d,",  bytes_out[c]) > file;
    printf("\"bytes_total\":%d,",bytes_total[c]) > file;
    printf("\"mb_in\":%.3f,",    mb_in) > file;
    printf("\"mb_out\":%.3f,",   mb_out) > file;
    printf("\"mb_total\":%.3f",  mb_total) > file;
    printf("}") > file;
  }
  printf("}}\n") > file;
  close(file);
}

END {
  dump_json(outfile);
}
'

