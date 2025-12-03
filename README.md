# Weviternia

Monitor passivo de tráfego da LAN, com:

- **Sniffer** em shell (tcpdump + awk)
- **Mini API** em Node.js
- **Dashboard** em Vue 3 + TypeScript

Objetivo: ver **o que cada IP da rede acessa** e **quanto trafega**, sem instalar nada nos clientes.

---

## Visão geral

### Componentes

1. **Sniffer de domínios – `analyzer.sh`**
   - Usa `tcpdump` na interface da LAN.
   - Extrai:
     - IP do cliente
     - IP remoto
     - host/domínio (DNS / reverse / SNI / etc.)
   - Escreve em `traffic-domains.log`:

     ```text
     [+] 2025-12-01 19:29:20 | 192.168.3.11 → exemplo.com (1.2.3.4) | fonte=DNS
     ```

   - Respeita uma lista de domínios ignorados (`ignore-domains.txt`).

2. **Sniffer de bytes – `bytes.sh`**
   - Também usa `tcpdump` na LAN.
   - Soma bytes *in/out* por IP de cliente.
   - Gera `traffic-bytes.json`, ex.:

     ```json
     {
       "updated_at": "2025-12-01 11:37:31",
       "clients": {
         "192.168.3.5": {
           "bytes_in": 698698,
           "bytes_out": 11921,
           "mb_in": 0.666,
           "mb_out": 0.011,
           "mb_total": 0.678
         }
       }
     }
     ```

3. **API HTTP – `traffic-api` (Node.js + TS)**
   - Porta padrão: **9080**.
   - Endpoints:
     - `GET /` → dashboard estático (build do Vite).
     - `GET /logs` → últimos eventos de `traffic-domains.log`.
     - `GET /bytes` → dados de `traffic-bytes.json`.
     - `GET /clients` → lista de IPs com tráfego.
     - `GET /ignored-domains` → lista de domínios ignorados.
     - `POST /ignored-domains` → adiciona domínio ignorado.
     - `DELETE /ignored-domains` → remove domínio ignorado.
   - Qualquer outro `GET` serve arquivo estático do diretório `web/` (JS/CSS/etc do build do Vite).

4. **Orquestrador – `monitor.sh`**
   - Sobe:
     - `analyzer.sh`
     - `bytes.sh`
     - `traffic-api.js`
   - Trata SIGTERM/SIGINT e derruba tudo de forma limpa (pensado para systemd).

---

## Estrutura em produção

Instalado em `/opt/traffic-monitor`:

```text
/opt/traffic-monitor
  ├── bin/
  │   ├── analyzer.sh       # sniffer de domínios
  │   ├── bytes.sh          # sniffer de bytes
  │   └── monitor.sh        # start de tudo
  ├── server/
  │   └── traffic-api.js    # API compilada (Node)
  ├── web/
  │   ├── index.html        # build do Vite
  │   └── assets/...        # JS/CSS/etc
  ├── logs/
  │   ├── traffic-domains.log
  │   └── traffic-bytes.json
  └── config/
      └── ignore-domains.txt
