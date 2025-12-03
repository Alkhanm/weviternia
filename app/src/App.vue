<template>
  <div>
    <header>
      <div class="title-block">
        <h1>Traffic Monitor</h1>
        <span class="tag">LAN Observer</span>
        <span class="tag">Passive Sniffer</span>
      </div>
      <div class="status">
        <span>{{ status }}</span>
      </div>
    </header>

    <main>
      <section class="controls">
        <label>
          Cliente
          <select v-model="selectedClient" @change="reloadAll">
            <option value="all">Todos</option>
            <option v-for="ip in clients" :key="ip" :value="ip">
              {{ ip }}
            </option>
          </select>
        </label>

        <label>
          Limite eventos
          <input type="number" min="10" max="5000" v-model.number="limit" @change="reloadLogs" />
        </label>

        <label>
          Janela
          <select v-model="timeWindow">
            <option value="all">Tudo</option>
            <option value="30m">30 min</option>
            <option value="1h">1 h</option>
            <option value="2h">2 h</option>
          </select>
        </label>

        <label>
          Filtro texto
          <input type="text" v-model="filterText" placeholder="domínio, IP, fonte..." />
        </label>

        <label>
          Refresh (s)
          <input type="number" min="5" max="300" v-model.number="refreshInterval" @change="setupAutoRefresh" />
        </label>

        <button @click="reloadAll">Atualizar agora</button>

        <label class="toggle-group">
          <input type="checkbox" v-model="groupMode" />
          Agrupar por domínio
        </label>

        <button v-if="ignoredDomains.length" class="chip-toggle-btn" @click="toggleIgnoredBox">
          {{ showIgnoredBox ? 'Ocultar domínios ignorados' : 'Mostrar domínios ignorados' }}
          ({{ ignoredDomains.length }})
        </button>
      </section>

      <div class="ignored-box" v-if="ignoredDomains.length && showIgnoredBox">
        <strong>Domínios ignorados:</strong>
        <span class="ignored-chip" v-for="dom in ignoredDomains" :key="dom">
          <span class="chip-label">{{ dom }}</span>
          <button class="chip-remove" @click="unignoreDomain(dom)" title="Remover domínio da lista de ignorados">
            ×
          </button>
        </span>
      </div>

      <section class="summary-section">
        <div class="summary-header">
          <h2>Resumo (sessão atual)</h2>
          <span v-if="bytesData.updated_at" class="summary-meta">
            Atualizado em {{ bytesData.updated_at }}
          </span>
        </div>
        <table class="summary-table">
          <thead>
            <tr>
              <th>Último acesso</th>
              <th>Cliente</th>
              <th>MB Recebido</th>
              <th>MB Enviado</th>
              <th>MB Total</th>
              <th>Online</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="row in summaryRows" :key="row.ip">
              <td>
                <span :class="['status-pill', row.online ? 'online' : 'offline']">
                  {{ row.online ? 'Online' : 'Offline' }}
                </span>
              </td>
              <td>{{ row.ip }}</td>
              <td>{{ row.mb_in.toFixed(3) }}</td>
              <td>{{ row.mb_out.toFixed(3) }}</td>
              <td>{{ row.mb_total.toFixed(3) }}</td>
              <td>{{ formatTimePart(row.lastSeen) || '-' }}</td>
            </tr>
          </tbody>
        </table>
      </section>

      <section class="table-section">
        <div class="table-header">
          <h2>Eventos recentes</h2>
        </div>
        <div class="table-wrapper">
          <table class="log-table">
            <thead>
              <tr>
                <th class="ts" @click="changeSort('timestamp')">
                  Horário
                  <span class="sort-indicator" v-if="sortKey === 'timestamp'">
                    {{ sortDir === 'asc' ? '▲' : '▼' }}
                  </span>
                </th>
                <th class="client" @click="changeSort('client')">
                  Cliente
                  <span class="sort-indicator" v-if="sortKey === 'client'">
                    {{ sortDir === 'asc' ? '▲' : '▼' }}
                  </span>
                </th>
                <th class="ip" @click="changeSort('remote_ip')">
                  IP remoto
                  <span class="sort-indicator" v-if="sortKey === 'remote_ip'">
                    {{ sortDir === 'asc' ? '▲' : '▼' }}
                  </span>
                </th>
                <th class="text">
                  Dominio
                </th>
                <th v-if="groupMode" class="count" @click="changeSort('count')">
                  Qtd
                  <span class="sort-indicator" v-if="sortKey === 'count'">
                    {{ sortDir === 'asc' ? '▲' : '▼' }}
                  </span>
                </th>
                <th class="source source-col" @click="changeSort('source')">
                  Fonte
                  <span class="sort-indicator" v-if="sortKey === 'source'">
                    {{ sortDir === 'asc' ? '▲' : '▼' }}
                  </span>
                </th>
                <th class="text">
                  Detalhes
                </th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="entry in displayLogs" :key="entry.key">
                <td class="ts">
                  <span class="ts-date">{{ formatDatePart(entry.timestamp) }}</span>
                  <span class="ts-time">{{ formatTimePart(entry.timestamp) }}</span>
                </td>
                <td class="client">{{ entry.client }}</td>
                <td class="ip">
                  <a v-if="entry.remote_ip" :href="'http://' + entry.remote_ip" target="_blank" rel="noreferrer">
                    {{ entry.remote_ip }}
                  </a>
                  <span v-else>-</span>
                  <button v-if="entry.remote_ip" class="ipinfo-btn" @click.stop="openIpInfo(entry.remote_ip)"
                    title="Abrir ipinfo.io">
                    ipinfo
                  </button>
                </td>
                <td class="text">
                  <span>{{ entry.domain || '-' }}</span>
                  <button v-if="entry.domain" class="ignore-btn" @click.stop="ignoreDomain(entry.domain)"
                    title="Ignorar futuras entradas deste domínio">
                    Ignorar domínio
                  </button>
                </td>
                <td v-if="groupMode" class="count">
                  {{ entry.count || 1 }}
                </td>
                <td class="source source-col">
                  {{ entry.source || '-' }}
                </td>
                <td class="text">
                  <span v-html="highlight(entry.raw || '')"></span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </main>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import type {
  SortKey,
  TimeWindow,
  LogEntryRaw,
  LogEntryDisplay,
  BytesData,
  LastSeenEntry,
  SummaryRow
} from './types';

// --------------------------
// estado reativo
// --------------------------
const status = ref<string>('Carregando...');
const clients = ref<string[]>([]);
const selectedClient = ref<string>('all');
const limit = ref<number>(500);
const timeWindow = ref<TimeWindow>('all');
const filterText = ref<string>('');
const refreshInterval = ref<number>(10);
const refreshTimerId = ref<number | null>(null);

const logsRaw = ref<LogEntryRaw[]>([]);
const bytesData = ref<BytesData>({ updated_at: null, clients: {} });

const sortKey = ref<SortKey>('timestamp');
const sortDir = ref<'asc' | 'desc'>('desc');
const groupMode = ref<boolean>(false);

const ONLINE_THRESHOLD_SECONDS = 120;

const ignoredDomains = ref<string[]>([]);
const showIgnoredBox = ref<boolean>(true);

// --------------------------
// helpers básicos
// --------------------------
async function fetchJSON<T = any>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return (await res.json()) as T;
}

function parseTimestampToDate(ts: string | null): Date | null {
  if (!ts) return null;
  const parts = ts.split(' ');
  if (parts.length < 2) return null;
  const iso = `${parts[0]}T${parts[1]}`;
  const d = new Date(iso);
  if (isNaN(d.getTime())) return null;
  return d;
}

function formatTimestamp(d: Date): string {
  const pad = (n: number) => (n < 10 ? '0' + n : '' + n);
  const y = d.getFullYear();
  const m = pad(d.getMonth() + 1);
  const day = pad(d.getDate());
  const h = pad(d.getHours());
  const mi = pad(d.getMinutes());
  const s = pad(d.getSeconds());
  return `${y}-${m}-${day} ${h}:${mi}:${s}`;
}

function getTimeWindowMinDate(): Date | null {
  const now = new Date();
  const tw = timeWindow.value;
  if (tw === 'all') return null;

  const d = new Date(now);
  if (tw === '30m') d.setMinutes(d.getMinutes() - 30);
  else if (tw === '1h') d.setHours(d.getHours() - 1);
  else if (tw === '2h') d.setHours(d.getHours() - 2);
  return d;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function highlight(text: string): string {
  const term = filterText.value.trim();
  if (!term) return escapeHtml(text);
  const escTerm = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(escTerm, 'gi');
  return escapeHtml(text).replace(re, (m) => `<mark>${m}</mark>`);
}

function formatDatePart(ts: string | null): string {
  if (!ts) return '';
  const parts = ts.split(' ');
  return parts[0] || ts;
}

function formatTimePart(ts: string | null): string {
  if (!ts) return '';
  const parts = ts.split(' ');
  return parts[1] || ts;
}

function openIpInfo(ip: string | null): void {
  if (!ip) return;
  window.open(`https://ipinfo.io/${encodeURIComponent(ip)}`, '_blank');
}

// --------------------------
// derivado: logs filtrados
// --------------------------
const filteredLogs = computed<LogEntryRaw[]>(() => {
  let logs = logsRaw.value;
  const minDate = getTimeWindowMinDate();
  const filter = filterText.value.trim().toLowerCase();

  if (minDate) {
    logs = logs.filter((entry) => {
      if (!entry.timestamp) return false;
      const dt = parseTimestampToDate(entry.timestamp);
      if (!dt) return false;
      return dt >= minDate;
    });
  }

  if (ignoredDomains.value.length > 0) {
    logs = logs.filter((entry) => {
      if (!entry.domain) return true;
      return !ignoredDomains.value.includes(entry.domain);
    });
  }

  if (filter) {
    logs = logs.filter((entry) =>
      (entry.raw || '').toLowerCase().includes(filter)
    );
  }

  return logs;
});

// --------------------------
// derivado: lastSeen por cliente
// --------------------------
const lastSeenByClient = computed<Record<string, LastSeenEntry>>(() => {
  const map: Record<string, LastSeenEntry> = {};
  for (const e of filteredLogs.value) {
    if (!e.client || !e.timestamp) continue;
    const d = parseTimestampToDate(e.timestamp);
    if (!d) continue;
    const existing = map[e.client];
    if (!existing || d > existing.ts) {
      map[e.client] = { ts: d, raw: e.raw };
    }
  }
  return map;
});

// --------------------------
// derivado: summaryRows (tabela de bytes)
// --------------------------
const summaryRows = computed<SummaryRow[]>(() => {
  const rows: SummaryRow[] = [];
  const bytes = bytesData.value.clients || {};
  const lastSeenMap = lastSeenByClient.value;
  const now = Date.now();

  for (const ip of Object.keys(bytes).sort()) {
    const info = bytes[ip];
    const last = lastSeenMap[ip];
    let online = false;
    let lastSeenStr: string | null = null;

    if (last && last.ts) {
      const diffSec = (now - last.ts.getTime()) / 1000;
      online = diffSec <= ONLINE_THRESHOLD_SECONDS;
      lastSeenStr = formatTimestamp(last.ts);
    }

    rows.push({
      ip,
      mb_in: info?.mb_in || 0,
      mb_out: info?.mb_out || 0,
      mb_total: info?.mb_total || 0,
      online,
      lastSeen: lastSeenStr
    });
  }

  return rows;
});

// --------------------------
// derivado: displayLogs (tabela de eventos)
// --------------------------
const displayLogs = computed<LogEntryDisplay[]>(() => {
  let logs: LogEntryDisplay[];

  if (groupMode.value) {
    const grouped = new Map<string, LogEntryDisplay>();

    for (const e of filteredLogs.value) {
      const key = `${e.domain || ''}||${e.client || ''}||${e.remote_ip || ''}||${e.source || ''}`;
      const existing = grouped.get(key);
      const dt = parseTimestampToDate(e.timestamp);

      if (!existing) {
        grouped.set(key, {
          ...e,
          key,
          count: 1
        });
      } else {
        existing.count += 1;
        const existingDate = parseTimestampToDate(existing.timestamp);
        if (dt && existingDate && dt > existingDate) {
          existing.timestamp = e.timestamp;
          existing.raw = e.raw;
        }
      }
    }

    logs = Array.from(grouped.values());
  } else {
    logs = filteredLogs.value.map((e, idx) => ({
      ...e,
      count: 1,
      key: `${e.timestamp}-${idx}`
    }));
  }

  logs.sort((a, b) => {
    const dir = sortDir.value === 'asc' ? 1 : -1;
    const k = sortKey.value;

    if (k === 'timestamp') {
      const da = parseTimestampToDate(a.timestamp);
      const db = parseTimestampToDate(b.timestamp);
      const va = da ? da.getTime() : 0;
      const vb = db ? db.getTime() : 0;
      return (va - vb) * dir;
    }

    if (k === 'count') {
      const va = a.count || 0;
      const vb = b.count || 0;
      return (va - vb) * dir;
    }

    const va = ((a as any)[k] ?? '').toString();
    const vb = ((b as any)[k] ?? '').toString();

    if (va < vb) return -1 * dir;
    if (va > vb) return 1 * dir;
    return 0;
  });

  return logs;
});

// --------------------------
// ações (fetch de dados)
// --------------------------
async function loadClients(): Promise<void> {
  try {
    const data = await fetchJSON<{ clients: string[] }>('/clients');
    clients.value = data.clients || [];
  } catch (e) {
    console.error('Erro ao carregar /clients', e);
    clients.value = [];
  }
}

async function loadIgnoredDomains(): Promise<void> {
  try {
    const data = await fetchJSON<{ domains: string[] }>('/ignored-domains');
    ignoredDomains.value = data.domains || [];
  } catch (e) {
    console.error('Erro ao carregar /ignored-domains', e);
    ignoredDomains.value = [];
  }
}

async function loadLogs(): Promise<void> {
  try {
    status.value = 'Carregando logs...';

    const params = new URLSearchParams();
    params.set('limit', (limit.value || 500).toString());
    if (selectedClient.value && selectedClient.value !== 'all') {
      params.set('client', selectedClient.value);
    }

    const data = await fetchJSON<{ entries: LogEntryRaw[] }>('/logs?' + params.toString());
    logsRaw.value = data.entries || [];

    status.value = `Carregado: ${logsRaw.value.length} eventos`;
  } catch (e) {
    console.error('Erro ao carregar /logs', e);
    logsRaw.value = [];
    status.value = 'Erro ao carregar logs';
  }
}

async function loadBytes(): Promise<void> {
  try {
    const data = await fetchJSON<BytesData>('/bytes');
    bytesData.value = data || { updated_at: null, clients: {} };
  } catch (e) {
    console.error('Erro ao carregar /bytes', e);
    bytesData.value = { updated_at: null, clients: {} };
  }
}

async function reloadAll(): Promise<void> {
  await loadLogs();
  await loadBytes();
}

function reloadLogs(): void {
  void loadLogs();
}

// --------------------------
// ações de UI
// --------------------------
function changeSort(key: SortKey): void {
  if (sortKey.value === key) {
    sortDir.value = sortDir.value === 'asc' ? 'desc' : 'asc';
  } else {
    sortKey.value = key;
    sortDir.value = key === 'timestamp' ? 'desc' : 'asc';
  }
}

function setupAutoRefresh(): void {
  if (refreshTimerId.value !== null) {
    clearInterval(refreshTimerId.value);
    refreshTimerId.value = null;
  }

  const intervalMs = (refreshInterval.value || 10) * 1000;
  const id = setInterval(() => {
    void reloadAll();
  }, intervalMs);

  refreshTimerId.value = id as unknown as number;
}

async function ignoreDomain(domain: string | null): Promise<void> {
  if (!domain) return;
  try {
    const res = await fetch('/ignored-domains', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain })
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    ignoredDomains.value = data.domains || [];
    await loadLogs();
  } catch (e) {
    console.error('Erro ao ignorar domínio', domain, e);
  }
}

async function unignoreDomain(domain: string | null): Promise<void> {
  if (!domain) return;
  try {
    const res = await fetch('/ignored-domains?domain=' + encodeURIComponent(domain), {
      method: 'DELETE'
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    ignoredDomains.value = data.domains || [];
    await loadLogs();
  } catch (e) {
    console.error('Erro ao remover domínio ignorado', domain, e);
  }
}

function toggleIgnoredBox(): void {
  showIgnoredBox.value = !showIgnoredBox.value;
}

// --------------------------
// lifecycle
// --------------------------
onMounted(async () => {
  await loadClients();
  await loadIgnoredDomains();
  await reloadAll();
  setupAutoRefresh();
});
</script>
