import http, { IncomingMessage, ServerResponse } from 'http';
import fs from 'fs';
import path from 'path';
import { parse as parseUrl } from 'url';
import type { ParsedUrlQuery } from 'querystring';

const HOST = '100.76.63.123';
const PORT = Number(process.env.PORT ?? 9080);

// diretório de instalação: /opt/traffic-monitor
const BASE_DIR = path.join(__dirname, '..');

// onde o Vite colocou o build: /opt/traffic-monitor/web
const WEB_DIR = path.join(BASE_DIR, 'web');

// arquivos de log/config continuam como estavam:
const LOG_FILE = process.env.LOG_FILE || '/var/log/traffic-domains/traffic-domains.log';
const BYTES_FILE = process.env.BYTES_FILE || '/var/log/traffic-domains/traffic-bytes.json';
const IGNORE_FILE = process.env.IGNORE_FILE || '/etc/traffic-monitor/ignore-domains.txt';

// mapa simples de Content-Type
const MIME_MAP: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.htm': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.json': 'application/json; charset=utf-8',
};


/**
 * dateStr: "YYYY-MM-DD" ou vazio/undefined para hoje.
 * Retorna caminho do arquivo + flag se está gzipado.
 */
function resolveLogPathForDate(dateStr?: string | null): { file: string; exists: boolean } {
  const today = new Date();
  const todayStr = today.toISOString().slice(0, 10); // YYYY-MM-DD

  // Se não veio data ou é hoje → arquivo atual
  if (!dateStr || dateStr === todayStr) {
    const exists = fs.existsSync(LOG_FILE);
    return { file: LOG_FILE, exists };
  }

  const candidate = `${LOG_FILE}-${dateStr}`;      // ex: traffic-domains.log-2025-12-02
  if (fs.existsSync(candidate)) {
    return { file: candidate,  exists: true };
  }

  return { file: candidate, exists: false };
}

// ------------------------
// helpers HTTP
// ------------------------

function sendText(res: ServerResponse, body: string, status = 200, contentType = 'text/plain; charset=utf-8') {
  res.writeHead(status, { 'Content-Type': contentType });
  res.end(body);
}

function serveStatic(res: ServerResponse, pathname: string) {
  // "/" -> "index.html"
  let relPath = pathname === '/' ? '/index.html' : pathname;

  // tira barras iniciais
  relPath = relPath.replace(/^\/+/, '');

  const filePath = path.join(WEB_DIR, relPath);

  // segurança básica: não deixar sair de WEB_DIR com "../"
  if (!filePath.startsWith(WEB_DIR)) {
    return sendText(res, 'Forbidden', 403);
  }

  if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
    return sendText(res, 'Not found', 404);
  }

  const ext = path.extname(filePath).toLowerCase();
  const mime = MIME_MAP[ext] ?? 'application/octet-stream';

  try {
    const data = fs.readFileSync(filePath);
    res.writeHead(200, { 'Content-Type': mime });
    res.end(data);
  } catch (e) {
    console.error('Erro lendo arquivo estático', filePath, e);
    sendText(res, 'Erro interno', 500);
  }
}


function sendJson(
  res: ServerResponse,
  payload: unknown,
  status = 200
): void {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8'
  });
  res.end(body);
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => { data += chunk; });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

// ------------------------
// ignored-domains helpers
// ------------------------

function ensureIgnoreFile(): void {
  const dir = path.dirname(IGNORE_FILE);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  if (!fs.existsSync(IGNORE_FILE)) {
    fs.writeFileSync(IGNORE_FILE, '# Domínios ignorados\n', 'utf8');
  }
}

function readIgnoredDomains(): string[] {
  try {
    if (!fs.existsSync(IGNORE_FILE)) return [];
    const content = fs.readFileSync(IGNORE_FILE, 'utf8');
    const lines = content.split('\n');
    const domains: string[] = [];
    for (let line of lines) {
      line = line.replace(/#.*/, '').trim();
      if (!line) continue;
      domains.push(line);
    }
    return domains;
  } catch (e) {
    console.error('[ignored-domains] erro ao ler arquivo:', e);
    return [];
  }
}

function writeIgnoredDomains(domains: string[]): void {
  try {
    ensureIgnoreFile();
    const unique = Array.from(new Set(domains.filter(Boolean)));
    const content =
      '# Domínios ignorados (um regex por linha)\n' +
      unique.map(d => d.trim()).join('\n') + '\n';
    fs.writeFileSync(IGNORE_FILE, content, 'utf8');
  } catch (e) {
    console.error('[ignored-domains] erro ao gravar arquivo:', e);
  }
}

function formatDate(d: Date): string {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

/**
 * Tenta descobrir quais dias recentes têm log.
 * Simples: olha hoje e X dias pra trás e verifica se o arquivo existe.
 */
function handleLogDays(_req: http.IncomingMessage, res: http.ServerResponse) {
  const days: string[] = [];
  const today = new Date();

  for (let i = 0; i < 30; i++) { // 30 dias pra trás
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    const dayStr = formatDate(d);
    const resolved = resolveLogPathForDate(dayStr);
    if (resolved.exists) {
      days.push(dayStr);
    }
  }

  sendJson(res, { days });
}


// ------------------------
// handlers ignored-domains
// ------------------------

async function handleGetIgnoredDomains(
  _req: IncomingMessage,
  res: ServerResponse
): Promise<void> {
  const domains = readIgnoredDomains();
  sendJson(res, { domains });
}

async function handlePostIgnoredDomains(
  req: IncomingMessage,
  res: ServerResponse
): Promise<void> {
  try {
    const raw = await readBody(req);
    const body = raw ? JSON.parse(raw) as { domain?: unknown } : {};
    let domain: string = String(body.domain);

    if (typeof domain !== 'string' || !domain.trim()) {
      sendJson(res, { error: 'domínio inválido' }, 400);
      return;
    }

    domain = domain.trim();
    const domains = readIgnoredDomains();
    if (!domains.includes(domain)) {
      domains.push(domain);
      writeIgnoredDomains(domains);
      console.log('[ignored-domains] adicionado:', domain);
    }

    sendJson(res, { domains });
  } catch (e) {
    console.error('[ignored-domains] POST erro:', e);
    sendJson(res, { error: 'erro interno' }, 500);
  }
}

async function handleDeleteIgnoredDomains(
  req: IncomingMessage,
  res: ServerResponse,
  query: ParsedUrlQuery
): Promise<void> {
  try {
    let domain: unknown = query.domain;

    if (!domain) {
      const raw = await readBody(req);
      const body = raw ? JSON.parse(raw) as { domain?: unknown } : {};
      domain = body.domain;
    }

    if (typeof domain !== 'string' || !domain.trim()) {
      sendJson(res, { error: 'domínio inválido' }, 400);
      return;
    }

    const cleanDomain = domain.trim();
    const domains = readIgnoredDomains().filter(d => d !== cleanDomain);
    writeIgnoredDomains(domains);
    console.log('[ignored-domains] removido:', cleanDomain);

    sendJson(res, { domains });
  } catch (e) {
    console.error('[ignored-domains] DELETE erro:', e);
    sendJson(res, { error: 'erro interno' }, 500);
  }
}

// ------------------------
// parse de linha do log
// ------------------------

interface ParsedLogEntry {
  timestamp: string;
  client_ip: string;
  client_name: string;
  host: string;
  domain: string | null;
  remote_ip: string | null;
  source: string | null;
  raw: string;
}

function parseLogLine(line: string): ParsedLogEntry | null {
  // Exemplo de entrada:
  // [+] 2025-12-11 23:31:42 | 192.168.1.201 (Redmi-13C) → graph.facebook.com (157.240.12.13) | fonte=TLS
  
  // Explicação dos Grupos do Regex:
  // 1. Timestamp: ([^|]+)
  // 2. Client IP: ([0-9a-fA-F\.:]+)
  // 3. Client Name (dentro dos parênteses): \(([^)]+)\)
  // 4. Domain/Host: (.+?)
  // 5. Remote IP (dentro dos parênteses): \(([0-9a-fA-F\.:]+)\)
  // 6. Fonte (opcional): fonte=([A-Za-z0-9\-_]+)

  const re = /^\[\+\]\s+([^|]+)\s+\|\s+([0-9a-fA-F\.:]+)\s+\(([^)]+)\)\s+→\s+(.+?)\s+\(([0-9a-fA-F\.:]+)\)(?:\s+\|\s+fonte=([A-Za-z0-9\-_]+))?/;
  
  const m = line.match(re);
  if (!m) return null;

  const timestamp = m[1].trim();
  const client_ip = m[2].trim();
  const client_name = m[3].trim(); // Agora capturamos o nome corretamente
  const host = m[4].trim();        // Domínio acessado
  const remote_ip = m[5].trim();
  const source = (m[6] || '').trim();
  const domain = host; 

  return {
    timestamp,
    client_ip,
    client_name,
    host,
    domain,
    remote_ip,
    source,
    raw: line
  };
}
// ------------------------
// /logs
// ------------------------


function handleLogs(_req: http.IncomingMessage, res: http.ServerResponse, query: any) {
  const clientFilter = (query.client || '').trim();
  const limit = Math.max(1, Math.min(parseInt(query.limit || '1000', 10) || 1000, 5000));

  const dateStr = (query.date || '').trim() || null;
  const resolved = resolveLogPathForDate(dateStr);

  if (!resolved.exists) {
    return sendJson(res, { entries: [], date: dateStr });
  }

  let content = '';
  try {
    const buf = fs.readFileSync(resolved.file);
    content = buf.toString('utf8');
  } catch (e) {
    console.error('[logs] erro ao ler', resolved.file, e);
    return sendJson(res, { entries: [], date: dateStr });
  }

  const lines = content.split('\n');
  const entries: any[] = [];

  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i].trim();
    if (!line) continue;
    const parsed = parseLogLine(line);
    if (!parsed) continue;

    if (clientFilter && clientFilter !== 'all' && parsed.client_ip !== clientFilter) {
      continue;
    }

    entries.push(parsed);
    if (entries.length >= limit) break;
  }

  entries.reverse();
  sendJson(res, { entries, date: dateStr });
}

// ------------------------
// /bytes
// ------------------------

function handleBytes(
  _req: IncomingMessage,
  res: ServerResponse
): void {
  try {
    if (!fs.existsSync(BYTES_FILE)) {
      sendJson(res, { updated_at: null, clients: {} });
      return;
    }
    const raw = fs.readFileSync(BYTES_FILE, 'utf8');
    const data = JSON.parse(raw);
    sendJson(res, data);
  } catch (e) {
    console.error('[bytes] erro ao ler', e);
    sendJson(res, { updated_at: null, clients: {} });
  }
}

// ------------------------
// /clients
// ------------------------

function handleClients(
  _req: IncomingMessage,
  res: ServerResponse
): void {
  try {
    if (!fs.existsSync(BYTES_FILE)) {
      sendJson(res, { clients: [] });
      return;
    }
    const raw = fs.readFileSync(BYTES_FILE, 'utf8');
    const data = JSON.parse(raw) as { clients?: Record<string, unknown> };
    const clientsMap = data && data.clients ? data.clients : {};
    const ips = Object.keys(clientsMap).sort();
    sendJson(res, { clients: ips });
  } catch (e) {
    console.error('[clients] erro ao ler', e);
    sendJson(res, { clients: [] });
  }
}

// ------------------------
// servidor HTTP
// ------------------------

const server = http.createServer(async (req: IncomingMessage, res: ServerResponse,) => {
  if (!req.url) return sendText(res, 'Bad request', 400);

  const parsed = parseUrl(req.url, true);
  const pathname = parsed.pathname || '/';
  const method = req.method || 'GET';

  // --- Rotas de API primeiro ---

  if (pathname === '/ignored-domains') {
    if (method === 'GET') return handleGetIgnoredDomains(req, res);
    if (method === 'POST') return handlePostIgnoredDomains(req, res);
    if (method === 'DELETE') return handleDeleteIgnoredDomains(req, res, parsed.query as ParsedUrlQuery);
  }

  if (pathname === '/logs' && method === 'GET') return handleLogs(req, res, parsed.query as ParsedUrlQuery);
  if (pathname === '/log-days' && req.method === 'GET') return handleLogDays(req, res);
  if (pathname === '/bytes' && method === 'GET') return handleBytes(req, res);
  if (pathname === '/clients' && method === 'GET') return handleClients(req, res);

  // --- Fallback: servir estático do WEB_DIR ---
  if (method === 'GET') {
    return serveStatic(res, pathname);
  }

  // Qualquer outra coisa:
  sendText(res, 'Not found', 404);
});


server.listen(PORT, HOST, () => {
  console.log(`Weviternia API ouvindo em http://${HOST}:${PORT}/`);
});
