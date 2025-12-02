#!/usr/bin/env node

const http = require('http');
const fs   = require('fs');
const path = require('path');
const url  = require('url');

const HOST = '0.0.0.0';
const PORT = 9080;

const BASE_DIR      = path.join(__dirname, '..');
const SRC_DIR       = __dirname;
const INDEX_FILE    = path.join(SRC_DIR, 'index.html');
const CSS_FILE      = path.join(SRC_DIR, 'style.css');
const FAVICON_FILE  = path.join(SRC_DIR, 'favicon.ico');

const LOG_FILE   = process.env.LOG_FILE   || '/var/log/traffic-domains/traffic-domains.log';
const BYTES_FILE = process.env.BYTES_FILE || '/var/log/traffic-domains/traffic-bytes.json';
const IGNORE_FILE = process.env.IGNORE_FILE || '/etc/traffic-monitor/ignore-domains.txt';

function sendText(res, body, status = 200, contentType = 'text/plain; charset=utf-8') {
  res.writeHead(status, { 'Content-Type': contentType });
  res.end(body);
}

function sendJson(res, payload, status = 200) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => { data += chunk; });
    req.on('end', () => resolve(data));
    req.on('error', reject);
  });
}

function ensureIgnoreFile() {
  const dir = path.dirname(IGNORE_FILE);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  if (!fs.existsSync(IGNORE_FILE)) {
    fs.writeFileSync(IGNORE_FILE, '# Domínios ignorados\n', 'utf8');
  }
}

function readIgnoredDomains() {
  try {
    if (!fs.existsSync(IGNORE_FILE)) return [];
    const content = fs.readFileSync(IGNORE_FILE, 'utf8');
    const lines = content.split('\n');
    const domains = [];
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

function writeIgnoredDomains(domains) {
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

async function handleGetIgnoredDomains(req, res) {
  const domains = readIgnoredDomains();
  sendJson(res, { domains });
}

async function handlePostIgnoredDomains(req, res) {
  try {
    const raw = await readBody(req);
    const body = raw ? JSON.parse(raw) : {};
    let { domain } = body;
    if (!domain || typeof domain !== 'string') {
      return sendJson(res, { error: 'domínio inválido' }, 400);
    }
    domain = domain.trim();
    if (!domain) {
      return sendJson(res, { error: 'domínio vazio' }, 400);
    }

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

async function handleDeleteIgnoredDomains(req, res, query) {
  try {
    let domain = query.domain;
    if (!domain) {
      const raw = await readBody(req);
      const body = raw ? JSON.parse(raw) : {};
      domain = body.domain;
    }
    if (!domain || typeof domain !== 'string') {
      return sendJson(res, { error: 'domínio inválido' }, 400);
    }
    domain = domain.trim();
    const domains = readIgnoredDomains().filter(d => d !== domain);
    writeIgnoredDomains(domains);
    console.log('[ignored-domains] removido:', domain);
    sendJson(res, { domains });
  } catch (e) {
    console.error('[ignored-domains] DELETE erro:', e);
    sendJson(res, { error: 'erro interno' }, 500);
  }
}

function parseLogLine(line) {
  // Exemplo:
  // [+] 2025-12-01 19:29:20 | 192.168.3.11 → exemplo.com (1.2.3.4) | fonte=DNS
  const re = /^\[\+\]\s+([^|]+)\s+\|\s+([0-9a-fA-F\.:]+)\s+→\s+(.+?)\s+\(([0-9a-fA-F\.:]+)\)(?:\s+\|\s+fonte=([A-Za-z0-9\-_]+))?/;
  const m = line.match(re);
  if (!m) return null;
  const timestamp = m[1].trim();
  const client    = m[2].trim();
  const host      = m[3].trim();
  const remote_ip = m[4].trim();
  const source    = (m[5] || '').trim();
  const domain    = host; // tratamos host como domínio principal

  return {
    timestamp,
    client,
    host,
    domain,
    remote_ip,
    source,
    raw: line
  };
}

function handleLogs(req, res, query) {
  const clientFilter = (query.client || '').trim();
  const limit = Math.max(1, Math.min(parseInt(query.limit || '1000', 10) || 1000, 5000));

  let content = '';
  try {
    content = fs.readFileSync(LOG_FILE, 'utf8');
  } catch (e) {
    return sendJson(res, { entries: [] });
  }

  const lines = content.split('\n');
  const entries = [];
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i].trim();
    if (!line) continue;
    const parsed = parseLogLine(line);
    if (!parsed) continue;

    if (clientFilter && clientFilter !== 'all' && parsed.client !== clientFilter) {
      continue;
    }

    entries.push(parsed);
    if (entries.length >= limit) break;
  }

  entries.reverse();
  sendJson(res, { entries });
}

function handleBytes(req, res) {
  try {
    if (!fs.existsSync(BYTES_FILE)) {
      return sendJson(res, { updated_at: null, clients: {} });
    }
    const raw = fs.readFileSync(BYTES_FILE, 'utf8');
    const data = JSON.parse(raw);
    sendJson(res, data);
  } catch (e) {
    console.error('[bytes] erro ao ler', e);
    sendJson(res, { updated_at: null, clients: {} });
  }
}

function handleClients(req, res) {
  try {
    if (!fs.existsSync(BYTES_FILE)) {
      return sendJson(res, { clients: [] });
    }
    const raw = fs.readFileSync(BYTES_FILE, 'utf8');
    const data = JSON.parse(raw);
    const clientsMap = (data && data.clients) || {};
    const ips = Object.keys(clientsMap).sort();
    sendJson(res, { clients: ips });
  } catch (e) {
    console.error('[clients] erro ao ler', e);
    sendJson(res, { clients: [] });
  }
}

const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;

  // estático
  if (req.method === 'GET' && (pathname === '/' || pathname === '/index.html')) {
    try {
      const html = fs.readFileSync(INDEX_FILE, 'utf8');
      return sendText(res, html, 200, 'text/html; charset=utf-8');
    } catch (e) {
      console.error('Erro lendo index.html', e);
      return sendText(res, 'index.html não encontrado', 500);
    }
  }

  if (req.method === 'GET' && pathname === '/style.css') {
    try {
      const css = fs.readFileSync(CSS_FILE, 'utf8');
      return sendText(res, css, 200, 'text/css; charset=utf-8');
    } catch (e) {
      console.error('Erro lendo style.css', e);
      return sendText(res, 'style.css não encontrado', 404);
    }
  }

  if (req.method === 'GET' && pathname === '/favicon.ico') {
    try {
      const ico = fs.readFileSync(FAVICON_FILE);
      res.writeHead(200, { 'Content-Type': 'image/x-icon' });
      return res.end(ico);
    } catch (e) {
      return sendText(res, '', 404);
    }
  }

  // ignored-domains
  if (pathname === '/ignored-domains') {
    if (req.method === 'GET') {
      return handleGetIgnoredDomains(req, res);
    }
    if (req.method === 'POST') {
      return handlePostIgnoredDomains(req, res);
    }
    if (req.method === 'DELETE') {
      return handleDeleteIgnoredDomains(req, res, parsed.query);
    }
  }

  // logs
  if (pathname === '/logs' && req.method === 'GET') {
    return handleLogs(req, res, parsed.query);
  }

  // bytes
  if (pathname === '/bytes' && req.method === 'GET') {
    return handleBytes(req, res);
  }

  // clients
  if (pathname === '/clients' && req.method === 'GET') {
    return handleClients(req, res);
  }

  sendText(res, 'Not found', 404);
});

server.listen(PORT, HOST, () => {
  console.log(`Traffic dashboard ouvindo em http://${HOST}:${PORT}/`);
});

