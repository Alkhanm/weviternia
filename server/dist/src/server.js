"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const http_1 = __importDefault(require("http"));
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const url_1 = require("url");
const HOST = '0.0.0.0';
const PORT = Number(process.env.PORT ?? 9080);
// diretório de instalação: /opt/traffic-monitor
const BASE_DIR = path_1.default.join(__dirname, '..');
// onde o Vite colocou o build: /opt/traffic-monitor/web
const WEB_DIR = path_1.default.join(BASE_DIR, 'web');
// arquivos de log/config continuam como estavam:
const LOG_FILE = process.env.LOG_FILE || '/var/log/traffic-domains/traffic-domains.log';
const BYTES_FILE = process.env.BYTES_FILE || '/var/log/traffic-domains/traffic-bytes.json';
const IGNORE_FILE = process.env.IGNORE_FILE || '/etc/traffic-monitor/ignore-domains.txt';
// mapa simples de Content-Type
const MIME_MAP = {
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
// ------------------------
// helpers HTTP
// ------------------------
function sendText(res, body, status = 200, contentType = 'text/plain; charset=utf-8') {
    res.writeHead(status, { 'Content-Type': contentType });
    res.end(body);
}
function serveStatic(res, pathname) {
    // "/" -> "index.html"
    let relPath = pathname === '/' ? '/index.html' : pathname;
    // tira barras iniciais
    relPath = relPath.replace(/^\/+/, '');
    const filePath = path_1.default.join(WEB_DIR, relPath);
    // segurança básica: não deixar sair de WEB_DIR com "../"
    if (!filePath.startsWith(WEB_DIR)) {
        return sendText(res, 'Forbidden', 403);
    }
    if (!fs_1.default.existsSync(filePath) || !fs_1.default.statSync(filePath).isFile()) {
        return sendText(res, 'Not found', 404);
    }
    const ext = path_1.default.extname(filePath).toLowerCase();
    const mime = MIME_MAP[ext] ?? 'application/octet-stream';
    try {
        const data = fs_1.default.readFileSync(filePath);
        res.writeHead(200, { 'Content-Type': mime });
        res.end(data);
    }
    catch (e) {
        console.error('Erro lendo arquivo estático', filePath, e);
        sendText(res, 'Erro interno', 500);
    }
}
function sendJson(res, payload, status = 200) {
    const body = JSON.stringify(payload);
    res.writeHead(status, {
        'Content-Type': 'application/json; charset=utf-8'
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
// ------------------------
// ignored-domains helpers
// ------------------------
function ensureIgnoreFile() {
    const dir = path_1.default.dirname(IGNORE_FILE);
    if (!fs_1.default.existsSync(dir)) {
        fs_1.default.mkdirSync(dir, { recursive: true });
    }
    if (!fs_1.default.existsSync(IGNORE_FILE)) {
        fs_1.default.writeFileSync(IGNORE_FILE, '# Domínios ignorados\n', 'utf8');
    }
}
function readIgnoredDomains() {
    try {
        if (!fs_1.default.existsSync(IGNORE_FILE))
            return [];
        const content = fs_1.default.readFileSync(IGNORE_FILE, 'utf8');
        const lines = content.split('\n');
        const domains = [];
        for (let line of lines) {
            line = line.replace(/#.*/, '').trim();
            if (!line)
                continue;
            domains.push(line);
        }
        return domains;
    }
    catch (e) {
        console.error('[ignored-domains] erro ao ler arquivo:', e);
        return [];
    }
}
function writeIgnoredDomains(domains) {
    try {
        ensureIgnoreFile();
        const unique = Array.from(new Set(domains.filter(Boolean)));
        const content = '# Domínios ignorados (um regex por linha)\n' +
            unique.map(d => d.trim()).join('\n') + '\n';
        fs_1.default.writeFileSync(IGNORE_FILE, content, 'utf8');
    }
    catch (e) {
        console.error('[ignored-domains] erro ao gravar arquivo:', e);
    }
}
// ------------------------
// handlers ignored-domains
// ------------------------
async function handleGetIgnoredDomains(_req, res) {
    const domains = readIgnoredDomains();
    sendJson(res, { domains });
}
async function handlePostIgnoredDomains(req, res) {
    try {
        const raw = await readBody(req);
        const body = raw ? JSON.parse(raw) : {};
        let domain = String(body.domain);
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
    }
    catch (e) {
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
        if (typeof domain !== 'string' || !domain.trim()) {
            sendJson(res, { error: 'domínio inválido' }, 400);
            return;
        }
        const cleanDomain = domain.trim();
        const domains = readIgnoredDomains().filter(d => d !== cleanDomain);
        writeIgnoredDomains(domains);
        console.log('[ignored-domains] removido:', cleanDomain);
        sendJson(res, { domains });
    }
    catch (e) {
        console.error('[ignored-domains] DELETE erro:', e);
        sendJson(res, { error: 'erro interno' }, 500);
    }
}
function parseLogLine(line) {
    // Exemplo:
    // [+] 2025-12-01 19:29:20 | 192.168.3.11 → exemplo.com (1.2.3.4) | fonte=DNS
    const re = /^\[\+\]\s+([^|]+)\s+\|\s+([0-9a-fA-F\.:]+)\s+→\s+(.+?)\s+\(([0-9a-fA-F\.:]+)\)(?:\s+\|\s+fonte=([A-Za-z0-9\-_]+))?/;
    const m = line.match(re);
    if (!m)
        return null;
    const timestamp = m[1].trim();
    const client = m[2].trim();
    const host = m[3].trim();
    const remote_ip = m[4].trim();
    const source = (m[5] || '').trim();
    const domain = host; // tratamos host como “domínio principal”
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
// ------------------------
// /logs
// ------------------------
function getQueryStringParam(query, key, defaultValue = '') {
    const v = query[key];
    if (typeof v === 'string')
        return v;
    if (Array.isArray(v) && v.length > 0)
        return v[0];
    return defaultValue;
}
function handleLogs(_req, res, query) {
    const clientFilter = getQueryStringParam(query, 'client').trim();
    const limitStr = getQueryStringParam(query, 'limit', '1000');
    const limitNum = parseInt(limitStr, 10);
    const limit = Math.max(1, Math.min(limitNum || 1000, 5000));
    let content = '';
    try {
        content = fs_1.default.readFileSync(LOG_FILE, 'utf8');
    }
    catch (e) {
        console.error('[logs] erro ao ler LOG_FILE', e);
        sendJson(res, { entries: [] });
        return;
    }
    const lines = content.split('\n');
    const entries = [];
    for (let i = lines.length - 1; i >= 0; i--) {
        const line = lines[i].trim();
        if (!line)
            continue;
        const parsed = parseLogLine(line);
        if (!parsed)
            continue;
        if (clientFilter && clientFilter !== 'all' && parsed.client !== clientFilter) {
            continue;
        }
        entries.push(parsed);
        if (entries.length >= limit)
            break;
    }
    entries.reverse();
    sendJson(res, { entries });
}
// ------------------------
// /bytes
// ------------------------
function handleBytes(_req, res) {
    try {
        if (!fs_1.default.existsSync(BYTES_FILE)) {
            sendJson(res, { updated_at: null, clients: {} });
            return;
        }
        const raw = fs_1.default.readFileSync(BYTES_FILE, 'utf8');
        const data = JSON.parse(raw);
        sendJson(res, data);
    }
    catch (e) {
        console.error('[bytes] erro ao ler', e);
        sendJson(res, { updated_at: null, clients: {} });
    }
}
// ------------------------
// /clients
// ------------------------
function handleClients(_req, res) {
    try {
        if (!fs_1.default.existsSync(BYTES_FILE)) {
            sendJson(res, { clients: [] });
            return;
        }
        const raw = fs_1.default.readFileSync(BYTES_FILE, 'utf8');
        const data = JSON.parse(raw);
        const clientsMap = data && data.clients ? data.clients : {};
        const ips = Object.keys(clientsMap).sort();
        sendJson(res, { clients: ips });
    }
    catch (e) {
        console.error('[clients] erro ao ler', e);
        sendJson(res, { clients: [] });
    }
}
// ------------------------
// servidor HTTP
// ------------------------
const server = http_1.default.createServer(async (req, res) => {
    if (!req.url)
        return sendText(res, 'Bad request', 400);
    const parsed = (0, url_1.parse)(req.url, true);
    const pathname = parsed.pathname || '/';
    const method = req.method || 'GET';
    // --- Rotas de API primeiro ---
    if (pathname === '/ignored-domains') {
        if (method === 'GET')
            return handleGetIgnoredDomains(req, res);
        if (method === 'POST')
            return handlePostIgnoredDomains(req, res);
        if (method === 'DELETE')
            return handleDeleteIgnoredDomains(req, res, parsed.query);
    }
    if (pathname === '/logs' && method === 'GET')
        return handleLogs(req, res, parsed.query);
    if (pathname === '/bytes' && method === 'GET')
        return handleBytes(req, res);
    if (pathname === '/clients' && method === 'GET')
        return handleClients(req, res);
    // --- Fallback: servir estático do WEB_DIR ---
    if (method === 'GET') {
        return serveStatic(res, pathname);
    }
    // Qualquer outra coisa:
    sendText(res, 'Not found', 404);
});
server.listen(PORT, HOST, () => {
    console.log(`Traffic dashboard API ouvindo em http://${HOST}:${PORT}/`);
});
