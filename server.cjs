const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = __dirname;
const KEYS_DIR = path.join(ROOT, 'keys');
const DATA_DIR = path.join(ROOT, 'data');
const PUBLIC_KEY_PATH = path.join(KEYS_DIR, 'public.pem');
const PRIVATE_KEY_PATH = path.join(KEYS_DIR, 'private.pem');
const DB_PATH = path.join(DATA_DIR, 'licenses.json');

const PORT = process.env.PORT || 8457;
const ADMIN_PASSWORD = (process.env.ADMIN_PASSWORD || '').trim();

// Persistencia na nuvem (Upstash Redis REST) quando configurado
const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL || '';
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || '';
const REDIS_KEY = 'ai_license_db';

// Chave privada: vem do ambiente (Render) ou do arquivo local
function loadPrivateKey() {
  const fromEnv = process.env.LICENSE_PRIVATE_KEY || '';
  if (fromEnv.trim()) return Buffer.from(fromEnv.replace(/\\n/g, '\n').trim());
  return fs.readFileSync(PRIVATE_KEY_PATH);
}
function loadPublicKey() {
  if (!fs.existsSync(PUBLIC_KEY_PATH)) return null;
  return fs.readFileSync(PUBLIC_KEY_PATH);
}

let licenses = [];
let privKey = null;
let pubKey = null;

function parseDb(raw) {
  if (raw === null || raw === undefined || raw === 'nil') return [];
  let value = raw;
  if (typeof value === 'string') {
    try { value = JSON.parse(value); } catch (e) { return []; }
  }
  // Formato legado gravado como { data: "<json>" }
  if (value && !Array.isArray(value) && typeof value.data !== 'undefined') {
    value = value.data;
    if (typeof value === 'string') {
      try { value = JSON.parse(value); } catch (e) { return []; }
    }
  }
  return Array.isArray(value) ? value : [];
}

async function loadDb() {
  if (REDIS_URL && REDIS_TOKEN) {
    try {
      const res = await fetch(REDIS_URL + '/get/' + REDIS_KEY, { headers: { Authorization: 'Bearer ' + REDIS_TOKEN } });
      const data = await res.json();
      licenses = parseDb(data ? data.result : null);
    } catch (e) {
      licenses = [];
    }
    return;
  }
  try { licenses = parseDb(fs.readFileSync(DB_PATH, 'utf8')); }
  catch (e) { licenses = []; }
}
async function saveDb() {
  if (!Array.isArray(licenses)) licenses = [];
  if (REDIS_URL && REDIS_TOKEN) {
    try {
      await fetch(REDIS_URL + '/set/' + REDIS_KEY, {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + REDIS_TOKEN, 'Content-Type': 'text/plain' },
        body: JSON.stringify(licenses)
      });
    } catch (e) {}
    return;
  }
  fs.writeFileSync(DB_PATH, JSON.stringify(licenses, null, 2));
}

const TOKEN_TTL = 7 * 86400000;
function sessionSecret() {
  return crypto.createHash('sha256').update('ai-live-player|' + ADMIN_PASSWORD + '|' + (process.env.LICENSE_PRIVATE_KEY || 'local')).digest();
}
function hmac(payload) {
  return crypto.createHmac('sha256', sessionSecret()).update(payload).digest('hex');
}
function createToken() {
  const payload = String(Date.now() + TOKEN_TTL);
  return payload + '.' + hmac(payload);
}
function verifyToken(token) {
  if (!token) return false;
  const i = token.indexOf('.');
  if (i < 0) return false;
  const payload = token.slice(0, i);
  const sig = token.slice(i + 1);
  const expected = hmac(payload);
  if (sig.length !== expected.length) return false;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return false;
  return Number(payload) > Date.now();
}

function b64u(buf) {
  return Buffer.from(buf).toString('base64url');
}
function signLicense(license) {
  const message = Buffer.from(JSON.stringify(license));
  const sig = crypto.sign(null, message, privKey);
  return b64u(message) + '.' + b64u(sig);
}

function normalizeHwid(raw) {
  return String(raw || '').trim().toUpperCase();
}

async function generateKey(email, name, days, hwid) {
  if (!Array.isArray(licenses)) licenses = [];
  const exp = Date.now() + days * 86400000;
  const license = { v: 1, email: (email || '').trim(), name: (name || '').trim(), hwid: normalizeHwid(hwid), days: Number(days) || 30, exp };
  const key = signLicense(license);
  licenses.push({ ...license, created: new Date().toISOString(), key });
  await saveDb();
  return key;
}

function sendJson(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => { data += c; if (data.length > 1e6) req.destroy(); });
    req.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch (e) { reject(new Error('JSON inválido')); } });
    req.on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;

  if (req.method === 'GET' && (p === '/' || p === '/admin')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(fs.readFileSync(path.join(ROOT, 'admin.html')));
    return;
  }

  if (req.method === 'POST' && p === '/api/login') {
    try {
      const body = await readBody(req);
      if (!ADMIN_PASSWORD) { sendJson(res, 500, { ok: false, error: 'ADMIN_PASSWORD não definida.' }); return; }
      if (String(body.password || '') === ADMIN_PASSWORD) {
        sendJson(res, 200, { ok: true, token: createToken() });
      } else {
        sendJson(res, 401, { ok: false, error: 'Senha incorreta' });
      }
    } catch (e) { sendJson(res, 400, { ok: false, error: e.message }); }
    return;
  }

  const authHeader = req.headers.authorization || '';
  const isAuthed = authHeader.startsWith('Bearer ') && verifyToken(authHeader.slice(7).trim());

  if (req.method === 'POST' && p === '/api/generate') {
    if (!isAuthed) { sendJson(res, 401, { ok: false, error: 'Não autenticado' }); return; }
    try {
      const body = await readBody(req);
      if (!body.hwid) { sendJson(res, 400, { ok: false, error: 'Informe o código do computador (HWID)' }); return; }
      const key = await generateKey(body.email, body.name, body.days, body.hwid);
      sendJson(res, 200, { ok: true, key });
    } catch (e) { sendJson(res, 400, { ok: false, error: e.message }); }
    return;
  }

  if (req.method === 'GET' && p === '/api/list') {
    if (!isAuthed) { sendJson(res, 401, { ok: false, error: 'Não autenticado' }); return; }
    sendJson(res, 200, { ok: true, licenses });
    return;
  }

  if (req.method === 'POST' && p === '/api/delete') {
    if (!isAuthed) { sendJson(res, 401, { ok: false, error: 'Não autenticado' }); return; }
    try {
      const body = await readBody(req);
      licenses = licenses.filter(l => l.key !== body.key);
      await saveDb();
      sendJson(res, 200, { ok: true });
    } catch (e) { sendJson(res, 400, { ok: false, error: e.message }); }
    return;
  }

  sendJson(res, 404, { ok: false, error: 'Rota não encontrada' });
});

privKey = loadPrivateKey();
pubKey = loadPublicKey();
loadDb().then(() => {
  server.listen(PORT, () => {
    console.log('=================================================');
    console.log('  AI Live Player - Painel de Licenças');
    console.log('  Acesse: http://localhost:' + PORT);
    console.log('  Persistência: ' + (REDIS_URL ? 'Upstash Redis (nuvem)' : 'arquivo local'));
    console.log('  Chave privada: ' + (process.env.LICENSE_PRIVATE_KEY ? 'ambiente' : 'keys/private.pem'));
    console.log('=================================================');
  });
});