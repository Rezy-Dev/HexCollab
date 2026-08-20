#!/usr/bin/env node
'use strict';

const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const readline = require('readline');
const { spawn } = require('child_process');

let IS_SEA = false;
try {
  IS_SEA = require('node:sea').isSea();
} catch {}


const HOME = os.homedir();
const APP_DIR = path.join(HOME, '.hexcollab');
const CONFIG_PATH = path.join(APP_DIR, 'config.json');
const SESSIONS_PATH = path.join(APP_DIR, 'sessions.json');
const SOCK_PATH = path.join(APP_DIR, 'hexcollab.sock');
const LOG_PATH = path.join(APP_DIR, 'daemon.log');
const PID_PATH = path.join(APP_DIR, 'daemon.pid');
const CF_DIR = path.join(APP_DIR, 'cloudflared');
const CF_CONFIG_PATH = path.join(CF_DIR, 'config.yml');
const CF_PID_PATH = path.join(APP_DIR, 'cloudflared.pid');
const CF_LOG_PATH = path.join(APP_DIR, 'cloudflared.log');

const DEFAULT_CONFIG = {
  server: 'http://localhost:6969',
  jwtSecret: '',
  port: 8484,
  bind: '0.0.0.0',
  advertiseHost: '',
  lang: 'en',
  cfTunnelName: 'hexcollab',
  cfTunnelId: '',
  cfHexHostname: '',
  cfDocHostname: '',
  cfConfigPath: '',
};

function ensureAppDir() {
  fs.mkdirSync(APP_DIR, { recursive: true });
}

function loadConfig() {
  ensureAppDir();
  if (!fs.existsSync(CONFIG_PATH)) {
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(DEFAULT_CONFIG, null, 2));
    return { ...DEFAULT_CONFIG };
  }
  try {
    const onDisk = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
    return { ...DEFAULT_CONFIG, ...onDisk };
  } catch (e) {
    console.error('Config file is corrupt, using defaults:', e.message);
    return { ...DEFAULT_CONFIG };
  }
}

function saveConfig(cfg) {
  ensureAppDir();
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2));
}

function loadSessions() {
  if (!fs.existsSync(SESSIONS_PATH)) return {};
  try {
    return JSON.parse(fs.readFileSync(SESSIONS_PATH, 'utf8'));
  } catch {
    return {};
  }
}

function saveSessions(sessions) {
  ensureAppDir();
  fs.writeFileSync(SESSIONS_PATH, JSON.stringify(sessions, null, 2));
}

function b64url(buf) {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function signJWT(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const headerPart = b64url(JSON.stringify(header));
  const payloadPart = b64url(JSON.stringify(payload));
  const signingInput = `${headerPart}.${payloadPart}`;
  const sig = crypto.createHmac('sha256', secret).update(signingInput).digest();
  return `${signingInput}.${b64url(sig)}`;
}

function verifyJWT(token, secret) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;
  const [headerPart, payloadPart, sigPart] = parts;
  const expected = b64url(
    crypto.createHmac('sha256', secret).update(`${headerPart}.${payloadPart}`).digest()
  );
  if (expected !== sigPart) return null;
  try {
    return JSON.parse(Buffer.from(payloadPart.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
  } catch {
    return null;
  }
}

function generatePassword(len = 25) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  let out = '';
  for (let i = 0; i < len; i++) out += chars[crypto.randomInt(0, chars.length)];
  return out;
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

function verifyPassword(password, salt, hash) {
  const test = crypto.scryptSync(password, salt, 64);
  const stored = Buffer.from(hash, 'hex');
  if (test.length !== stored.length) return false;
  return crypto.timingSafeEqual(test, stored);
}

const TYPE_MAP = {
  doc: ['word', 'doc'], docx: ['word', 'docx'], odt: ['word', 'odt'], rtf: ['word', 'rtf'],
  txt: ['word', 'txt'], dot: ['word', 'dot'], dotx: ['word', 'dotx'], epub: ['word', 'epub'],
  fb2: ['word', 'fb2'], html: ['word', 'html'], htm: ['word', 'htm'], md: ['word', 'md'],
  xls: ['cell', 'xls'], xlsx: ['cell', 'xlsx'], ods: ['cell', 'ods'], csv: ['cell', 'csv'],
  xlsm: ['cell', 'xlsm'], xlt: ['cell', 'xlt'], xltx: ['cell', 'xltx'],
  ppt: ['slide', 'ppt'], pptx: ['slide', 'pptx'], odp: ['slide', 'odp'], pps: ['slide', 'pps'],
  ppsx: ['slide', 'ppsx'], pot: ['slide', 'pot'], potx: ['slide', 'potx'],
  pdf: ['pdf', 'pdf'],
};

function fileTypeInfo(filename) {
  const ext = path.extname(filename).slice(1).toLowerCase();
  const info = TYPE_MAP[ext];
  if (!info) return null;
  return { documentType: info[0], fileType: info[1], ext };
}

function detectLanIPs() {
  const ifaces = os.networkInterfaces();
  const ips = [];
  for (const name of Object.keys(ifaces)) {
    for (const iface of ifaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        ips.push(iface.address);
      }
    }
  }
  return ips;
}

function isDaemonRunning() {
  return fs.existsSync(SOCK_PATH);
}

function sendToDaemon(msg, timeoutMs = 4000) {
  return new Promise((resolve, reject) => {
    const client = net.createConnection(SOCK_PATH);
    let data = '';
    const timer = setTimeout(() => {
      client.destroy();
      reject(new Error('daemon did not respond in time'));
    }, timeoutMs);
    client.on('connect', () => client.end(JSON.stringify(msg)));
    client.on('data', (chunk) => (data += chunk));
    client.on('end', () => {
      clearTimeout(timer);
      try {
        resolve(JSON.parse(data));
      } catch (e) {
        reject(new Error('bad response from daemon: ' + e.message));
      }
    });
    client.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

async function ensureDaemon(cfg) {
  if (isDaemonRunning()) {
    try {
      await sendToDaemon({ cmd: 'ping' }, 1500);
      return;
    } catch {
      try { fs.unlinkSync(SOCK_PATH); } catch {}
    }
  }
  ensureAppDir();
  const out = fs.openSync(LOG_PATH, 'a');
  const err = fs.openSync(LOG_PATH, 'a');
  const child = spawn(process.execPath, IS_SEA ? ['--daemon'] : [__filename, '--daemon'], {
    detached: true,
    stdio: ['ignore', out, err],
    cwd: process.cwd(),
  });
  fs.writeFileSync(PID_PATH, String(child.pid));
  child.unref();

  for (let i = 0; i < 50; i++) {
    await new Promise((r) => setTimeout(r, 100));
    if (isDaemonRunning()) {
      try {
        await sendToDaemon({ cmd: 'ping' }, 1500);
        return;
      } catch {}
    }
  }
  throw new Error(`daemon did not start in time — check ${LOG_PATH}`);
}

function runDaemon() {
  ensureAppDir();
  const cfg = loadConfig();
  const sessions = loadSessions();

  function persist() {
    saveSessions(sessions);
  }

  function advertiseHost() {
    if (cfg.advertiseHost) return cfg.advertiseHost;
    const ips = detectLanIPs();
    return ips[0] || '127.0.0.1';
  }

  function buildEditorConfig(session, userName) {
    const host = advertiseHost();
    const base = `http://${host}:${cfg.port}`;
    const docUrl = `${base}/files/${session.id}/${encodeURIComponent(session.filename)}`;
    const callbackUrl = `${base}/callback/${session.id}`;
    const userId = crypto.createHash('md5').update(userName || 'guest').digest('hex').slice(0, 12);
    const config = {
      document: {
        fileType: session.fileType,
        key: session.key,
        title: session.filename,
        url: docUrl,
        permissions: { edit: true, comment: true, download: true, print: true },
      },
      documentType: session.documentType,
      editorConfig: {
        callbackUrl,
        lang: cfg.lang,
        mode: 'edit',
        user: { id: userId, name: userName || 'Guest' },
        customization: { autosave: true, forcesave: true },
      },
      width: '100%',
      height: '100%',
      type: 'desktop',
    };
    if (cfg.jwtSecret) {
      config.token = signJWT(config, cfg.jwtSecret);
    }
    return config;
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function editHtml(config, serverBase) {
    const json = JSON.stringify(config).replace(/</g, '\\u003c');
    return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>${escapeHtml(config.document.title)} — hexcollab</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>html,body,#placeholder{height:100%;margin:0;padding:0;}</style>
</head>
<body>
<div id="placeholder"></div>
<script src="${serverBase}/web-apps/apps/api/documents/api.js"></script>
<script>
  var config = ${json};
  new DocsAPI.DocEditor("placeholder", config);
</script>
</body>
</html>`;
  }

  function nameFormHtml(actionPath, carryParams, errorMsg) {
    const hidden = Object.entries(carryParams || {})
      .filter(([, v]) => v)
      .map(([k, v]) => `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}">`)
      .join('\n  ');
    const errorHtml = errorMsg
      ? `<p class="err">${escapeHtml(errorMsg)}</p>`
      : '';
    return `<!doctype html>
<html><head><meta charset="utf-8"><title>Join document — HexCollab</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root{color-scheme:dark;}
  *{box-sizing:border-box;}
  body{
    margin:0;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;
    background:radial-gradient(circle at 50% 0%, #161b22 0%, #0d1117 60%);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif;
    color:#c9d1d9;padding:2rem 1rem;
  }
  .brand{
    font-size:2rem;font-weight:700;letter-spacing:.04em;margin-bottom:2rem;
    background:linear-gradient(90deg,#58a6ff,#79c0ff);-webkit-background-clip:text;background-clip:text;color:transparent;
  }
  form{
    background:#161b22;border:1px solid #30363d;border-radius:12px;
    padding:2.25rem 2rem;width:100%;max-width:340px;box-shadow:0 8px 30px rgba(0,0,0,.45);
  }
  label{display:block;margin-bottom:1.1rem;font-size:.85rem;color:#8b949e;}
  input{
    width:100%;margin-top:.4rem;padding:.6rem .7rem;font-size:1rem;
    background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;
  }
  input:focus{outline:none;border-color:#58a6ff;}
  button{
    width:100%;padding:.65rem;font-size:1rem;font-weight:600;margin-top:.4rem;
    background:#238636;color:#fff;border:none;border-radius:6px;cursor:pointer;
  }
  button:hover{background:#2ea043;}
  .err{color:#f85149;font-size:.85rem;margin:0 0 1rem;}
  footer{margin-top:2rem;font-size:.8rem;color:#6e7681;}
  footer a{color:#8b949e;text-decoration:none;}
  footer a:hover{color:#58a6ff;}
</style></head>
<body>
<div class="brand">HexCollab</div>
<form method="POST" action="${actionPath}">
  ${errorHtml}
  ${hidden}
  <label>Your name<input name="name" autofocus required></label>
  <label>Password<input type="password" name="password" required></label>
  <button type="submit">Join</button>
</form>
<footer>Made with ❤️ by <a href="https://rezydev.com" target="_blank" rel="noopener">rezydev</a></footer>
</body></html>`;
  }

  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://placeholder');
      const parts = url.pathname.split('/').filter(Boolean);

      if (url.pathname === '/api/health') {
        res.writeHead(200, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ ok: true }));
      }

      if (parts[0] === 'edit' && parts[1] && req.method === 'GET') {
        const session = sessions[parts[1]];
        if (!session) {
          res.writeHead(404);
          return res.end('No such session. It may have been stopped.');
        }
        const docServerOverride = url.searchParams.get('docserver');
        res.writeHead(200, { 'content-type': 'text/html' });
        return res.end(nameFormHtml(url.pathname, { docserver: docServerOverride }));
      }

      if (parts[0] === 'edit' && parts[1] && req.method === 'POST') {
        const session = sessions[parts[1]];
        if (!session) {
          res.writeHead(404);
          return res.end('No such session. It may have been stopped.');
        }
        let body = '';
        req.on('data', (c) => (body += c));
        req.on('end', () => {
          const form = new URLSearchParams(body);
          const name = form.get('name');
          const password = form.get('password') || '';
          const docServerOverride = form.get('docserver');
          if (!name) {
            res.writeHead(200, { 'content-type': 'text/html' });
            return res.end(nameFormHtml(url.pathname, { docserver: docServerOverride }, 'Name is required.'));
          }
          if (!verifyPassword(password, session.passwordSalt, session.passwordHash)) {
            res.writeHead(200, { 'content-type': 'text/html' });
            return res.end(nameFormHtml(url.pathname, { docserver: docServerOverride }, 'Incorrect password.'));
          }
          const config = buildEditorConfig(session, name);
          const scriptBase = (docServerOverride || cfg.server).replace(/\/$/, '');
          res.writeHead(200, { 'content-type': 'text/html' });
          return res.end(editHtml(config, scriptBase));
        });
        return;
      }

      if (parts[0] === 'files' && parts[1] && parts[2]) {
        const session = sessions[parts[1]];
        if (!session) {
          res.writeHead(404);
          return res.end('Not found');
        }
        if (!fs.existsSync(session.path)) {
          res.writeHead(404);
          return res.end('File missing on disk');
        }
        const stat = fs.statSync(session.path);
        res.writeHead(200, {
          'content-type': 'application/octet-stream',
          'content-length': stat.size,
          'content-disposition': `attachment; filename="${session.filename}"`,
        });
        return fs.createReadStream(session.path).pipe(res);
      }

      if (parts[0] === 'callback' && parts[1] && req.method === 'POST') {
        const session = sessions[parts[1]];
        if (!session) {
          res.writeHead(404);
          return res.end(JSON.stringify({ error: 1 }));
        }
        let body = '';
        req.on('data', (c) => (body += c));
        req.on('end', async () => {
          let payload;
          try {
            payload = JSON.parse(body || '{}');
          } catch {
            res.writeHead(400);
            return res.end(JSON.stringify({ error: 1 }));
          }

          if (cfg.jwtSecret) {
            const authHeader = req.headers['authorization'] || '';
            const bearer = authHeader.replace(/^Bearer\s+/i, '');
            const token = bearer || payload.token;
            const verified = token && verifyJWT(token, cfg.jwtSecret);
            if (!verified) {
              log(`[callback] rejected unsigned/invalid request for ${session.id}`);
              res.writeHead(403);
              return res.end(JSON.stringify({ error: 1 }));
            }
          }

          if (payload.status === 2 || payload.status === 6) {
            try {
              await downloadTo(payload.url, session.path);
              log(`[callback] saved ${session.filename} (session ${session.id})`);
            } catch (e) {
              log(`[callback] FAILED saving ${session.filename}: ${e.message}`);
              res.writeHead(200, { 'content-type': 'application/json' });
              return res.end(JSON.stringify({ error: 1 }));
            }
          }
          res.writeHead(200, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 0 }));
        });
        return;
      }

      res.writeHead(404);
      res.end('Not found');
    } catch (e) {
      log('HTTP handler error: ' + e.stack);
      res.writeHead(500);
      res.end('Internal error');
    }
  });

  function downloadTo(fileUrl, destPath) {
    return new Promise((resolve, reject) => {
      const mod = fileUrl.startsWith('https:') ? https : http;
      mod
        .get(fileUrl, (resp) => {
          if (resp.statusCode !== 200) {
            reject(new Error('download failed, status ' + resp.statusCode));
            return;
          }
          const tmp = destPath + '.hexcollab-tmp';
          const out = fs.createWriteStream(tmp);
          resp.pipe(out);
          out.on('finish', () => {
            out.close(() => {
              fs.renameSync(tmp, destPath);
              resolve();
            });
          });
          out.on('error', reject);
        })
        .on('error', reject);
    });
  }

  function log(line) {
    const msg = `[${new Date().toISOString()}] ${line}\n`;
    try {
      fs.appendFileSync(LOG_PATH, msg);
    } catch {}
  }

  server.listen(cfg.port, cfg.bind, () => {
    log(`hexcollab daemon listening on ${cfg.bind}:${cfg.port}`);
  });

  try {
    fs.unlinkSync(SOCK_PATH);
  } catch {}

  const ctrl = net.createServer((sock) => {
    let data = '';
    sock.on('data', (c) => (data += c));
    sock.on('end', () => {
      let msg;
      try {
        msg = JSON.parse(data);
      } catch {
        sock.end(JSON.stringify({ error: 'bad request' }));
        return;
      }
      handleControl(msg, sock);
    });
  });

  function handleControl(msg, sock) {
    if (msg.cmd === 'ping') {
      return sock.end(JSON.stringify({ ok: true }));
    }

    if (msg.cmd === 'share') {
      const abs = path.resolve(msg.path);
      if (!fs.existsSync(abs)) {
        return sock.end(JSON.stringify({ error: `file not found: ${abs}` }));
      }
      const filename = path.basename(abs);
      const info = fileTypeInfo(filename);
      if (!info) {
        return sock.end(
          JSON.stringify({ error: `unsupported file extension for: ${filename}` })
        );
      }
      const id = crypto.randomBytes(4).toString('hex');
      const stat = fs.statSync(abs);
      const { salt, hash } = hashPassword(msg.password);
      const session = {
        id,
        path: abs,
        filename,
        documentType: info.documentType,
        fileType: info.fileType,
        key: `${id}-${Math.floor(stat.mtimeMs)}`,
        createdAt: Date.now(),
        passwordSalt: salt,
        passwordHash: hash,
      };
      sessions[id] = session;
      persist();

      const host = advertiseHost();
      const editUrls = [`http://${host}:${cfg.port}/edit/${id}`];
      return sock.end(JSON.stringify({ id, editUrls, port: cfg.port }));
    }

    if (msg.cmd === 'passwd') {
      const session = sessions[msg.id];
      if (!session) {
        return sock.end(JSON.stringify({ error: 'no such session' }));
      }
      const { salt, hash } = hashPassword(msg.password);
      session.passwordSalt = salt;
      session.passwordHash = hash;
      persist();
      return sock.end(JSON.stringify({ ok: true }));
    }

    if (msg.cmd === 'info') {
      const session = sessions[msg.id];
      if (!session) {
        return sock.end(JSON.stringify({ error: 'no such session' }));
      }
      const { passwordSalt, passwordHash, ...safe } = session;
      return sock.end(JSON.stringify({ session: safe }));
    }

    if (msg.cmd === 'list') {
      const safeList = Object.values(sessions).map(({ passwordSalt, passwordHash, ...s }) => s);
      return sock.end(JSON.stringify({ sessions: safeList }));
    }

    if (msg.cmd === 'stop') {
      if (msg.all) {
        for (const id of Object.keys(sessions)) delete sessions[id];
      } else if (msg.id && sessions[msg.id]) {
        delete sessions[msg.id];
      } else {
        return sock.end(JSON.stringify({ error: 'no such session' }));
      }
      persist();
      return sock.end(JSON.stringify({ ok: true }));
    }

    if (msg.cmd === 'shutdown') {
      sock.end(JSON.stringify({ ok: true }));
      setTimeout(() => process.exit(0), 100);
      return;
    }

    sock.end(JSON.stringify({ error: 'unknown command' }));
  }

  ctrl.listen(SOCK_PATH, () => {
    log(`control socket ready at ${SOCK_PATH}`);
  });

  process.on('SIGTERM', () => {
    try { fs.unlinkSync(SOCK_PATH); } catch {}
    process.exit(0);
  });
}

function commandExists(bin) {
  return new Promise((resolve) => {
    const which = spawn('which', [bin]);
    let out = '';
    which.stdout.on('data', (d) => (out += d));
    which.on('close', (code) => resolve(code === 0 && !!out.trim()));
  });
}

function runCapture(cmd, args) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args);
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('close', (code) => resolve({ code, stdout, stderr }));
    child.on('error', (e) => resolve({ code: -1, stdout, stderr: stderr + e.message }));
  });
}

function runInteractive(cmd, args) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { stdio: 'inherit' });
    child.on('close', (code) => resolve(code));
    child.on('error', () => resolve(-1));
  });
}

function startQuickTunnel(port, timeoutMs = 25000) {
  return new Promise((resolve, reject) => {
    const child = spawn('cloudflared', ['tunnel', '--url', `http://localhost:${port}`], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const urlRe = /https:\/\/[a-z0-9-]+\.trycloudflare\.com/i;
    let resolved = false;
    const onData = (chunk) => {
      const m = chunk.toString().match(urlRe);
      if (m && !resolved) {
        resolved = true;
        clearTimeout(timer);
        resolve({ url: m[0], proc: child });
      }
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.on('error', (e) => {
      if (!resolved) reject(e);
    });
    child.on('exit', (code) => {
      if (!resolved) reject(new Error(`cloudflared exited (code ${code}) before printing a URL`));
    });
    const timer = setTimeout(() => {
      if (!resolved) {
        resolved = true;
        child.kill();
        reject(new Error(`timed out waiting for cloudflared to print a URL for port ${port}`));
      }
    }, timeoutMs);
  });
}

function askQuestion(query) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => rl.question(query, (ans) => { rl.close(); resolve(ans.trim()); }));
}

function askPasswordMasked(query) {
  return new Promise((resolve) => {
    process.stdout.write(query);
    const stdin = process.stdin;
    stdin.resume();
    stdin.setRawMode(true);
    let input = '';
    const onData = (buf) => {
      const char = buf.toString('utf8');
      if (char === '\r' || char === '\n') {
        stdin.setRawMode(false);
        stdin.pause();
        stdin.removeListener('data', onData);
        process.stdout.write('\n');
        resolve(input);
      } else if (char === '\u0003') {
        process.exit(1);
      } else if (char === '\u007f' || char === '\b') {
        if (input.length) {
          input = input.slice(0, -1);
          process.stdout.write('\b \b');
        }
      } else {
        input += char;
        process.stdout.write('*');
      }
    };
    stdin.on('data', onData);
  });
}

async function resolvePassword(explicit) {
  if (explicit) return explicit;
  if (process.stdin.isTTY) {
    const entered = await askPasswordMasked('Set a password (blank to auto-generate): ');
    if (entered) return entered;
  }
  const generated = generatePassword(25);
  console.log(`Generated password: ${generated}`);
  return generated;
}

function extractFlag(args, name) {
  const i = args.indexOf(name);
  if (i === -1) return { value: undefined, rest: args };
  const value = args[i + 1];
  const rest = args.slice(0, i).concat(args.slice(i + 2));
  return { value, rest };
}

function isPidRunning(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

function isCfTunnelRunning() {
  if (!fs.existsSync(CF_PID_PATH)) return false;
  const pid = Number(fs.readFileSync(CF_PID_PATH, 'utf8').trim());
  if (!pid || !isPidRunning(pid)) return false;
  return true;
}

function startCfTunnel(cfg) {
  return new Promise((resolve, reject) => {
    if (!cfg.cfConfigPath || !fs.existsSync(cfg.cfConfigPath)) {
      reject(new Error('no cloudflared config found — run: hexcollab cloudflare setup'));
      return;
    }
    const out = fs.openSync(CF_LOG_PATH, 'a');
    const err = fs.openSync(CF_LOG_PATH, 'a');
    const child = spawn('cloudflared', ['tunnel', '--config', cfg.cfConfigPath, 'run', cfg.cfTunnelName], {
      detached: true,
      stdio: ['ignore', out, err],
    });
    fs.writeFileSync(CF_PID_PATH, String(child.pid));
    child.unref();
    setTimeout(resolve, 3000);
  });
}

function stopCfTunnel() {
  if (!fs.existsSync(CF_PID_PATH)) return false;
  const pid = Number(fs.readFileSync(CF_PID_PATH, 'utf8').trim());
  if (pid && isPidRunning(pid)) {
    try { process.kill(pid, 'SIGTERM'); } catch {}
  }
  try { fs.unlinkSync(CF_PID_PATH); } catch {}
  return true;
}

async function cloudflareSetup(cfg, args) {
  if (!(await commandExists('cloudflared'))) {
    console.log('cloudflared not found in PATH. Install it first:');
    console.log('https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/');
    process.exit(1);
  }

  console.log('Opening cloudflared login — authenticate with the Cloudflare account that owns your domain.\n');
  const loginCode = await runInteractive('cloudflared', ['tunnel', 'login']);
  if (loginCode !== 0) {
    console.error('cloudflared login did not complete successfully.');
    process.exit(1);
  }

  let domain = args[0];
  if (!domain) {
    domain = await askQuestion('Domain to use (must be added to your Cloudflare account, e.g. example.com): ');
  }
  domain = domain.trim().replace(/^https?:\/\//, '').replace(/\/$/, '');
  if (!domain) {
    console.error('No domain given.');
    process.exit(1);
  }

  const tunnelName = cfg.cfTunnelName || 'hexcollab';
  let tunnelId = '';

  const create = await runCapture('cloudflared', ['tunnel', 'create', tunnelName]);
  const uuidRe = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;
  let m = (create.stdout + create.stderr).match(uuidRe);
  if (m) {
    tunnelId = m[0];
  } else {
    const list = await runCapture('cloudflared', ['tunnel', 'list']);
    const lines = list.stdout.split('\n').filter((l) => l.includes(tunnelName));
    if (lines.length) {
      const lm = lines[0].match(uuidRe);
      if (lm) tunnelId = lm[0];
    }
  }
  if (!tunnelId) {
    console.error('Could not determine tunnel ID. Output was:\n' + create.stdout + create.stderr);
    process.exit(1);
  }

  const credentialsFile = path.join(HOME, '.cloudflared', `${tunnelId}.json`);
  if (!fs.existsSync(credentialsFile)) {
    console.error(`Expected credentials file not found at ${credentialsFile}`);
    process.exit(1);
  }

  const hexHostname = `hex.${domain}`;
  const docHostname = `docs.${domain}`;

  await runCapture('cloudflared', ['tunnel', 'route', 'dns', tunnelName, hexHostname]);
  await runCapture('cloudflared', ['tunnel', 'route', 'dns', tunnelName, docHostname]);

  let docPort = 80;
  try {
    docPort = Number(new URL(cfg.server).port) || (cfg.server.startsWith('https') ? 443 : 80);
  } catch {
    docPort = 8080;
  }

  fs.mkdirSync(CF_DIR, { recursive: true });
  const configYml = `tunnel: ${tunnelId}
credentials-file: ${credentialsFile}
ingress:
  - hostname: ${hexHostname}
    service: http://localhost:${cfg.port}
  - hostname: ${docHostname}
    service: http://localhost:${docPort}
  - service: http_status:404
`;
  fs.writeFileSync(CF_CONFIG_PATH, configYml);

  cfg.cfTunnelName = tunnelName;
  cfg.cfTunnelId = tunnelId;
  cfg.cfHexHostname = hexHostname;
  cfg.cfDocHostname = docHostname;
  cfg.cfConfigPath = CF_CONFIG_PATH;
  saveConfig(cfg);

  console.log('\nCloudflare tunnel configured:');
  console.log(`  ${hexHostname}  -> localhost:${cfg.port}`);
  console.log(`  ${docHostname}  -> localhost:${docPort}`);
  console.log('\nStart it with: hexcollab cloudflare start');
  console.log('Then: hexcollab tunnel <session-id>   will use this automatically.');
}

function printLanIPHint(cfg) {
  const ips = detectLanIPs();
  if (cfg.advertiseHost) return;
  if (ips.length > 1) {
    console.log(
      `(auto-detected LAN IPs: ${ips.join(', ')} — using ${ips[0]}. ` +
      `Set "advertiseHost" in config if that's the wrong interface.)`
    );
  }
}

async function main() {
  const args = process.argv.slice(2);
  const cmd = args[0];

  if (cmd === '--daemon') {
    runDaemon();
    return;
  }

  const cfg = loadConfig();

  if (!cmd || cmd === 'help' || cmd === '-h' || cmd === '--help') {
    console.log(`hexcollab

Usage:
  hexcollab share <file> [--password <pw>]
  hexcollab list
  hexcollab info <id>
  hexcollab passwd <id> [--password <pw>]
  hexcollab stop <id>
  hexcollab stop --all
  hexcollab tunnel <id>
  hexcollab cloudflare setup [domain]
  hexcollab cloudflare start
  hexcollab cloudflare stop
  hexcollab config
  hexcollab config <key> <value>
  hexcollab kill

Config file: ${CONFIG_PATH}
Log file:    ${LOG_PATH}
`);
    return;
  }

  if (cmd === 'config') {
    if (args.length === 1) {
      console.log(JSON.stringify(cfg, null, 2));
      return;
    }
    const key = args[1];
    const value = args[2];
    if (!(key in DEFAULT_CONFIG)) {
      console.error(`Unknown config key "${key}". Valid keys: ${Object.keys(DEFAULT_CONFIG).join(', ')}`);
      process.exit(1);
    }
    if (value === undefined) {
      console.log(cfg[key]);
      return;
    }
    cfg[key] = key === 'port' ? Number(value) : value;
    saveConfig(cfg);
    console.log(`Set ${key} = ${cfg[key]}`);
    console.log('Restart the daemon for this to take effect: hexcollab kill && hexcollab share <file>');
    return;
  }

  if (cmd === 'share') {
    const { value: passwordFlag, rest } = extractFlag(args.slice(1), '--password');
    const file = rest[0];
    if (!file) {
      console.error('Usage: hexcollab share <file> [--password <pw>]');
      process.exit(1);
    }
    const password = await resolvePassword(passwordFlag);
    await ensureDaemon(cfg);
    const resp = await sendToDaemon({ cmd: 'share', path: file, password });
    if (resp.error) {
      console.error('Error:', resp.error);
      process.exit(1);
    }
    console.log(`\nShared "${path.basename(file)}" — session ${resp.id}`);
    console.log(`Password: ${password}\n`);
    console.log('Give this to collaborators on your LAN:');
    for (const u of resp.editUrls) console.log('  ' + u);
    printLanIPHint(cfg);
    console.log('\nFor internet collaboration instead, run:');
    console.log(`  hexcollab tunnel ${resp.id}`);
    return;
  }

  if (cmd === 'list') {
    await ensureDaemon(cfg);
    const resp = await sendToDaemon({ cmd: 'list' });
    if (!resp.sessions || resp.sessions.length === 0) {
      console.log('No active sessions.');
      return;
    }
    for (const s of resp.sessions) {
      console.log(`${s.id}  ${s.filename}  ${new Date(s.createdAt).toLocaleString()}  (${s.path})`);
    }
    return;
  }

  if (cmd === 'info') {
    const id = args[1];
    if (!id) {
      console.error('Usage: hexcollab info <id>');
      process.exit(1);
    }
    await ensureDaemon(cfg);
    const resp = await sendToDaemon({ cmd: 'info', id });
    if (resp.error) {
      console.error('Error:', resp.error);
      process.exit(1);
    }
    console.log(JSON.stringify(resp.session, null, 2));
    return;
  }

  if (cmd === 'passwd') {
    const { value: passwordFlag, rest } = extractFlag(args.slice(1), '--password');
    const id = rest[0];
    if (!id) {
      console.error('Usage: hexcollab passwd <id> [--password <pw>]');
      process.exit(1);
    }
    const password = await resolvePassword(passwordFlag);
    await ensureDaemon(cfg);
    const resp = await sendToDaemon({ cmd: 'passwd', id, password });
    if (resp.error) {
      console.error('Error:', resp.error);
      process.exit(1);
    }
    console.log(`\nNew password for ${id}: ${password}`);
    return;
  }

  if (cmd === 'stop') {
    await ensureDaemon(cfg);
    if (args[1] === '--all') {
      await sendToDaemon({ cmd: 'stop', all: true });
      console.log('Stopped all sessions.');
    } else if (args[1]) {
      const resp = await sendToDaemon({ cmd: 'stop', id: args[1] });
      if (resp.error) {
        console.error('Error:', resp.error);
        process.exit(1);
      }
      console.log(`Stopped session ${args[1]}.`);
    } else {
      console.error('Usage: hexcollab stop <id> | hexcollab stop --all');
      process.exit(1);
    }
    return;
  }

  if (cmd === 'cloudflare') {
    const sub = args[1];
    if (sub === 'setup') {
      await cloudflareSetup(cfg, args.slice(2));
      return;
    }
    if (sub === 'start') {
      if (isCfTunnelRunning()) {
        console.log('Already running.');
        return;
      }
      try {
        await startCfTunnel(cfg);
        console.log(`Started. Logs: ${CF_LOG_PATH}`);
      } catch (e) {
        console.error('Error:', e.message);
        process.exit(1);
      }
      return;
    }
    if (sub === 'stop') {
      const stopped = stopCfTunnel();
      console.log(stopped ? 'Stopped.' : 'Was not running.');
      return;
    }
    console.error('Usage: hexcollab cloudflare setup|start|stop');
    process.exit(1);
  }

  if (cmd === 'tunnel') {
    const id = args[1];
    if (!id) {
      console.error('Usage: hexcollab tunnel <id>');
      process.exit(1);
    }

    if (cfg.cfHexHostname && cfg.cfDocHostname && cfg.cfConfigPath) {
      if (!isCfTunnelRunning()) {
        console.log('Starting cloudflared tunnel...');
        try {
          await startCfTunnel(cfg);
        } catch (e) {
          console.error('Error:', e.message);
          process.exit(1);
        }
      }
      const joinUrl = `https://${cfg.cfHexHostname}/edit/${id}?docserver=${encodeURIComponent('https://' + cfg.cfDocHostname)}`;
      console.log('Share this link for internet collaboration:');
      console.log('  ' + joinUrl);
      return;
    }

    if (!(await commandExists('cloudflared'))) {
      console.log('cloudflared not found in PATH. Install it, then run this again.');
      process.exit(1);
    }

    let docPort = 80;
    try {
      docPort = Number(new URL(cfg.server).port) || (cfg.server.startsWith('https') ? 443 : 80);
    } catch {
      console.error(`Config "server" (${cfg.server}) isn't a valid URL — fix it with: hexcollab config server <url>`);
      process.exit(1);
    }

    console.log('No persistent tunnel configured (run "hexcollab cloudflare setup" for a stable link).');
    console.log('Starting two temporary tunnels instead...\n');

    let hex, doc;
    try {
      [hex, doc] = await Promise.all([
        startQuickTunnel(cfg.port),
        startQuickTunnel(docPort),
      ]);
    } catch (e) {
      console.error('Failed to start tunnel:', e.message);
      process.exit(1);
    }

    const joinUrl = `${hex.url}/edit/${id}?docserver=${encodeURIComponent(doc.url)}`;
    console.log(`hexcollab tunnel:       ${hex.url}`);
    console.log(`Document Server tunnel: ${doc.url}`);
    console.log('\nShare this link for internet collaboration:');
    console.log('  ' + joinUrl);
    console.log('\nPress Ctrl+C to stop both tunnels.');

    const stop = () => {
      hex.proc.kill();
      doc.proc.kill();
      process.exit(0);
    };
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
    await new Promise(() => {});
    return;
  }

  if (cmd === 'kill') {
    if (!isDaemonRunning()) {
      console.log('Daemon is not running.');
      return;
    }
    try {
      await sendToDaemon({ cmd: 'shutdown' }, 1500);
    } catch {}
    try { fs.unlinkSync(SOCK_PATH); } catch {}
    console.log('Daemon stopped.');
    return;
  }

  console.error(`Unknown command: ${cmd}\nRun "hexcollab help" for usage.`);
  process.exit(1);
}

main().catch((e) => {
  console.error('Error:', e.message);
  process.exit(1);
});
