#!/usr/bin/env node
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { mkdtempSync, rmSync, readFileSync } = require('node:fs');
const { pbkdf2Sync, createDecipheriv } = require('node:crypto');

const DEBUG = process.env.DEBUG_COOKIES === '1' || process.env.DEBUG === '1';
const BRAVE_PROFILE = process.env.BRAVE_PROFILE || 'Default';
const BRAVE_COOKIES_PATH = process.env.BRAVE_COOKIES_PATH;
const SQLITE_TIMEOUT_MS = Number(process.env.SQLITE_TIMEOUT_MS || 15000);
const ALL_COOKIE_DOMAINS = process.env.ALL_COOKIE_DOMAINS === '1';
const COOKIE_ALLOWLIST = process.env.COOKIE_ALLOWLIST;
const MAX_COOKIE_HEADER_BYTES = Number(process.env.MAX_COOKIE_HEADER_BYTES || 8192);

const BRAVE_KEYCHAIN_SERVICE = process.env.BRAVE_KEYCHAIN_SERVICE || 'Brave Safe Storage';
const BRAVE_KEYCHAIN_ACCOUNT = process.env.BRAVE_KEYCHAIN_ACCOUNT || 'Brave';
const BRAVE_KEYCHAIN_SERVICE_ALT = process.env.BRAVE_KEYCHAIN_SERVICE_ALT || 'Chrome Safe Storage';
const BRAVE_KEYCHAIN_ACCOUNT_ALT = process.env.BRAVE_KEYCHAIN_ACCOUNT_ALT || 'Brave Browser';

const DEFAULT_COOKIE_ALLOWLIST = [
  'SAPISID','APISID','HSID','SSID','SID','SIDCC','LOGIN_INFO','PREF','VISITOR_INFO1_LIVE',
  'VISITOR_PRIVACY_METADATA','YSC','__Secure-1PAPISID','__Secure-3PAPISID','__Secure-1PSID',
  '__Secure-3PSID','__Secure-1PSIDTS','__Secure-3PSIDTS','__Secure-1PSIDCC','__Secure-3PSIDCC',
  '__Secure-YNID','SOCS'
];

function debug(msg) {
  if (DEBUG) console.error(`[debug] ${msg}`);
}

function isValidCookieHeader(header) {
  if (!header) return false;
  for (let i = 0; i < header.length; i += 1) {
    const code = header.charCodeAt(i);
    if (code < 0x20 || code > 0x7e) return false;
  }
  return true;
}

function getBraveProfileRoots(profile) {
  const home = os.homedir();
  if (!home) return [];
  const braveDirs = ['Brave-Browser','Brave-Browser-Beta','Brave-Browser-Nightly','Brave-Browser-Dev'];
  if (process.platform === 'darwin') {
    return braveDirs.map((dir) => path.join(home, 'Library', 'Application Support', 'BraveSoftware', dir, profile));
  }
  if (process.platform === 'linux') {
    return braveDirs.map((dir) => path.join(home, '.config', 'BraveSoftware', dir, profile));
  }
  if (process.platform === 'win32') {
    const localAppData = process.env.LOCALAPPDATA || path.join(home, 'AppData', 'Local');
    return braveDirs.map((dir) => path.join(localAppData, 'BraveSoftware', dir, 'User Data', profile));
  }
  return [];
}

function resolveBraveProfileOrPath(profile) {
  if (BRAVE_COOKIES_PATH) return BRAVE_COOKIES_PATH;
  if (profile.includes('/') || profile.includes('\\')) return profile;
  const roots = getBraveProfileRoots(profile);
  const candidates = roots.flatMap((root) => [path.join(root, 'Network', 'Cookies'), path.join(root, 'Cookies')]);
  const existing = candidates.find((p) => fs.existsSync(p));
  if (existing) return existing;
  if (candidates.length) return candidates[0];
  throw new Error('Plateforme non supportee. Definis BRAVE_COOKIES_PATH.');
}

function getKeychainPassword(service, account) {
  const args = ['find-generic-password', '-w', '-s', service];
  if (account) args.push('-a', account);
  const result = spawnSync('security', args, { encoding: 'buffer' });
  if (result.error || result.status !== 0) return null;
  let out = result.stdout;
  if (!out || !out.length) return null;
  if (out[out.length - 1] === 0x0a) out = out.subarray(0, -1);
  return out;
}

function deriveKey(password, iterations=1003, keyLen=16) {
  return pbkdf2Sync(password, 'saltysalt', iterations, keyLen, 'sha1');
}

function decryptV10(encryptedHex, key, metaVersion) {
  const enc = Buffer.from(encryptedHex, 'hex');
  if (enc.length < 3) return '';
  const data = enc.subarray(3);
  const iv = Buffer.alloc(16, ' ');
  const decipher = createDecipheriv('aes-128-cbc', key, iv);
  decipher.setAutoPadding(false);
  const decoded = Buffer.concat([decipher.update(data), decipher.final()]);
  if (!decoded.length) return '';
  const pad = decoded[decoded.length - 1];
  const unpadded = pad > 0 && pad <= 16 ? decoded.subarray(0, decoded.length - pad) : decoded;
  const out = metaVersion >= 24 && unpadded.length > 32 ? unpadded.subarray(32) : unpadded;
  return out.toString('utf8');
}

function parseSqlite(output, key, metaVersion) {
  const separator = '\u001f';
  const jar = new Map();
  for (const line of output.split(/\r?\n/).filter(Boolean)) {
    const [hostKey, name, valueRaw, encryptedHex] = line.split(separator);
    if (!hostKey || !name) continue;
    const value = valueRaw && valueRaw !== 'NULL' ? valueRaw : '';
    const decrypted = value || (encryptedHex ? decryptV10(encryptedHex, key, metaVersion) : '');
    if (!decrypted) continue;
    const existing = jar.get(name);
    if (!existing || (hostKey.includes('youtube.com') && !existing.host.includes('youtube.com'))) {
      jar.set(name, { value: decrypted, host: hostKey });
    }
  }

  const allowlist =
    (COOKIE_ALLOWLIST ? COOKIE_ALLOWLIST.split(',').map((n) => n.trim()).filter(Boolean) : null) ||
    DEFAULT_COOKIE_ALLOWLIST;
  const allowset = new Set(allowlist);

  const flatJar = new Map();
  for (const [name, entry] of jar.entries()) {
    if (!isValidCookieHeader(`${name}=${entry.value}`)) continue;
    if (!allowset.has(name)) continue;
    flatJar.set(name, entry.value);
  }

  let header = Array.from(flatJar.entries()).map(([k, v]) => `${k}=${v}`).join('; ');
  if (Buffer.byteLength(header, 'utf8') > MAX_COOKIE_HEADER_BYTES) {
    const fallback = new Set(DEFAULT_COOKIE_ALLOWLIST);
    header = Array.from(flatJar.entries())
      .filter(([k]) => fallback.has(k))
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
  }
  return header;
}

function main() {
  const dbPath = resolveBraveProfileOrPath(BRAVE_PROFILE);
  if (!fs.existsSync(dbPath)) throw new Error(`Cookies Brave introuvables: ${dbPath}`);
  debug(`sqlite db: ${dbPath}`);

  const tmpDir = mkdtempSync(path.join(os.tmpdir(), 'brave-cookies-'));
  const tmpDb = path.join(tmpDir, 'Cookies');
  fs.copyFileSync(dbPath, tmpDb);

  try {
    const separator = '\u001f';
    const query =
      "SELECT host_key, name, value, hex(encrypted_value) " +
      "FROM cookies " +
      "WHERE host_key LIKE '%.youtube.com' " +
      "OR host_key LIKE '%.google.com' " +
      "OR host_key = 'youtube.com' " +
      "OR host_key = 'google.com';";

    const result = spawnSync('sqlite3', ['-readonly', '-separator', separator, tmpDb, query], {
      encoding: 'utf8',
      timeout: SQLITE_TIMEOUT_MS
    });
    if (result.error || result.status !== 0) {
      throw new Error((result.stderr || '').trim() || 'sqlite3 error');
    }

    const candidates = [];
    const envPass = process.env.BRAVE_SAFE_STORAGE_PASSWORD;
    if (envPass) {
      candidates.push({ label: 'env', value: Buffer.from(envPass, 'utf8') });
      try {
        const decoded = Buffer.from(envPass, 'base64');
        if (decoded.length) candidates.push({ label: 'env:base64', value: decoded });
      } catch {}
    }

    const kc = [
      { service: BRAVE_KEYCHAIN_SERVICE, account: BRAVE_KEYCHAIN_ACCOUNT },
      { service: BRAVE_KEYCHAIN_SERVICE, account: BRAVE_KEYCHAIN_ACCOUNT_ALT },
      { service: BRAVE_KEYCHAIN_SERVICE, account: '' },
      { service: BRAVE_KEYCHAIN_SERVICE_ALT, account: BRAVE_KEYCHAIN_ACCOUNT },
      { service: BRAVE_KEYCHAIN_SERVICE_ALT, account: BRAVE_KEYCHAIN_ACCOUNT_ALT },
      { service: BRAVE_KEYCHAIN_SERVICE_ALT, account: '' }
    ];

    for (const k of kc) {
      const pw = getKeychainPassword(k.service, k.account);
      if (pw) candidates.push({ label: `keychain:${k.service}:${k.account}`, value: pw });
    }

    if (!candidates.length) throw new Error('Keychain introuvable.');

    let metaVersion = 0;
    const metaResult = spawnSync('sqlite3', ['-readonly', tmpDb, "select value from meta where key='version' limit 1;"], {
      encoding: 'utf8',
      timeout: SQLITE_TIMEOUT_MS
    });
    if (metaResult.status === 0) {
      const raw = (metaResult.stdout || '').trim();
      const parsed = Number(raw);
      if (Number.isFinite(parsed)) metaVersion = parsed;
    }

    for (const cand of candidates) {
      const key = deriveKey(cand.value, 1003, 16);
      const header = parseSqlite(result.stdout || '', key, metaVersion);
      debug(`candidate ${cand.label} header bytes=${Buffer.byteLength(header, 'utf8')}`);
      if (header && isValidCookieHeader(header)) {
        process.stdout.write(header);
        return;
      }
    }

    throw new Error('Aucun cookie lisible (header vide).');
  } finally {
    rmSync(tmpDir, { recursive: true, force: true });
  }
}

main();
