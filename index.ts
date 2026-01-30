import { Innertube, UniversalCache, Mixins, YTNodes } from "youtubei.js";
import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { createDecipheriv, pbkdf2Sync } from "node:crypto";

type ChromeCookiesModule = {
  getCookies: (
    uri: string,
    format: string,
    callback: (err: unknown, cookies: unknown) => void,
    profileOrPath?: string
  ) => void;
  getCookiesPromised?: (
    uri: string,
    format?: string,
    profileOrPath?: string
  ) => Promise<unknown>;
};

const COOKIE_URL = "https://www.youtube.com";
const GOOGLE_COOKIE_URL = "https://www.google.com";
const BRAVE_PROFILE = process.env.BRAVE_PROFILE ?? "Default";
const BRAVE_COOKIES_PATH = process.env.BRAVE_COOKIES_PATH;
const NODE_BINARY = process.env.NODE_BINARY ?? "node";
const IS_BUN =
  typeof process !== "undefined" &&
  !!(process as { versions?: { bun?: string } }).versions?.bun;
const YT_DLP_BINARY = process.env.YT_DLP_BINARY ?? "yt-dlp";
const DEBUG_COOKIES = process.env.DEBUG_COOKIES === "1" || process.env.DEBUG === "1";
const NODE_COOKIE_TIMEOUT_MS = Number(process.env.NODE_COOKIE_TIMEOUT_MS ?? 15000);
const YT_DLP_TIMEOUT_MS = Number(process.env.YT_DLP_TIMEOUT_MS ?? 20000);
const SQLITE_TIMEOUT_MS = Number(process.env.SQLITE_TIMEOUT_MS ?? 15000);
const KEYCHAIN_TIMEOUT_MS = Number(process.env.KEYCHAIN_TIMEOUT_MS ?? 15000);
const MAX_PLAYLIST_PAGES = Number(process.env.MAX_PLAYLIST_PAGES ?? 3);
const ALL_PLAYLISTS = process.env.ALL_PLAYLISTS === "1";
const USE_YTDLP = process.env.USE_YTDLP === "1";
const USE_SQLITE = process.env.USE_SQLITE === "1";
const ALL_COOKIE_DOMAINS = process.env.ALL_COOKIE_DOMAINS === "1";
const COOKIE_ALLOWLIST = process.env.COOKIE_ALLOWLIST;
const MAX_COOKIE_HEADER_BYTES = Number(process.env.MAX_COOKIE_HEADER_BYTES ?? 8192);
const ACCOUNT_INDEX = process.env.ACCOUNT_INDEX
  ? Number(process.env.ACCOUNT_INDEX)
  : undefined;
const ON_BEHALF_OF_USER = process.env.ON_BEHALF_OF_USER;
const ACCOUNT_INDEX_AT_CREATE = process.env.ACCOUNT_INDEX_AT_CREATE === "1";
const SHOW_ACCOUNT_ENDPOINTS = process.env.SHOW_ACCOUNT_ENDPOINTS === "1";
const USE_LIBRARY_PLAYLISTS = process.env.USE_LIBRARY_PLAYLISTS === "1";
const { Feed } = Mixins;
const BRAVE_KEYCHAIN_SERVICE =
  process.env.BRAVE_KEYCHAIN_SERVICE ?? "Brave Safe Storage";
const BRAVE_KEYCHAIN_SERVICE_ALT =
  process.env.BRAVE_KEYCHAIN_SERVICE_ALT ?? "Chrome Safe Storage";
const BRAVE_KEYCHAIN_ACCOUNT =
  process.env.BRAVE_KEYCHAIN_ACCOUNT ?? "Brave";
const BRAVE_KEYCHAIN_ACCOUNT_ALT =
  process.env.BRAVE_KEYCHAIN_ACCOUNT_ALT ?? "Brave Browser";

function debugLog(message: string) {
  if (DEBUG_COOKIES) {
    console.error(`[debug] ${message}`);
  }
}

function isValidCookieHeader(header: string): boolean {
  if (!header) return false;
  for (let i = 0; i < header.length; i += 1) {
    const code = header.charCodeAt(i);
    if (code < 0x20 || code > 0x7e) {
      return false;
    }
  }
  return true;
}

function assertValidCookieHeader(header: string, source: string) {
  if (!isValidCookieHeader(header)) {
    throw new Error(
      `Cookies invalides (${source}). Valeurs non-ASCII detectees, ` +
        "probable cle Brave Safe Storage non prise en charge. " +
        "Utilise USE_SQLITE=1 ou USE_YTDLP=1."
    );
  }
}

function normalizeCookies(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  if (Array.isArray(value)) {
    return value
      .map((item) => {
        if (item && typeof item === "object") {
          const name = (item as { name?: string }).name;
          const val = (item as { value?: string }).value;
          if (name && typeof val === "string") {
            return `${name}=${val}`;
          }
        }
        return "";
      })
      .filter(Boolean)
      .join("; ");
  }
  if (value && typeof value === "object") {
    const maybe = (value as { cookies?: unknown }).cookies;
    if (maybe && typeof maybe === "string") {
      return maybe;
    }
  }
  return "";
}

function isPathLike(value: string): boolean {
  return value.includes("/") || value.includes("\\");
}

function getBraveProfileRoots(profile: string): string[] {
  const home = os.homedir();
  if (!home) {
    return [];
  }

  const braveDirs = [
    "Brave-Browser",
    "Brave-Browser-Beta",
    "Brave-Browser-Nightly",
    "Brave-Browser-Dev"
  ];

  if (process.platform === "darwin") {
    return braveDirs.map((dir) =>
      path.join(
        home,
        "Library",
        "Application Support",
        "BraveSoftware",
        dir,
        profile
      )
    );
  }

  if (process.platform === "linux") {
    return braveDirs.map((dir) =>
      path.join(home, ".config", "BraveSoftware", dir, profile)
    );
  }

  if (process.platform === "win32") {
    const localAppData =
      process.env.LOCALAPPDATA ?? path.join(home, "AppData", "Local");
    return braveDirs.map((dir) =>
      path.join(localAppData, "BraveSoftware", dir, "User Data", profile)
    );
  }

  return [];
}

function resolveBraveProfileOrPath(profile: string): string {
  if (BRAVE_COOKIES_PATH) {
    debugLog(`BRAVE_COOKIES_PATH fourni: ${BRAVE_COOKIES_PATH}`);
    return BRAVE_COOKIES_PATH;
  }

  if (isPathLike(profile)) {
    return profile;
  }

  const roots = getBraveProfileRoots(profile);
  const candidates = roots.flatMap((root) => [
    path.join(root, "Network", "Cookies"),
    path.join(root, "Cookies")
  ]);

  const existing = candidates.find((candidate) => fs.existsSync(candidate));
  if (existing) {
    debugLog(`Brave cookies detectes: ${existing}`);
    return existing;
  }

  if (candidates.length > 0) {
    return candidates[0];
  }

  throw new Error(
    "Plateforme non supportee. Definis BRAVE_COOKIES_PATH."
  );
}

async function fetchChromeCookies(
  chrome: ChromeCookiesModule,
  uri: string,
  profileOrPath?: string
): Promise<string> {
  if (chrome.getCookiesPromised) {
    const cookies = await chrome.getCookiesPromised(uri, "header", profileOrPath);
    return normalizeCookies(cookies);
  }

  return await new Promise((resolve, reject) => {
    const callback = (err: unknown, cookies: unknown) => {
      if (err) {
        reject(err);
        return;
      }
      resolve(normalizeCookies(cookies));
    };
    try {
      chrome.getCookies(uri, "header", callback, profileOrPath);
    } catch (err) {
      reject(err);
    }
  });
}

function fetchCookiesViaNode(uri: string, profileOrPath: string): string {
  debugLog(`Lecture cookies via Node (${NODE_BINARY}) pour ${uri}`);
  const nodeScript = [
    "const chrome = require('chrome-cookies-secure');",
    "const uri = process.env.NODE_COOKIE_URI;",
    "const profile = process.env.NODE_COOKIE_PROFILE;",
    "if (!uri) {",
    "  process.stderr.write('Missing NODE_COOKIE_URI');",
    "  process.exit(2);",
    "}",
    "chrome.getCookiesPromised(uri, 'header', profile)",
    ".then((cookies)=>{",
    "  if (typeof cookies === 'string') process.stdout.write(cookies);",
    "  else process.stdout.write(JSON.stringify(cookies));",
    "})",
    ".catch((err)=>{",
    "  const msg = err && err.message ? err.message : String(err);",
    "  process.stderr.write(msg);",
    "  process.exit(2);",
    "});"
  ].join("");

  const result = spawnSync(
    NODE_BINARY,
    ["-e", nodeScript],
    {
      encoding: "utf8",
      timeout: NODE_COOKIE_TIMEOUT_MS,
      env: {
        ...process.env,
        NODE_COOKIE_URI: uri,
        NODE_COOKIE_PROFILE: profileOrPath
      }
    }
  );

  if (result.error) {
    throw new Error(
      `Impossible d'executer ${NODE_BINARY}. Installe Node ou definis NODE_BINARY.`
    );
  }

  if (result.status !== 0) {
    const stderr = (result.stderr || "").trim();
    if (result.error && (result.error as { code?: string }).code === "ETIMEDOUT") {
      throw new Error("Timeout Node cookies. Deverrouille le Trousseau ou ferme Brave.");
    }
    throw new Error(stderr || "Echec de l'extraction des cookies via Node.");
  }

  return normalizeCookies(result.stdout.trim());
}

function hasAuthCookies(cookieHeader: string): boolean {
  return /SAPISID=/.test(cookieHeader) || /__Secure-3PAPISID=/.test(cookieHeader);
}

function mergeCookieHeaders(...headers: string[]): string {
  const jar = new Map<string, string>();
  for (const header of headers) {
    const parts = header
      .split(";")
      .map((part) => part.trim())
      .filter(Boolean);
    for (const part of parts) {
      const idx = part.indexOf("=");
      if (idx === -1) continue;
      const name = part.slice(0, idx).trim();
      const value = part.slice(idx + 1);
      if (name) {
        jar.set(name, value);
      }
    }
  }
  return Array.from(jar.entries())
    .map(([name, value]) => `${name}=${value}`)
    .join("; ");
}

const DEFAULT_COOKIE_ALLOWLIST = [
  "SAPISID",
  "APISID",
  "HSID",
  "SSID",
  "SID",
  "SIDCC",
  "LOGIN_INFO",
  "PREF",
  "VISITOR_INFO1_LIVE",
  "VISITOR_PRIVACY_METADATA",
  "YSC",
  "__Secure-1PAPISID",
  "__Secure-3PAPISID",
  "__Secure-1PSID",
  "__Secure-3PSID",
  "__Secure-1PSIDTS",
  "__Secure-3PSIDTS",
  "__Secure-1PSIDCC",
  "__Secure-3PSIDCC",
  "__Secure-YNID",
  "SOCS"
];

function buildCookieHeader(
  jar: Map<string, string>,
  allowlist?: Set<string>
): string {
  const entries = Array.from(jar.entries()).filter(([name]) =>
    allowlist ? allowlist.has(name) : true
  );
  return entries.map(([name, value]) => `${name}=${value}`).join("; ");
}

function parseNetscapeCookies(content: string, domains: string[]): string {
  const jar = new Map<string, { value: string; host: string }>();
  const domainList = domains.map((domain) => domain.toLowerCase());

  const matchesDomain = (rawDomain: string) => {
    if (ALL_COOKIE_DOMAINS) {
      return true;
    }
    const cleaned = rawDomain.replace(/^#HttpOnly_/i, "").toLowerCase();
    return domainList.some((domain) =>
      cleaned === domain || cleaned.endsWith(`.${domain}`)
    );
  };

  for (const line of content.split(/\r?\n/)) {
    if (!line) continue;
    if (line.startsWith("#") && !line.startsWith("#HttpOnly_")) continue;
    const parts = line.split("\t");
    if (parts.length < 7) continue;
    const domain = parts[0]?.trim();
    const name = parts[5]?.trim();
    const value = parts[6]?.trim();
    if (!domain || !name || value === undefined) continue;
    if (!matchesDomain(domain)) continue;
    const host = domain.replace(/^#HttpOnly_/i, "");
    const existing = jar.get(name);
    if (!existing || isPreferredHost(host, existing.host)) {
      jar.set(name, { value, host });
    }
  }

  const allowlist =
    COOKIE_ALLOWLIST?.split(",").map((name) => name.trim()).filter(Boolean) ??
    (ALL_COOKIE_DOMAINS ? DEFAULT_COOKIE_ALLOWLIST : []);
  const allowset = allowlist.length > 0 ? new Set(allowlist) : undefined;

  const flatJar = new Map<string, string>();
  for (const [name, entry] of jar.entries()) {
    flatJar.set(name, entry.value);
  }

  let header = buildCookieHeader(flatJar, allowset);
  if (Buffer.byteLength(header, "utf8") > MAX_COOKIE_HEADER_BYTES) {
    const fallbackAllowset = new Set(DEFAULT_COOKIE_ALLOWLIST);
    header = buildCookieHeader(flatJar, fallbackAllowset);
  }
  return header;
}

function getKeychainPassword(service: string, account?: string): string {
  const args = ["find-generic-password", "-w", "-s", service];
  if (account) {
    args.push("-a", account);
  }
  const result = spawnSync("security", args, {
    encoding: "utf8",
    timeout: KEYCHAIN_TIMEOUT_MS
  });

  if (result.error) {
    if ((result.error as { code?: string }).code === "ETIMEDOUT") {
      throw new Error("Timeout keychain. Autorise l'acces dans Trousseau.");
    }
    throw new Error("Impossible d'acceder au Trousseau macOS.");
  }

  if (result.status !== 0) {
    const stderr = (result.stderr || "").trim();
    throw new Error(stderr || "Keychain introuvable.");
  }

  const password = (result.stdout || "").trim();
  if (!password) {
    throw new Error("Mot de passe Trousseau vide.");
  }
  return password;
}

function decodeMaybeBase64(secret: string): Buffer | string {
  const trimmed = secret.trim();
  const base64Pattern = /^[A-Za-z0-9+/=]+$/;
  if (trimmed.length % 4 === 0 && base64Pattern.test(trimmed)) {
    try {
      const decoded = Buffer.from(trimmed, "base64");
      if (decoded.length > 0) {
        return decoded;
      }
    } catch {
      // fall through
    }
  }
  return trimmed;
}

function getBraveSafeStoragePassword(): Buffer | string {
  const envPassword = process.env.BRAVE_SAFE_STORAGE_PASSWORD;
  if (envPassword) {
    return decodeMaybeBase64(envPassword);
  }

  const candidates: Array<{ service: string; account?: string }> = [
    { service: BRAVE_KEYCHAIN_SERVICE, account: BRAVE_KEYCHAIN_ACCOUNT },
    { service: BRAVE_KEYCHAIN_SERVICE, account: BRAVE_KEYCHAIN_ACCOUNT_ALT },
    { service: BRAVE_KEYCHAIN_SERVICE },
    { service: BRAVE_KEYCHAIN_SERVICE_ALT, account: BRAVE_KEYCHAIN_ACCOUNT },
    { service: BRAVE_KEYCHAIN_SERVICE_ALT, account: BRAVE_KEYCHAIN_ACCOUNT_ALT },
    { service: BRAVE_KEYCHAIN_SERVICE_ALT }
  ];

  let lastError: Error | null = null;
  for (const candidate of candidates) {
    try {
      const password = getKeychainPassword(candidate.service, candidate.account);
      return decodeMaybeBase64(password);
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
    }
  }

  throw lastError ?? new Error("Keychain introuvable.");
}

function deriveBraveKey(password: Buffer | string): Buffer {
  return pbkdf2Sync(password, "saltysalt", 1003, 16, "sha1");
}

function decryptMacCookie(encryptedHex: string, key: Buffer): string {
  if (!encryptedHex) return "";
  const encrypted = Buffer.from(encryptedHex, "hex");
  if (encrypted.length === 0) return "";
  const prefix = encrypted.slice(0, 3).toString();
  if (prefix === "v11") {
    throw new Error("Format v11 non supporte (AES-GCM).");
  }
  const data = prefix === "v10" ? encrypted.slice(3) : encrypted;
  const iv = Buffer.alloc(16, " ");
  const decipher = createDecipheriv("aes-128-cbc", key, iv);
  decipher.setAutoPadding(false);
  const decoded = Buffer.concat([decipher.update(data), decipher.final()]);
  const padding = decoded[decoded.length - 1];
  const unpadded =
    padding > 0 && padding <= 16 ? decoded.slice(0, decoded.length - padding) : decoded;
  return unpadded.toString("utf8");
}

function isPreferredHost(newHost: string, existingHost: string): boolean {
  const newIsYouTube = newHost.includes("youtube.com");
  const existingIsYouTube = existingHost.includes("youtube.com");
  if (newIsYouTube && !existingIsYouTube) return true;
  if (!newIsYouTube && existingIsYouTube) return false;
  return newHost.length > existingHost.length;
}

function parseSqliteCookies(
  output: string,
  key: Buffer
): { header: string; skipped: number } {
  const separator = "\u001f";
  const jar = new Map<string, { value: string; host: string }>();
  let skipped = 0;

  const lines = output.split(/\r?\n/).filter(Boolean);
  for (const line of lines) {
    const [hostKey, name, valueRaw, encryptedHex] = line.split(separator);
    if (!name) continue;
    const value = valueRaw && valueRaw !== "NULL" ? valueRaw : "";
    const decrypted =
      value || (!encryptedHex ? "" : decryptMacCookie(encryptedHex, key));
    if (!decrypted) continue;
    if (!isValidCookieHeader(`${name}=${decrypted}`)) {
      skipped += 1;
      continue;
    }

    const existing = jar.get(name);
    if (!existing || isPreferredHost(hostKey, existing.host)) {
      jar.set(name, { value: decrypted, host: hostKey });
    }
  }

  const header = Array.from(jar.entries())
    .map(([name, entry]) => `${name}=${entry.value}`)
    .join("; ");
  return { header, skipped };
}

async function getBraveCookiesViaSqlite(): Promise<string> {
  if (process.platform !== "darwin") {
    throw new Error("SQLite cookies uniquement supporte sur macOS.");
  }

  const dbPath = resolveBraveProfileOrPath(BRAVE_PROFILE);
  if (!fs.existsSync(dbPath)) {
    throw new Error(`Cookies Brave introuvables: ${dbPath}`);
  }

  debugLog(`Lecture cookies sqlite: ${dbPath}`);
  const password = getBraveSafeStoragePassword();
  const key = deriveBraveKey(password);

  const separator = "\u001f";
  const query =
    "SELECT host_key, name, value, hex(encrypted_value) " +
    "FROM cookies " +
    "WHERE host_key LIKE '%.youtube.com' " +
    "OR host_key LIKE '%.google.com' " +
    "OR host_key = 'youtube.com' " +
    "OR host_key = 'google.com';";

  const tmpDir = await mkdtemp(path.join(os.tmpdir(), "brave-cookies-"));
  const tmpDb = path.join(tmpDir, "Cookies");
  try {
    fs.copyFileSync(dbPath, tmpDb);
  } catch {
    await rm(tmpDir, { recursive: true, force: true });
    throw new Error("Impossible de copier la base Cookies (ferme Brave).");
  }

  const result = spawnSync(
    "sqlite3",
    ["-readonly", "-separator", separator, tmpDb, query],
    { encoding: "utf8", timeout: SQLITE_TIMEOUT_MS }
  );

  if (result.error) {
    if ((result.error as { code?: string }).code === "ETIMEDOUT") {
      await rm(tmpDir, { recursive: true, force: true });
      throw new Error("Timeout sqlite3. Ferme Brave et reessaie.");
    }
    await rm(tmpDir, { recursive: true, force: true });
    throw new Error("Erreur sqlite3.");
  }

  if (result.status !== 0) {
    const stderr = (result.stderr || "").trim();
    await rm(tmpDir, { recursive: true, force: true });
    throw new Error(stderr || "Impossible de lire la base Cookies.");
  }

  const { header, skipped } = parseSqliteCookies(result.stdout || "", key);
  await rm(tmpDir, { recursive: true, force: true });
  if (!header) {
    if (skipped > 0) {
      throw new Error(
        "Dechiffrement cookies invalide. Autorise l'acces au Trousseau " +
          "ou fournis BRAVE_SAFE_STORAGE_PASSWORD."
      );
    }
    throw new Error("Aucun cookie lisible dans la base Brave.");
  }
  assertValidCookieHeader(header, "sqlite");
  return header;
}

async function fetchCookiesViaYtDlp(): Promise<string> {
  debugLog(`Lecture cookies via yt-dlp (${YT_DLP_BINARY})`);
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), "yt-cookies-"));
  const cookieFile = path.join(tmpDir, "cookies.txt");
  const browserSpec = `brave:${BRAVE_PROFILE}`;
  const args = ["--cookies-from-browser", browserSpec, "--cookies", cookieFile];

  try {
    let result = spawnSync(YT_DLP_BINARY, args, {
      encoding: "utf8",
      timeout: YT_DLP_TIMEOUT_MS
    });
    let stderr = (result.stderr || "").trim();

    if (
      result.status !== 0 &&
      /URL|No video|nothing to do|You must provide/i.test(stderr)
    ) {
      const fallbackArgs = [
        ...args,
        "--skip-download",
        "--no-playlist",
        COOKIE_URL
      ];
      result = spawnSync(YT_DLP_BINARY, fallbackArgs, {
        encoding: "utf8",
        timeout: YT_DLP_TIMEOUT_MS
      });
      stderr = (result.stderr || "").trim();
    }

    let content = "";
    try {
      content = await readFile(cookieFile, "utf8");
    } catch {
      content = "";
    }

    const header = parseNetscapeCookies(content, [
      "youtube.com",
      "google.com",
      "accounts.google.com"
    ]);
    if (header) {
      assertValidCookieHeader(header, "yt-dlp");
      debugLog(
        `Cookies yt-dlp: SAPISID=${/SAPISID=/.test(header)} __Secure-3PAPISID=${/__Secure-3PAPISID=/.test(
          header
        )}`
      );
      return header;
    }

    if (result.error) {
      if ((result.error as { code?: string }).code === "ETIMEDOUT") {
        throw new Error("Timeout yt-dlp. Verifie l'acces reseau ou ferme Brave.");
      }
      throw new Error(
        `Impossible d'executer ${YT_DLP_BINARY}. Installe yt-dlp ou definis YT_DLP_BINARY.`
      );
    }

    throw new Error(
      stderr || "yt-dlp n'a pas retourne de cookies utilisables."
    );
  } finally {
    await rm(tmpDir, { recursive: true, force: true });
  }
}

async function getCookiesForUrlWithModule(
  chrome: ChromeCookiesModule,
  url: string
): Promise<string> {
  const profileOrPath = resolveBraveProfileOrPath(BRAVE_PROFILE);
  try {
    const cookies = await fetchChromeCookies(chrome, url, profileOrPath);
    if (cookies) {
      return cookies;
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err ?? "");
    const pathHint = isPathLike(profileOrPath)
      ? ` Chemin: ${profileOrPath}.`
      : "";
    throw new Error(
      `Impossible de lire les cookies Brave pour ${url} (profil: ${BRAVE_PROFILE}). ` +
        "Ferme Brave et reessaie, ou definit BRAVE_PROFILE/BRAVE_COOKIES_PATH. " +
        pathHint +
        message
    );
  }

  const pathHint = isPathLike(profileOrPath)
    ? ` Chemin: ${profileOrPath}.`
    : "";
  throw new Error(
    `Impossible de lire les cookies Brave pour ${url} (profil: ${BRAVE_PROFILE}). ` +
      "Ferme Brave et reessaie, ou definit BRAVE_PROFILE/BRAVE_COOKIES_PATH. " +
      pathHint +
      "Cookies vides."
  );
}

function getCookiesForUrlViaNode(url: string): string {
  const profileOrPath = resolveBraveProfileOrPath(BRAVE_PROFILE);
  try {
    const cookies = fetchCookiesViaNode(url, profileOrPath);
    if (cookies) {
      return cookies;
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err ?? "");
    const pathHint = isPathLike(profileOrPath)
      ? ` Chemin: ${profileOrPath}.`
      : "";
    throw new Error(
      `Impossible de lire les cookies Brave pour ${url} (profil: ${BRAVE_PROFILE}). ` +
        "Ferme Brave et reessaie, ou definit BRAVE_PROFILE/BRAVE_COOKIES_PATH. " +
        pathHint +
        message
    );
  }

  const pathHint = isPathLike(profileOrPath)
    ? ` Chemin: ${profileOrPath}.`
    : "";
  throw new Error(
    `Impossible de lire les cookies Brave pour ${url} (profil: ${BRAVE_PROFILE}). ` +
      "Ferme Brave et reessaie, ou definit BRAVE_PROFILE/BRAVE_COOKIES_PATH. " +
      pathHint +
      "Cookies vides."
  );
}

async function loadChromeCookiesModule(): Promise<ChromeCookiesModule> {
  try {
    const mod = (await import("chrome-cookies-secure")) as unknown;
    return (mod as { default?: ChromeCookiesModule }).default ?? (mod as ChromeCookiesModule);
  } catch {
    throw new Error(
      "chrome-cookies-secure manquant. Lance `bun add chrome-cookies-secure`."
    );
  }
}

async function getBraveCookiesWithModule(): Promise<string> {
  debugLog("Chargement chrome-cookies-secure (module)");
  const chrome = await loadChromeCookiesModule();

  const youtubeCookies = await getCookiesForUrlWithModule(chrome, COOKIE_URL);
  assertValidCookieHeader(youtubeCookies, "chrome-cookies-secure");
  debugLog(
    `Cookies module: SAPISID=${/SAPISID=/.test(youtubeCookies)} __Secure-3PAPISID=${/__Secure-3PAPISID=/.test(
      youtubeCookies
    )}`
  );
  if (hasAuthCookies(youtubeCookies)) {
    return youtubeCookies;
  }

  try {
    const googleCookies = await getCookiesForUrlWithModule(chrome, GOOGLE_COOKIE_URL);
    return mergeCookieHeaders(youtubeCookies, googleCookies);
  } catch {
    return youtubeCookies;
  }
}

async function getBraveCookiesViaNode(): Promise<string> {
  debugLog("Lecture cookies via Node helper");
  const youtubeCookies = getCookiesForUrlViaNode(COOKIE_URL);
  assertValidCookieHeader(youtubeCookies, "node-helper");
  debugLog(
    `Cookies node: SAPISID=${/SAPISID=/.test(youtubeCookies)} __Secure-3PAPISID=${/__Secure-3PAPISID=/.test(
      youtubeCookies
    )}`
  );
  if (hasAuthCookies(youtubeCookies)) {
    return youtubeCookies;
  }

  try {
    const googleCookies = getCookiesForUrlViaNode(GOOGLE_COOKIE_URL);
    return mergeCookieHeaders(youtubeCookies, googleCookies);
  } catch {
    return youtubeCookies;
  }
}

async function getBraveCookies(): Promise<string> {
  const envCookie = process.env.YT_COOKIE ?? process.env.YOUTUBE_COOKIE;
  if (envCookie) {
    debugLog("Cookies fournis via env");
    return envCookie;
  }

  if (USE_YTDLP) {
    return await fetchCookiesViaYtDlp();
  }

  if (IS_BUN) {
    debugLog("Execution sous Bun -> helper Node + fallback yt-dlp");
    if (USE_SQLITE) {
      return await getBraveCookiesViaSqlite();
    }
    if (process.platform === "darwin") {
      try {
        return await getBraveCookiesViaSqlite();
      } catch (err) {
        debugLog(
          `SQLite cookies a echoue: ${err instanceof Error ? err.message : String(err ?? "")}`
        );
      }
    }

    try {
      return await getBraveCookiesViaNode();
    } catch (err) {
      debugLog(
        `Node cookies a echoue: ${err instanceof Error ? err.message : String(err ?? "")}`
      );
      try {
        return await fetchCookiesViaYtDlp();
      } catch (ytErr) {
        const nodeMessage = err instanceof Error ? err.message : String(err ?? "");
        const ytdlpMessage = ytErr instanceof Error ? ytErr.message : String(ytErr ?? "");
        throw new Error(
          `${nodeMessage} | Fallback yt-dlp: ${ytdlpMessage}`
        );
      }
    }
  }

  return await getBraveCookiesWithModule();
}

async function main() {
  debugLog("Demarrage");
  console.log("Lecture des cookies Brave...");
  const cookie = await getBraveCookies();
  if (!cookie) {
    throw new Error("Cookies vides.");
  }

  console.log("Initialisation Innertube...");
  debugLog("Creation session Innertube");
  const yt = await Innertube.create({
    cookie,
    cache: new UniversalCache(true),
    account_index:
      ACCOUNT_INDEX_AT_CREATE && Number.isFinite(ACCOUNT_INDEX)
        ? ACCOUNT_INDEX
        : undefined,
    on_behalf_of_user: ON_BEHALF_OF_USER
  });

  console.log(`Session connectee: ${yt.session.logged_in ? "oui" : "non"}`);
  if (!yt.session.logged_in) {
    console.log(
      "Si tu as plusieurs comptes, definis BRAVE_PROFILE (ex: \"Profile 1\")."
    );
  }

  let accounts: any[] = [];
  try {
    accounts = await yt.account.getInfo(true);
    if (accounts.length > 0) {
      console.log("Comptes detectes :");
      accounts.forEach((account: any, index: number) => {
        const name =
          account?.account_name?.toString?.() ??
          account?.title?.toString?.() ??
          "Sans nom";
        const byline = account?.account_byline?.toString?.() ?? "";
        const handle = account?.channel_handle?.toString?.() ?? "";
        const ids = getAccountIds(account);
        const parts = [name];
        if (handle) parts.push(handle);
        if (byline && byline !== name) parts.push(byline);
        if (ids.page_id) parts.push(`page_id=${ids.page_id}`);
        console.log(`${index}. ${parts.join(" - ")}`);
        if (SHOW_ACCOUNT_ENDPOINTS) {
          console.log(
            `   endpoint=${JSON.stringify(account?.endpoint?.payload ?? {})}`
          );
        }
      });
      console.log(
        "Choisis le compte avec ACCOUNT_INDEX (ex: ACCOUNT_INDEX=1) ou ON_BEHALF_OF_USER=page_id."
      );
    }
  } catch (err) {
    debugLog(
      `Account listing a echoue: ${err instanceof Error ? err.message : String(err ?? "")}`
    );
  }

  if (
    Number.isFinite(ACCOUNT_INDEX) &&
    accounts.length > 0 &&
    ACCOUNT_INDEX! >= 0 &&
    ACCOUNT_INDEX! < accounts.length
  ) {
    const account = accounts[ACCOUNT_INDEX!];
    if (account?.endpoint?.call) {
      console.log(`Selection du compte: ${ACCOUNT_INDEX}`);
      try {
        await account.endpoint.call(yt.actions, { parse: false });
      } catch (err) {
        debugLog(
          `Switch account a echoue: ${err instanceof Error ? err.message : String(err ?? "")}`
        );
      }
    }
  }

  console.log("Recuperation des playlists...");
  if (DEBUG_COOKIES && yt.actions?.session) {
    debugLog(
      `Account index actif: ${yt.actions.session.account_index ?? "n/a"}`
    );
    debugLog(
      `On behalf of user: ${yt.actions.session.context?.client?.on_behalf_of_user ?? "n/a"}`
    );
  }
  const feed = await yt.getPlaylists();
  let playlists = await collectPlaylists(feed);

  if (USE_LIBRARY_PLAYLISTS || playlists.length <= 2) {
    try {
      const libraryPlaylists = await getPlaylistsFromLibrary(yt);
      if (libraryPlaylists.length > playlists.length) {
        playlists = libraryPlaylists;
      }
    } catch (err) {
      debugLog(
        `Library playlists a echoue: ${err instanceof Error ? err.message : String(err ?? "")}`
      );
    }
  }

  if (playlists.length === 0) {
    console.log("Aucune playlist trouvee.");
    return;
  }

  console.log(`Playlists (${playlists.length}) :`);
  playlists.forEach((playlist, index) => {
    const title = getPlaylistTitle(playlist);
    const id = getPlaylistId(playlist);
    const count = getPlaylistCount(playlist);
    const parts = [`${index + 1}. ${title}`];
    if (count) {
      parts.push(`(${count})`);
    }
    if (id) {
      parts.push(`- ${id}`);
    }
    console.log(parts.join(" "));
  });
}

async function collectPlaylists(feed: any): Promise<any[]> {
  const items: any[] = [];
  let current = feed;
  let page = 0;
  const maxPages = ALL_PLAYLISTS ? Infinity : MAX_PLAYLIST_PAGES;

  while (current) {
    if (Array.isArray(current.playlists)) {
      items.push(...current.playlists);
    }
    page += 1;
    if (!current.has_continuation || page >= maxPages) {
      break;
    }
    current = await current.getContinuation();
  }

  return dedupePlaylists(items);
}

function dedupePlaylists(items: any[]): any[] {
  const seen = new Set<string>();
  const out: any[] = [];
  for (const item of items) {
    const id = getPlaylistId(item) ?? "";
    const title = getPlaylistTitle(item) ?? "";
    const key = `${id}::${title}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}

function getPlaylistTitle(item: any): string {
  if (item?.title?.toString) {
    return item.title.toString();
  }
  if (item?.metadata?.title?.toString) {
    return item.metadata.title.toString();
  }
  return "Sans titre";
}

function getPlaylistId(item: any): string | null {
  if (typeof item?.id === "string" && item.id) {
    return item.id;
  }
  if (typeof item?.content_id === "string" && item.content_id) {
    return item.content_id;
  }
  return null;
}

function getPlaylistCount(item: any): string | null {
  if (item?.video_count_short?.toString) {
    return item.video_count_short.toString();
  }
  if (item?.video_count?.toString) {
    return item.video_count.toString();
  }
  const metadataRows = item?.metadata?.metadata_rows;
  if (Array.isArray(metadataRows)) {
    for (const row of metadataRows) {
      const parts = row?.metadata_parts;
      if (!Array.isArray(parts)) continue;
      for (const part of parts) {
        const text = part?.text?.toString?.();
        if (text && /\b\d+\s+videos?\b/i.test(text)) {
          return text;
        }
      }
    }
  }
  return null;
}

function getAccountIds(account: any): { page_id?: string } {
  const payload = account?.endpoint?.payload;
  const selectIdentity = payload?.selectActiveIdentityEndpoint;
  const nextEndpoint = selectIdentity?.nextEndpoint;
  const browseId =
    nextEndpoint?.browseEndpoint?.browseId ??
    nextEndpoint?.browseEndpoint?.browseId?.toString?.();
  if (browseId && typeof browseId === "string") {
    return { page_id: browseId };
  }
  return {};
}

async function getPlaylistsFromLibrary(yt: any): Promise<any[]> {
  const library = await yt.getLibrary();
  if (DEBUG_COOKIES && library?.sections) {
    const labels = library.sections
      .map((section: any) => section?.title?.toString?.() ?? section?.type ?? "")
      .filter(Boolean)
      .join(", ");
    debugLog(`Library sections: ${labels}`);
  }
  const playlistsSection = library?.playlists_section;
  if (playlistsSection?.getAll) {
    const page = await playlistsSection.getAll();
    const feed = new Feed(yt.actions, page, true);
    return await collectPlaylists(feed);
  }

  const shelves =
    library?.page?.contents_memo?.getType?.(YTNodes.Shelf) ??
    library?.memo?.getType?.(YTNodes.Shelf) ??
    [];
  if (DEBUG_COOKIES && shelves.length > 0) {
    const names = shelves
      .map((shelf: any) => shelf?.title?.toString?.() ?? "")
      .filter(Boolean)
      .join(", ");
    debugLog(`Library shelves: ${names}`);
  }
  const playlistShelf = shelves.find(
    (shelf: any) => shelf?.icon_type === "PLAYLISTS"
  );
  if (!playlistShelf) {
    return [];
  }

  let endpoint = playlistShelf?.endpoint;
  if (!endpoint && playlistShelf?.menu?.top_level_buttons) {
    const buttons = playlistShelf.menu.top_level_buttons;
    endpoint = buttons.find((btn: any) => btn?.endpoint)?.endpoint;
  }

  if (!endpoint || typeof endpoint.call !== "function") {
    return [];
  }

  const response = await endpoint.call(yt.actions, { parse: true });
  const feed = new Feed(yt.actions, response, true);
  return await collectPlaylists(feed);
}

main().catch((err) => {
  const message = err instanceof Error ? err.message : String(err);
  console.error(`[erreur] ${message}`);
  process.exit(1);
});
