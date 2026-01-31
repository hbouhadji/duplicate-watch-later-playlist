import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  BRAVE_COOKIES_PATH,
  BRAVE_KEYCHAIN_ACCOUNT,
  BRAVE_KEYCHAIN_ACCOUNT_ALT,
  BRAVE_KEYCHAIN_SERVICE,
  BRAVE_KEYCHAIN_SERVICE_ALT,
  BRAVE_PROFILE,
  COOKIE_URL,
  GOOGLE_COOKIE_URL,
  IS_BUN,
  KEYCHAIN_TIMEOUT_MS,
  NODE_BINARY,
  NODE_COOKIE_TIMEOUT_MS,
  SQLITE_TIMEOUT_MS,
  DEBUG_COOKIES,
  USE_CHROME_COOKIES_SECURE,
  USE_SQLITE,
  USE_YTDLP,
  YT_DLP_BINARY,
  YT_DLP_TIMEOUT_MS
} from "../config.ts";
import { debugLog } from "../logging.ts";
import {
  assertValidCookieHeader,
  decodeMaybeBase64,
  deriveBraveKeys,
  hasAuthCookies,
  isPathLike,
  isValidCookieHeader,
  mergeCookieHeaders,
  normalizeCookies,
  parseNetscapeCookies,
  parseSqliteCookies
} from "./common.ts";
import type { ChromeCookiesModule } from "../config.ts";

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
    const first = candidates[0];
    if (first) {
      return first;
    }
  }

  throw new Error("Plateforme non supportee. Definis BRAVE_COOKIES_PATH.");
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

  const result = spawnSync(NODE_BINARY, ["-e", nodeScript], {
    encoding: "utf8",
    timeout: NODE_COOKIE_TIMEOUT_MS,
    env: {
      ...process.env,
      NODE_COOKIE_URI: uri,
      NODE_COOKIE_PROFILE: profileOrPath
    }
  });

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

function fetchCookiesViaNodeSqlite(): string {
  debugLog(`Lecture cookies sqlite via Node (${NODE_BINARY})`);
  const script = path.join(process.cwd(), "scripts", "cookies_sqlite_node.cjs");
  const result = spawnSync(
    NODE_BINARY,
    [script],
    {
      encoding: "utf8",
      timeout: SQLITE_TIMEOUT_MS,
      env: {
        ...process.env
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
    throw new Error(stderr || "Echec de l'extraction des cookies via Node sqlite.");
  }

  return normalizeCookies(result.stdout.trim());
}
function getKeychainPassword(service: string, account?: string): Buffer {
  debugLog(
    `Keychain lookup: service="${service}" account="${account ?? ""}"`
  );
  const args = ["find-generic-password", "-w", "-s", service];
  if (account) {
    args.push("-a", account);
  }
  const result = spawnSync("security", args, {
    encoding: "buffer",
    timeout: KEYCHAIN_TIMEOUT_MS
  });

  if (result.error) {
    if ((result.error as { code?: string }).code === "ETIMEDOUT") {
      throw new Error("Timeout keychain. Autorise l'acces dans Trousseau.");
    }
    throw new Error("Impossible d'acceder au Trousseau macOS.");
  }

  if (result.status !== 0) {
    const stderr = ((result.stderr as Buffer | null)?.toString("utf8") || "").trim();
    throw new Error(stderr || "Keychain introuvable.");
  }

  const stdout = result.stdout as Buffer | null;
  if (!stdout || stdout.length === 0) {
    throw new Error("Mot de passe Trousseau vide.");
  }
  let password = stdout;
  if (password[password.length - 1] === 0x0a) {
    password = password.subarray(0, password.length - 1);
  }
  debugLog(`Keychain password length: ${password.length}`);
  return password;
}

function getBraveSafeStorageCandidates(): Array<{ service: string; account?: string }> {
  return [
    { service: BRAVE_KEYCHAIN_SERVICE, account: BRAVE_KEYCHAIN_ACCOUNT },
    { service: BRAVE_KEYCHAIN_SERVICE, account: BRAVE_KEYCHAIN_ACCOUNT_ALT },
    { service: BRAVE_KEYCHAIN_SERVICE },
    { service: BRAVE_KEYCHAIN_SERVICE_ALT, account: BRAVE_KEYCHAIN_ACCOUNT },
    { service: BRAVE_KEYCHAIN_SERVICE_ALT, account: BRAVE_KEYCHAIN_ACCOUNT_ALT },
    { service: BRAVE_KEYCHAIN_SERVICE_ALT }
  ];
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
  const envPassword = process.env.BRAVE_SAFE_STORAGE_PASSWORD;
  const candidatePasswords: Array<{ label: string; value: Buffer | string }> = [];
  if (envPassword) {
    candidatePasswords.push({
      label: "env:BRAVE_SAFE_STORAGE_PASSWORD",
      value: decodeMaybeBase64(envPassword)
    });
  } else {
    let lastError: Error | null = null;
    for (const candidate of getBraveSafeStorageCandidates()) {
      try {
        const password = getKeychainPassword(candidate.service, candidate.account);
        const labelBase = `keychain:${candidate.service}:${candidate.account ?? ""}`;
        candidatePasswords.push({
          label: labelBase,
          value: password
        });
        const utf8 = password.toString("utf8");
        if (utf8 && utf8 !== password.toString("binary")) {
          candidatePasswords.push({
            label: `${labelBase}:utf8`,
            value: utf8
          });
          const decoded = decodeMaybeBase64(utf8);
          if (decoded !== utf8) {
            candidatePasswords.push({
              label: `${labelBase}:utf8:base64`,
              value: decoded
            });
          }
        }
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));
      }
    }
    if (candidatePasswords.length === 0) {
      throw lastError ?? new Error("Keychain introuvable.");
    }
  }

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

  const iterationCandidates = [1003, 1, 10000, 2000, 1500];
  let metaVersion = 0;
  const metaResult = spawnSync(
    "sqlite3",
    ["-readonly", tmpDb, "select value from meta where key='version' limit 1;"],
    { encoding: "utf8", timeout: SQLITE_TIMEOUT_MS }
  );
  if (metaResult.status === 0) {
    const raw = (metaResult.stdout || "").trim();
    const parsed = Number(raw);
    if (Number.isFinite(parsed)) metaVersion = parsed;
  }

  let bestStats:
    | { label: string; stats: ReturnType<typeof parseSqliteCookies> }
    | null = null;
  for (const candidate of candidatePasswords) {
    for (const iterations of iterationCandidates) {
      const keys = deriveBraveKeys(candidate.value, iterations);
      const stats = parseSqliteCookies(result.stdout || "", keys, metaVersion);
      if (DEBUG_COOKIES) {
    debugLog(
      `SQLite stats (${candidate.label} | iter=${iterations}): total=${stats.total} plain=${stats.plain} v10=${stats.v10} v11=${stats.v11} decrypted=${stats.decrypted} skipped=${stats.skipped} skipped_non_ascii=${stats.skipped_non_ascii}`
    );
      }
      if (stats.header && isValidCookieHeader(stats.header)) {
        bestStats = { label: `${candidate.label} | iter=${iterations}`, stats };
        break;
      }
      if (!bestStats) {
        bestStats = { label: `${candidate.label} | iter=${iterations}`, stats };
      }
    }
    if (bestStats?.stats.header && isValidCookieHeader(bestStats.stats.header)) {
      break;
    }
  }
  await rm(tmpDir, { recursive: true, force: true });
  if (!bestStats || !bestStats.stats.header) {
    if (bestStats?.stats && (bestStats.stats.skipped > 0 || bestStats.stats.total > 0)) {
      throw new Error(
        "Dechiffrement cookies invalide. Autorise l'acces au Trousseau " +
          "ou fournis BRAVE_SAFE_STORAGE_PASSWORD."
      );
    }
    throw new Error("Aucun cookie lisible dans la base Brave.");
  }
  if (DEBUG_COOKIES) {
    debugLog(`SQLite selected key: ${bestStats.label}`);
  }
  assertValidCookieHeader(bestStats.stats.header, "sqlite");
  return bestStats.stats.header;
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

    throw new Error(stderr || "yt-dlp n'a pas retourne de cookies utilisables.");
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

export async function getBraveCookies(): Promise<string> {
  const envCookie = process.env.YT_COOKIE ?? process.env.YOUTUBE_COOKIE;
  if (envCookie) {
    debugLog("Cookies fournis via env");
    return envCookie;
  }

  if (USE_CHROME_COOKIES_SECURE) {
    debugLog("Force chrome-cookies-secure (sans fallback)");
    return await getBraveCookiesWithModule();
  }

  if (USE_YTDLP) {
    return await fetchCookiesViaYtDlp();
  }

  if (IS_BUN) {
    debugLog("Execution sous Bun -> helper Node + fallback yt-dlp");
    if (USE_SQLITE) {
      return fetchCookiesViaNodeSqlite();
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
        throw new Error(`${nodeMessage} | Fallback yt-dlp: ${ytdlpMessage}`);
      }
    }
  }

  return await getBraveCookiesWithModule();
}
