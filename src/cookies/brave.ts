import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  BRAVE_COOKIES_PATH,
  BRAVE_KEYCHAIN_ACCOUNT,
  BRAVE_KEYCHAIN_ACCOUNT_ALT,
  BRAVE_KEYCHAIN_SERVICE,
  BRAVE_KEYCHAIN_SERVICE_ALT,
  BRAVE_PROFILE,
  IS_BUN,
  KEYCHAIN_TIMEOUT_MS,
  NODE_BINARY,
  SQLITE_TIMEOUT_MS,
  DEBUG_COOKIES,
} from "../config.ts";
import { debugLog } from "../logging.ts";
import {
  assertValidCookieHeader,
  decodeMaybeBase64,
  deriveBraveKeys,
  isPathLike,
  isValidCookieHeader,
  parseSqliteCookies
} from "./common.ts";

function getBraveProfileRoots(profile: string): string[] {
  const home = os.homedir();
  if (!home) return [];

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
    if (first) return first;
  }

  throw new Error("Plateforme non supportee. Definis BRAVE_COOKIES_PATH.");
}

function getKeychainPassword(service: string, account?: string): Buffer {
  debugLog(`Keychain lookup: service="${service}" account="${account ?? ""}"`);
  const args = ["find-generic-password", "-w", "-s", service];
  if (account) args.push("-a", account);
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
        candidatePasswords.push({ label: labelBase, value: password });
        const utf8 = password.toString("utf8");
        if (utf8 && utf8 !== password.toString("binary")) {
          candidatePasswords.push({ label: `${labelBase}:utf8`, value: utf8 });
          const decoded = decodeMaybeBase64(utf8);
          if (decoded !== utf8) {
            candidatePasswords.push({ label: `${labelBase}:utf8:base64`, value: decoded });
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
    throw new Error("Impossible de copier la base Cookies (ferme Brave)." );
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

  const iterationCandidates = [1003];
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

function fetchCookiesViaNodeSqlite(): string {
  debugLog(`Lecture cookies sqlite via Node (${NODE_BINARY})`);
  const script = path.join(process.cwd(), "scripts", "cookies_sqlite_node.cjs");
  const result = spawnSync(NODE_BINARY, [script], {
    encoding: "utf8",
    timeout: SQLITE_TIMEOUT_MS,
    env: {
      ...process.env
    }
  });

  if (result.error) {
    throw new Error(
      `Impossible d'executer ${NODE_BINARY}. Installe Node ou definis NODE_BINARY.`
    );
  }

  if (result.status !== 0) {
    const stderr = (result.stderr || "").trim();
    throw new Error(stderr || "Echec de l'extraction des cookies via Node sqlite.");
  }

  return (result.stdout || "").trim();
}

export async function getBraveCookies(): Promise<string> {
  const envCookie = process.env.YT_COOKIE ?? process.env.YOUTUBE_COOKIE;
  if (envCookie) {
    debugLog("Cookies fournis via env");
    return envCookie;
  }

  if (IS_BUN) {
    debugLog("Execution sous Bun -> helper Node sqlite");
    return fetchCookiesViaNodeSqlite();
  }

  return await getBraveCookiesViaSqlite();
}
