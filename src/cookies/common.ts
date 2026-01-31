import { createDecipheriv, pbkdf2Sync } from "node:crypto";
import { COOKIE_ALLOWLIST, MAX_COOKIE_HEADER_BYTES } from "../config.ts";

export function isValidCookieHeader(header: string): boolean {
  if (!header) return false;
  for (let i = 0; i < header.length; i += 1) {
    const code = header.charCodeAt(i);
    if (code < 0x20 || code > 0x7e) {
      return false;
    }
  }
  return true;
}

export function assertValidCookieHeader(header: string, source: string) {
  if (!isValidCookieHeader(header)) {
    throw new Error(
      `Cookies invalides (${source}). Valeurs non-ASCII detectees, ` +
        "probable cle Brave Safe Storage non prise en charge. " +
        "Utilise USE_SQLITE=1."
    );
  }
}

export function isPathLike(value: string): boolean {
  return value.includes("/") || value.includes("\\");
}

export const DEFAULT_COOKIE_ALLOWLIST = [
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

export function buildCookieHeader(
  jar: Map<string, string>,
  allowlist?: Set<string>
): string {
  const entries = Array.from(jar.entries()).filter(([name]) =>
    allowlist ? allowlist.has(name) : true
  );
  return entries.map(([name, value]) => `${name}=${value}`).join("; ");
}

export function decodeMaybeBase64(secret: string): Buffer | string {
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

export type BraveKeys = {
  v10: Buffer;
  v11: Buffer;
};

export function deriveBraveKeys(
  password: Buffer | string,
  iterations = 1003
): BraveKeys {
  return {
    v10: pbkdf2Sync(password, "saltysalt", iterations, 16, "sha1"),
    v11: pbkdf2Sync(password, "saltysalt", iterations, 32, "sha1")
  };
}

export function decryptMacCookie(
  encryptedHex: string,
  keys: BraveKeys,
  metaVersion = 0
): string {
  if (!encryptedHex) return "";
  const encrypted = Buffer.from(encryptedHex, "hex");
  if (encrypted.length === 0) return "";
  const prefix = encrypted.slice(0, 3).toString();
  const isPrintableAscii = (value: string) => {
    if (!value) return false;
    for (let i = 0; i < value.length; i += 1) {
      const code = value.charCodeAt(i);
      if (code < 0x20 || code > 0x7e) return false;
    }
    return true;
  };
  if (prefix === "v11") {
    const data = encrypted.slice(3);
    if (data.length < 12 + 16) return "";
    const iv = data.subarray(0, 12);
    const tag = data.subarray(data.length - 16);
    const ciphertext = data.subarray(12, data.length - 16);
    try {
      const decipher = createDecipheriv("aes-256-gcm", keys.v11, iv);
      decipher.setAuthTag(tag);
      const decoded = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      return decoded.toString("utf8");
    } catch {
      return "";
    }
  }

  const data = prefix === "v10" ? encrypted.slice(3) : encrypted;
  // Some builds use AES-256-GCM even with v10 prefix.
  if (prefix === "v10" && data.length >= 12 + 16) {
    const iv = data.subarray(0, 12);
    const tag = data.subarray(data.length - 16);
    const ciphertext = data.subarray(12, data.length - 16);
    try {
      const decipher = createDecipheriv("aes-256-gcm", keys.v11, iv);
      decipher.setAuthTag(tag);
      let decoded = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
      if (metaVersion >= 24 && decoded.length > 32) {
        decoded = decoded.subarray(32);
      }
      const text = decoded.toString("utf8");
      if (isPrintableAscii(text)) return text;
    } catch {
      // fall through to CBC
    }
  }
  const iv = Buffer.alloc(16, " ");
  const tryCbc = (key: Buffer) => {
    const decipher = createDecipheriv("aes-128-cbc", key, iv);
    decipher.setAutoPadding(false);
    let decoded = Buffer.concat([decipher.update(data), decipher.final()]);
    if (decoded.length === 0) return "";
    const padding = decoded[decoded.length - 1];
    if (padding === undefined) return "";
    const unpadded =
      padding > 0 && padding <= 16 ? decoded.slice(0, decoded.length - padding) : decoded;
    let out = unpadded;
    if (metaVersion >= 24 && out.length > 32) {
      out = out.subarray(32);
    }
    return out.toString("utf8");
  };

  let decoded = tryCbc(keys.v10);
  if (isPrintableAscii(decoded)) return decoded;

  // Some builds may use AES-256-CBC with 32-byte key.
  try {
    const decipher = createDecipheriv("aes-256-cbc", keys.v11, iv);
    decipher.setAutoPadding(false);
    let decoded256 = Buffer.concat([decipher.update(data), decipher.final()]);
    const padding = decoded256[decoded256.length - 1];
    if (padding === undefined) return decoded;
    const unpadded =
      padding > 0 && padding <= 16
        ? decoded256.slice(0, decoded256.length - padding)
        : decoded256;
    let out = unpadded;
    if (metaVersion >= 24 && out.length > 32) {
      out = out.subarray(32);
    }
    const text = out.toString("utf8");
    if (isPrintableAscii(text)) return text;
  } catch {
    // ignore
  }

  return decoded;
}

export function isPreferredHost(newHost: string, existingHost: string): boolean {
  const newIsYouTube = newHost.includes("youtube.com");
  const existingIsYouTube = existingHost.includes("youtube.com");
  if (newIsYouTube && !existingIsYouTube) return true;
  if (!newIsYouTube && existingIsYouTube) return false;
  return newHost.length > existingHost.length;
}

export type SqliteCookieStats = {
  header: string;
  skipped: number;
  total: number;
  decrypted: number;
  v10: number;
  v11: number;
  plain: number;
  skipped_non_ascii: number;
};

export function parseSqliteCookies(
  output: string,
  keys: BraveKeys,
  metaVersion = 0
): SqliteCookieStats {
  const separator = "\u001f";
  const jar = new Map<string, { value: string; host: string }>();
  let skipped = 0;
  let total = 0;
  let decrypted = 0;
  let v10 = 0;
  let v11 = 0;
  let plain = 0;
  let skippedNonAscii = 0;

  const lines = output.split(/\r?\n/).filter(Boolean);
  for (const line of lines) {
    const [hostKey, name, valueRaw, encryptedHex] = line.split(separator);
    if (!hostKey || !name) continue;
    total += 1;
    const value = valueRaw && valueRaw !== "NULL" ? valueRaw : "";
    if (value) plain += 1;
    if (encryptedHex) {
      const prefix = encryptedHex.slice(0, 6);
      if (prefix === "763130") v10 += 1; // "v10" in hex
      if (prefix === "763131") v11 += 1; // "v11" in hex
    }
    const decryptedValue =
      value || (!encryptedHex ? "" : decryptMacCookie(encryptedHex, keys, metaVersion));
    if (!decryptedValue) continue;
    if (!value) decrypted += 1;
    const existing = jar.get(name);
    if (!existing || isPreferredHost(hostKey, existing.host)) {
      jar.set(name, { value: decryptedValue, host: hostKey });
    }
  }

  const allowlist =
    COOKIE_ALLOWLIST?.split(",").map((name) => name.trim()).filter(Boolean) ??
    DEFAULT_COOKIE_ALLOWLIST;
  const allowset = allowlist.length > 0 ? new Set(allowlist) : undefined;

  const flatJar = new Map<string, string>();
  for (const [name, entry] of jar.entries()) {
    if (!isValidCookieHeader(`${name}=${entry.value}`)) {
      skippedNonAscii += 1;
      continue;
    }
    flatJar.set(name, entry.value);
  }

  let header = buildCookieHeader(flatJar, allowset);
  if (Buffer.byteLength(header, "utf8") > MAX_COOKIE_HEADER_BYTES) {
    const fallbackAllowset = new Set(DEFAULT_COOKIE_ALLOWLIST);
    header = buildCookieHeader(flatJar, fallbackAllowset);
  }

  return {
    header,
    skipped,
    total,
    decrypted,
    v10,
    v11,
    plain,
    skipped_non_ascii: skippedNonAscii
  };
}
