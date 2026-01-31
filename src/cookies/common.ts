import { createDecipheriv, pbkdf2Sync } from "node:crypto";
import {
  ALL_COOKIE_DOMAINS,
  COOKIE_ALLOWLIST,
  MAX_COOKIE_HEADER_BYTES
} from "../config.ts";

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
        "Utilise USE_SQLITE=1 ou USE_YTDLP=1."
    );
  }
}

export function normalizeCookies(value: unknown): string {
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

export function isPathLike(value: string): boolean {
  return value.includes("/") || value.includes("\\");
}

export function hasAuthCookies(cookieHeader: string): boolean {
  return /SAPISID=/.test(cookieHeader) || /__Secure-3PAPISID=/.test(cookieHeader);
}

export function mergeCookieHeaders(...headers: string[]): string {
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

function buildCookieHeader(
  jar: Map<string, string>,
  allowlist?: Set<string>
): string {
  const entries = Array.from(jar.entries()).filter(([name]) =>
    allowlist ? allowlist.has(name) : true
  );
  return entries.map(([name, value]) => `${name}=${value}`).join("; ");
}

export function parseNetscapeCookies(content: string, domains: string[]): string {
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

export function deriveBraveKey(password: Buffer | string): Buffer {
  return pbkdf2Sync(password, "saltysalt", 1003, 16, "sha1");
}

export function decryptMacCookie(encryptedHex: string, key: Buffer): string {
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

export function isPreferredHost(newHost: string, existingHost: string): boolean {
  const newIsYouTube = newHost.includes("youtube.com");
  const existingIsYouTube = existingHost.includes("youtube.com");
  if (newIsYouTube && !existingIsYouTube) return true;
  if (!newIsYouTube && existingIsYouTube) return false;
  return newHost.length > existingHost.length;
}

export function parseSqliteCookies(
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
