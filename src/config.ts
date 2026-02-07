export const BRAVE_PROFILE = process.env.BRAVE_PROFILE ?? "Default";
export const BRAVE_COOKIES_PATH = process.env.BRAVE_COOKIES_PATH;
export const NODE_BINARY = process.env.NODE_BINARY ?? "node";
export const IS_BUN =
  typeof process !== "undefined" &&
  !!(process as { versions?: { bun?: string } }).versions?.bun;
export const DEBUG_COOKIES =
  process.env.DEBUG_COOKIES === "1" || process.env.DEBUG === "1";
export const SQLITE_TIMEOUT_MS = Number(process.env.SQLITE_TIMEOUT_MS ?? 15000);
export const KEYCHAIN_TIMEOUT_MS = Number(process.env.KEYCHAIN_TIMEOUT_MS ?? 15000);
export const MAX_PLAYLIST_PAGES = Number(process.env.MAX_PLAYLIST_PAGES ?? 3);
export const ALL_PLAYLISTS = process.env.ALL_PLAYLISTS === "1";
export const COOKIE_ALLOWLIST = process.env.COOKIE_ALLOWLIST;
export const MAX_COOKIE_HEADER_BYTES = Number(
  process.env.MAX_COOKIE_HEADER_BYTES ?? 8192
);
export const ACCOUNT_INDEX = process.env.ACCOUNT_INDEX
  ? Number(process.env.ACCOUNT_INDEX)
  : undefined;
export const ON_BEHALF_OF_USER = process.env.ON_BEHALF_OF_USER;
export const ACCOUNT_INDEX_AT_CREATE =
  process.env.ACCOUNT_INDEX_AT_CREATE === "1";
export const SHOW_ACCOUNT_ENDPOINTS = process.env.SHOW_ACCOUNT_ENDPOINTS === "1";
export const WATCH_LATER_LIMIT = Number(process.env.WATCH_LATER_LIMIT ?? 50);
export const WATCH_LATER_DELETE_LIMIT = Number(
  process.env.WATCH_LATER_DELETE_LIMIT ?? 500
);
export const LIST_WATCH_LATER = process.env.LIST_WATCH_LATER !== "0";
export const USE_LIBRARY_PLAYLISTS = process.env.USE_LIBRARY_PLAYLISTS === "1";
export const BRAVE_KEYCHAIN_SERVICE =
  process.env.BRAVE_KEYCHAIN_SERVICE ?? "Brave Safe Storage";
export const BRAVE_KEYCHAIN_SERVICE_ALT =
  process.env.BRAVE_KEYCHAIN_SERVICE_ALT ?? "Chrome Safe Storage";
export const BRAVE_KEYCHAIN_ACCOUNT = process.env.BRAVE_KEYCHAIN_ACCOUNT ?? "Brave";
export const BRAVE_KEYCHAIN_ACCOUNT_ALT =
  process.env.BRAVE_KEYCHAIN_ACCOUNT_ALT ?? "Brave Browser";
