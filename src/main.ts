import { Innertube, UniversalCache } from "youtubei.js";
import {
  ACCOUNT_INDEX,
  ACCOUNT_INDEX_AT_CREATE,
  DEBUG_COOKIES,
  ON_BEHALF_OF_USER,
  SHOW_ACCOUNT_ENDPOINTS,
  USE_LIBRARY_PLAYLISTS
} from "./config.ts";
import { debugLog } from "./logging.ts";
import { getBraveCookies } from "./cookies/brave.ts";
import {
  collectPlaylists,
  getAccountIds,
  getOrCreatePlaylist,
  getPlaylistCount,
  getPlaylistId,
  getPlaylistTitle,
  getPlaylistsFromLibrary,
  clearWatchLater,
  getWatchLaterItems,
  listWatchLater
} from "./youtube.ts";
import { confirm, input, select } from "@inquirer/prompts";

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

type SessionOverrides = {
  accountIndex?: number;
  onBehalfOfUser?: string;
};

async function getFromCache<T>(
    file: string,
    ttlMs: number,
    fetcher: () => Promise<T>
): Promise<T> {
    try {
        const f = Bun.file(file);
        const { v, e } = await f.json();
        if (e > Date.now()) return v as T;
    } catch {}

    const v = await fetcher();
    await mkdir(dirname(file), { recursive: true });
    await Bun.write(file, JSON.stringify({ v, e: Date.now() + ttlMs }));
    return v;
}

async function createSession(cookie: string, overrides: SessionOverrides = {}) {
  return await Innertube.create({
    cookie,
    cache: new UniversalCache(true),
    account_index: Number.isFinite(overrides.accountIndex)
      ? overrides.accountIndex
      : undefined,
    on_behalf_of_user: overrides.onBehalfOfUser ?? ON_BEHALF_OF_USER
  });
}

async function initSession() {
  debugLog("Demarrage");
  console.log("Lecture des cookies Brave...");
  const cookie = await getFromCache('storage/cookies.json', 3600 * 1000, getBraveCookies);
  if (!cookie) {
    throw new Error("Cookies vides.");
  }

  console.log("Initialisation Innertube...");
  debugLog("Creation session Innertube");
  const yt = await createSession(cookie);

  console.log(`Session connectee: ${yt.session.logged_in ? "oui" : "non"}`);
  if (!yt.session.logged_in) {
    console.log(
      "Si tu as plusieurs comptes, definis BRAVE_PROFILE (ex: \"Profile 1\")."
    );
  }

  return { yt, cookie };
}

async function listAccounts(yt: Innertube): Promise<any[]> {
  try {
    const accounts = await yt.account.getInfo(true);
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
    return accounts;
  } catch (err) {
    debugLog(
      `Account listing a echoue: ${err instanceof Error ? err.message : String(err ?? "")}`
    );
    return [];
  }
}

function getAccountPageIdByIndex(accounts: any[], index?: number): string | undefined {
  if (!Number.isFinite(index)) return undefined;
  const account = accounts[index!];
  if (!account) return undefined;
  return getAccountIds(account).page_id;
}

function renderAccountChoice(account: any, index: number): string {
  const name =
    account?.account_name?.toString?.() ??
    account?.title?.toString?.() ??
    "Sans nom";
  const byline = account?.account_byline?.toString?.() ?? "";
  const handle = account?.channel_handle?.toString?.() ?? "";
  const ids = getAccountIds(account);
  const parts = [`${index}. ${name}`];
  if (handle) parts.push(handle);
  if (byline && byline !== name) parts.push(byline);
  if (ids.page_id) parts.push(`page_id=${ids.page_id}`);
  return parts.join(" - ");
}

async function promptAccountIndex(accounts: any[]): Promise<number | undefined> {
  if (!process.stdin.isTTY || accounts.length === 0) return undefined;
  return await select({
    message: "Choisis un compte",
    choices: accounts.map((account: any, index: number) => ({
      name: renderAccountChoice(account, index),
      value: index
    }))
  });
}

type ActionChoice =
  | "playlists"
  | "watch_later"
  | "watch_later_dump"
  | "watch_later_clear"
  | "playlist_get_or_create";

async function promptAction(): Promise<ActionChoice> {
  if (!process.stdin.isTTY) return "watch_later_dump";
  return await select({
    message: "Choisis une action",
    choices: [
      { name: "Lister les playlists", value: "playlists" },
      { name: "Lister Watch later", value: "watch_later" },
      { name: "Dump Watch later (JSON)", value: "watch_later_dump" },
      { name: "Supprimer toutes les videos Watch later", value: "watch_later_clear" },
      { name: "Get or create playlist", value: "playlist_get_or_create" }
    ]
  });
}

async function promptDumpPath(): Promise<string> {
  if (!process.stdin.isTTY) return "storage/watch-later.json";
  return await input({
    message: "Fichier de sortie",
    default: "storage/watch-later.json"
  });
}

async function promptPlaylistTitle(): Promise<string> {
  if (!process.stdin.isTTY) return "New Playlist";
  return await input({
    message: "Titre de la playlist",
    default: "New Playlist"
  });
}

async function promptWatchLaterClearConfirm(): Promise<boolean> {
  if (!process.stdin.isTTY) return false;
  return await confirm({
    message: "Confirmer la suppression de toutes les videos Watch later ?",
    default: false
  });
}

async function promptImportWatchLater(): Promise<boolean> {
  if (!process.stdin.isTTY) return false;
  return await confirm({
    message: "Importer storage/watch-later.json dans cette playlist ?",
    default: false
  });
}

async function loadWatchLaterIdsFromFile(filePath: string): Promise<string[]> {
  const raw = await readFile(filePath, "utf8");
  const parsed = JSON.parse(raw);
  const ids: string[] = [];
  if (Array.isArray(parsed)) {
    for (const item of parsed) {
      if (typeof item === "string") {
        ids.push(item);
      } else if (item && typeof item === "object") {
        const id = (item as { id?: string }).id;
        if (id && typeof id === "string") ids.push(id);
      }
    }
  }
  return Array.from(new Set(ids.filter(Boolean)));
}

async function addVideosToPlaylist(
  yt: any,
  playlistId: string,
  videoIds: string[]
) {
  const chunkSize = 50;
  for (let i = 0; i < videoIds.length; i += chunkSize) {
    const chunk = videoIds.slice(i, i + chunkSize);
    await yt.playlist.addVideos(playlistId, chunk);
  }
}

async function selectAccount(
  yt: Innertube,
  accounts: any[],
  index?: number
) {
  if (
    Number.isFinite(index) &&
    accounts.length > 0 &&
    index! >= 0 &&
    index! < accounts.length
  ) {
    const account = accounts[index!];
    if (account?.endpoint?.call) {
      console.log(`Selection du compte: ${index}`);
      try {
        await account.endpoint.call(yt.actions, { parse: false });
      } catch (err) {
        debugLog(
          `Switch account a echoue: ${err instanceof Error ? err.message : String(err ?? "")}`
        );
      }
    }
  }
}

async function fetchPlaylists(yt: Innertube): Promise<any[]> {
  console.log("Recuperation des playlists...");
  if (DEBUG_COOKIES && (yt as any).actions?.session) {
    debugLog(
      `Account index actif: ${(yt as any).actions.session.account_index ?? "n/a"}`
    );
    debugLog(
      `On behalf of user: ${(yt as any).actions.session.context?.client?.on_behalf_of_user ?? "n/a"}`
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

  return playlists;
}

function printPlaylists(playlists: any[]) {
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

export async function main() {
  const { yt, cookie } = await initSession();
  const accounts = await listAccounts(yt);
  let selectedIndex: number | undefined = ACCOUNT_INDEX;
  if (!ON_BEHALF_OF_USER && !Number.isFinite(ACCOUNT_INDEX) && accounts.length > 1) {
    selectedIndex = await promptAccountIndex(accounts);
  }
  const targetPageId =
    ON_BEHALF_OF_USER ?? getAccountPageIdByIndex(accounts, selectedIndex);

  let activeYt = yt;
  if (targetPageId && targetPageId !== ON_BEHALF_OF_USER) {
    debugLog(`Recreation session avec on_behalf_of_user=${targetPageId}`);
    activeYt = await createSession(cookie, { onBehalfOfUser: targetPageId });
  } else if (
    ACCOUNT_INDEX_AT_CREATE &&
    Number.isFinite(selectedIndex) &&
    !ON_BEHALF_OF_USER
  ) {
    debugLog(`Recreation session avec account_index=${selectedIndex}`);
    activeYt = await createSession(cookie, { accountIndex: selectedIndex! });
  } else if (!ON_BEHALF_OF_USER) {
    await selectAccount(yt, accounts, selectedIndex);
  }

  const action = await promptAction();
  if (action === "playlists") {
    const playlists = await fetchPlaylists(activeYt);
    printPlaylists(playlists);
  } else if (action === "watch_later") {
    await listWatchLater(activeYt);
  } else if (action === "watch_later_dump") {
    const filePath = await promptDumpPath();
    const entries = await getWatchLaterItems(activeYt);
    await mkdir(dirname(filePath), { recursive: true });
    await writeFile(filePath, JSON.stringify(entries, null, 2), "utf8");
    console.log(`Watch later exporte: ${filePath} (${entries.length} items)`);
  } else if (action === "watch_later_clear") {
    const ok = await promptWatchLaterClearConfirm();
    if (ok) {
      await clearWatchLater(activeYt);
    } else {
      console.log("Suppression annulee.");
    }
  } else if (action === "playlist_get_or_create") {
    const title = await promptPlaylistTitle();
    const result = await getOrCreatePlaylist(activeYt, title);
    const status = result.created ? "cree" : "existe";
    const idSuffix = result.id ? ` (${result.id})` : "";
    console.log(`Playlist ${status}: ${result.title}${idSuffix}`);
    if (result.id) {
      const shouldImport = await promptImportWatchLater();
      if (shouldImport) {
        try {
          const ids = await loadWatchLaterIdsFromFile("storage/watch-later.json");
          if (ids.length === 0) {
            console.log("Aucune video a importer.");
          } else {
            await addVideosToPlaylist(activeYt, result.id, ids);
            console.log(`Import termine: ${ids.length} videos ajoutees.`);
          }
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err ?? "");
          console.error(`[erreur] Import watch later: ${message}`);
        }
      }
    }
  }

  // activeYt.playlist.create("My Playlist", ["QnjJMJhW-gw", "sdWPiBrsCVo"]);
}
