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
  getPlaylistCount,
  getPlaylistId,
  getPlaylistTitle,
  getPlaylistsFromLibrary
} from "./youtube.ts";

async function initSession() {
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

  return yt;
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

async function selectAccount(yt: Innertube, accounts: any[]) {
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
  const yt = await initSession();
  const accounts = await listAccounts(yt);
  await selectAccount(yt, accounts);
  const playlists = await fetchPlaylists(yt);
  printPlaylists(playlists);

  // yt.playlist.create("My Playlist", ["QnjJMJhW-gw", "sdWPiBrsCVo"]);

  // if (LIST_WATCH_LATER) {
  //   await listWatchLater(yt);
  // }
}
