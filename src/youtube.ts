import { Innertube, Mixins, YTNodes } from "youtubei.js";
import { DEBUG_COOKIES, WATCH_LATER_LIMIT, MAX_PLAYLIST_PAGES, ALL_PLAYLISTS } from "./config.ts";
import { debugLog } from "./logging.ts";

const { Feed } = Mixins;

export async function collectPlaylists(feed: any): Promise<any[]> {
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

export function getPlaylistTitle(item: any): string {
  if (item?.title?.toString) {
    return item.title.toString();
  }
  if (item?.metadata?.title?.toString) {
    return item.metadata.title.toString();
  }
  return "Sans titre";
}

export function getPlaylistId(item: any): string | null {
  if (typeof item?.id === "string" && item.id) {
    return item.id;
  }
  if (typeof item?.content_id === "string" && item.content_id) {
    return item.content_id;
  }
  return null;
}

export function getPlaylistCount(item: any): string | null {
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

export async function listWatchLater(yt: Innertube) {
  console.log("Recuperation de Watch later...");
  const playlist = await yt.getPlaylist("WL");
  const items: any[] = [];
  let current = playlist;
  while (current) {
    if (Array.isArray(current.videos)) {
      items.push(...current.videos);
    }
    if (!current.has_continuation || items.length >= WATCH_LATER_LIMIT) {
      break;
    }
    current = await current.getContinuation();
  }

  const limited = items.slice(0, WATCH_LATER_LIMIT);
  if (limited.length === 0) {
    console.log("Watch later vide.");
    return;
  }

  console.log(`Watch later (${limited.length}) :`);
  limited.forEach((video: any, index: number) => {
    const title = video?.title?.toString?.() ?? "Sans titre";
    const id = video?.id ?? video?.video_id ?? "";
    const duration = video?.duration?.text ?? "";
    const parts = [`${index + 1}. ${title}`];
    if (duration) parts.push(`(${duration})`);
    if (id) parts.push(`- ${id}`);
    console.log(parts.join(" "));
  });
}

export function getAccountIds(account: any): { page_id?: string } {
  const payload = account?.endpoint?.payload;
  const tokens = payload?.supportedTokens;
  if (Array.isArray(tokens)) {
    for (const token of tokens) {
      const pageId = token?.pageIdToken?.pageId ?? token?.pageIdToken?.pageId?.toString?.();
      if (typeof pageId === "string" && pageId) {
        return { page_id: pageId };
      }
      const gaiaId =
        token?.accountStateToken?.obfuscatedGaiaId ??
        token?.accountStateToken?.obfuscatedGaiaId?.toString?.();
      if (typeof gaiaId === "string" && gaiaId) {
        return { page_id: gaiaId };
      }
      const datasync = token?.datasyncIdToken?.datasyncIdToken;
      if (typeof datasync === "string" && datasync) {
        const pageFromDatasync = datasync.split("||")[0];
        if (pageFromDatasync) {
          return { page_id: pageFromDatasync };
        }
      }
    }
  }

  return {};
}

export async function getPlaylistsFromLibrary(yt: any): Promise<any[]> {
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
