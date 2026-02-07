import { Innertube, Mixins, YTNodes } from "youtubei.js";
import {
  DEBUG_COOKIES,
  WATCH_LATER_LIMIT,
  WATCH_LATER_DELETE_LIMIT,
  MAX_PLAYLIST_PAGES,
  ALL_PLAYLISTS,
  USE_LIBRARY_PLAYLISTS
} from "./config.ts";
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

export type WatchLaterEntry = {
  title: string;
  id: string;
  duration?: string;
};

export async function getWatchLaterItems(
  yt: Innertube,
  limit = WATCH_LATER_LIMIT
): Promise<WatchLaterEntry[]> {
  console.log("Recuperation de Watch later...");
  const playlist = await yt.getPlaylist("WL");
  const items: any[] = [];
  let current = playlist;
  while (current) {
    if (Array.isArray(current.videos)) {
      items.push(...current.videos);
    }
    if (!current.has_continuation || items.length >= limit) {
      break;
    }
    current = await current.getContinuation();
  }

  const limited = items.slice(0, limit);
  return limited.map((video: any) => ({
    title: video?.title?.toString?.() ?? "Sans titre",
    id: video?.id ?? video?.video_id ?? "",
    duration: video?.duration?.text ?? "",
    author_name: video?.author?.name ?? "",
    author_id: video?.author?.id ?? null,
    thumbnail: video?.thumbnails?.[0]?.url ?? null,
    video_info: video?.video_info?.text ?? "",
  }));
}

async function getWatchLaterSetVideoIds(
  yt: Innertube,
  limit = WATCH_LATER_DELETE_LIMIT
): Promise<string[]> {
  const playlist = await yt.getPlaylist("WL");
  const setIds: string[] = [];
  let current = playlist;
  while (current) {
    if (Array.isArray(current.videos)) {
      for (const video of current.videos as any[]) {
        const setId =
          (video as { set_video_id?: string; setVideoId?: string })?.set_video_id ??
          (video as { set_video_id?: string; setVideoId?: string })?.setVideoId ??
          null;
        if (typeof setId === "string" && setId) setIds.push(setId);
      }
    }
    if (!current.has_continuation || setIds.length >= limit) {
      break;
    }
    current = await current.getContinuation();
  }
  return setIds.slice(0, limit);
}

export async function clearWatchLater(
  yt: Innertube,
  limit = WATCH_LATER_DELETE_LIMIT
) {
  console.log("Suppression Watch later...");
  const setIds = await getWatchLaterSetVideoIds(yt, limit);
  if (setIds.length === 0) {
    console.log("Watch later vide.");
    return;
  }

  const chunkSize = 50;
  for (let i = 0; i < setIds.length; i += chunkSize) {
    const chunk = setIds.slice(i, i + chunkSize);
    await yt.playlist.removeVideos("WL", chunk, true);
  }
  console.log(`Watch later supprime (${setIds.length} videos).`);
}

export async function listWatchLater(yt: Innertube) {
  const entries = await getWatchLaterItems(yt);
  if (entries.length === 0) {
    console.log("Watch later vide.");
    return;
  }

  console.log(`Watch later (${entries.length}) :`);
  entries.forEach((video, index) => {
    const parts = [`${index + 1}. ${video.title}`];
    if (video.duration) parts.push(`(${video.duration})`);
    if (video.id) parts.push(`- ${video.id}`);
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

export type EnsurePlaylistResult = {
  id?: string;
  created: boolean;
  title: string;
};

function normalizeTitle(value: string): string {
  return value.trim().toLowerCase();
}

function findPlaylistByTitle(playlists: any[], title: string): any | undefined {
  const target = normalizeTitle(title);
  return playlists.find((playlist) => normalizeTitle(getPlaylistTitle(playlist)) === target);
}

export async function getOrCreatePlaylist(
  yt: any,
  title: string
): Promise<EnsurePlaylistResult> {
  const trimmed = title.trim();
  if (!trimmed) {
    throw new Error("Titre de playlist vide.");
  }

  const feed = await yt.getPlaylists();
  let playlists = await collectPlaylists(feed);
  if (USE_LIBRARY_PLAYLISTS || playlists.length <= 2) {
    try {
      const libraryPlaylists = await getPlaylistsFromLibrary(yt);
      if (libraryPlaylists.length > playlists.length) {
        playlists = libraryPlaylists;
      }
    } catch {
      // ignore library errors
    }
  }

  const existing = findPlaylistByTitle(playlists, trimmed);
  if (existing) {
    return { id: getPlaylistId(existing) ?? undefined, created: false, title: trimmed };
  }

  const response = await yt.playlist.create(trimmed, []);
  const createdId =
    response?.playlist_id ??
    response?.playlistId ??
    response?.id ??
    response?.playlist?.id ??
    response?.playlist?.playlist_id;
  if (typeof createdId === "string" && createdId) {
    return { id: createdId, created: true, title: trimmed };
  }

  // Fallback: refetch and match by title
  const refreshFeed = await yt.getPlaylists();
  const refreshed = await collectPlaylists(refreshFeed);
  const created = findPlaylistByTitle(refreshed, trimmed);
  return { id: getPlaylistId(created) ?? undefined, created: true, title: trimmed };
}
