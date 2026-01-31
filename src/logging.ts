import { DEBUG_COOKIES } from "./config.ts";

export function debugLog(message: string) {
  if (DEBUG_COOKIES) {
    console.error(`[debug] ${message}`);
  }
}
