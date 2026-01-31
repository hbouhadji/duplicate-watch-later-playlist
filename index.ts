import { main } from "./src/main.ts";

main().catch((err) => {
  const message = err instanceof Error ? err.message : String(err);
  console.error(`[erreur] ${message}`);
  process.exit(1);
});
