import { cp, mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

export const DEMO = resolve(import.meta.dirname, "../../demo/vulnerable-app");

/** A throwaway copy of the vulnerable demo, so tests can write into it. */
export async function demoCopy(opts: { withFix?: boolean } = {}): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "ap-demo-"));
  await cp(DEMO, dir, { recursive: true });
  if (opts.withFix) await cp(join(DEMO, "supabase/fixes/0002_fix_access.sql"), join(dir, "supabase/migrations/0002_fix_access.sql"));
  return dir;
}
