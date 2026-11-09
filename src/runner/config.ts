import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { assertSafeTarget, loadProductionHosts } from "./guard.js";

export interface Connection {
  url: string;
  anonKey: string;
  serviceKey: string;
}

export interface ConnectionFlags {
  url?: string;
  anonKey?: string;
  serviceKey?: string;
  allowRemote?: string[];
}

function parseDotenv(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
    if (m) out[m[1]!] = m[2]!.replace(/^['"]|['"]$/g, "");
  }
  return out;
}

async function readEnvFiles(root: string): Promise<Record<string, string>> {
  let merged: Record<string, string> = {};
  for (const f of [".env", ".env.local", ".env.development", ".env.development.local"]) {
    try {
      merged = { ...merged, ...parseDotenv(await readFile(join(root, f), "utf8")) };
    } catch {
      /* missing */
    }
  }
  return merged;
}

/**
 * Local Supabase defaults to http://127.0.0.1:54321. Keys come from flags, then the
 * environment, then local .env files (`supabase status -o env` prints them).
 * The safety guard runs before anything is returned.
 */
export async function resolveConnection(root: string, flags: ConnectionFlags = {}, env = process.env): Promise<Connection> {
  const file = await readEnvFiles(root);
  const pick = (...names: string[]) => names.map((n) => env[n] ?? file[n]).find((v) => v && v.length > 0);

  const url = flags.url ?? env.SUPABASE_URL ?? env.API_URL ?? "http://127.0.0.1:54321";
  const anonKey = flags.anonKey ?? pick("SUPABASE_ANON_KEY", "ANON_KEY", "NEXT_PUBLIC_SUPABASE_ANON_KEY");
  const serviceKey = flags.serviceKey ?? pick("SUPABASE_SERVICE_ROLE_KEY", "SERVICE_ROLE_KEY");

  // Unlocking a remote host is a human decision: via the --allow-remote flag or ACCESSPROOF_ALLOW_REMOTE in their shell.
  const fromEnv = (env.ACCESSPROOF_ALLOW_REMOTE ?? "").split(",").map((h) => h.trim()).filter(Boolean);
  assertSafeTarget(url, { allowRemote: [...(flags.allowRemote ?? []), ...fromEnv], productionHosts: await loadProductionHosts(root) });

  const missing = [!anonKey && "SUPABASE_ANON_KEY", !serviceKey && "SUPABASE_SERVICE_ROLE_KEY"].filter(Boolean);
  if (missing.length) {
    throw new Error(
      `Missing ${missing.join(" and ")}. Start local Supabase and export its keys:\n` +
        `  supabase start\n  eval "$(supabase status -o env | sed 's/^/export /')"\n  # then: SUPABASE_ANON_KEY=$ANON_KEY SUPABASE_SERVICE_ROLE_KEY=$SERVICE_ROLE_KEY accessproof test`,
    );
  }
  return { url, anonKey: anonKey!, serviceKey: serviceKey! };
}
