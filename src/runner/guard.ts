import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { isIP } from "node:net";

export class UnsafeTargetError extends Error {}

const LOCAL_NAMES = new Set(["localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0", "host.docker.internal", "kong"]);

function isPrivateIp(host: string): boolean {
  if (isIP(host) !== 4) return false;
  const [a, b] = host.split(".").map(Number) as [number, number];
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

export function isLocalHost(host: string): boolean {
  const h = host.toLowerCase();
  return LOCAL_NAMES.has(h) || h.endsWith(".localhost") || isPrivateIp(h);
}

/**
 * accessproof creates users and rows and tries to change/delete data, so it must
 * never touch a real deployment. Local targets are always fine. A remote host is
 * allowed only if the caller typed its exact hostname into --allow-remote AND it
 * is not one of the project's production hosts.
 */
export function assertSafeTarget(
  urlStr: string,
  opts: { allowRemote?: string[]; productionHosts?: string[] } = {},
): URL {
  let url: URL;
  try {
    url = new URL(urlStr);
  } catch {
    throw new UnsafeTargetError(`"${urlStr}" is not a valid URL.`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new UnsafeTargetError("Only http(s) URLs are supported.");
  if (url.username || url.password) throw new UnsafeTargetError("Do not put credentials in the URL.");

  const host = url.hostname.toLowerCase();
  const prod = (opts.productionHosts ?? []).map((h) => h.toLowerCase());
  if (prod.includes(host)) {
    throw new UnsafeTargetError(
      `${host} is listed as a production host in your .env.production files. accessproof will not run against production.`,
    );
  }
  if (isLocalHost(host)) return url;

  const allowed = (opts.allowRemote ?? []).map((h) => h.toLowerCase());
  if (!allowed.includes(host)) {
    throw new UnsafeTargetError(
      `${host} is not a local address. accessproof creates test users and tries to modify and delete data, so it only runs against local ` +
        `Supabase (supabase start) or a throwaway staging project. If ${host} is a staging project you own, re-run with --allow-remote ${host}.`,
    );
  }
  return url;
}

function hostOf(value: string): string | undefined {
  try {
    return new URL(value.trim().replace(/^['"]|['"]$/g, "")).hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

/** Hostnames found in .env.production*, .env.prod* — never test against these. */
export async function loadProductionHosts(root: string): Promise<string[]> {
  const hosts = new Set<string>();
  for (const f of [".env.production", ".env.production.local", ".env.prod", ".env.prod.local"]) {
    let text: string;
    try {
      text = await readFile(join(root, f), "utf8");
    } catch {
      continue;
    }
    for (const line of text.split("\n")) {
      const m = /^\s*(?:export\s+)?[A-Z0-9_]*URL[A-Z0-9_]*\s*=\s*(.+?)\s*$/.exec(line);
      const h = m && hostOf(m[1]!);
      if (h) hosts.add(h);
    }
  }
  return [...hosts];
}
