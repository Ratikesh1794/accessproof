import { readdir, readFile, stat } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import type { Finding } from "../findings.js";

export interface RouteInfo {
  file: string;
  /** URL path derived from the file location, e.g. /api/orders/[id] */
  route: string;
  methods: string[];
  tables: string[];
  usesServiceRole: boolean;
  checksAuth: boolean;
  usesParams: boolean;
  scopesToUser: boolean;
}

const SKIP_DIRS = new Set(["node_modules", ".next", "dist", "build", ".git", ".vercel", "coverage", ".turbo", ".accessproof"]);
const CODE_EXT = /\.(?:[cm]?[jt]sx?)$/;

async function walk(dir: string, out: string[] = []): Promise<string[]> {
  let entries;
  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    if (SKIP_DIRS.has(e.name)) continue;
    const full = join(dir, e.name);
    if (e.isDirectory()) await walk(full, out);
    else if (e.isFile()) out.push(full);
  }
  return out;
}

const AUTH_CHECK =
  /auth\.getUser\(|auth\.getSession\(|getServerSession\(|\bauth\(\)|currentUser\(|requireAuth|withAuth|getUser\(\)|verifyJwt|jwt\.verify|clerkClient/;
const SERVICE_ROLE = /SERVICE_ROLE|supabaseAdmin|createAdminClient|service_role/i;
const USER_SCOPE = /user\??\.id|session\??\.user|auth\.uid\(|\.eq\(\s*['"`](?:user_id|owner_id|author_id|created_by)['"`]/;

function routeFromFile(rel: string): string | null {
  const p = rel.split(sep).join("/");
  let m = /(?:^|\/)app\/(.*)\/route\.[cm]?[jt]sx?$/.exec(p);
  if (m) return "/" + m[1]!.replace(/\([^)]*\)\/?/g, "");
  m = /(?:^|\/)pages\/(api\/.*)\.[cm]?[jt]sx?$/.exec(p);
  if (m) return "/" + m[1]!.replace(/\/index$/, "");
  return null;
}

export function analyseRoute(rel: string, src: string): RouteInfo | null {
  const route = routeFromFile(rel);
  const isAction = /^\s*['"]use server['"]/m.test(src);
  if (!route && !isAction) return null;

  const methods = new Set<string>();
  for (const m of src.matchAll(/export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\b/g)) methods.add(m[1]!);
  for (const m of src.matchAll(/export\s+const\s+(GET|POST|PUT|PATCH|DELETE)\b/g)) methods.add(m[1]!);
  if (route?.startsWith("/api") && methods.size === 0 && /export\s+default/.test(src)) methods.add("ANY");

  const tables = [...new Set([...src.matchAll(/\.from\(\s*['"`](\w+)['"`]\s*\)/g)].map((m) => m[1]!))];

  return {
    file: rel,
    route: route ?? `(server action) ${rel}`,
    methods: [...methods],
    tables,
    usesServiceRole: SERVICE_ROLE.test(src),
    checksAuth: AUTH_CHECK.test(src),
    usesParams: /params\.\w+|searchParams\.get\(|req\.query|await\s+params|\{\s*params\s*\}/.test(src),
    scopesToUser: USER_SCOPE.test(src),
  };
}

export function routeFindings(routes: RouteInfo[]): Finding[] {
  const out: Finding[] = [];
  for (const r of routes) {
    if (r.tables.length === 0) continue;
    const where = `${r.methods.join("/") || "handler"} ${r.route}`;
    if (r.usesServiceRole && !r.checksAuth) {
      out.push({
        id: "route-service-role-no-auth",
        severity: "high",
        title: `${where} uses the service_role key without checking who is calling`,
        detail:
          "The service_role key bypasses all Row Level Security. A route that uses it and never identifies the caller lets anyone read or change " +
          `${r.tables.join(", ")} by calling the URL.`,
        file: r.file,
        resource: r.tables[0],
        fix: `In ${r.file}, identify the caller first (e.g. supabase.auth.getUser()), reject with 401 if missing, and filter queries by that user's id. Prefer the anon/user client so RLS applies.`,
      });
    } else if (r.usesParams && !r.checksAuth && !r.usesServiceRole) {
      out.push({
        id: "route-no-auth-check",
        severity: "medium",
        title: `${where} reads ${r.tables.join(", ")} by id without an auth check`,
        detail: "No sign-in check was found. If RLS is missing or too loose on these tables, this is an IDOR (anyone can fetch anyone's row by changing the id).",
        file: r.file,
        resource: r.tables[0],
        fix: `In ${r.file}, require a signed-in user and make sure RLS limits ${r.tables.join(", ")} to the owner.`,
      });
    }
    if (r.usesParams && r.checksAuth && !r.scopesToUser && r.usesServiceRole) {
      out.push({
        id: "route-possible-idor",
        severity: "high",
        title: `${where} checks sign-in but never ties the row to the caller`,
        detail: "It uses the service_role key and a URL parameter, but nothing compares the row owner to the signed-in user. Any signed-in user can pass another user's id.",
        file: r.file,
        resource: r.tables[0],
        fix: `In ${r.file}, add .eq("user_id", user.id) (or equivalent) to the query, or switch to the user-scoped client.`,
      });
    }
  }
  return out;
}

// ------------------------------------------------------------------ secrets

const JWT = /eyJ[A-Za-z0-9_-]{10,}\.(eyJ[A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]{10,}/g;

function jwtRole(payloadB64: string): string | undefined {
  try {
    const json = Buffer.from(payloadB64.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    return (JSON.parse(json) as { role?: string }).role;
  } catch {
    return undefined;
  }
}

export function secretFindings(rel: string, src: string): Finding[] {
  const out: Finding[] = [];
  const lines = src.split("\n");
  lines.forEach((text, i) => {
    const line = i + 1;
    if (/NEXT_PUBLIC_[A-Z0-9_]*(SERVICE_ROLE|SECRET)[A-Z0-9_]*/.test(text)) {
      out.push({
        id: "public-env-secret",
        severity: "critical",
        title: "A secret is exposed through a NEXT_PUBLIC_ variable",
        detail: "Anything prefixed NEXT_PUBLIC_ is bundled into the browser. A service_role or secret key there gives every visitor full database access.",
        file: rel,
        line,
        fix: "Rename the variable without NEXT_PUBLIC_, use it only in server code, and rotate the key in the Supabase dashboard.",
      });
    }
    for (const m of text.matchAll(JWT)) {
      if (jwtRole(m[1]!) === "service_role") {
        out.push({
          id: "service-role-jwt",
          severity: "critical",
          title: "A service_role key is committed in source",
          detail: "This JWT has role=service_role and bypasses Row Level Security.",
          file: rel,
          line,
          fix: "Remove it from source, load it from a server-only environment variable, and rotate the key in Supabase.",
        });
      }
    }
    if (/\bsk_live_[A-Za-z0-9]{16,}/.test(text)) {
      out.push({
        id: "stripe-live-key",
        severity: "critical",
        title: "A live Stripe secret key is committed",
        detail: "sk_live_ keys can move money.",
        file: rel,
        line,
        fix: "Remove it, rotate it in Stripe, and load it from a server-only environment variable.",
      });
    }
  });
  return out;
}

/** Scans an app directory for routes, server actions and leaked secrets. */
export async function scanCode(root: string): Promise<{ routes: RouteInfo[]; findings: Finding[]; usesNextPublicSupabaseOnly: boolean }> {
  const files = await walk(root);
  const routes: RouteInfo[] = [];
  const findings: Finding[] = [];

  for (const file of files) {
    const rel = relative(root, file);
    const base = rel.split(sep).pop() ?? "";
    const isEnv = /^\.env(\..+)?$/.test(base) && !/\.(example|sample|template)$/.test(base);
    const isCode = CODE_EXT.test(base);
    if (!isCode && !isEnv) continue;
    try {
      if ((await stat(file)).size > 400_000) continue;
      const src = await readFile(file, "utf8");
      if (isCode) {
        const info = analyseRoute(rel, src);
        if (info) routes.push(info);
        findings.push(...secretFindings(rel, src));
      }
      if (isEnv) findings.push(...(await envFindings(root, rel, src)));
    } catch {
      /* skip unreadable */
    }
  }
  findings.push(...routeFindings(routes));
  return { routes, findings, usesNextPublicSupabaseOnly: true };
}

async function envFindings(root: string, rel: string, src: string): Promise<Finding[]> {
  const out: Finding[] = [];
  let ignore = "";
  try {
    ignore = await readFile(join(root, ".gitignore"), "utf8");
  } catch {
    /* none */
  }
  const ignored = ignore.split("\n").some((l) => {
    const t = l.trim();
    return t === ".env" || t === ".env*" || t === ".env.*" || t === rel || t === ".env.local" && rel === ".env.local";
  });
  const hasSecret = /(SERVICE_ROLE|SECRET|PRIVATE|API_KEY|PASSWORD)[A-Z_]*\s*=\s*\S{8,}/.test(src);
  if (hasSecret && !ignored) {
    out.push({
      id: "env-not-ignored",
      severity: "high",
      title: `${rel} contains secrets and is not in .gitignore`,
      detail: "If this file is committed or deployed with the source, its secrets are public.",
      file: rel,
      fix: `Add ${rel} to .gitignore, remove it from git history if it was committed, and rotate any key it contained.`,
    });
  }
  return out;
}
