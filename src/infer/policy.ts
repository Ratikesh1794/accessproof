import type { Level, Op } from "../spec/schema.js";
import { OPS } from "../spec/schema.js";
import type { Command, ParsedSchema, PolicyDef, TableDef } from "./sql.js";

/** What a single USING / WITH CHECK expression grants. */
export interface Effect {
  level: Level | "unknown";
  /** Column compared with auth.uid() when level is "own". */
  ownerColumn?: string;
  /** The expression only holds for signed-in users (anon excluded). */
  requiresAuth: boolean;
  /** The expression is gated on an admin check. */
  admin: boolean;
  /** Admin check could be turned into a seed recipe. */
  adminSeed?: { table?: string; set?: Record<string, unknown>; app_metadata?: Record<string, unknown> };
  /** Expression is "owner OR admin": grants own to users and all to admins. */
  alsoAdmin?: boolean;
  /** Matched a bucket id, for storage.objects policies. */
  bucket?: string;
  /** Storage folder check: first path segment equals auth.uid(). */
  folderOwned?: boolean;
}

function clean(expr: string): string {
  return expr
    .toLowerCase()
    .replace(/\s+/g, " ")
    .replace(/::\s*(text|uuid|varchar|bigint|int|integer)\b/g, "")
    .replace(/\bpublic\./g, "")
    .replace(/\(\s*select\s+auth\.uid\(\)\s*(?:as\s+\w+\s*)?\)/g, "auth.uid()")
    .replace(/\(\s*select\s+auth\.role\(\)\s*(?:as\s+\w+\s*)?\)/g, "auth.role()")
    .trim();
}

export function classifyExpr(expr: string | undefined): Effect {
  const base: Effect = { level: "unknown", requiresAuth: false, admin: false };
  if (expr === undefined) return { ...base, level: "none" };
  const e = clean(expr);

  const bucket = /bucket_id\s*=\s*'([^']+)'/.exec(e)?.[1];
  if (bucket) base.bucket = bucket;
  if (/storage\.foldername\(\s*name\s*\)\s*\)?\s*\[\s*1\s*\]\s*=\s*auth\.uid\(\)/.test(e) || /auth\.uid\(\)\s*=\s*\(?\s*storage\.foldername/.test(e)) {
    base.folderOwned = true;
  }

  // Owner comparison (computed first: "owner OR admin" must keep the owner part).
  const own1 = /auth\.uid\(\)\s*=\s*"?(\w+)"?(?!\s*\()/.exec(e);
  const own2 = /"?(\w+)"?\s*=\s*auth\.uid\(\)/.exec(e);
  const ownerColumn = own2?.[1] ?? own1?.[1];
  const hasOr = /\sor\s/.test(e);

  // Admin gates.
  const adminJwt = /auth\.jwt\(\)\s*(?:->\s*'(\w+)'\s*)?->>\s*'(\w+)'\s*=\s*'admin'/.exec(e);
  const adminFn = /\b(?:is_admin|has_role|is_super_admin|is_superadmin)\s*\(/.test(e);
  const adminRow = /from\s+(\w+)\s+where[\s\S]*?(?:\b\w+\.)?\b(\w+)\s*=\s*'admin'/.exec(e);
  if (adminJwt || adminFn || adminRow || /'admin'/.test(e)) {
    let adminSeed: Effect["adminSeed"];
    if (adminJwt?.[1] === "app_metadata") adminSeed = { app_metadata: { [adminJwt[2]!]: "admin" } };
    else if (adminRow) adminSeed = { table: adminRow[1]!, set: { [adminRow[2]!]: "admin" } };
    if (ownerColumn && ownerColumn !== "auth" && hasOr) {
      return { ...base, level: "own", ownerColumn, requiresAuth: true, alsoAdmin: true, adminSeed };
    }
    return { ...base, level: "all", requiresAuth: true, admin: true, adminSeed };
  }

  if (e === "true" || e === "(true)") return { ...base, level: "all" };
  if (e === "false" || e === "(false)") return { ...base, level: "none" };

  if (ownerColumn && !hasOr && ownerColumn !== "auth") {
    return { ...base, level: "own", ownerColumn, requiresAuth: true };
  }
  if (base.folderOwned && !hasOr) return { ...base, level: "own", requiresAuth: true };

  if (/auth\.role\(\)\s*=\s*'authenticated'/.test(e) || /auth\.uid\(\)\s+is\s+not\s+null/.test(e)) {
    return hasOr ? base : { ...base, level: "all", requiresAuth: true };
  }
  if (/auth\.role\(\)\s*=\s*'anon'/.test(e)) return { ...base, level: "all" };

  // Only a bucket check (public read policies on storage.objects).
  if (bucket && /^\(?\s*bucket_id\s*=\s*'[^']+'\s*\)?$/.test(e)) return { ...base, level: "all" };

  return base;
}

export type RoleName = "anon" | "user" | "admin";

export interface PolicyEffectRow {
  policy: PolicyDef;
  op: Op;
  effect: Effect;
}

const opsOf = (c: Command): Op[] =>
  c === "all" ? [...OPS] : c === "select" ? ["read"] : [c as Op];

/** The expression that decides an operation: WITH CHECK for inserts, USING otherwise. */
function exprFor(p: PolicyDef, op: Op): string | undefined {
  if (op === "insert") return p.check ?? p.using;
  if (op === "update") return p.using ?? p.check;
  return p.using ?? p.check;
}

const rank: Record<Level, number> = { none: 0, own: 1, all: 2 };
const maxLevel = (a: Level, b: Level): Level => (rank[a] >= rank[b] ? a : b);

export interface Effective {
  /** role -> op -> level actually granted by RLS */
  access: Record<RoleName, Record<Op, Level>>;
  rows: PolicyEffectRow[];
  /** policies we could not interpret */
  unknown: PolicyEffectRow[];
  ownerColumns: Set<string>;
}

const blank = (): Record<Op, Level> => ({ read: "none", insert: "none", update: "none", delete: "none" });

export function effectiveForPolicies(policies: PolicyDef[], tableRls: boolean): Effective {
  const out: Effective = {
    access: { anon: blank(), user: blank(), admin: blank() },
    rows: [],
    unknown: [],
    ownerColumns: new Set(),
  };

  if (!tableRls) {
    // RLS off: PostgREST exposes every row to anyone with the anon key.
    for (const r of ["anon", "user"] as const) for (const op of OPS) out.access[r][op] = "all";
    return out;
  }

  for (const p of policies) {
    if (!p.permissive) continue; // restrictive policies only narrow; ignore for upper bound
    const applies = (role: "anon" | "authenticated") =>
      p.roles.includes("public") || p.roles.includes(role);
    const toAnon = applies("anon");
    const toAuth = applies("authenticated");
    if (!toAnon && !toAuth) continue;

    for (const op of opsOf(p.command)) {
      const effect = classifyExpr(exprFor(p, op));
      const row = { policy: p, op, effect };
      out.rows.push(row);
      if (effect.ownerColumn) out.ownerColumns.add(effect.ownerColumn);
      if (effect.level === "unknown") {
        out.unknown.push(row);
        continue;
      }
      const level = effect.level;
      if (effect.admin) {
        out.access.admin[op] = maxLevel(out.access.admin[op], level);
        continue;
      }
      if (effect.alsoAdmin) out.access.admin[op] = "all";
      if (toAnon && !effect.requiresAuth) out.access.anon[op] = maxLevel(out.access.anon[op], level);
      if (toAuth) out.access.user[op] = maxLevel(out.access.user[op], level);
    }
  }
  return out;
}

export function effectiveForTable(schema: ParsedSchema, table: TableDef): Effective {
  const policies = schema.policies.filter((p) => p.schema === table.schema && p.table === table.name);
  return effectiveForPolicies(policies, table.rls);
}

/** Effective access on a storage bucket from policies on storage.objects. */
export function effectiveForBucket(schema: ParsedSchema, bucketId: string): Effective & { folderOwned: boolean } {
  const policies = schema.policies.filter((p) => p.schema === "storage" && p.table === "objects");
  const scoped = policies.filter((p) => {
    const text = `${p.using ?? ""} ${p.check ?? ""}`;
    // A policy with no bucket_id check applies to every bucket.
    return text.includes(`'${bucketId}'`) || !/bucket_id/i.test(text);
  });
  const eff = effectiveForPolicies(scoped, true);
  const folderOwned = eff.rows.some((r) => r.effect.folderOwned);
  return { ...eff, folderOwned };
}
