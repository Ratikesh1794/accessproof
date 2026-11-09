import type { Finding, Severity } from "../findings.js";
import { AccessSpec, OPS, type Level, type Op, type Resource } from "../spec/schema.js";
import { effectiveForBucket, effectiveForTable, type Effective } from "./policy.js";
import type { ParsedSchema, TableDef } from "./sql.js";

export type Confidence = "high" | "medium" | "low";

export interface Draft {
  spec: AccessSpec;
  findings: Finding[];
  /** per-resource explanation shown in the report */
  explain: Record<string, { confidence: Confidence; reasons: string[] }>;
}

const OWNER_NAMES = ["user_id", "owner_id", "author_id", "created_by", "profile_id", "account_id", "member_id", "customer_id", "uid"];
const PUBLIC_NAME = /^(posts?|articles?|blogs?|products?|categories|category|tags?|pages?|comments?|reviews?|listings?|courses?|lessons?|events?|faqs?|announcements?|news|public_\w+|countries|plans?)$/;
const SENSITIVE_NAME = /^(orders?|payments?|invoices?|messages?|notes?|tasks?|todos?|settings?|subscriptions?|addresses|documents?|files?|chats?|conversations?|carts?|bookings?|transactions?|journals?|entries|drafts?|uploads?|api_keys?|tokens?|sessions?|notifications?|projects?|workspaces?)$/;
const PROFILE_NAME = /^(profiles?|users?|accounts?|members?)$/;

const rank: Record<Level, number> = { none: 0, own: 1, all: 2 };

const refsAuthUsers = (c: { references?: { schema: string; table: string } }) =>
  c.references?.schema === "auth" && c.references.table === "users";

function ownerOf(table: TableDef, eff: Effective): { column?: string; why?: string } {
  for (const c of eff.ownerColumns) {
    if (table.columns.some((x) => x.name === c)) return { column: c, why: `an existing policy compares auth.uid() with ${c}` };
  }
  const fk = table.columns.find((c) => refsAuthUsers(c) && !c.primaryKey);
  if (fk) return { column: fk.name, why: `${fk.name} references auth.users` };
  const byName = OWNER_NAMES.map((n) => table.columns.find((c) => c.name === n)).find(Boolean);
  if (byName) return { column: byName.name, why: `column ${byName.name} looks like an owner id` };
  const pk = table.columns.find((c) => c.primaryKey && refsAuthUsers(c));
  if (pk) return { column: pk.name, why: `primary key ${pk.name} references auth.users (one row per user)` };
  return {};
}

type Rules = Partial<Record<Op, Level>>;
const all4 = (level: Level): Rules => ({ read: level, insert: level, update: level, delete: level });

function intentForTable(table: TableDef, owner: string | undefined, why: string | undefined) {
  const n = table.name;
  const reasons: string[] = [];
  const isProfile = PROFILE_NAME.test(n) || (owner && table.columns.find((c) => c.name === owner)?.primaryKey);
  let anon: Rules = {};
  let user: Rules = {};
  let confidence: Confidence;

  if (isProfile && owner) {
    reasons.push(`${why}.`, "Profile-style table: assuming each user manages only their own row. Many apps show profiles publicly — change read to `all` if yours does.");
    user = { read: "own", insert: "own", update: "own" };
    confidence = "low";
  } else if (owner && PUBLIC_NAME.test(n)) {
    reasons.push(`${why}.`, `"${n}" sounds like public content: anyone may read, only the owner may change it.`);
    anon = { read: "all" };
    user = { read: "all", insert: "own", update: "own", delete: "own" };
    confidence = "medium";
  } else if (owner) {
    reasons.push(`${why}.`, SENSITIVE_NAME.test(n) ? `"${n}" is typically private per-user data.` : "Per-user rows: assuming each user sees and changes only their own.");
    user = all4("own");
    confidence = SENSITIVE_NAME.test(n) ? "high" : "medium";
  } else if (PUBLIC_NAME.test(n)) {
    reasons.push(`No owner column and "${n}" sounds like shared content: readable by everyone, writable by no ordinary user.`);
    anon = { read: "all" };
    user = { read: "all" };
    confidence = "medium";
  } else {
    reasons.push("No owner column and unclear purpose: assuming no direct access for ordinary users. Confirm.");
    confidence = "low";
  }
  return { anon, user, confidence, reasons };
}

const sev = (s: Severity, down: boolean): Severity => {
  if (!down) return s;
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  return order[Math.min(order.indexOf(s) + 1, order.length - 1)]!;
};

const levelOf = (rules: Rules | undefined, op: Op): Level => rules?.[op] ?? "none";

export function draftSpec(schema: ParsedSchema): Draft {
  const resources: Record<string, Resource> = {};
  const findings: Finding[] = [];
  const explain: Draft["explain"] = {};
  let adminSeed: { table?: string; set?: Record<string, unknown>; app_metadata?: Record<string, unknown> } | undefined;
  let adminSeen = false;

  const publicTables = [...schema.tables.values()].filter((t) => t.schema === "public");

  for (const table of publicTables) {
    const eff = effectiveForTable(schema, table);
    const { column: owner, why } = ownerOf(table, eff);
    const intent = intentForTable(table, owner, why);

    const rules: Record<string, Rules> = {};
    if (Object.keys(intent.anon).length) rules.anon = intent.anon;
    if (Object.keys(intent.user).length) rules.user = intent.user;

    // Admin policies already present tell us admins are expected to have access.
    const adminOps = OPS.filter((op) => eff.access.admin[op] === "all");
    if (adminOps.length) {
      adminSeen = true;
      rules.admin = Object.fromEntries(adminOps.map((op) => [op, "all" as Level]));
      adminSeed ??= eff.rows.find((r) => r.effect.adminSeed)?.effect.adminSeed;
      intent.reasons.push("An existing policy grants admins access, so an `admin` role is included.");
    }

    const matches = (["anon", "user"] as const).every((role) =>
      OPS.every((op) => levelOf(rules[role], op) === eff.access[role][op]),
    );
    if (table.rls && matches && schema.policies.some((p) => p.table === table.name)) {
      intent.reasons.push("Existing policies already match this.");
    }

    resources[table.name] = {
      kind: "table",
      ...(owner ? { owner } : {}),
      confirmed: false,
      notes: `[${intent.confidence} confidence] ${intent.reasons.join(" ")}`,
      rules,
    } as Resource;
    explain[table.name] = { confidence: intent.confidence, reasons: intent.reasons };

    // ---------------------------------------------------- static findings
    const down = intent.confidence === "low";
    const where = { file: table.file, line: table.line, resource: table.name };

    if (!table.rls) {
      findings.push({
        id: "rls-disabled",
        severity: sev("high", false),
        title: `Row Level Security is off on "${table.name}"`,
        detail:
          `Supabase exposes every public table over its REST API. With RLS off, anyone holding the public anon key can read${owner ? " every user's rows and" : ""} change this table` +
          " (unless you revoked grants on it).",
        ...where,
        fix: `Add a migration: ALTER TABLE public.${table.name} ENABLE ROW LEVEL SECURITY; then create policies that match access.yml.`,
      });
      continue;
    }

    for (const role of ["anon", "user"] as const) {
      const over = OPS.filter((op) => rank[eff.access[role][op]] > rank[levelOf(rules[role], op)]);
      if (over.length) {
        const writes = over.some((o) => o !== "read");
        const who = role === "anon" ? "anyone who is not signed in" : "any signed-in user";
        const base: Severity = role === "anon" ? (writes ? "critical" : "high") : writes ? "high" : "medium";
        findings.push({
          id: "policy-too-permissive",
          severity: sev(base, down),
          title: `"${table.name}" lets ${who} ${over.join("/")} more than expected`,
          detail: `Existing policies grant ${over.map((o) => `${o}: ${eff.access[role][o]}`).join(", ")}; the likely intent is ${over
            .map((o) => `${o}: ${levelOf(rules[role], o)}`)
            .join(", ")}.`,
          ...where,
          fix: `Tighten the ${over.join("/")} policies on ${table.name}${owner ? ` to compare auth.uid() with ${owner}` : ""}, in a new migration.`,
        });
      }
      const under = OPS.filter((op) => rank[eff.access[role][op]] < rank[levelOf(rules[role], op)]);
      if (under.length && intent.confidence !== "low") {
        findings.push({
          id: "policy-too-strict",
          severity: "low",
          title: `"${table.name}" may block ${role === "anon" ? "visitors" : "signed-in users"} from ${under.join("/")}`,
          detail: "No policy allows it. If the app works locally only because it uses the service_role key, it will fail (or silently return nothing) for real users.",
          ...where,
        });
      }
    }

    // Columns that grant privileges, writable by the row owner: classic privilege escalation.
    const privileged = table.columns.filter((c) => /^(role|roles|is_admin|is_superuser|is_staff|admin|plan|tier|credits|balance|is_premium|is_paid)$/.test(c.name));
    if (privileged.length && eff.access.user.update !== "none") {
      findings.push({
        id: "sensitive-column-writable",
        severity: sev("medium", false),
        title: `Users may be able to edit their own ${privileged.map((c) => c.name).join(", ")} on "${table.name}"`,
        detail:
          "RLS limits which rows a user can update, not which columns. If the app stores roles, plans or balances in this table, a user can send a PATCH setting role='admin' on their own row.",
        ...where,
        fix: `Move ${privileged.map((c) => c.name).join(", ")} to a table users cannot update, or block changes with a BEFORE UPDATE trigger / column-level privileges.`,
      });
    }

    for (const row of eff.unknown) {
      findings.push({
        id: "policy-unreadable",
        severity: "info",
        title: `Policy "${row.policy.name}" on "${table.name}" could not be analysed statically`,
        detail: `Expression: ${(row.policy.using ?? row.policy.check ?? "").slice(0, 160)}. The runtime test will check what it actually allows.`,
        file: row.policy.file,
        line: row.policy.line,
        resource: table.name,
      });
    }
  }

  // ------------------------------------------------------------- buckets
  for (const bucket of schema.buckets.values()) {
    const eff = effectiveForBucket(schema, bucket.id);
    const reasons: string[] = [];
    const rules: Record<string, Rules> = {};
    let confidence: Confidence = "medium";
    if (bucket.public) {
      rules.anon = { read: "all" };
      rules.user = { read: "all", insert: "own", update: "own", delete: "own" };
      reasons.push("Bucket is public: anyone may read objects; only the owner (first folder = user id) should write.");
    } else {
      rules.user = { read: "own", insert: "own", update: "own", delete: "own" };
      reasons.push("Bucket is private: each user should access only objects under their own `<user id>/` folder.");
    }
    const key = schema.tables.has(`public.${bucket.id}`) ? `${bucket.id}_bucket` : bucket.id;
    resources[key] = {
      kind: "bucket",
      owner_path: "{uid}/*",
      confirmed: false,
      notes: `[${confidence} confidence] ${reasons.join(" ")}`,
      rules,
    } as Resource;
    explain[key] = { confidence, reasons };

    const anonRead = bucket.public ? "all" : eff.access.anon.read;
    const effective: Record<"anon" | "user", Record<Op, Level>> = {
      anon: { ...eff.access.anon, read: anonRead as Level },
      user: eff.access.user,
    };
    for (const role of ["anon", "user"] as const) {
      const over = OPS.filter((op) => rank[effective[role][op]] > rank[levelOf(rules[role], op)]);
      if (over.length) {
        const writes = over.some((o) => o !== "read");
        findings.push({
          id: "bucket-too-permissive",
          severity: role === "anon" ? (writes ? "critical" : "high") : writes ? "high" : "medium",
          title: `Storage bucket "${bucket.id}" gives ${role === "anon" ? "anonymous visitors" : "any signed-in user"} more than expected (${over.join("/")})`,
          detail: `Policies on storage.objects allow ${over.map((o) => `${o}: ${effective[role][o]}`).join(", ")}.`,
          file: bucket.file,
          line: bucket.line,
          resource: key,
          fix: `Scope the storage.objects policies for "${bucket.id}" with (storage.foldername(name))[1] = auth.uid()::text.`,
        });
      }
    }
  }

  const roles: AccessSpec["roles"] = { anon: { description: "Not signed in" }, user: { description: "Any signed-in user" } };
  if (adminSeen) {
    roles.admin = {
      description: "Admin (inferred from existing policies)",
      ...(adminSeed ? { seed: adminSeed } : {}),
    };
  }

  const spec = AccessSpec.parse({
    version: 1,
    project: { framework: "nextjs", backend: "supabase" },
    roles,
    resources,
  });
  return { spec, findings, explain };
}
