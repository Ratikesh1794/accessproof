import { readdir, readFile, stat } from "node:fs/promises";
import { join, relative } from "node:path";

/**
 * A deliberately small, forgiving SQL reader for Supabase migrations.
 * It understands just enough DDL to answer "which tables exist, is RLS on,
 * and what do the policies say?" — not full PostgreSQL.
 */

export type Command = "all" | "select" | "insert" | "update" | "delete";

export interface Column {
  name: string;
  type: string;
  notNull: boolean;
  hasDefault: boolean;
  primaryKey: boolean;
  references?: { schema: string; table: string; column: string };
}

export interface TableDef {
  schema: string;
  name: string;
  columns: Column[];
  rls: boolean;
  file: string;
  line: number;
}

export interface PolicyDef {
  name: string;
  schema: string;
  table: string;
  command: Command;
  roles: string[];
  permissive: boolean;
  using?: string;
  check?: string;
  file: string;
  line: number;
}

export interface BucketDef {
  id: string;
  public: boolean;
  file: string;
  line: number;
}

export interface ParsedSchema {
  tables: Map<string, TableDef>;
  policies: PolicyDef[];
  buckets: Map<string, BucketDef>;
  files: string[];
}

export const tableKey = (schema: string, name: string) => `${schema}.${name}`;

// ---------------------------------------------------------------- tokenising

export function splitStatements(sql: string): Array<{ text: string; line: number }> {
  const out: Array<{ text: string; line: number }> = [];
  let buf = "";
  let line = 1;
  let startLine = 1;
  let started = false;
  let i = 0;
  const n = sql.length;

  const add = (chunk: string) => {
    if (!started && chunk.trim()) {
      started = true;
      startLine = line;
    }
    buf += chunk;
  };
  const flush = () => {
    const t = buf.trim();
    if (t) out.push({ text: t, line: startLine });
    buf = "";
    started = false;
  };

  while (i < n) {
    const c = sql[i]!;
    const d = sql[i + 1];

    if (c === "-" && d === "-") {
      while (i < n && sql[i] !== "\n") i++;
      continue;
    }
    if (c === "/" && d === "*") {
      i += 2;
      while (i < n && !(sql[i] === "*" && sql[i + 1] === "/")) {
        if (sql[i] === "\n") line++;
        i++;
      }
      i += 2;
      buf += " ";
      continue;
    }
    if (c === "'" || c === '"') {
      let j = i + 1;
      while (j < n) {
        if (sql[j] === c) {
          if (sql[j + 1] === c) {
            j += 2;
            continue;
          }
          break;
        }
        j++;
      }
      const chunk = sql.slice(i, j + 1);
      add(chunk);
      line += (chunk.match(/\n/g) ?? []).length;
      i = j + 1;
      continue;
    }
    if (c === "$") {
      const tag = /^\$([A-Za-z_]\w*)?\$/.exec(sql.slice(i, i + 64));
      if (tag) {
        const end = sql.indexOf(tag[0], i + tag[0].length);
        const j = end === -1 ? n : end + tag[0].length;
        const chunk = sql.slice(i, j);
        add(chunk);
        line += (chunk.match(/\n/g) ?? []).length;
        i = j;
        continue;
      }
    }
    if (c === ";") {
      flush();
      i++;
      continue;
    }
    if (c === "\n") line++;
    add(c);
    i++;
  }
  flush();
  return out;
}

/** Index of the paren matching the one at `open`, ignoring quoted text. -1 if unbalanced. */
export function matchParen(s: string, open: number): number {
  let depth = 0;
  for (let i = open; i < s.length; i++) {
    const c = s[i]!;
    if (c === "'" || c === '"') {
      const q = c;
      i++;
      while (i < s.length && !(s[i] === q && s[i + 1] !== q)) {
        if (s[i] === q) i++;
        i++;
      }
      continue;
    }
    if (c === "(") depth++;
    if (c === ")") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

export function splitTopLevel(s: string, sep = ","): string[] {
  const parts: string[] = [];
  let depth = 0;
  let cur = "";
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (c === "'" || c === '"') {
      const q = c;
      cur += c;
      i++;
      while (i < s.length && !(s[i] === q && s[i + 1] !== q)) {
        if (s[i] === q) {
          cur += q;
          i++;
        }
        cur += s[i];
        i++;
      }
      cur += q;
      continue;
    }
    if (c === "(") depth++;
    if (c === ")") depth--;
    if (c === sep && depth === 0) {
      parts.push(cur.trim());
      cur = "";
    } else cur += c;
  }
  if (cur.trim()) parts.push(cur.trim());
  return parts;
}

// ------------------------------------------------------------------ parsing

const ID = `(?:"[^"]+"|[A-Za-z_][\\w$]*)`;
const QN = `(?:(${ID})\\s*\\.\\s*)?(${ID})`;

const unq = (x: string) => x.replace(/^"|"$/g, "").toLowerCase();
const norm = (s: string) => s.replace(/\s+/g, " ").trim();

function qname(schema: string | undefined, name: string): { schema: string; name: string } {
  return { schema: schema ? unq(schema) : "public", name: unq(name) };
}

function parseColumn(item: string): Column | null {
  const m = new RegExp(`^(${ID})\\s+(.*)$`, "is").exec(item);
  if (!m) return null;
  const name = unq(m[1]!);
  const rest = m[2]!;
  const typeMatch =
    /^(.*?)(?=\s+(?:not\s+null|null|default|references|primary|unique|check|generated|constraint|collate)\b|$)/is.exec(rest);
  const type = (typeMatch?.[1] ?? rest).trim().toLowerCase();
  const primaryKey = /\bprimary\s+key\b/i.test(rest);
  const col: Column = {
    name,
    type,
    primaryKey,
    notNull: /\bnot\s+null\b/i.test(rest) || primaryKey,
    hasDefault: /\bdefault\b|\bgenerated\b/i.test(rest) || /^(big|small)?serial/.test(type),
  };
  const ref = new RegExp(`\\breferences\\s+${QN}\\s*(?:\\(\\s*(${ID})\\s*\\))?`, "i").exec(rest);
  if (ref) {
    const q = qname(ref[1], ref[2]!);
    col.references = { schema: q.schema, table: q.name, column: ref[3] ? unq(ref[3]) : "id" };
  }
  return col;
}

function applyTableConstraint(table: TableDef, item: string): boolean {
  const pk = /^(?:constraint\s+\S+\s+)?primary\s+key\s*\(([^)]*)\)/i.exec(item);
  if (pk) {
    for (const c of pk[1]!.split(",")) {
      const col = table.columns.find((x) => x.name === unq(c.trim()));
      if (col) {
        col.primaryKey = true;
        col.notNull = true;
      }
    }
    return true;
  }
  const fk = new RegExp(
    `^(?:constraint\\s+\\S+\\s+)?foreign\\s+key\\s*\\(\\s*(${ID})\\s*\\)\\s*references\\s+${QN}\\s*(?:\\(\\s*(${ID})\\s*\\))?`,
    "i",
  ).exec(item);
  if (fk) {
    const col = table.columns.find((x) => x.name === unq(fk[1]!));
    const q = qname(fk[2], fk[3]!);
    if (col) col.references = { schema: q.schema, table: q.name, column: fk[4] ? unq(fk[4]) : "id" };
    return true;
  }
  return /^(?:constraint\s+\S+\s+)?(unique|check|exclude)\b/i.test(item) || /^like\b/i.test(item);
}

export function parseSql(sql: string, file: string, schema: ParsedSchema): void {
  for (const { text, line } of splitStatements(sql)) {
    const s = norm(text);

    // ---- CREATE TABLE
    const ct = new RegExp(`^create\\s+(?:unlogged\\s+)?table\\s+(?:if\\s+not\\s+exists\\s+)?${QN}\\s*\\(`, "i").exec(s);
    if (ct) {
      const q = qname(ct[1], ct[2]!);
      const open = ct[0].length - 1;
      const close = matchParen(s, open);
      const body = s.slice(open + 1, close === -1 ? undefined : close);
      const table: TableDef = { schema: q.schema, name: q.name, columns: [], rls: false, file, line };
      const constraints: string[] = [];
      for (const item of splitTopLevel(body)) {
        if (/^(constraint|primary\s+key|foreign\s+key|unique|check|exclude|like)\b/i.test(item)) {
          constraints.push(item);
          continue;
        }
        const col = parseColumn(item);
        if (col) table.columns.push(col);
      }
      for (const c of constraints) applyTableConstraint(table, c);
      schema.tables.set(tableKey(q.schema, q.name), table);
      continue;
    }

    // ---- ALTER TABLE
    const at = new RegExp(`^alter\\s+table\\s+(?:if\\s+exists\\s+)?(?:only\\s+)?${QN}\\s+(.*)$`, "i").exec(s);
    if (at) {
      const q = qname(at[1], at[2]!);
      const table = schema.tables.get(tableKey(q.schema, q.name));
      if (!table) continue;
      for (const action of splitTopLevel(at[3]!)) {
        if (/^enable\s+row\s+level\s+security/i.test(action)) table.rls = true;
        else if (/^disable\s+row\s+level\s+security/i.test(action)) table.rls = false;
        else if (/^force\s+row\s+level\s+security/i.test(action)) continue;
        else if (/^add\s+(?:constraint\s+\S+\s+)?(primary|foreign|unique|check)/i.test(action)) {
          applyTableConstraint(table, action.replace(/^add\s+/i, ""));
        } else {
          const add = /^add\s+(?:column\s+)?(?:if\s+not\s+exists\s+)?(.*)$/i.exec(action);
          if (add) {
            const col = parseColumn(add[1]!);
            if (col) table.columns = [...table.columns.filter((c) => c.name !== col.name), col];
            continue;
          }
          const drop = new RegExp(`^drop\\s+column\\s+(?:if\\s+exists\\s+)?(${ID})`, "i").exec(action);
          if (drop) table.columns = table.columns.filter((c) => c.name !== unq(drop[1]!));
        }
      }
      continue;
    }

    // ---- DROP TABLE / DROP POLICY
    const dt = new RegExp(`^drop\\s+table\\s+(?:if\\s+exists\\s+)?${QN}`, "i").exec(s);
    if (dt) {
      const q = qname(dt[1], dt[2]!);
      schema.tables.delete(tableKey(q.schema, q.name));
      schema.policies = schema.policies.filter((p) => !(p.schema === q.schema && p.table === q.name));
      continue;
    }
    const dp = new RegExp(`^drop\\s+policy\\s+(?:if\\s+exists\\s+)?(${ID})\\s+on\\s+${QN}`, "i").exec(s);
    if (dp) {
      const q = qname(dp[2], dp[3]!);
      const name = unq(dp[1]!);
      schema.policies = schema.policies.filter((p) => !(p.name === name && p.schema === q.schema && p.table === q.name));
      continue;
    }

    // ---- CREATE POLICY
    const cp = new RegExp(`^create\\s+policy\\s+(${ID})\\s+on\\s+${QN}\\s*(.*)$`, "i").exec(s);
    if (cp) {
      const q = qname(cp[2], cp[3]!);
      const rest = cp[4] ?? "";
      const firstExpr = rest.search(/\b(?:using|with\s+check)\s*\(/i);
      const head = firstExpr === -1 ? rest : rest.slice(0, firstExpr);
      const cmd = /\bfor\s+(all|select|insert|update|delete)\b/i.exec(head)?.[1]?.toLowerCase() as Command | undefined;
      const toMatch = /\bto\s+(.+?)\s*$/i.exec(head);
      const roles = toMatch
        ? toMatch[1]!.split(",").map((r) => unq(r.trim())).filter(Boolean)
        : ["public"];
      const grab = (re: RegExp): string | undefined => {
        const m = re.exec(rest);
        if (!m) return undefined;
        const open = m.index + m[0].length - 1;
        const close = matchParen(rest, open);
        return rest.slice(open + 1, close === -1 ? undefined : close).trim();
      };
      schema.policies.push({
        name: unq(cp[1]!),
        schema: q.schema,
        table: q.name,
        command: cmd ?? "all",
        roles,
        permissive: !/\bas\s+restrictive\b/i.test(head),
        using: grab(/\busing\s*\(/i),
        check: grab(/\bwith\s+check\s*\(/i),
        file,
        line,
      });
      continue;
    }

    // ---- storage.buckets inserts
    const ib = /^insert\s+into\s+storage\.buckets\s*\(([^)]*)\)\s*values\s*(.*)$/i.exec(s);
    if (ib) {
      const cols = ib[1]!.split(",").map((c) => unq(c.trim()));
      let rest = ib[2]!;
      let idx = rest.indexOf("(");
      while (idx !== -1) {
        const close = matchParen(rest, idx);
        if (close === -1) break;
        const vals = splitTopLevel(rest.slice(idx + 1, close)).map((v) => v.replace(/^'|'$/g, ""));
        const row = Object.fromEntries(cols.map((c, i) => [c, vals[i]]));
        const id = row["id"] ?? row["name"];
        if (id) schema.buckets.set(id, { id, public: /^(true|t|1)$/i.test(row["public"] ?? "false"), file, line });
        rest = rest.slice(close + 1);
        idx = rest.indexOf("(");
      }
    }
  }
}

export function emptySchema(): ParsedSchema {
  return { tables: new Map(), policies: [], buckets: new Map(), files: [] };
}

async function sqlFilesIn(dir: string): Promise<string[]> {
  try {
    const entries = await readdir(dir);
    return entries.filter((f) => f.endsWith(".sql")).sort().map((f) => join(dir, f));
  } catch {
    return [];
  }
}

/** Reads supabase/migrations/*.sql in order, then loose supabase/*.sql dumps. */
export async function parseProject(root: string): Promise<ParsedSchema> {
  const schema = emptySchema();
  const files = [
    ...(await sqlFilesIn(join(root, "supabase", "migrations"))),
    ...(await sqlFilesIn(join(root, "supabase"))),
  ];
  for (const f of files) {
    try {
      if (!(await stat(f)).isFile()) continue;
      parseSql(await readFile(f, "utf8"), relative(root, f), schema);
      schema.files.push(relative(root, f));
    } catch {
      /* unreadable file: skip */
    }
  }
  return schema;
}
