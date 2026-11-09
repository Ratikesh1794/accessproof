import { randomBytes, randomUUID } from "node:crypto";
import type { Severity } from "../findings.js";
import type { ParsedSchema, TableDef } from "../infer/sql.js";
import type { AccessSpec, Op, Resource } from "../spec/schema.js";
import { buildPlan, describe, type TestCase } from "./plan.js";
import { newPk, replaceUid, singlePk, synthValue, UnsupportedColumn, updatableColumn } from "./rows.js";
import { errorMessage, Supa, type Actor } from "./supabase.js";
import type { Transport } from "./types.js";

export type Status = "pass" | "fail" | "needs-review" | "skipped" | "error";

export interface CaseResult {
  id: string;
  resource: string;
  kind: string;
  role: string;
  op: Op;
  target: "self" | "other";
  description: string;
  expect: "allow" | "deny";
  observed?: "allowed" | "denied";
  status: Status;
  /** exposure = someone can do something they must not; blocked = someone cannot do something they should */
  failure?: "exposure" | "blocked";
  severity?: Severity;
  evidence?: { request: string; httpStatus?: number; note: string };
  message?: string;
}

export interface RunReport {
  startedAt: string;
  finishedAt: string;
  target: string;
  results: CaseResult[];
  summary: Record<Status, number>;
  warnings: string[];
}

export interface RunOptions {
  spec: AccessSpec;
  schema: ParsedSchema;
  transport: Transport;
  keys: { anon: string; service: string };
  /** shown in the report only */
  target: string;
  only?: string[];
  onProgress?: (done: number, total: number, c: TestCase) => void;
}

interface Observation {
  /** undefined = inconclusive */
  allowed?: boolean;
  request: string;
  httpStatus?: number;
  note: string;
}

const TOUCH = "accessproof-touched";
const OBJ_BODY = "accessproof";

type Row = Record<string, unknown>;
type TableResource = Extract<Resource, { kind: "table" }>;
type BucketResource = Extract<Resource, { kind: "bucket" }>;

export class Runner {
  private readonly supa: Supa;
  private readonly users = new Map<string, Actor>();
  private readonly cleanups: Array<{ label: string; run: () => Promise<void> }> = [];
  private readonly mainRows = new Map<string, { pkCol: string; pk: unknown }>();
  private readonly mainObjects = new Map<string, string>();
  private readonly buckets = new Map<string, boolean>();
  readonly warnings: string[] = [];
  private readonly runId = randomBytes(3).toString("hex");

  constructor(private readonly o: RunOptions) {
    this.supa = new Supa(o.transport, o.keys);
  }

  // ------------------------------------------------------------- lifecycle

  async run(): Promise<RunReport> {
    const startedAt = new Date().toISOString();
    const plan = buildPlan(this.o.spec).filter((c) => !this.o.only?.length || this.o.only.includes(c.resource));
    const results: CaseResult[] = [];
    let setupError: string | undefined;

    try {
      await this.setupUsers(plan);
    } catch (e) {
      setupError = (e as Error).message;
    }

    let done = 0;
    for (const c of plan) {
      results.push(setupError ? this.errored(c, `Setup failed: ${setupError}`) : await this.runCase(c));
      this.o.onProgress?.(++done, plan.length, c);
    }
    await this.teardown();

    const summary: Record<Status, number> = { pass: 0, fail: 0, "needs-review": 0, skipped: 0, error: 0 };
    for (const r of results) summary[r.status]++;
    return { startedAt, finishedAt: new Date().toISOString(), target: this.o.target, results, summary, warnings: this.warnings };
  }

  private async setupUsers(plan: TestCase[]): Promise<void> {
    const roles = new Set(plan.map((c) => c.role));
    const labels: Array<{ label: string; role: string }> = [{ label: "user-b", role: "user" }];
    for (const role of roles) if (role !== "anon") labels.push({ label: `${role}-a`, role });
    if (!labels.some((l) => l.label === "user-a") && roles.has("user")) labels.push({ label: "user-a", role: "user" });

    for (const { label, role } of labels) {
      const seed = this.o.spec.roles[role]?.seed;
      const email = `ap-${this.runId}-${label}@accessproof.test`;
      const password = randomUUID();
      const id = await this.supa.createUser(email, password, seed?.app_metadata);
      this.cleanups.push({ label: `user ${label}`, run: () => this.supa.deleteUser(id) });
      const token = await this.supa.signIn(email, password);
      this.users.set(label, this.supa.actor(label, role, id, token));
      if (seed?.table && seed.set) await this.promote(seed.table, seed.set, id, role);
      else if (role !== "user" && !seed) {
        this.warnings.push(`Role "${role}" has no \`seed\` in access.yml, so its test user is an ordinary user. Its tests may fail until you add one.`);
      }
    }
  }

  private async promote(table: string, set: Record<string, unknown>, id: string, role: string): Promise<void> {
    const t = this.o.schema.tables.get(`public.${table}`);
    const pk = (t && singlePk(t)?.name) ?? "id";
    const upd = await this.supa.rest(this.supa.service, "PATCH", table, { query: { [pk]: `eq.${id}` }, body: set, prefer: "return=representation" });
    if (upd.status < 300 && Array.isArray(upd.body) && upd.body.length > 0) return;
    const ins = await this.supa.rest(this.supa.service, "POST", table, { body: { [pk]: id, ...set }, prefer: "return=minimal" });
    if (ins.status >= 300) this.warnings.push(`Could not give the "${role}" test user its role via ${table} (${ins.status}: ${errorMessage(ins)}).`);
  }

  private async teardown(): Promise<void> {
    for (const c of this.cleanups.reverse()) {
      try {
        await c.run();
      } catch (e) {
        this.warnings.push(`Cleanup of ${c.label} failed: ${(e as Error).message}. Remove leftovers with the service key if needed.`);
      }
    }
  }

  // ----------------------------------------------------------- case plumbing

  private errored(c: TestCase, message: string): CaseResult {
    return { ...this.base(c), status: "error", message };
  }

  private base(c: TestCase): CaseResult {
    return {
      id: c.id,
      resource: c.resource,
      kind: c.kind,
      role: c.role,
      op: c.op,
      target: c.target,
      description: describe(c),
      expect: c.expect,
      status: "error",
    };
  }

  private async runCase(c: TestCase): Promise<CaseResult> {
    const res = this.o.spec.resources[c.resource]!;
    const base = this.base(c);
    try {
      if (res.kind === "route") return { ...base, status: "skipped", message: "API route resources are not executable yet (planned for v0.2)." };
      const o = res.kind === "table" ? await this.tableCase(c, res) : await this.bucketCase(c, res);
      return this.judge(c, base, o);
    } catch (e) {
      const msg = e instanceof UnsupportedColumn ? e.message : (e as Error).message;
      return { ...base, status: "error", message: msg };
    }
  }

  private judge(c: TestCase, base: CaseResult, o: Observation): CaseResult {
    const evidence = { request: o.request, httpStatus: o.httpStatus, note: o.note };
    if (o.allowed === undefined) {
      return { ...base, status: "error", evidence, message: `Inconclusive: ${o.note}` };
    }
    const observed = o.allowed ? "allowed" : "denied";
    if ((o.allowed ? "allow" : "deny") === c.expect) return { ...base, status: "pass", observed, evidence };

    const failure = o.allowed ? "exposure" : "blocked";
    let severity: Severity = "low";
    if (failure === "exposure") {
      if (c.role === "anon") severity = c.op === "read" ? "high" : "critical";
      else severity = c.target === "other" && !c.ownerless ? "high" : "medium";
    }
    return { ...base, status: c.unconfirmed ? "needs-review" : "fail", observed, failure, severity, evidence };
  }

  // ---------------------------------------------------------------- actors

  private actorOf(role: string): Actor {
    if (role === "anon") return this.supa.anon;
    const a = this.users.get(`${role}-a`);
    if (!a) throw new Error(`No test user for role "${role}".`);
    return a;
  }

  private ownerOf(c: TestCase): { label: string; id?: string } {
    if (c.ownerless) return { label: "shared" };
    const label = c.target === "self" ? `${c.role}-a` : "user-b";
    const id = this.users.get(label)?.id;
    if (!id) throw new Error(`No test user "${label}".`);
    return { label, id };
  }

  private who(actor: Actor): string {
    return actor.role === "anon" ? "anon" : actor.label;
  }

  // ----------------------------------------------------------------- tables

  private tableDef(name: string): TableDef {
    const t = this.o.schema.tables.get(`public.${name}`);
    if (!t) throw new Error(`Table "${name}" was not found in your migrations, so test rows can't be built. Run \`supabase db pull\`, or add a \`seed:\` template.`);
    return t;
  }

  private async buildRow(table: TableDef, res: TableResource | undefined, ownerId: string | undefined, depth: number): Promise<Row> {
    const template = (res?.seed ? (replaceUid(res.seed, ownerId) as Row) : {}) ?? {};
    const row: Row = {};
    const pk = singlePk(table);
    for (const col of table.columns) {
      if (col.name in template) {
        row[col.name] = template[col.name];
        continue;
      }
      if (res?.owner === col.name && ownerId) {
        row[col.name] = ownerId;
        continue;
      }
      if (pk && col.name === pk.name) {
        const v = newPk(pk);
        if (v !== undefined) row[col.name] = v;
        continue;
      }
      const required = col.notNull && !col.hasDefault;
      if (col.references?.schema === "auth" && col.references.table === "users") {
        if (ownerId && (required || col.name === res?.owner)) row[col.name] = ownerId;
        continue;
      }
      if (!required) continue;
      if (col.references) {
        const parent = this.o.schema.tables.get(`${col.references.schema}.${col.references.table}`);
        if (!parent || depth >= 3) throw new UnsupportedColumn(table.name, col);
        const pres = this.o.spec.resources[parent.name];
        const made = await this.createRaw(parent, pres?.kind === "table" ? pres : undefined, ownerId, depth + 1);
        this.cleanups.push({ label: `${parent.name} row`, run: () => this.dropRow(parent.name, made.pkCol, made.pk) });
        row[col.name] = made.row[col.references.column];
        continue;
      }
      const v = synthValue(col);
      if (v === undefined) throw new UnsupportedColumn(table.name, col);
      row[col.name] = v;
    }
    return row;
  }

  private async createRaw(table: TableDef, res: TableResource | undefined, ownerId: string | undefined, depth = 0) {
    const pkc = singlePk(table);
    if (!pkc) throw new Error(`"${table.name}" has no single-column primary key, so test rows can't be tracked.`);
    const row = await this.buildRow(table, res, ownerId, depth);
    const r = await this.supa.rest(this.supa.service, "POST", table.name, { body: row, prefer: "return=representation" });
    if (r.status >= 300) {
      throw new Error(`Could not seed a row in ${table.name} (${r.status}: ${errorMessage(r)}). Add a \`seed:\` row template under "${table.name}" in access.yml.`);
    }
    const created = (Array.isArray(r.body) ? r.body[0] : r.body) as Row;
    return { row: created, pkCol: pkc.name, pk: created[pkc.name] ?? row[pkc.name] };
  }

  private async dropRow(table: string, pkCol: string, pk: unknown): Promise<void> {
    await this.supa.rest(this.supa.service, "DELETE", table, { query: { [pkCol]: `eq.${String(pk)}` }, prefer: "return=minimal" });
  }

  private async rowExists(table: string, pkCol: string, pk: unknown): Promise<Row | undefined> {
    const r = await this.supa.rest(this.supa.service, "GET", table, { query: { [pkCol]: `eq.${String(pk)}`, select: "*" } });
    return Array.isArray(r.body) ? (r.body[0] as Row | undefined) : undefined;
  }

  private async mainRow(res: string, table: TableDef, label: string, ownerId: string | undefined, resource: TableResource) {
    const key = `${res}|${label}`;
    let m = this.mainRows.get(key);
    if (!m) {
      const made = await this.createRaw(table, resource, ownerId);
      m = { pkCol: made.pkCol, pk: made.pk };
      this.mainRows.set(key, m);
      this.cleanups.push({ label: `${res} row (${label})`, run: () => this.dropRow(table.name, m!.pkCol, m!.pk) });
    }
    return m;
  }

  /** Denial = 401/403, or a 2xx that changed nothing. Any other status is inconclusive. */
  private verdict(effect: boolean, status: number): boolean | undefined {
    if (effect) return true;
    if ((status >= 200 && status < 300) || status === 401 || status === 403) return false;
    return undefined;
  }

  private async tableCase(c: TestCase, res: TableResource): Promise<Observation> {
    const table = this.tableDef(c.resource);
    const pkc = singlePk(table);
    if (!pkc) throw new Error(`"${table.name}" has no single-column primary key; the runner can't track its test rows.`);
    const actor = this.actorOf(c.role);
    const owner = this.ownerOf(c);
    const t = table.name;
    const asWho = `as ${this.who(actor)}`;

    // One row per user, keyed by the user id (profiles-style): a second row can't be invented.
    if (res.owner && res.owner === pkc.name && owner.id) {
      return this.singleRowCase(c, table, res, pkc.name, actor, owner.id, asWho);
    }

    if (c.op === "read") {
      const m = await this.mainRow(c.resource, table, owner.label, owner.id, res);
      const r = await this.supa.rest(actor, "GET", t, { query: { [pkc.name]: `eq.${String(m.pk)}`, select: pkc.name } });
      const seen = r.status === 200 && Array.isArray(r.body) && r.body.some((x) => String((x as Row)[pkc.name]) === String(m.pk));
      return {
        allowed: this.verdict(seen, r.status),
        request: `GET /rest/v1/${t}?${pkc.name}=eq.<id of ${c.ownerless ? "a" : c.target === "self" ? "own" : "another user's"} row> ${asWho}`,
        httpStatus: r.status,
        note: seen ? "the row came back" : r.status === 200 ? "empty result (row hidden)" : errorMessage(r) || `HTTP ${r.status}`,
      };
    }

    if (c.op === "insert") {
      const row = await this.buildRow(table, res, owner.id, 0);
      const pk = row[pkc.name];
      if (pk === undefined) return { request: `POST /rest/v1/${t}`, note: `cannot choose a primary key for ${t}.${pkc.name} (type ${pkc.type}); add a \`seed:\` template`, httpStatus: undefined };
      const r = await this.supa.rest(actor, "POST", t, { body: row, prefer: "return=minimal" });
      const exists = await this.rowExists(t, pkc.name, pk);
      if (exists) await this.dropRow(t, pkc.name, pk);
      return {
        allowed: this.verdict(!!exists, r.status),
        request: `POST /rest/v1/${t} {${res.owner ? `${res.owner}: <${c.target === "self" ? "own" : "another user's"} id>, ` : ""}…} ${asWho}`,
        httpStatus: r.status,
        note: exists ? "the row was created" : errorMessage(r) || `HTTP ${r.status}, nothing created`,
      };
    }

    const col = updatableColumn(table, res.owner);
    if (c.op === "update" && !col) {
      return { request: `PATCH /rest/v1/${t}`, note: `no plain text column in ${t} to change safely; add one or skip update checks`, httpStatus: undefined };
    }
    const made = await this.createRaw(table, res, owner.id);
    try {
      if (c.op === "update") {
        const r = await this.supa.rest(actor, "PATCH", t, { query: { [pkc.name]: `eq.${String(made.pk)}` }, body: { [col!.name]: TOUCH }, prefer: "return=minimal" });
        const after = await this.rowExists(t, pkc.name, made.pk);
        const changed = after?.[col!.name] === TOUCH;
        return {
          allowed: this.verdict(changed, r.status),
          request: `PATCH /rest/v1/${t}?${pkc.name}=eq.<id of ${c.ownerless ? "a" : c.target === "self" ? "own" : "another user's"} row> {${col!.name}: …} ${asWho}`,
          httpStatus: r.status,
          note: changed ? "the row was changed" : errorMessage(r) || `HTTP ${r.status}, row unchanged`,
        };
      }
      const r = await this.supa.rest(actor, "DELETE", t, { query: { [pkc.name]: `eq.${String(made.pk)}` }, prefer: "return=minimal" });
      const still = await this.rowExists(t, pkc.name, made.pk);
      return {
        allowed: this.verdict(!still, r.status),
        request: `DELETE /rest/v1/${t}?${pkc.name}=eq.<id of ${c.ownerless ? "a" : c.target === "self" ? "own" : "another user's"} row> ${asWho}`,
        httpStatus: r.status,
        note: !still ? "the row was deleted" : errorMessage(r) || `HTTP ${r.status}, row still there`,
      };
    } finally {
      if (await this.rowExists(t, made.pkCol, made.pk)) await this.dropRow(t, made.pkCol, made.pk);
    }
  }

  private async singleRowCase(c: TestCase, table: TableDef, res: TableResource, pkCol: string, actor: Actor, ownerId: string, asWho: string): Promise<Observation> {
    const t = table.name;
    const filter = { [pkCol]: `eq.${ownerId}` };
    const whose = c.target === "self" ? "own" : "another user's";
    let original = await this.rowExists(t, pkCol, ownerId);
    if (!original) {
      const made = await this.createRaw(table, res, ownerId);
      original = made.row;
      this.cleanups.push({ label: `${t} row`, run: () => this.dropRow(t, pkCol, ownerId) });
    }
    const orig = original;
    const col = updatableColumn(table, res.owner);
    const restore = async () => {
      const now = await this.rowExists(t, pkCol, ownerId);
      if (!now) await this.supa.rest(this.supa.service, "POST", t, { body: orig, prefer: "return=minimal" });
      else if (col) await this.supa.rest(this.supa.service, "PATCH", t, { query: filter, body: { [col.name]: orig[col.name] ?? null }, prefer: "return=minimal" });
    };
    try {
      if (c.op === "read") {
        const r = await this.supa.rest(actor, "GET", t, { query: { ...filter, select: pkCol } });
        const seen = r.status === 200 && Array.isArray(r.body) && r.body.length > 0;
        return { allowed: this.verdict(seen, r.status), request: `GET /rest/v1/${t}?${pkCol}=eq.<id of ${whose} row> ${asWho}`, httpStatus: r.status, note: seen ? "the row came back" : r.status === 200 ? "empty result (row hidden)" : errorMessage(r) || `HTTP ${r.status}` };
      }
      if (c.op === "update") {
        if (!col) return { request: `PATCH /rest/v1/${t}`, note: `no plain text column in ${t} to change safely` };
        await this.supa.rest(this.supa.service, "PATCH", t, { query: filter, body: { [col.name]: orig[col.name] ?? null }, prefer: "return=minimal" });
        const r = await this.supa.rest(actor, "PATCH", t, { query: filter, body: { [col.name]: TOUCH }, prefer: "return=minimal" });
        const changed = (await this.rowExists(t, pkCol, ownerId))?.[col.name] === TOUCH;
        return { allowed: this.verdict(changed, r.status), request: `PATCH /rest/v1/${t}?${pkCol}=eq.<id of ${whose} row> {${col.name}: …} ${asWho}`, httpStatus: r.status, note: changed ? "the row was changed" : errorMessage(r) || `HTTP ${r.status}, row unchanged` };
      }
      if (c.op === "delete") {
        const r = await this.supa.rest(actor, "DELETE", t, { query: filter, prefer: "return=minimal" });
        const gone = !(await this.rowExists(t, pkCol, ownerId));
        return { allowed: this.verdict(gone, r.status), request: `DELETE /rest/v1/${t}?${pkCol}=eq.<id of ${whose} row> ${asWho}`, httpStatus: r.status, note: gone ? "the row was deleted" : errorMessage(r) || `HTTP ${r.status}, row still there` };
      }
      await this.dropRow(t, pkCol, ownerId);
      const r = await this.supa.rest(actor, "POST", t, { body: orig, prefer: "return=minimal" });
      const exists = !!(await this.rowExists(t, pkCol, ownerId));
      return { allowed: this.verdict(exists, r.status), request: `POST /rest/v1/${t} {${pkCol}: <${whose} id>, …} ${asWho}`, httpStatus: r.status, note: exists ? "the row was created" : errorMessage(r) || `HTTP ${r.status}, nothing created` };
    } finally {
      await restore();
    }
  }

  // ---------------------------------------------------------------- buckets

  private async isPublic(bucket: string): Promise<boolean> {
    const known = this.buckets.get(bucket);
    if (known !== undefined) return known;
    const r = await this.supa.storage(this.supa.service, "GET", `/bucket/${encodeURIComponent(bucket)}`);
    if (r.status !== 200) throw new Error(`Storage bucket "${bucket}" does not exist on the target. Apply your migrations first (supabase db reset).`);
    const pub = !!(r.body as { public?: boolean }).public;
    this.buckets.set(bucket, pub);
    return pub;
  }

  private objPath(ownerId: string | undefined, name: string): string {
    return encodeURI(ownerId ? `${ownerId}/${name}` : name);
  }

  private async putObject(bucket: string, path: string, body: string): Promise<void> {
    const r = await this.supa.storage(this.supa.service, "POST", `/object/${encodeURIComponent(bucket)}/${path}`, body);
    if (r.status >= 300) throw new Error(`Could not seed a storage object in "${bucket}" (${r.status}: ${errorMessage(r)}).`);
    this.cleanups.push({ label: `object ${path}`, run: () => this.dropObject(bucket, path) });
  }

  private async dropObject(bucket: string, path: string): Promise<void> {
    await this.supa.storage(this.supa.service, "DELETE", `/object/${encodeURIComponent(bucket)}/${path}`);
  }

  private async readObject(actor: Actor, bucket: string, path: string, pub: boolean) {
    const route = pub ? "public" : "authenticated";
    return this.supa.storage(actor, "GET", `/object/${route}/${encodeURIComponent(bucket)}/${path}`);
  }

  private storageVerdict(effect: boolean, status: number): boolean | undefined {
    if (effect) return true;
    if ((status >= 200 && status < 300) || [400, 401, 403, 404].includes(status)) return false;
    return undefined;
  }

  private async bucketCase(c: TestCase, res: BucketResource): Promise<Observation> {
    void res;
    const bucket = c.resource;
    const bucketId = this.bucketId(bucket);
    const actor = this.actorOf(c.role);
    const owner = this.ownerOf(c);
    const pub = await this.isPublic(bucketId);
    const asWho = `as ${this.who(actor)}`;
    const whose = c.ownerless ? "a" : c.target === "self" ? "own" : "another user's";
    const rand = randomUUID().slice(0, 8);

    if (c.op === "read") {
      const key = `${bucketId}|${owner.label}`;
      let path = this.mainObjects.get(key);
      if (!path) {
        path = this.objPath(owner.id, "seed.txt");
        await this.putObject(bucketId, path, OBJ_BODY);
        this.mainObjects.set(key, path);
      }
      const r = await this.readObject(actor, bucketId, path, pub);
      const seen = r.status === 200 && String(r.body).includes(OBJ_BODY);
      return {
        allowed: this.storageVerdict(seen, r.status),
        request: `GET /storage/v1/object/${pub ? "public" : "authenticated"}/${bucketId}/<${whose} file> ${asWho}`,
        httpStatus: r.status,
        note: seen ? "the file came back" : errorMessage(r) || `HTTP ${r.status}`,
      };
    }

    if (c.op === "insert") {
      const path = this.objPath(owner.id, `new-${rand}.txt`);
      const r = await this.supa.storage(actor, "POST", `/object/${encodeURIComponent(bucketId)}/${path}`, OBJ_BODY);
      const check = await this.readObject(this.supa.service, bucketId, path, false);
      const exists = check.status === 200;
      if (exists) await this.dropObject(bucketId, path);
      return {
        allowed: this.storageVerdict(exists, r.status),
        request: `POST /storage/v1/object/${bucketId}/<new file in ${whose === "own" ? "own" : whose === "a" ? "the" : "another user's"} folder> ${asWho}`,
        httpStatus: r.status,
        note: exists ? "the file was uploaded" : errorMessage(r) || `HTTP ${r.status}, nothing uploaded`,
      };
    }

    const path = this.objPath(owner.id, `${c.op}-${rand}.txt`);
    await this.putObject(bucketId, path, OBJ_BODY);
    try {
      if (c.op === "update") {
        const r = await this.supa.storage(actor, "PUT", `/object/${encodeURIComponent(bucketId)}/${path}`, TOUCH);
        const after = await this.readObject(this.supa.service, bucketId, path, false);
        const changed = after.status === 200 && String(after.body) === TOUCH;
        return {
          allowed: this.storageVerdict(changed, r.status),
          request: `PUT /storage/v1/object/${bucketId}/<${whose} file> ${asWho}`,
          httpStatus: r.status,
          note: changed ? "the file was overwritten" : errorMessage(r) || `HTTP ${r.status}, file unchanged`,
        };
      }
      const r = await this.supa.storage(actor, "DELETE", `/object/${encodeURIComponent(bucketId)}/${path}`);
      const after = await this.readObject(this.supa.service, bucketId, path, false);
      const gone = after.status !== 200;
      return {
        allowed: this.storageVerdict(gone, r.status),
        request: `DELETE /storage/v1/object/${bucketId}/<${whose} file> ${asWho}`,
        httpStatus: r.status,
        note: gone ? "the file was deleted" : errorMessage(r) || `HTTP ${r.status}, file still there`,
      };
    } finally {
      const still = await this.readObject(this.supa.service, bucketId, path, false);
      if (still.status === 200) await this.dropObject(bucketId, path);
    }
  }

  /** Resource names may carry a `_bucket` suffix to avoid clashing with a table of the same name. */
  private bucketId(resource: string): string {
    if (this.o.schema.buckets.has(resource)) return resource;
    const stripped = resource.replace(/_bucket$/, "");
    return this.o.schema.buckets.has(stripped) ? stripped : resource;
  }
}

export async function runAccessTests(o: RunOptions): Promise<RunReport> {
  return new Runner(o).run();
}
