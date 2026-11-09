import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { inferProject, renderYaml } from "../src/infer/index.js";
import { applyAdjustment, parseAdjustment } from "../src/infer/llm.js";
import { analyseRoute, secretFindings } from "../src/infer/routes.js";
import { AccessSpec } from "../src/spec/schema.js";
import { parse } from "yaml";

const demo = resolve(import.meta.dirname, "../demo/vulnerable-app");

describe("inferProject on the vulnerable demo", () => {
  it("drafts rules for every table and bucket, all unconfirmed", async () => {
    const r = await inferProject(demo);
    expect(Object.keys(r.spec.resources).sort()).toEqual(["avatars", "notes", "orders", "posts", "profiles"]);
    expect(Object.values(r.spec.resources).every((x) => x.confirmed === false)).toBe(true);
    expect(r.spec.resources.orders).toMatchObject({ owner: "user_id" });
    expect(r.spec.resources.posts!.rules.anon).toEqual({ read: "all" });
  });

  it("finds each planted bug", async () => {
    const r = await inferProject(demo);
    const has = (id: string, resource?: string) => r.findings.some((f) => f.id === id && (!resource || f.resource === resource));
    expect(has("rls-disabled", "notes")).toBe(true);
    expect(has("policy-too-permissive", "orders")).toBe(true);
    expect(has("policy-too-permissive", "posts")).toBe(true);
    expect(has("bucket-too-permissive", "avatars")).toBe(true);
    expect(has("sensitive-column-writable", "profiles")).toBe(true);
    expect(has("route-service-role-no-auth")).toBe(true);
    expect(has("public-env-secret")).toBe(true);
  });

  it("does not flag the well-behaved notes route", async () => {
    const r = await inferProject(demo);
    expect(r.findings.some((f) => f.file?.includes("api/notes"))).toBe(false);
  });

  it("emits YAML that round-trips through the schema", async () => {
    const r = await inferProject(demo);
    expect(AccessSpec.safeParse(parse(renderYaml(r.spec))).success).toBe(true);
  });

  it("fails with a helpful message when there is no SQL", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ap-"));
    await expect(inferProject(dir)).rejects.toThrow(/supabase db pull/);
  });

  it("adds an admin role when policies mention admins", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ap-"));
    await mkdir(join(dir, "supabase/migrations"), { recursive: true });
    await writeFile(
      join(dir, "supabase/migrations/1.sql"),
      `create table profiles (id uuid primary key references auth.users(id), role text);
       create table tickets (id uuid primary key, user_id uuid references auth.users(id));
       alter table tickets enable row level security;
       create policy t1 on tickets for select using (auth.uid() = user_id or exists (select 1 from profiles where profiles.id = auth.uid() and profiles.role = 'admin'));`,
    );
    const r = await inferProject(dir);
    expect(r.spec.roles.admin?.seed).toEqual({ table: "profiles", set: { role: "admin" } });
    expect(r.spec.resources.tickets!.rules.admin).toEqual({ read: "all" });
    expect(r.spec.resources.tickets!.rules.user!.read).toBe("own");
  });
});

describe("route and secret scanning", () => {
  it("derives routes and detects auth / service role usage", () => {
    const r = analyseRoute(
      "app/api/orders/[id]/route.ts",
      `const a = createClient(u, process.env.SUPABASE_SERVICE_ROLE_KEY!);
       export async function GET(req, { params }) { return a.from("orders").select().eq("id", params.id) }`,
    )!;
    expect(r).toMatchObject({ route: "/api/orders/[id]", methods: ["GET"], tables: ["orders"], usesServiceRole: true, checksAuth: false });
  });

  it("strips route groups from the path", () => {
    expect(analyseRoute("src/app/(shop)/api/cart/route.ts", `export async function POST() {}`)!.route).toBe("/api/cart");
  });

  it("detects a service_role JWT but ignores an anon JWT", () => {
    const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const jwt = (role: string) => `eyJhbGciOiJIUzI1NiJ9.${b64({ role })}.c2lnbmF0dXJlc2lnbmF0dXJl`;
    expect(secretFindings("a.ts", `const k = "${jwt("service_role")}"`).map((f) => f.id)).toEqual(["service-role-jwt"]);
    expect(secretFindings("a.ts", `const k = "${jwt("anon")}"`)).toEqual([]);
  });
});

describe("LLM adjustments are constrained", () => {
  const spec = AccessSpec.parse({
    version: 1,
    project: { framework: "nextjs", backend: "supabase" },
    roles: { anon: {}, user: {} },
    resources: {
      a: { kind: "table", owner: "user_id", confirmed: false, rules: { user: { read: "own" } } },
      b: { kind: "table", owner: "user_id", confirmed: true, rules: { user: { read: "own" } } },
      c: { kind: "table", confirmed: false, rules: {} },
    },
  });

  it("changes unconfirmed resources only, and rejects invalid results", () => {
    const adj = parseAdjustment(
      `Sure! {"resources": {"a": {"rules": {"user": {"read": "all"}}, "reason": "public"},
        "b": {"rules": {"user": {"read": "all"}}}, "c": {"rules": {"user": {"read": "own"}}}, "zzz": {"rules": {"user": {"read": "all"}}}}}`,
    );
    const { spec: next, changed } = applyAdjustment(spec, adj);
    expect(changed).toEqual(["a"]);
    expect(next.resources.a!.rules.user!.read).toBe("all");
    expect(next.resources.b!.rules.user!.read).toBe("own"); // confirmed: untouched
    expect(next.resources.c!.rules).toEqual({}); // would need an owner column
  });

  it("tolerates non-JSON answers", () => {
    expect(parseAdjustment("I have no changes.")).toEqual({ resources: {} });
  });
});
