import { resolve } from "node:path";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parseProject } from "../src/infer/sql.js";
import { runAccessTests, type RunReport } from "../src/runner/execute.js";
import { renderFailureBrief } from "../src/runner/report.js";
import { loadSpec } from "../src/spec/load.js";
import { KEYS, PgSupabase, applySql, createDatabase, dropDatabase, migrationFiles } from "./support/pg-supabase.js";

/**
 * Runs the demo's real migrations in real PostgreSQL and checks that the runner finds
 * exactly the planted bugs, then none after the fix. Needs a Postgres superuser URL:
 *   ACCESSPROOF_PG_URL=postgres://postgres:postgres@127.0.0.1:5432/postgres npm test
 * Note: Postgres evaluates the RLS policies for real; PostgREST/Auth/Storage HTTP layers are emulated.
 */
const ADMIN = process.env.ACCESSPROOF_PG_URL;
const demo = resolve(import.meta.dirname, "../demo/vulnerable-app");
const labels = resolve(import.meta.dirname, "../eval/labels/vulnerable-app.access.yml");

async function runDemo(dbName: string, withFix: boolean) {
  const url = await createDatabase(ADMIN!, dbName);
  const pool = new pg.Pool({ connectionString: url });
  await applySql(pool, resolve(import.meta.dirname, "support/supabase-prelude.sql"), ...(await migrationFiles(`${demo}/supabase/migrations`)));
  if (withFix) await applySql(pool, `${demo}/supabase/fixes/0002_fix_access.sql`);
  const report = await runAccessTests({
    spec: await loadSpec(labels),
    schema: await parseProject(demo),
    transport: new PgSupabase(pool),
    keys: KEYS,
    target: "pg-test-double",
  });
  const leftovers = {
    users: (await pool.query("select count(*)::int n from auth.users")).rows[0].n,
    orders: (await pool.query("select count(*)::int n from public.orders")).rows[0].n,
    notes: (await pool.query("select count(*)::int n from public.notes")).rows[0].n,
    posts: (await pool.query("select count(*)::int n from public.posts")).rows[0].n,
    objects: (await pool.query("select count(*)::int n from storage.objects")).rows[0].n,
  };
  await pool.end();
  await dropDatabase(ADMIN!, dbName);
  return { report, leftovers };
}

const failIds = (r: RunReport) => r.results.filter((x) => x.status === "fail").map((x) => x.id).sort();
const status = (r: RunReport, id: string) => r.results.find((x) => x.id === id)?.status;

describe.skipIf(!ADMIN)("runner against real Postgres RLS", () => {
  let bad: Awaited<ReturnType<typeof runDemo>>;
  let good: Awaited<ReturnType<typeof runDemo>>;

  beforeAll(async () => {
    bad = await runDemo("ap_test_bad", false);
    good = await runDemo("ap_test_good", true);
  }, 120_000);
  afterAll(() => undefined);

  it("finds every planted exposure on the vulnerable schema", () => {
    const ids = failIds(bad.report);
    // orders: "temporary" using(true) read policy
    expect(ids).toContain("orders.anon.read.other");
    expect(ids).toContain("orders.user.read.other");
    // notes: RLS never enabled → anyone can do anything
    for (const op of ["read", "insert", "update", "delete"]) {
      expect(ids).toContain(`notes.anon.${op}.other`);
      expect(ids).toContain(`notes.user.${op}.other`);
    }
    // posts: update policy only checks "signed in"
    expect(ids).toContain("posts.user.update.other");
    // avatars: delete policy only checks "signed in" (and the API lies that it succeeded)
    expect(ids).toContain("avatars.user.delete.other");
  });

  it("rates unauthenticated writes critical and cross-user reads high", () => {
    const sev = (id: string) => bad.report.results.find((x) => x.id === id)?.severity;
    expect(sev("notes.anon.delete.other")).toBe("critical");
    expect(sev("orders.user.read.other")).toBe("high");
  });

  it("does not raise false alarms on what was done correctly", () => {
    for (const id of [
      "orders.user.read.self",
      "orders.user.update.other", // update policy is owner-scoped
      "orders.user.insert.other", // insert check is owner-scoped
      "posts.anon.read.other", // public feed is intended
      "posts.user.delete.other",
      "profiles.user.read.other",
      "profiles.user.update.other",
      "avatars.anon.read.other",
      "avatars.user.insert.other",
    ]) {
      expect(status(bad.report, id), id).toBe("pass");
    }
  });

  it("reports blocked-but-should-work cases separately from exposures", () => {
    const blocked = bad.report.results.filter((x) => x.failure === "blocked").map((x) => x.id);
    expect(blocked).toContain("orders.user.delete.self");
    expect(blocked).toContain("avatars.user.update.self");
  });

  it("passes everything after the fix, with no errors or skips", () => {
    expect(failIds(good.report)).toEqual([]);
    expect(good.report.summary.error).toBe(0);
    expect(good.report.summary.pass).toBe(good.report.results.length);
  });

  it("is not fooled by an API that says 'deleted' when nothing was removed", () => {
    const r = good.report.results.find((x) => x.id === "avatars.user.delete.other")!;
    expect(r.status).toBe("pass");
    expect(r.evidence?.httpStatus).toBe(200);
    expect(r.observed).toBe("denied");
  });

  it("cleans up every user, row and object it created", () => {
    expect(bad.leftovers).toEqual({ users: 0, orders: 0, notes: 0, posts: 0, objects: 0 });
    expect(good.leftovers).toEqual({ users: 0, orders: 0, notes: 0, posts: 0, objects: 0 });
  });

  it("writes a fix brief an AI agent can act on", () => {
    const brief = renderFailureBrief(bad.report);
    expect(brief).toMatch(/never edit `access.yml`/);
    expect(brief).toMatch(/## notes/);
    expect(renderFailureBrief(good.report)).toMatch(/Nothing to fix/);
  });
});
