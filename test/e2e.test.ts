import { execFile } from "node:child_process";
import { cp, readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import pg from "pg";
import { describe, expect, it } from "vitest";
import { KEYS, PgSupabase, applySql, createDatabase, dropDatabase, migrationFiles } from "./support/pg-supabase.js";
import { serve } from "./support/http-server.js";
import { DEMO, demoCopy } from "./support/fixtures.js";

const ADMIN = process.env.ACCESSPROOF_PG_URL;
const CLI = resolve(import.meta.dirname, "../src/cli.ts");

function cli(args: string[]) {
  return new Promise<{ code: number; stdout: string; stderr: string }>((res) => {
    execFile(process.execPath, ["--import", "tsx", CLI, ...args], { env: { ...process.env, NO_COLOR: "1" } }, (err, stdout, stderr) =>
      res({ code: err ? ((err as { code?: number }).code ?? 1) : 0, stdout, stderr }),
    );
  });
}

async function withServer(name: string, withFix: boolean, fn: (url: string, root: string) => Promise<void>) {
  const dbUrl = await createDatabase(ADMIN!, name);
  const pool = new pg.Pool({ connectionString: dbUrl });
  await applySql(pool, resolve(import.meta.dirname, "support/supabase-prelude.sql"), ...(await migrationFiles(`${DEMO}/supabase/migrations`)));
  if (withFix) await applySql(pool, `${DEMO}/supabase/fixes/0002_fix_access.sql`);
  const server = await serve(new PgSupabase(pool));
  const root = await demoCopy();
  // a human-confirmed spec: the hand-labelled intent
  await cp(resolve(import.meta.dirname, "../eval/labels/vulnerable-app.access.yml"), join(root, "access.yml"));
  try {
    await fn(server.url, root);
  } finally {
    await server.close();
    await pool.end();
    await dropDatabase(ADMIN!, name);
  }
}

describe.skipIf(!ADMIN)("`accessproof test` over real HTTP", () => {
  const flags = (url: string) => ["--url", url, "--anon-key", KEYS.anon, "--service-key", KEYS.service];

  it("exits 1, names the exposures and writes reports for the vulnerable app", async () => {
    await withServer("ap_e2e_bad", false, async (url, root) => {
      const r = await cli(["test", root, ...flags(url)]);
      expect(r.code).toBe(1);
      expect(r.stdout).toMatch(/14 failed/);
      expect(r.stdout).toMatch(/EXPOSED/);
      expect(r.stdout).toMatch(/signed-out visitor must NOT be able to read another user's orders/);
      const report = JSON.parse(await readFile(join(root, ".accessproof/report.json"), "utf8"));
      expect(report.summary.fail).toBe(14);
      expect(await readFile(join(root, ".accessproof/FIXES.md"), "utf8")).toMatch(/## notes/);
      expect(await readFile(join(root, ".accessproof/report.md"), "utf8")).toMatch(/Problems found/);
    });
  }, 60_000);

  it("exits 0 once the fix is applied", async () => {
    await withServer("ap_e2e_good", true, async (url, root) => {
      const r = await cli(["test", root, ...flags(url)]);
      expect(r.stdout).toMatch(/60 passed/);
      expect(r.code).toBe(0);
    });
  }, 60_000);

  it("turns failures into 'needs review' while the rules are unconfirmed", async () => {
    await withServer("ap_e2e_review", false, async (url, root) => {
      const unconfirmed = (await readFile(join(root, "access.yml"), "utf8")).replaceAll("confirmed: true", "confirmed: false");
      const { writeFile } = await import("node:fs/promises");
      await writeFile(join(root, "access.yml"), unconfirmed);
      const lenient = await cli(["test", root, ...flags(url)]);
      expect(lenient.code).toBe(0);
      expect(lenient.stdout).toMatch(/14 need review/);
      expect(lenient.stdout).toMatch(/REVIEW/);
      const strict = await cli(["test", root, ...flags(url), "--strict"]);
      expect(strict.code).toBe(1);
    });
  }, 90_000);

  it("reports an unreachable server helpfully", async () => {
    const root = await demoCopy();
    await cp(resolve(import.meta.dirname, "../eval/labels/vulnerable-app.access.yml"), join(root, "access.yml"));
    const r = await cli(["test", root, "--url", "http://127.0.0.1:9", "--anon-key", "a", "--service-key", "s"]);
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/supabase start/);
  }, 30_000);
});
