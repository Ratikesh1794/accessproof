import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { resolveConnection } from "../src/runner/config.js";
import { assertSafeTarget, isLocalHost, loadProductionHosts, UnsafeTargetError } from "../src/runner/guard.js";
import { isTextType, newPk, replaceUid, singlePk, synthValue, updatableColumn } from "../src/runner/rows.js";
import { renderFailureBrief } from "../src/runner/report.js";
import type { Column, TableDef } from "../src/infer/sql.js";
import type { RunReport } from "../src/runner/execute.js";

describe("assertSafeTarget", () => {
  it.each(["http://127.0.0.1:54321", "http://localhost:54321", "http://[::1]:54321", "http://192.168.1.20:54321", "http://host.docker.internal:54321", "http://10.0.0.5"])(
    "allows local target %s",
    (u) => expect(() => assertSafeTarget(u)).not.toThrow(),
  );

  it("refuses a remote host unless its exact hostname is allowed", () => {
    expect(() => assertSafeTarget("https://abc.supabase.co")).toThrow(UnsafeTargetError);
    expect(() => assertSafeTarget("https://abc.supabase.co", { allowRemote: ["other.supabase.co"] })).toThrow(UnsafeTargetError);
    expect(() => assertSafeTarget("https://abc.supabase.co", { allowRemote: ["abc.supabase.co"] })).not.toThrow();
  });

  it("refuses production hosts even if allowed", () => {
    expect(() => assertSafeTarget("https://prod.supabase.co", { allowRemote: ["prod.supabase.co"], productionHosts: ["prod.supabase.co"] })).toThrow(/production/);
  });

  it("refuses odd URLs", () => {
    expect(() => assertSafeTarget("not a url")).toThrow(UnsafeTargetError);
    expect(() => assertSafeTarget("ftp://localhost")).toThrow(UnsafeTargetError);
    expect(() => assertSafeTarget("http://user:pw@localhost")).toThrow(/credentials/);
  });

  it("does not treat look-alike hosts as local", () => {
    expect(isLocalHost("localhost.evil.com")).toBe(false);
    expect(isLocalHost("172.32.0.1")).toBe(false);
    expect(isLocalHost("172.16.0.1")).toBe(true);
  });
});

describe("resolveConnection", () => {
  const dir = async (files: Record<string, string>) => {
    const d = await mkdtemp(join(tmpdir(), "ap-"));
    for (const [n, c] of Object.entries(files)) await writeFile(join(d, n), c);
    return d;
  };

  it("defaults to local Supabase and reads keys from env", async () => {
    const root = await dir({});
    const c = await resolveConnection(root, {}, { SUPABASE_ANON_KEY: "a", SUPABASE_SERVICE_ROLE_KEY: "s" });
    expect(c).toEqual({ url: "http://127.0.0.1:54321", anonKey: "a", serviceKey: "s" });
  });

  it("explains how to get missing keys", async () => {
    await expect(resolveConnection(await dir({}), {}, {})).rejects.toThrow(/supabase status/);
  });

  it("refuses a URL that appears in .env.production", async () => {
    const root = await dir({ ".env.production": "NEXT_PUBLIC_SUPABASE_URL=https://prod.supabase.co\n" });
    expect(await loadProductionHosts(root)).toEqual(["prod.supabase.co"]);
    await expect(
      resolveConnection(root, { url: "https://prod.supabase.co", allowRemote: ["prod.supabase.co"] }, { SUPABASE_ANON_KEY: "a", SUPABASE_SERVICE_ROLE_KEY: "s" }),
    ).rejects.toThrow(/production/);
  });

  it("refuses a remote URL given in the environment unless allowed", async () => {
    await expect(
      resolveConnection(await dir({}), {}, { SUPABASE_URL: "https://x.supabase.co", SUPABASE_ANON_KEY: "a", SUPABASE_SERVICE_ROLE_KEY: "s" }),
    ).rejects.toThrow(/not a local address/);
  });
});

const col = (o: Partial<Column> & { name: string; type: string }): Column => ({ notNull: false, hasDefault: false, primaryKey: false, ...o });

describe("row helpers", () => {
  it("invents values by type and gives up on unknown types", () => {
    expect(synthValue(col({ name: "t", type: "varchar(40)" }))).toBe("accessproof-t");
    expect(synthValue(col({ name: "n", type: "integer" }))).toBe(1);
    expect(synthValue(col({ name: "b", type: "boolean" }))).toBe(false);
    expect(synthValue(col({ name: "j", type: "jsonb" }))).toEqual({});
    expect(synthValue(col({ name: "a", type: "text[]" }))).toEqual([]);
    expect(synthValue(col({ name: "e", type: "order_status" }))).toBeUndefined();
  });

  it("generates primary keys of the right type", () => {
    expect(newPk(col({ name: "id", type: "uuid" }))).toMatch(/^[0-9a-f-]{36}$/);
    expect(typeof newPk(col({ name: "id", type: "bigint" }))).toBe("number");
    expect(newPk(col({ name: "id", type: "geometry" }))).toBeUndefined();
  });

  it("picks a safe column to update", () => {
    const t: TableDef = {
      schema: "public", name: "x", rls: true, file: "f", line: 1,
      columns: [col({ name: "id", type: "uuid", primaryKey: true }), col({ name: "user_id", type: "uuid" }), col({ name: "fk", type: "text", references: { schema: "public", table: "y", column: "id" } }), col({ name: "title", type: "text" })],
    };
    expect(updatableColumn(t, "user_id")?.name).toBe("title");
    expect(singlePk(t)?.name).toBe("id");
    expect(isTextType("character varying(10)")).toBe(true);
  });

  it("substitutes {uid} in seed templates", () => {
    expect(replaceUid({ a: "{uid}", b: ["x-{uid}"], c: 1 }, "U")).toEqual({ a: "U", b: ["x-U"], c: 1 });
  });
});

describe("failure brief", () => {
  const report = (results: RunReport["results"]): RunReport => ({
    startedAt: "t", finishedAt: "t", target: "x", warnings: [], results, summary: { pass: 0, fail: 0, "needs-review": 0, skipped: 0, error: 0 },
  });

  it("says nothing to fix when everything passes", () => {
    expect(renderFailureBrief(report([]))).toMatch(/Nothing to fix/);
  });

  it("tells the agent not to edit access.yml and groups by resource", () => {
    const brief = renderFailureBrief(
      report([{ id: "orders.anon.read.other", resource: "orders", kind: "table", role: "anon", op: "read", target: "other", description: "A signed-out visitor must NOT be able to read another user's orders rows.", expect: "deny", observed: "allowed", status: "fail", failure: "exposure", severity: "high", evidence: { request: "GET /rest/v1/orders", httpStatus: 200, note: "the row came back" } }]),
    );
    expect(brief).toContain("## orders");
    expect(brief).toContain("never edit `access.yml`");
    expect(brief).toContain("Must be denied but was allowed");
  });
});
