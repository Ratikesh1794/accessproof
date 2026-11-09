import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildServer } from "../src/mcp/server.js";
import { demoCopy } from "./support/fixtures.js";

async function connect() {
  const [a, b] = InMemoryTransport.createLinkedPair();
  const server = buildServer();
  const client = new Client({ name: "test", version: "0.0.0" });
  await Promise.all([server.connect(a), client.connect(b)]);
  const call = async (name: string, args: Record<string, unknown>) => {
    const r = (await client.callTool({ name, arguments: args })) as { isError?: boolean; content: Array<{ text: string }> };
    return { error: !!r.isError, text: r.content.map((c) => c.text).join("\n") };
  };
  return { client, call };
}

describe("MCP server", () => {
  it("exposes the five tools, and no way to unlock remote targets", async () => {
    const { client } = await connect();
    const { tools } = await client.listTools();
    expect(tools.map((t) => t.name).sort()).toEqual(["explain_rule", "get_failures", "infer_policy", "run_access_tests", "static_check"]);
    const run = tools.find((t) => t.name === "run_access_tests")!;
    expect(JSON.stringify(run.inputSchema)).not.toMatch(/allow|remote|service|key/i);
  });

  it("infer_policy writes access.yml but leaves everything unconfirmed", async () => {
    const root = await demoCopy();
    const { call } = await connect();
    const r = await call("infer_policy", { root });
    expect(r.error).toBe(false);
    expect(r.text).toMatch(/Ask the user to review/);
    const yml = await readFile(join(root, "access.yml"), "utf8");
    expect(yml).not.toMatch(/^\s+confirmed: true/m);
    // second call refuses to clobber the file
    const again = await call("infer_policy", { root });
    expect(again.error).toBe(true);
    expect(again.text).toMatch(/already exists/);
  });

  it("static_check, explain_rule and get_failures work without a database", async () => {
    const root = await demoCopy();
    const { call } = await connect();
    expect((await call("static_check", { root })).text).toMatch(/Row Level Security is off on "notes"/);
    await call("infer_policy", { root });
    const explained = await call("explain_rule", { root, resource: "orders" });
    expect(explained.text).toMatch(/NOT yet confirmed/);
    expect(explained.text).toMatch(/user: read only their own/);
    expect((await call("explain_rule", { root, resource: "nope" })).text).toMatch(/No resource/);
    expect((await call("get_failures", { root })).text).toMatch(/No test report yet/);
  });

  it("run_access_tests refuses remote URLs and explains missing keys", async () => {
    const root = await demoCopy();
    const { call } = await connect();
    await call("infer_policy", { root });
    const remote = await call("run_access_tests", { root, url: "https://abc.supabase.co" });
    expect(remote.error).toBe(true);
    expect(remote.text).toMatch(/not a local address/);
    const saved = { a: process.env.SUPABASE_ANON_KEY, s: process.env.SUPABASE_SERVICE_ROLE_KEY };
    delete process.env.SUPABASE_ANON_KEY;
    delete process.env.SUPABASE_SERVICE_ROLE_KEY;
    try {
      const noKeys = await call("run_access_tests", { root });
      expect(noKeys.error).toBe(true);
      expect(noKeys.text).toMatch(/Missing SUPABASE_ANON_KEY/);
    } finally {
      if (saved.a) process.env.SUPABASE_ANON_KEY = saved.a;
      if (saved.s) process.env.SUPABASE_SERVICE_ROLE_KEY = saved.s;
    }
  });
});
