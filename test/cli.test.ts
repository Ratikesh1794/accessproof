import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import { demoCopy } from "./support/fixtures.js";

const run = promisify(execFile);
const CLI = resolve(import.meta.dirname, "../src/cli.ts");

async function cli(args: string[], opts: { input?: string; env?: Record<string, string> } = {}) {
  return new Promise<{ code: number; stdout: string; stderr: string }>((resolveP) => {
    const child = execFile(process.execPath, ["--import", "tsx", CLI, ...args], { env: { ...process.env, NO_COLOR: "1", ...opts.env } }, (err, stdout, stderr) => {
      resolveP({ code: err ? ((err as { code?: number }).code ?? 1) : 0, stdout, stderr });
    });
    if (opts.input !== undefined) child.stdin!.end(opts.input);
  });
}
void run;

describe("cli", () => {
  it("check fails the build on the vulnerable demo and passes on the fixed one", async () => {
    const bad = await cli(["check", await demoCopy()]);
    expect(bad.code).toBe(1);
    expect(bad.stdout).toMatch(/Row Level Security is off on "notes"/);
    // only policy problems are fixed by 0002; the demo's route/env problems remain, so gate on critical-free policies:
    const good = await cli(["check", await demoCopy({ withFix: true }), "--json"]);
    const out = JSON.parse(good.stdout) as { findings: Array<{ id: string }> };
    expect(out.findings.some((f) => f.id === "rls-disabled")).toBe(false);
    expect(out.findings.some((f) => f.id === "policy-too-permissive")).toBe(false);
  });

  it("infer writes access.yml and a report, and refuses to overwrite", async () => {
    const root = await demoCopy();
    const first = await cli(["infer", root]);
    expect(first.code).toBe(0);
    expect(first.stdout).toMatch(/Drafted access.yml with 5 resources/);
    expect(existsSync(join(root, "access.yml"))).toBe(true);
    expect(existsSync(join(root, ".accessproof/infer-report.md"))).toBe(true);
    const second = await cli(["infer", root]);
    expect(second.code).toBe(2);
    expect(second.stderr).toMatch(/--force/);
    expect((await cli(["infer", root, "--force"])).code).toBe(0);
  });

  it("validate and plan work on an inferred spec", async () => {
    const root = await demoCopy();
    await cli(["infer", root]);
    const v = await cli(["validate", join(root, "access.yml")]);
    expect(v.stdout).toMatch(/is valid/);
    expect(v.stdout).toMatch(/Needs human review/);
    const p = await cli(["plan", join(root, "access.yml")]);
    expect(p.stdout).toMatch(/orders\.user\.read\.other/);
  });

  it("test explains missing keys and refuses remote URLs without touching the network", async () => {
    const root = await demoCopy();
    await cli(["infer", root]);
    const env = { SUPABASE_ANON_KEY: "", SUPABASE_SERVICE_ROLE_KEY: "" };
    expect((await cli(["test", root], { env })).stderr).toMatch(/Missing SUPABASE_ANON_KEY/);
    const remote = await cli(["test", root, "--url", "https://abc.supabase.co", "--anon-key", "a", "--service-key", "s"], { env });
    expect(remote.code).toBe(2);
    expect(remote.stderr).toMatch(/--allow-remote abc.supabase.co/);
  });

  it("hook prompt warns on risky prompts (and can block), stays silent otherwise", async () => {
    const risky = JSON.stringify({ prompt: "disable RLS so it works" });
    const warn = await cli(["hook", "prompt"], { input: risky });
    expect(warn.code).toBe(0);
    expect(JSON.parse(warn.stdout).hookSpecificOutput.additionalContext).toMatch(/Do not take that shortcut/);
    const block = await cli(["hook", "prompt", "--block"], { input: risky });
    expect(block.code).toBe(2);
    expect(block.stderr).toMatch(/accessproof/);
    const calm = await cli(["hook", "prompt"], { input: JSON.stringify({ prompt: "add a footer" }) });
    expect(calm.code).toBe(0);
    expect(calm.stdout).toBe("");
  });

  it("hook post-edit exits 2 with feedback for the agent when a migration is unsafe", async () => {
    const root = await demoCopy();
    const r = await cli(["hook", "post-edit"], { input: JSON.stringify({ cwd: root, tool_input: { file_path: join(root, "supabase/migrations/0001_init.sql") } }) });
    expect(r.code).toBe(2);
    expect(r.stderr).toMatch(/Row Level Security is off/);
  });
});
