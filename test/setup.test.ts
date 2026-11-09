import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { setupClaude } from "../src/setup.js";

const tmp = () => mkdtemp(join(tmpdir(), "ap-setup-"));
const json = async (p: string) => JSON.parse(await readFile(p, "utf8"));

describe("setupClaude", () => {
  it("creates MCP config, hooks and the skill in a bare project", async () => {
    const root = await tmp();
    const changes = await setupClaude(root);
    expect(changes.map((c) => c.action)).toEqual(["create", "create", "create"]);
    expect((await json(join(root, ".mcp.json"))).mcpServers.accessproof).toEqual({ command: "npx", args: ["-y", "accessproof", "mcp"] });
    const hooks = (await json(join(root, ".claude/settings.json"))).hooks;
    expect(hooks.UserPromptSubmit[0].hooks[0].command).toBe("npx -y accessproof hook prompt");
    expect(hooks.PostToolUse[0]).toMatchObject({ matcher: "Edit|Write|MultiEdit" });
    expect(await readFile(join(root, ".claude/skills/secure/SKILL.md"), "utf8")).toMatch(/^name: secure/m);
  });

  it("is idempotent", async () => {
    const root = await tmp();
    await setupClaude(root);
    expect((await setupClaude(root)).map((c) => c.action)).toEqual(["unchanged", "unchanged", "unchanged"]);
    const hooks = (await json(join(root, ".claude/settings.json"))).hooks;
    expect(hooks.PostToolUse).toHaveLength(1);
  });

  it("keeps the user's existing servers, hooks and settings", async () => {
    const root = await tmp();
    await mkdir(join(root, ".claude"), { recursive: true });
    await writeFile(join(root, ".mcp.json"), JSON.stringify({ mcpServers: { other: { command: "x" } } }));
    await writeFile(
      join(root, ".claude/settings.json"),
      JSON.stringify({ permissions: { allow: ["Bash(ls)"] }, hooks: { PostToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "echo hi" }] }] } }),
    );
    await setupClaude(root);
    expect((await json(join(root, ".mcp.json"))).mcpServers).toMatchObject({ other: { command: "x" }, accessproof: {} });
    const s = await json(join(root, ".claude/settings.json"));
    expect(s.permissions).toEqual({ allow: ["Bash(ls)"] });
    expect(s.hooks.PostToolUse).toHaveLength(2);
    expect(s.hooks.PostToolUse[0].hooks[0].command).toBe("echo hi");
  });

  it("refuses to touch invalid JSON and supports dry runs", async () => {
    const root = await tmp();
    await writeFile(join(root, ".mcp.json"), "{ nope");
    await expect(setupClaude(root)).rejects.toThrow(/left untouched/);
    const clean = await tmp();
    const dry = await setupClaude(clean, { dryRun: true });
    expect(dry.every((c) => c.action === "create")).toBe(true);
    await expect(readFile(join(clean, ".mcp.json"), "utf8")).rejects.toThrow();
  });

  it("--local is idempotent too", async () => {
    const root = await tmp();
    await setupClaude(root, { local: true });
    expect((await setupClaude(root, { local: true })).every((c) => c.action === "unchanged")).toBe(true);
    // and running the npx flavour afterwards does not add a duplicate
    expect((await setupClaude(root)).filter((c) => c.file.includes("settings")).map((c) => c.action)).toEqual(["unchanged"]);
  });

  it("--local points at this checkout", async () => {
    const root = await tmp();
    await setupClaude(root, { local: true });
    const server = (await json(join(root, ".mcp.json"))).mcpServers.accessproof;
    expect(server.command).toBe("node");
    expect(server.args[0]).toMatch(/cli\.js$/);
    expect(server.args[1]).toBe("mcp");
  });
});
