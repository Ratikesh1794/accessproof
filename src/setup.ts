import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export interface SetupOptions {
  /** Use this checkout instead of `npx accessproof` (handy before the package is published). */
  local?: boolean;
  dryRun?: boolean;
}

export interface SetupChange {
  file: string;
  action: "create" | "update" | "unchanged";
  summary: string;
}

type Json = Record<string, unknown>;


async function readJson(path: string): Promise<Json | undefined> {
  try {
    return JSON.parse(await readFile(path, "utf8")) as Json;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw new Error(`${path} is not valid JSON, so it was left untouched. Fix it or add the entries by hand.`);
  }
}

function command(opts: SetupOptions): { cmd: string; args: string[]; shell: string } {
  if (opts.local) {
    const cli = resolve(dirname(fileURLToPath(import.meta.url)), "cli.js");
    return { cmd: "node", args: [cli], shell: `node "${cli}"` };
  }
  return { cmd: "npx", args: ["-y", "accessproof"], shell: "npx -y accessproof" };
}

interface HookEntry {
  matcher?: string;
  hooks: Array<{ type: string; command: string }>;
}

/** Adds `entry` unless an accessproof hook for the same sub-command (e.g. "hook prompt") is already there. */
function addHook(settings: Json, event: string, entry: HookEntry, sub: string): boolean {
  const hooks = (settings.hooks ??= {}) as Record<string, HookEntry[]>;
  const list = (hooks[event] ??= []);
  const ours = (cmd: string | undefined) => !!cmd && /accessproof|cli\.js/.test(cmd) && cmd.trimEnd().endsWith(sub);
  if (list.some((e) => e.hooks?.some((h) => ours(h.command)))) return false;
  list.push(entry);
  return true;
}

/** Wires accessproof into Claude Code for one project: MCP server, hooks, and the /secure skill. */
export async function setupClaude(root: string, opts: SetupOptions = {}): Promise<SetupChange[]> {
  const changes: SetupChange[] = [];
  const write = async (file: string, content: string) => {
    if (opts.dryRun) return;
    await mkdir(dirname(file), { recursive: true });
    await writeFile(file, content);
  };
  const c = command(opts);

  // ---- .mcp.json
  const mcpPath = join(root, ".mcp.json");
  const mcp = (await readJson(mcpPath)) ?? {};
  const servers = (mcp.mcpServers ??= {}) as Record<string, unknown>;
  if (servers.accessproof) {
    changes.push({ file: ".mcp.json", action: "unchanged", summary: "accessproof MCP server already configured" });
  } else {
    const existed = Object.keys(servers).length > 0;
    servers.accessproof = { command: c.cmd, args: [...c.args, "mcp"] };
    await write(mcpPath, JSON.stringify(mcp, null, 2) + "\n");
    changes.push({ file: ".mcp.json", action: existed ? "update" : "create", summary: "added the accessproof MCP server" });
  }

  // ---- .claude/settings.json hooks
  const settingsPath = join(root, ".claude", "settings.json");
  const existing = await readJson(settingsPath);
  const settings = existing ?? {};
  const a = addHook(settings, "UserPromptSubmit", { hooks: [{ type: "command", command: `${c.shell} hook prompt` }] }, "hook prompt");
  const b = addHook(
    settings,
    "PostToolUse",
    { matcher: "Edit|Write|MultiEdit", hooks: [{ type: "command", command: `${c.shell} hook post-edit` }] },
    "hook post-edit",
  );
  if (a || b) {
    await write(settingsPath, JSON.stringify(settings, null, 2) + "\n");
    changes.push({ file: ".claude/settings.json", action: existing ? "update" : "create", summary: "added the prompt guard and post-edit security check hooks" });
  } else {
    changes.push({ file: ".claude/settings.json", action: "unchanged", summary: "accessproof hooks already configured" });
  }

  // ---- /secure skill
  const skillSrc = resolve(dirname(fileURLToPath(import.meta.url)), "..", "skills", "secure", "SKILL.md");
  const skillDest = join(root, ".claude", "skills", "secure", "SKILL.md");
  const skill = await readFile(skillSrc, "utf8");
  let current: string | undefined;
  try {
    current = await readFile(skillDest, "utf8");
  } catch {
    /* new */
  }
  if (current === skill) changes.push({ file: ".claude/skills/secure/SKILL.md", action: "unchanged", summary: "/secure skill is up to date" });
  else {
    await write(skillDest, skill);
    changes.push({ file: ".claude/skills/secure/SKILL.md", action: current ? "update" : "create", summary: "installed the /secure skill" });
  }
  return changes;
}
