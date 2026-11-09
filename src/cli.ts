#!/usr/bin/env node
import { access, copyFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Command } from "commander";
import { rootOf, inferToFiles, staticCheck, summariseFindings, testProject } from "./api.js";
import { SEVERITY_ORDER, type Severity } from "./findings.js";
import { checkEdit, checkPrompt } from "./hook.js";
import { renderFindings } from "./infer/index.js";
import { setupClaude } from "./setup.js";
import { buildPlan, describe } from "./runner/plan.js";
import { problems } from "./runner/report.js";
import { loadSpec } from "./spec/load.js";

const color = !process.env.NO_COLOR && process.stdout.isTTY;
const c = (code: number, s: string) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);
const green = (s: string) => c(32, s);
const red = (s: string) => c(31, s);
const yellow = (s: string) => c(33, s);
const dim = (s: string) => c(2, s);
const bold = (s: string) => c(1, s);

const program = new Command()
  .name("accessproof")
  .description("Security tests your AI can't break — prove who can access what in your Next.js + Supabase app.")
  .version("0.1.0");

async function run(fn: () => Promise<void>) {
  try {
    await fn();
  } catch (e) {
    console.error(red("✖ ") + (e as Error).message);
    process.exit(2);
  }
}

const severityOpt = (v: string): Severity => {
  if (!SEVERITY_ORDER.includes(v as Severity)) throw new Error(`--fail-on must be one of ${SEVERITY_ORDER.join(", ")}`);
  return v as Severity;
};

program
  .command("init")
  .description("Create a starter access.yml you can edit by hand")
  .action(() =>
    run(async () => {
      try {
        await access("access.yml");
        throw new Error("access.yml already exists — not overwriting.");
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
      }
      await copyFile(join(dirname(fileURLToPath(import.meta.url)), "..", "examples", "access.yml"), "access.yml");
      console.log("Created access.yml (an example). Prefer `accessproof infer` to draft one from your own migrations.");
    }),
  );

program
  .command("infer")
  .argument("[dir]", "project root", ".")
  .option("-o, --out <file>", "where to write the spec", "access.yml")
  .option("--force", "overwrite an existing spec (confirmed rules are lost)")
  .option("--llm", "ask Claude to sanity-check the draft (needs ANTHROPIC_API_KEY)")
  .description("Read migrations + API routes and draft access.yml for you to review")
  .action((dir: string, opts: { out: string; force?: boolean; llm?: boolean }) =>
    run(async () => {
      const root = rootOf(dir);
      const { result, files } = await inferToFiles(root, opts);
      const n = Object.keys(result.spec.resources).length;
      console.log(green("✓") + ` Drafted ${bold(opts.out)} with ${n} resource${n === 1 ? "" : "s"} (all unconfirmed).`);
      for (const [name, e] of Object.entries(result.explain)) console.log(`  ${name.padEnd(18)} ${dim(`[${e.confidence}]`)} ${e.reasons[e.reasons.length - 1] ?? ""}`);
      console.log("\n" + bold("Static findings") + dim(" (read from code only; nothing was run)"));
      console.log(summariseFindings(result.findings));
      console.log(`\nNext: review ${opts.out} (set confirmed: true per resource), then run ${bold("accessproof test")}.`);
      console.log(dim(`Details: ${files.reportPath}`));
    }),
  );

program
  .command("check")
  .argument("[dir]", "project root", ".")
  .option("--fail-on <severity>", "exit 1 if a finding is at least this severe", severityOpt, "high" as Severity)
  .option("--json", "machine-readable output")
  .description("Fast static check (no database needed): RLS gaps, risky policies, leaked keys, unprotected routes")
  .action((dir: string, opts: { failOn: Severity; json?: boolean }) =>
    run(async () => {
      const { result, blocking } = await staticCheck(rootOf(dir), opts.failOn);
      if (opts.json) console.log(JSON.stringify({ findings: result.findings, blocking: blocking.length }, null, 2));
      else console.log(renderFindings(result.findings));
      process.exit(blocking.length ? 1 : 0);
    }),
  );

program
  .command("validate")
  .argument("[file]", "path to access.yml", "access.yml")
  .description("Check access.yml is well-formed")
  .action((file: string) =>
    run(async () => {
      const spec = await loadSpec(file);
      const pending = Object.entries(spec.resources).filter(([, r]) => !r.confirmed).map(([n]) => n);
      console.log(green("✓") + ` ${file} is valid — ${Object.keys(spec.resources).length} resources, ${Object.keys(spec.roles).length} roles.`);
      if (pending.length) console.log(yellow("!") + ` Needs human review: ${pending.join(", ")}`);
    }),
  );

program
  .command("plan")
  .argument("[file]", "path to access.yml", "access.yml")
  .option("--json", "output machine-readable JSON")
  .description("Show every check that `accessproof test` will run")
  .action((file: string, opts: { json?: boolean }) =>
    run(async () => {
      const plan = buildPlan(await loadSpec(file));
      if (opts.json) return console.log(JSON.stringify(plan, null, 2));
      for (const t of plan) console.log(`${t.unconfirmed ? "?" : " "} ${t.id.padEnd(34)} ${describe(t)}`);
      console.log(`\n${plan.length} checks (${plan.filter((t) => t.unconfirmed).length} from unconfirmed rules, marked ?).`);
    }),
  );

program
  .command("test")
  .argument("[dir]", "project root", ".")
  .option("-s, --spec <file>", "access spec, relative to the project", "access.yml")
  .option("--url <url>", "Supabase API URL (default http://127.0.0.1:54321)")
  .option("--anon-key <key>", "anon key (or SUPABASE_ANON_KEY)")
  .option("--service-key <key>", "service_role key (or SUPABASE_SERVICE_ROLE_KEY)")
  .option("--allow-remote <host...>", "hostnames of throwaway STAGING projects you own that may be tested")
  .option("--only <resource...>", "test only these resources")
  .option("--strict", "unconfirmed rules also fail the run")
  .option("--json", "print the full report as JSON")
  .description("Create test users on LOCAL/STAGING Supabase and prove every rule with real requests")
  .action((dir: string, opts: { spec: string; url?: string; anonKey?: string; serviceKey?: string; allowRemote?: string[]; only?: string[]; strict?: boolean; json?: boolean }) =>
    run(async () => {
      const root = rootOf(dir);
      const { report, dir: out, unconfirmed } = await testProject(root, {
        ...opts,
        onProgress: (done, total) => {
          if (!opts.json && process.stdout.isTTY) process.stdout.write(`\r${dim(`running checks ${done}/${total}`)}`);
        },
      });
      if (process.stdout.isTTY && !opts.json) process.stdout.write("\r\x1b[K");

      if (opts.json) console.log(JSON.stringify(report, null, 2));
      else {
        const s = report.summary;
        console.log(`${bold("accessproof")} · ${report.target}`);
        console.log(`${green(`${s.pass} passed`)} · ${s.fail ? red(`${s.fail} failed`) : "0 failed"} · ${s["needs-review"] ? yellow(`${s["needs-review"]} need review`) : "0 need review"} · ${s.error} errors · ${s.skipped} skipped\n`);
        for (const r of problems(report).slice(0, 15)) {
          const tag = r.status === "needs-review" ? yellow("REVIEW") : red(r.failure === "exposure" ? "EXPOSED" : "BLOCKED");
          console.log(`  ${tag} ${dim(`[${r.severity}]`)} ${r.description}\n         ${dim(r.evidence ? `${r.evidence.request} → ${r.evidence.note}` : "")}`);
        }
        const more = problems(report).length - 15;
        if (more > 0) console.log(dim(`  …and ${more} more`));
        for (const r of report.results.filter((x) => x.status === "error").slice(0, 5)) console.log(`  ${yellow("COULD NOT TEST")} ${r.id}: ${r.message}`);
        for (const w of report.warnings) console.log(yellow("! ") + w);
        if (unconfirmed.length) console.log(yellow("\n! ") + `Unconfirmed rules (${unconfirmed.join(", ")}) are reported as REVIEW, not failures. Confirm them in access.yml.`);
        console.log(dim(`\nFull report: ${out}/report.md · Fix brief for Claude Code: ${out}/FIXES.md`));
      }
      const s = report.summary;
      process.exit(s.fail > 0 || (opts.strict && s["needs-review"] > 0) ? 1 : s.error > 0 ? 2 : 0);
    }),
  );

program
  .command("hook")
  .argument("<event>", "prompt | post-edit")
  .option("--block", "block risky prompts instead of only warning the agent")
  .description("Claude Code hook entry point (reads the hook JSON on stdin)")
  .action(async (event: string, opts: { block?: boolean }) => {
    let input: { prompt?: string; cwd?: string; tool_input?: { file_path?: string } } = {};
    try {
      const chunks: Buffer[] = [];
      for await (const ch of process.stdin) chunks.push(ch as Buffer);
      input = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
    } catch {
      /* no/invalid stdin: nothing to do */
    }
    if (event === "prompt") {
      const advice = input.prompt ? checkPrompt(input.prompt) : undefined;
      if (!advice) return;
      if (opts.block) {
        console.error(advice);
        process.exit(2);
      }
      console.log(JSON.stringify({ hookSpecificOutput: { hookEventName: "UserPromptSubmit", additionalContext: advice } }));
    } else if (event === "post-edit") {
      const file = input.tool_input?.file_path;
      const msg = file ? await checkEdit(input.cwd ?? process.cwd(), file) : undefined;
      if (msg) {
        console.error(msg);
        process.exit(2);
      }
    } else {
      console.error(`Unknown hook event "${event}". Use prompt or post-edit.`);
      process.exit(2);
    }
  });

program
  .command("setup-claude")
  .argument("[dir]", "project root", ".")
  .option("--local", "point at this checkout instead of `npx accessproof` (before the package is published)")
  .option("--dry-run", "show what would change without writing")
  .description("Wire accessproof into Claude Code for this project: MCP server, hooks, and the /secure skill")
  .action((dir: string, opts: { local?: boolean; dryRun?: boolean }) =>
    run(async () => {
      const changes = await setupClaude(rootOf(dir), opts);
      for (const ch of changes) console.log(`${ch.action === "unchanged" ? dim("·") : green("✓")} ${ch.file.padEnd(34)} ${ch.summary}${opts.dryRun && ch.action !== "unchanged" ? dim(" (dry run)") : ""}`);
      console.log(`\nIn Claude Code, ask: ${bold("/secure")}  (or "secure my app").`);
    }),
  );

program
  .command("mcp")
  .description("Run the MCP server (stdio) so Claude Code / Cursor can call accessproof as tools")
  .action(() =>
    run(async () => {
      const { startMcpServer } = await import("./mcp/server.js");
      await startMcpServer();
    }),
  );

program.parseAsync();
