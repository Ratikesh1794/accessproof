import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { SEVERITY_ORDER } from "../findings.js";
import type { CaseResult, RunReport } from "./execute.js";

const ICON: Record<CaseResult["status"], string> = { pass: "✅", fail: "❌", "needs-review": "❓", skipped: "⏭️", error: "⚠️" };

const sevRank = (r: CaseResult) => (r.severity ? SEVERITY_ORDER.indexOf(r.severity) : 99);

export const failing = (r: RunReport) => r.results.filter((x) => x.status === "fail").sort((a, b) => sevRank(a) - sevRank(b));

/** Cases that point at an access-control problem, whether or not the rule is confirmed yet. */
export const problems = (r: RunReport) => r.results.filter((x) => x.status === "fail" || x.status === "needs-review").sort((a, b) => sevRank(a) - sevRank(b));

export function renderReport(r: RunReport): string {
  const s = r.summary;
  const out: string[] = [
    "# accessproof — test report",
    "",
    `Target: \`${r.target}\` · ${r.startedAt}`,
    "",
    `**${s.pass} passed · ${s.fail} failed · ${s["needs-review"]} need review · ${s.error} errors · ${s.skipped} skipped**`,
    "",
  ];
  if (r.warnings.length) out.push("## Warnings", "", ...r.warnings.map((w) => `- ${w}`), "");

  const bad = problems(r);
  if (bad.length) {
    out.push("## Problems found", "");
    for (const x of bad) {
      const tag = x.status === "needs-review" ? " _(rule not confirmed yet)_" : "";
      out.push(
        `### ${ICON[x.status]} ${x.failure === "exposure" ? "EXPOSED" : "BLOCKED"} · ${(x.severity ?? "").toUpperCase()} · \`${x.id}\`${tag}`,
        "",
        x.description,
        "",
        `- Expected: **${x.expect}** · Observed: **${x.observed}**`,
        x.evidence ? `- Proof: \`${x.evidence.request}\` → HTTP ${x.evidence.httpStatus ?? "?"} — ${x.evidence.note}` : "",
        "",
      );
    }
  }
  const errs = r.results.filter((x) => x.status === "error");
  if (errs.length) {
    out.push("## Could not be tested", "");
    for (const x of errs) out.push(`- \`${x.id}\` — ${x.message}`);
    out.push("");
  }
  out.push("## All checks", "", "| | Check | Expected | Observed |", "|---|---|---|---|");
  for (const x of r.results) out.push(`| ${ICON[x.status]} | \`${x.id}\` | ${x.expect} | ${x.observed ?? "—"} |`);
  return out.join("\n") + "\n";
}

/** Plain-English brief that an AI coding agent can act on directly. */
export function renderFailureBrief(r: RunReport): string {
  const bad = problems(r).filter((x) => x.failure === "exposure");
  const blocked = problems(r).filter((x) => x.failure === "blocked");
  if (!bad.length && !blocked.length) return "All access rules pass. Nothing to fix.\n";

  const byResource = new Map<string, CaseResult[]>();
  for (const x of [...bad, ...blocked]) byResource.set(x.resource, [...(byResource.get(x.resource) ?? []), x]);

  const out: string[] = [
    "# Access-control fixes needed",
    "",
    "These checks were run against a real Supabase instance. Each failure was PROVEN with a real request, not guessed.",
    "",
    "Rules for fixing:",
    "- Fix the cause (RLS policies in a NEW migration under supabase/migrations/, or the API route) — never edit `access.yml` to make a check pass. If you believe a rule is wrong, stop and ask the user.",
    "- Do not disable RLS, do not use the service_role key in client code, do not widen a policy to `using (true)`.",
    "- After fixing, re-run `npx accessproof test` and repeat until everything passes.",
    "",
  ];
  for (const [resource, items] of byResource) {
    out.push(`## ${resource}`, "");
    for (const x of items) {
      out.push(
        `- **${x.failure === "exposure" ? "Must be denied but was allowed" : "Should be allowed but was denied"}** (${x.severity}): ${x.description}`,
        x.evidence ? `  - proof: \`${x.evidence.request}\` → HTTP ${x.evidence.httpStatus ?? "?"}, ${x.evidence.note}` : "",
      );
    }
    out.push("");
  }
  return out.join("\n");
}

export async function writeReports(root: string, r: RunReport) {
  const dir = join(root, ".accessproof");
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "report.json"), JSON.stringify(r, null, 2));
  await writeFile(join(dir, "report.md"), renderReport(r));
  await writeFile(join(dir, "FIXES.md"), renderFailureBrief(r));
  return dir;
}

export async function readLastReport(root: string): Promise<RunReport | undefined> {
  try {
    return JSON.parse(await readFile(join(root, ".accessproof", "report.json"), "utf8")) as RunReport;
  } catch {
    return undefined;
  }
}
