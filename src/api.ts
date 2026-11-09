import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { severityAtLeast, type Finding, type Severity } from "./findings.js";
import { inferProject, writeInferOutputs, type InferResult } from "./infer/index.js";
import { parseProject } from "./infer/sql.js";
import { resolveConnection, type Connection, type ConnectionFlags } from "./runner/config.js";
import { runAccessTests, type RunReport } from "./runner/execute.js";
import { problems, readLastReport, renderFailureBrief, writeReports } from "./runner/report.js";
import { fetchTransport, type Transport } from "./runner/types.js";
import { loadSpec } from "./spec/load.js";
import { expandRule, OPS, type AccessSpec } from "./spec/schema.js";
import { describe as describeCase } from "./runner/plan.js";

/** Operations shared by the CLI and the MCP server. */

export async function inferToFiles(root: string, o: { out?: string; force?: boolean; llm?: boolean } = {}) {
  const result = await inferProject(root, { llm: o.llm });
  const files = await writeInferOutputs(root, result, { out: o.out ?? "access.yml", force: !!o.force });
  return { result, files };
}

export async function staticCheck(root: string, failOn: Severity = "high") {
  const result = await inferProject(root);
  const blocking = result.findings.filter((f) => severityAtLeast(f.severity, failOn));
  return { result, blocking };
}

export interface TestOptions extends ConnectionFlags {
  spec?: string;
  only?: string[];
  /** For tests: skip env/guard resolution and use this connection + transport. */
  connection?: Connection;
  transport?: Transport;
  onProgress?: Parameters<typeof runAccessTests>[0]["onProgress"];
}

export async function testProject(root: string, o: TestOptions = {}) {
  const specPath = join(root, o.spec ?? "access.yml");
  let spec: AccessSpec;
  try {
    spec = await loadSpec(specPath);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error(`${o.spec ?? "access.yml"} not found in ${root}. Run \`accessproof infer\` first, review the rules, then test.`);
    }
    throw e;
  }
  const schema = await parseProject(root);
  const conn = o.connection ?? (await resolveConnection(root, o));
  const transport = o.transport ?? fetchTransport(conn.url);

  try {
    await transport.send({ method: "GET", path: "/auth/v1/health", headers: { apikey: conn.anonKey } });
  } catch {
    throw new Error(`Could not reach ${conn.url}. Is local Supabase running? Start it with \`supabase start\`.`);
  }

  const report = await runAccessTests({
    spec,
    schema,
    transport,
    keys: { anon: conn.anonKey, service: conn.serviceKey },
    target: conn.url,
    only: o.only,
    onProgress: o.onProgress,
  });
  const dir = await writeReports(root, report);
  const unconfirmed = Object.entries(spec.resources).filter(([, r]) => !r.confirmed).map(([n]) => n);
  return { report, dir, unconfirmed };
}

export async function failureBrief(root: string): Promise<string> {
  const last = await readLastReport(root);
  if (!last) return "No test report yet. Run `accessproof test` (or the run_access_tests tool) first.\n";
  return renderFailureBrief(last);
}

const RULE_WORDS = { none: "never", own: "only their own", all: "all" } as const;

/** Plain-English summary of one resource: rules, why they were guessed, findings, last results. */
export async function explainRule(root: string, resource: string): Promise<string> {
  const spec = await loadSpec(join(root, "access.yml"));
  const res = spec.resources[resource];
  if (!res) return `No resource "${resource}" in access.yml. Known: ${Object.keys(spec.resources).join(", ")}.`;
  const lines = [`# ${resource} (${res.kind})`, "", `Status: ${res.confirmed ? "confirmed by a human" : "NOT yet confirmed — ask the user before relying on it"}`];
  if (res.notes) lines.push(`Why: ${res.notes}`);
  lines.push("", "Rules:");
  for (const role of Object.keys(spec.roles)) {
    const r = expandRule(res.rules[role]);
    lines.push(`- ${role}: ${OPS.map((op) => `${op} ${RULE_WORDS[r[op]]}`).join(", ")}`);
  }
  const last = await readLastReport(root);
  const mine = last ? problems(last).filter((x) => x.resource === resource) : [];
  if (mine.length) lines.push("", "Last test run found:", ...mine.map((x) => `- ${x.description} (${x.severity}, ${x.evidence?.note ?? ""})`));
  return lines.join("\n") + "\n";
}

export function summariseFindings(findings: Finding[], limit = 12): string {
  if (!findings.length) return "No static findings.";
  const shown = findings.slice(0, limit).map((f) => `- [${f.severity}] ${f.title}${f.file ? ` (${f.file}${f.line ? `:${f.line}` : ""})` : ""}`);
  if (findings.length > limit) shown.push(`…and ${findings.length - limit} more (see .accessproof/infer-report.md).`);
  return shown.join("\n");
}

export const rootOf = (dir?: string) => resolve(dir ?? ".");
export async function exists(path: string) {
  try {
    await readFile(path);
    return true;
  } catch {
    return false;
  }
}
export type { InferResult, RunReport };
export { describeCase };
