import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { stringify } from "yaml";
import { sortFindings, type Finding } from "../findings.js";
import type { AccessSpec } from "../spec/schema.js";
import { draftSpec, type Draft } from "./heuristics.js";
import { anthropicComplete, refineWithLLM, type Complete } from "./llm.js";
import { scanCode, type RouteInfo } from "./routes.js";
import { parseProject, type ParsedSchema } from "./sql.js";

export interface InferOptions {
  llm?: boolean;
  complete?: Complete;
}

export interface InferResult extends Draft {
  schema: ParsedSchema;
  routes: RouteInfo[];
  llmChanged: string[];
}

export async function inferProject(root: string, opts: InferOptions = {}): Promise<InferResult> {
  const schema = await parseProject(root);
  if (schema.files.length === 0) {
    throw new Error(`No SQL found. Expected supabase/migrations/*.sql under ${root}. Run \`supabase db pull\` to export your schema.`);
  }
  const code = await scanCode(root);
  const draft = draftSpec(schema);
  let spec = draft.spec;
  let llmChanged: string[] = [];

  if (opts.llm) {
    const key = process.env.ANTHROPIC_API_KEY;
    const complete = opts.complete ?? (key ? anthropicComplete(key) : undefined);
    if (!complete) throw new Error("--llm needs ANTHROPIC_API_KEY set.");
    const context = code.routes
      .map((r) => `${r.methods.join("/") || "-"} ${r.route} tables=[${r.tables.join(",")}] auth=${r.checksAuth} serviceRole=${r.usesServiceRole}`)
      .join("\n");
    const out = await refineWithLLM(spec, context || "(no API routes found)", complete);
    spec = out.spec;
    llmChanged = out.changed;
  }

  return {
    ...draft,
    spec,
    findings: sortFindings([...draft.findings, ...code.findings]),
    schema,
    routes: code.routes,
    llmChanged,
  };
}

export function renderYaml(spec: AccessSpec): string {
  const header = [
    "# access.yml — who may do what in this app.",
    "# Drafted by `accessproof infer`. Every resource is `confirmed: false` until YOU review it:",
    "#   - read each `notes` line, fix the rules if the guess is wrong, then set `confirmed: true`.",
    "#   - then run `accessproof test` to prove the rules against a local/staging Supabase.",
    "# Levels: none = never, own = only rows the user owns, all = every row.",
    "",
  ].join("\n");
  return header + stringify(spec, { lineWidth: 0 });
}

const SEV_ICON: Record<Finding["severity"], string> = { critical: "🔴", high: "🟠", medium: "🟡", low: "🔵", info: "⚪" };

export function renderFindings(findings: Finding[]): string {
  if (!findings.length) return "_No static findings._\n";
  return findings
    .map((f) => {
      const loc = f.file ? ` \`${f.file}${f.line ? `:${f.line}` : ""}\`` : "";
      return `- ${SEV_ICON[f.severity]} **${f.severity.toUpperCase()}** — ${f.title}${loc}\n  ${f.detail}${f.fix ? `\n  _Fix:_ ${f.fix}` : ""}`;
    })
    .join("\n");
}

export function renderInferReport(r: InferResult): string {
  const lines: string[] = ["# accessproof — infer report", ""];
  lines.push(`Read ${r.schema.files.length} SQL file(s), ${r.schema.tables.size} table(s), ${r.schema.policies.length} polic${r.schema.policies.length === 1 ? "y" : "ies"}, ${r.routes.length} API route(s)/server action(s).`, "");
  lines.push("## Review these rules (2 minutes)", "", "Open `access.yml`, check each guess, then set `confirmed: true`.", "");
  lines.push("| Resource | Confidence | Why |", "|---|---|---|");
  for (const [name, e] of Object.entries(r.explain)) {
    lines.push(`| \`${name}\` | ${e.confidence} | ${e.reasons.join(" ").replace(/\|/g, "\\|")} |`);
  }
  if (r.llmChanged.length) lines.push("", `LLM review adjusted: ${r.llmChanged.map((n) => `\`${n}\``).join(", ")}.`);
  lines.push("", "## Static findings", "", "Found by reading code and migrations only; nothing was run. `accessproof test` proves them for real.", "", renderFindings(r.findings));
  return lines.join("\n") + "\n";
}

export async function writeInferOutputs(root: string, r: InferResult, opts: { out: string; force: boolean }) {
  const specPath = join(root, opts.out);
  let exists = false;
  try {
    await readFile(specPath);
    exists = true;
  } catch {
    /* new file */
  }
  if (exists && !opts.force) {
    throw new Error(`${opts.out} already exists. Re-run with --force to overwrite (your confirmed rules would be lost).`);
  }
  await writeFile(specPath, renderYaml(r.spec));
  const dir = join(root, ".accessproof");
  await mkdir(dir, { recursive: true });
  const reportPath = join(dir, "infer-report.md");
  await writeFile(reportPath, renderInferReport(r));
  return { specPath, reportPath };
}
