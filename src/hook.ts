import { relative, resolve } from "node:path";
import { severityAtLeast, type Finding } from "./findings.js";
import { inferProject } from "./infer/index.js";

/**
 * Claude Code hook logic. Two jobs:
 *  - prompt:    when the user asks for something that weakens access control, remind the agent to
 *               do it safely instead of taking the shortcut ("disable RLS so it works").
 *  - post-edit: after a migration / API route / env file is edited, re-run the fast static checks
 *               and feed serious findings straight back to the agent.
 */

const RISKY: Array<{ re: RegExp; why: string }> = [
  { re: /\b(disable|turn\s+off|remove|drop|skip|bypass)\s+(the\s+)?(rls|row[\s-]*level(\s+security)?)\b/i, why: "disables Row Level Security" },
  { re: /service[_\s-]*role[^.\n]{0,60}\b(front[\s-]*end|client|browser|public)\b|\b(front[\s-]*end|client|browser)\b[^.\n]{0,60}service[_\s-]*role/i, why: "puts the service_role key where visitors can read it" },
  { re: /\busing\s*\(\s*true\s*\)/i, why: "adds an allow-everything policy" },
  { re: /\b(allow|let)\s+(all|everyone|anyone|any\s+user)\s+(to\s+)?(read|write|edit|update|delete|access)/i, why: "grants access to everyone" },
  { re: /\b(remove|disable|skip)\s+(the\s+)?(login|auth(entication)?)\b[^.\n]{0,30}(for now|temporar|to debug|to test)/i, why: "removes authentication" },
  { re: /\bmake\s+(it|everything|the\s+(table|bucket|database))\s+public\b/i, why: "makes data public" },
];

export function checkPrompt(prompt: string): string | undefined {
  const hits = RISKY.filter((r) => r.re.test(prompt)).map((r) => r.why);
  if (!hits.length) return undefined;
  return (
    `accessproof: this request ${hits.join(" and ")}. Do not take that shortcut. ` +
    "Fix the underlying problem with a narrowly scoped policy (compare auth.uid() with the owner column), keep the service_role key on the server, " +
    "and run `npx accessproof test` afterwards. Explain the risk to the user before doing anything that widens access."
  );
}

const WATCHED = /(^|\/)(supabase\/migrations\/[^/]+\.sql|supabase\/[^/]+\.sql|app\/.*\/route\.[cm]?[jt]sx?|pages\/api\/.*|\.env[^/]*)$/;
const POLICY_IDS = new Set(["rls-disabled", "policy-too-permissive", "bucket-too-permissive", "sensitive-column-writable"]);

export async function checkEdit(cwd: string, filePath: string): Promise<string | undefined> {
  const root = resolve(cwd);
  const rel = relative(root, resolve(root, filePath));
  if (rel.startsWith("..") || !WATCHED.test(rel)) return undefined;

  let findings: Finding[];
  try {
    findings = (await inferProject(root)).findings;
  } catch {
    return undefined; // no migrations yet: nothing to check
  }
  const isSql = rel.endsWith(".sql");
  const relevant = findings.filter(
    (f) => severityAtLeast(f.severity, "high") && (f.file === rel || (isSql && POLICY_IDS.has(f.id))),
  );
  if (!relevant.length) return undefined;
  return (
    `accessproof found access-control problems after editing ${rel}:\n` +
    relevant.map((f) => `- [${f.severity}] ${f.title}${f.fix ? ` — ${f.fix}` : ""}`).join("\n") +
    "\nFix these (new migration / route change) before continuing, then run `npx accessproof test`."
  );
}
