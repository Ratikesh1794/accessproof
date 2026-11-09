import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { explainRule, failureBrief, inferToFiles, rootOf, staticCheck, summariseFindings, testProject } from "../api.js";
import { problems } from "../runner/report.js";

const INSTRUCTIONS = `accessproof checks who can access what in a Next.js + Supabase app.
Workflow for "secure my app":
1. infer_policy → drafts access.yml. SHOW the drafted rules to the user in plain English and ask them to confirm or correct each one. Only the user may set \`confirmed: true\`. Never edit access.yml to make a check pass.
2. run_access_tests → proves every rule with real requests against LOCAL Supabase. It refuses non-local targets.
3. get_failures → exact problems and proof. Fix the cause (new migration / route change), then run_access_tests again until everything passes.`;

const text = (t: string) => ({ content: [{ type: "text" as const, text: t }] });
const fail = (e: unknown) => ({ isError: true, content: [{ type: "text" as const, text: (e as Error).message }] });

const rootArg = z.string().optional().describe("Project root (default: current directory)");

export function buildServer(): McpServer {
  const server = new McpServer({ name: "accessproof", version: "0.1.0" }, { instructions: INSTRUCTIONS });

  server.registerTool(
    "infer_policy",
    {
      title: "Draft access.yml",
      description:
        "Read supabase/migrations and API routes and draft access.yml (who may read/insert/update/delete what). All rules start unconfirmed. Show them to the user for confirmation; do not confirm them yourself.",
      inputSchema: { root: rootArg, force: z.boolean().optional().describe("Overwrite an existing access.yml (loses confirmed rules)") },
      annotations: { readOnlyHint: false, destructiveHint: false },
    },
    async ({ root, force }) => {
      try {
        const { result, files } = await inferToFiles(rootOf(root), { force });
        const lines = Object.entries(result.explain).map(([n, e]) => `- ${n} [${e.confidence} confidence]: ${e.reasons.join(" ")}`);
        return text(
          `Drafted ${files.specPath} (all unconfirmed). Ask the user to review:\n${lines.join("\n")}\n\nStatic findings:\n${summariseFindings(result.findings)}\n\nFull details: ${files.reportPath}`,
        );
      } catch (e) {
        return fail(e);
      }
    },
  );

  server.registerTool(
    "static_check",
    {
      title: "Fast static security check",
      description: "No database needed. Finds RLS-off tables, over-permissive policies, leaked service_role keys and unprotected service_role routes by reading code and migrations.",
      inputSchema: { root: rootArg },
      annotations: { readOnlyHint: true },
    },
    async ({ root }) => {
      try {
        return text(summariseFindings((await staticCheck(rootOf(root))).result.findings, 40));
      } catch (e) {
        return fail(e);
      }
    },
  );

  server.registerTool(
    "run_access_tests",
    {
      title: "Prove access rules against local Supabase",
      description:
        "Creates throwaway test users on LOCAL Supabase, makes real requests as each role, and checks the outcome against access.yml. Refuses non-local targets. Keys come from the environment (SUPABASE_ANON_KEY, SUPABASE_SERVICE_ROLE_KEY).",
      inputSchema: {
        root: rootArg,
        only: z.array(z.string()).optional().describe("Test only these resources"),
        url: z.string().optional().describe("Local Supabase API URL (default http://127.0.0.1:54321)"),
      },
      annotations: { readOnlyHint: false, destructiveHint: false },
    },
    async ({ root, only, url }) => {
      try {
        const r = rootOf(root);
        const { report, unconfirmed } = await testProject(r, { only, url });
        const s = report.summary;
        const bad = problems(report).slice(0, 20).map((x) => `- [${x.severity}] ${x.status === "needs-review" ? "(unconfirmed rule) " : ""}${x.description} — ${x.evidence?.note ?? ""}`);
        return text(
          `${s.pass} passed, ${s.fail} failed, ${s["needs-review"]} need review, ${s.error} errors.\n` +
            (bad.length ? `\nProblems:\n${bad.join("\n")}\n\nCall get_failures for the full fix brief.` : "\nEverything passes.") +
            (unconfirmed.length ? `\n\nUnconfirmed rules (ask the user to confirm): ${unconfirmed.join(", ")}` : "") +
            (report.warnings.length ? `\n\nWarnings:\n${report.warnings.join("\n")}` : ""),
        );
      } catch (e) {
        return fail(e);
      }
    },
  );

  server.registerTool(
    "get_failures",
    {
      title: "Get the fix brief from the last test run",
      description: "Returns each failing check in plain English with the request that proved it, plus rules for fixing safely.",
      inputSchema: { root: rootArg },
      annotations: { readOnlyHint: true },
    },
    async ({ root }) => {
      try {
        return text(await failureBrief(rootOf(root)));
      } catch (e) {
        return fail(e);
      }
    },
  );

  server.registerTool(
    "explain_rule",
    {
      title: "Explain one resource's rules",
      description: "Plain-English rules for a table or bucket, why they were guessed, and what the last test run found.",
      inputSchema: { root: rootArg, resource: z.string().describe("Table or bucket name from access.yml") },
      annotations: { readOnlyHint: true },
    },
    async ({ root, resource }) => {
      try {
        return text(await explainRule(rootOf(root), resource));
      } catch (e) {
        return fail(e);
      }
    },
  );

  return server;
}

export async function startMcpServer(): Promise<void> {
  await buildServer().connect(new StdioServerTransport());
}
