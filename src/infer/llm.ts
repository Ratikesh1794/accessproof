import { z } from "zod";
import { AccessSpec, RuleSet, type Op } from "../spec/schema.js";

/**
 * Optional second pass: ask an LLM to sanity-check the heuristic draft.
 * It may only adjust rules/notes of resources that are still unconfirmed, and
 * its answer is validated before it is merged. Off unless `--llm` is passed.
 */

const Adjustment = z.object({
  resources: z
    .record(
      z.string(),
      z.object({
        rules: z.record(z.string(), RuleSet).optional(),
        reason: z.string().max(400).optional(),
      }),
    )
    .default({}),
});
export type Adjustment = z.infer<typeof Adjustment>;

export type Complete = (system: string, user: string) => Promise<string>;

export function anthropicComplete(apiKey: string, model = process.env.ACCESSPROOF_MODEL ?? "claude-sonnet-5-5"): Complete {
  return async (system, user) => {
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-key": apiKey, "anthropic-version": "2023-06-01" },
      body: JSON.stringify({ model, max_tokens: 4000, system, messages: [{ role: "user", content: user }] }),
    });
    if (!res.ok) throw new Error(`Anthropic API ${res.status}: ${(await res.text()).slice(0, 200)}`);
    const json = (await res.json()) as { content: Array<{ type: string; text?: string }> };
    return json.content.filter((b) => b.type === "text").map((b) => b.text ?? "").join("");
  };
}

const SYSTEM = `You review a draft access-control spec for a Next.js + Supabase app.
Levels per role and operation: none | own | all. "own" means rows owned by the signed-in user.
Return ONLY JSON: {"resources": {"<name>": {"rules": {"anon": {...}, "user": {...}}, "reason": "<one sentence>"}}}.
Only include resources whose rules you would CHANGE. Prefer the least access that still lets the app work.
Never grant access beyond what the schema, routes and column names suggest.`;

export function buildPrompt(spec: AccessSpec, context: string): string {
  return `Draft spec (YAML-like JSON):\n${JSON.stringify(spec.resources, null, 1)}\n\nProject context:\n${context}`;
}

export function parseAdjustment(text: string): Adjustment {
  const json = /\{[\s\S]*\}/.exec(text)?.[0];
  if (!json) return { resources: {} };
  return Adjustment.parse(JSON.parse(json));
}

export function applyAdjustment(spec: AccessSpec, adj: Adjustment): { spec: AccessSpec; changed: string[] } {
  const next = structuredClone(spec);
  const changed: string[] = [];
  for (const [name, a] of Object.entries(adj.resources)) {
    const res = next.resources[name];
    if (!res || res.confirmed || !a.rules) continue; // never touch confirmed rules or unknown resources
    const validRoles = Object.keys(next.roles);
    const rules = Object.fromEntries(Object.entries(a.rules).filter(([role]) => validRoles.includes(role)));
    if (!Object.keys(rules).length) continue;
    const merged = { ...res, rules, notes: `${res.notes ?? ""} (LLM review: ${a.reason ?? "adjusted"})`.trim() };
    const trial = { ...next, resources: { ...next.resources, [name]: merged } };
    if (!AccessSpec.safeParse(trial).success) continue; // e.g. "own" without an owner column
    next.resources[name] = merged as typeof res;
    changed.push(name);
  }
  return { spec: next, changed };
}

export async function refineWithLLM(spec: AccessSpec, context: string, complete: Complete) {
  const text = await complete(SYSTEM, buildPrompt(spec, context));
  return applyAdjustment(spec, parseAdjustment(text));
}

export const _ops: Op[] = ["read", "insert", "update", "delete"];
