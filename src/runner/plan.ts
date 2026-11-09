import { AccessSpec, OPS, Op, expandRule } from "../spec/schema.js";

/**
 * One executable assertion: "acting as <role>, <op> on a row owned by <target>
 * should be <expect>". `target` is whose data we touch:
 *  - self:  a row owned by this role's own test user
 *  - other: a row owned by a different test user
 */
export interface TestCase {
  id: string;
  resource: string;
  kind: string;
  role: string;
  op: Op;
  target: "self" | "other";
  /** The resource has no owner concept, so "other" simply means "any row". */
  ownerless: boolean;
  expect: "allow" | "deny";
  unconfirmed: boolean;
}

export function buildPlan(spec: AccessSpec): TestCase[] {
  const cases: TestCase[] = [];
  for (const [resource, res] of Object.entries(spec.resources)) {
    for (const role of Object.keys(spec.roles)) {
      const levels = expandRule(res.rules[role]);
      const ownerless =
        (res.kind === "table" && !res.owner) || (res.kind === "bucket" && !res.owner_path);
      for (const op of OPS) {
        const level = levels[op];
        // anon owns nothing, so only the "other" target is meaningful.
        // ownerless resources have no "own" rows either, so one target covers every row.
        const targets: Array<"self" | "other"> = role === "anon" || ownerless ? ["other"] : ["self", "other"];
        for (const target of targets) {
          const expect =
            level === "all" ? "allow" : level === "own" && target === "self" ? "allow" : "deny";
          cases.push({
            id: `${resource}.${role}.${op}.${target}`,
            resource,
            kind: res.kind,
            role,
            op,
            target,
            expect,
            ownerless,
            unconfirmed: !res.confirmed,
          });
        }
      }
    }
  }
  return cases;
}

/** Plain-English sentence for reports and for the AI fix loop. */
export function describe(c: TestCase): string {
  const who = c.role === "anon" ? "A signed-out visitor" : c.role === "user" ? "A signed-in user" : `A user with the "${c.role}" role`;
  const whose = c.ownerless ? "any" : c.target === "self" ? "their own" : "another user's";
  const verb = c.expect === "allow" ? "should be able to" : "must NOT be able to";
  return `${who} ${verb} ${c.op} ${whose} ${c.resource} ${c.kind === "bucket" ? "files" : "rows"}.`;
}
