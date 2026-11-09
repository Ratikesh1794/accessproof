import { describe as suite, it, expect } from "vitest";
import { AccessSpec } from "../src/spec/schema.js";
import { buildPlan } from "../src/runner/plan.js";

const base = {
  version: 1,
  project: { framework: "nextjs", backend: "supabase" },
  roles: { anon: {}, user: {} },
};

suite("buildPlan", () => {
  it("own = allow on self, deny on other", () => {
    const spec = AccessSpec.parse({
      ...base,
      resources: { orders: { kind: "table", owner: "user_id", confirmed: true, rules: { user: { read: "own" } } } },
    });
    const plan = buildPlan(spec);
    expect(plan.find((c) => c.id === "orders.user.read.self")?.expect).toBe("allow");
    expect(plan.find((c) => c.id === "orders.user.read.other")?.expect).toBe("deny");
  });

  it("unspecified ops and roles default to deny", () => {
    const spec = AccessSpec.parse({
      ...base,
      resources: { orders: { kind: "table", owner: "user_id", rules: {} } },
    });
    expect(buildPlan(spec).every((c) => c.expect === "deny")).toBe(true);
  });

  it("anon only gets 'other' targets", () => {
    const spec = AccessSpec.parse({
      ...base,
      resources: { posts: { kind: "table", rules: { anon: { read: "all" } } } },
    });
    expect(buildPlan(spec).filter((c) => c.role === "anon").every((c) => c.target === "other")).toBe(true);
  });

  it("rejects 'own' without an owner column", () => {
    const r = AccessSpec.safeParse({
      ...base,
      resources: { orders: { kind: "table", rules: { user: { read: "own" } } } },
    });
    expect(r.success).toBe(false);
  });

  it("rejects unknown roles", () => {
    const r = AccessSpec.safeParse({
      ...base,
      resources: { orders: { kind: "table", owner: "user_id", rules: { staff: { read: "all" } } } },
    });
    expect(r.success).toBe(false);
  });
});
