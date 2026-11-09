import { z } from "zod";

/**
 * Access levels for one operation:
 *  - none: the role must NOT be able to perform it on any row/object
 *  - own:  allowed on rows the role's test user owns, denied on other users' rows
 *  - all:  allowed on every row, including other users'
 * Operations left out of a rule default to `none` (deny by default).
 */
export const Level = z.enum(["none", "own", "all"]);
export type Level = z.infer<typeof Level>;

export const OPS = ["read", "insert", "update", "delete"] as const;
export type Op = (typeof OPS)[number];

export const RuleSet = z
  .object({
    read: Level.optional(),
    insert: Level.optional(),
    update: Level.optional(),
    delete: Level.optional(),
  })
  .strict();

const Rules = z.record(z.string(), RuleSet);

const Base = {
  confirmed: z.boolean().default(false),
  notes: z.string().optional(),
  rules: Rules,
};

export const TableResource = z
  .object({
    kind: z.literal("table"),
    owner: z.string().optional(),
    /** Optional row template used when seeding test rows. `{uid}` is replaced with the row owner's id. */
    seed: z.record(z.string(), z.unknown()).optional(),
    ...Base,
  })
  .strict();

export const BucketResource = z
  .object({ kind: z.literal("bucket"), owner_path: z.string().optional(), ...Base })
  .strict();

// Planned for v0.2: API routes that wrap a table.
export const RouteResource = z
  .object({
    kind: z.literal("route"),
    method: z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]),
    path: z.string(),
    backs: z.string().describe("table resource this route reads/writes"),
    ...Base,
  })
  .strict();

export const Resource = z.discriminatedUnion("kind", [TableResource, BucketResource, RouteResource]);
export type Resource = z.infer<typeof Resource>;

export const Role = z
  .object({
    description: z.string().optional(),
    seed: z
      .object({
        /** Make the test user an admin by upserting `set` into this table (row keyed by the user id). */
        table: z.string().optional(),
        set: z.record(z.string(), z.unknown()).optional(),
        /** Or by setting auth app_metadata (e.g. { role: admin }). */
        app_metadata: z.record(z.string(), z.unknown()).optional(),
      })
      .strict()
      .optional(),
  })
  .strict();

export const AccessSpec = z
  .object({
    version: z.literal(1),
    project: z
      .object({ framework: z.enum(["nextjs"]), backend: z.enum(["supabase"]) })
      .strict(),
    roles: z.record(z.string(), Role),
    resources: z.record(z.string(), Resource),
  })
  .strict()
  .superRefine((spec, ctx) => {
    const roles = new Set(Object.keys(spec.roles));
    for (const [name, res] of Object.entries(spec.resources)) {
      for (const [role, rule] of Object.entries(res.rules)) {
        if (!roles.has(role)) {
          ctx.addIssue({ code: "custom", path: ["resources", name, "rules", role], message: `unknown role "${role}"` });
        }
        const usesOwn = Object.values(rule).includes("own");
        const hasOwner = (res.kind === "table" && res.owner) || (res.kind === "bucket" && res.owner_path) || res.kind === "route";
        if (usesOwn && !hasOwner) {
          ctx.addIssue({ code: "custom", path: ["resources", name], message: `uses "own" but no owner column/path is set` });
        }
        if (role === "anon" && usesOwn) {
          ctx.addIssue({ code: "custom", path: ["resources", name, "rules", "anon"], message: `anon can't own rows; use none or all` });
        }
      }
    }
  });
export type AccessSpec = z.infer<typeof AccessSpec>;

/** Fill in defaults so every role has an explicit level for every op. */
export function expandRule(rule: z.infer<typeof RuleSet> | undefined): Record<Op, Level> {
  return Object.fromEntries(OPS.map((op) => [op, rule?.[op] ?? "none"])) as Record<Op, Level>;
}
