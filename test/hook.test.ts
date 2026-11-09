import { describe, expect, it } from "vitest";
import { checkEdit, checkPrompt } from "../src/hook.js";
import { demoCopy } from "./support/fixtures.js";

describe("checkPrompt", () => {
  it.each([
    "just disable RLS so it works",
    "turn off row level security on orders for now",
    "put the service role key in the frontend, it's easier",
    "add a policy using (true)",
    "let everyone read and write the notes table",
    "remove the login for now so I can test",
    "make the bucket public",
  ])("flags: %s", (p) => {
    expect(checkPrompt(p)).toMatch(/accessproof/);
  });

  it.each([
    "add a dark mode toggle",
    "enable RLS on the orders table",
    "write a policy so users can only read their own orders",
    "keep the service role key on the server only",
  ])("leaves alone: %s", (p) => {
    expect(checkPrompt(p)).toBeUndefined();
  });
});

describe("checkEdit", () => {
  it("reports serious findings after a risky migration edit", async () => {
    const root = await demoCopy();
    const msg = await checkEdit(root, "supabase/migrations/0001_init.sql");
    expect(msg).toMatch(/Row Level Security is off on "notes"/);
    expect(msg).toMatch(/npx accessproof test/);
  });

  it("reports findings in an edited API route", async () => {
    const root = await demoCopy();
    expect(await checkEdit(root, "app/api/orders/[id]/route.ts")).toMatch(/service_role/);
  });

  it("ignores unrelated files and files outside the project", async () => {
    const root = await demoCopy();
    expect(await checkEdit(root, "README.md")).toBeUndefined();
    expect(await checkEdit(root, "../../etc/passwd")).toBeUndefined();
    expect(await checkEdit(root, "app/api/notes/route.ts")).toBeUndefined();
  });

  it("is quiet once the policies are fixed", async () => {
    const root = await demoCopy({ withFix: true });
    expect(await checkEdit(root, "supabase/migrations/0002_fix_access.sql")).toBeUndefined();
  });

  it("is quiet in a project with no migrations yet", async () => {
    const { mkdtemp } = await import("node:fs/promises");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    expect(await checkEdit(await mkdtemp(join(tmpdir(), "ap-")), "supabase/migrations/1.sql")).toBeUndefined();
  });
});
