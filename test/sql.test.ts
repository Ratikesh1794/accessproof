import { describe, expect, it } from "vitest";
import { classifyExpr, effectiveForPolicies } from "../src/infer/policy.js";
import { emptySchema, parseSql, splitStatements } from "../src/infer/sql.js";

const parse = (sql: string) => {
  const s = emptySchema();
  parseSql(sql, "t.sql", s);
  return s;
};

describe("splitStatements", () => {
  it("ignores comments, keeps quoted semicolons and dollar-quoted bodies", () => {
    const out = splitStatements(`
      -- a comment; with semicolon
      create table a (x text default 'a;b'); /* block ; */
      create function f() returns void as $$ begin perform 1; end; $$ language plpgsql;
    `);
    expect(out).toHaveLength(2);
    expect(out[0]!.text).toContain("'a;b'");
    expect(out[1]!.text).toContain("perform 1;");
  });

  it("reports the line a statement starts on", () => {
    const out = splitStatements("\n\n-- c\ncreate table a (x int);\n\ncreate table b (y int);");
    expect(out.map((s) => s.line)).toEqual([4, 6]);
  });
});

describe("parseSql tables", () => {
  it("reads columns, types, defaults, references and primary keys", () => {
    const s = parse(`
      create table if not exists public.orders (
        id uuid primary key default gen_random_uuid(),
        user_id uuid not null references auth.users(id) on delete cascade,
        total numeric(10,2) not null default 0,
        note text,
        constraint orders_chk check (total >= 0)
      );`);
    const t = s.tables.get("public.orders")!;
    expect(t.columns.map((c) => c.name)).toEqual(["id", "user_id", "total", "note"]);
    expect(t.columns[0]).toMatchObject({ primaryKey: true, hasDefault: true, notNull: true });
    expect(t.columns[1]!.references).toEqual({ schema: "auth", table: "users", column: "id" });
    expect(t.columns[2]!.type).toBe("numeric(10,2)");
    expect(t.columns[3]).toMatchObject({ notNull: false, hasDefault: false });
  });

  it("applies table-level constraints and ALTER TABLE changes", () => {
    const s = parse(`
      create table "Posts" (id uuid, author uuid, title text, primary key (id));
      alter table "Posts" add column body text, add column slug text not null default '';
      alter table "Posts" add constraint fk foreign key (author) references auth.users(id);
      alter table "Posts" drop column title;
      alter table "Posts" enable row level security;`);
    const t = s.tables.get("public.posts")!;
    expect(t.rls).toBe(true);
    expect(t.columns.map((c) => c.name)).toEqual(["id", "author", "body", "slug"]);
    expect(t.columns[0]!.primaryKey).toBe(true);
    expect(t.columns[1]!.references?.table).toBe("users");
  });

  it("handles disabling RLS, dropping tables and policies", () => {
    const s = parse(`
      create table a (id int); alter table a enable row level security;
      create policy p on a for select using (true);
      alter table a disable row level security;
      create table b (id int);
      create policy q on b for select using (true);
      drop policy q on b;
      create table c (id int); drop table c;`);
    expect(s.tables.get("public.a")!.rls).toBe(false);
    expect(s.policies.map((p) => p.name)).toEqual(["p"]);
    expect(s.tables.has("public.c")).toBe(false);
  });
});

describe("parseSql policies", () => {
  it("parses command, roles, using and with check", () => {
    const s = parse(`
      create table t (id int, user_id uuid);
      create policy "own rows" on public.t as permissive for update to authenticated
        using (auth.uid() = user_id) with check ((select auth.uid()) = user_id);
      create policy open on t for select using (true);
      create policy strict on t as restrictive for all to anon, authenticated using (false);`);
    const [own, open, strict] = s.policies;
    expect(own).toMatchObject({ name: "own rows", command: "update", roles: ["authenticated"], permissive: true });
    expect(own!.using).toBe("auth.uid() = user_id");
    expect(own!.check).toBe("(select auth.uid()) = user_id");
    expect(open).toMatchObject({ command: "select", roles: ["public"] });
    expect(strict).toMatchObject({ permissive: false, roles: ["anon", "authenticated"], command: "all" });
  });

  it("reads storage buckets and storage.objects policies", () => {
    const s = parse(`
      insert into storage.buckets (id, name, public) values ('avatars','avatars', true), ('docs','docs', false);
      create policy r on storage.objects for select using (bucket_id = 'avatars');`);
    expect(s.buckets.get("avatars")!.public).toBe(true);
    expect(s.buckets.get("docs")!.public).toBe(false);
    expect(s.policies[0]).toMatchObject({ schema: "storage", table: "objects" });
  });
});

describe("classifyExpr", () => {
  it.each([
    ["true", "all"],
    ["false", "none"],
    ["auth.uid() = user_id", "own"],
    ["user_id = (select auth.uid())", "own"],
    ["auth.role() = 'authenticated'", "all"],
    ["auth.uid() is not null", "all"],
    ["some_custom_fn(id)", "unknown"],
    ["auth.uid() = user_id or is_public", "unknown"],
  ])("%s -> %s", (expr, level) => {
    expect(classifyExpr(expr).level).toBe(level);
  });

  it("finds the owner column and admin gates", () => {
    expect(classifyExpr("auth.uid() = author_id").ownerColumn).toBe("author_id");
    const admin = classifyExpr("exists (select 1 from profiles where profiles.id = auth.uid() and profiles.role = 'admin')");
    expect(admin).toMatchObject({ admin: true, level: "all" });
    expect(admin.adminSeed).toEqual({ table: "profiles", set: { role: "admin" } });
    const both = classifyExpr("auth.uid() = user_id or public.is_admin()");
    expect(both).toMatchObject({ level: "own", alsoAdmin: true, ownerColumn: "user_id" });
  });

  it("recognises storage folder ownership", () => {
    const e = classifyExpr("bucket_id = 'a' and (storage.foldername(name))[1] = auth.uid()::text");
    expect(e).toMatchObject({ level: "own", folderOwned: true, bucket: "a" });
  });
});

describe("effectiveForPolicies", () => {
  const pol = (sql: string) => parse(`create table t (id int, user_id uuid); ${sql}`).policies;

  it("RLS off means everyone gets everything", () => {
    const eff = effectiveForPolicies([], false);
    expect(eff.access.anon.delete).toBe("all");
    expect(eff.access.user.insert).toBe("all");
  });

  it("RLS on with no policies denies everything", () => {
    const eff = effectiveForPolicies([], true);
    expect(eff.access.user.read).toBe("none");
  });

  it("takes the most permissive policy per role and operation", () => {
    const eff = effectiveForPolicies(
      pol(`create policy a on t for select to authenticated using (auth.uid() = user_id);
           create policy b on t for select to authenticated using (true);`),
      true,
    );
    expect(eff.access.user.read).toBe("all");
    expect(eff.access.anon.read).toBe("none");
  });

  it("a signed-in-only expression never grants anon, even for TO public", () => {
    const eff = effectiveForPolicies(pol(`create policy a on t for update using (auth.role() = 'authenticated');`), true);
    expect(eff.access.anon.update).toBe("none");
    expect(eff.access.user.update).toBe("all");
  });

  it("for ALL policies uses USING for reads and WITH CHECK for inserts", () => {
    const eff = effectiveForPolicies(
      pol(`create policy a on t for all to authenticated using (auth.uid() = user_id) with check (true);`),
      true,
    );
    expect(eff.access.user.read).toBe("own");
    expect(eff.access.user.insert).toBe("all");
  });
});
