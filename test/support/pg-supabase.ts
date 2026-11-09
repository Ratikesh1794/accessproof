import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";
import pg from "pg";
import type { HttpRequest, HttpResponse, Transport } from "../../src/runner/types.js";

/**
 * A TEST DOUBLE, not Supabase. It accepts the same HTTP-shaped requests the runner sends and
 * executes them in real PostgreSQL as the anon / authenticated / service_role roles with the
 * JWT claims set, so Row Level Security policies are evaluated by Postgres itself.
 *
 * What it does NOT cover: PostgREST's HTTP layer and Supabase Auth/Storage services.
 */
export const KEYS = { anon: "emu-anon", service: "emu-service" };

const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;
const quote = (s: string) => {
  if (!IDENT.test(s)) throw new Error(`bad identifier ${s}`);
  return `"${s}"`;
};

const json = (status: number, body: unknown): HttpResponse => ({ status, headers: {}, body });
const text = (status: number, body: string): HttpResponse => ({ status, headers: {}, body });

export async function createDatabase(adminUrl: string, name: string): Promise<string> {
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  await admin.query(`drop database if exists ${quote(name)} with (force)`);
  await admin.query(`create database ${quote(name)}`);
  await admin.end();
  const u = new URL(adminUrl);
  u.pathname = `/${name}`;
  return u.toString();
}

export async function dropDatabase(adminUrl: string, name: string): Promise<void> {
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  await admin.query(`drop database if exists ${quote(name)} with (force)`);
  await admin.end();
}

export async function applySql(pool: pg.Pool, ...files: string[]): Promise<void> {
  for (const f of files) await pool.query(await readFile(f, "utf8"));
}

export async function migrationFiles(dir: string): Promise<string[]> {
  return (await readdir(dir)).filter((f) => f.endsWith(".sql")).sort().map((f) => join(dir, f));
}

interface Session {
  role: "anon" | "authenticated" | "service_role";
  claims: Record<string, unknown>;
}

export class PgSupabase implements Transport {
  constructor(private readonly pool: pg.Pool) {}

  private async session(req: HttpRequest): Promise<Session | undefined> {
    const bearer = /^Bearer (.+)$/.exec(req.headers?.authorization ?? "")?.[1];
    if (bearer === KEYS.anon) return { role: "anon", claims: { role: "anon" } };
    if (bearer === KEYS.service) return { role: "service_role", claims: { role: "service_role" } };
    const id = /^emu\.(.+)$/.exec(bearer ?? "")?.[1];
    if (!id) return undefined;
    const r = await this.pool.query("select raw_app_meta_data from auth.users where id = $1", [id]);
    if (!r.rowCount) return undefined;
    return { role: "authenticated", claims: { sub: id, role: "authenticated", app_metadata: r.rows[0].raw_app_meta_data } };
  }

  private async as<T>(s: Session, fn: (c: pg.PoolClient) => Promise<T>): Promise<T> {
    const c = await this.pool.connect();
    try {
      await c.query("begin");
      await c.query(`set local role ${s.role}`);
      await c.query("select set_config('request.jwt.claims', $1, true)", [JSON.stringify(s.claims)]);
      const out = await fn(c);
      await c.query("commit");
      return out;
    } catch (e) {
      await c.query("rollback").catch(() => undefined);
      throw e;
    } finally {
      c.release();
    }
  }

  async send(req: HttpRequest): Promise<HttpResponse> {
    const url = new URL(req.path, "http://emu");
    const p = url.pathname;
    try {
      if (p.startsWith("/auth/v1/")) return await this.auth(req, url);
      const s = await this.session(req);
      if (!s) return json(401, { message: "Invalid token" });
      if (p.startsWith("/rest/v1/")) return await this.rest(req, url, s);
      if (p.startsWith("/storage/v1/")) return await this.storage(req, url, s);
      return json(404, { message: "not found" });
    } catch (e) {
      const err = e as { code?: string; message: string };
      return json(400, { code: err.code, message: err.message });
    }
  }

  // --------------------------------------------------------------------- auth
  private async auth(req: HttpRequest, url: URL): Promise<HttpResponse> {
    const body = (req.body ?? {}) as { email?: string; app_metadata?: object };
    if (req.method === "POST" && url.pathname === "/auth/v1/admin/users") {
      const r = await this.pool.query("insert into auth.users (email, raw_app_meta_data) values ($1, $2) returning id", [body.email, body.app_metadata ?? {}]);
      return json(200, { id: r.rows[0].id });
    }
    const del = /^\/auth\/v1\/admin\/users\/(.+)$/.exec(url.pathname);
    if (req.method === "DELETE" && del) {
      await this.pool.query("delete from auth.users where id = $1", [del[1]]);
      return json(200, {});
    }
    if (req.method === "POST" && url.pathname === "/auth/v1/token") {
      const r = await this.pool.query("select id from auth.users where email = $1", [body.email]);
      if (!r.rowCount) return json(400, { error_description: "Invalid login credentials" });
      return json(200, { access_token: `emu.${r.rows[0].id}` });
    }
    return json(404, { message: "not found" });
  }

  // --------------------------------------------------------------------- rest
  private denied(s: Session, e: { code?: string; message: string }): HttpResponse {
    if (e.code === "42501") return json(s.role === "anon" ? 401 : 403, { code: e.code, message: e.message });
    if (e.code === "23505" || e.code === "23503") return json(409, { code: e.code, message: e.message });
    return json(400, { code: e.code, message: e.message });
  }

  private where(url: URL, params: unknown[]): string {
    const parts: string[] = [];
    for (const [k, v] of url.searchParams) {
      if (["select", "order", "limit", "offset", "on_conflict", "columns"].includes(k)) continue;
      const m = /^eq\.(.*)$/.exec(v);
      if (!m) throw new Error(`unsupported filter ${k}=${v}`);
      params.push(m[1]);
      parts.push(`t.${quote(k)}::text = $${params.length}`);
    }
    return parts.length ? "where " + parts.join(" and ") : "";
  }

  private async rest(req: HttpRequest, url: URL, s: Session): Promise<HttpResponse> {
    const table = quote(decodeURIComponent(url.pathname.replace("/rest/v1/", "")));
    const full = `public.${table}`;
    const prefer = req.headers?.prefer ?? "";
    const representation = /return=representation/.test(prefer);
    try {
      return await this.as(s, async (c) => {
        const params: unknown[] = [];
        if (req.method === "GET") {
          const r = await c.query(`select to_json(t) as j from ${full} t ${this.where(url, params)}`, params);
          return json(200, r.rows.map((x) => x.j));
        }
        if (req.method === "POST") {
          const rows = Array.isArray(req.body) ? req.body : [req.body];
          const out: unknown[] = [];
          for (const row of rows as Array<Record<string, unknown>>) {
            const cols = Object.keys(row).map(quote);
            const r = await c.query(
              `insert into ${full} (${cols.join(",")}) select ${cols.join(",")} from json_populate_record(null::${full}, $1::json)` +
                (representation ? " returning to_json(" + full.slice(7) + ") as j" : ""),
              [JSON.stringify(row)],
            );
            if (representation) out.push(...r.rows.map((x) => x.j));
          }
          return representation ? json(201, out) : json(201, null);
        }
        if (req.method === "PATCH") {
          const body = req.body as Record<string, unknown>;
          params.push(JSON.stringify(body));
          const sets = Object.keys(body).map((k) => `${quote(k)} = x.${quote(k)}`);
          const where = this.where(url, params);
          const r = await c.query(
            `update ${full} as t set ${sets.join(",")} from json_populate_record(null::${full}, $1::json) x ${where}` +
              (representation ? " returning to_json(t) as j" : ""),
            params,
          );
          return representation ? json(200, r.rows.map((x) => x.j)) : json(204, null);
        }
        if (req.method === "DELETE") {
          const r = await c.query(`delete from ${full} as t ${this.where(url, params)}` + (representation ? " returning to_json(t) as j" : ""), params);
          return representation ? json(200, r.rows.map((x) => x.j)) : json(204, null);
        }
        return json(405, { message: "method not allowed" });
      });
    } catch (e) {
      return this.denied(s, e as { code?: string; message: string });
    }
  }

  // ------------------------------------------------------------------ storage
  private async storage(req: HttpRequest, url: URL, s: Session): Promise<HttpResponse> {
    const p = url.pathname.replace("/storage/v1", "");
    const bucketInfo = /^\/bucket\/([^/]+)$/.exec(p);
    if (req.method === "GET" && bucketInfo) {
      const r = await this.pool.query("select id, public from storage.buckets where id = $1", [decodeURIComponent(bucketInfo[1]!)]);
      return r.rowCount ? json(200, r.rows[0]) : json(404, { message: "Bucket not found" });
    }

    const read = /^\/object\/(authenticated|public)\/([^/]+)\/(.+)$/.exec(p);
    const write = /^\/object\/([^/]+)\/(.+)$/.exec(p);
    const unauthorized = (e: { code?: string; message: string }) =>
      e.code === "42501" ? json(400, { statusCode: "403", error: "Unauthorized", message: "new row violates row-level security policy" }) : json(400, { message: e.message });

    if (req.method === "GET" && read) {
      const [, kind, bucket, name] = read;
      const b = decodeURIComponent(bucket!);
      const n = decodeURI(name!);
      if (kind === "public") {
        const r = await this.pool.query(
          "select o.content from storage.objects o join storage.buckets k on k.id = o.bucket_id where o.bucket_id = $1 and o.name = $2 and k.public",
          [b, n],
        );
        return r.rowCount ? text(200, r.rows[0].content) : json(400, { statusCode: "404", message: "Object not found" });
      }
      const r = await this.as(s, (c) => c.query("select content from storage.objects where bucket_id = $1 and name = $2", [b, n]));
      return r.rowCount ? text(200, r.rows[0].content) : json(400, { statusCode: "404", message: "Object not found" });
    }

    if (write) {
      const b = decodeURIComponent(write[1]!);
      const n = decodeURI(write[2]!);
      try {
        return await this.as(s, async (c) => {
          if (req.method === "POST") {
            await c.query("insert into storage.objects (bucket_id, name, owner, content) values ($1, $2, auth.uid(), $3)", [b, n, String(req.body ?? "")]);
            return json(200, { Key: `${b}/${n}` });
          }
          if (req.method === "PUT") {
            const r = await c.query("update storage.objects set content = $3 where bucket_id = $1 and name = $2", [b, n, String(req.body ?? "")]);
            return r.rowCount ? json(200, { Key: `${b}/${n}` }) : json(404, { message: "Object not found" });
          }
          if (req.method === "DELETE") {
            // Deliberately reports success even when nothing was removed: the runner must not trust it.
            await c.query("delete from storage.objects where bucket_id = $1 and name = $2", [b, n]);
            return json(200, { message: "Successfully deleted" });
          }
          return json(405, { message: "method not allowed" });
        });
      } catch (e) {
        return unauthorized(e as { code?: string; message: string });
      }
    }
    return json(404, { message: "not found" });
  }
}
