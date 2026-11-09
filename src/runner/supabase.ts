import type { HttpResponse, Transport } from "./types.js";

export interface Keys {
  anon: string;
  service: string;
}

/** Someone the runner can act as. */
export interface Actor {
  label: string;
  role: string;
  id?: string;
  token: string;
  apikey: string;
}

export const errorMessage = (r: HttpResponse): string => {
  const b = r.body as { message?: string; msg?: string; error?: string; error_description?: string; code?: string } | string | null;
  if (b && typeof b === "object") return String(b.message ?? b.msg ?? b.error_description ?? b.error ?? b.code ?? "").slice(0, 200);
  return typeof b === "string" ? b.slice(0, 200) : "";
};

/** Thin wrapper over Supabase's Auth, PostgREST and Storage HTTP APIs. */
export class Supa {
  readonly anon: Actor;
  readonly service: Actor;

  constructor(
    private readonly t: Transport,
    keys: Keys,
  ) {
    this.anon = { label: "anon", role: "anon", token: keys.anon, apikey: keys.anon };
    this.service = { label: "service", role: "service_role", token: keys.service, apikey: keys.service };
  }

  private headers(a: Actor, extra: Record<string, string> = {}) {
    return { apikey: a.apikey, authorization: `Bearer ${a.token}`, ...extra };
  }

  async createUser(email: string, password: string, appMetadata?: Record<string, unknown>): Promise<string> {
    const r = await this.t.send({
      method: "POST",
      path: "/auth/v1/admin/users",
      headers: this.headers(this.service),
      body: { email, password, email_confirm: true, ...(appMetadata ? { app_metadata: appMetadata } : {}) },
    });
    const id = (r.body as { id?: string } | null)?.id;
    if (r.status >= 300 || !id) throw new Error(`Could not create test user (${r.status}): ${errorMessage(r)}`);
    return id;
  }

  async deleteUser(id: string): Promise<void> {
    await this.t.send({ method: "DELETE", path: `/auth/v1/admin/users/${id}`, headers: this.headers(this.service) });
  }

  async signIn(email: string, password: string): Promise<string> {
    const r = await this.t.send({
      method: "POST",
      path: "/auth/v1/token?grant_type=password",
      headers: { apikey: this.anon.apikey },
      body: { email, password },
    });
    const token = (r.body as { access_token?: string } | null)?.access_token;
    if (r.status >= 300 || !token) throw new Error(`Could not sign in test user (${r.status}): ${errorMessage(r)}`);
    return token;
  }

  actor(label: string, role: string, id: string, token: string): Actor {
    return { label, role, id, token, apikey: this.anon.apikey };
  }

  rest(
    actor: Actor,
    method: "GET" | "POST" | "PATCH" | "DELETE",
    table: string,
    opts: { query?: Record<string, string>; body?: unknown; prefer?: string } = {},
  ): Promise<HttpResponse> {
    const qs = opts.query ? "?" + new URLSearchParams(opts.query).toString() : "";
    return this.t.send({
      method,
      path: `/rest/v1/${encodeURIComponent(table)}${qs}`,
      headers: this.headers(actor, opts.prefer ? { prefer: opts.prefer } : {}),
      body: opts.body,
    });
  }

  storage(actor: Actor, method: "GET" | "POST" | "PUT" | "DELETE", path: string, body?: string): Promise<HttpResponse> {
    return this.t.send({ method, path: `/storage/v1${path}`, headers: this.headers(actor), body });
  }
}
