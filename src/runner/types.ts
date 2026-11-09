export interface HttpRequest {
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  /** Path plus query string, e.g. /rest/v1/orders?id=eq.1 */
  path: string;
  headers?: Record<string, string>;
  /** Objects are sent as JSON, strings as plain text. */
  body?: unknown;
}

export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: unknown;
}

/** The only thing the runner needs from the network. Swappable in tests. */
export interface Transport {
  send(req: HttpRequest): Promise<HttpResponse>;
}

export function fetchTransport(baseUrl: string, timeoutMs = 15_000): Transport {
  const base = baseUrl.replace(/\/+$/, "");
  return {
    async send(req) {
      const headers: Record<string, string> = { ...(req.headers ?? {}) };
      let body: string | undefined;
      if (typeof req.body === "string") {
        body = req.body;
        headers["content-type"] ??= "text/plain";
      } else if (req.body !== undefined) {
        body = JSON.stringify(req.body);
        headers["content-type"] ??= "application/json";
      }
      const res = await fetch(base + req.path, {
        method: req.method,
        headers,
        body,
        signal: AbortSignal.timeout(timeoutMs),
      });
      const text = await res.text();
      let parsed: unknown = text;
      if (/json/i.test(res.headers.get("content-type") ?? "")) {
        try {
          parsed = text ? JSON.parse(text) : null;
        } catch {
          /* keep text */
        }
      }
      return { status: res.status, headers: Object.fromEntries(res.headers.entries()), body: parsed };
    },
  };
}
