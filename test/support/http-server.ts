import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import type { Transport } from "../../src/runner/types.js";

/** Exposes a Transport (the Postgres test double) over real HTTP, so the CLI's fetch path is exercised. */
export async function serve(t: Transport): Promise<{ url: string; close: () => Promise<void> }> {
  const server: Server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const raw = Buffer.concat(chunks).toString("utf8");
    const isJson = /json/.test(req.headers["content-type"] ?? "");
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.headers)) if (typeof v === "string") headers[k] = v;
    const out = await t.send({
      method: req.method as "GET",
      path: req.url ?? "/",
      headers,
      body: raw === "" ? undefined : isJson ? JSON.parse(raw) : raw,
    });
    if (out.body === null || out.body === undefined || out.body === "") {
      res.writeHead(out.status).end();
    } else if (typeof out.body === "string") {
      res.writeHead(out.status, { "content-type": "text/plain" }).end(out.body);
    } else {
      res.writeHead(out.status, { "content-type": "application/json" }).end(JSON.stringify(out.body));
    }
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as AddressInfo).port;
  return { url: `http://127.0.0.1:${port}`, close: () => new Promise((r) => server.close(() => r())) };
}
