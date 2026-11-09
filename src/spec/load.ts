import { readFile } from "node:fs/promises";
import { parse } from "yaml";
import { AccessSpec } from "./schema.js";

export async function loadSpec(path: string): Promise<AccessSpec> {
  const raw = parse(await readFile(path, "utf8"));
  const result = AccessSpec.safeParse(raw);
  if (!result.success) {
    const lines = result.error.issues.map((i) => `  - ${i.path.join(".") || "(root)"}: ${i.message}`);
    throw new Error(`Invalid ${path}:\n${lines.join("\n")}`);
  }
  return result.data;
}
