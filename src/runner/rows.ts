import { randomUUID } from "node:crypto";
import type { Column, TableDef } from "../infer/sql.js";

export class UnsupportedColumn extends Error {
  constructor(
    public table: string,
    public column: Column,
  ) {
    super(
      `Cannot invent a value for ${table}.${column.name} (type ${column.type}). ` +
        `Add a \`seed:\` row template for "${table}" in access.yml, e.g. seed: { ${column.name}: <value> }.`,
    );
  }
}

const baseType = (t: string) => t.replace(/\(.*?\)/g, "").replace(/\s+/g, " ").trim();

export function isTextType(type: string): boolean {
  return /^(text|varchar|character varying|char|character|citext|name)$/.test(baseType(type));
}

/** A plausible value for a NOT NULL column with no default, or undefined if the type is unknown. */
export function synthValue(col: Column): unknown {
  const t = baseType(col.type);
  if (t.endsWith("[]") || t.startsWith("_")) return [];
  if (isTextType(t)) return `accessproof-${col.name}`.slice(0, 30);
  if (t === "uuid") return randomUUID();
  if (/^(int2|smallint|int|int4|integer|int8|bigint|serial|bigserial|smallserial)$/.test(t)) return 1;
  if (/^(numeric|decimal|real|float4|float8|double precision|money)$/.test(t)) return 1;
  if (/^(bool|boolean)$/.test(t)) return false;
  if (/^timestamp/.test(t)) return new Date().toISOString();
  if (t === "date") return new Date().toISOString().slice(0, 10);
  if (/^time/.test(t)) return "12:00:00";
  if (/^jsonb?$/.test(t)) return {};
  return undefined;
}

/** Fresh primary key value so tests can find the exact row they created. */
export function newPk(col: Column): unknown {
  const t = baseType(col.type);
  if (t === "uuid") return randomUUID();
  if (/^(int|int4|integer|int8|bigint|serial|bigserial)$/.test(t)) return 1_500_000_000 + Math.floor(Math.random() * 400_000_000);
  if (isTextType(t)) return `ap-${randomUUID()}`;
  return undefined;
}

export function singlePk(table: TableDef): Column | undefined {
  const pks = table.columns.filter((c) => c.primaryKey);
  return pks.length === 1 ? pks[0] : undefined;
}

/** A harmless column to modify when probing UPDATE access. */
export function updatableColumn(table: TableDef, ownerColumn?: string): Column | undefined {
  return table.columns.find((c) => isTextType(c.type) && !c.primaryKey && c.name !== ownerColumn && !c.references);
}

export function replaceUid(value: unknown, uid: string | undefined): unknown {
  if (typeof value === "string") return value === "{uid}" ? uid : value.replaceAll("{uid}", uid ?? "");
  if (Array.isArray(value)) return value.map((v) => replaceUid(v, uid));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, replaceUid(v, uid)]));
  }
  return value;
}
