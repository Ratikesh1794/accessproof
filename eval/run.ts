/**
 * Scores `accessproof infer` against hand-labelled intent.
 * Unit of measure: one cell = (resource, role, operation). Accuracy = matching cells / labelled cells.
 * Usage: npm run eval            (looks in demo/<name> and eval/repos/<name>)
 */
import { readdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { inferProject } from "../src/infer/index.js";
import { loadSpec } from "../src/spec/load.js";
import { OPS, expandRule } from "../src/spec/schema.js";

const root = resolve(import.meta.dirname, "..");
const labelsDir = join(root, "eval", "labels");

let totalCells = 0;
let totalOk = 0;
for (const file of (await readdir(labelsDir)).filter((f) => f.endsWith(".access.yml")).sort()) {
  const name = basename(file, ".access.yml");
  const project = [join(root, "demo", name), join(root, "eval", "repos", name)].find(existsSync);
  if (!project) {
    console.log(`- ${name}: no project folder found, skipped`);
    continue;
  }
  const label = await loadSpec(join(labelsDir, file));
  const { spec } = await inferProject(project);

  let cells = 0;
  let ok = 0;
  const misses: string[] = [];
  for (const [res, want] of Object.entries(label.resources)) {
    const got = spec.resources[res];
    for (const role of Object.keys(label.roles)) {
      for (const op of OPS) {
        cells++;
        const w = expandRule(want.rules[role])[op];
        const g = got ? expandRule(got.rules[role])[op] : "(missing)";
        if (w === g) ok++;
        else misses.push(`${res}.${role}.${op}: wanted ${w}, inferred ${g}`);
      }
    }
  }
  const extra = Object.keys(spec.resources).filter((r) => !label.resources[r]);
  console.log(`\n${name}: ${ok}/${cells} cells correct (${((100 * ok) / cells).toFixed(1)}%)`);
  for (const m of misses) console.log(`   miss  ${m}`);
  if (extra.length) console.log(`   extra resources not in label: ${extra.join(", ")}`);
  totalCells += cells;
  totalOk += ok;
}
if (totalCells) console.log(`\nOverall: ${totalOk}/${totalCells} (${((100 * totalOk) / totalCells).toFixed(1)}%)`);
