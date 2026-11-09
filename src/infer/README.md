# infer

`sql.ts` reads migrations → `policy.ts` classifies what each policy grants → `heuristics.ts` drafts intent
and compares it with reality (static findings) → `routes.ts` scans Next.js routes and secrets →
`index.ts` assembles `access.yml` + `.accessproof/infer-report.md`. `llm.ts` is an optional, constrained review pass.
Everything here is deterministic and offline except `llm.ts`.
