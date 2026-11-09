# Roadmap

## Done (v0.1)
- `access.yml` spec, validator, deny-by-default planner
- `infer`: SQL/policy reader, intent heuristics, optional LLM review, static findings
- `check`: fast static gate for CI and hooks
- `test`: safety guard, user/row seeding, table + Storage probes judged by effect, reports and an AI fix brief
- MCP server, Claude Code hooks, `/secure` skill, `setup-claude`
- Demo app with planted bugs and a verified fix

## Next (highest value first)
1. **Verify against a real Supabase stack** (`supabase start` in CI) and fix whatever differs from the test double.
2. **A real eval set**: 20–30 labelled public Next.js + Supabase repos; track rule-level accuracy in the README.
3. `kind: route` — execute API routes as different users (IDOR in handlers, not just RLS).
4. Column-level checks (can a user write `role`?), RPC / `SECURITY DEFINER` functions.
5. Firebase backend.
6. Hosted: scheduled re-checks, authenticated scans on staging, agency reports (paid tier ideas; the open-source core stays free).
