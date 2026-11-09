# Contributing

Bug reports with a minimal `supabase/migrations` + `access.yml` that misbehaves are the most useful contribution.

```bash
npm install
npm test                                   # unit tests
ACCESSPROOF_PG_URL=postgres://postgres:postgres@127.0.0.1:5432/postgres npm test   # + real-Postgres integration/e2e
npm run build && node dist/cli.js --help
```

## Ground rules
- **Never weaken the safety guard** (`src/runner/guard.ts`) or give the MCP server a way to unlock remote targets.
- **Judge by effect, not status code.** Runtime probes decide allowed/denied from the resulting database/storage state; a status code is only evidence.
- New static checks need a test in `test/` and, if they add a finding, a planted example in `demo/vulnerable-app`.
- Inference changes should not lower `npm run eval`. Better: add a labelled repo under `eval/` (see `eval/repos/README.md`). Accuracy claims need many repos, not one.

## Layout
- `src/infer/` SQL reader → policy classifier → intent heuristics → `access.yml` + static findings
- `src/runner/` guard, config, Supabase API client, row builder, executor, reports
- `src/mcp/` MCP server · `src/hook.ts` Claude Code hooks · `src/setup.ts` `setup-claude`
- `test/support/` the Postgres-backed test double (a test aid, not Supabase)
