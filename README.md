# accessproof

**Security tests your AI can't break.**

Apps built with Lovable, Bolt, Cursor or Claude Code mostly leak data through *access control*, not exotic exploits: a table with no Row Level Security, a policy that says `using (true)`, an API route that fetches `orders/:id` without asking whose order it is. Scanners can flag patterns once. Then your next prompt quietly reopens the hole.

accessproof is different in three ways:

1. **It asks what you *intend*.** It drafts `access.yml` ("users see only their own orders; visitors see nothing"), you confirm it in two minutes, and that file is the source of truth. No false alarms on data that is meant to be public.
2. **It proves, not guesses.** It signs up throwaway users on your **local** Supabase, makes real requests as each role, and checks the *actual outcome* in the database. It does not trust HTTP status codes (an API can say "deleted" when nothing was).
3. **It closes the loop with your AI.** Failures come out as a plain-English brief, an MCP server, and a `/secure` skill, so Claude Code can fix them and re-run until everything is green. Hooks stop the next prompt from undoing it.

```
$ accessproof test
accessproof · http://127.0.0.1:54321
46 passed · 14 failed · 0 need review · 0 errors · 0 skipped

  EXPOSED [critical] A signed-out visitor must NOT be able to delete another user's notes rows.
         DELETE /rest/v1/notes?id=eq.<id of another user's row> as anon → the row was deleted
  EXPOSED [high] A signed-out visitor must NOT be able to read another user's orders rows.
         GET /rest/v1/orders?id=eq.<id of another user's row> as anon → the row came back
  EXPOSED [high] A signed-in user must NOT be able to update another user's posts rows.
         PATCH /rest/v1/posts?id=eq.<id of another user's row> {title: …} as user-a → the row was changed
  …
```

## Quick start

```bash
npm install -g accessproof        # or use npx accessproof …  (not published yet: see "Status")

accessproof infer                 # 1. draft access.yml from supabase/migrations + API routes
$EDITOR access.yml                # 2. read the guesses, fix them, set confirmed: true
supabase start                    # 3. local Supabase
export SUPABASE_ANON_KEY=...  SUPABASE_SERVICE_ROLE_KEY=...   # from `supabase status -o env`
accessproof test                  # 4. prove every rule; writes .accessproof/{report.md,FIXES.md}
```

No database handy? `accessproof check` needs nothing: it reads migrations and code and flags RLS-off tables, allow-everything policies, a service_role key in `NEXT_PUBLIC_*`, and routes that use service_role without checking the caller. Exit code 1 makes it a CI gate.

### With Claude Code

```bash
accessproof setup-claude          # adds the MCP server, two hooks, and the /secure skill (merges, never overwrites)
```

Then ask Claude Code to **`/secure`**. It drafts the rules, shows them to you to confirm, runs the tests, fixes failures in a new migration, and re-runs until green. The hooks:

- **prompt guard** — if a prompt says "disable RLS so it works" or "put the service role key in the frontend", the agent is reminded to do it safely instead (`--block` to refuse outright).
- **post-edit check** — after a migration, API route or `.env` edit, serious findings are fed straight back to the agent.

### In CI

[`templates/accessproof-ci.yml`](templates/accessproof-ci.yml) starts local Supabase on a pull request, then runs `check` and `test --strict`.

## What it checks

| | Static (`check`/`infer`, no DB) | Proven (`test`, local Supabase) |
|---|---|---|
| Table has RLS off | ✅ | ✅ (anyone can read/write) |
| Policy grants more than intended | ✅ | ✅ |
| Cross-user read/insert/update/delete on tables | | ✅ |
| Storage bucket read/upload/overwrite/delete | ✅ | ✅ |
| Policy blocks something the app needs | ✅ (hint) | ✅ |
| Users can edit their own `role`/`plan`/`balance` column | ✅ (warning) | |
| `service_role` key in `NEXT_PUBLIC_*` or committed | ✅ | |
| Route uses `service_role` with no caller check | ✅ | |

## Safety

accessproof creates users and rows and tries to modify and delete data, so it **refuses to run against anything but local Supabase**. A remote host is allowed only if you type its exact hostname with `--allow-remote` (or `ACCESSPROOF_ALLOW_REMOTE`), and never if it appears in your `.env.production*` files. The MCP server cannot unlock remote targets. Everything it creates is deleted afterwards. Only test projects you own.

## Commands

| | |
|---|---|
| `infer [dir]` | Draft `access.yml` + `.accessproof/infer-report.md` (`--llm` asks Claude to sanity-check it) |
| `check [dir]` | Static findings; `--fail-on <severity>`, `--json` |
| `test [dir]` | Prove the rules; `--url --anon-key --service-key --allow-remote --only --strict --json` |
| `plan [file]` | List every check `test` will run |
| `validate [file]` | Check `access.yml` is well-formed |
| `setup-claude [dir]` | Wire up MCP + hooks + `/secure` (`--dry-run`, `--local`) |
| `hook <prompt\|post-edit>` | Claude Code hook entry points |
| `mcp` | Run the MCP server (tools: `infer_policy`, `static_check`, `run_access_tests`, `get_failures`, `explain_rule`) |

The spec format is in [docs/SPEC.md](docs/SPEC.md).

## Status: early (v0.1) — read this

**Works and is tested** (`npm test`, 100+ tests): the SQL/policy reader, intent inference, the safety guard, the test runner, the CLI and exit codes, the MCP server (over the real protocol), hook logic, and `setup-claude`. The runner is verified end to end by running the demo app's real migrations in real PostgreSQL: **14 exposures found on the vulnerable schema, 0 after the fix**.

**Not yet verified, be sceptical:**
- **Not tested against a real Supabase stack.** In tests the policies are evaluated by real Postgres, but PostgREST, Supabase Auth and Supabase Storage are emulated by a small test double. Real-world HTTP details (status codes, Storage quirks) may differ. Treat the first runs on a real project as a trial, and please report anything odd.
- The `--llm` pass, the hook JSON contract inside a live Claude Code session, and the CI template have not been run against live services.
- The accuracy eval (`npm run eval`) has **one** hand-labelled fixture written by the author. It is a regression check, not evidence of accuracy on your app. Real accuracy needs many labelled repos (see [eval/repos/README.md](eval/repos/README.md)); this is the main thing to build next.

**Known limits** ([docs/LIMITATIONS.md](docs/LIMITATIONS.md)): Next.js + Supabase only; tables and Storage buckets (API routes are only checked statically); row-level not column-level rules; your migrations are the schema (not a live database); one test row per table needs to be creatable (add a `seed:` template when it can't be invented); not a substitute for a pen test or a security engineer on a high-stakes app.

## Develop

```bash
npm install && npm test                 # unit tests
# integration + end-to-end tests also run the demo migrations in real Postgres:
ACCESSPROOF_PG_URL=postgres://postgres:postgres@127.0.0.1:5432/postgres npm test
npm run eval                            # infer vs hand-labelled intent
```

[`demo/vulnerable-app`](demo/vulnerable-app) is a deliberately insecure project; [`demo/.../fixes/0002_fix_access.sql`](demo/vulnerable-app/supabase/fixes/0002_fix_access.sql) is the fix that turns it green. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT
