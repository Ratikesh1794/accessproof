# Limitations

Read these before trusting a green run.

## Scope
- **Next.js + Supabase only.** Other frameworks and backends are not read.
- **Tables and Storage buckets are tested at runtime.** API routes (`kind: route`) are only analysed statically; a route that checks the wrong thing will not be caught by `test`.
- **Row-level, not column-level.** RLS decides which rows a user can change, not which columns. A user editing their own `role` is flagged statically (`sensitive-column-writable`) but not proven at runtime.
- **Operations are read / insert / update / delete.** No RPC functions (`supabase.rpc`), `SECURITY DEFINER` functions, realtime channels, GraphQL, or Edge Functions.

## Schema source
- Your **migrations are the schema** (`supabase/migrations/*.sql`, plus loose `supabase/*.sql` dumps). Policies created through the dashboard and never exported are invisible to `infer`/`check`. The runtime `test` is not affected: it observes the real database. Run `supabase db pull` to capture dashboard changes.
- The SQL reader is intentionally small. Unusual DDL (partitioned tables, inheritance, `ALTER POLICY`, `GRANT/REVOKE`-based hardening) is not interpreted. `REVOKE` on a table can make `rls-disabled` a false positive.
- Policies that call custom functions are marked "could not be analysed"; only the runtime test judges them.

## Intent inference
- `infer` is a draft from names, column types, foreign keys and existing policies. "Per-user" vs "public" is a guess: that is why every rule starts `confirmed: false` and failures on unconfirmed rules are reported as **needs review**, not as vulnerabilities.
- Existing policies are used as hints, so a wrong policy can nudge the draft. Always read the `notes` line of each resource.

## Test runner
- Needs to create a plausible row for every table. Required columns of unusual types (enums, custom types) can't be invented: add `seed:` under that resource in `access.yml`.
- Tables need a single-column primary key.
- Each rule is probed with one test row per user; a policy that only misbehaves for particular data (e.g. depends on a `status` column) may pass.
- Email confirmation, MFA, captcha and rate limits on Auth can block test-user creation on some projects.
- Tests run sequentially against a *local* database and take seconds, not minutes; they are not load tests.

## Verification status
See the README: real Postgres evaluates policies in the test suite, but PostgREST, Auth and Storage are emulated there. Real-stack differences are possible.

## Not a substitute for
A penetration test, a threat model, dependency scanning, SQL-injection/XSS testing, secrets scanning of your git history, or a security engineer reviewing an app that handles sensitive data.
