---
name: secure
description: Prove and fix access-control bugs (missing RLS, over-permissive policies, routes that skip ownership checks, leaked service_role keys) in a Next.js + Supabase app using accessproof. Use when asked to secure the app, check who can see what, or fix RLS/auth problems.
---

# /secure — make the access rules pass

accessproof proves who can read/insert/update/delete what by making real requests as test users against LOCAL Supabase.
Use the accessproof MCP tools when they are available; otherwise run the same steps with `npx accessproof`.

## 1. Get the rules confirmed (the human decides intent)

- No `access.yml` yet → `infer_policy` (CLI: `npx accessproof infer`).
- Show the user the drafted rules in plain English, one resource at a time ("`orders`: signed-in users can read/change only their own; visitors nothing"). Ask them to confirm or correct each.
- Update the file with their corrections. Set `confirmed: true` ONLY for resources the user has explicitly approved. Never confirm a rule yourself and never edit a rule to make a check pass.

## 2. Check, then prove

- `static_check` (CLI: `npx accessproof check`) is fast and needs no database.
- Make sure local Supabase is running (`supabase start`) and keys are exported (`eval "$(supabase status -o env | sed 's/^/export /')"` then `export SUPABASE_ANON_KEY=$ANON_KEY SUPABASE_SERVICE_ROLE_KEY=$SERVICE_ROLE_KEY`).
- `run_access_tests` (CLI: `npx accessproof test`). It refuses non-local targets. Never pass `--allow-remote` yourself; that is the user's call.

## 3. Fix until green

- `get_failures` returns each problem with the request that proved it.
- Fix the CAUSE in a NEW migration under `supabase/migrations/` (or the API route): enable RLS, scope policies with `auth.uid() = <owner column>`, keep `service_role` on the server only.
- Do not disable RLS, widen a policy to `using (true)`, or move a secret into a `NEXT_PUBLIC_` variable.
- Apply the migration locally (`supabase db reset`), re-run the tests, repeat.

## 4. Report

Summarise: what was exposed (in plain words, with the proof), what you changed and in which files, and anything still unconfirmed or untestable (e.g. column-level rules, API routes) that needs a human look.
