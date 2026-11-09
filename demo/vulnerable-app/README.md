# vulnerable-app (demo)

A tiny Next.js + Supabase project with **deliberate** access-control mistakes, used to demo and test accessproof.
**Never deploy it.**

| Mistake | Where |
|---|---|
| RLS never enabled on `notes` | `0001_init.sql` |
| `orders` readable by everyone (`using (true)`) | `0001_init.sql` |
| Any signed-in user can edit any `posts` row | `0001_init.sql` |
| Any signed-in user can delete any avatar | `0001_init.sql` |
| Users can edit their own `profiles.role` | `0001_init.sql` |
| `service_role` key used with no caller check (IDOR) | `app/api/orders/[id]/route.ts` |
| `service_role` key behind a `NEXT_PUBLIC_` variable | `lib/browser-client.ts` |

`supabase/fixes/0002_fix_access.sql` is the fix. Applying it should turn every red test green.
