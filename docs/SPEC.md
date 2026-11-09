# access.yml spec (v1)

`access.yml` says, in plain terms, who may do what. accessproof turns each line into real requests
made by seeded test users, so every rule is *proven*, not assumed.

```yaml
version: 1
project: { framework: nextjs, backend: supabase }
roles:
  anon: { description: Not signed in }
  user: { description: Any signed-in user }
  admin:
    seed: { table: profiles, set: { role: admin } }   # how to make a test admin
resources:
  orders:
    kind: table
    owner: user_id          # column holding auth.uid() of the owner
    confirmed: true         # a human approved these rules
    rules:
      anon:  { read: none }
      user:  { read: own, insert: own, update: own, delete: own }
      admin: { read: all }
  avatars:
    kind: bucket
    owner_path: "{uid}/*"   # objects live under the owner's id
    rules:
      anon: { read: all }
      user: { read: all, insert: own, update: own, delete: own }
```

## Levels
| Level | Meaning | Checks generated |
|---|---|---|
| `none` | never allowed | deny on own rows, deny on others' |
| `own`  | only rows this user owns | allow on own, deny on others' |
| `all`  | every row | allow on own, allow on others' |

Anything not written is `none` (deny by default). `anon` can't own rows, so it is checked against another user's rows only. Resources with no owner have no "own" level; one check per operation covers every row.

## Resources
- `table` — `owner: <column>` is required to use `own`. Optional `seed:` is a row template for tables whose required columns can't be invented (`{uid}` becomes the row owner's id).
- `bucket` — `owner_path` (currently `"{uid}/*"`) is required to use `own`. A resource named `<bucket>_bucket` refers to bucket `<bucket>` (avoids clashing with a table of the same name).
- `route` — reserved for v0.2 (`method`, `path`, `backs`); currently skipped by `test`.

## Roles
`anon` is signed out. Every other role gets a seeded test user. `seed` says how to make one:
- `table` + `set` — upsert those columns on the user's row in that table (e.g. `profiles.role = admin`)
- `app_metadata` — set Supabase auth `app_metadata` on the user (e.g. `{ role: admin }`)

A second ordinary user, `user-b`, is always created: it owns the "another user's rows" that every actor tries to touch.

## How each operation is proven
The runner decides allowed/denied from the **resulting state**, read back with the service role, not from the HTTP status:

| Operation | Probe | Allowed means |
|---|---|---|
| read | `GET` a seeded row/object by id | the row/object came back |
| insert | `POST` a new row/object owned by the target | it now exists |
| update | `PATCH`/`PUT` a fresh disposable row/object | its value changed |
| delete | `DELETE` a fresh disposable row/object | it is gone |

A 401/403, or a 2xx that changed nothing, is *denied*. Any other status is *inconclusive* (`error`), never silently a pass.

## Confirmation
`confirmed: false` means inferred and not yet approved. Tests still run, but a mismatch is reported as **needs review**, not as a vulnerability (`--strict` makes it fail). Only a human flips it to `true`; the AI fix loop must never edit rules to make checks pass.

## Failure kinds and severity
- **exposure** — someone can do something they must not. anon read: high; anon write: critical; signed-in cross-user: high.
- **blocked** — someone cannot do something they should (a policy is too strict). low.
