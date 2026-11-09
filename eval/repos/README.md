# Eval set

`npm run eval` scores `accessproof infer` against hand-labelled intent. One cell = (resource, role, operation);
accuracy = matching cells / labelled cells.

Today there is **one** fixture (`demo/vulnerable-app`, labelled by the author). That makes it a regression
check, not evidence of accuracy. To measure real accuracy:

1. Clone 20–30 public Next.js + Supabase repos (ideally ones built with Lovable / Bolt / Cursor) into
   `eval/repos/<name>/` (this folder's contents are gitignored).
2. For each, write `eval/labels/<name>.access.yml` by hand: the rules a careful human would want, **not**
   what the migrations currently do. Label before you run `infer`, so the labels aren't tuned to its output.
3. `npm run eval` and record the overall number (and the misses) in the README.
