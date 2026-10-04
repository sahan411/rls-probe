# supabase-rls-audit

Audit a Supabase schema (or your `supabase/migrations` folder) for Row Level Security gaps, then **prove the result by executing access tests** in a sandboxed Postgres. It never connects to your live project and never needs your keys.

AI app builders (Lovable, Bolt, Replit, Cursor) routinely generate tables with RLS off, `using (true)` policies, security-definer views over `auth.users`, and policies that trust `user_metadata`. Static checkers can point at these; this tool also **runs the queries** as `anon` and as "user A" against "user B's" rows and tells you what the database actually allowed.

```
supabase-rls-audit: 20/20 statements loaded from 1 file(s)
findings: CRITICAL 3  HIGH 8  MEDIUM 0  LOW 4  INFO 1   | failing access tests: 33
  [CRITICAL] public.orders: Table is open to the API with Row Level Security turned off
  [CRITICAL] public.member_directory: A public view exposes auth.users (emails and account data) to the API
  ...
after draft fix: CRITICAL 0  HIGH 2  MEDIUM 1  | failing access tests: 1  (3 item(s) need a human decision)
```

A full sample report on a fictional app is in [`samples/`](samples/): [report](samples/habithub-report.md), [draft fix SQL](samples/habithub-draft-fix.sql).

## Quick start

```bash
git clone https://github.com/sahan411/supabase-rls-audit && cd supabase-rls-audit && npm install
node bin/cli.mjs path/to/supabase/migrations --out report.md
```

Needs Node 20+. The first run installs the Postgres WASM engine via npm (about 25 MB on disk).

### Where do I get the schema?
Any one of these (all contain structure only, no data and no secrets):
1. **Lovable / Bolt / Cursor projects exported to GitHub:** the `supabase/migrations/` folder in the repo.
2. **Supabase CLI:** `supabase db dump --schema public -f schema.sql`
3. **pg_dump:** `pg_dump --schema-only --no-owner --schema=public "$DATABASE_URL" > schema.sql` (run it yourself; the tool never needs the connection string)

Several files or folders can be passed; `.sql` files are loaded in name order (migration timestamps sort correctly).

### Options
| Option | Meaning |
|---|---|
| `--out report.md`, `--html report.html`, `--json report.json` | write reports (print the HTML to PDF in a browser) |
| `--fix fix.sql` | write a **draft** fix migration, apply it to a fresh copy and re-audit (before/after) |
| `--schemas public,api` | schemas exposed through the Data API (default `public`) |
| `--no-probe` | skip the executed access tests |
| `--default-grants off` | do not assume Supabase's default privileges on `public` |
| `--fail-on high\|medium\|never` | exit code 2 when findings at that level exist (CI gate; default `high`) |

## What it checks
Rule names follow Supabase's [database linter](https://supabase.com/docs/guides/database/database-linter) where one exists (verified against the docs on 2026-10-04). This is an independent implementation, not the Supabase linter.

| Rule | Lint | What it catches |
|---|---|---|
| `RLS-DISABLED` | 0013 | table open to `anon`/`authenticated` with RLS off (CRITICAL if it holds token/secret/key-looking columns) |
| `POLICY-NO-RLS` | 0007 | policies written but RLS never enabled |
| `RLS-NO-POLICY` | 0008 | RLS on, no policy (safe, but the app may break) |
| `POLICY-ALWAYS-TRUE` | 0024 | `using (true)` / `with check (true)`; public read is only a "confirm" item, public write is HIGH |
| `USER-METADATA-POLICY` | 0015 | policy trusts `user_metadata`, which users can edit |
| `POLICY-NO-IDENTITY` | custom | write policy that never looks at the caller |
| `AUTH-USERS-EXPOSED` / `VIEW-DEFINER` | 0002 / 0010 | views that bypass RLS (and leak `auth.users`) |
| `MATVIEW-IN-API` | 0016 | materialized view reachable through the API |
| `DEFINER-FUNCTION` / `FUNC-SEARCH-PATH` | 0011 / 0028 / 0029 | SECURITY DEFINER functions without `search_path`, callable by `anon` |
| `STORAGE-BROAD-WRITE` / `STORAGE-BROAD-READ` | 0025 / custom | storage policies not tied to a user or folder |
| `AUTH-INITPLAN` | 0003 | `auth.uid()` evaluated per row instead of once |

**Executed access tests** (per table, seeded with two synthetic users): anon read/insert/update/delete, user A reading/updating/deleting/forging rows of user B, and "can the owner still read their own rows". Failing tests become findings even when no static rule fired. A deliberate public-read policy is reported as "confirm", not as a failure.

## How it works
Your SQL is loaded statement by statement into [PGlite](https://pglite.dev) (real PostgreSQL compiled to WASM, in-process, no network) on top of a small emulation of Supabase's roles, `auth.users`, `auth.uid()` and `storage`. Findings come from the real catalogs (`pg_class`, `pg_policies`, `pg_proc`, `has_table_privilege`, ...). Access tests run `set local role anon|authenticated` with JWT claims and roll back. Statements that cannot be loaded are listed, never silently dropped.

## Honest limits
- Schema-only: no data, no live project, no Auth/dashboard settings, no Edge Function logic, no leaked-key scan, no business-logic review.
- Assumes Supabase's default public-schema privileges (switch off with `--default-grants off`).
- Extensions the sandbox cannot load (e.g. `pg_graphql`, `pgsodium`) are skipped and reported.
- Tables whose columns the seeder cannot fill are reported as skipped, not passed.
- The draft fix is mechanical for owner-scoped tables and views/functions; anything needing a product decision is listed for a human. Review before applying.
- A technical review, not a penetration test; no tool can guarantee security.

## Tests
`npm test` runs 12 tests, including a hand-secured twin of the vulnerable schema (must stay quiet), a `pg_dump`-style file with psql meta-commands, and Supabase's own official starter migration as an independent third-party check against false alarms.

## Need it fixed and verified?
Applying the fixes safely (policies that match how your app really works, re-tested before and after) is a paid service; see the profile on this account. The tool itself is free (MIT).

License: MIT
