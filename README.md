# rls-probe

**rls-probe works offline on your Supabase migrations or a schema dump.** It loads them into a local sandbox Postgres ([PGlite](https://pglite.dev)), runs static Row Level Security rules plus **executed access probes** as `anon`, "user A" and "user B", and writes a ranked report, a SARIF file and a draft fix. No keys, no live database access, no network: it only reads the files you give it.

AI app builders (Lovable, Bolt, Replit, Cursor) routinely generate tables with RLS off, `using (true)` policies, security-definer views over `auth.users`, and policies that trust `user_metadata`. A static rule can point at these; rls-probe also **runs the queries** as `anon` and as user A against user B's rows and tells you what the database actually allowed.

### Other tools exist
Other tools approach the same problem differently: SQL scripts you paste into the Supabase SQL editor that inspect a live project's catalogs, test generators that write RLS test files for you to run, and Supabase's own database linter. They are useful, and rls-probe is not a replacement for all of them. What is different here is that **nothing touches your live project** (it works from files, so it fits a pull request or a project you only have a repository for), and that **findings are backed by queries that were actually executed** against your policies in the sandbox, not only by reading the catalog. The price of that design: it sees only the SQL you supply, so anything changed in the dashboard, any data, and any Auth setting is outside what it can check (see "Honest limits").

```
rls-probe: 20/20 statements loaded from 1 file(s)
findings: CRITICAL 3  HIGH 8  MEDIUM 0  LOW 4  INFO 1   | failing access tests: 33
  [CRITICAL] public.member_directory: A public view exposes auth.users (emails and account data) to the API
  [CRITICAL] public.orders: Table is open to the API with Row Level Security turned off
  ...
after draft fix: CRITICAL 0  HIGH 2  MEDIUM 1  | failing access tests: 1  (3 item(s) need a human decision)
```

A full sample report on a fictional app is in [`samples/`](samples/): [report](samples/habithub-report.md), [draft fix SQL](samples/habithub-draft-fix.sql).

## What v0.2 adds over v0.1
- **SARIF 2.1.0 output** (`--sarif`) for GitHub code scanning and other SARIF tools. The files the CLI writes are checked against the official OASIS schema in the tests.
- **GitHub annotations** (`--format github`): every MEDIUM or higher finding becomes an `::error` / `::warning` on the file and lines that define the object.
- **File and line for findings**, in the JSON, SARIF, annotations and summary, attached only when the mapping is certain (details below).
- **A composite GitHub Action** (`action.yml`) plus two example workflows in [`examples/`](examples/): annotations, a run summary, step outputs, optional SARIF.
- **Safe handling of `pg_dump` files that contain data.** `COPY ... FROM stdin` blocks (and `\copy`) and `INSERT` statements are skipped, counted and never loaded or printed. A `COPY` block used to hang the engine; that is fixed and covered by a regression test.
- **A hard time limit** (`--timeout`, default 60 s, exit code 70) enforced from a worker thread, so a statement that never finishes cannot hang a CI job. A few statements that would stall the sandbox (`LISTEN`, long `pg_sleep`, `DO` blocks calling `pg_sleep`) are skipped and listed.

## Quick start

```bash
git clone https://github.com/sahan411/rls-probe && cd rls-probe && npm install
node bin/cli.mjs path/to/supabase/migrations --out report.md
```

The package's command is `rls-probe` (`bin` in `package.json`); from a clone, `node bin/cli.mjs` runs the same program (the examples below use it). Node 20 or newer is declared in `engines`; the tests and the Action run on Node 24. The first install pulls the Postgres WASM engine from npm (about 25 MB on disk).

### Where do I get the schema?
Any one of these (all contain structure only, no data and no secrets):
1. **Lovable / Bolt / Cursor projects exported to GitHub:** the `supabase/migrations/` folder in the repo.
2. **Supabase CLI:** `supabase db dump --schema public -f schema.sql`
3. **pg_dump:** `pg_dump --schema-only --no-owner --schema=public "$DATABASE_URL" > schema.sql` (run it yourself; the tool never needs the connection string)

A dump that does contain data (`pg_dump` without `--schema-only`) is accepted: the data is skipped, see "Row data".

Several files or folders can be passed; `.sql` files are loaded in name order (migration timestamps sort correctly).

### Usage
```
node bin/cli.mjs <file-or-folder...> [options]
node bin/cli.mjs supabase/migrations --fail-on medium --sarif results.sarif --summary-file summary.md
node bin/cli.mjs supabase/migrations --format github        # annotations for a CI log
node bin/cli.mjs schema.sql --out report.md --html report.html --fix fix.sql
```

| Option | Meaning |
|---|---|
| `--out report.md`, `--html report.html`, `--json report.json` | write reports (print the HTML to PDF in a browser) |
| `--sarif out.sarif` | write a SARIF 2.1.0 log |
| `--summary-file s.md` | write a compact Markdown summary (the Action appends it to the run summary) |
| `--format text\|github` | console output: a plain list (default) or GitHub `::error` / `::warning` annotations |
| `--fix fix.sql` | write a **draft** fix migration, apply it to a fresh copy and re-audit (before/after) |
| `--schemas public,api` | schemas exposed through the Data API (default `public`) |
| `--no-probe` | skip the executed access tests |
| `--default-grants on\|off` | assume Supabase's default privileges on `public` (default `on`) |
| `--fail-on high\|medium\|never` | exit code 2 when findings at that level exist (CI gate; default `high`) |
| `--timeout seconds` | abort the whole audit after this long (default 60), exit code 70 |
| `--title "text"`, `--badge "text"` | report title and banner line |

### Exit codes
| Code | Meaning |
|---|---|
| `0` | the audit finished and no finding reached the `--fail-on` level (always, with `--fail-on never`) |
| `1` | internal error, for example an output file could not be written; one `error:` line on stderr |
| `2` | at least one CRITICAL or HIGH finding (with `--fail-on medium`: or MEDIUM), or a failing executed access test at that level |
| `64` | usage error: unknown option, missing or invalid value |
| `66` | nothing to audit: path not found, or no `.sql` file in it |
| `70` | the audit did not finish within `--timeout` |

## GitHub Action

```yaml
# .github/workflows/rls-audit.yml
name: RLS audit
on: pull_request
permissions:
  contents: read
jobs:
  rls-audit:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: sahan411/rls-probe@v0.2.1   # pin the full commit SHA of the release you reviewed
        with:
          path: supabase/migrations
          fail-on: high
```

The `v0.2.1` reference only resolves once that tag exists in `sahan411/rls-probe`. A tag can be moved; the commit SHA behind it cannot.

| Input | Default | Meaning |
|---|---|---|
| `path` | `supabase/migrations` | folders or `.sql` files relative to the repository root, one per line |
| `fail-on` | `high` | `high`, `medium` or `never` (same as the CLI) |
| `schemas` | `public` | comma-separated schemas exposed through the API |
| `default-grants` | `on` | `on` or `off` (same as the CLI) |
| `sarif` | `false` | `true` also writes `$RUNNER_TEMP/rls-probe/results.sarif` |
| `timeout` | `60` | seconds before the audit is aborted |

Outputs: `critical`, `high`, `medium` (counts), `failing-tests` (failing executed access tests) and `sarif-file` (only when `sarif` is `true`). The outputs are written even when the step fails because of findings; the run summary (verdict, counts, findings with file and line, failing tests) is appended in a step that also runs after a failure. The summary lists at most 40 findings; use the CLI with `--out` for the full report.

What the action does and does not do:
- It needs **no secret and no token**; `permissions: contents: read` is enough for the audit, annotations and summary.
- Inputs reach the program only as environment variables and an argument array, never through a shell command line, so a path or value from a pull request cannot inject shell syntax. Names taken from the audited SQL are neutralised before they are printed (annotation escaping, one line per message, Markdown escaping in the summary).
- The **audit itself opens no network connection** and sends the schema nowhere; the test suite records socket, DNS, `fetch` and UDP use in the main thread and the worker and requires it to stay empty. The setup steps do use the network: `actions/setup-node` downloads Node 24 and `npm ci --omit=dev --ignore-scripts` installs the `@electric-sql/pglite` dependency from the npm registry. `setup-node` also puts Node 24 on the `PATH` of later steps in the same job.
- Third-party actions in the action and in the examples are pinned to full commit SHAs.

### Upload to GitHub code scanning (optional)
[`examples/github-workflow-sarif.yml`](examples/github-workflow-sarif.yml) adds `sarif: "true"` and a `github/codeql-action/upload-sarif` step with `if: always()`, so results are uploaded when the audit fails on findings. It needs `security-events: write` (private repositories also `actions: read`), code scanning must be available for the repository, and pull requests from forks get a read-only token, so the upload cannot work there (the audit, annotations and summary still do).

SARIF level mapping: CRITICAL and HIGH are `error`, MEDIUM is `warning`, LOW and INFO are `note`. GitHub only shows results that have a file location, so a finding without a location stays in the annotations and the summary. No `security-severity` score is written: one rule here spans several severities, so a per-rule score would mislabel some alerts. The SARIF files are validated against the official schema, but the upload to GitHub itself is not exercised by the tests.

## Row data in dumps
A `pg_dump` taken without `--schema-only` contains your rows. The tool does not need them and does not touch them:
- every `COPY ... FROM stdin` block (and `\copy`, with its inline rows, up to the `\.` line) and every `INSERT` (including `WITH ... INSERT`) is skipped, counted, and reported as "N data statement(s) skipped";
- the one `INSERT` that is executed is into `storage.buckets`, because the public-bucket check reads bucket settings;
- skipped rows are not stored, not echoed in the console, Markdown, HTML, JSON, SARIF, summary or fix SQL (the tests scan every output of a dump full of fake personal data for it);
- a `COPY` block that never reaches its `\.` line swallows the rest of its file; that is reported instead of being silent.

Other statements in your migrations (`UPDATE`, `DELETE`, `create function`, ...) are executed against the empty sandbox like any other SQL. If a statement cannot be loaded, its first 140 characters are shown in the "could not be loaded" list.

## File and line locations
A finding carries `locations: [{ file, line, endLine }]` when the loader can say with certainty which statement defines the object: the first and last line of the `CREATE` statement of the table, view, function or policy, relative to the repository root (`GITHUB_WORKSPACE` in Actions, otherwise the working directory), with forward slashes. A location is recorded only after the statement loaded without error, and the latest `CREATE` wins. It is dropped instead of guessed when the object was renamed, moved to another schema, given a changed policy (`ALTER POLICY`), when a function of that name was dropped or renamed, when the function is overloaded, when the `search_path` makes an unqualified name ambiguous, or when the file lies outside the repository. Objects created inside `DO` blocks or dynamic SQL have no location. The location is where the object is defined, which is not always the line that has to change (for a table with RLS off, the missing `enable row level security` has no line).

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
Your SQL is loaded statement by statement into [PGlite](https://pglite.dev) (real PostgreSQL compiled to WASM, in-process, no network) on top of a small emulation of Supabase's roles, `auth.users`, `auth.uid()` and `storage`. The audit runs in a worker thread so the time limit can be enforced. Findings come from the real catalogs (`pg_class`, `pg_policies`, `pg_proc`, `has_table_privilege`, ...). Access tests run `set local role anon|authenticated` with JWT claims and roll back. Statements that cannot be loaded are listed, never silently dropped.

## Honest limits
- A schema-level review, not a penetration test; no tool can guarantee security. The schema is loaded into a local sandbox only: no live project, no network, no keys.
- Schema-only: no data, no Auth/dashboard settings, no Edge Function logic, no leaked-key scan, no business-logic review. Row data in a dump is skipped and never printed.
- Assumes Supabase's default public-schema privileges (switch off with `--default-grants off`).
- Extensions the sandbox cannot load (e.g. `pg_graphql`, `pgsodium`) are skipped and reported.
- Tables whose columns the seeder cannot fill are reported as skipped, not passed.
- File and line locations exist only where the mapping is certain (see above); findings without one still appear in the report, the annotations (without a file) and the summary, but not in GitHub code scanning.
- A statement that blocks without being recognised is only stopped by `--timeout`; the audit then produces no report (exit code 70). SQL-standard `BEGIN ATOMIC` function bodies are not split correctly.
- The draft fix is mechanical for owner-scoped tables and views/functions; anything needing a product decision is listed for a human. Review before applying.
- Tested with Node 24 (the Action uses Node 24) on Windows; the Linux runner path and the upload to GitHub code scanning are not exercised by the tests.

## Tests
`npm test` runs 88 tests in 8 files (Node's built-in runner, no extra framework). Most of them boot a throw-away Postgres, so expect one to two minutes: 66 to 110 seconds on the development machine (an 8-thread laptop, files running in parallel). What they cover:
- `audit.test.js`: the planted mistakes of a vulnerable schema, the executed probes, a hand-secured twin (must stay quiet), a `pg_dump`-style file with psql meta-commands, the draft fix, and Supabase's own starter migration as an independent check against false alarms;
- `data-safety.test.js`: `COPY` / `\copy` / `INSERT` skipping, the hang regression, no row data in any output, risky statements, the timeout;
- `locations.test.js`: file and line of every located finding, and the cases where a location must be left out;
- `formats.test.js`: GitHub annotation escaping (checked against a model of the runner's parser), hostile names, the Markdown summary;
- `sarif.test.js`: SARIF structure, level mapping, rule ids, relative URIs, and validation against the official `sarif-schema-2.1.0.json` (downloaded once, pinned by SHA-256, cached in `node_modules/.cache`; **skipped with a message when offline**, or point `RLS_SARIF_SCHEMA` at a local copy);
- `ci.test.js`: the Action's inputs and outputs, `action.yml` and the example workflows (SHA pinning, no `${{ }}` inside scripts, least privilege), and `bin/ci.mjs` end to end with hostile inputs;
- `cli.test.js`: every exit code, every output file, path handling, no row data and no network use;
- `restrictive.test.js`: RESTRICTIVE policies only narrow access, so a RESTRICTIVE policy with a literal `true` is not reported as always-true and a RESTRICTIVE storage policy is not reported as broad write, while the same text written as PERMISSIVE still is.

The test-only dependencies (`ajv`, `ajv-draft-04`, `ajv-formats`, `yaml`) are `devDependencies`; the Action installs with `--omit=dev` and the package ships only `bin/`, `src/`, `examples/` and `action.yml`.

## Need it fixed and verified?
Applying the fixes safely (policies that match how your app really works, re-tested before and after) is a paid service; see the profile on this account. The tool itself is free (MIT).

License: MIT
