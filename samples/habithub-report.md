# Supabase security audit: HabitHub (fictional demo app)

> **SAMPLE REPORT - FICTIONAL DEMO APP - NO REAL DATA**

Generated 2026-10-09T10:08:30.110Z by rls-probe 0.2.3 (PGlite (PostgreSQL 18, WASM sandbox)). Schemas checked: public.

Loaded 20 of 20 SQL statements from 1 file(s).

## Verdict

**Do not put real user data in this project yet.** 3 critical and 8 high-severity issue(s) let people read or change data they should not.

| Severity | Count |
|---|---|
| CRITICAL | 3 |
| HIGH | 8 |
| MEDIUM | 0 |
| LOW | 4 |
| INFO | 1 |

## Before and after the draft fix

| | Before | After |
|---|---|---|
| CRITICAL findings | 3 | 0 |
| HIGH findings | 8 | 2 |
| MEDIUM findings | 0 | 1 |
| LOW findings | 4 | 3 |
| Failing access tests | 33 | 1 |

## Findings

### CRITICAL

#### 1. A public view exposes auth.users (emails and account data) to the API
**Where:** `public.member_directory`  |  **Rule:** AUTH-USERS-EXPOSED (Supabase lint 0002_auth_users_exposed)

**Why it matters:** Views run with their owner's rights, so this view bypasses every protection on auth.users. Reachable by: anon (anyone with the public key) and authenticated (any signed-in user).

**Fix:** alter view public.member_directory set (security_invoker = on);  -- or drop the view and expose only the columns you need through a table with RLS

#### 2. Table is open to the API with Row Level Security turned off
**Where:** `public.orders`  |  **Rule:** RLS-DISABLED (Supabase lint 0013_rls_disabled_in_public)

**Why it matters:** Anyone holding the public (anon) key can use the auto-generated API to read and change every row. Privileges seen: anon can select/insert/update/delete; authenticated can select/insert/update/delete. It also holds sensitive-looking columns: card_token.

**Fix:** Enable RLS and add owner-scoped policies (draft SQL in the fix file).

#### 3. Table is open to the API with Row Level Security turned off
**Where:** `public.profiles`  |  **Rule:** RLS-DISABLED (Supabase lint 0013_rls_disabled_in_public)

**Why it matters:** Anyone holding the public (anon) key can use the auto-generated API to read and change every row. Privileges seen: anon can select/insert/update/delete; authenticated can select/insert/update/delete. It also holds sensitive-looking columns: stripe_customer_secret.

**Fix:** Enable RLS and add owner-scoped policies (draft SQL in the fix file).

### HIGH

#### 4. Table is open to the API with Row Level Security turned off
**Where:** `public.audit_log`  |  **Rule:** RLS-DISABLED (Supabase lint 0013_rls_disabled_in_public)

**Why it matters:** Anyone holding the public (anon) key can use the auto-generated API to read and change every row. Privileges seen: anon can select/insert/update/delete; authenticated can select/insert/update/delete. Policies exist but are NOT enforced because RLS is off.

**Fix:** Enable RLS and add owner-scoped policies (draft SQL in the fix file).

#### 5. Policies are defined but Row Level Security is disabled, so they do nothing
**Where:** `public.audit_log`  |  **Rule:** POLICY-NO-RLS (Supabase lint 0007_policy_exists_rls_disabled)

**Why it matters:** This usually means a migration created policies and forgot `alter table ... enable row level security`.

**Fix:** alter table public.audit_log enable row level security;

#### 6. Policy "log insert" lets anyone insert every row
**Where:** `public.audit_log`  |  **Rule:** POLICY-ALWAYS-TRUE (Supabase lint 0024_permissive_rls_policy)

**Why it matters:** The condition is literally `true` and the policy applies to the anonymous role (or to everyone), so it grants access with no check at all.

**Fix:** Replace the condition with an ownership or role check, e.g. `(select auth.uid()) = user_id`.

#### 7. View ignores Row Level Security of the tables it reads (runs as its owner)
**Where:** `public.note_counts`  |  **Rule:** VIEW-DEFINER (Supabase lint 0010_security_definer_view)

**Why it matters:** Postgres views are SECURITY DEFINER by default, so queries through this view skip RLS on tables that have it. Reachable by: anon (anyone with the public key) and authenticated (any signed-in user).

**Fix:** alter view public.note_counts set (security_invoker = on);

#### 8. Policy "Anyone can do anything" lets anyone read and write every row
**Where:** `public.notes`  |  **Rule:** POLICY-ALWAYS-TRUE (Supabase lint 0024_permissive_rls_policy)

**Why it matters:** The condition is literally `true` and the policy applies to the anonymous role (or to everyone), so it grants access with no check at all.

**Fix:** Replace the condition with an ownership or role check, e.g. `(select auth.uid()) = user_id`.

#### 9. SECURITY DEFINER function without a fixed search_path callable by anon and authenticated
**Where:** `public.promote_to_admin(target uuid)`  |  **Rule:** DEFINER-FUNCTION (Supabase lint 0011/0028/0029)

**Why it matters:** The function runs with its owner's (superuser-like) rights. Without `set search_path` a caller can shadow objects and escalate privileges. It is reachable as an RPC endpoint; it must check permissions inside.

**Fix:** alter function public.promote_to_admin(target uuid) set search_path = public;  -- prefer '' and schema-qualified names
-- and if logged-out users must not call it: revoke execute on function public.promote_to_admin(target uuid) from anon, public;

#### 10. Policy "admins manage settings" trusts user_metadata, which users can edit themselves
**Where:** `public.workspace_settings`  |  **Rule:** USER-METADATA-POLICY (Supabase lint 0015_rls_references_user_metadata)

**Why it matters:** user_metadata can be changed by the signed-in user (via auth.updateUser). A policy that grants access from it can be bypassed by anyone.

**Fix:** Use app_metadata (only the server can change it) or a separate roles table instead.

#### 11. Storage policy "anyone can upload" allows insert on files without tying them to a user
**Where:** `storage.objects`  |  **Rule:** STORAGE-BROAD-WRITE

**Why it matters:** Anyone can insert files in the covered bucket(s) (condition: (bucket_id = 'uploads'::text)).

**Fix:** Add a folder or owner check, e.g. `(storage.foldername(name))[1] = (select auth.uid())::text`.

### LOW

#### 12. Functions without a fixed search_path
**Where:** `1 function(s)`  |  **Rule:** FUNC-SEARCH-PATH (Supabase lint 0011_function_search_path_mutable)

**Why it matters:** Hygiene issue: public.slugify(t text).

**Fix:** Add `set search_path = public` (or '') to each function.

#### 13. Policy "categories readable" makes every row readable to anyone (confirm that is intended)
**Where:** `public.categories`  |  **Rule:** POLICY-ALWAYS-TRUE (Supabase lint 0024_permissive_rls_policy)

**Why it matters:** Fine for genuinely public reference data; confirm that is the intent.

**Fix:** If only some columns or rows should be public, expose them through a view or a narrower condition.

#### 14. Policies call auth.uid()/auth.jwt() per row instead of once per query
**Where:** `public.workspace_settings`  |  **Rule:** AUTH-INITPLAN (Supabase lint 0003_auth_rls_initplan)

**Why it matters:** Slower on big tables. Policies: admins manage settings.

**Fix:** Wrap calls: `(select auth.uid())` instead of `auth.uid()`.

#### 15. Storage policy "anyone can read uploads" lets anyone list every file in the bucket
**Where:** `storage.objects`  |  **Rule:** STORAGE-BROAD-READ (Supabase lint 0025_public_bucket_allows_listing)

**Why it matters:** A broad SELECT policy lets clients enumerate file names, not just open known URLs.

**Fix:** Public buckets serve files by URL without a SELECT policy; remove this policy unless listing is required.

### INFO

#### 16. 1 public bucket(s): uploads
**Where:** `storage.buckets`  |  **Rule:** PUBLIC-BUCKET

**Why it matters:** Files in public buckets are readable by anyone who knows or guesses the URL, with no policy involved.

**Fix:** Make sure nothing private (invoices, IDs, exports) is stored there.

## Proof: executed access tests

Each test ran as the stated role against seeded rows of two synthetic users (A and B), inside a transaction that was rolled back.

| Table | Test | Role | Expected | Observed | Result |
|---|---|---|---|---|---|
| `public.audit_log` | anon reads rows | anon | no rows | 2 of 2 seeded rows visible | **FAIL** |
| `public.audit_log` | anon inserts a row | anon | blocked | insert succeeded | **FAIL** |
| `public.audit_log` | anon updates rows | anon | blocked | 2 row(s) changed | **FAIL** |
| `public.audit_log` | anon deletes rows | anon | blocked | 2 row(s) deleted | **FAIL** |
| `public.audit_log` | user A reads user B's rows | authenticated | no rows | 1 of B's rows visible | **FAIL** |
| `public.audit_log` | user A reads own rows | authenticated | own rows visible | 1 of A's rows visible | PASS |
| `public.audit_log` | user A updates user B's rows | authenticated | blocked | 1 row(s) changed | **FAIL** |
| `public.audit_log` | user A deletes user B's rows | authenticated | blocked | 1 row(s) deleted | **FAIL** |
| `public.audit_log` | user A inserts a row owned by B | authenticated | blocked | forged row accepted | **FAIL** |
| `public.categories` | anon reads rows | anon | info | 2 of 2 seeded rows visible (no owner column, so intent unknown) | info |
| `public.categories` | anon inserts a row | anon | blocked | blocked (new row violates row-level security policy for table "categories") | PASS |
| `public.categories` | anon updates rows | anon | blocked | 0 row(s) changed | PASS |
| `public.categories` | anon deletes rows | anon | blocked | 0 row(s) deleted | PASS |
| `public.notes` | anon reads rows | anon | no rows | 2 of 2 seeded rows visible | **FAIL** |
| `public.notes` | anon inserts a row | anon | blocked | insert succeeded | **FAIL** |
| `public.notes` | anon updates rows | anon | blocked | 2 row(s) changed | **FAIL** |
| `public.notes` | anon deletes rows | anon | blocked | 2 row(s) deleted | **FAIL** |
| `public.notes` | user A reads user B's rows | authenticated | no rows | 1 of B's rows visible | **FAIL** |
| `public.notes` | user A reads own rows | authenticated | own rows visible | 1 of A's rows visible | PASS |
| `public.notes` | user A updates user B's rows | authenticated | blocked | 1 row(s) changed | **FAIL** |
| `public.notes` | user A deletes user B's rows | authenticated | blocked | 1 row(s) deleted | **FAIL** |
| `public.notes` | user A inserts a row owned by B | authenticated | blocked | forged row accepted | **FAIL** |
| `public.orders` | anon reads rows | anon | no rows | 2 of 2 seeded rows visible | **FAIL** |
| `public.orders` | anon inserts a row | anon | blocked | insert succeeded | **FAIL** |
| `public.orders` | anon updates rows | anon | blocked | 2 row(s) changed | **FAIL** |
| `public.orders` | anon deletes rows | anon | blocked | 2 row(s) deleted | **FAIL** |
| `public.orders` | user A reads user B's rows | authenticated | no rows | 1 of B's rows visible | **FAIL** |
| `public.orders` | user A reads own rows | authenticated | own rows visible | 1 of A's rows visible | PASS |
| `public.orders` | user A updates user B's rows | authenticated | blocked | 1 row(s) changed | **FAIL** |
| `public.orders` | user A deletes user B's rows | authenticated | blocked | 1 row(s) deleted | **FAIL** |
| `public.orders` | user A inserts a row owned by B | authenticated | blocked | forged row accepted | **FAIL** |
| `public.profiles` | anon reads rows | anon | no rows | 2 of 2 seeded rows visible | **FAIL** |
| `public.profiles` | anon inserts a row | anon | blocked | blocked (duplicate key value violates unique constraint "profiles_pkey") | PASS |
| `public.profiles` | anon updates rows | anon | blocked | 2 row(s) changed | **FAIL** |
| `public.profiles` | anon deletes rows | anon | blocked | 2 row(s) deleted | **FAIL** |
| `public.profiles` | user A reads user B's rows | authenticated | no rows | 1 of B's rows visible | **FAIL** |
| `public.profiles` | user A reads own rows | authenticated | own rows visible | 1 of A's rows visible | PASS |
| `public.profiles` | user A updates user B's rows | authenticated | blocked | 1 row(s) changed | **FAIL** |
| `public.profiles` | user A deletes user B's rows | authenticated | blocked | 1 row(s) deleted | **FAIL** |
| `public.profiles` | user A inserts a row owned by B | authenticated | blocked | blocked (duplicate key value violates unique constraint "profiles_pkey") | PASS |
| `public.workspace_settings` | anon reads rows | anon | no rows | 0 of 2 seeded rows visible | PASS |
| `public.workspace_settings` | anon inserts a row | anon | blocked | blocked (new row violates row-level security policy for table "workspace_settings") | PASS |
| `public.workspace_settings` | anon updates rows | anon | blocked | 0 row(s) changed | PASS |
| `public.workspace_settings` | anon deletes rows | anon | blocked | 0 row(s) deleted | PASS |
| `public.workspace_settings` | user A reads user B's rows | authenticated | no rows | 0 of B's rows visible | PASS |
| `public.workspace_settings` | user A reads own rows | authenticated | own rows visible | 0 of A's rows visible | **FAIL** |
| `public.workspace_settings` | user A updates user B's rows | authenticated | blocked | 0 row(s) changed | PASS |
| `public.workspace_settings` | user A deletes user B's rows | authenticated | blocked | 0 row(s) deleted | PASS |
| `public.workspace_settings` | user A inserts a row owned by B | authenticated | blocked | blocked (new row violates row-level security policy for table "workspace_settings") | PASS |
| `public.member_directory` | anon reads through the view | anon | no rows | 2 row(s) returned | **FAIL** |
| `public.note_counts` | anon reads through the view | anon | no rows | 2 row(s) returned | **FAIL** |

## Draft fix (SQL)

```sql
-- Draft fix generated by rls-probe. REVIEW before applying: owner-scoped policies assume each row belongs to the signed-in user.
-- If other users must read some rows (public profiles, shared items), add a narrower SELECT policy or a view for those fields.

alter view "public"."member_directory" set (security_invoker = on);

-- public.orders: RLS was off (CRITICAL); rows belong to user_id
alter table "public"."orders" enable row level security;
drop policy if exists "orders_select_own" on "public"."orders";
create policy "orders_select_own" on "public"."orders" for select to authenticated using ((select auth.uid()) = "user_id");
drop policy if exists "orders_insert_own" on "public"."orders";
create policy "orders_insert_own" on "public"."orders" for insert to authenticated with check ((select auth.uid()) = "user_id");
drop policy if exists "orders_update_own" on "public"."orders";
create policy "orders_update_own" on "public"."orders" for update to authenticated using ((select auth.uid()) = "user_id") with check ((select auth.uid()) = "user_id");
drop policy if exists "orders_delete_own" on "public"."orders";
create policy "orders_delete_own" on "public"."orders" for delete to authenticated using ((select auth.uid()) = "user_id");
revoke all on "public"."orders" from anon;  -- remove this line if logged-out visitors must read the table

-- public.profiles: RLS was off (CRITICAL); rows belong to id
alter table "public"."profiles" enable row level security;
drop policy if exists "profiles_select_own" on "public"."profiles";
create policy "profiles_select_own" on "public"."profiles" for select to authenticated using ((select auth.uid()) = "id");
drop policy if exists "profiles_insert_own" on "public"."profiles";
create policy "profiles_insert_own" on "public"."profiles" for insert to authenticated with check ((select auth.uid()) = "id");
drop policy if exists "profiles_update_own" on "public"."profiles";
create policy "profiles_update_own" on "public"."profiles" for update to authenticated using ((select auth.uid()) = "id") with check ((select auth.uid()) = "id");
drop policy if exists "profiles_delete_own" on "public"."profiles";
create policy "profiles_delete_own" on "public"."profiles" for delete to authenticated using ((select auth.uid()) = "id");
revoke all on "public"."profiles" from anon;  -- remove this line if logged-out visitors must read the table

-- public.audit_log: RLS was off (HIGH); rows belong to user_id
alter table "public"."audit_log" enable row level security;
drop policy if exists "audit_log_select_own" on "public"."audit_log";
create policy "audit_log_select_own" on "public"."audit_log" for select to authenticated using ((select auth.uid()) = "user_id");
drop policy if exists "audit_log_insert_own" on "public"."audit_log";
create policy "audit_log_insert_own" on "public"."audit_log" for insert to authenticated with check ((select auth.uid()) = "user_id");
drop policy if exists "audit_log_update_own" on "public"."audit_log";
create policy "audit_log_update_own" on "public"."audit_log" for update to authenticated using ((select auth.uid()) = "user_id") with check ((select auth.uid()) = "user_id");
drop policy if exists "audit_log_delete_own" on "public"."audit_log";
create policy "audit_log_delete_own" on "public"."audit_log" for delete to authenticated using ((select auth.uid()) = "user_id");
revoke all on "public"."audit_log" from anon;  -- remove this line if logged-out visitors must read the table

-- public.audit_log: replace always-true policy "log insert"
drop policy if exists "log insert" on "public"."audit_log";
alter table "public"."audit_log" enable row level security;
drop policy if exists "audit_log_insert_own" on "public"."audit_log";
create policy "audit_log_insert_own" on "public"."audit_log" for insert to authenticated with check ((select auth.uid()) = "user_id");

alter view "public"."note_counts" set (security_invoker = on);

-- public.notes: replace always-true policy "Anyone can do anything"
drop policy if exists "Anyone can do anything" on "public"."notes";
alter table "public"."notes" enable row level security;
drop policy if exists "notes_select_own" on "public"."notes";
create policy "notes_select_own" on "public"."notes" for select to authenticated using ((select auth.uid()) = "user_id");
drop policy if exists "notes_insert_own" on "public"."notes";
create policy "notes_insert_own" on "public"."notes" for insert to authenticated with check ((select auth.uid()) = "user_id");
drop policy if exists "notes_update_own" on "public"."notes";
create policy "notes_update_own" on "public"."notes" for update to authenticated using ((select auth.uid()) = "user_id") with check ((select auth.uid()) = "user_id");
drop policy if exists "notes_delete_own" on "public"."notes";
create policy "notes_delete_own" on "public"."notes" for delete to authenticated using ((select auth.uid()) = "user_id");

alter function "public"."promote_to_admin"(target uuid) set search_path = public;  -- check the body uses schema-qualified names; '' is stricter

-- public.workspace_settings: policy "admins manage settings" trusts user_metadata. Needs a human decision (see report).

alter policy "admins manage settings" on "public"."workspace_settings" using (((((select auth.jwt()) -> 'user_metadata'::text) ->> 'role'::text) = 'admin'::text)) with check (((((select auth.jwt()) -> 'user_metadata'::text) ->> 'role'::text) = 'admin'::text));
```

### Needs a human decision

- `public.promote_to_admin(target uuid)` (DEFINER-FUNCTION): Callable by logged-out users: confirm that is intended, otherwise `revoke execute ... from anon, public`.
- `public.workspace_settings` (USER-METADATA-POLICY): Rewrite policy "admins manage settings" to use app_metadata (server-controlled) or a roles table: e.g. (select auth.jwt() -> 'app_metadata' ->> 'role') = 'admin'.
- `storage.objects` (STORAGE-BROAD-WRITE): Storage policy "anyone can upload": restrict by folder, e.g. (storage.foldername(name))[1] = (select auth.uid())::text.

## What was and was not checked

- This is an audit of the schema and migrations you supplied (tables, views, functions, policies, grants) executed in a sandboxed Postgres. It never connects to your live project and never needs your keys.
- Not checked: leaked keys in code or git history, Edge Function and API route logic, Auth settings (email confirmation, OTP expiry, redirect URLs), hosting and dashboard configuration, rate limiting, business-logic abuse, and the actual data in your tables.
- Access tests use two synthetic users and seeded rows. Tables whose columns the seeder cannot fill are listed as skipped, not as passed.
- Assumes Supabase's default privileges for the public schema (all privileges granted to anon and authenticated; Row Level Security is what protects the data). Re-run with --default-grants off if your project removed them.
- Rule names follow Supabase's published database linter where one exists; this is an independent implementation, not the Supabase linter.
- This is a technical review, not a penetration test, and it cannot show that an application is secure. It reports what was tested, as of the date above.
