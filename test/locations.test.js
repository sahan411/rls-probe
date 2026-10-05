import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { audit } from "../src/audit.js";
import { LocationIndex } from "../src/locations.js";
import { fixture, auditFixture, lineOf, closingLine, here } from "./helpers.js";
import { join } from "node:path";

const loc = (f) => (f.locations ? f.locations.map((l) => `${l.file}:${l.line}-${l.endLine}`) : null);
const byRuleObject = (res, rule, object) => res.findings.find((f) => f.rule === rule && f.object === object);

test("vulnerable schema: every located finding points at the exact first and last line of the statement that defines it", async () => {
  const [{ text }] = fixture("vulnerable", { withPaths: true });
  const FILE = "test/fixtures/vulnerable/001_schema.sql";
  const at = (start, end = null, from = 1) => {
    const a = lineOf(text, start, from);
    return `${FILE}:${a}-${end ? closingLine(text, a, end) : a}`;
  };
  const expected = [
    ["RLS-DISABLED", "public.profiles", at("create table public.profiles (", ");")],
    ["RLS-DISABLED", "public.orders", at("create table public.orders (", ");")],
    ["RLS-DISABLED", "public.audit_log", at("create table public.audit_log (", ");")],
    ["POLICY-NO-RLS", "public.audit_log", at('create policy "log insert"')],
    ["POLICY-ALWAYS-TRUE", "public.audit_log", at('create policy "log insert"')],
    ["POLICY-ALWAYS-TRUE", "public.notes", at('create policy "Anyone can do anything"')],
    ["POLICY-ALWAYS-TRUE", "public.categories", at('create policy "categories readable"')],
    ["USER-METADATA-POLICY", "public.workspace_settings", at('create policy "admins manage settings"', "with check ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');")],
    ["AUTH-INITPLAN", "public.workspace_settings", at('create policy "admins manage settings"', "with check ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');")],
    ["AUTH-USERS-EXPOSED", "public.member_directory", at("create view public.member_directory as", "select id, email, raw_user_meta_data from auth.users;")],
    ["VIEW-DEFINER", "public.note_counts", at("create view public.note_counts as", "select user_id, count(*) as n from public.notes group by user_id;")],
    ["DEFINER-FUNCTION", "public.promote_to_admin(target uuid)", at("create function public.promote_to_admin", "end $$;")],
    ["STORAGE-BROAD-WRITE", "storage.objects", at('create policy "anyone can upload"')],
    ["STORAGE-BROAD-READ", "storage.objects", at('create policy "anyone can read uploads"')],
  ];
  // checked with the probes on: the executed tests must not change where a finding points
  const res = await auditFixture("vulnerable", {}, { withPaths: true });
  for (const [rule, object, where] of expected) {
    const f = byRuleObject(res, rule, object);
    assert.ok(f, `${rule} ${object} missing`);
    assert.deepEqual(loc(f), [where], `${rule} ${object}`);
  }
  // the one function without a fixed search_path that the API can call is slugify, nothing else
  const slug = res.findings.find((f) => f.rule === "FUNC-SEARCH-PATH");
  assert.deepEqual(loc(slug), [at("create function public.slugify", "$$;")]);
  // a bucket row is data, not a definition: no location rather than a guess
  assert.equal(byRuleObject(res, "PUBLIC-BUCKET", "storage.buckets").locations, undefined);
  // no located finding carries more than one location here, and the list above covers every other finding
  const unexpected = res.findings.filter((f) => !expected.some(([r, o]) => r === f.rule && o === f.object) && f.rule !== "FUNC-SEARCH-PATH" && f.rule !== "PUBLIC-BUCKET");
  assert.deepEqual(unexpected.map((f) => `${f.rule} ${f.object}`), []);
});

test("generic check on every fixture: each location is a CREATE statement for the very object the finding names", async () => {
  const dirs = readdirSync(join(here, "fixtures")).sort();
  let checked = 0;
  for (const dir of dirs) {
    const files = fixture(dir, { withPaths: true });
    if (dir === "busy") continue; // deliberately never finishes
    const res = await auditFixture(dir, dir === "vulnerable" ? {} : { probe: false }, { withPaths: true }); // vulnerable: the run of the first test
    const textOf = Object.fromEntries(files.map((f) => [f.path, f.text.split(/\r?\n/)]));
    for (const f of res.findings) {
      for (const l of f.locations || []) {
        const lines = textOf[l.file];
        assert.ok(lines, `${dir}: location in unknown file ${l.file}`);
        assert.ok(l.line >= 1 && l.endLine >= l.line && l.endLine <= lines.length, `${dir}: ${f.rule} ${f.object} line range ${l.line}-${l.endLine}`);
        const stmt = lines.slice(l.line - 1, l.endLine).join("\n").replace(/"/g, "");
        const label = `${dir}: ${f.rule} ${f.object} -> ${l.file}:${l.line}-${l.endLine}`;
        if (f.evidence?.policy || f.evidence?.policies) {
          const names = f.evidence.policy ? [f.evidence.policy] : f.evidence.policies;
          assert.match(stmt, /^\s*create\s+policy\b/i, label);
          assert.ok(names.some((n) => stmt.includes(n)) || f.rule === "POLICY-NO-RLS", label);
        } else if (f.evidence?.fn || f.evidence?.fns) {
          const names = f.evidence.fn ? [f.evidence.fn.name] : f.evidence.fns.map((x) => x.name);
          assert.match(stmt, /^\s*create\s+(or\s+replace\s+)?(function|procedure)\b/i, label);
          assert.ok(names.some((n) => stmt.includes(n)), label);
        } else {
          assert.match(stmt, /^\s*create\s+(or\s+replace\s+)?(unlogged\s+)?(table|view|materialized\s+view|foreign\s+table)\b/i, label);
          assert.ok(stmt.includes(f.object.split(".").pop()), label);
        }
        checked++;
      }
    }
  }
  assert.ok(checked >= 25, `only ${checked} locations were checked`);
});

test("locations stay exact after COPY data blocks and with CRLF line endings", async () => {
  const [{ text }] = fixture("pgdump-data", { withPaths: true });
  const res = await auditFixture("pgdump-data", { probe: false }, { withPaths: true });
  const FILE = "test/fixtures/pgdump-data/schema.sql";
  const start = (needle) => lineOf(text, needle);
  assert.deepEqual(loc(byRuleObject(res, "RLS-DISABLED", "public.after_data")), [`${FILE}:${start("CREATE TABLE public.after_data (")}-${closingLine(text, start("CREATE TABLE public.after_data ("), ");")}`]);
  assert.deepEqual(loc(byRuleObject(res, "RLS-DISABLED", "public.audit_events")), [`${FILE}:${start("CREATE TABLE public.audit_events (")}-${closingLine(text, start("CREATE TABLE public.audit_events ("), ");")}`]);
  assert.ok(start("CREATE TABLE public.after_data (") > start("\\."), "the table under test really sits after the data block");

  const vuln = fixture("vulnerable", { withPaths: true });
  const lf = await auditFixture("vulnerable", {}, { withPaths: true });
  const crlf = await audit(vuln.map((f) => ({ ...f, text: f.text.replace(/\n/g, "\r\n") })), { probe: false });
  assert.deepEqual(crlf.findings.map((f) => [f.rule, f.object, loc(f)]), lf.findings.map((f) => [f.rule, f.object, loc(f)]));
  assert.ok(lf.findings.filter((f) => f.locations).length >= 14);
});

test("ambiguity removes a location instead of guessing; the latest definition wins; path null/omitted behave as documented", async () => {
  const a = [
    "create table public.plain (id int);", // 1
    "create table public.redo (id int);", // 2
    "drop table public.redo;", // 3
    "create table public.redo (", // 4
    "  id int", // 5
    ");", // 6
    "create table public.once (id int);", // 7
    "create table if not exists public.once (id int, extra int);", // 8 (no-op: the table exists)
    "create table public.old_name (id int);", // 9
    "alter table public.old_name rename to new_name;", // 10
    "create table public.failing (id int, id int);", // 11 (fails to load)
    "create table public.moved (id int);", // 12 (re-created in b.sql)
    "create table public.pol (id uuid primary key default gen_random_uuid(), user_id uuid references auth.users(id));", // 13
    "alter table public.pol enable row level security;", // 14
    "create policy keep_me on public.pol for insert to anon with check (true);", // 15
    "create policy altered on public.pol for update to anon using (true);", // 16
    "alter policy altered on public.pol using (true);", // 17
    "create policy recreated on public.pol for delete to anon using (true);", // 18
    "drop policy recreated on public.pol;", // 19
    "create policy recreated on public.pol for delete to anon using (true);", // 20
    "create function public.solo() returns void language sql security definer as $$ select 1 $$;", // 21
    "create or replace function public.solo() returns void language sql security definer as $$ select 2 $$;", // 22
    "create function public.dup(a int) returns void language sql security definer as $$ select 1 $$;", // 23
    "create function public.dup(a text) returns void language sql security definer as $$ select 1 $$;", // 24
    "create function public.gone() returns void language sql security definer as $$ select 1 $$;", // 25
    "drop function public.gone();", // 26
    "create function public.gone() returns void language sql security definer as $$ select 1 $$;", // 27
    "do $$ begin execute 'create table public.dyn (id int)'; end $$;", // 28 (dynamic SQL: the table exists, its definition cannot be located)
  ].join("\n");
  const b = ["drop table public.moved;", "create table public.moved (id int, more int);", "create table public.in_b (id int);"].join("\n");
  const c = "create table public.no_path (id int);";
  const d = "create table public.by_name (id int);";
  const res = await audit([
    { name: "a.sql", path: "db/a.sql", text: a },
    { name: "b.sql", path: "db/b.sql", text: b },
    { name: "c.sql", path: null, text: c },
    { name: "d.sql", text: d },
  ], { probe: false });

  assert.deepEqual(res.load.failed.map((x) => [x.file, x.line]), [["a.sql", 11]]);
  const rls = (t) => byRuleObject(res, "RLS-DISABLED", `public.${t}`);
  assert.deepEqual(loc(rls("plain")), ["db/a.sql:1-1"]);
  assert.deepEqual(loc(rls("redo")), ["db/a.sql:4-6"], "drop and re-create: the live definition is the latest one");
  assert.deepEqual(loc(rls("once")), ["db/a.sql:7-7"], "CREATE TABLE IF NOT EXISTS that did nothing must not move the location");
  assert.equal(rls("new_name").locations, undefined, "renamed table: unknown rather than wrong");
  assert.equal(rls("old_name"), undefined);
  assert.equal(rls("failing"), undefined);
  assert.ok(rls("dyn"), "a table created by dynamic SQL is still audited");
  assert.equal(rls("dyn").locations, undefined, "but it has no location");
  assert.deepEqual(loc(rls("moved")), ["db/b.sql:2-2"], "a later file wins");
  assert.deepEqual(loc(rls("in_b")), ["db/b.sql:3-3"]);
  assert.equal(rls("no_path").locations, undefined, "path: null means the file is outside the repository");
  assert.deepEqual(loc(rls("by_name")), ["d.sql:1-1"], "no path: falls back to the file name");

  const pol = (name) => res.findings.find((f) => f.rule === "POLICY-ALWAYS-TRUE" && f.evidence.policy === name);
  assert.deepEqual(loc(pol("keep_me")), ["db/a.sql:15-15"]);
  assert.equal(pol("altered").locations, undefined, "ALTER POLICY changes the definition: no location");
  assert.deepEqual(loc(pol("recreated")), ["db/a.sql:20-20"], "drop policy then create policy: the new statement");

  const fn = (name, args) => res.findings.find((f) => f.rule === "DEFINER-FUNCTION" && f.evidence.fn.name === name && f.object.endsWith(`(${args})`));
  assert.deepEqual(loc(fn("solo", "")), ["db/a.sql:22-22"], "CREATE OR REPLACE FUNCTION: the replacing statement");
  assert.equal(fn("dup", "a integer").locations, undefined, "overloaded function: cannot tell which statement defines which");
  assert.equal(fn("dup", "a text").locations, undefined);
  assert.equal(fn("gone", "").locations, undefined, "a dropped function of that name makes the mapping uncertain");
});

test("LocationIndex: statement forms, quoting, temp objects, search_path and drops", () => {
  const idx = new LocationIndex();
  let n = 0;
  const run = (sql) => { n++; idx.apply(idx.effectOf(sql), { file: "m.sql", line: n, endLine: n }); return n; };
  const line = (r) => (r ? r.line : null);

  assert.equal(line(idx.relation("public.a")), null);
  const a = run("create table public.a (id int)");
  assert.equal(line(idx.relation("public.a")), a);
  assert.equal(line(idx.relation(`public.my table`)), null);
  const q = run('create table "Public"."My Table" (id int)');
  assert.equal(line(idx.relation("Public.My Table")), q, "quoted names keep their case");
  const u = run("create unlogged table public.u (id int)");
  assert.equal(line(idx.relation("public.u")), u);
  run("create temp table public.tmp (id int)");
  run("create temporary table tmp2 (id int)");
  assert.equal(idx.relation("public.tmp"), null);
  assert.equal(idx.relation("public.tmp2"), null);
  const m = run("create materialized view public.m as select 1");
  assert.equal(line(idx.relation("public.m")), m);
  const v = run("create or replace view v as select 1");
  assert.equal(line(idx.relation("public.v")), v, "unqualified names resolve to public by default");
  const v2 = run("create or replace view v as select 2");
  assert.equal(line(idx.relation("public.v")), v2);

  // ALTER TABLE that keeps the identity changes nothing; rename and set schema make the old mapping invalid
  run("alter table public.a add column x int");
  run("alter table public.a rename column x to y");
  assert.equal(line(idx.relation("public.a")), a);
  run("alter table if exists only public.a rename to z");
  assert.equal(idx.relation("public.a"), null);
  const b = run("create table public.b (id int)");
  run("alter table public.b set schema other");
  assert.equal(idx.relation("public.b"), null);
  assert.notEqual(b, null);

  // search_path: unqualified names are only trusted while public comes first
  run("set search_path = extensions");
  run("create table after_path (id int)");
  assert.equal(idx.relation("public.after_path"), null);
  const qualified = run("create table public.qualified (id int)");
  assert.equal(line(idx.relation("public.qualified")), qualified, "qualified names do not depend on the search_path");
  run("set search_path to public, extensions");
  const back = run("create table back_in_public (id int)");
  assert.equal(line(idx.relation("public.back_in_public")), back);
  run("select pg_catalog.set_config('search_path', '', false)");
  run("create table dump_style (id int)");
  assert.equal(idx.relation("public.dump_style"), null);
  run("reset search_path");
  const reset = run("create table after_reset (id int)");
  assert.equal(line(idx.relation("public.after_reset")), reset);

  // drops: tables take their policies with them; DROP SCHEMA takes everything of that schema
  const t = run("create table public.t (id int)");
  const p = run("create policy pp on public.t for select using (true)");
  assert.equal(line(idx.policy("public.t", "pp")), p);
  run("drop table if exists public.t, public.nothing");
  assert.equal(idx.relation("public.t"), null);
  assert.equal(idx.policy("public.t", "pp"), null);
  assert.notEqual(t, null);
  run("create table public.s (id int)");
  run("create function public.f() returns int language sql as 'select 1'");
  run("drop schema public cascade");
  assert.equal(idx.relation("public.s"), null);
  assert.equal(idx.fn("public", "f", 1), null);
});

test("LocationIndex: functions are located only when the name is unique and was never dropped or renamed", () => {
  const idx = new LocationIndex();
  idx.apply(idx.effectOf("create function public.f(a int) returns int language sql as 'select 1'"), { file: "m.sql", line: 1, endLine: 1 });
  assert.equal(idx.fn("public", "f", 1).line, 1);
  assert.equal(idx.fn("public", "f", 2), null, "two overloads in the catalog");
  idx.apply(idx.effectOf("create function public.g() returns int language sql as 'select 1'"), { file: "m.sql", line: 2, endLine: 2 });
  idx.apply(idx.effectOf("alter function public.g() rename to g2"), { file: "m.sql", line: 3, endLine: 3 });
  assert.equal(idx.fn("public", "g", 1), null);
  idx.apply(idx.effectOf("alter function public.f(int) owner to postgres"), { file: "m.sql", line: 4, endLine: 4 });
  assert.equal(idx.fn("public", "f", 1).line, 1, "ALTER FUNCTION ... OWNER does not change the definition");
  idx.apply(idx.effectOf("drop function public.f(int)"), { file: "m.sql", line: 5, endLine: 5 });
  assert.equal(idx.fn("public", "f", 1), null);
});

test("statements that are only skipped (data) never create or move a location", async () => {
  const res = await audit([{ name: "d.sql", path: "d.sql", text: [
    "create table public.t (id int);", // 1
    "COPY public.t (id) FROM stdin;", // 2
    "1", // 3
    "\\.", // 4
    "INSERT INTO public.t (id) VALUES (1);", // 5
    "create table public.u (id int);", // 6
  ].join("\n") }], { probe: false });
  assert.deepEqual(loc(byRuleObject(res, "RLS-DISABLED", "public.t")), ["d.sql:1-1"]);
  assert.deepEqual(loc(byRuleObject(res, "RLS-DISABLED", "public.u")), ["d.sql:6-6"]);
});
