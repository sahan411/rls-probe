import { test } from "node:test";
import assert from "node:assert/strict";
import { splitSql } from "../src/splitter.js";
import { classifyStatement } from "../src/sqlparse.js";
import { loadSchema } from "../src/loader.js";
import { audit } from "../src/audit.js";
import { toMarkdown, toHtml, toSummary } from "../src/report.js";
import { fixture, runCli, lineOf, here } from "./helpers.js";
import { join } from "node:path";

// A hung audit must fail the test, not stall the run.
function within(ms, promise, label) {
  const signal = AbortSignal.timeout(ms);
  return Promise.race([
    promise,
    new Promise((_, reject) => signal.addEventListener("abort", () => reject(new Error(`${label} did not finish within ${ms} ms (hang regression)`)))),
  ]);
}

test("splitter: COPY ... FROM stdin and \\copy data blocks are consumed up to the \\. line, line numbers stay exact", () => {
  const sql = [
    "create table t (a int);", // 1
    "COPY public.notes (id, body) FROM stdin;", // 2
    "1\ta;b'c jane@example.com", // 3
    "select 'not sql';\t-- semicolons; and quotes ' \" in data", // 4
    "\\.", // 5
    "create table u (b int);", // 6
    "\\copy public.t from stdin", // 7
    "x\ty", // 8
    "\\.  ", // 9 (trailing blanks are accepted)
    "create table v (c int);", // 10
  ].join("\n");
  const s = splitSql(sql);
  assert.deepEqual(s.map((x) => x.sql.split(/[ (]/)[0]), ["create", "COPY", "create", "\\copy", "create"]);
  assert.deepEqual(s.map((x) => x.line), [1, 2, 6, 7, 10]);
  assert.deepEqual(s.map((x) => x.kind), [undefined, "copy", undefined, "copy", undefined]);
  assert.equal(s[1].dataLines, 2);
  assert.equal(s[3].dataLines, 1);
});

test("splitter: a data line that is not exactly \\. does not end the block; CRLF input and a missing terminator are handled", () => {
  const trap = splitSql("COPY t (a) FROM stdin;\n\\\\.\nx \\.\n\\.\nselect 1;");
  assert.deepEqual(trap.map((x) => x.sql), ["COPY t (a) FROM stdin;", "select 1;"]);
  assert.equal(trap[0].dataLines, 2);
  assert.equal(trap[1].line, 5);

  const crlf = splitSql("COPY t (a) FROM stdin;\r\nrow;1\r\n\\.\r\nselect 2;\r\n");
  assert.deepEqual(crlf.map((x) => x.sql), ["COPY t (a) FROM stdin;", "select 2;"]);
  assert.equal(crlf[1].line, 4);

  const open = splitSql("select 1;\nCOPY t (a) FROM stdin;\nrow1;\nrow2;\n");
  assert.deepEqual(open.map((x) => x.sql), ["select 1;", "COPY t (a) FROM stdin;"]);

  // "from stdin" inside a string or a different COPY source must not swallow what follows
  const prog = splitSql("COPY t FROM PROGRAM 'cat from stdin';\ncreate table z (a int);");
  assert.deepEqual(prog.map((x) => x.sql.split(" ")[0]), ["COPY", "create"]);
  assert.equal(prog[1].line, 2);
});

test("splitter: endLine is the last line of the statement, comments and trailing blank lines excluded", () => {
  const s = splitSql("create table a (\n  id int, -- note\n  x int\n);\n\n-- tail\ncreate view v as\n  select 1\n\n");
  assert.deepEqual(s.map((x) => [x.line, x.endLine]), [[1, 4], [7, 8]]);
});

test("classifier: INSERT and COPY are data, except INSERT into storage.buckets; risky statements are skipped with a reason", () => {
  const c = (sql, kind) => classifyStatement({ sql, kind });
  assert.deepEqual(c("insert into public.t values (1)"), { action: "skip", category: "data", what: "insert" });
  assert.deepEqual(c('INSERT INTO "auth"."users" (id) VALUES (1)'), { action: "skip", category: "data", what: "insert" });
  assert.deepEqual(c("insert into notes values (1)"), { action: "skip", category: "data", what: "insert" });
  assert.deepEqual(c("copy public.t from stdin;"), { action: "skip", category: "data", what: "copy" });
  assert.deepEqual(c("\\copy t from 'f.csv'", "copy"), { action: "skip", category: "data", what: "copy" });
  assert.deepEqual(c("with x as (select 1 as id) insert into public.t select id from x"), { action: "skip", category: "data", what: "insert" }, "a data-modifying CTE is data too");
  assert.equal(c("with x as (select 'insert into' as s) select * from x").action, "run", "the words inside a string are not an INSERT");
  assert.deepEqual(c("insert into storage.buckets (id) values ('a')"), { action: "run" });
  assert.deepEqual(c('INSERT INTO "storage"."buckets" (id) VALUES (\'a\')'), { action: "run" });
  assert.equal(c("listen chan").category, "unsafe");
  assert.equal(c("select pg_sleep(30)").category, "unsafe");
  assert.equal(c("select pg_sleep(0.5)").action, "run");
  assert.equal(c("select pg_sleep(0.7), pg_sleep(0.7)").category, "unsafe", "durations add up");
  assert.equal(c("select pg_sleep(some_col) from t").category, "unsafe");
  assert.equal(c("select pg_sleep_for('1 hour')").category, "unsafe");
  assert.equal(c("do $$ begin perform pg_sleep(1); end $$").category, "unsafe");
  assert.equal(c("do $$ begin perform 1; end $$").action, "run");
  assert.equal(c("create function f() returns void language sql as $$ select pg_sleep(100) $$").action, "run", "a function BODY is not executed at creation");
  assert.equal(c("create table t (a int)").action, "run");
});

test("full pg_dump with COPY data and INSERT rows: no load failures, data skipped and counted, nothing loaded into the engine", async () => {
  const { db, load } = await within(30000, loadSchema(fixture("pgdump-data")), "loadSchema");
  try {
    assert.deepEqual(load.failed, []);
    assert.equal(load.dataSkipped, 4, "1 COPY + 2 INSERT into public.audit_events + 1 INSERT into auth.users");
    assert.deepEqual(load.skippedStatements, []);
    const count = async (table) => (await db.query(`select count(*)::int as c from ${table}`)).rows[0].c;
    assert.equal(await count("public.customers"), 0, "COPY rows must not be loaded");
    assert.equal(await count("public.audit_events"), 0, "INSERT rows must not be loaded");
    assert.equal(await count("auth.users"), 0, "INSERT into auth.users must not be loaded");
    assert.equal((await db.query("select to_regclass('public.customers') is not null as e")).rows[0].e, true, "DROP TABLE text inside COPY data must never run");
    assert.equal((await db.query("select to_regclass('public.after_data') is not null as e")).rows[0].e, true, "statements after the \\. line still load");
    assert.deepEqual((await db.query("select id, public from storage.buckets order by id")).rows, [{ id: "avatars", public: true }], "INSERT into storage.buckets keeps working");
  } finally {
    await db.close();
  }
});

test("full pg_dump with data: audit finishes, finds the public bucket, and no row data appears in any output", async () => {
  const res = await within(30000, audit(fixture("pgdump-data")), "audit");
  assert.equal(res.load.failed.length, 0);
  assert.equal(res.load.dataSkipped, 4);
  assert.ok(res.findings.some((f) => f.rule === "PUBLIC-BUCKET"), "the storage.buckets row is still read");
  // customers has RLS + an owner policy: its probes pass on the synthetic rows the prober seeds itself. The two tables without RLS
  // are meant to fail (that is the audit working), they are not a data problem.
  const failing = res.proof.probes.filter((p) => p.pass === false);
  assert.deepEqual([...new Set(failing.map((p) => p.table))].sort(), ["public.after_data", "public.audit_events"]);
  assert.ok(res.proof.probes.some((p) => p.table === "public.customers" && p.probe === "user A reads own rows" && p.pass === true));
  const everything = [JSON.stringify({ ...res, _model: undefined }), toMarkdown(res), toHtml(res), toSummary(res)].join("\n");
  for (const secret of ["jane.doe@example.com", "bob.fake@example.com", "carol.fake@example.com", "DROP TABLE public.customers"]) {
    assert.ok(!everything.includes(secret), `${secret} leaked into an output`);
  }
});

test("data skipping is announced: report load notes (Markdown, HTML, summary), CLI summary line and JSON", async () => {
  const res = await audit(fixture("pgdump-data"));
  const wording = /row data is ignored and never loaded/;
  const md = toMarkdown(res);
  assert.match(md, /## Load notes/);
  assert.match(md, wording);
  assert.match(md, /4 data statement\(s\) skipped/);
  assert.match(toHtml(res), wording);
  assert.match(toSummary(res), wording);

  assert.equal(JSON.parse(JSON.stringify(res.load)).dataSkipped, 4, "the count is part of the JSON output (res.load)");

  const cli = runCli([join(here, "fixtures", "pgdump-data"), "--fail-on", "never"]);
  assert.equal(cli.status, 0, cli.stdout + cli.stderr);
  assert.match(cli.stdout, /4 data statement\(s\) skipped \(row data is ignored and never loaded\)/);
});

test("regression: COPY ... FROM stdin used to hang the engine; audit() now returns, with a hard timeout around it", async () => {
  const text = "create table public.notes (id uuid primary key default gen_random_uuid(), user_id uuid, body text);\n"
    + "alter table public.notes enable row level security;\n"
    + "COPY public.notes (id, user_id, body) FROM stdin;\n"
    + "00000000-0000-4000-8000-000000000001\t00000000-0000-4000-8000-00000000000a\ta;b'c\tjane@example.com; \"q\"\n"
    + "\\.\n"
    + "create table public.other (id int);\n";
  const res = await within(20000, audit([{ name: "dump.sql", text }]), "audit() with a COPY block");
  assert.equal(res.load.failed.length, 0, JSON.stringify(res.load.failed));
  assert.equal(res.load.dataSkipped, 1);
  assert.ok(res.findings.some((f) => f.rule === "RLS-DISABLED" && f.object === "public.other"), "the statement after the COPY block was loaded");
});

test("statements that could stall the sandbox are skipped with a reason and the audit still finishes", async () => {
  const text = [
    "create table public.t (id int primary key, user_id uuid);", // 1
    "select pg_sleep(30);", // 2
    "select pg_sleep(0.1);", // 3 (allowed)
    "LISTEN some_channel;", // 4
    "do $$ begin perform pg_sleep(60); end $$;", // 5
    "select pg_sleep_for('5 minutes');", // 6
    "create table public.after (id int);", // 7
  ].join("\n");
  const started = Date.now();
  const res = await within(20000, audit([{ name: "risky.sql", text }]), "audit() with sleeping statements");
  assert.ok(Date.now() - started < 15000);
  assert.deepEqual(res.load.failed, []);
  assert.deepEqual(res.load.skippedStatements.map((s) => s.line), [2, 4, 5, 6]);
  assert.match(res.load.skippedStatements[0].reason, /pg_sleep\(30\) would stall the audit/);
  assert.match(res.load.skippedStatements[1].reason, /LISTEN/);
  assert.match(res.load.skippedStatements[2].reason, /DO block calls pg_sleep/);
  assert.match(res.load.skippedStatements[3].reason, /pg_sleep_for/);
  assert.equal(res.load.skippedStatements[0].file, "risky.sql");
  assert.ok(res.findings.some((f) => f.object === "public.after"), "statements after the skipped ones load");
  const md = toMarkdown(res);
  assert.match(md, /Statements that were not executed/);
  assert.match(md, /risky\.sql:2 pg_sleep\(30\)/);
  assert.match(toHtml(res), /could stall the audit/);
  assert.equal(lineOf(text, "LISTEN"), 4);
});

test("a COPY block without its terminating \\. line is reported instead of silently swallowing the rest of the file", async () => {
  const text = [
    "create table public.before_copy (id int);", // 1
    "COPY public.before_copy (id) FROM stdin;", // 2
    "1", // 3
    "create table public.hidden (id int);", // 4 (is data as far as the parser can tell)
  ].join("\n");
  const s = splitSql(text);
  assert.equal(s[1].unterminated, true);
  assert.equal(s[0].unterminated, undefined);
  const res = await audit([{ name: "cut.sql", text }]);
  assert.equal(res.load.dataSkipped, 1);
  assert.equal(res.load.skippedStatements.length, 1);
  assert.equal(res.load.skippedStatements[0].line, 2);
  assert.match(res.load.skippedStatements[0].reason, /no terminating \\\. line/);
  assert.ok(res.findings.some((f) => f.object === "public.before_copy"));
  assert.ok(!res.findings.some((f) => f.object === "public.hidden"), "what follows an unterminated block is data, not schema");
  assert.match(toMarkdown(res), /no terminating/);
  // a properly terminated block reports nothing
  const ok = await audit([{ name: "ok.sql", text: `${text.split("\n").slice(0, 3).join("\n")}\n\\.\ncreate table public.shown (id int);` }]);
  assert.deepEqual(ok.load.skippedStatements, []);
  assert.ok(ok.findings.some((f) => f.object === "public.shown"));
});

test("--timeout aborts a statement the loader cannot recognise, with a clear message and exit code 70", () => {
  const started = Date.now();
  const r = runCli([join(here, "fixtures", "busy"), "--timeout", "3"], { timeout: 60000 });
  assert.equal(r.status, 70, r.stdout + r.stderr);
  assert.match(r.stderr, /the audit did not finish within 3 second\(s\) and was aborted/);
  assert.match(r.stderr, /--timeout/);
  assert.ok(Date.now() - started < 30000, "must be killed promptly, not hang");
});
