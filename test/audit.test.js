import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { splitSql } from "../src/splitter.js";
import { audit, auditWithFix } from "../src/audit.js";
import { toMarkdown } from "../src/report.js";

const here = dirname(fileURLToPath(import.meta.url));
const fx = (dir) => readdirSync(join(here, "fixtures", dir)).sort().map((f) => ({ name: f, text: readFileSync(join(here, "fixtures", dir, f), "utf8") }));
// the vulnerable schema is audited once for the two read-only tests below
let vulnerableRun;
const vulnerable = () => (vulnerableRun ||= audit(fx("vulnerable")));
const find = (res, rule, object) => res.findings.find((f) => f.rule === rule && (!object || f.object === object));
const probe = (res, table, name) => res.proof.probes.find((p) => p.table === table && p.probe === name);

test("splitter keeps dollar-quoted bodies, strings and comments intact", () => {
  const s = splitSql(`-- c1; not a statement
select 'a;b' as x; /* block; with ; */ select $$ x; y $$ as z;
create function f() returns int language plpgsql as $body$ begin return 1; end $body$;
select E'it\\'s;' as e;
\\restrict foo
select 1`);
  assert.deepEqual(s.map((x) => x.sql.split(" ")[0]), ["select", "select", "create", "select", "select"]);
  assert.match(s[1].sql, /\$\$ x; y \$\$/);
  assert.match(s[2].sql, /return 1; end/);
  assert.equal(s[0].line, 2);
});

test("vulnerable schema: every planted mistake is found with the right severity", async () => {
  const r = await vulnerable();
  assert.equal(r.load.failed.length, 0, JSON.stringify(r.load.failed));
  assert.equal(find(r, "RLS-DISABLED", "public.profiles").severity, "CRITICAL");
  assert.equal(find(r, "RLS-DISABLED", "public.orders").severity, "CRITICAL");
  assert.equal(find(r, "RLS-DISABLED", "public.audit_log").severity, "HIGH");
  assert.ok(find(r, "POLICY-NO-RLS", "public.audit_log"));
  assert.equal(find(r, "POLICY-ALWAYS-TRUE", "public.notes").severity, "HIGH");
  assert.equal(find(r, "USER-METADATA-POLICY", "public.workspace_settings").severity, "HIGH");
  assert.equal(find(r, "AUTH-USERS-EXPOSED", "public.member_directory").severity, "CRITICAL");
  assert.equal(find(r, "VIEW-DEFINER", "public.note_counts").severity, "HIGH");
  assert.equal(find(r, "DEFINER-FUNCTION", "public.promote_to_admin(target uuid)").severity, "HIGH");
  assert.ok(find(r, "STORAGE-BROAD-WRITE", "storage.objects"));
  assert.ok(find(r, "STORAGE-BROAD-READ", "storage.objects"));
  assert.ok(find(r, "PUBLIC-BUCKET", "storage.buckets"));
  assert.ok(find(r, "AUTH-INITPLAN", "public.workspace_settings"));
  assert.equal(find(r, "POLICY-ALWAYS-TRUE", "public.categories").severity, "LOW");
  assert.ok(find(r, "FUNC-SEARCH-PATH"));
  assert.ok(r.counts.CRITICAL === 3 && r.counts.HIGH >= 6, JSON.stringify(r.counts));
});

test("vulnerable schema: executed probes prove the leaks", async () => {
  const r = await vulnerable();
  assert.equal(probe(r, "public.notes", "anon reads rows").pass, false);
  assert.match(probe(r, "public.notes", "anon reads rows").observed, /2 of 2/);
  assert.equal(probe(r, "public.notes", "user A reads user B's rows").pass, false);
  assert.equal(probe(r, "public.notes", "user A updates user B's rows").pass, false);
  assert.equal(probe(r, "public.notes", "user A deletes user B's rows").pass, false);
  assert.equal(probe(r, "public.notes", "user A inserts a row owned by B").pass, false);
  assert.equal(probe(r, "public.orders", "anon reads rows").pass, false);
  assert.equal(probe(r, "public.profiles", "user A reads user B's rows").pass, false);
  assert.equal(probe(r, "public.member_directory", "anon reads through the view").pass, false);
  assert.ok(r.proof.failures >= 15, String(r.proof.failures));
});

test("secured twin: no critical/high finding and every executed probe passes", async () => {
  const r = await audit(fx("fixed"));
  assert.equal(r.load.failed.length, 0, JSON.stringify(r.load.failed));
  const bad = r.findings.filter((f) => ["CRITICAL", "HIGH"].includes(f.severity));
  assert.deepEqual(bad.map((f) => `${f.rule} ${f.object}`), []);
  const failing = r.proof.probes.filter((p) => p.pass === false);
  assert.deepEqual(failing.map((p) => `${p.table}: ${p.probe} -> ${p.observed}`), []);
  assert.equal(r.proof.probes.length, 18, `probes ran: ${r.proof.probes.length}`);
  assert.equal(find(r, "AUTH-INITPLAN"), undefined, "wrapped (select auth.uid()) must not be flagged");
  assert.equal(probe(r, "public.notes", "user A reads own rows").pass, true);
});

test("draft fix: applies cleanly, removes criticals and shrinks failing probes; manual items are reported", async () => {
  const v = await auditWithFix(fx("vulnerable"));
  assert.equal(v.after.load.failed.length, 0, JSON.stringify(v.after.load.failed));
  assert.equal(v.after.counts.CRITICAL, 0, JSON.stringify(v.after.findings.filter((f) => f.severity === "CRITICAL")));
  assert.ok(v.after.counts.HIGH < v.before.counts.HIGH);
  assert.ok(v.after.proof.failures < v.before.proof.failures / 2, `${v.before.proof.failures} -> ${v.after.proof.failures}`);
  assert.equal(probe(v.after, "public.notes", "user A reads user B's rows").pass, true);
  assert.equal(probe(v.after, "public.notes", "anon reads rows").pass, true);
  assert.equal(probe(v.after, "public.member_directory", "anon reads through the view")?.pass ?? true, true);
  const manual = v.fix.manual.map((m) => m.object);
  assert.ok(manual.includes("public.workspace_settings"));
  assert.ok(v.fix.sql.includes("security_invoker = on"));
  const md = toMarkdown(v.before, { verification: v });
  assert.match(md, /Before and after the draft fix/);
  assert.match(md, /Proof: executed access tests/);
});

test("pg_dump style input: meta-commands, set_config search_path, unsupported extension and quoted names", async () => {
  const r = await audit(fx("pgdump-style"));
  assert.equal(r.load.failed.length, 0, JSON.stringify(r.load.failed));
  assert.ok(r.load.skippedExtensions.some((e) => e.name === "pg_graphql"));
  assert.equal(find(r, "RLS-DISABLED", "public.invoices").severity, "HIGH");
  assert.equal(find(r, "RLS-DISABLED", "public.profiles"), undefined);
  assert.equal(probe(r, "public.invoices", "anon reads rows").pass, false);
  assert.equal(probe(r, "public.profiles", "anon reads rows")?.pass ?? true, true);
});

test("CLI exit codes: 2 for the vulnerable schema, 0 for the secured twin", () => {
  const bin = join(here, "..", "bin", "cli.mjs");
  const bad = spawnSync(process.execPath, [bin, join(here, "fixtures", "vulnerable")], { encoding: "utf8" });
  const good = spawnSync(process.execPath, [bin, join(here, "fixtures", "fixed")], { encoding: "utf8" });
  assert.equal(bad.status, 2, bad.stdout + bad.stderr);
  assert.equal(good.status, 0, good.stdout + good.stderr);
  assert.match(bad.stdout, /CRITICAL/);
});

test("load failures are reported, and the valid part of the schema is still audited", async () => {
  const r = await audit([{
    name: "x.sql",
    text: `create table public.ok_table (id uuid primary key, user_id uuid references auth.users(id));
create tabel broken (;
create policy p on public.missing for select using (true);`,
  }]);
  assert.equal(r.load.failed.length, 2);
  assert.ok(r.load.failed[0].line >= 2 && /syntax/i.test(r.load.failed[0].message));
  assert.ok(find(r, "RLS-DISABLED", "public.ok_table"));
});

test("table without an owner column: public write policy is still caught and probed", async () => {
  const r = await audit([{
    name: "x.sql",
    text: `create table public.products (id serial primary key, name text);
alter table public.products enable row level security;
create policy everyone on public.products for all to public using (true) with check (true);`,
  }]);
  assert.equal(find(r, "POLICY-ALWAYS-TRUE", "public.products").severity, "HIGH");
  assert.equal(probe(r, "public.products", "anon inserts a row").pass, false);
  assert.equal(probe(r, "public.products", "anon reads rows").pass, null);
});

test("--default-grants off: a table nobody was granted access to is not reported as exposed", async () => {
  const sql = [{ name: "x.sql", text: "create table public.t (id uuid primary key, user_id uuid references auth.users(id));" }];
  assert.ok(find(await audit(sql), "RLS-DISABLED", "public.t"));
  assert.equal(find(await audit(sql, { defaultGrants: false }), "RLS-DISABLED", "public.t"), undefined);
});

test("update policy that tests row data only (no identity) is flagged", async () => {
  const r = await audit([{
    name: "x.sql",
    text: `create table public.docs (id uuid primary key default gen_random_uuid(), status text not null default 'draft');
alter table public.docs enable row level security;
create policy upd on public.docs for update to authenticated using (status = 'draft');`,
  }]);
  assert.equal(find(r, "POLICY-NO-IDENTITY", "public.docs").severity, "MEDIUM");
});


test("independent third-party schema (Supabase's official starter): no false alarms, public profile flagged only as 'confirm'", async () => {
  const r = await audit(fx("official-starter"));
  assert.equal(r.load.failed.length, 0, JSON.stringify(r.load.failed));
  assert.equal(r.counts.CRITICAL, 0);
  assert.equal(find(r, "POLICY-ALWAYS-TRUE", "public.profiles").severity, "MEDIUM");
  assert.equal(probe(r, "public.profiles", "anon reads rows").pass, null);
  assert.equal(r.proof.failures, 0, JSON.stringify(r.proof.probes.filter((p) => p.pass === false)));
  assert.ok(find(r, "STORAGE-BROAD-WRITE", "storage.objects"), "a policy that lets anyone upload must still be flagged");
  assert.ok(find(r, "AUTH-INITPLAN", "public.profiles"));
});
