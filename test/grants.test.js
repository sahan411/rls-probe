import { test } from "node:test";
import assert from "node:assert/strict";
import { audit, auditWithFix } from "../src/audit.js";
import { toMarkdown, toHtml, toSummary } from "../src/report.js";
import { toSarif } from "../src/sarif.js";

// Supabase stopped granting new public tables to anon / authenticated automatically (new projects since 2026-05-30, new tables
// in older projects from 2026-10-30). These tests cover the grants setting, the POLICY-NO-GRANT finding and the report wording.

const sql = (text) => [{ name: "001.sql", text, path: "supabase/migrations/001.sql" }];
const lines = (...l) => l.join("\n");

const TABLE = (name) => `create table public.${name} (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users(id), body text);`;
const OWN = "((select auth.uid()) = user_id)";

// line 1 table, line 2 RLS, line 3 policy; no grant anywhere
const NOTES_NO_GRANT = lines(TABLE("notes"), "alter table public.notes enable row level security;", `create policy "own rows" on public.notes for all to authenticated using ${OWN} with check ${OWN};`);
const NOTES_GRANTED = lines(TABLE("notes"), "alter table public.notes enable row level security;", "grant select, insert, update, delete on public.notes to authenticated;", `create policy "own rows" on public.notes for all to authenticated using ${OWN} with check ${OWN};`);

const runs = new Map();
const run = (key, text, opts) => {
  if (!runs.has(key)) runs.set(key, audit(sql(text), opts));
  return runs.get(key);
};
const gap = (res, table) => res.findings.find((f) => f.rule === "POLICY-NO-GRANT" && f.object === table);

test("defaults off, policies but no grant: reported as LOW, with the privileges, a location and a fix", async () => {
  const r = await run("noGrantOff", NOTES_NO_GRANT, { defaultGrants: false });
  assert.equal(r.load.failed.length, 0, JSON.stringify(r.load.failed));
  assert.equal(r.meta.defaultGrants, false);
  const f = gap(r, "public.notes");
  assert.ok(f, "POLICY-NO-GRANT expected");
  assert.equal(f.severity, "LOW");
  assert.deepEqual(f.evidence.gaps, [{ role: "authenticated", privileges: ["select", "insert", "update", "delete"], policies: ["own rows"] }]);
  assert.match(f.why, /permission denied for table notes/);
  assert.match(f.why, /42501/);
  assert.match(f.fix, /grant select, insert, update, delete on public\.notes to authenticated;/);
  assert.deepEqual(f.locations?.map((l) => `${l.file}:${l.line}`), ["supabase/migrations/001.sql:3"], "points at the policy that cannot take effect");
  assert.deepEqual(r.counts, { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 1, INFO: 0 });
  assert.equal(r.proof.probes.length, 0, "an unreachable table is not exposed, so no access test runs");
});

test("defaults off, explicit grant in the SQL: no finding, and the executed access tests run and pass", async () => {
  const r = await run("grantedOff", NOTES_GRANTED, { defaultGrants: false });
  assert.equal(gap(r, "public.notes"), undefined);
  assert.ok(r.proof.probes.length >= 5, String(r.proof.probes.length));
  assert.equal(r.proof.failures, 0);
  assert.deepEqual(r.counts, { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 });
});

test("defaults on: the same SQL without a grant is reachable by default, so there is no finding", async () => {
  const r = await run("noGrantOn", NOTES_NO_GRANT, { defaultGrants: true });
  assert.equal(gap(r, "public.notes"), undefined);
  assert.ok(r.proof.probes.length >= 5);
  assert.equal(r.proof.failures, 0);
});

test("a gap is a missing privilege for a single-command policy, a role with no privilege at all for FOR ALL, never a restrictive policy", async () => {
  const r = await run("partial", lines(
    TABLE("a"), "alter table public.a enable row level security;", "grant select on public.a to authenticated;",
    `create policy a_ins on public.a for insert to authenticated with check ${OWN};`,
    // read-only grant plus a FOR ALL policy: a deliberate least-privilege choice, not reported
    TABLE("b"), "alter table public.b enable row level security;", "grant select on public.b to authenticated;",
    `create policy b_all on public.b for all to authenticated using ${OWN} with check ${OWN};`,
    // a restrictive policy only narrows access and needs nothing
    TABLE("c"), "alter table public.c enable row level security;",
    `create policy c_restr on public.c as restrictive for select to authenticated using ${OWN};`,
    // no TO clause means public: both API roles are named
    TABLE("d"), "alter table public.d enable row level security;",
    "create policy d_read on public.d for select using (true);",
  ), { defaultGrants: false });
  assert.equal(r.load.failed.length, 0, JSON.stringify(r.load.failed));
  assert.deepEqual(gap(r, "public.a")?.evidence.gaps, [{ role: "authenticated", privileges: ["insert"], policies: ["a_ins"] }]);
  assert.equal(gap(r, "public.b"), undefined);
  assert.equal(gap(r, "public.c"), undefined);
  assert.deepEqual(gap(r, "public.d")?.evidence.gaps.map((g) => `${g.role}:${g.privileges}`), ["anon:select", "authenticated:select"]);
  assert.match(gap(r, "public.d").title, /anon and authenticated/);
});

test("an explicit revoke is a gap even with defaults on", async () => {
  const r = await run("revokeOn", lines(
    TABLE("e"), "alter table public.e enable row level security;", "revoke all on public.e from anon;",
    "create policy e_anon on public.e for select to anon using (true);",
  ), { defaultGrants: true });
  assert.deepEqual(gap(r, "public.e")?.evidence.gaps, [{ role: "anon", privileges: ["select"], policies: ["e_anon"] }]);
});

test("the draft fix grants what the policies address, and the re-audit then runs the access tests", async () => {
  const { before, after, fix } = await auditWithFix(sql(NOTES_NO_GRANT), { defaultGrants: false });
  assert.ok(gap(before, "public.notes"));
  assert.match(fix.sql, /grant select, insert, update, delete on "public"\."notes" to authenticated;/);
  assert.equal(gap(after, "public.notes"), undefined);
  assert.ok(after.proof.probes.length >= 5, String(after.proof.probes.length));
  assert.equal(after.proof.failures, 0);
});

test("every report format states the default-privileges setting the run used", async () => {
  const on = await run("noGrantOn", NOTES_NO_GRANT, { defaultGrants: true });
  const off = await run("noGrantOff", NOTES_NO_GRANT, { defaultGrants: false });
  const fmt = (res) => ({ md: toMarkdown(res), html: toHtml(res), summary: toSummary(res) });
  const a = fmt(on);
  const b = fmt(off);

  assert.match(a.md, /Default privileges: on \(/);
  assert.match(a.md, /Default privileges: ON\. This run assumes Supabase's previous behaviour/);
  assert.match(a.md, /--default-grants off/);
  assert.match(a.html, /Default privileges: on \(/);
  assert.match(a.html, /Default privileges: ON\./);
  assert.match(a.summary, /Default privileges: on\./);

  assert.match(b.md, /Default privileges: off \(/);
  assert.match(b.md, /Default privileges: OFF\. This run assumes Supabase's newer behaviour/);
  assert.match(b.md, /--default-grants on/);
  assert.doesNotMatch(b.md, /Default privileges: ON/, "a run with the setting off must not claim the legacy assumption");
  assert.doesNotMatch(b.md, /granted to anon and authenticated automatically/);
  assert.match(b.html, /Default privileges: off \(/);
  assert.match(b.html, /Default privileges: OFF\./);
  assert.match(b.summary, /Default privileges: off\./);
  assert.match(b.md, /Policies exist but no grant lets authenticated reach the table/);

  for (const [name, text] of [...Object.entries(a), ...Object.entries(b)]) {
    assert.ok(!/guarantee|sign-?off|assurance/i.test(text), `${name} output uses a banned word`);
    assert.match(text, /not a penetration test/i, `${name} keeps the penetration-test disclaimer`);
  }
});

test("SARIF carries the rule as a note with the policy location", async () => {
  const off = await run("noGrantOff", NOTES_NO_GRANT, { defaultGrants: false });
  const log = toSarif(off);
  const rule = log.runs[0].tool.driver.rules.find((x) => x.id === "POLICY-NO-GRANT");
  assert.ok(rule, "rule metadata present");
  assert.equal(rule.name, "PolicyWithoutGrant");
  const result = log.runs[0].results.find((x) => x.ruleId === "POLICY-NO-GRANT");
  assert.equal(result.level, "note");
  assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, "supabase/migrations/001.sql");
  assert.equal(result.locations[0].physicalLocation.region.startLine, 3);
});
