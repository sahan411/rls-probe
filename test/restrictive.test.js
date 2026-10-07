import { test } from "node:test";
import assert from "node:assert/strict";
import { audit } from "../src/audit.js";

const sql = (text) => [{ name: "001.sql", text }];

test("a RESTRICTIVE policy with a literal true is not reported as always-true", async () => {
  const r = await audit(sql(`
    create table public.members (id uuid primary key default gen_random_uuid(), owner uuid not null, role text not null default 'member');
    alter table public.members enable row level security;
    create policy own_update on public.members for update to authenticated
      using (owner = (select auth.uid())) with check (owner = (select auth.uid()));
    create policy no_self_promotion on public.members as restrictive for update to public
      using (true) with check (role = 'member');
  `));
  assert.equal(r.load.failed.length, 0, JSON.stringify(r.load.failed));
  const hit = r.findings.filter((f) => f.rule === "POLICY-ALWAYS-TRUE" && f.object === "public.members");
  assert.deepEqual(hit, []);
});

test("the same literal true on a PERMISSIVE policy is still reported", async () => {
  const r = await audit(sql(`
    create table public.members (id uuid primary key default gen_random_uuid(), owner uuid not null);
    alter table public.members enable row level security;
    create policy anyone_update on public.members for update to public using (true) with check (true);
  `));
  assert.ok(r.findings.some((f) => f.rule === "POLICY-ALWAYS-TRUE" && f.object === "public.members"));
});
