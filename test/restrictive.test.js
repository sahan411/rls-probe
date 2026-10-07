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

test("a RESTRICTIVE storage policy that blocks a private bucket is not reported as broad write", async () => {
  const r = await audit(sql(`
    insert into storage.buckets(id, name, public) values ('ticket-fonts', 'ticket-fonts', false);
    create policy ticket_fonts_private on storage.objects as restrictive for all to anon, authenticated
      using (bucket_id <> 'ticket-fonts') with check (bucket_id <> 'ticket-fonts');
    create table public.t (id int primary key, owner uuid);
    alter table public.t enable row level security;
    create policy only_owner_rows on public.t as restrictive for select to authenticated using (owner is not null);
  `));
  const bad = r.findings.filter((f) => ["STORAGE-BROAD-WRITE", "STORAGE-BROAD-READ", "POLICY-NO-IDENTITY", "POLICY-ALWAYS-TRUE"].includes(f.rule));
  assert.deepEqual(bad.map((f) => f.rule + " " + f.object), []);
});

test("the same storage policy written as PERMISSIVE is still reported", async () => {
  const r = await audit(sql(`
    create policy open_writes on storage.objects for all to anon, authenticated
      using (bucket_id <> 'ticket-fonts') with check (bucket_id <> 'ticket-fonts');
  `));
  assert.ok(r.findings.some((f) => f.rule === "STORAGE-BROAD-WRITE"));
});
