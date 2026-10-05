-- Only a MEDIUM finding: the update policy never looks at who is asking.
-- Exists to test the --fail-on high / medium thresholds.
create table public.docs (
  id uuid primary key default gen_random_uuid(),
  status text not null default 'draft'
);
alter table public.docs enable row level security;
create policy "docs readable by signed-in users" on public.docs for select to authenticated using ((select auth.uid()) is not null);
create policy "docs updatable while draft" on public.docs for update to authenticated using (status = 'draft');
