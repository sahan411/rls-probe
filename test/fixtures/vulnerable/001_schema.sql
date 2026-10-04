-- FICTIONAL demo app "HabitHub". Every name is invented. This schema contains the mistakes AI app builders
-- most often generate; it exists to test the auditor and to illustrate a sample report.

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text unique,
  full_name text,
  avatar_url text,
  stripe_customer_secret text
);
-- (RLS never enabled)

create table public.notes (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null,
  body text
);
alter table public.notes enable row level security;
create policy "Anyone can do anything" on public.notes for all using (true) with check (true);

create table public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  total_cents integer not null,
  card_token text not null
);
-- (RLS never enabled)

create table public.workspace_settings (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id),
  data jsonb not null default '{}'::jsonb
);
alter table public.workspace_settings enable row level security;
create policy "admins manage settings" on public.workspace_settings for all to authenticated
  using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin')
  with check ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');

create table public.categories (
  id serial primary key,
  name text not null
);
alter table public.categories enable row level security;
create policy "categories readable" on public.categories for select using (true);

create table public.audit_log (
  id bigserial primary key,
  action text not null,
  user_id uuid references auth.users(id)
);
-- a policy was written, but RLS was never switched on, so it is ignored
create policy "log insert" on public.audit_log for insert to anon with check (true);

create view public.member_directory as
  select id, email, raw_user_meta_data from auth.users;

create view public.note_counts as
  select user_id, count(*) as n from public.notes group by user_id;

create function public.promote_to_admin(target uuid) returns void
language plpgsql security definer as $$
begin
  update auth.users
     set raw_app_meta_data = jsonb_set(coalesce(raw_app_meta_data, '{}'::jsonb), '{role}', '"admin"'::jsonb)
   where id = target;
end $$;

create function public.slugify(t text) returns text language sql immutable as $$
  select lower(regexp_replace(t, '[^a-zA-Z0-9]+', '-', 'g'))
$$;

insert into storage.buckets (id, name, public) values ('uploads', 'uploads', true) on conflict do nothing;
create policy "anyone can upload" on storage.objects for insert to public with check (bucket_id = 'uploads');
create policy "anyone can read uploads" on storage.objects for select to public using (bucket_id = 'uploads');
