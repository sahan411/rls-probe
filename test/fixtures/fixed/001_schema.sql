-- FICTIONAL demo app "HabitHub", hand-secured version of ../vulnerable. Used to prove the auditor stays quiet on correct work.

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text unique,
  full_name text,
  avatar_url text,
  stripe_customer_secret text
);
alter table public.profiles enable row level security;
create policy "profiles_select_own" on public.profiles for select to authenticated using ((select auth.uid()) = id);
create policy "profiles_insert_own" on public.profiles for insert to authenticated with check ((select auth.uid()) = id);
create policy "profiles_update_own" on public.profiles for update to authenticated using ((select auth.uid()) = id) with check ((select auth.uid()) = id);
revoke all on public.profiles from anon;

create table public.notes (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null,
  body text
);
alter table public.notes enable row level security;
create policy "notes_select_own" on public.notes for select to authenticated using ((select auth.uid()) = user_id);
create policy "notes_insert_own" on public.notes for insert to authenticated with check ((select auth.uid()) = user_id);
create policy "notes_update_own" on public.notes for update to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "notes_delete_own" on public.notes for delete to authenticated using ((select auth.uid()) = user_id);
revoke all on public.notes from anon;

create table public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  total_cents integer not null,
  card_token text not null
);
alter table public.orders enable row level security;
create policy "orders_select_own" on public.orders for select to authenticated using ((select auth.uid()) = user_id);
revoke all on public.orders from anon;
revoke insert, update, delete on public.orders from authenticated;

create table public.workspace_settings (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id),
  data jsonb not null default '{}'::jsonb
);
alter table public.workspace_settings enable row level security;
create policy "settings_select_own" on public.workspace_settings for select to authenticated using ((select auth.uid()) = owner_id);
create policy "settings_insert_own" on public.workspace_settings for insert to authenticated with check ((select auth.uid()) = owner_id);
create policy "settings_update_own" on public.workspace_settings for update to authenticated using ((select auth.uid()) = owner_id) with check ((select auth.uid()) = owner_id);
create policy "settings_delete_own" on public.workspace_settings for delete to authenticated using ((select auth.uid()) = owner_id);
revoke all on public.workspace_settings from anon;

create table public.categories (
  id serial primary key,
  name text not null
);
alter table public.categories enable row level security;
create policy "categories readable" on public.categories for select to authenticated using (true);
revoke all on public.categories from anon;
revoke insert, update, delete on public.categories from authenticated;

create table public.audit_log (
  id bigserial primary key,
  action text not null,
  user_id uuid references auth.users(id)
);
alter table public.audit_log enable row level security;
create policy "log insert own" on public.audit_log for insert to authenticated with check ((select auth.uid()) = user_id);
revoke all on public.audit_log from anon;
revoke select, update, delete on public.audit_log from authenticated;

create view public.member_directory with (security_invoker = on) as
  select id, email, raw_user_meta_data from auth.users;

create view public.note_counts with (security_invoker = on) as
  select user_id, count(*) as n from public.notes group by user_id;

create function public.promote_to_admin(target uuid) returns void
language plpgsql security definer set search_path = '' as $$
begin
  update auth.users
     set raw_app_meta_data = jsonb_set(coalesce(raw_app_meta_data, '{}'::jsonb), '{role}', '"admin"'::jsonb)
   where id = target;
end $$;
revoke execute on function public.promote_to_admin(uuid) from public, anon, authenticated;

create function public.slugify(t text) returns text language sql immutable set search_path = '' as $$
  select lower(regexp_replace(t, '[^a-zA-Z0-9]+', '-', 'g'))
$$;

insert into storage.buckets (id, name, public) values ('uploads', 'uploads', true) on conflict do nothing;
create policy "own folder upload" on storage.objects for insert to authenticated
  with check (bucket_id = 'uploads' and (storage.foldername(name))[1] = (select auth.uid())::text);
create policy "own folder read" on storage.objects for select to authenticated
  using (bucket_id = 'uploads' and (storage.foldername(name))[1] = (select auth.uid())::text);
