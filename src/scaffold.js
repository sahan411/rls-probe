// Minimal emulation of what a Supabase project provides around the user's own schema:
// API roles, auth.users + auth.uid()/jwt()/role()/email(), a storage schema with RLS-protected objects,
// extension schema, realtime publication and (optionally) the default privileges Supabase applies to the public schema.
// It is an emulation for AUDITING policies, not a copy of Supabase internals.

export function scaffoldSql({ defaultGrants = true } = {}) {
  return `
do $$ begin
  create role anon nologin noinherit;
exception when duplicate_object then null; end $$;
do $$ begin create role authenticated nologin noinherit; exception when duplicate_object then null; end $$;
do $$ begin create role service_role nologin noinherit bypassrls; exception when duplicate_object then null; end $$;
do $$ begin create role authenticator noinherit login; exception when duplicate_object then null; end $$;
do $$ begin create role supabase_admin; exception when duplicate_object then null; end $$;
do $$ begin create role supabase_auth_admin; exception when duplicate_object then null; end $$;
do $$ begin create role supabase_storage_admin; exception when duplicate_object then null; end $$;
do $$ begin create role supabase_realtime_admin; exception when duplicate_object then null; end $$;
do $$ begin create role dashboard_user; exception when duplicate_object then null; end $$;
do $$ begin create role pgbouncer; exception when duplicate_object then null; end $$;

create schema if not exists extensions;
create schema if not exists auth;
create schema if not exists storage;
create schema if not exists graphql_public;

create table auth.users (
  instance_id uuid,
  id uuid primary key default gen_random_uuid(),
  aud varchar(255),
  role varchar(255),
  email text,
  encrypted_password text,
  email_confirmed_at timestamptz,
  phone text,
  last_sign_in_at timestamptz,
  raw_app_meta_data jsonb default '{}'::jsonb,
  raw_user_meta_data jsonb default '{}'::jsonb,
  is_super_admin boolean,
  is_anonymous boolean not null default false,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);
create table auth.identities (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users(id) on delete cascade, provider text, identity_data jsonb);
create table auth.sessions (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users(id) on delete cascade);

create function auth.uid() returns uuid language sql stable as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim.sub', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')
  )::uuid
$$;
create function auth.role() returns text language sql stable as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim.role', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role')
  )::text
$$;
create function auth.email() returns text language sql stable as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim.email', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'email')
  )::text
$$;
create function auth.jwt() returns jsonb language sql stable as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim', true), ''),
    nullif(current_setting('request.jwt.claims', true), '')
  )::jsonb
$$;

create table storage.buckets (
  id text primary key, name text not null, owner uuid, public boolean default false,
  file_size_limit bigint, allowed_mime_types text[], created_at timestamptz default now(), updated_at timestamptz default now()
);
create table storage.objects (
  id uuid primary key default gen_random_uuid(), bucket_id text references storage.buckets(id), name text,
  owner uuid, owner_id text, metadata jsonb, version text,
  path_tokens text[] generated always as (string_to_array(name, '/')) stored,
  created_at timestamptz default now(), updated_at timestamptz default now(), last_accessed_at timestamptz default now()
);
alter table storage.buckets enable row level security;
alter table storage.objects enable row level security;
create function storage.foldername(name text) returns text[] language plpgsql immutable as $$
declare _parts text[]; begin
  select string_to_array(name, '/') into _parts;
  return _parts[1:array_length(_parts, 1) - 1];
end $$;
create function storage.filename(name text) returns text language plpgsql immutable as $$
declare _parts text[]; begin
  select string_to_array(name, '/') into _parts;
  return _parts[array_length(_parts, 1)];
end $$;
create function storage.extension(name text) returns text language plpgsql immutable as $$
declare _parts text[]; _filename text; begin
  select string_to_array(name, '/') into _parts;
  select _parts[array_length(_parts, 1)] into _filename;
  return reverse(split_part(reverse(_filename), '.', 1));
end $$;

-- Helpers the storage API provides. Emulated as permissive: a policy that relies on them is treated as unrestricted by operation.
create function storage.operation() returns text language sql stable as $$ select current_setting('storage.operation', true) $$;
create function storage.allow_any_operation(expected_operations text[]) returns boolean language sql stable as $$ select true $$;
create function storage.allow_only_operation(expected_operation text) returns boolean language sql stable as $$ select true $$;
create function storage.search(prefix text, bucketname text, limits int default 100, levels int default 1, offsets int default 0) returns setof storage.objects language sql stable as $$ select * from storage.objects where bucket_id = bucketname and name like prefix || '%' limit limits offset offsets $$;

grant usage on schema public, auth, storage, extensions to anon, authenticated, service_role;
grant execute on function auth.uid(), auth.role(), auth.email(), auth.jwt() to anon, authenticated, service_role;
grant all on all tables in schema storage to anon, authenticated, service_role;
grant execute on all functions in schema storage to anon, authenticated, service_role;

create publication supabase_realtime;
${defaultGrants ? `
alter default privileges in schema public grant all on tables to anon, authenticated, service_role;
alter default privileges in schema public grant all on sequences to anon, authenticated, service_role;
alter default privileges in schema public grant all on functions to anon, authenticated, service_role;
` : ""}
`;
}
