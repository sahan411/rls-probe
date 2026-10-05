-- Policy names are attacker-controlled when the SQL comes from a pull request.
create table public.notes (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users(id), body text);
alter table public.notes enable row level security;
create policy "evil
::error title=forged::pwned
::add-mask::secret" on public.notes for all using (true) with check (true);
create policy "[click](http://evil.example) <script>alert(1)</script>" on public.notes for select using (true);
-- A table name with a pipe would split a Markdown table cell; a table name that looks like a link must stay text.
create table public."odd | name [x](http://evil.example)" (id uuid primary key default gen_random_uuid(), user_id uuid);
