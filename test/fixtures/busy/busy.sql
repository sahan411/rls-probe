-- A statement the loader cannot recognise as dangerous but that never finishes in useful time:
-- only the overall --timeout can stop it.
create table public.t (id int primary key, user_id uuid);
select count(*) from generate_series(1, 100000000000);
