--
-- PostgreSQL database dump (shape of a full pg_dump WITH data; fictional app, fake people)
--

SET statement_timeout = 0;
SET client_encoding = 'UTF8';
SELECT pg_catalog.set_config('search_path', '', false);

CREATE TABLE public.customers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    email text,
    note text
);

ALTER TABLE ONLY public.customers
    ADD CONSTRAINT customers_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.customers
    ADD CONSTRAINT customers_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id);

ALTER TABLE public.customers ENABLE ROW LEVEL SECURITY;

CREATE POLICY "own rows" ON public.customers TO authenticated
    USING (((SELECT auth.uid() AS uid) = user_id))
    WITH CHECK (((SELECT auth.uid() AS uid) = user_id));

CREATE TABLE public.audit_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    action text
);

--
-- Data for Name: customers; Type: TABLE DATA; Schema: public
--

COPY public.customers (id, user_id, email, note) FROM stdin;
11111111-1111-4111-8111-111111111111	22222222-2222-4222-8222-222222222222	jane.doe@example.com	it's "quoted"; DROP TABLE public.customers; --
33333333-3333-4333-8333-333333333333	44444444-4444-4444-8444-444444444444	bob.fake@example.com	two\ttabs\\and a \\. inside; select 1;
\.

INSERT INTO public.audit_events (action) VALUES ('login by jane.doe@example.com');
INSERT INTO public.audit_events (action) VALUES ('it''s; a semicolon');
INSERT INTO "auth"."users" (id, email) VALUES ('55555555-5555-4555-8555-555555555555', 'carol.fake@example.com');
INSERT INTO storage.buckets (id, name, public) VALUES ('avatars', 'avatars', true);

CREATE TABLE public.after_data (
    id integer NOT NULL
);
