// Catalog introspection helpers. Everything here reads the REAL Postgres catalog of the loaded schema.

const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;

export function schemaList(schemas) {
  for (const s of schemas) if (!IDENT.test(s)) throw new Error(`Invalid schema name: ${s}`);
  return schemas.map((s) => `'${s}'`).join(",");
}

export function q(db, sql) {
  return db.query(sql).then((r) => r.rows);
}

export function qi(name) {
  return '"' + String(name).replace(/"/g, '""') + '"';
}
export function qname(schema, name) {
  return `${qi(schema)}.${qi(name)}`;
}

function parseArr(v) {
  if (Array.isArray(v)) return v;
  if (typeof v === "string" && v.startsWith("{")) return v.slice(1, -1).split(",").filter(Boolean).map((s) => s.replace(/^"|"$/g, ""));
  return v == null ? [] : [v];
}

export async function listRelations(db, schemas) {
  const rows = await q(db, `
    select n.nspname as schema, c.relname as name, c.relkind as kind, c.relrowsecurity as rls, c.relforcerowsecurity as force_rls,
      coalesce(c.reloptions, '{}'::text[]) as reloptions, c.oid::int as oid, pg_get_userbyid(c.relowner) as owner,
      has_table_privilege('anon', c.oid, 'SELECT') as anon_select, has_table_privilege('anon', c.oid, 'INSERT') as anon_insert,
      has_table_privilege('anon', c.oid, 'UPDATE') as anon_update, has_table_privilege('anon', c.oid, 'DELETE') as anon_delete,
      has_table_privilege('authenticated', c.oid, 'SELECT') as auth_select, has_table_privilege('authenticated', c.oid, 'INSERT') as auth_insert,
      has_table_privilege('authenticated', c.oid, 'UPDATE') as auth_update, has_table_privilege('authenticated', c.oid, 'DELETE') as auth_delete
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where n.nspname in (${schemaList(schemas)}) and c.relkind in ('r','p','v','m','f') and not c.relispartition
    order by n.nspname, c.relname`);
  return rows.map((r) => ({
    ...r,
    reloptions: parseArr(r.reloptions),
    full: `${r.schema}.${r.name}`,
    anyAnon: r.anon_select || r.anon_insert || r.anon_update || r.anon_delete,
    anyAuth: r.auth_select || r.auth_insert || r.auth_update || r.auth_delete,
  }));
}

export async function listPolicies(db, schemas) {
  const rows = await q(db, `
    select schemaname as schema, tablename as table, policyname as name, permissive, roles, cmd, qual, with_check
    from pg_policies where schemaname in (${schemaList(schemas)}) order by schemaname, tablename, policyname`);
  return rows.map((p) => {
    const roles = parseArr(p.roles);
    return {
      ...p,
      roles,
      full: `${p.schema}.${p.table}`,
      appliesAnon: roles.includes("public") || roles.includes("anon"),
      appliesAuth: roles.includes("public") || roles.includes("authenticated"),
      isWrite: ["INSERT", "UPDATE", "DELETE", "ALL"].includes(p.cmd),
      alwaysTrue: (p.qual && p.qual.trim() === "true") || (p.with_check && p.with_check.trim() === "true"),
    };
  });
}

export async function listFunctions(db, schemas) {
  const rows = await q(db, `
    select p.oid::int as oid, n.nspname as schema, p.proname as name, pg_get_function_identity_arguments(p.oid) as args,
      p.prosecdef as definer, p.proconfig as config, p.prorettype::regtype::text as ret, pg_get_userbyid(p.proowner) as owner,
      has_function_privilege('anon', p.oid, 'EXECUTE') as anon_exec, has_function_privilege('authenticated', p.oid, 'EXECUTE') as auth_exec
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname in (${schemaList(schemas)}) and p.prokind in ('f','p')
      and not exists (select 1 from pg_depend d where d.objid = p.oid and d.deptype = 'e')
    order by n.nspname, p.proname`);
  return rows
    .filter((f) => f.ret !== "trigger" && f.ret !== "event_trigger")
    .map((f) => {
      const config = parseArr(f.config);
      return { ...f, config, full: `${f.schema}.${f.name}(${f.args})`, hasSearchPath: config.some((c) => /^search_path=/i.test(c)) };
    });
}

// How many functions of each schema.name exist in the loaded catalog (overloads count separately). Map "schema.name" -> count.
export async function functionCounts(db) {
  const rows = await q(db, `
    select n.nspname as schema, p.proname as name, count(*)::int as c
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname not in ('pg_catalog', 'information_schema') group by 1, 2`);
  return new Map(rows.map((r) => [`${r.schema}.${r.name}`, r.c]));
}

export async function viewDependencies(db, viewOid) {
  return q(db, `
    select distinct n.nspname as schema, c.relname as name, c.relkind as kind, c.relrowsecurity as rls
    from pg_depend d join pg_rewrite r on r.oid = d.objid
      join pg_class c on c.oid = d.refobjid join pg_namespace n on n.oid = c.relnamespace
    where r.ev_class = ${Number(viewOid)} and d.classid = 'pg_rewrite'::regclass and d.refobjid <> ${Number(viewOid)}
      and c.relkind in ('r','p','v','m','f')`);
}

export async function columnsOf(db, oid) {
  return q(db, `
    select a.attname as name, format_type(a.atttypid, a.atttypmod) as type, t.typname as typname, t.typtype as typtype, t.typcategory as category,
      a.attnotnull as notnull, a.atthasdef as hasdef, a.attgenerated as generated, a.attidentity as identity, a.atttypid::int as typid, a.attnum as num
    from pg_attribute a join pg_type t on t.oid = a.atttypid
    where a.attrelid = ${Number(oid)} and a.attnum > 0 and not a.attisdropped order by a.attnum`);
}

const SENSITIVE = /(^|_)(password|passwd|pwd|secret|token|apikey|api_key|access_key|private_key|ssn|social_security|card_number|cvv|iban|otp|refresh_token)(_|$)|(api|secret|private|service)_?key/i;
export function sensitiveColumns(cols) {
  return cols.filter((c) => SENSITIVE.test(c.name)).map((c) => c.name);
}

const OWNER_NAMES = ["user_id", "owner_id", "author_id", "created_by", "profile_id", "uid", "owner", "userid", "creator_id"];

// The column that ties a row to a signed-in user: a FK to auth.users, else a conventional name.
export async function ownerColumn(db, rel, cols) {
  const fk = await q(db, `
    select a.attname as name from pg_constraint c join pg_attribute a on a.attrelid = c.conrelid and a.attnum = any(c.conkey)
    where c.contype = 'f' and c.conrelid = ${Number(rel.oid)} and c.confrelid = 'auth.users'::regclass and array_length(c.conkey, 1) = 1
    order by (a.attname = 'user_id') desc, a.attnum limit 1`);
  if (fk.length) return fk[0].name;
  const byName = cols.find((c) => OWNER_NAMES.includes(c.name.toLowerCase()) && c.typname === "uuid");
  if (byName) return byName.name;
  if (/^(profiles?|users?|accounts?)$/i.test(rel.name) && cols.some((c) => c.name === "id" && c.typname === "uuid")) return "id";
  return null;
}
