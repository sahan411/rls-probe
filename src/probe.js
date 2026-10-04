import { qi, qname, q } from "./introspect.js";

export const USER_A = "00000000-0000-4000-8000-00000000000a";
export const USER_B = "00000000-0000-4000-8000-00000000000b";

// Runs one statement as an API role inside a transaction that is always rolled back (probes never change the seeded data).
async function asRole(db, role, sub, sql) {
  const claims = role === "anon" ? { role: "anon" } : { sub, role: "authenticated", aud: "authenticated", email: sub === USER_A ? "a@probe.test" : "b@probe.test" };
  await db.exec("begin");
  try {
    await db.exec(`set local role ${role}`);
    await db.query("select set_config('request.jwt.claims', $1, true), set_config('request.jwt.claim.sub', $2, true)", [JSON.stringify(claims), sub || ""]);
    const r = await db.query(sql);
    return { ok: true, rows: r.rows };
  } catch (e) {
    return { ok: false, error: String(e.message).split("\n")[0] };
  } finally {
    await db.exec("rollback");
  }
}

async function valueExpr(db, col, idx) {
  const n = col.name.toLowerCase();
  if (col.typtype === "e" || col.category === "E") {
    const r = await q(db, `select enumlabel from pg_enum where enumtypid = ${col.typid} order by enumsortorder limit 1`);
    return r.length ? `'${r[0].enumlabel.replace(/'/g, "''")}'::${col.type}` : null;
  }
  if (col.typname === "uuid") return "gen_random_uuid()";
  if (col.typname === "json" || col.typname === "jsonb") return `'{}'::${col.type}`;
  if (col.typname === "bytea") return "'\\x00'::bytea";
  switch (col.category) {
    case "S": return n.includes("email") ? `('probe${idx}@probe.test')::${col.type}` : `('p${idx}')::${col.type}`;
    case "N": return `${idx}::${col.type}`;
    case "B": return "false";
    case "D": return `now()::${col.type}`;
    case "T": return "'1 hour'::interval";
    case "A": return `'{}'::${col.type}`;
    case "R": return `'empty'::${col.type}`;
    case "I": return col.typname === "cidr" ? `'10.0.0.0/24'::cidr` : col.typname === "inet" ? `'10.0.0.${idx}'::inet` : null;
    default: return null;
  }
}

async function rowValues(db, cols, owner, ownerValue, idx, mode) {
  const names = [];
  const vals = [];
  for (const c of cols) {
    if (c.generated) continue;
    if (c.identity === "a") continue;
    const isOwner = owner && c.name === owner;
    const required = c.notnull && !c.hasdef;
    if (!isOwner && !(mode === "all" ? c.identity !== "d" : required)) continue;
    const v = isOwner ? `'${ownerValue}'::uuid` : await valueExpr(db, c, idx);
    if (v === null) {
      if (required || isOwner) return null;
      continue;
    }
    names.push(qi(c.name));
    vals.push(v);
  }
  return { names, vals };
}

function insertSql(rel, rv, returning) {
  if (rv.names.length === 0) return `insert into ${qname(rel.schema, rel.name)} default values returning ${returning}`;
  return `insert into ${qname(rel.schema, rel.name)} (${rv.names.join(", ")}) values (${rv.vals.join(", ")}) returning ${returning}`;
}

async function seedTable(db, rel, cols, owner) {
  let lastErr = "";
  for (const mode of ["min", "all"]) {
    try {
      const a = await rowValues(db, cols, owner, USER_A, 1, mode);
      const b = await rowValues(db, cols, owner, USER_B, 2, mode);
      if (!a || !b) { lastErr = "column type not supported by the probe seeder"; continue; }
      await db.exec(insertSql(rel, a, "1"));
      await db.exec(insertSql(rel, b, "1"));
      return { ok: true };
    } catch (e) {
      lastErr = String(e.message).split("\n")[0];
      await db.exec(`delete from ${qname(rel.schema, rel.name)}`).catch(() => {});
    }
  }
  return { ok: false, reason: lastErr };
}

export async function runProbes(db, model, findings) {
  const probes = [];
  const skipped = [];
  const push = (table, probe, role, expectation, pass, observed, severity, note = "") => probes.push({ table, probe, role, expectation, pass, observed, severity, note });

  await db.exec("set session_replication_role = replica");
  await db.exec(`insert into auth.users (id, email, aud, role) values ('${USER_A}', 'a@probe.test', 'authenticated', 'authenticated'), ('${USER_B}', 'b@probe.test', 'authenticated', 'authenticated') on conflict do nothing`);

  for (const [full, t] of Object.entries(model.tables)) {
    if (!(t.anyAnon || t.anyAuth)) continue;
    const owner = t.owner;
    const sev = t.sensitive.length ? "CRITICAL" : "HIGH";
    const seeded = await seedTable(db, t, t.cols, owner);
    if (!seeded.ok) { skipped.push({ table: full, reason: seeded.reason }); continue; }
    const T = qname(t.schema, t.name);
    const oc = owner ? qi(owner) : null;
    const anyCol = qi(t.cols.find((c) => !c.generated && c.identity !== "a")?.name ?? t.cols[0].name);

    // --- anonymous access
    if (t.anon_select) {
      const r = await asRole(db, "anon", null, `select count(*)::int as c from ${T}`);
      const n = r.ok ? r.rows[0].c : 0;
      if (owner && t.publicRead?.anon) push(full, "anon reads rows", "anon", "info", null, `${n} of 2 seeded rows visible: public read by design? policy "${t.publicRead.anon}" is always true (confirm)`, "INFO");
      else if (owner) push(full, "anon reads rows", "anon", "no rows", n === 0, r.ok ? `${n} of 2 seeded rows visible` : `blocked (${r.error})`, sev);
      else push(full, "anon reads rows", "anon", "info", null, r.ok ? `${n} of 2 seeded rows visible (no owner column, so intent unknown)` : `blocked (${r.error})`, "INFO");
    }
    const anonIns = await asRole(db, "anon", null, insertSql(t, await rowValues(db, t.cols, owner, USER_A, 3, "min") ?? { names: [], vals: [] }, "1 as x"));
    if (t.anon_insert) push(full, "anon inserts a row", "anon", "blocked", !anonIns.ok, anonIns.ok ? "insert succeeded" : `blocked (${anonIns.error})`, sev);
    if (t.anon_update) {
      const r = await asRole(db, "anon", null, `with u as (update ${T} set ${owner ? oc : anyCol} = ${owner ? oc : anyCol} returning 1) select count(*)::int as c from u`);
      push(full, "anon updates rows", "anon", "blocked", !r.ok || r.rows[0].c === 0, r.ok ? `${r.rows[0].c} row(s) changed` : `blocked (${r.error})`, sev);
    }
    if (t.anon_delete) {
      const r = await asRole(db, "anon", null, `with d as (delete from ${T} returning 1) select count(*)::int as c from d`);
      push(full, "anon deletes rows", "anon", "blocked", !r.ok || r.rows[0].c === 0, r.ok ? `${r.rows[0].c} row(s) deleted` : `blocked (${r.error})`, sev);
    }

    // --- user A against user B's data (needs an owner column)
    if (owner && t.anyAuth) {
      if (t.auth_select) {
        const rb = await asRole(db, "authenticated", USER_A, `select count(*)::int as c from ${T} where ${oc} = '${USER_B}'`);
        const pubName = t.publicRead?.anon || t.publicRead?.auth;
        if (pubName) push(full, "user A reads user B's rows", "authenticated", "info", null, `${rb.ok ? rb.rows[0].c : 0} of B's rows visible: public read by design? policy "${pubName}" is always true (confirm)`, "INFO");
        else push(full, "user A reads user B's rows", "authenticated", "no rows", !rb.ok || rb.rows[0].c === 0, rb.ok ? `${rb.rows[0].c} of B's rows visible` : `blocked (${rb.error})`, sev);
        const ra = await asRole(db, "authenticated", USER_A, `select count(*)::int as c from ${T} where ${oc} = '${USER_A}'`);
        push(full, "user A reads own rows", "authenticated", "own rows visible", ra.ok && ra.rows[0].c >= 1, ra.ok ? `${ra.rows[0].c} of A's rows visible` : `blocked (${ra.error})`, "MEDIUM", "Over-restrictive policies break the app for legitimate users.");
      }
      if (t.auth_update) {
        const r = await asRole(db, "authenticated", USER_A, `with u as (update ${T} set ${oc} = ${oc} where ${oc} = '${USER_B}' returning 1) select count(*)::int as c from u`);
        push(full, "user A updates user B's rows", "authenticated", "blocked", !r.ok || r.rows[0].c === 0, r.ok ? `${r.rows[0].c} row(s) changed` : `blocked (${r.error})`, sev);
      }
      if (t.auth_delete) {
        const r = await asRole(db, "authenticated", USER_A, `with d as (delete from ${T} where ${oc} = '${USER_B}' returning 1) select count(*)::int as c from d`);
        push(full, "user A deletes user B's rows", "authenticated", "blocked", !r.ok || r.rows[0].c === 0, r.ok ? `${r.rows[0].c} row(s) deleted` : `blocked (${r.error})`, sev);
      }
      if (t.auth_insert) {
        const rv = await rowValues(db, t.cols, owner, USER_B, 4, "min");
        if (rv) {
          const r = await asRole(db, "authenticated", USER_A, insertSql(t, rv, `${oc}::text as o`));
          const forged = r.ok && r.rows[0]?.o === USER_B;
          push(full, "user A inserts a row owned by B", "authenticated", "blocked", !forged, r.ok ? (forged ? "forged row accepted" : "owner was rewritten by a trigger (not forged)") : `blocked (${r.error})`, sev);
        }
      }
    }
  }

  // --- views flagged as bypassing RLS: prove what anon actually gets
  for (const f of findings.filter((x) => x.rule === "VIEW-DEFINER" || x.rule === "AUTH-USERS-EXPOSED")) {
    const [schema, name] = f.object.split(".");
    const r = await asRole(db, "anon", null, `select count(*)::int as c from ${qname(schema, name)}`);
    const n = r.ok ? r.rows[0].c : 0;
    push(f.object, "anon reads through the view", "anon", "no rows", !r.ok || n === 0, r.ok ? `${n} row(s) returned` : `blocked (${r.error})`, f.severity);
  }

  await db.exec("set session_replication_role = origin");
  return { probes, skipped, failures: probes.filter((p) => p.pass === false).length };
}
