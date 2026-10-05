import { listRelations, listPolicies, listFunctions, viewDependencies, columnsOf, sensitiveColumns, ownerColumn, q } from "./introspect.js";

export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));

const IDENTITY = /auth\.(uid|jwt|role|email)\(\)/i;
const STORAGE_IDENTITY = /auth\.(uid|jwt|email|role)\(\)|\bowner\b|\bowner_id\b|foldername/i;

let seq = 0;
function F(rule, lint, severity, object, title, why, fix, evidence = {}) {
  return { id: `${rule}#${++seq}`, rule, lint, severity, object, title, why, fix, evidence };
}

function who(r) {
  const out = [];
  if (r.anyAnon) out.push("anon (anyone with the public key)");
  if (r.anyAuth) out.push("authenticated (any signed-in user)");
  return out.join(" and ");
}
function privs(r, role) {
  const p = role === "anon" ? [["select", r.anon_select], ["insert", r.anon_insert], ["update", r.anon_update], ["delete", r.anon_delete]] : [["select", r.auth_select], ["insert", r.auth_insert], ["update", r.auth_update], ["delete", r.auth_delete]];
  return p.filter(([, v]) => v).map(([k]) => k);
}

// Runs every static check against the loaded catalog. Returns { findings, model } where model carries per-table facts reused by probes and fixes.
export async function runChecks(db, { schemas = ["public"] } = {}) {
  seq = 0;
  const findings = [];
  const rels = await listRelations(db, schemas);
  const pols = await listPolicies(db, [...new Set([...schemas, "storage"])]);
  const funcs = await listFunctions(db, schemas);
  const usersDeps = new Set((await q(db, `
    select distinct v.oid::int as oid from pg_depend d join pg_rewrite r on r.oid = d.objid join pg_class v on v.oid = r.ev_class
    where d.refobjid = 'auth.users'::regclass and d.classid = 'pg_rewrite'::regclass and v.relkind in ('v','m')`)).map((r) => r.oid));

  const model = { tables: {}, schemas, policies: pols };
  const polsByTable = {};
  for (const p of pols) (polsByTable[p.full] ||= []).push(p);

  for (const r of rels) {
    const exposed = r.anyAnon || r.anyAuth;
    if (r.kind === "r" || r.kind === "p") {
      const cols = await columnsOf(db, r.oid);
      const owner = await ownerColumn(db, r, cols);
      const sens = sensitiveColumns(cols);
      const tp = polsByTable[r.full] || [];
      model.tables[r.full] = { ...r, owner, sensitive: sens, policies: tp.map((p) => p.name), cols };

      if (!r.rls && exposed) {
        const open = [];
        if (r.anyAnon) open.push(`anon can ${privs(r, "anon").join("/")}`);
        if (r.anyAuth) open.push(`authenticated can ${privs(r, "authenticated").join("/")}`);
        findings.push(F("RLS-DISABLED", "0013_rls_disabled_in_public", sens.length ? "CRITICAL" : "HIGH", r.full,
          "Table is open to the API with Row Level Security turned off",
          `Anyone holding the public (anon) key can use the auto-generated API to ${r.anyAnon ? "read and change" : "reach"} every row. Privileges seen: ${open.join("; ")}.${sens.length ? ` It also holds sensitive-looking columns: ${sens.join(", ")}.` : ""}${tp.length ? " Policies exist but are NOT enforced because RLS is off." : ""}`,
          owner ? "Enable RLS and add owner-scoped policies (draft SQL in the fix file)." : "Enable RLS, then add the policies that match who should see this table (a reviewer must decide; drafts in the fix file).",
          { owner_column: owner, sensitive_columns: sens, privileges: open, policies_ignored: tp.map((p) => p.name) }));
        if (tp.length) findings.push(F("POLICY-NO-RLS", "0007_policy_exists_rls_disabled", "HIGH", r.full,
          "Policies are defined but Row Level Security is disabled, so they do nothing",
          "This usually means a migration created policies and forgot `alter table ... enable row level security`.",
          `alter table ${r.full} enable row level security;`, { policies: tp.map((p) => p.name) }));
      }
      if (r.rls && tp.length === 0 && exposed) {
        findings.push(F("RLS-NO-POLICY", "0008_rls_enabled_no_policy", "INFO", r.full,
          "RLS is on but no policy exists: the API returns no rows (safe, but check the app expects this)",
          "With RLS enabled and no policies, anon and signed-in users see nothing. Safe by default; confirm it is intended.",
          "Add the policies the app needs, if any.", {}));
      }
    } else if (r.kind === "v") {
      if (!exposed) continue;
      const invoker = r.reloptions.some((o) => /^security_invoker=(true|on)$/i.test(o));
      if (invoker) continue;
      const deps = await viewDependencies(db, r.oid);
      const readsUsers = usersDeps.has(r.oid);
      const readsRls = deps.some((d) => d.rls && `${d.schema}.${d.name}` !== r.full);
      if (readsUsers) {
        findings.push(F("AUTH-USERS-EXPOSED", "0002_auth_users_exposed", "CRITICAL", r.full,
          "A public view exposes auth.users (emails and account data) to the API",
          `Views run with their owner's rights, so this view bypasses every protection on auth.users. Reachable by: ${who(r)}.`,
          `alter view ${r.full} set (security_invoker = on);  -- or drop the view and expose only the columns you need through a table with RLS`,
          { depends_on: deps.map((d) => `${d.schema}.${d.name}`) }));
      } else {
        findings.push(F("VIEW-DEFINER", "0010_security_definer_view", readsRls ? "HIGH" : "MEDIUM", r.full,
          "View ignores Row Level Security of the tables it reads (runs as its owner)",
          `Postgres views are SECURITY DEFINER by default, so queries through this view skip RLS${readsRls ? " on tables that have it" : ""}. Reachable by: ${who(r)}.`,
          `alter view ${r.full} set (security_invoker = on);`, { depends_on: deps.map((d) => `${d.schema}.${d.name}`) }));
      }
    } else if (r.kind === "m" && exposed) {
      findings.push(F("MATVIEW-IN-API", "0016_materialized_view_in_api", "MEDIUM", r.full,
        "Materialized view is reachable through the API and cannot have RLS",
        `Materialized views cannot carry Row Level Security. Reachable by: ${who(r)}.`,
        `revoke all on ${r.full} from anon, authenticated;  -- and read it through a function or a table with RLS`, {}));
    }
  }

  // ---- policies
  const initplan = {};
  for (const p of pols) {
    const isStorage = p.schema === "storage";
    if (isStorage && p.table !== "objects") continue;
    const exprs = [p.qual, p.with_check].filter(Boolean).join(" ");
    const t = model.tables[p.full];

    if (!isStorage) {
      if (t && p.cmd === "SELECT" && p.alwaysTrue) {
        t.publicRead ||= {};
        if (p.appliesAnon) t.publicRead.anon = p.name;
        if (p.appliesAuth) t.publicRead.auth = p.name;
      }
      if (p.alwaysTrue) {
        const hasOwnerOrSens = t && (t.owner || t.sensitive.length);
        if (p.isWrite && p.appliesAnon) {
          findings.push(F("POLICY-ALWAYS-TRUE", "0024_permissive_rls_policy", t?.sensitive.length ? "CRITICAL" : "HIGH", p.full,
            `Policy "${p.name}" lets anyone ${p.cmd.toLowerCase() === "all" ? "read and write" : p.cmd.toLowerCase()} every row`,
            "The condition is literally `true` and the policy applies to the anonymous role (or to everyone), so it grants access with no check at all.",
            "Replace the condition with an ownership or role check, e.g. `(select auth.uid()) = user_id`.", { policy: p.name, cmd: p.cmd, roles: p.roles }));
        } else if (p.isWrite && p.appliesAuth) {
          findings.push(F("POLICY-ALWAYS-TRUE", "0024_permissive_rls_policy", "MEDIUM", p.full,
            `Policy "${p.name}" lets any signed-in user ${p.cmd.toLowerCase() === "all" ? "read and write" : p.cmd.toLowerCase()} every row`,
            "The condition is literally `true`: every account can change every other account's rows.",
            "Replace the condition with an ownership or role check, e.g. `(select auth.uid()) = user_id`.", { policy: p.name, cmd: p.cmd, roles: p.roles }));
        } else if (p.cmd === "SELECT") {
          const sev = t?.sensitive.length ? (p.appliesAnon ? "HIGH" : "MEDIUM") : t?.owner ? (p.appliesAnon ? "MEDIUM" : "LOW") : (p.appliesAnon ? "LOW" : "INFO");
          findings.push(F("POLICY-ALWAYS-TRUE", "0024_permissive_rls_policy", sev, p.full,
            `Policy "${p.name}" makes every row readable${p.appliesAnon ? " to anyone" : " to any signed-in user"} (confirm that is intended)`,
            t?.sensitive.length ? `The table holds sensitive-looking columns (${t.sensitive.join(", ")}), so open read access is dangerous.` : t?.owner ? "The table has an owner column, so these rows may be personal data. Fine for deliberately public profile fields; not fine for anything private." : "Fine for genuinely public reference data; confirm that is the intent.",
            "If only some columns or rows should be public, expose them through a view or a narrower condition.", { policy: p.name, roles: p.roles }));
        }
      }
      if (/(user_metadata|raw_user_meta_data)/i.test(exprs)) {
        findings.push(F("USER-METADATA-POLICY", "0015_rls_references_user_metadata", "HIGH", p.full,
          `Policy "${p.name}" trusts user_metadata, which users can edit themselves`,
          "user_metadata can be changed by the signed-in user (via auth.updateUser). A policy that grants access from it can be bypassed by anyone.",
          "Use app_metadata (only the server can change it) or a separate roles table instead.", { policy: p.name, expression: exprs.slice(0, 200) }));
      }
      if (p.isWrite && !p.alwaysTrue && (p.appliesAnon || p.appliesAuth) && !/auth\./i.test(exprs) && !/\w\s*\(/.test(exprs.replace(/::[a-z_ ]+/gi, ""))) {
        findings.push(F("POLICY-NO-IDENTITY", "custom", "MEDIUM", p.full,
          `Policy "${p.name}" allows ${p.cmd.toLowerCase()} based on row data only, not on who is asking`,
          `The condition (${exprs.slice(0, 120)}) never looks at the signed-in user, so it applies equally to everyone it is granted to.`,
          "Bind the condition to the caller, e.g. `(select auth.uid()) = user_id`.", { policy: p.name, roles: p.roles }));
      }
      const unwrapped = exprs.replace(/\(\s*SELECT\s+auth\.(uid|jwt|role|email)\(\)\s+AS\s+\w+\s*\)/gi, "");
      if (IDENTITY.test(unwrapped)) (initplan[p.full] ||= []).push(p.name);
    } else {
      // storage.objects
      const bound = STORAGE_IDENTITY.test(exprs);
      if (p.isWrite && (p.alwaysTrue || !bound) && (p.appliesAnon || p.appliesAuth)) {
        findings.push(F("STORAGE-BROAD-WRITE", "custom", p.appliesAnon ? "HIGH" : "MEDIUM", "storage.objects",
          `Storage policy "${p.name}" allows ${p.cmd.toLowerCase()} on files without tying them to a user`,
          `${p.appliesAnon ? "Anyone" : "Any signed-in user"} can ${p.cmd === "ALL" ? "upload, overwrite and delete" : p.cmd.toLowerCase()} files in the covered bucket(s) (condition: ${exprs.slice(0, 120) || "none"}).`,
          "Add a folder or owner check, e.g. `(storage.foldername(name))[1] = (select auth.uid())::text`.", { policy: p.name, roles: p.roles }));
      }
      if (p.cmd === "SELECT" && p.appliesAnon && !bound) {
        findings.push(F("STORAGE-BROAD-READ", "0025_public_bucket_allows_listing", "LOW", "storage.objects",
          `Storage policy "${p.name}" lets anyone list every file in the bucket`,
          "A broad SELECT policy lets clients enumerate file names, not just open known URLs.",
          "Public buckets serve files by URL without a SELECT policy; remove this policy unless listing is required.", { policy: p.name }));
      }
    }
  }
  for (const [table, names] of Object.entries(initplan)) {
    findings.push(F("AUTH-INITPLAN", "0003_auth_rls_initplan", "LOW", table,
      "Policies call auth.uid()/auth.jwt() per row instead of once per query",
      `Slower on big tables. Policies: ${names.join(", ")}.`,
      "Wrap calls: `(select auth.uid())` instead of `auth.uid()`.", { policies: names }));
  }

  // ---- functions
  const looseInvoker = [];
  const looseRefs = [];
  for (const f of funcs) {
    const callable = [f.anon_exec && "anon", f.auth_exec && "authenticated"].filter(Boolean);
    if (f.definer) {
      let sev = "LOW";
      if (!f.hasSearchPath && callable.length) sev = "HIGH";
      else if (callable.includes("anon")) sev = "MEDIUM";
      else if (!f.hasSearchPath) sev = "MEDIUM";
      findings.push(F("DEFINER-FUNCTION", "0011/0028/0029", sev, f.full,
        `SECURITY DEFINER function${f.hasSearchPath ? "" : " without a fixed search_path"}${callable.length ? ` callable by ${callable.join(" and ")}` : ""}`,
        `The function runs with its owner's (superuser-like) rights. ${f.hasSearchPath ? "" : "Without `set search_path` a caller can shadow objects and escalate privileges. "}${callable.length ? "It is reachable as an RPC endpoint; it must check permissions inside." : ""}`,
        `alter function ${f.schema}.${f.name}(${f.args}) set search_path = public;  -- prefer '' and schema-qualified names${callable.includes("anon") ? `\n-- and if logged-out users must not call it: revoke execute on function ${f.schema}.${f.name}(${f.args}) from anon, public;` : ""}`,
        { callable_by: callable, search_path_fixed: f.hasSearchPath, fn: { schema: f.schema, name: f.name } }));
    } else if (!f.hasSearchPath && callable.length) {
      looseInvoker.push(f.full);
      looseRefs.push({ schema: f.schema, name: f.name });
    }
  }
  if (looseInvoker.length) findings.push(F("FUNC-SEARCH-PATH", "0011_function_search_path_mutable", "LOW", `${looseInvoker.length} function(s)`,
    "Functions without a fixed search_path", `Hygiene issue: ${looseInvoker.slice(0, 8).join(", ")}${looseInvoker.length > 8 ? ", ..." : ""}.`,
    "Add `set search_path = public` (or '') to each function.", { functions: looseInvoker, fns: looseRefs }));

  // ---- storage buckets loaded by migrations
  try {
    const b = await q(db, "select id, public from storage.buckets order by id");
    const pub = b.filter((x) => x.public);
    if (pub.length) findings.push(F("PUBLIC-BUCKET", "info", "INFO", "storage.buckets",
      `${pub.length} public bucket(s): ${pub.map((x) => x.id).join(", ")}`,
      "Files in public buckets are readable by anyone who knows or guesses the URL, with no policy involved.",
      "Make sure nothing private (invoices, IDs, exports) is stored there.", { buckets: pub.map((x) => x.id) }));
  } catch { /* storage.buckets always exists in the scaffold */ }

  findings.sort((a, b) => RANK[a.severity] - RANK[b.severity] || a.object.localeCompare(b.object));
  return { findings, model };
}
