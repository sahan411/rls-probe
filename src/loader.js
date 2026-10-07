import { PGlite } from "@electric-sql/pglite";
import { pgcrypto } from "@electric-sql/pglite/contrib/pgcrypto";
import { uuid_ossp } from "@electric-sql/pglite/contrib/uuid_ossp";
import { citext } from "@electric-sql/pglite/contrib/citext";
import { pg_trgm } from "@electric-sql/pglite/contrib/pg_trgm";
import { ltree } from "@electric-sql/pglite/contrib/ltree";
import { splitSql } from "./splitter.js";
import { scaffoldSql } from "./scaffold.js";
import { classifyStatement } from "./sqlparse.js";
import { LocationIndex } from "./locations.js";
import { qname } from "./introspect.js";

// Extensions we can really load. Anything else in a dump (pg_graphql, pgsodium, vault, pg_net, postgis, ...) is skipped and reported.
const SUPPORTED_EXT = { pgcrypto, "uuid-ossp": uuid_ossp, citext, pg_trgm, ltree };

const BENIGN_EXISTS = /^\s*create\s+(schema|role|extension|publication)\b/i;

// A migration may use a schema that was created in the dashboard (for example "private"). Such a schema is assumed to exist so the
// statements that use it still load; each one is reported in load.assumedSchemas. Bounded, and never for system schemas.
const MISSING_SCHEMA = /^schema "([^"]+)" does not exist/i;
const SYSTEM_SCHEMAS = new Set(["pg_catalog", "information_schema", "pg_temp", "pg_toast", "public", "extensions"]);
const MAX_ASSUMED_SCHEMAS = 20;

export function stmtPreview(sql) {
  return sql.replace(/\s+/g, " ").slice(0, 140);
}

async function relationExists(db, schema, name) {
  const r = await db.query("select to_regclass($1) is not null as e", [qname(schema, name)]);
  return r.rows[0].e;
}

// files: [{ name, text, path? }]. Each statement runs on its own so one unsupported statement cannot hide the rest of the schema.
// `path` is the repository-relative path used for source locations (null = unknown, undefined = use `name`).
//
// Row data is never loaded: COPY / \copy (inline data blocks included) and every INSERT except into storage.buckets are skipped and
// counted in load.dataSkipped. Statements that could stall the sandbox (LISTEN, long pg_sleep, DO blocks calling pg_sleep) are
// skipped and listed in load.skippedStatements with the reason.
export async function loadSchema(files, { defaultGrants = true } = {}) {
  const db = new PGlite({ extensions: SUPPORTED_EXT });
  await db.exec(scaffoldSql({ defaultGrants }));
  await db.exec("set search_path = public, extensions;");

  const locations = new LocationIndex();
  const report = { files: files.map((f) => f.name), total: 0, ok: 0, failed: [], skippedExtensions: [], ignored: 0, dataSkipped: 0, skippedStatements: [], transactionStatements: 0, assumedSchemas: [] };
  for (const f of files) {
    const file = f.path === undefined ? f.name : f.path;
    // Each migration file starts from the normal API search_path (a previous file may have blanked it).
    await db.exec("set search_path = public, extensions;");
    for (const st of splitSql(f.text)) {
      const verdict = classifyStatement(st);
      if (verdict.action === "skip" && verdict.category === "txn") { report.transactionStatements++; continue; }
      if (verdict.action === "skip") {
        if (verdict.category === "data") report.dataSkipped++;
        else report.skippedStatements.push({ file: f.name, line: st.line, reason: verdict.reason, statement: stmtPreview(st.sql) });
        // A COPY block that never reaches its terminating "\." line swallows the rest of the file: say so instead of hiding it.
        if (st.unterminated) report.skippedStatements.push({ file: f.name, line: st.line, reason: "the COPY data block has no terminating \\. line, so everything after it in this file was treated as data (truncated dump?)", statement: stmtPreview(st.sql) });
        continue;
      }
      report.total++;
      const ext = /^\s*create\s+extension\s+(?:if\s+not\s+exists\s+)?"?([A-Za-z0-9_\-]+)"?/i.exec(st.sql);
      if (ext && !SUPPORTED_EXT[ext[1]]) {
        report.skippedExtensions.push({ name: ext[1], file: f.name, line: st.line });
        continue;
      }
      // Source-location bookkeeping must never be able to break loading, so it is isolated from the statement itself.
      let effect = null;
      let preExisting = false;
      try {
        effect = locations.effectOf(st.sql);
        if (effect?.ifNotExists) preExisting = await relationExists(db, effect.schema, effect.name);
      } catch { effect = null; }
      try {
        try {
          await db.exec(st.sql);
        } catch (e0) {
          const ms = MISSING_SCHEMA.exec(String(e0.message));
          if (!ms || SYSTEM_SCHEMAS.has(ms[1].toLowerCase()) || report.assumedSchemas.length >= MAX_ASSUMED_SCHEMAS) throw e0;
          await db.exec(`create schema if not exists "${ms[1].replace(/"/g, '""')}"`);
          report.assumedSchemas.push({ name: ms[1], file: f.name, line: st.line });
          await db.exec(st.sql);
        }
        report.ok++;
        try { locations.apply(effect, { file, line: st.line, endLine: st.endLine }, { preExisting }); } catch { /* location unknown */ }
      } catch (e) {
        if (BENIGN_EXISTS.test(st.sql) && /already exists/i.test(e.message)) { report.ignored++; continue; }
        report.failed.push({ file: f.name, line: st.line, message: String(e.message).split("\n")[0], statement: stmtPreview(st.sql) });
      }
    }
  }
  // dumps often blank the search_path; policies and probes run under the normal API path
  await db.exec("set search_path = public, extensions;");
  return { db, load: report, locations };
}
