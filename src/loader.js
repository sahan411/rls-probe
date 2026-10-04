import { PGlite } from "@electric-sql/pglite";
import { pgcrypto } from "@electric-sql/pglite/contrib/pgcrypto";
import { uuid_ossp } from "@electric-sql/pglite/contrib/uuid_ossp";
import { citext } from "@electric-sql/pglite/contrib/citext";
import { pg_trgm } from "@electric-sql/pglite/contrib/pg_trgm";
import { splitSql } from "./splitter.js";
import { scaffoldSql } from "./scaffold.js";

// Extensions we can really load. Anything else in a dump (pg_graphql, pgsodium, vault, pg_net, postgis, ...) is skipped and reported.
const SUPPORTED_EXT = { pgcrypto, "uuid-ossp": uuid_ossp, citext, pg_trgm };

const BENIGN_EXISTS = /^\s*create\s+(schema|role|extension|publication)\b/i;

export function stmtPreview(sql) {
  return sql.replace(/\s+/g, " ").slice(0, 140);
}

// files: [{ name, text }]. Each statement runs on its own so one unsupported statement cannot hide the rest of the schema.
export async function loadSchema(files, { defaultGrants = true } = {}) {
  const db = new PGlite({ extensions: SUPPORTED_EXT });
  await db.exec(scaffoldSql({ defaultGrants }));
  await db.exec("set search_path = public, extensions;");

  const report = { files: files.map((f) => f.name), total: 0, ok: 0, failed: [], skippedExtensions: [], ignored: 0 };
  for (const f of files) {
    for (const st of splitSql(f.text)) {
      report.total++;
      const ext = /^\s*create\s+extension\s+(?:if\s+not\s+exists\s+)?"?([A-Za-z0-9_\-]+)"?/i.exec(st.sql);
      if (ext && !SUPPORTED_EXT[ext[1]]) {
        report.skippedExtensions.push({ name: ext[1], file: f.name, line: st.line });
        continue;
      }
      try {
        await db.exec(st.sql);
        report.ok++;
      } catch (e) {
        if (BENIGN_EXISTS.test(st.sql) && /already exists/i.test(e.message)) { report.ignored++; continue; }
        report.failed.push({ file: f.name, line: st.line, message: String(e.message).split("\n")[0], statement: stmtPreview(st.sql) });
      }
    }
  }
  // dumps often blank the search_path; policies and probes run under the normal API path
  await db.exec("set search_path = public, extensions;");
  return { db, load: report };
}
