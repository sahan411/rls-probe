import { readFileSync } from "node:fs";
import { loadSchema } from "./loader.js";
import { runChecks, SEVERITIES } from "./checks.js";
import { runProbes } from "./probe.js";
import { generateFix } from "./fixgen.js";
import { locateFinding } from "./locations.js";
import { functionCounts } from "./introspect.js";

// One source of truth for the version: package.json (a test keeps meta.version and package.json in step).
export const VERSION = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version;

const RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));

function count(findings) {
  const c = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const f of findings) c[f.severity]++;
  return c;
}

// files: [{ name, text, path? }]  (path: repository-relative path for source locations; null = unknown; omitted = use name)
export async function audit(files, { schemas = ["public"], probe = true, defaultGrants = true } = {}) {
  const started = Date.now();
  const { db, load, locations } = await loadSchema(files, { defaultGrants });
  try {
    const { findings, model } = await runChecks(db, { schemas });
    let proof = { probes: [], skipped: [], failures: 0 };
    if (probe) {
      proof = await runProbes(db, model, findings);
      // An executed probe can fail even when static checks look fine: that is exactly what execution is for.
      const byTable = {};
      for (const p of proof.probes.filter((x) => x.pass === false)) (byTable[p.table] ||= []).push(p);
      for (const [table, ps] of Object.entries(byTable)) {
        const covered = findings.some((f) => f.object === table && RANK[f.severity] <= RANK.HIGH && f.rule !== "PROBE-FAILED");
        if (covered) continue;
        const sev = ps.reduce((m, p) => (RANK[p.severity] < RANK[m] ? p.severity : m), "INFO");
        findings.push({
          id: `PROBE-FAILED#${table}`, rule: "PROBE-FAILED", lint: "executed", severity: sev, object: table,
          title: "An executed access test failed even though no static rule fired",
          why: ps.map((p) => `${p.probe}: ${p.observed}`).join("; "),
          fix: "Read the table's policies against this result and correct the condition; re-run to confirm.", evidence: { probes: ps.map((p) => p.probe) },
        });
      }
      findings.sort((a, b) => RANK[a.severity] - RANK[b.severity] || a.object.localeCompare(b.object));
    }
    // Where the finding lives in the supplied SQL (file, line). Attached only when certain; see src/locations.js.
    const fnCounts = await functionCounts(db);
    for (const f of findings) {
      const at = locateFinding(f, locations, fnCounts);
      if (at.length) f.locations = at;
    }
    const tables = Object.fromEntries(Object.entries(model.tables).map(([k, t]) => [k, {
      owner_column: t.owner, rls: t.rls, policies: t.policies, sensitive_columns: t.sensitive,
      api_access: { anon: [t.anon_select && "select", t.anon_insert && "insert", t.anon_update && "update", t.anon_delete && "delete"].filter(Boolean), authenticated: [t.auth_select && "select", t.auth_insert && "insert", t.auth_update && "update", t.auth_delete && "delete"].filter(Boolean) },
    }]));
    return {
      meta: { tool: "rls-probe", version: VERSION, schemas, generated: new Date().toISOString(), ms: Date.now() - started, defaultGrants, engine: "PGlite (PostgreSQL 18, WASM sandbox)" },
      load, findings, counts: count(findings), tables, proof, _model: model,
    };
  } finally {
    await db.close();
  }
}

// Audit, generate a draft fix, apply it to a fresh copy of the schema and audit again.
export async function auditWithFix(files, opts = {}) {
  const before = await audit(files, opts);
  const fix = generateFix(before.findings, before._model);
  const after = await audit([...files, { name: "draft-fix.sql", text: fix.sql }], opts);
  return { before, after, fix };
}

export function exitCode(result, failOn = "high") {
  if (failOn === "never") return 0;
  const limit = failOn === "medium" ? RANK.MEDIUM : RANK.HIGH;
  const bad = result.findings.some((f) => RANK[f.severity] <= limit && f.severity !== "INFO");
  const probeBad = result.proof.probes.some((p) => p.pass === false && RANK[p.severity] <= limit && p.severity !== "INFO");
  return bad || probeBad ? 2 : 0;
}
