#!/usr/bin/env node
import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join, resolve, basename } from "node:path";
import { audit, auditWithFix, exitCode } from "../src/audit.js";
import { toMarkdown, toHtml } from "../src/report.js";

const HELP = `supabase-rls-audit <file-or-folder...> [options]

Audits Supabase schema SQL or a migrations folder for Row Level Security gaps and PROVES the result by
executing access tests in a sandboxed Postgres (PGlite). No keys, no live database.

Options
  --schemas a,b          schemas exposed through the API (default: public)
  --out report.md        write the Markdown report
  --html report.html     write an HTML report (print it to PDF in a browser)
  --json report.json     write machine-readable results
  --fix fix.sql          write a DRAFT fix migration; also applies it to a fresh copy and re-audits (before/after)
  --title "text"         report title
  --badge "text"         banner line at the top of the report (e.g. SAMPLE - FICTIONAL APP)
  --no-probe             skip the executed access tests
  --default-grants off   do not assume Supabase's default privileges on the public schema
  --fail-on high|medium|never   exit code 2 if findings at this level exist (default: high)
  -h, --help
`;

function collect(paths) {
  const files = [];
  const walk = (p) => {
    const st = statSync(p);
    if (st.isDirectory()) readdirSync(p).sort().forEach((e) => walk(join(p, e)));
    else if (/\.sql$/i.test(p)) files.push({ name: p, text: readFileSync(p, "utf8") });
  };
  paths.forEach((p) => walk(resolve(p)));
  return files.map((f) => ({ ...f, name: basename(f.name) }));
}

const args = process.argv.slice(2);
const opt = { schemas: ["public"], probe: true, defaultGrants: true, failOn: "high" };
const paths = [];
let out, html, json, fix, title, badge;
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === "-h" || a === "--help") { console.log(HELP); process.exit(0); }
  else if (a === "--schemas") opt.schemas = args[++i].split(",").map((s) => s.trim()).filter(Boolean);
  else if (a === "--out") out = args[++i];
  else if (a === "--html") html = args[++i];
  else if (a === "--json") json = args[++i];
  else if (a === "--fix") fix = args[++i];
  else if (a === "--title") title = args[++i];
  else if (a === "--badge") badge = args[++i];
  else if (a === "--no-probe") opt.probe = false;
  else if (a === "--default-grants") opt.defaultGrants = args[++i] !== "off";
  else if (a === "--fail-on") opt.failOn = args[++i];
  else if (a.startsWith("-")) { console.error(`Unknown option ${a}\n\n${HELP}`); process.exit(64); }
  else paths.push(a);
}
if (!paths.length) { console.error(HELP); process.exit(64); }

const files = collect(paths);
if (!files.length) { console.error("No .sql files found."); process.exit(66); }

const verification = fix ? await auditWithFix(files, opt) : null;
const res = verification ? verification.before : await audit(files, opt);
const ropts = { title: title || "Supabase security audit", badge: badge || "", verification };
if (fix) writeFileSync(fix, verification.fix.sql);
if (out) writeFileSync(out, toMarkdown(res, ropts));
if (html) writeFileSync(html, toHtml(res, ropts));
if (json) {
  const { _model, ...rest } = res;
  writeFileSync(json, JSON.stringify(verification ? { ...rest, after: { counts: verification.after.counts, failures: verification.after.proof.failures } } : rest, null, 2));
}

const c = res.counts;
console.log(`supabase-rls-audit: ${res.load.ok}/${res.load.total} statements loaded from ${files.length} file(s)`);
console.log(`findings: CRITICAL ${c.CRITICAL}  HIGH ${c.HIGH}  MEDIUM ${c.MEDIUM}  LOW ${c.LOW}  INFO ${c.INFO}   | failing access tests: ${res.proof.failures}`);
for (const f of res.findings.filter((x) => x.severity !== "INFO").slice(0, 25)) console.log(`  [${f.severity}] ${f.object}: ${f.title}`);
if (verification) console.log(`after draft fix: CRITICAL ${verification.after.counts.CRITICAL}  HIGH ${verification.after.counts.HIGH}  MEDIUM ${verification.after.counts.MEDIUM}  | failing access tests: ${verification.after.proof.failures}  (${verification.fix.manual.length} item(s) need a human decision)`);
if (res.load.failed.length) console.log(`note: ${res.load.failed.length} statement(s) could not be loaded; see the report`);
process.exit(exitCode(res, opt.failOn));
