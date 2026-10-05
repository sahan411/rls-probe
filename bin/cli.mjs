#!/usr/bin/env node
import { readFileSync, readdirSync, statSync, writeFileSync, mkdirSync } from "node:fs";
import { join, resolve, basename, dirname, relative, isAbsolute, sep } from "node:path";
import { exitCode } from "../src/audit.js";
import { runAudit, AuditTimeoutError, DEFAULT_TIMEOUT_SECONDS } from "../src/runner.js";
import { toMarkdown, toHtml, toSummary } from "../src/report.js";
import { toSarif } from "../src/sarif.js";
import { findingCommands } from "../src/github.js";
import { oneLine } from "../src/text.js";

const HELP = `rls-probe <file-or-folder...> [options]

Works offline on your Supabase migrations or a schema dump: loads them into a local sandbox Postgres (PGlite),
runs static Row Level Security rules plus executed access probes (anon, user A, user B), and writes a ranked
report, SARIF and a draft fix. No keys, no live database, no network.
Row data in the SQL (COPY blocks, INSERT rows) is ignored and never loaded.

Options
  --schemas a,b          schemas exposed through the API (default: public)
  --out report.md        write the Markdown report
  --html report.html     write an HTML report (print it to PDF in a browser)
  --json report.json     write machine-readable results
  --sarif out.sarif      write a SARIF 2.1.0 log (GitHub code scanning and other SARIF tools)
  --summary-file f.md    write a compact Markdown summary (for $GITHUB_STEP_SUMMARY)
  --format text|github   console output: text (default) or GitHub Actions annotations (::error / ::warning)
  --fix fix.sql          write a DRAFT fix migration; also applies it to a fresh copy and re-audits (before/after)
  --title "text"         report title
  --badge "text"         banner line at the top of the report (e.g. SAMPLE - FICTIONAL APP)
  --no-probe             skip the executed access tests
  --default-grants on|off   assume Supabase's default privileges on the public schema (default: on)
  --fail-on high|medium|never   exit code 2 if findings at this level exist (default: high)
  --timeout seconds      abort the whole audit after this long (default: ${DEFAULT_TIMEOUT_SECONDS}); exits with code 70
  -h, --help

Exit codes: 0 ok, 2 findings at the --fail-on level, 64 usage error, 66 no input, 70 timeout, 1 internal error.
`;

const usage = (msg) => { console.error(`error: ${oneLine(msg)}\n\n${HELP}`); return 64; };

// Path used for file locations in annotations and SARIF: relative to the repository root (GITHUB_WORKSPACE in Actions, else the
// working directory), forward slashes. null when the file lies outside it, so no location is better than a wrong one.
const base = resolve(process.env.GITHUB_WORKSPACE || process.cwd());
function repoPath(abs) {
  const rel = relative(base, abs);
  if (!rel || rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel)) return null;
  return rel.split(sep).join("/");
}

function collect(paths) {
  const files = [];
  const seen = new Set();
  const walk = (p) => {
    const st = statSync(p);
    if (st.isDirectory()) readdirSync(p).sort().forEach((e) => walk(join(p, e)));
    else if (/\.sql$/i.test(p) && !seen.has(p)) {
      seen.add(p);
      files.push({ name: basename(p), path: repoPath(p), text: readFileSync(p, "utf8") });
    }
  };
  paths.forEach((p) => walk(resolve(p)));
  return files;
}

function write(file, text) {
  mkdirSync(dirname(resolve(file)), { recursive: true });
  writeFileSync(file, text);
}

async function main(args) {
  const opt = { schemas: ["public"], probe: true, defaultGrants: true, failOn: "high" };
  const paths = [];
  let out, html, json, fix, title, badge, sarif, summaryFile;
  let format = "text";
  let timeoutSeconds = DEFAULT_TIMEOUT_SECONDS;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    const value = () => {
      if (i + 1 >= args.length) throw new Error(`option ${a} needs a value`);
      return args[++i];
    };
    try {
      if (a === "-h" || a === "--help") { console.log(HELP); return 0; }
      else if (a === "--schemas") {
        opt.schemas = value().split(",").map((s) => s.trim()).filter(Boolean);
        if (!opt.schemas.length || opt.schemas.some((s) => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(s))) throw new Error("--schemas expects a comma-separated list of schema names (letters, digits, underscore)");
      }
      else if (a === "--out") out = value();
      else if (a === "--html") html = value();
      else if (a === "--json") json = value();
      else if (a === "--sarif") sarif = value();
      else if (a === "--summary-file") summaryFile = value();
      else if (a === "--fix") fix = value();
      else if (a === "--title") title = value();
      else if (a === "--badge") badge = value();
      else if (a === "--no-probe") opt.probe = false;
      else if (a === "--default-grants") {
        const v = value();
        if (v !== "on" && v !== "off") throw new Error("--default-grants expects on or off");
        opt.defaultGrants = v !== "off";
      }
      else if (a === "--fail-on") {
        opt.failOn = value();
        if (!["high", "medium", "never"].includes(opt.failOn)) throw new Error("--fail-on expects high, medium or never");
      }
      else if (a === "--format") {
        format = value();
        if (!["text", "github"].includes(format)) throw new Error("--format expects text or github");
      }
      else if (a === "--timeout") {
        timeoutSeconds = Number(value());
        if (!Number.isFinite(timeoutSeconds) || timeoutSeconds <= 0) throw new Error("--timeout expects a positive number of seconds");
      }
      else if (a.startsWith("-")) throw new Error(`unknown option ${a}`);
      else paths.push(a);
    } catch (e) {
      return usage(e.message);
    }
  }
  if (!paths.length) { console.error(HELP); return 64; }

  let files;
  try {
    files = collect(paths);
  } catch (e) {
    if (e.code === "ENOENT") { console.error(oneLine(`error: path not found: ${e.path ?? paths.join(", ")}`)); return 66; }
    throw e;
  }
  if (!files.length) { console.error("No .sql files found."); return 66; }

  let verification = null;
  let res;
  try {
    if (fix) {
      verification = await runAudit(files, opt, { withFix: true, timeoutSeconds });
      res = verification.before;
    } else {
      res = await runAudit(files, opt, { timeoutSeconds });
    }
  } catch (e) {
    if (e instanceof AuditTimeoutError) { console.error(`error: ${e.message}`); return 70; }
    throw e;
  }

  const c = res.counts;
  const ld = res.load;
  const extra = [
    ld.dataSkipped ? `${ld.dataSkipped} data statement(s) skipped (row data is ignored and never loaded)` : "",
    ld.skippedStatements.length ? `${ld.skippedStatements.length} statement(s) not executed because they could stall the audit or hide the rest of the file (see the report)` : "",
  ].filter(Boolean);
  console.log(`rls-probe: ${ld.ok}/${ld.total} statements loaded from ${files.length} file(s)${extra.length ? `; ${extra.join("; ")}` : ""}`);
  console.log(`findings: CRITICAL ${c.CRITICAL}  HIGH ${c.HIGH}  MEDIUM ${c.MEDIUM}  LOW ${c.LOW}  INFO ${c.INFO}   | failing access tests: ${res.proof.failures}`);
  // Names and titles come from the audited SQL (possibly a pull request): keep each one on a single log line.
  if (format === "github") for (const line of findingCommands(res.findings)) console.log(line);
  else for (const f of res.findings.filter((x) => x.severity !== "INFO").slice(0, 25)) console.log(oneLine(`  [${f.severity}] ${f.object}: ${f.title}`));
  if (verification) console.log(`after draft fix: CRITICAL ${verification.after.counts.CRITICAL}  HIGH ${verification.after.counts.HIGH}  MEDIUM ${verification.after.counts.MEDIUM}  | failing access tests: ${verification.after.proof.failures}  (${verification.fix.manual.length} item(s) need a human decision)`);
  if (ld.failed.length) console.log(`note: ${ld.failed.length} statement(s) could not be loaded; see the report`);

  // Files are written after the console summary, so a failed write (bad path, read-only folder) cannot hide the findings.
  const ropts = { title: title || "Supabase security audit", badge: badge || "", verification };
  if (fix) write(fix, verification.fix.sql);
  if (out) write(out, toMarkdown(res, ropts));
  if (html) write(html, toHtml(res, ropts));
  if (summaryFile) write(summaryFile, toSummary(res, { title: title || "rls-probe: Row Level Security audit" }));
  if (sarif) write(sarif, JSON.stringify(toSarif(res), null, 2) + "\n");
  if (json) {
    const { _model, ...rest } = res;
    write(json, JSON.stringify(verification ? { ...rest, after: { counts: verification.after.counts, failures: verification.after.proof.failures } } : rest, null, 2));
  }
  return exitCode(res, opt.failOn);
}

try {
  process.exitCode = await main(process.argv.slice(2));
} catch (e) {
  console.error(oneLine(`error: ${e?.message ?? e}`));
  if (process.env.RLS_PROBE_DEBUG) console.error(e?.stack);
  process.exitCode = 1;
}
