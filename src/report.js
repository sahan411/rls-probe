import { SEVERITIES } from "./checks.js";

const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

const LIMITS = [
  "This is an audit of the schema and migrations you supplied (tables, views, functions, policies, grants) executed in a sandboxed Postgres. It never connects to your live project and never needs your keys.",
  "Not checked: leaked keys in code or git history, Edge Function and API route logic, Auth settings (email confirmation, OTP expiry, redirect URLs), hosting and dashboard configuration, rate limiting, business-logic abuse, and the actual data in your tables.",
  "Access tests use two synthetic users and seeded rows. Tables whose columns the seeder cannot fill are listed as skipped, not as passed.",
  "Assumes Supabase's default privileges for the public schema (all privileges granted to anon and authenticated; Row Level Security is what protects the data). Re-run with --default-grants off if your project removed them.",
  "Rule names follow Supabase's published database linter where one exists; this is an independent implementation, not the Supabase linter.",
  "This is a technical review, not a penetration test, and no review can guarantee security.",
];

function verdict(c) {
  if (c.CRITICAL || c.HIGH) return { text: "Do not put real user data in this project yet.", detail: `${c.CRITICAL} critical and ${c.HIGH} high-severity issue(s) let people read or change data they should not.` };
  if (c.MEDIUM) return { text: "No high-severity issue found; fix the medium items soon.", detail: `${c.MEDIUM} medium issue(s) weaken the protections.` };
  return { text: "No high-severity issue found in the supplied schema.", detail: "Only low or informational notes remain." };
}

function groups(findings) {
  return SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s)]).filter(([, l]) => l.length);
}

export function toMarkdown(res, { title = "Supabase security audit", verification = null, badge = "" } = {}) {
  const v = verdict(res.counts);
  const L = [];
  L.push(`# ${title}`, "");
  if (badge) L.push(`> **${badge}**`, "");
  L.push(`Generated ${res.meta.generated} by ${res.meta.tool} ${res.meta.version} (${res.meta.engine}). Schemas checked: ${res.meta.schemas.join(", ")}.`, "");
  L.push(`Loaded ${res.load.ok} of ${res.load.total} SQL statements from ${res.load.files.length} file(s)${res.load.failed.length ? `; ${res.load.failed.length} could not be loaded (listed at the end)` : ""}.`, "");
  L.push("## Verdict", "", `**${v.text}** ${v.detail}`, "");
  L.push("| Severity | Count |", "|---|---|", ...SEVERITIES.map((s) => `| ${s} | ${res.counts[s]} |`), "");
  if (verification) {
    const b = verification.before, a = verification.after;
    L.push("## Before and after the draft fix", "", "| | Before | After |", "|---|---|---|", ...["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => `| ${s} findings | ${b.counts[s]} | ${a.counts[s]} |`), `| Failing access tests | ${b.proof.failures} | ${a.proof.failures} |`, "");
  }
  L.push("## Findings", "");
  if (!res.findings.length) L.push("No findings.", "");
  let n = 0;
  for (const [sev, list] of groups(res.findings)) {
    L.push(`### ${sev}`, "");
    for (const f of list) {
      n++;
      L.push(`#### ${n}. ${f.title}`, `**Where:** \`${f.object}\`  |  **Rule:** ${f.rule}${f.lint && f.lint !== "custom" && f.lint !== "info" && f.lint !== "executed" ? ` (Supabase lint ${f.lint})` : ""}`, "", `**Why it matters:** ${f.why}`, "", `**Fix:** ${f.fix}`, "");
    }
  }
  L.push("## Proof: executed access tests", "");
  if (res.proof.probes.length) {
    L.push("Each test ran as the stated role against seeded rows of two synthetic users (A and B), inside a transaction that was rolled back.", "", "| Table | Test | Role | Expected | Observed | Result |", "|---|---|---|---|---|---|");
    for (const p of res.proof.probes) L.push(`| \`${p.table}\` | ${p.probe} | ${p.role} | ${p.expectation} | ${p.observed} | ${p.pass === null ? "info" : p.pass ? "PASS" : "**FAIL**"} |`);
  } else L.push("No access tests ran (probes disabled or no API-exposed tables).");
  if (res.proof.skipped.length) L.push("", "Skipped (could not seed test rows): " + res.proof.skipped.map((s) => `\`${s.table}\` (${s.reason})`).join("; "));
  L.push("");
  if (verification) L.push("## Draft fix (SQL)", "", "```sql", verification.fix.sql.trim(), "```", "", ...(verification.fix.manual.length ? ["### Needs a human decision", "", ...verification.fix.manual.map((m) => `- \`${m.object}\` (${m.rule}): ${m.note}`), ""] : []));
  L.push("## What was and was not checked", "", ...LIMITS.map((x) => `- ${x}`), "");
  if (res.load.skippedExtensions.length) L.push("## Load notes", "", "Extensions not available in the sandbox and skipped: " + [...new Set(res.load.skippedExtensions.map((e) => e.name))].join(", "), "");
  if (res.load.failed.length) L.push("Statements that could not be loaded (their objects are missing from this audit):", "", ...res.load.failed.slice(0, 20).map((x) => `- ${x.file}:${x.line} ${x.message} — \`${x.statement}\``), "");
  return L.join("\n");
}

export const CSS = `
@page { size: A4; margin: 16mm 14mm; }
body{font-family:'Segoe UI',Arial,sans-serif;color:#111827;font-size:10pt;line-height:1.45}
h1{font-size:21pt;margin:0 0 4px;color:#14213d} h2{font-size:13.5pt;border-bottom:2px solid #0f766e;padding-bottom:3px;margin-top:20px;color:#14213d}
h3{font-size:11.5pt;margin:12px 0 4px} code{background:#f1f5f9;padding:1px 4px;border-radius:3px;font-size:9pt} pre{background:#0f172a;color:#e2e8f0;padding:8px 10px;border-radius:5px;font-size:8.3pt;white-space:pre-wrap}
.badge{display:inline-block;background:#fef3c7;color:#92400e;padding:3px 9px;border-radius:4px;font-size:9pt;font-weight:600}
table{border-collapse:collapse;width:100%;margin:6px 0} th,td{border:1px solid #cbd5e1;padding:4px 7px;text-align:left;vertical-align:top;font-size:8.8pt} th{background:#14213d;color:#fff}
.CRITICAL{color:#7f1d1d;font-weight:800}.HIGH{color:#b91c1c;font-weight:700}.MEDIUM{color:#b45309;font-weight:700}.LOW{color:#0369a1;font-weight:700}.INFO{color:#475569;font-weight:700}
.PASS{color:#047857;font-weight:700}.FAIL{color:#b91c1c;font-weight:800}
.box{border-left:4px solid #0f766e;background:#f0fdfa;padding:8px 12px;margin:10px 0}.finding{page-break-inside:avoid;margin-bottom:9px}.small{font-size:8.8pt;color:#475569}
`;

export function toHtml(res, { title = "Supabase security audit", verification = null, badge = "" } = {}) {
  const v = verdict(res.counts);
  let n = 0;
  const fl = groups(res.findings).map(([sev, list]) => list.map((f) => {
    n++;
    return `<div class="finding"><h3><span class="${sev}">${sev}</span> &nbsp;${n}. ${esc(f.title)}</h3><div class="small">Where: <code>${esc(f.object)}</code> &nbsp; Rule: ${esc(f.rule)}${f.lint && !["custom", "info", "executed"].includes(f.lint) ? ` (Supabase lint ${esc(f.lint)})` : ""}</div><p><b>Why it matters:</b> ${esc(f.why)}<br><b>Fix:</b> <code>${esc(f.fix).replace(/\n/g, "<br>")}</code></p></div>`;
  }).join("")).join("");
  const probeRows = res.proof.probes.map((p) => `<tr><td><code>${esc(p.table)}</code></td><td>${esc(p.probe)}</td><td>${esc(p.role)}</td><td>${esc(p.expectation)}</td><td>${esc(p.observed)}</td><td class="${p.pass === null ? "INFO" : p.pass ? "PASS" : "FAIL"}">${p.pass === null ? "info" : p.pass ? "PASS" : "FAIL"}</td></tr>`).join("");
  const ba = verification ? `<h2>Before and after the draft fix</h2><table><tr><th></th><th>Before</th><th>After</th></tr>${["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => `<tr><td>${s} findings</td><td>${verification.before.counts[s]}</td><td>${verification.after.counts[s]}</td></tr>`).join("")}<tr><td>Failing access tests</td><td>${verification.before.proof.failures}</td><td>${verification.after.proof.failures}</td></tr></table>` : "";
  const fixBlock = verification ? `<h2>Draft fix (SQL)</h2><pre>${esc(verification.fix.sql.trim())}</pre>${verification.fix.manual.length ? `<h3>Needs a human decision</h3><ul>${verification.fix.manual.map((m) => `<li><code>${esc(m.object)}</code> (${esc(m.rule)}): ${esc(m.note)}</li>`).join("")}</ul>` : ""}` : "";
  return `<html><head><meta charset="utf-8"><title>${esc(title)}</title><style>${CSS}</style></head><body>
${badge ? `<span class="badge">${esc(badge)}</span>` : ""}<h1>${esc(title)}</h1>
<p class="small">Generated ${esc(res.meta.generated)} by ${esc(res.meta.tool)} ${esc(res.meta.version)} (${esc(res.meta.engine)}). Schemas checked: ${esc(res.meta.schemas.join(", "))}. Loaded ${res.load.ok} of ${res.load.total} SQL statements.</p>
<h2>Verdict</h2><div class="box"><b>${esc(v.text)}</b> ${esc(v.detail)}</div>
<table><tr><th>Severity</th><th>Count</th></tr>${SEVERITIES.map((s) => `<tr><td class="${s}">${s}</td><td>${res.counts[s]}</td></tr>`).join("")}</table>
${ba}<h2>Findings</h2>${fl || "<p>No findings.</p>"}
<h2>Proof: executed access tests</h2><p class="small">Each test ran as the stated role against seeded rows of two synthetic users (A and B), inside a transaction that was rolled back.</p>
${probeRows ? `<table><tr><th>Table</th><th>Test</th><th>Role</th><th>Expected</th><th>Observed</th><th>Result</th></tr>${probeRows}</table>` : "<p>No access tests ran.</p>"}
${res.proof.skipped.length ? `<p class="small">Skipped (could not seed test rows): ${res.proof.skipped.map((s) => `<code>${esc(s.table)}</code> (${esc(s.reason)})`).join("; ")}</p>` : ""}
${fixBlock}<h2>What was and was not checked</h2><ul>${LIMITS.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></body></html>`;
}
