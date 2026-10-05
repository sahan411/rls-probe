import { createHash } from "node:crypto";
import { SEVERITIES } from "./checks.js";
import { sentence } from "./text.js";

// SARIF 2.1.0 output (OASIS standard; the format GitHub code scanning ingests).
//  * level: CRITICAL and HIGH -> error, MEDIUM -> warning, LOW and INFO -> note
//  * logicalLocations always name the database object; physicalLocation (file + lines) only when the finding has a verified
//    source location (see src/locations.js). GitHub code scanning only displays results that have a file location.
//  * No `security-severity` is emitted: GitHub reads it per RULE, but one rule here spans several severities (for example
//    RLS-DISABLED is CRITICAL or HIGH), so a rule-level score would mislabel some alerts. Each result carries its own level, its own
//    severity in properties.severity and the severity word at the start of its message.

const SCHEMA_URL = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json";
const INFORMATION_URI = "https://github.com/sahan411/rls-probe";
const LINT_BASE = "https://supabase.com/docs/guides/database/database-linter";

const MAX_RESULT_LOCATIONS = 10;
const RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));
export const sarifLevel = (severity) => (RANK[severity] <= RANK.HIGH ? "error" : severity === "MEDIUM" ? "warning" : "note");

// Per-rule metadata for the SARIF `rules` array (only rules that fired are written out).
const RULES = {
  "RLS-DISABLED": ["RlsDisabled", "Table open to the API with Row Level Security off", "A table in an exposed schema is readable or writable through the API roles (anon / authenticated) and Row Level Security is not enabled, so nothing restricts which rows they reach.", "Enable RLS and add policies that scope rows to their owner (or to the intended audience).", "error", "high"],
  "POLICY-NO-RLS": ["PolicyWithoutRls", "Policies exist but Row Level Security is disabled", "Policies are defined on a table whose Row Level Security is switched off, so they are ignored.", "Run `alter table ... enable row level security;`.", "error", "high"],
  "RLS-NO-POLICY": ["RlsEnabledNoPolicy", "RLS enabled but no policy", "Row Level Security is on and no policy exists: the API returns no rows. Safe, but confirm the application expects it.", "Add the policies the application needs, if any.", "note", "high"],
  "POLICY-ALWAYS-TRUE": ["PermissivePolicy", "Policy that is always true", "A policy condition is the literal `true`, so it grants access without any check. Public read can be intended; public write rarely is.", "Replace the condition with an ownership or role check, for example `(select auth.uid()) = user_id`.", "warning", "high"],
  "USER-METADATA-POLICY": ["PolicyTrustsUserMetadata", "Policy trusts user_metadata", "user_metadata can be edited by the signed-in user, so a policy that grants access from it can be bypassed.", "Use app_metadata (server-controlled) or a roles table.", "error", "high"],
  "POLICY-NO-IDENTITY": ["PolicyIgnoresCaller", "Write policy that ignores who is asking", "A write policy tests row data only and never the signed-in user, so it applies equally to everyone it is granted to.", "Bind the condition to the caller, for example `(select auth.uid()) = user_id`.", "warning", "medium"],
  "AUTH-USERS-EXPOSED": ["AuthUsersExposed", "View exposes auth.users", "A view in an exposed schema reads auth.users with its owner's rights, bypassing every protection on it.", "Set `security_invoker = on` or drop the view and expose only the needed columns through a table with RLS.", "error", "high"],
  "VIEW-DEFINER": ["SecurityDefinerView", "View ignores RLS of its source tables", "Postgres views run with their owner's rights by default, so queries through the view skip Row Level Security.", "`alter view ... set (security_invoker = on);`", "warning", "high"],
  "MATVIEW-IN-API": ["MaterializedViewInApi", "Materialized view reachable through the API", "Materialized views cannot carry Row Level Security and are readable by the API roles.", "Revoke access from anon and authenticated and read it through a function or a table with RLS.", "warning", "high"],
  "DEFINER-FUNCTION": ["SecurityDefinerFunction", "SECURITY DEFINER function", "The function runs with its owner's rights; without a fixed search_path a caller can shadow objects, and a callable one is an RPC endpoint that must check permissions itself.", "Set `search_path` on the function and revoke execute from roles that should not call it.", "warning", "high"],
  "FUNC-SEARCH-PATH": ["FunctionSearchPathMutable", "Function without a fixed search_path", "Hygiene issue: functions callable through the API without `set search_path`.", "Add `set search_path = public` (or '') to each function.", "note", "high"],
  "STORAGE-BROAD-WRITE": ["StorageBroadWrite", "Storage write policy not tied to a user", "A storage.objects policy lets anonymous or signed-in users write files without tying them to a user or folder.", "Add an owner or folder check, for example `(storage.foldername(name))[1] = (select auth.uid())::text`.", "warning", "medium"],
  "STORAGE-BROAD-READ": ["StorageBroadRead", "Storage policy lets anyone list files", "A broad SELECT policy on storage.objects lets clients enumerate file names.", "Remove the policy unless listing is required; public buckets serve files by URL without it.", "note", "medium"],
  "AUTH-INITPLAN": ["AuthRlsInitplan", "auth.uid() evaluated per row", "Policies that call auth.uid() or auth.jwt() directly run the call once per row instead of once per query.", "Wrap the calls: `(select auth.uid())`.", "note", "high"],
  "PUBLIC-BUCKET": ["PublicBucket", "Public storage bucket", "Files in public buckets are readable by anyone who knows or guesses the URL, with no policy involved.", "Make sure nothing private is stored in a public bucket.", "note", "high"],
  "PROBE-FAILED": ["AccessTestFailed", "Executed access test failed", "An executed access test (as anon or as another user) reached rows it should not, even though no static rule fired.", "Read the table's policies against the failing test and correct the condition; re-run to confirm.", "error", "high"],
};

const toUri = (p) => p.split("/").map(encodeURIComponent).join("/");
const kindOf = (f) => (f.rule === "DEFINER-FUNCTION" || f.rule === "FUNC-SEARCH-PATH" ? "function" : "resource");

function logicalLocations(f) {
  const out = [];
  if (f.rule === "FUNC-SEARCH-PATH") {
    for (const fn of (f.evidence?.functions || []).slice(0, 20)) out.push({ name: fn, fullyQualifiedName: fn, kind: "function" });
    return out;
  }
  out.push({ name: f.object.split(".").pop(), fullyQualifiedName: f.object, kind: kindOf(f) });
  const policy = f.evidence?.policy;
  if (policy) out.push({ name: policy, fullyQualifiedName: `${f.object}.${policy}`, kind: "member" });
  return out;
}

function ruleEntry(id, firstFinding) {
  const m = RULES[id];
  const lint = firstFinding.lint;
  const helpUri = /^\d{4}_/.test(lint || "") ? `${LINT_BASE}?lint=${lint}` : /^\d{4}\//.test(lint || "") ? LINT_BASE : undefined;
  const [name, short, full, help, level, precision] = m || [id.replace(/[^A-Za-z0-9]/g, ""), firstFinding.title, firstFinding.why, firstFinding.fix, "warning", "medium"];
  return {
    id,
    name,
    shortDescription: { text: short },
    fullDescription: { text: full },
    help: { text: `${full} ${help}`, markdown: `${full}\n\n**Fix:** ${help}${helpUri ? `\n\n[Supabase database linter reference](${helpUri})` : ""}` },
    ...(helpUri ? { helpUri } : {}),
    defaultConfiguration: { level },
    properties: { tags: ["security", "supabase", "row-level-security", "postgres"], precision },
  };
}

function resultFor(f, ruleIndex) {
  const logical = logicalLocations(f);
  // GitHub reads at most 10 locations per result (and shows only the first), so more would only be dead weight.
  const physical = (f.locations || []).filter((l) => l.file && Number.isInteger(l.line) && l.line > 0).slice(0, MAX_RESULT_LOCATIONS);
  const locations = physical.length
    ? physical.map((l) => ({
      physicalLocation: {
        artifactLocation: { uri: toUri(l.file) },
        region: { startLine: l.line, ...(Number.isInteger(l.endLine) && l.endLine > l.line ? { endLine: l.endLine } : {}) },
      },
      logicalLocations: logical,
    }))
    : [{ logicalLocations: logical }];
  return {
    ruleId: f.rule,
    ruleIndex,
    level: sarifLevel(f.severity),
    message: { text: `[${f.severity}] ${sentence(f.title)} ${sentence(f.why)} Fix: ${f.fix}` },
    locations,
    // stable across line moves: identifies the same problem in the same object between runs
    fingerprints: { "rls-probe/v1": createHash("sha256").update([f.rule, f.object, f.evidence?.policy ?? ""].join("\u0000")).digest("hex") },
    properties: { severity: f.severity, object: f.object, ...(f.evidence?.policy ? { policy: f.evidence.policy } : {}) },
  };
}

export function toSarif(res) {
  const rules = [];
  const index = new Map();
  for (const f of res.findings) {
    if (!index.has(f.rule)) { index.set(f.rule, rules.length); rules.push(ruleEntry(f.rule, f)); }
  }
  return {
    $schema: SCHEMA_URL,
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: res.meta.tool, version: res.meta.version, semanticVersion: res.meta.version, informationUri: INFORMATION_URI, rules } },
      results: res.findings.map((f) => resultFor(f, index.get(f.rule))),
    }],
  };
}
