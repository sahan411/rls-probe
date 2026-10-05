import { join } from "node:path";
import { tmpdir } from "node:os";

// Logic behind the composite GitHub Action (action.yml -> bin/ci.mjs): turns the action's inputs into a CLI command line, and the
// CLI's JSON result into step outputs. Kept in its own module so it is unit-tested without a GitHub runner.
//
// Inputs arrive as environment variables set by action.yml (RLS_PATH, RLS_FAIL_ON, ...). They are never pasted into a shell
// script: the CLI is started with an argument array, so an input can not inject shell syntax.

export class CiInputError extends Error {
  constructor(message) { super(message); this.name = "CiInputError"; }
}

export const FILES = { json: "report.json", summary: "summary.md", sarif: "results.sarif" };
export const DEFAULTS = { path: "supabase/migrations", failOn: "high", schemas: "public", defaultGrants: "on", sarif: "false", timeout: "60" };

const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;

function pick(env, key, fallback) {
  const v = env[key];
  return v === undefined || String(v).trim() === "" ? fallback : String(v).trim();
}

export function parseInputs(env) {
  const paths = String(env.RLS_PATH ?? "").split(/\r?\n/).map((p) => p.trim()).filter(Boolean);
  if (!paths.length) paths.push(DEFAULTS.path);
  for (const p of paths) {
    if (p.startsWith("-")) throw new CiInputError(`input "path" must not start with "-" (got "${p}")`);
  }

  const failOn = pick(env, "RLS_FAIL_ON", DEFAULTS.failOn).toLowerCase();
  if (!["high", "medium", "never"].includes(failOn)) throw new CiInputError(`input "fail-on" must be high, medium or never (got "${failOn}")`);

  const schemas = pick(env, "RLS_SCHEMAS", DEFAULTS.schemas).split(",").map((s) => s.trim()).filter(Boolean);
  if (!schemas.length || schemas.some((s) => !IDENT.test(s))) throw new CiInputError(`input "schemas" must be a comma-separated list of schema names (got "${env.RLS_SCHEMAS}")`);

  const defaultGrants = pick(env, "RLS_DEFAULT_GRANTS", DEFAULTS.defaultGrants).toLowerCase();
  if (defaultGrants !== "on" && defaultGrants !== "off") throw new CiInputError(`input "default-grants" must be on or off (got "${defaultGrants}")`);

  const sarifRaw = pick(env, "RLS_SARIF", DEFAULTS.sarif).toLowerCase();
  if (sarifRaw !== "true" && sarifRaw !== "false") throw new CiInputError(`input "sarif" must be true or false (got "${sarifRaw}")`);

  const timeout = Number(pick(env, "RLS_TIMEOUT", DEFAULTS.timeout));
  if (!Number.isFinite(timeout) || timeout <= 0) throw new CiInputError(`input "timeout" must be a positive number of seconds (got "${env.RLS_TIMEOUT}")`);

  const outDir = pick(env, "RLS_OUT_DIR", join(env.RUNNER_TEMP || tmpdir(), "rls-probe"));
  return { paths, failOn, schemas, defaultGrants, sarif: sarifRaw === "true", timeout, outDir };
}

export function outputFiles(outDir) {
  return { json: join(outDir, FILES.json), summary: join(outDir, FILES.summary), sarif: join(outDir, FILES.sarif) };
}

// The exact argument vector passed to bin/cli.mjs.
export function buildArgs(inputs) {
  const f = outputFiles(inputs.outDir);
  return [
    ...inputs.paths,
    "--fail-on", inputs.failOn,
    "--schemas", inputs.schemas.join(","),
    "--default-grants", inputs.defaultGrants,
    "--timeout", String(inputs.timeout),
    "--format", "github",
    "--json", f.json,
    "--summary-file", f.summary,
    ...(inputs.sarif ? ["--sarif", f.sarif] : []),
  ];
}

// Step outputs from the CLI's --json result. Only integers and a generated path: nothing from the audited SQL reaches
// $GITHUB_OUTPUT.
export function outputsFrom(result, inputs, { sarifWritten = false } = {}) {
  const int = (n) => String(Number.isInteger(n) ? n : 0);
  return {
    critical: int(result.counts?.CRITICAL),
    high: int(result.counts?.HIGH),
    medium: int(result.counts?.MEDIUM),
    "failing-tests": int(result.proof?.failures),
    ...(inputs.sarif && sarifWritten ? { "sarif-file": outputFiles(inputs.outDir).sarif } : {}),
  };
}

// name=value lines in the format of $GITHUB_OUTPUT. A value that could span lines is refused instead of escaped.
export function formatOutputs(outputs) {
  return Object.entries(outputs).map(([name, value]) => {
    if (!/^[a-z][a-z0-9-]*$/.test(name)) throw new Error(`invalid output name: ${name}`);
    if (/[\r\n]/.test(String(value))) throw new Error(`output ${name} must be a single line`);
    return `${name}=${value}\n`;
  }).join("");
}
