// Shared test helpers (not a test file: it is not listed in the npm test script).
import { readFileSync, readdirSync, existsSync, mkdirSync, mkdtempSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { audit } from "../src/audit.js";

export const here = dirname(fileURLToPath(import.meta.url));
export const root = join(here, "..");
export const cliPath = join(root, "bin", "cli.mjs");
export const ciPath = join(root, "bin", "ci.mjs");
export const fixtureDir = (name) => join(here, "fixtures", name);

// Fixture folder -> [{ name, text }]; withPaths adds the repository-relative path the CLI would pass.
export function fixture(dir, { withPaths = false } = {}) {
  return readdirSync(join(here, "fixtures", dir)).sort().map((f) => ({
    name: f,
    text: readFileSync(join(here, "fixtures", dir, f), "utf8"),
    ...(withPaths ? { path: `test/fixtures/${dir}/${f}` } : {}),
  }));
}

const cache = new Map();
// One audit per fixture and options per test file (each audit boots a Postgres, about 1-3 seconds).
export function auditFixture(dir, opts = {}, { withPaths = false } = {}) {
  const key = `${dir}|${withPaths}|${JSON.stringify(opts)}`;
  if (!cache.has(key)) cache.set(key, audit(fixture(dir, { withPaths }), opts));
  return cache.get(key);
}

export const lineOf = (text, needle, from = 1) => {
  const lines = text.split("\n");
  for (let i = from - 1; i < lines.length; i++) if (lines[i].includes(needle)) return i + 1;
  throw new Error(`"${needle}" not found from line ${from}`);
};

// First line at or after `from` whose trimmed text equals `exact` (the closing line of a multi-line statement).
export const closingLine = (text, from, exact = ");") => {
  const lines = text.split("\n");
  for (let i = from - 1; i < lines.length; i++) if (lines[i].trim() === exact) return i + 1;
  throw new Error(`no line "${exact}" after ${from}`);
};

// Scratch folders are removed when the process ends.
const scratch = [];
process.on("exit", () => {
  for (const d of scratch) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});
export function tempDir(prefix = "rls-audit-test-") {
  const d = mkdtempSync(join(tmpdir(), prefix));
  scratch.push(d);
  return d;
}
// Writes { "relative/path.sql": "text" } below dir and returns dir.
export function writeTree(dir, files) {
  for (const [rel, text] of Object.entries(files)) {
    const p = join(dir, rel);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, text);
  }
  return dir;
}

// GITHUB_WORKSPACE etc. are blanked so a developer running the tests inside Actions does not change the expected paths.
const baseEnv = () => ({ ...process.env, GITHUB_WORKSPACE: "", GITHUB_OUTPUT: "", GITHUB_STEP_SUMMARY: "" });

export function runCli(args, { cwd = root, env = {}, timeout = 120000, nodeArgs = [] } = {}) {
  return spawnSync(process.execPath, [...nodeArgs, cliPath, ...args], { cwd, encoding: "utf8", timeout, env: { ...baseEnv(), ...env } });
}

// Same as runCli but does not block the event loop, so several end-to-end cases can run side by side.
function spawnOnce(script, args, { cwd = root, env = {}, timeout = 120000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [script, ...args], { cwd, env: { ...baseEnv(), ...env }, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (d) => { stdout += d; });
    child.stderr.setEncoding("utf8").on("data", (d) => { stderr += d; });
    const timer = setTimeout(() => { child.kill(); reject(new Error(`timed out after ${timeout} ms: ${script} ${args.join(" ")}`)); }, timeout);
    child.on("error", (e) => { clearTimeout(timer); reject(e); });
    child.on("close", (status) => { clearTimeout(timer); resolve({ status, stdout, stderr }); });
  });
}
// Windows occasionally refuses to create the stdio pipes of a child process (ENOTCONN, EAGAIN, ...) when the whole suite is
// starting dozens of processes at once. That happens before the child exists, so retrying cannot run anything twice.
const TRANSIENT_SPAWN_ERRORS = new Set(["ENOTCONN", "EAGAIN", "EMFILE", "EBUSY", "EPERM"]);
export async function runScript(script, args, opts) {
  for (let attempt = 1; ; attempt++) {
    try {
      return await spawnOnce(script, args, opts);
    } catch (e) {
      if (attempt >= 4 || !TRANSIENT_SPAWN_ERRORS.has(e.code)) throw e;
      await new Promise((r) => setTimeout(r, 250 * attempt));
    }
  }
}
export const runCliAsync = (args, opts) => runScript(cliPath, args, opts);
export const runCiAsync = (env, opts = {}) => runScript(ciPath, [], { ...opts, env });

// ---- SARIF schema validation ----------------------------------------------------------------------------------------
// The official OASIS schema is fetched once over HTTPS, checked against a pinned SHA-256 and cached under node_modules/.cache.
// Offline, or if the file or the dev-only validator (ajv) is unavailable, the schema test is SKIPPED with the reason, never failed.
// RLS_SARIF_SCHEMA can point at a local copy of sarif-schema-2.1.0.json for fully offline runs.
const SCHEMA_URL = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json";
const SCHEMA_SHA256 = "c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e";
const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");

async function schemaText() {
  if (process.env.RLS_SARIF_SCHEMA) return readFileSync(process.env.RLS_SARIF_SCHEMA, "utf8");
  const cacheFile = join(root, "node_modules", ".cache", "rls-probe", "sarif-schema-2.1.0.json");
  if (existsSync(cacheFile)) {
    const buf = readFileSync(cacheFile);
    if (sha256(buf) === SCHEMA_SHA256) return buf.toString("utf8");
  }
  // A few attempts: a busy machine (the whole suite runs in parallel) occasionally fails a single request.
  let buf;
  let lastError;
  for (let attempt = 1; attempt <= 3 && !buf; attempt++) {
    try {
      const res = await fetch(SCHEMA_URL, { signal: AbortSignal.timeout(20000) });
      if (!res.ok) throw new Error(`HTTP ${res.status} from ${SCHEMA_URL}`);
      buf = Buffer.from(await res.arrayBuffer());
    } catch (e) {
      lastError = e;
      await new Promise((r) => setTimeout(r, 1000 * attempt));
    }
  }
  if (!buf) throw lastError;
  if (sha256(buf) !== SCHEMA_SHA256) throw new Error("the downloaded schema differs from the pinned copy (sha256 mismatch)");
  try {
    mkdirSync(dirname(cacheFile), { recursive: true });
    const tmp = `${cacheFile}.${process.pid}.tmp`;
    writeFileSync(tmp, buf);
    renameSync(tmp, cacheFile); // two test files may fetch at the same time: never leave a half-written cache file
  } catch { /* the cache is optional */ }
  return buf.toString("utf8");
}

let validatorPromise;
// Resolves { validate(log) -> string[] (empty = valid) } or { skip: "reason" }.
export function sarifValidator() {
  validatorPromise ||= (async () => {
    try {
      const text = await schemaText();
      const { default: Ajv } = await import("ajv-draft-04"); // the official schema is JSON Schema draft-04
      const { default: addFormats } = await import("ajv-formats");
      const ajv = new Ajv({ strict: false, allErrors: true });
      addFormats(ajv);
      const check = ajv.compile(JSON.parse(text));
      return { validate: (log) => (check(log) ? [] : check.errors.map((e) => `${e.instancePath || "/"} ${e.message}`)) };
    } catch (e) {
      return { skip: `SARIF schema validation skipped: ${e.message}` };
    }
  })();
  return validatorPromise;
}

// Optional YAML parser (dev dependency) for the action and workflow files.
export async function yamlParser() {
  try {
    const { parse } = await import("yaml");
    return { parse };
  } catch (e) {
    return { skip: `yaml not installed: ${e.message}` };
  }
}
