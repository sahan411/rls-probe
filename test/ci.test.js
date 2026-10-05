import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { CiInputError, DEFAULTS, FILES, buildArgs, formatOutputs, outputFiles, outputsFrom, parseInputs } from "../src/ci.js";
import { auditFixture, root, runCiAsync, tempDir, writeTree, yamlParser } from "./helpers.js";

const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const fwd = (p) => p.replace(/\\/g, "/");

// ---- src/ci.js: inputs -> command line -> outputs ---------------------------------------------------------------------

test("parseInputs: documented defaults, trimming, case-insensitive switches, one path per line", () => {
  const d = parseInputs({});
  assert.deepEqual(d, { paths: ["supabase/migrations"], failOn: "high", schemas: ["public"], defaultGrants: "on", sarif: false, timeout: 60, outDir: join(tmpdir(), "rls-probe") });
  assert.equal(parseInputs({ RUNNER_TEMP: "/runner/tmp" }).outDir, join("/runner/tmp", "rls-probe"));
  const blank = parseInputs({ RLS_PATH: "  ", RLS_FAIL_ON: "", RLS_SCHEMAS: " ", RLS_DEFAULT_GRANTS: "\n", RLS_SARIF: "", RLS_TIMEOUT: "  " });
  assert.deepEqual({ ...blank, outDir: undefined }, { ...d, outDir: undefined }, "blank input means default");
  const p = parseInputs({ RLS_PATH: "a\r\n\r\n  b/c  \nd.sql\n", RLS_FAIL_ON: " Medium ", RLS_SCHEMAS: "public, api ,,x_1", RLS_DEFAULT_GRANTS: "OFF", RLS_SARIF: "TRUE", RLS_TIMEOUT: "1e2" });
  assert.deepEqual({ ...p, outDir: undefined }, { paths: ["a", "b/c", "d.sql"], failOn: "medium", schemas: ["public", "api", "x_1"], defaultGrants: "off", sarif: true, timeout: 100, outDir: undefined });
  assert.equal(parseInputs({ RLS_TIMEOUT: "1.5" }).timeout, 1.5);
});

test("parseInputs: every invalid input is rejected with a message that names it (no shell syntax, no option smuggling)", () => {
  const bad = [
    [{ RLS_PATH: "--help" }, /input "path"/],
    [{ RLS_PATH: "ok\n-rf" }, /input "path"/],
    [{ RLS_PATH: "-" }, /input "path"/],
    [{ RLS_FAIL_ON: "low" }, /input "fail-on"/],
    [{ RLS_FAIL_ON: "high; rm -rf /" }, /input "fail-on"/],
    [{ RLS_SCHEMAS: "public;drop" }, /input "schemas"/],
    [{ RLS_SCHEMAS: "1abc" }, /input "schemas"/],
    [{ RLS_SCHEMAS: 'a"b' }, /input "schemas"/],
    [{ RLS_SCHEMAS: "a b" }, /input "schemas"/],
    [{ RLS_SCHEMAS: ",," }, /input "schemas"/],
    [{ RLS_DEFAULT_GRANTS: "yes" }, /input "default-grants"/],
    [{ RLS_SARIF: "1" }, /input "sarif"/],
    [{ RLS_SARIF: "yes" }, /input "sarif"/],
    [{ RLS_TIMEOUT: "0" }, /input "timeout"/],
    [{ RLS_TIMEOUT: "-5" }, /input "timeout"/],
    [{ RLS_TIMEOUT: "abc" }, /input "timeout"/],
    [{ RLS_TIMEOUT: "Infinity" }, /input "timeout"/],
  ];
  for (const [env, re] of bad) assert.throws(() => parseInputs(env), (e) => e instanceof CiInputError && re.test(e.message), JSON.stringify(env));
});

test("buildArgs: exact argument vector, paths stay single arguments and come first", () => {
  const inputs = parseInputs({ RLS_PATH: "supabase/migrations\ndb/extra file.sql", RLS_FAIL_ON: "medium", RLS_SCHEMAS: "public,api", RLS_DEFAULT_GRANTS: "off", RLS_SARIF: "true", RLS_TIMEOUT: "90", RUNNER_TEMP: "/rt" });
  const f = outputFiles(inputs.outDir);
  assert.deepEqual(buildArgs(inputs), [
    "supabase/migrations", "db/extra file.sql",
    "--fail-on", "medium", "--schemas", "public,api", "--default-grants", "off", "--timeout", "90", "--format", "github",
    "--json", f.json, "--summary-file", f.summary, "--sarif", f.sarif,
  ]);
  assert.deepEqual(f, { json: join("/rt", "rls-probe", FILES.json), summary: join("/rt", "rls-probe", FILES.summary), sarif: join("/rt", "rls-probe", FILES.sarif) });
  const hostile = parseInputs({ RLS_PATH: "a b; $(touch x) `id` 'q' && echo" });
  assert.deepEqual(buildArgs(hostile).slice(0, 1), ["a b; $(touch x) `id` 'q' && echo"]);
  assert.ok(!buildArgs(parseInputs({})).includes("--sarif"), "no SARIF unless asked");
});

test("outputsFrom / formatOutputs: only integers and a generated path ever reach $GITHUB_OUTPUT", () => {
  const inputs = parseInputs({ RLS_SARIF: "true", RUNNER_TEMP: "/rt" });
  assert.deepEqual(outputsFrom({ counts: { CRITICAL: 2, HIGH: 5, MEDIUM: 1 }, proof: { failures: 9 } }, inputs, { sarifWritten: true }), {
    critical: "2", high: "5", medium: "1", "failing-tests": "9", "sarif-file": join("/rt", "rls-probe", FILES.sarif),
  });
  assert.deepEqual(Object.keys(outputsFrom({}, inputs, { sarifWritten: false })), ["critical", "high", "medium", "failing-tests"], "no sarif-file when none was written");
  assert.ok(!("sarif-file" in outputsFrom({}, parseInputs({}), { sarifWritten: true })), "no sarif-file when the input was off");
  const nasty = outputsFrom({ counts: { CRITICAL: "1\nevil=1", HIGH: 2.5, MEDIUM: null }, proof: { failures: "7" } }, parseInputs({}));
  assert.deepEqual(nasty, { critical: "0", high: "0", medium: "0", "failing-tests": "0" }, "anything that is not an integer becomes 0");
  assert.equal(formatOutputs({ critical: "1", "failing-tests": "2" }), "critical=1\nfailing-tests=2\n");
  assert.throws(() => formatOutputs({ Critical: "1" }), /invalid output name/);
  assert.throws(() => formatOutputs({ "a b": "1" }), /invalid output name/);
  assert.throws(() => formatOutputs({ a: "1\nb=2" }), /single line/);
  assert.throws(() => formatOutputs({ a: "1\r" }), /single line/);
});

// ---- action.yml and the example workflows -----------------------------------------------------------------------------

const SHA_PIN = /@[0-9a-f]{40}(\s|$)/;
const usesLines = (text) => text.split(/\r?\n/).filter((l) => /^\s*-?\s*uses:/.test(l));

test("action.yml: composite, no secrets, pinned third-party actions, inputs only reach the script through env vars", async (t) => {
  const y = await yamlParser();
  if (y.skip) return t.skip(y.skip);
  const text = readFileSync(join(root, "action.yml"), "utf8");
  const action = y.parse(text);
  assert.equal(action.runs.using, "composite");

  assert.deepEqual(Object.keys(action.inputs).sort(), ["default-grants", "fail-on", "path", "sarif", "schemas", "timeout"]);
  assert.deepEqual(
    Object.fromEntries(Object.entries(action.inputs).map(([k, v]) => [k, String(v.default)])),
    { path: DEFAULTS.path, "fail-on": DEFAULTS.failOn, schemas: DEFAULTS.schemas, "default-grants": DEFAULTS.defaultGrants, sarif: DEFAULTS.sarif, timeout: DEFAULTS.timeout },
    "action defaults and src/ci.js defaults are the same",
  );
  for (const [name, input] of Object.entries(action.inputs)) assert.equal(input.required, false, `input ${name} must be optional`);

  // every step that runs code uses bash (composite requirement) and contains no expression: inputs travel as env vars only
  const steps = action.runs.steps;
  for (const s of steps.filter((x) => x.run)) {
    assert.equal(s.shell, "bash");
    assert.ok(!s.run.includes("${{"), `step "${s.name}" interpolates an expression into a script`);
  }
  const audit = steps.find((s) => s.id === "audit");
  const wanted = { RLS_PATH: "path", RLS_FAIL_ON: "fail-on", RLS_SCHEMAS: "schemas", RLS_DEFAULT_GRANTS: "default-grants", RLS_SARIF: "sarif", RLS_TIMEOUT: "timeout" };
  assert.deepEqual(audit.env, Object.fromEntries(Object.entries(wanted).map(([k, v]) => [k, `\${{ inputs.${v} }}`])));
  assert.equal(audit.run, 'node "$GITHUB_ACTION_PATH/bin/ci.mjs"');
  const ciSource = readFileSync(join(root, "src", "ci.js"), "utf8");
  const read = new Set([...ciSource.matchAll(/RLS_[A-Z_]+/g)].map((m) => m[0]));
  read.delete("RLS_OUT_DIR"); // internal (tests); the action never sets it
  assert.deepEqual([...read].sort(), Object.keys(wanted).sort(), "ci.js reads exactly the variables the action sets");

  // outputs: declared names are exactly the ones bin/ci.mjs writes, each wired to the audit step
  const written = Object.keys(outputsFrom({}, parseInputs({ RLS_SARIF: "true" }), { sarifWritten: true })).sort();
  assert.deepEqual(Object.keys(action.outputs).sort(), written);
  for (const [name, o] of Object.entries(action.outputs)) assert.equal(o.value, `\${{ steps.audit.outputs.${name} }}`);

  // the job summary is appended even when the audit step failed, from the file ci.mjs writes, using only runner-provided env
  const summary = steps.find((s) => s.run && s.run.includes("GITHUB_STEP_SUMMARY"));
  assert.equal(summary.if, "always()");
  assert.ok(summary.run.includes(`$RUNNER_TEMP/rls-probe/${FILES.summary}`));

  // install: lockfile, no dev dependencies, no lifecycle scripts
  const install = steps.find((s) => s.run && s.run.includes("npm ci"));
  assert.match(install.run, /npm ci\b.*--omit=dev.*--ignore-scripts/);
  assert.ok(existsSync(join(root, "package-lock.json")));

  // supply chain and secrets
  for (const l of usesLines(text)) assert.match(l, SHA_PIN, `third-party action not pinned to a full commit SHA: ${l.trim()}`);
  assert.ok(usesLines(text).length >= 1);
  assert.ok(!/secrets\.[A-Za-z_*]|github\.token|GITHUB_TOKEN|\bcurl\b|\bwget\b|https?:\/\/(?!github\.com\/sahan411)/.test(text.replace(/^\s*#.*$/gm, "")), "the action needs no secret and makes no network calls of its own");
  assert.ok(!/pull_request_target/.test(text));
});

for (const file of ["github-workflow.yml", "github-workflow-sarif.yml"]) {
  test(`examples/${file}: least privilege, pull_request only, pinned actions, inputs the action really has`, async (t) => {
    const y = await yamlParser();
    if (y.skip) return t.skip(y.skip);
    const text = readFileSync(join(root, "examples", file), "utf8");
    const wf = y.parse(text);
    assert.deepEqual(Object.keys(wf.on), ["pull_request"], "runs on pull_request, never on pull_request_target");
    assert.deepEqual(wf.permissions, { contents: "read" });
    const action = y.parse(readFileSync(join(root, "action.yml"), "utf8"));
    const job = Object.values(wf.jobs)[0];
    assert.ok(job["timeout-minutes"] > 0);
    assert.ok(!/secrets\.[A-Za-z_*]/.test(text.replace(/^\s*#.*$/gm, "")));
    for (const l of usesLines(text)) {
      if (l.includes("sahan411/rls-probe@")) assert.match(l, new RegExp(`@v${pkg.version.replace(/\./g, "\\.")}\\s*$`), "the example names the released version");
      else assert.match(l, SHA_PIN, l.trim());
    }
    const checkout = job.steps.find((s) => s.uses?.startsWith("actions/checkout@"));
    assert.equal(checkout.with["persist-credentials"], false);
    const ours = job.steps.find((s) => s.uses?.startsWith("sahan411/rls-probe@"));
    for (const k of Object.keys(ours.with)) assert.ok(k in action.inputs, `unknown input ${k}`);
    assert.ok(["high", "medium", "never"].includes(ours.with["fail-on"]));

    if (file.includes("sarif")) {
      assert.equal(ours.with.sarif, "true");
      assert.equal(job.permissions["security-events"], "write");
      assert.equal(job.permissions.contents, "read");
      const upload = job.steps.find((s) => s.uses?.startsWith("github/codeql-action/upload-sarif@"));
      assert.equal(upload.if, "always()", "results are uploaded even when the audit step fails on findings");
      const expected = fwd(outputFiles(parseInputs({ RUNNER_TEMP: "${{ runner.temp }}" }).outDir).sarif);
      assert.equal(fwd(upload.with.sarif_file), expected, "the upload reads the file bin/ci.mjs writes");
      assert.ok(upload.with.category);
    } else {
      assert.ok(!text.includes("security-events"));
    }
  });
}

// ---- bin/ci.mjs end to end ------------------------------------------------------------------------------------------------

const parseOutputs = (text) => Object.fromEntries(text.split("\n").filter(Boolean).map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1)]));

// Runs bin/ci.mjs the way the action does: inputs as RLS_* variables, RUNNER_TEMP and GITHUB_OUTPUT provided.
async function ci(env, { cwd = root, outputFile = true } = {}) {
  const runnerTemp = tempDir("rls-ci-temp-");
  const out = join(runnerTemp, "github_output");
  writeFileSync(out, "");
  const r = await runCiAsync({ RUNNER_TEMP: runnerTemp, ...(outputFile ? { GITHUB_OUTPUT: out } : {}), ...env }, { cwd });
  const dir = join(runnerTemp, "rls-probe");
  return { ...r, runnerTemp, dir, outputs: parseOutputs(readFileSync(out, "utf8")), file: (n) => join(dir, n) };
}
const rel = (name) => `test/fixtures/${name}`;

describe("bin/ci.mjs", { concurrency: 2 }, () => {
  test("findings at the fail-on level fail the step, after outputs, annotations, the summary and the SARIF file were written", async () => {
    const expected = (await auditFixture("vulnerable")).counts;
    const r = await ci({ RLS_PATH: rel("vulnerable"), RLS_SARIF: "true" });
    assert.equal(r.status, 2, r.stdout + r.stderr);
    assert.deepEqual(Object.keys(r.outputs), ["critical", "high", "medium", "failing-tests", "sarif-file"]);
    assert.deepEqual({ ...r.outputs, "failing-tests": undefined, "sarif-file": undefined }, { critical: String(expected.CRITICAL), high: String(expected.HIGH), medium: String(expected.MEDIUM), "failing-tests": undefined, "sarif-file": undefined });
    assert.ok(Number(r.outputs["failing-tests"]) > 0);
    assert.match(r.stdout, /^::error title=CRITICAL RLS-DISABLED public\.orders,file=test\/fixtures\/vulnerable\/001_schema\.sql,line=22,endLine=27::/m);
    assert.match(readFileSync(r.file(FILES.summary), "utf8"), /^## rls-probe: Row Level Security audit/);
    assert.ok(existsSync(r.file(FILES.json)));
    // sarif: true writes the log even though the audit failed, and reports its path
    assert.equal(r.outputs["sarif-file"], r.file(FILES.sarif));
    const log = JSON.parse(readFileSync(r.outputs["sarif-file"], "utf8"));
    assert.equal(log.version, "2.1.0");
    assert.ok(log.runs[0].results.length >= 10);
    assert.equal(log.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, "test/fixtures/vulnerable/001_schema.sql");
  });

  test("fail-on thresholds: a MEDIUM-only schema passes at high, fails at medium, and warns both times; no SARIF unless asked (never: see cli.test.js)", async () => {
    const high = await ci({ RLS_PATH: rel("medium-only"), RLS_FAIL_ON: "high" });
    assert.equal(high.status, 0, high.stdout + high.stderr);
    assert.deepEqual(high.outputs, { critical: "0", high: "0", medium: "1", "failing-tests": "0" }, "no sarif-file output unless sarif is true");
    assert.ok(!existsSync(high.file(FILES.sarif)));
    assert.match(high.stdout, /^::warning title=MEDIUM POLICY-NO-IDENTITY public\.docs,file=test\/fixtures\/medium-only\/001_docs\.sql,line=9::/m);
    assert.ok(!/^::error/m.test(high.stdout));
    const medium = await ci({ RLS_PATH: rel("medium-only"), RLS_FAIL_ON: "medium" });
    assert.equal(medium.status, 2, medium.stdout + medium.stderr);
    assert.equal(medium.outputs.medium, "1");
    assert.match(medium.stdout, /^::warning title=MEDIUM/m);
  });

  test("a clean schema exits 0 with zero counts and a summary; without GITHUB_OUTPUT (local run) the outputs are printed instead", async () => {
    const r = await ci({ RLS_PATH: rel("fixed") }, { outputFile: false });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /^critical=0\nhigh=0\nmedium=0\nfailing-tests=0$/m);
    assert.deepEqual(r.outputs, {});
    assert.match(readFileSync(r.file(FILES.summary), "utf8"), /No high-severity issue found/);
  });

  test("several paths, one per line; folder and file names with spaces, quotes, $ ; & stay literal", async () => {
    const ws = tempDir("rls-ci-ws-");
    const dirName = "my 'dir' $HOME; echo & more";
    writeTree(ws, {
      [`${dirName}/001.sql`]: "create table public.a (id uuid primary key, user_id uuid references auth.users(id));\n",
      "other.sql": "create table public.b (id uuid primary key, user_id uuid references auth.users(id));\n",
    });
    const r = await ci({ RLS_PATH: `${dirName}\nother.sql\n`, GITHUB_WORKSPACE: ws }, { cwd: ws });
    assert.equal(r.status, 2, r.stdout + r.stderr);
    assert.match(r.stdout, /file=my 'dir' \$HOME; echo & more\/001\.sql,line=1::/, "a one-line statement has no endLine");
    assert.match(r.stdout, /RLS-DISABLED public\.b,file=other\.sql,line=1/);
    assert.equal(r.outputs.high, "2");
  });

  test("shell syntax in an input is just a path that does not exist: nothing is executed", async () => {
    const ws = tempDir("rls-ci-ws-");
    const marker = join(ws, "PWNED");
    for (const evil of [`x; touch "${marker}"`, `$(touch "${marker}")`, "`touch " + marker + "`", `x && touch ${marker}`, `x | touch ${marker}`]) {
      const r = await ci({ RLS_PATH: evil }, { cwd: ws });
      assert.equal(r.status, 66, r.stdout + r.stderr);
      assert.match(r.stderr, /path not found/);
      assert.ok(!existsSync(marker), `executed: ${evil}`);
      assert.deepEqual(r.outputs, {});
    }
  });

  test("invalid inputs stop before any audit: exit 64 and one ::error annotation that names the input", async () => {
    for (const [env, name] of [
      [{ RLS_PATH: "--help" }, "path"],
      [{ RLS_FAIL_ON: "banana" }, "fail-on"],
      [{ RLS_SCHEMAS: "public;drop" }, "schemas"],
      [{ RLS_DEFAULT_GRANTS: "maybe" }, "default-grants"],
      [{ RLS_SARIF: "yes" }, "sarif"],
      [{ RLS_TIMEOUT: "abc" }, "timeout"],
    ]) {
      const r = await ci({ RLS_PATH: rel("fixed"), ...env });
      assert.equal(r.status, 64, r.stdout + r.stderr);
      assert.match(r.stdout, new RegExp(`^::error title=rls-probe::input "${name}"`));
      assert.equal(r.stdout.trim().split("\n").length, 1);
      assert.deepEqual(r.outputs, {});
      assert.ok(!existsSync(r.file(FILES.json)));
    }
    // a value that tries to forge a second command is escaped into the single annotation
    const forged = await ci({ RLS_FAIL_ON: "x\n::error::forged" });
    assert.equal(forged.status, 64);
    assert.equal(forged.stdout.trim().split("\n").length, 1, forged.stdout);
    assert.ok(forged.stdout.includes("%0A::error::forged"));
  });

  test("results of an earlier run are never reused: a failing run leaves no stale outputs behind", async () => {
    const runnerTemp = tempDir("rls-ci-temp-");
    const dir = join(runnerTemp, "rls-probe");
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, FILES.json), JSON.stringify({ counts: { CRITICAL: 99, HIGH: 99, MEDIUM: 99 }, proof: { failures: 99 } }));
    writeFileSync(join(dir, FILES.sarif), "{}");
    const out = join(runnerTemp, "github_output");
    writeFileSync(out, "");
    const r = await runCiAsync({ RUNNER_TEMP: runnerTemp, GITHUB_OUTPUT: out, RLS_PATH: "does/not/exist" });
    assert.equal(r.status, 66);
    assert.equal(readFileSync(out, "utf8"), "", "stale numbers were not published");
    assert.deepEqual(readdirSync(dir), []);
  });

  test("hostile policy and table names cannot inject workflow commands through the action", async () => {
    const r = await ci({ RLS_PATH: rel("injection"), RLS_FAIL_ON: "never" });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    const commands = r.stdout.split("\n").filter((l) => l.startsWith("::"));
    assert.ok(commands.length >= 3);
    assert.ok(commands.every((l) => /^::(error|warning) title=/.test(l)), commands.map((l) => l.slice(0, 40)).join("\n"));
    assert.ok(!r.stdout.includes("::add-mask::secret\n") && !/^::add-mask/m.test(r.stdout));
    assert.ok(!/^::error title=forged/m.test(r.stdout));
  });

  test("the audit timeout fails the step with exit 70 and publishes no outputs", async () => {
    const r = await ci({ RLS_PATH: rel("busy"), RLS_TIMEOUT: "2" });
    assert.equal(r.status, 70, r.stdout + r.stderr);
    assert.match(r.stderr, /did not finish within 2 second\(s\)/);
    assert.deepEqual(r.outputs, {});
  });
});
