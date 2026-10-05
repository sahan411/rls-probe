import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fixtureDir, root, runCliAsync, sarifValidator, tempDir, writeTree } from "./helpers.js";

const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
const fx = (name) => fixtureDir(name);

describe("bin/cli.mjs: exit codes", { concurrency: 2 }, () => {
  test("--help prints the usage and the exit-code table, exit 0", async () => {
    const r = await runCliAsync(["--help"]);
    assert.equal(r.status, 0);
    assert.match(r.stdout, /^rls-probe <file-or-folder\.\.\.> \[options\]/);
    assert.match(r.stdout, /Exit codes: 0 ok, 2 findings at the --fail-on level, 64 usage error, 66 no input, 70 timeout, 1 internal error\./);
    for (const flag of ["--out", "--html", "--json", "--sarif", "--summary-file", "--format", "--fix", "--fail-on", "--timeout", "--schemas", "--default-grants", "--no-probe"]) assert.ok(r.stdout.includes(flag), flag);
  });

  test("exit 2 when findings reach --fail-on (vulnerable), 0 when they do not (secured twin)", async () => {
    const [bad, good, never] = await Promise.all([
      runCliAsync([fx("vulnerable"), "--no-probe"]),
      runCliAsync([fx("fixed"), "--no-probe"]),
      runCliAsync([fx("vulnerable"), "--no-probe", "--fail-on", "never"]),
    ]);
    assert.equal(bad.status, 2, bad.stdout + bad.stderr);
    assert.match(bad.stdout, /findings: CRITICAL 3  HIGH 8/);
    assert.equal(good.status, 0, good.stdout + good.stderr);
    assert.equal(never.status, 0, never.stdout + never.stderr);
    assert.match(never.stdout, /findings: CRITICAL 3/, "never only changes the exit code");
  });

  test("--fail-on medium counts MEDIUM findings, --fail-on high does not", async () => {
    const [high, medium] = await Promise.all([
      runCliAsync([fx("medium-only"), "--no-probe", "--fail-on", "high"]),
      runCliAsync([fx("medium-only"), "--no-probe", "--fail-on", "medium"]),
    ]);
    assert.equal(high.status, 0, high.stdout + high.stderr);
    assert.match(high.stdout, /MEDIUM 1/);
    assert.equal(medium.status, 2, medium.stdout + medium.stderr);
  });

  test("exit 64 for every usage error, with the reason first and nothing on stdout", async () => {
    const cases = [
      [[fx("fixed"), "--bogus"], /unknown option --bogus/],
      [[fx("fixed"), "--out"], /option --out needs a value/],
      [[fx("fixed"), "--fail-on", "low"], /--fail-on expects high, medium or never/],
      [[fx("fixed"), "--format", "xml"], /--format expects text or github/],
      [[fx("fixed"), "--timeout", "0"], /--timeout expects a positive number/],
      [[fx("fixed"), "--timeout", "soon"], /--timeout expects a positive number/],
      [[fx("fixed"), "--schemas", "public;drop table x"], /--schemas expects/],
      [[fx("fixed"), "--default-grants", "maybe"], /--default-grants expects on or off/],
      [[], /rls-probe <file-or-folder/],
    ];
    const results = await Promise.all(cases.map(([args]) => runCliAsync(args)));
    for (const [i, r] of results.entries()) {
      assert.equal(r.status, 64, `${cases[i][0].join(" ")}: ${r.stdout}${r.stderr}`);
      assert.match(r.stderr, cases[i][1]);
      assert.equal(r.stdout, "");
    }
  });

  test("exit 66 when there is nothing to audit", async () => {
    const empty = tempDir();
    writeTree(empty, { "notes.txt": "not sql", "sub/readme.md": "x" });
    const [missing, none] = await Promise.all([runCliAsync([join(empty, "does-not-exist")]), runCliAsync([empty])]);
    assert.equal(missing.status, 66);
    assert.match(missing.stderr, /error: path not found: .*does-not-exist/);
    assert.equal(none.status, 66);
    assert.match(none.stderr, /No \.sql files found/);
  });

  test("exit 70 on timeout (details in data-safety.test.js); the error says how to raise the limit", async () => {
    const r = await runCliAsync([fx("busy"), "--timeout", "2"]);
    assert.equal(r.status, 70);
    assert.match(r.stderr, /re-run with --timeout <seconds>/);
    assert.equal(r.stdout, "");
  });

  test("exit 1 with a one-line error (no stack trace) when an output file cannot be written; findings were still printed", async () => {
    const dir = tempDir();
    writeTree(dir, { "plain-file": "x" });
    const r = await runCliAsync([fx("fixed"), "--no-probe", "--out", join(dir, "plain-file", "report.md")]);
    assert.equal(r.status, 1, r.stdout + r.stderr);
    assert.match(r.stdout, /^findings: CRITICAL 0/m);
    assert.match(r.stderr, /^error: /);
    assert.ok(!/\n\s+at /.test(r.stderr), "no stack trace");
    assert.equal(r.stderr.trim().split("\n").length, 1);
  });
});

describe("bin/cli.mjs: outputs", { concurrency: 2 }, () => {
  test("every output option writes its file (parent folders are created) and the files are consistent", async () => {
    const out = tempDir();
    const p = (n) => join(out, "nested", "dir", n);
    const r = await runCliAsync([fx("vulnerable"), "--out", p("r.md"), "--html", p("r.html"), "--json", p("r.json"), "--sarif", p("r.sarif"), "--summary-file", p("s.md"), "--fix", p("fix.sql"), "--title", "My title", "--badge", "My badge", "--fail-on", "never"]);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    const md = readFileSync(p("r.md"), "utf8");
    assert.match(md, /^# My title\n\n> \*\*My badge\*\*/);
    assert.match(md, /## Draft fix \(SQL\)/);
    assert.match(readFileSync(p("r.html"), "utf8"), /<title>My title<\/title>|<h1>My title<\/h1>/);
    const json = JSON.parse(readFileSync(p("r.json"), "utf8"));
    assert.equal(json.meta.version, pkg.version);
    assert.ok(!("_model" in json));
    assert.ok(json.after && json.after.counts.CRITICAL === 0, "--fix adds the after-fix numbers to the JSON");
    assert.ok(json.findings.some((f) => f.locations?.[0].file === "test/fixtures/vulnerable/001_schema.sql"), "JSON carries the locations");
    const sarif = JSON.parse(readFileSync(p("r.sarif"), "utf8"));
    assert.equal(sarif.runs[0].results.length, json.findings.length);
    assert.match(readFileSync(p("s.md"), "utf8"), /^## My title\n/, "--title also names the summary");
    assert.match(readFileSync(p("fix.sql"), "utf8"), /alter table/i);
    assert.match(r.stdout, /^after draft fix: CRITICAL 0/m);
    const v = await sarifValidator();
    if (!v.skip) assert.deepEqual(v.validate(sarif), [], "the file written by the CLI is valid SARIF 2.1.0");
  });

  test("--format text lists findings, --format github emits annotations; LOW findings are never annotated", async () => {
    const [text, gh] = await Promise.all([
      runCliAsync([fx("vulnerable"), "--no-probe", "--fail-on", "never"]),
      runCliAsync([fx("vulnerable"), "--no-probe", "--fail-on", "never", "--format", "github"]),
    ]);
    assert.match(text.stdout, /^  \[CRITICAL\] public\.orders: /m);
    assert.ok(!/^::/m.test(text.stdout));
    const cmds = gh.stdout.split("\n").filter((l) => l.startsWith("::"));
    assert.equal(cmds.length, 11, "3 critical + 8 high, no MEDIUM in this schema, LOW stays out");
    assert.ok(cmds.every((l) => l.startsWith("::error ")));
    assert.ok(!/^  \[/m.test(gh.stdout), "annotations replace the plain list");
  });

  test("--no-probe skips the executed tests but keeps the static findings and the exit code", async () => {
    const r = await runCliAsync([fx("vulnerable"), "--no-probe"]);
    assert.equal(r.status, 2);
    assert.match(r.stdout, /failing access tests: 0/);
  });

  test("the same file given twice (directly and through its folder) is audited once", async () => {
    const r = await runCliAsync([fx("fixed"), join(fx("fixed"), "001_schema.sql"), "--no-probe"]);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /statements loaded from 1 file\(s\)/);
  });

  test("row data of a pg_dump never reaches any output file or the console", async () => {
    const out = tempDir();
    const p = (n) => join(out, n);
    const r = await runCliAsync([fx("pgdump-data"), "--no-probe", "--out", p("r.md"), "--html", p("r.html"), "--json", p("r.json"), "--sarif", p("r.sarif"), "--summary-file", p("s.md"), "--fix", p("fix.sql"), "--format", "github", "--fail-on", "never"]);
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /4 data statement\(s\) skipped \(row data is ignored and never loaded\)/);
    const everything = [r.stdout, r.stderr, ...["r.md", "r.html", "r.json", "r.sarif", "s.md", "fix.sql"].map((n) => readFileSync(p(n), "utf8"))].join("\n");
    for (const secret of ["jane.doe@example.com", "bob.fake@example.com", "carol.fake@example.com", "DROP TABLE public.customers", "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333", "55555555-5555-4555-8555-555555555555", "it's \"quoted\"", "two\\ttabs"]) {
      assert.ok(!everything.includes(secret), `row data leaked: ${secret}`);
    }
    assert.ok(everything.includes("avatars"), "the one INSERT that is read (storage.buckets) still produces its finding");
  });
});

describe("bin/cli.mjs: file locations", { concurrency: 2 }, () => {
  test("paths are relative to GITHUB_WORKSPACE (or the working directory), with forward slashes", async () => {
    const parent = join(root, "test", "fixtures");
    const [fromCwd, fromWorkspace] = await Promise.all([
      runCliAsync(["vulnerable", "--no-probe", "--fail-on", "never", "--format", "github"], { cwd: parent }),
      runCliAsync([fx("vulnerable"), "--no-probe", "--fail-on", "never", "--format", "github"], { cwd: tempDir(), env: { GITHUB_WORKSPACE: root } }),
    ]);
    assert.match(fromCwd.stdout, /file=vulnerable\/001_schema\.sql,line=22,endLine=27::/);
    assert.match(fromWorkspace.stdout, /file=test\/fixtures\/vulnerable\/001_schema\.sql,line=22,endLine=27::/);
    assert.ok(!/file=[^,]*\\/.test(fromCwd.stdout + fromWorkspace.stdout), "no backslashes");
    assert.ok(!/file=[A-Za-z]:|file=\//.test(fromCwd.stdout + fromWorkspace.stdout), "never an absolute path");
  });

  test("a file outside the workspace gets no location at all (no annotation file, no physicalLocation) but is still audited", async () => {
    const ws = tempDir();
    const elsewhere = tempDir();
    const sarifFile = join(ws, "out.sarif");
    writeTree(elsewhere, { "m.sql": "create table public.t (id uuid primary key, user_id uuid references auth.users(id));\n" });
    const r = await runCliAsync([elsewhere, "--no-probe", "--format", "github", "--sarif", sarifFile], { cwd: ws, env: { GITHUB_WORKSPACE: ws } });
    assert.equal(r.status, 2, r.stdout + r.stderr);
    assert.match(r.stdout, /^::error title=HIGH RLS-DISABLED public\.t::/m);
    assert.ok(!/file=/.test(r.stdout));
    const log = JSON.parse(readFileSync(sarifFile, "utf8"));
    assert.equal(log.runs[0].results.length, 1);
    assert.equal(log.runs[0].results[0].locations[0].physicalLocation, undefined);
    assert.ok(!JSON.stringify(log).includes(elsewhere.replace(/\\/g, "\\\\")), "the outside path is not leaked");
  });

  test("a folder whose name merely starts with two dots is inside the workspace; BOM and CRLF do not move the line", async () => {
    const ws = tempDir();
    writeTree(ws, { "..odd/bom.sql": "﻿create table public.t (\r\n  id uuid primary key,\r\n  user_id uuid references auth.users(id)\r\n);\r\n" });
    const r = await runCliAsync(["..odd", "--no-probe", "--format", "github", "--fail-on", "never"], { cwd: ws, env: { GITHUB_WORKSPACE: ws } });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /file=\.\.odd\/bom\.sql,line=1,endLine=4::/);
  });
});

describe("bin/cli.mjs: untrusted names and the network", { concurrency: 2 }, () => {
  test("hostile policy and table names are flattened to one line in the text output and escaped in annotations", async () => {
    const [text, gh] = await Promise.all([
      runCliAsync([fx("injection"), "--no-probe", "--fail-on", "never"]),
      runCliAsync([fx("injection"), "--no-probe", "--fail-on", "never", "--format", "github"]),
    ]);
    for (const out of [text.stdout, gh.stdout]) {
      assert.ok(!/^::add-mask/m.test(out) && !/^::error title=forged/m.test(out), out);
      assert.ok(!/^secret"/m.test(out), "no fragment of the hostile name starts a line");
    }
    assert.ok(!/^::/m.test(text.stdout));
    assert.match(text.stdout, /^  \[HIGH\] public\.notes: Policy "evil ::error title=forged::pwned ::add-mask::secret" lets anyone/m);
    assert.ok(gh.stdout.split("\n").filter((l) => l.startsWith("::")).every((l) => /^::(error|warning) title=/.test(l)));
  });

  test("an audit opens no network connection: no sockets, DNS lookups, fetch or UDP in the main thread or the worker", async () => {
    const dir = tempDir();
    const log = join(dir, "network.log");
    const hook = join(dir, "no-network.cjs");
    writeFileSync(hook, `
      const fs = require("node:fs");
      const note = (what) => { try { fs.appendFileSync(process.env.NET_LOG, what + "\\n"); } catch {} };
      const net = require("node:net");
      const connect = net.Socket.prototype.connect;
      net.Socket.prototype.connect = function (...a) { note("net.connect " + JSON.stringify(a[0]).slice(0, 80)); return connect.apply(this, a); };
      const dns = require("node:dns");
      for (const fn of ["lookup", "resolve", "resolve4", "resolve6"]) { const o = dns[fn]; dns[fn] = function (...a) { note("dns." + fn + " " + a[0]); return o.apply(this, a); }; }
      const dgram = require("node:dgram");
      const cs = dgram.createSocket;
      dgram.createSocket = function (...a) { note("dgram.createSocket"); return cs.apply(this, a); };
      const f = globalThis.fetch;
      globalThis.fetch = function (...a) { note("fetch " + a[0]); return f.apply(this, a); };
    `);
    // canary: the hook must catch an attempt made inside a worker thread, otherwise a silent log would prove nothing
    const canary = join(dir, "canary.cjs");
    writeFileSync(canary, `
      const { Worker, isMainThread } = require("node:worker_threads");
      if (isMainThread) new Worker(__filename);
      else fetch("http://127.0.0.1:9/").catch(() => {});
    `);
    const { spawnSync } = await import("node:child_process");
    // the same mechanism for the canary and for the audit: NODE_OPTIONS (forward slashes survive its quoting rules)
    const nodeOptions = `--require ${JSON.stringify(hook.split("\\").join("/"))}`;
    spawnSync(process.execPath, [canary], { env: { ...process.env, NET_LOG: log, NODE_OPTIONS: nodeOptions }, timeout: 30000 });
    assert.ok(existsSync(log) && readFileSync(log, "utf8").includes("fetch http://127.0.0.1:9/"), "the hook sees network use inside a worker thread");
    writeFileSync(log, "");

    const r = await runCliAsync([fx("vulnerable"), "--fix", join(dir, "fix.sql"), "--fail-on", "never"], { env: { NET_LOG: log, NODE_OPTIONS: nodeOptions } });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.match(r.stdout, /after draft fix/);
    assert.equal(readFileSync(log, "utf8"), "", "network activity during the audit: " + readFileSync(log, "utf8"));
  });
});

test("the README documents every exit code the CLI can return", () => {
  const readme = readFileSync(join(root, "README.md"), "utf8");
  for (const code of [0, 1, 2, 64, 66, 70]) assert.match(readme, new RegExp(`\\|\\s*\`?${code}\`?\\s*\\|`), `exit code ${code} missing from the README table`);
});
