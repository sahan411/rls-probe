import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { toSarif, sarifLevel } from "../src/sarif.js";
import { audit } from "../src/audit.js";
import { auditFixture, fixture, sarifValidator, root } from "./helpers.js";

const meta = { tool: "rls-probe", version: "9.9.9" };
const fake = (severity, extra = {}) => ({ id: `x#${severity}`, rule: "RLS-DISABLED", lint: "0013_rls_disabled_in_public", severity, object: "public.t", title: "Title", why: "Why", fix: "Fix it", evidence: {}, ...extra });

test("level mapping: CRITICAL and HIGH are errors, MEDIUM a warning, LOW and INFO notes", () => {
  assert.deepEqual(
    ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map(sarifLevel),
    ["error", "error", "warning", "note", "note"],
  );
  const log = toSarif({ meta, findings: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((s) => fake(s, { object: `public.${s.toLowerCase()}` })) });
  assert.deepEqual(log.runs[0].results.map((r) => [r.properties.severity, r.level]), [
    ["CRITICAL", "error"], ["HIGH", "error"], ["MEDIUM", "warning"], ["LOW", "note"], ["INFO", "note"],
  ]);
});

test("SARIF 2.1.0 structure of a real audit: version, schema, tool.driver.rules matching results, relative locations with lines", async () => {
  const res = await auditFixture("vulnerable", {}, { withPaths: true });
  const log = toSarif(res);
  assert.equal(log.version, "2.1.0");
  assert.match(log.$schema, /^https:\/\/.+sarif-schema-2\.1\.0\.json$/);
  assert.equal(log.runs.length, 1);
  const [run] = log.runs;
  const driver = run.tool.driver;
  assert.equal(driver.name, "rls-probe");
  assert.equal(driver.version, res.meta.version);
  assert.match(driver.informationUri, /^https:\/\//);

  const ids = driver.rules.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length, "rule ids are unique");
  assert.deepEqual([...new Set(res.findings.map((f) => f.rule))].sort(), [...ids].sort(), "only rules that fired are listed, none missing");
  for (const rule of driver.rules) {
    assert.ok(rule.name && rule.shortDescription.text && rule.fullDescription.text && rule.help.text && rule.help.markdown, rule.id);
    assert.ok(["error", "warning", "note"].includes(rule.defaultConfiguration.level), rule.id);
    assert.ok(["very-high", "high", "medium", "low"].includes(rule.properties.precision), rule.id);
    if (rule.helpUri) assert.match(rule.helpUri, /^https:\/\/supabase\.com\/docs\//);
    assert.ok(!("security-severity" in rule.properties), "no rule-level score: one rule spans several severities");
  }

  assert.equal(run.results.length, res.findings.length);
  for (const [i, r] of run.results.entries()) {
    const f = res.findings[i];
    assert.equal(r.ruleId, f.rule);
    assert.equal(driver.rules[r.ruleIndex].id, r.ruleId, "ruleIndex points at the rule with the same id");
    assert.equal(r.level, sarifLevel(f.severity));
    assert.match(r.message.text, new RegExp(`^\\[${f.severity}\\] `));
    assert.ok(r.locations.length >= 1);
    assert.match(r.fingerprints["rls-probe/v1"], /^[0-9a-f]{64}$/);
    for (const loc of r.locations) {
      assert.ok(loc.logicalLocations.length >= 1 && loc.logicalLocations.every((l) => l.name && l.fullyQualifiedName), "database object named");
      if (!f.locations) { assert.equal(loc.physicalLocation, undefined); continue; }
      const { artifactLocation, region } = loc.physicalLocation;
      assert.equal(artifactLocation.uri, "test/fixtures/vulnerable/001_schema.sql");
      assert.ok(!/^[A-Za-z][A-Za-z0-9+.-]*:|^\/|\\|(^|\/)\.\.(\/|$)/.test(artifactLocation.uri), "relative URI, no scheme, no absolute or parent path");
      assert.ok(Number.isInteger(region.startLine) && region.startLine >= 1);
      if ("endLine" in region) assert.ok(Number.isInteger(region.endLine) && region.endLine > region.startLine);
    }
  }
  assert.equal(run.results.filter((r) => r.locations[0].physicalLocation).length, res.findings.filter((f) => f.locations).length);
  assert.ok(run.results.filter((r) => r.locations[0].physicalLocation).length >= 14);

  const text = JSON.stringify(log);
  assert.ok(!text.includes(root.replace(/\\/g, "\\\\")) && !text.includes(root), "no absolute path of this machine");
  assert.deepEqual(JSON.parse(text), log, "plain JSON, survives a round trip");
});

test("every rule the checks can emit has curated SARIF metadata (none falls back to the generic entry)", () => {
  const src = ["checks.js", "audit.js"].map((f) => readFileSync(join(root, "src", f), "utf8")).join("\n");
  const ruleIds = [...new Set([...src.matchAll(/\bF\("([A-Z][A-Z-]+)"/g), ...src.matchAll(/\brule: "([A-Z][A-Z-]+)"/g)].map((m) => m[1]))];
  assert.ok(ruleIds.length >= 15, ruleIds.join(","));
  const log = toSarif({ meta, findings: ruleIds.map((rule) => fake("HIGH", { rule, lint: "custom", object: `public.${rule}` })) });
  const names = log.runs[0].tool.driver.rules.map((r) => r.name);
  assert.equal(new Set(names).size, names.length);
  for (const rule of log.runs[0].tool.driver.rules) {
    assert.notEqual(rule.name, rule.id.replace(/[^A-Za-z0-9]/g, ""), `${rule.id} uses the fallback entry`);
    assert.match(rule.name, /^[A-Z][A-Za-z]+$/);
    assert.notEqual(rule.shortDescription.text, "Title", rule.id);
  }
  // an unknown rule still produces a valid entry rather than crashing
  const unknown = toSarif({ meta, findings: [fake("LOW", { rule: "NEW-RULE", lint: undefined })] });
  assert.equal(unknown.runs[0].tool.driver.rules[0].id, "NEW-RULE");
});

test("locations: URIs are percent-encoded, at most 10 per result, a missing location is left out rather than invented", () => {
  const many = Array.from({ length: 15 }, (_, i) => ({ file: "db/m.sql", line: i + 1, endLine: i + 1 }));
  const log = toSarif({ meta, findings: [
    fake("HIGH", { object: "public.a", locations: [{ file: "db/my dir/#x ü.sql", line: 3, endLine: 9 }] }),
    fake("HIGH", { object: "public.b", locations: many }),
    fake("HIGH", { object: "public.c" }),
    fake("HIGH", { object: "public.d", locations: [{ file: "x.sql", line: 0 }, { file: null, line: 4 }] }),
  ] });
  const [a, b, c, d] = log.runs[0].results;
  assert.deepEqual(a.locations[0].physicalLocation, { artifactLocation: { uri: "db/my%20dir/%23x%20%C3%BC.sql" }, region: { startLine: 3, endLine: 9 } });
  assert.equal(b.locations.length, 10);
  assert.deepEqual(b.locations.map((l) => l.physicalLocation.region.startLine), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  assert.ok(!("endLine" in b.locations[0].physicalLocation.region), "endLine equal to startLine is omitted");
  for (const r of [c, d]) {
    assert.equal(r.locations.length, 1);
    assert.equal(r.locations[0].physicalLocation, undefined);
    assert.equal(r.locations[0].logicalLocations[0].fullyQualifiedName, r.properties.object);
  }
});

test("fingerprints identify the problem, not the line: stable when code moves, different for different problems", async () => {
  const files = fixture("vulnerable", { withPaths: true });
  const moved = files.map((f) => ({ ...f, text: `-- a\n-- b\n-- c\n${f.text}` }));
  const a = toSarif(await auditFixture("vulnerable", { probe: false }, { withPaths: true })).runs[0].results;
  const b = toSarif(await audit(moved, { probe: false })).runs[0].results;
  const key = (r) => r.fingerprints["rls-probe/v1"];
  assert.deepEqual(a.map(key), b.map(key), "same fingerprints after inserting lines at the top");
  assert.notDeepEqual(a.map((r) => r.locations[0].physicalLocation?.region.startLine), b.map((r) => r.locations[0].physicalLocation?.region.startLine), "the lines themselves did move");
  const rlsFp = a.filter((r) => r.ruleId === "RLS-DISABLED").map(key);
  assert.equal(new Set(rlsFp).size, rlsFp.length, "different tables, different fingerprints");
});

test("no findings: a valid log with empty results and rules", () => {
  const log = toSarif({ meta, findings: [] });
  assert.deepEqual(log.runs[0].results, []);
  assert.deepEqual(log.runs[0].tool.driver.rules, []);
  assert.equal(log.version, "2.1.0");
});

// ---- validation against the official OASIS schema (skipped when offline or when the dev-only validator is missing) ----------
test("official sarif-schema-2.1.0.json accepts every log this tool writes (and rejects a broken one)", async (t) => {
  const v = await sarifValidator();
  if (v.skip) return t.skip(v.skip);
  const broken = { version: "2.1.0", runs: [{ tool: { driver: { name: "x" } }, results: [{ message: { text: "m" }, level: "fatal" }] }] };
  assert.notDeepEqual(v.validate(broken), [], "the validator must be able to fail");
  assert.notDeepEqual(v.validate({ runs: [] }), [], "missing version is rejected");

  const many = Array.from({ length: 15 }, (_, i) => ({ file: "db/m.sql", line: i + 1, endLine: i + 3 }));
  const logs = {
    vulnerable: toSarif(await auditFixture("vulnerable", {}, { withPaths: true })),
    injection: toSarif(await auditFixture("injection", { probe: false }, { withPaths: true })),
    pgdump: toSarif(await auditFixture("pgdump-data", { probe: false }, { withPaths: true })),
    clean: toSarif(await auditFixture("fixed", { probe: false }, { withPaths: true })),
    synthetic: toSarif({ meta, findings: [fake("HIGH", { locations: many }), fake("MEDIUM", { object: "public.m" }), fake("LOW", { object: "public.u", locations: [{ file: "a b/ü.sql", line: 2 }] }), fake("INFO", { object: "public.v" })] }),
    empty: toSarif({ meta, findings: [] }),
  };
  for (const [name, log] of Object.entries(logs)) assert.deepEqual(v.validate(log), [], `${name} is not valid SARIF 2.1.0`);
});
