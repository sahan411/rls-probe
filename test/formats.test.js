import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { escapeData, escapeProperty, workflowCommand, findingCommands } from "../src/github.js";
import { oneLine, mdText, mdCode, mdCodeCell, sentence } from "../src/text.js";
import { toSummary, toHtml, toMarkdown } from "../src/report.js";
import { toSarif } from "../src/sarif.js";
import { VERSION } from "../src/audit.js";
import { auditFixture, root } from "./helpers.js";

// ---- a model of how the Actions runner reads one workflow command line ------------------------------------------------
// (actions/runner ActionCommand.cs: the command ends at the first "::", properties are "k=v" pairs separated by ",", and
// the escapes are undone with %25 last).
const unescapeData = (s) => s.replace(/%0D/g, "\r").replace(/%0A/g, "\n").replace(/%25/g, "%");
const unescapeProperty = (s) => s.replace(/%0D/g, "\r").replace(/%0A/g, "\n").replace(/%3A/g, ":").replace(/%2C/g, ",").replace(/%25/g, "%");
function parseCommandLine(line) {
  assert.ok(!/[\r\n]/.test(line), "a workflow command must be a single physical line");
  assert.ok(line.startsWith("::"), line.slice(0, 60));
  const end = line.indexOf("::", 2);
  assert.ok(end > 2, "no closing :: in " + line.slice(0, 60));
  const header = line.slice(2, end);
  const space = header.indexOf(" ");
  const command = space === -1 ? header : header.slice(0, space);
  const props = {};
  if (space !== -1) {
    for (const pair of header.slice(space + 1).split(",")) {
      const eq = pair.indexOf("=");
      assert.ok(eq > 0, `bad property "${pair}"`);
      props[pair.slice(0, eq)] = unescapeProperty(pair.slice(eq + 1));
    }
  }
  return { command, props, message: unescapeData(line.slice(end + 2)) };
}

test("GitHub escaping: exactly the characters GitHub documents, and the runner's decoding gives the original back", () => {
  assert.equal(escapeData("100% done\r\nnext\n"), "100%25 done%0D%0Anext%0A");
  assert.equal(escapeData("a:b,c"), "a:b,c", "message data keeps : and ,");
  assert.equal(escapeProperty("a:b,c%\r\n"), "a%3Ab%2Cc%25%0D%0A");
  assert.equal(escapeData("%0A"), "%250A", "text that merely looks like an escape is escaped itself");
  assert.equal(escapeData("::error::x"), "::error::x", "colons in a message are harmless after the first ::");
  assert.equal(escapeData(undefined), "");
  assert.equal(escapeData(null), "");
  assert.equal(escapeData(42), "42");
  for (const s of ["", "plain", "50%", "%0A%0D%25", "a\nb\r\nc\rd", "x:y,z", "::error title=a,b::c", "  \u0085 end", "emoji \u{1F600} ü"]) {
    assert.equal(unescapeData(escapeData(s)), s, JSON.stringify(s));
    assert.equal(unescapeProperty(escapeProperty(s)), s, JSON.stringify(s));
    assert.ok(!/[\r\n]/.test(escapeData(s)) && !/[\r\n:,]/.test(escapeProperty(s)));
  }
});

test("workflowCommand: empty properties are left out, the message and every property value are escaped", () => {
  assert.equal(workflowCommand("error", {}, "msg"), "::error::msg");
  assert.equal(workflowCommand("warning", { file: undefined, line: null, title: "" }, "m"), "::warning::m");
  assert.equal(
    workflowCommand("error", { title: "a: b, c", file: "dir/x.sql", line: 3 }, "100%\nnext"),
    "::error title=a%3A b%2C c,file=dir/x.sql,line=3::100%25%0Anext",
  );
  const parsed = parseCommandLine(workflowCommand("error", { title: "t,:%\n", file: "a,b:c.sql" }, "x\r\ny::z"));
  assert.deepEqual(parsed, { command: "error", props: { title: "t,:%\n", file: "a,b:c.sql" }, message: "x\r\ny::z" });
});

const finding = (severity, extra = {}) => ({ rule: "RLS-DISABLED", severity, object: "public.t", title: "Title", why: "Why it matters", fix: "Do this", evidence: {}, ...extra });

test("findingCommands: CRITICAL and HIGH are errors, MEDIUM is a warning, LOW and INFO are not annotated", () => {
  const lines = findingCommands([finding("CRITICAL"), finding("HIGH"), finding("MEDIUM"), finding("LOW"), finding("INFO")]);
  assert.deepEqual(lines.map((l) => parseCommandLine(l).command), ["error", "error", "warning"]);
  assert.deepEqual(findingCommands([finding("LOW"), finding("INFO")], { minSeverity: "LOW" }).map((l) => parseCommandLine(l).command), ["warning"], "minSeverity widens the set; INFO still stays out");
  assert.equal(parseCommandLine(lines[0]).props.title, "CRITICAL RLS-DISABLED public.t");
  assert.equal(parseCommandLine(lines[0]).message, "Title. Why it matters. Fix: Do this");
});

test("findingCommands: file, line and endLine only from a verified location, endLine only when it extends past line", () => {
  const p = (f) => parseCommandLine(findingCommands([f])[0]).props;
  assert.deepEqual(p(finding("HIGH")), { title: "HIGH RLS-DISABLED public.t" });
  assert.deepEqual(p(finding("HIGH", { locations: [{ file: "db/a b.sql", line: 4, endLine: 9 }] })), { title: "HIGH RLS-DISABLED public.t", file: "db/a b.sql", line: "4", endLine: "9" });
  assert.deepEqual(p(finding("HIGH", { locations: [{ file: "x.sql", line: 4, endLine: 4 }] })), { title: "HIGH RLS-DISABLED public.t", file: "x.sql", line: "4" });
  assert.deepEqual(p(finding("HIGH", { locations: [{ file: "x.sql", line: 0, endLine: 3 }, { file: "y,z:w.sql", line: 7, endLine: 8 }] })), { title: "HIGH RLS-DISABLED public.t", file: "y,z:w.sql", line: "7", endLine: "8" }, "the first usable location is used; , and : in the path survive the round trip");
  assert.deepEqual(p(finding("HIGH", { locations: [{ file: null, line: 3 }] })), { title: "HIGH RLS-DISABLED public.t" });
  assert.deepEqual(p(finding("HIGH", { locations: [{ file: "x.sql", line: 2.5 }] })), { title: "HIGH RLS-DISABLED public.t" });
  const long = findingCommands([finding("HIGH", { why: "w".repeat(10000) })])[0];
  assert.ok(parseCommandLine(long).message.length <= 4000);
});

test("hostile names from a pull request cannot forge workflow commands: one line per finding, round trip intact", async () => {
  const res = await auditFixture("injection", {}, { withPaths: true });
  const wanted = res.findings.filter((f) => ["CRITICAL", "HIGH", "MEDIUM"].includes(f.severity));
  assert.ok(wanted.length >= 3);
  const lines = findingCommands(res.findings);
  assert.equal(lines.length, wanted.length, "exactly one line per finding, no extra lines from embedded newlines");
  const hostile = res.findings.find((f) => f.evidence.policy?.includes("::error title=forged"));
  assert.ok(hostile, "fixture finding present");
  for (const [i, line] of lines.entries()) {
    const c = parseCommandLine(line);
    assert.ok(c.command === "error" || c.command === "warning", `unexpected command ${c.command}`);
    assert.equal(c.props.title, `${wanted[i].severity} ${wanted[i].rule} ${wanted[i].object}`);
    assert.ok(!/^::(?!error |warning )/m.test(line), "no second command hides inside the line");
  }
  const decoded = lines.map((l) => parseCommandLine(l).message).find((m) => m.includes("forged"));
  assert.ok(decoded.includes('evil\n::error title=forged::pwned\n::add-mask::secret'), "the hostile text survives as data (decoded by the runner), not as commands");
  assert.ok(lines.every((l) => !l.includes("\n")));
  assert.ok(!lines.some((l) => /(^|\n)::add-mask::/.test(l)));
});

test("text helpers: one line, no control characters, Markdown and links neutralised, code fences that cannot be closed", () => {
  assert.equal(oneLine("a\nb\r\nc\td e f\u0000g\u007fh\u009fi"), "a b  c d e f g h i");
  assert.equal(oneLine(null), "");
  assert.equal(mdText("a|b*c_d`e<f>[g]\\h&i~j"), "a\\|b\\*c\\_d\\`e\\<f\\>\\[g\\]\\\\h\\&i\\~j");
  assert.ok(!mdText("x\ny").includes("\n"));
  assert.ok(!mdText("see http://evil.example/x and www.evil.example").match(/:\/\/|www\./), "no text left that GitHub would autolink");
  assert.equal(mdText("see http://evil.example").replace(/​/g, ""), "see http://evil.example", "only an invisible character is added");
  assert.equal(mdCode("plain"), "`plain`");
  assert.equal(mdCode("a`b"), "``a`b``");
  assert.equal(mdCode("`edge`"), "`` `edge` ``");
  assert.equal(mdCode("a``b`c"), "```a``b`c```");
  assert.equal(mdCode("two\nlines"), "`two lines`");
  assert.equal(mdCodeCell("a|b"), "`a\\|b`");
  assert.equal(sentence("Table is open"), "Table is open.");
  assert.equal(sentence("Done!"), "Done!");
  assert.equal(sentence("  "), "");
});

test("summary Markdown: verdict, counts, located findings, failing tests; hostile names stay inert and tables stay intact", async () => {
  const res = await auditFixture("vulnerable", {}, { withPaths: true });
  const md = toSummary(res);
  assert.match(md, /^## rls-probe: Row Level Security audit\n/);
  assert.match(md, /\*\*Do not put real user data in this project yet\.\*\* 3 critical and 8 high-severity issue\(s\)/);
  for (const [sev, n] of Object.entries(res.counts)) assert.match(md, new RegExp(`\\| ${sev} \\| ${n} \\|`));
  assert.match(md, new RegExp(`Failing executed access tests: \\*\\*${res.proof.failures}\\*\\*`));
  assert.match(md, /Loaded 20 of 20 SQL statements from 1 file\(s\)/);
  assert.match(md, /- \*\*CRITICAL\*\* `public\.orders` — .* — `test\/fixtures\/vulnerable\/001_schema\.sql:22`\n {2}- Fix: /);
  assert.match(md, /### Failing access tests/);
  assert.match(md, /Not a penetration test/);
  assert.ok(!md.includes("_model"));
  // truncation is announced, not silent
  const short = toSummary(res, { maxFindings: 2, maxProbes: 3 });
  assert.match(short, /\.\.\.and 13 more finding\(s\)/);
  assert.match(short, /\| \.\.\.and 30 more \| \| \| \|/);

  const bad = toSummary(await auditFixture("injection", {}, { withPaths: true }));
  assert.ok(!/^::/m.test(bad), "no line of the summary starts with a workflow command");
  assert.ok(!bad.includes("<script>"), "no raw HTML");
  assert.ok(!/(^|[^\\])\[click\]\(/.test(bad), "no live Markdown link");
  assert.ok(!/(^|[^`])https?:\/\//.test(bad.replace(/`[^`]*`/g, "")), "no bare URL outside code spans");
  const tableRows = bad.split("\n").filter((l) => /^\| `public\./.test(l));
  assert.ok(tableRows.length >= 8);
  for (const row of tableRows) assert.equal(row.replace(/\\\|/g, "").split("|").length - 2, 4, `table row broken by a hostile name: ${row}`);
});

test("HTML report escapes names taken from the audited SQL", async () => {
  const html = toHtml(await auditFixture("injection", {}, { withPaths: true }));
  assert.ok(!html.includes("<script>alert(1)</script>"));
  assert.ok(html.includes("&lt;script&gt;alert(1)&lt;/script&gt;"));
  assert.ok(!/<a\s/i.test(html), "the report contains no links built from audited names");
});

test("outward copy: no report format claims a guarantee, a sign-off or an assurance", async () => {
  const res = await auditFixture("vulnerable", {}, { withPaths: true });
  const outputs = { markdown: toMarkdown(res), html: toHtml(res), summary: toSummary(res) };
  for (const [name, text] of Object.entries(outputs)) {
    assert.ok(!/guarantee|sign-?off|assurance/i.test(text), `${name} output uses a banned word`);
    assert.match(text, /not a penetration test/i, `${name} output keeps the penetration-test disclaimer`);
  }
  assert.match(outputs.markdown, /cannot show that an application is secure/);
});

test("JSON result: locations are repository-relative, no engine internals, one version everywhere", async () => {
  const res = await auditFixture("vulnerable", {}, { withPaths: true });
  const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  assert.equal(VERSION, pkg.version);
  assert.equal(res.meta.version, pkg.version);
  assert.equal(toSarif(res).runs[0].tool.driver.version, pkg.version);
  assert.match(toSummary(res), new RegExp(`rls-probe ${pkg.version.replace(/\./g, "\\.")}:`));
  assert.match(toMarkdown(res), new RegExp(`rls-probe ${pkg.version.replace(/\./g, "\\.")} `));
  const located = res.findings.filter((f) => f.locations);
  assert.ok(located.length >= 14);
  for (const f of located) for (const l of f.locations) {
    assert.match(l.file, /^test\/fixtures\/vulnerable\/001_schema\.sql$/);
    assert.ok(Number.isInteger(l.line) && l.line >= 1 && Number.isInteger(l.endLine) && l.endLine >= l.line);
  }
  assert.ok(!("_model" in JSON.parse(JSON.stringify((({ _model, ...r }) => r)(res)))));
});
