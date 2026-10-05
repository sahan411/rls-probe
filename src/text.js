// Helpers for putting text that comes from the audited SQL (object names, policy names, statements) into logs and Markdown.
// That text is attacker-controlled when the SQL comes from a pull request, so it is neutralised before printing.

// C0/C1 control characters plus the Unicode line and paragraph separators (built from code points: they are line terminators
// and cannot appear inside a regex literal).
const CONTROL = new RegExp(`[\\u0000-\\u001f\\u007f-\\u009f${String.fromCharCode(0x2028, 0x2029)}]`, "g");

// One line, no control characters: stops a quoted identifier containing a newline from forging a log line that starts with ::
// (a GitHub Actions workflow command).
export const oneLine = (s) => String(s ?? "").replace(CONTROL, " ");

// Escapes Markdown / HTML-significant characters so untrusted text renders as plain text. Bare URLs would still be turned into
// links by GitHub's autolinker, so "://" and "www." get an invisible zero-width space that stops the autolink from matching.
const ZWSP = "​";
export const mdText = (s) => oneLine(s)
  .replace(/[\\`*_[\]<>|&~]/g, (c) => `\\${c}`)
  .replace(/:\/\//g, `:${ZWSP}//`)
  .replace(/\bwww\./gi, (m) => `${m.slice(0, 3)}${ZWSP}.`);

// Inline code span that cannot be broken out of: the fence is longer than any backtick run inside.
export function mdCode(s) {
  const t = oneLine(s);
  const longest = Math.max(0, ...(t.match(/`+/g) || []).map((r) => r.length));
  const fence = "`".repeat(longest + 1);
  const pad = t.startsWith("`") || t.endsWith("`") ? " " : "";
  return `${fence}${pad}${t}${pad}${fence}`;
}

// Inline code span for a Markdown table cell: GitHub splits a cell at every unescaped pipe, even inside a code span.
export const mdCodeCell = (s) => mdCode(s).replace(/\|/g, "\\|");

// Makes a fragment end like a sentence ("Table is open" -> "Table is open.") without doubling existing punctuation.
export const sentence = (s) => {
  const t = String(s ?? "").trim();
  return !t || /[.!?]$/.test(t) ? t : `${t}.`;
};
