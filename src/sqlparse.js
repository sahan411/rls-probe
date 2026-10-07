// Small, dependency-free SQL helpers shared by the splitter, the loader and the location index.
// Input is always ONE statement as produced by splitSql (comments already removed).

const WS = /\s/;
const ASCII_UPPER = /[A-Z]/g;

// Postgres folds unquoted identifiers to lower case (ASCII only) and keeps quoted ones as written.
export const fold = (s) => s.replace(ASCII_UPPER, (c) => c.toLowerCase());

export function skipWs(s, i) {
  while (i < s.length && WS.test(s[i])) i++;
  return i;
}

// Reads one identifier at position i (after optional whitespace). Returns { value, end } or null.
export function readIdent(s, i = 0) {
  i = skipWs(s, i);
  if (s[i] === '"') {
    let v = "";
    i++;
    while (i < s.length) {
      if (s[i] === '"') {
        if (s[i + 1] === '"') { v += '"'; i += 2; continue; }
        return { value: v, end: i + 1 };
      }
      v += s[i++];
    }
    return null; // unterminated
  }
  const m = /^[A-Za-z_\u0080-￿][A-Za-z0-9_$\u0080-￿]*/.exec(s.slice(i, i + 200));
  return m ? { value: fold(m[0]), end: i + m[0].length } : null;
}

// Reads a possibly schema-qualified name (a.b or "a"."b"). Returns { parts, end } or null.
export function readQualified(s, i = 0) {
  const parts = [];
  let cur = readIdent(s, i);
  if (!cur) return null;
  parts.push(cur.value);
  i = cur.end;
  for (;;) {
    const j = skipWs(s, i);
    if (s[j] !== ".") break;
    cur = readIdent(s, j + 1);
    if (!cur) return null;
    parts.push(cur.value);
    i = cur.end;
  }
  return { parts, end: i };
}

// Skips a balanced (...) group starting at the first "(" at or after i (strings and quoted identifiers respected).
export function skipParens(s, i) {
  i = skipWs(s, i);
  if (s[i] !== "(") return i;
  let depth = 0;
  while (i < s.length) {
    const c = s[i];
    if (c === "'" || c === '"') {
      const q = c;
      i++;
      while (i < s.length) {
        if (s[i] === q) { if (s[i + 1] === q) { i += 2; continue; } break; }
        i++;
      }
    } else if (c === "(") depth++;
    else if (c === ")") { depth--; if (depth === 0) return i + 1; }
    i++;
  }
  return i;
}

// Replaces string literals and quoted identifiers by empty ones so keyword tests cannot be fooled by their content.
export function stripQuoted(sql) {
  return sql.replace(/'(?:[^']|'')*'/g, "''").replace(/"(?:[^"]|"")*"/g, '""');
}

// COPY ... FROM STDIN carries its rows inline, after the statement, up to a line holding only \.
export function isCopyFromStdin(sql) {
  const t = stripQuoted(sql);
  return /^\s*copy\b/i.test(t) && /\bfrom\s+stdin\b/i.test(t);
}

export function firstKeyword(sql) {
  const m = /^\s*([A-Za-z_]+)/.exec(sql);
  return m ? m[1].toLowerCase() : "";
}

// ---- statement classification for the loader -------------------------------------------------------------------

const MAX_SLEEP_SECONDS = 1;

// pg_sleep(<number literal>) up to 1 second in total is allowed. pg_sleep_for / pg_sleep_until and any argument that is not
// a plain number are blocked, because their duration cannot be bounded by reading the statement.
function sleepVerdict(sql) {
  const calls = /\bpg_sleep(_for|_until)?\s*\(/gi;
  let total = 0;
  for (let m; (m = calls.exec(sql));) {
    if (m[1]) return { block: true, what: `pg_sleep${m[1]}(...)` };
    const num = /^\s*([0-9]*\.?[0-9]+(?:[eE][+-]?[0-9]+)?)\s*\)/.exec(sql.slice(m.index + m[0].length));
    if (!num) return { block: true, what: "pg_sleep(<not a plain number>)" };
    total += Number(num[1]);
    if (total > MAX_SLEEP_SECONDS) return { block: true, what: `pg_sleep(${num[1]})` };
  }
  return { block: false };
}

const READ_LIKE = new Set(["select", "with", "call", "explain", "values", "table", "perform"]);

// Transaction control is never executed: the loader runs every statement on its own (see loader.js), and an explicit
// BEGIN would turn one failed statement into "current transaction is aborted" for the rest of the file.
const TXN_STATEMENT = /^\s*(begin|start\s+transaction|commit|end|rollback|abort|savepoint|release)(?![A-Za-z0-9_])/i;

// Decides what the loader does with one statement.
//   { action: "run" }
//   { action: "skip", category: "data", what: "copy" | "insert" }       row data is never loaded
//   { action: "skip", category: "unsafe", reason }                      could stall the sandbox; listed with a reason
export function classifyStatement(st) {
  const sql = st.sql;
  const first = st.kind === "copy" ? "copy" : firstKeyword(sql);

  if (first === "copy") return { action: "skip", category: "data", what: "copy" };

  if (TXN_STATEMENT.test(sql)) return { action: "skip", category: "txn", what: first };

  if (first === "insert") {
    const m = /^\s*insert\s+into\s+(?:only\s+)?/i.exec(sql);
    const q = m ? readQualified(sql, m[0].length) : null;
    // The public-bucket check reads the rows of storage.buckets; every other INSERT is row data and is ignored.
    if (q && q.parts.length === 2 && q.parts[0] === "storage" && q.parts[1] === "buckets") return { action: "run" };
    return { action: "skip", category: "data", what: "insert" };
  }

  // WITH ... INSERT INTO ... (a data-modifying CTE) writes rows just like a plain INSERT.
  if (first === "with" && /\binsert\s+into\b/i.test(stripQuoted(sql))) return { action: "skip", category: "data", what: "insert" };

  if (first === "listen") return { action: "skip", category: "unsafe", reason: "LISTEN is never executed (a schema audit has nothing to wait for)" };

  if (first === "do" && /\bpg_sleep(_for|_until)?\b/i.test(sql)) {
    return { action: "skip", category: "unsafe", reason: "DO block calls pg_sleep and would stall the audit; not executed" };
  }

  if (READ_LIKE.has(first)) {
    const v = sleepVerdict(sql);
    if (v.block) return { action: "skip", category: "unsafe", reason: `${v.what} would stall the audit; not executed (only pg_sleep with a plain number totalling ${MAX_SLEEP_SECONDS} second or less is allowed)` };
  }
  return { action: "run" };
}
