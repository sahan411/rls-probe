import { isCopyFromStdin, stripQuoted } from "./sqlparse.js";

// Splits a SQL script into statements. Understands -- and nested /* */ comments, '...' and E'...' strings,
// "quoted identifiers", $tag$ dollar quoting (function bodies) and psql meta-commands such as \restrict.
// Row data is never returned as SQL: the inline data of COPY ... FROM stdin (and \copy ... from stdin) is skipped up to the
// line that holds only \. , keeping line numbers correct. The COPY / \copy command itself is returned with kind: "copy"
// so the loader can count it; it must never be executed.
// Each statement is { sql, line, endLine } (1-based first and last line, comments excluded).
// Not supported: SQL-standard "BEGIN ATOMIC ... END" function bodies (rare in Supabase projects).
export function splitSql(sql) {
  const stmts = [];
  const n = sql.length;
  let cur = "";
  let curLine = null;
  let line = 1;
  let lastLine = 1; // line of the last non-blank, non-comment character consumed
  let i = 0;

  const push = () => {
    const t = cur.trim();
    let st = null;
    if (t) {
      st = { sql: t, line: curLine ?? line, endLine: lastLine };
      stmts.push(st);
    }
    cur = "";
    curLine = null;
    return st;
  };
  const mark = () => {
    if (curLine === null) curLine = line;
    lastLine = line;
  };

  // Called with i just after the command that announced inline data. Consumes the rest of that line and every data line,
  // including the terminating \. line (or everything to the end of the input if it never comes).
  const skipInlineData = (st) => {
    while (i < n && sql[i] !== "\n") i++;
    if (i < n) { i++; line++; }
    let rows = 0;
    let closed = false;
    while (i < n) {
      let e = sql.indexOf("\n", i);
      if (e === -1) e = n;
      const text = sql.slice(i, e);
      i = e < n ? e + 1 : n;
      if (e < n) line++;
      if (/^\\\.[ \t\r]*$/.test(text)) { closed = true; break; }
      rows++;
    }
    if (st) {
      st.dataLines = rows;
      if (!closed) st.unterminated = true; // the rest of the input was swallowed as data: the loader reports it
    }
  };

  while (i < n) {
    const c = sql[i];
    const d = sql[i + 1];

    if (c === "\n") { line++; cur += c; i++; continue; }

    // psql meta-command at the start of a statement: skip the whole line (\copy ... from stdin also carries inline data)
    if (c === "\\" && cur.trim() === "") {
      let e = sql.indexOf("\n", i);
      if (e === -1) e = n;
      const text = sql.slice(i, e).trim();
      if (/^\\copy\b/i.test(text)) {
        const st = { sql: text, line, endLine: line, kind: "copy" };
        stmts.push(st);
        if (/\bfrom\s+stdin\b/i.test(stripQuoted(text))) { i = e; skipInlineData(st); continue; }
      }
      i = e;
      continue;
    }
    // line comment
    if (c === "-" && d === "-") {
      while (i < n && sql[i] !== "\n") i++;
      continue;
    }
    // block comment (nested)
    if (c === "/" && d === "*") {
      let depth = 1;
      i += 2;
      while (i < n && depth > 0) {
        if (sql[i] === "/" && sql[i + 1] === "*") { depth++; i += 2; }
        else if (sql[i] === "*" && sql[i + 1] === "/") { depth--; i += 2; }
        else { if (sql[i] === "\n") line++; i++; }
      }
      cur += " ";
      continue;
    }
    // single-quoted string (E'' strings allow backslash escapes)
    if (c === "'") {
      mark();
      const isE = /(^|[^A-Za-z0-9_])[eE]$/.test(cur);
      cur += c; i++;
      while (i < n) {
        const ch = sql[i];
        cur += ch; i++;
        if (ch === "\n") line++;
        if (isE && ch === "\\" && i < n) { cur += sql[i]; if (sql[i] === "\n") line++; i++; continue; }
        if (ch === "'") {
          if (sql[i] === "'") { cur += "'"; i++; continue; }
          break;
        }
      }
      lastLine = line;
      continue;
    }
    // quoted identifier
    if (c === '"') {
      mark();
      cur += c; i++;
      while (i < n) {
        const ch = sql[i];
        cur += ch; i++;
        if (ch === "\n") line++;
        if (ch === '"') {
          if (sql[i] === '"') { cur += '"'; i++; continue; }
          break;
        }
      }
      lastLine = line;
      continue;
    }
    // dollar quoting
    if (c === "$" && !/[A-Za-z0-9_]$/.test(cur)) {
      const m = /^\$([A-Za-z_\u0080-￿][A-Za-z0-9_\u0080-￿]*)?\$/.exec(sql.slice(i, i + 80));
      if (m) {
        mark();
        const tag = m[0];
        const end = sql.indexOf(tag, i + tag.length);
        const stop = end === -1 ? n : end + tag.length;
        const chunk = sql.slice(i, stop);
        cur += chunk;
        for (const ch of chunk) if (ch === "\n") line++;
        lastLine = line;
        i = stop;
        continue;
      }
    }
    if (c === ";") {
      mark();
      cur += c; i++;
      const st = push();
      if (st && isCopyFromStdin(st.sql)) { st.kind = "copy"; skipInlineData(st); }
      continue;
    }
    if (!/\s/.test(c)) mark();
    cur += c; i++;
  }
  push();
  return stmts;
}
