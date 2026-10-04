// Splits a SQL script into statements. Understands -- and nested /* */ comments, '...' and E'...' strings,
// "quoted identifiers", $tag$ dollar quoting (function bodies) and psql meta-commands such as \restrict.
// Not supported: SQL-standard "BEGIN ATOMIC ... END" function bodies (rare in Supabase projects).
export function splitSql(sql) {
  const stmts = [];
  const n = sql.length;
  let cur = "";
  let curLine = null;
  let line = 1;
  let i = 0;

  const push = () => {
    const t = cur.trim();
    if (t) stmts.push({ sql: t, line: curLine ?? line });
    cur = "";
    curLine = null;
  };
  const mark = () => {
    if (curLine === null) curLine = line;
  };

  while (i < n) {
    const c = sql[i];
    const d = sql[i + 1];

    if (c === "\n") { line++; cur += c; i++; continue; }

    // psql meta-command at the start of a statement: skip the whole line
    if (c === "\\" && cur.trim() === "") {
      while (i < n && sql[i] !== "\n") i++;
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
        i = stop;
        continue;
      }
    }
    if (c === ";") { cur += c; i++; push(); continue; }
    if (!/\s/.test(c)) mark();
    cur += c; i++;
  }
  push();
  return stmts;
}
