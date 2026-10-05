import { readIdent, readQualified, skipParens, skipWs, fold } from "./sqlparse.js";

// Maps database objects back to the statement (file and line) that defines them, so findings can point at source code.
//
// Principle: attach a location only when it is certain, otherwise attach nothing.
//   * A location is recorded only after the statement ran without error.
//   * The latest successful CREATE wins (a later CREATE OR REPLACE or drop-and-recreate is the live definition).
//   * Anything that could make the mapping ambiguous removes it: ALTER POLICY, RENAME / SET SCHEMA, DROP of a function (a
//     later overload could be the survivor), overloaded functions, and unqualified names after a non-public search_path.
//   * CREATE ... IF NOT EXISTS is recorded only when it really created the object (the loader checks beforehand).

const sep = "\u0000";
const relKey = (schema, name) => `${schema}.${name}`;
const polKey = (rel, policy) => `${rel}${sep}${policy}`;

const REL_KINDS = "table|view|materialized\\s+view|foreign\\s+table";

function searchPathIsPublicFirst(value) {
  const first = value.split(",").map((s) => s.trim().replace(/^"(.*)"$/, "$1")).filter((s) => s && s !== "$user")[0];
  return first !== undefined && fold(first) === "public";
}

export class LocationIndex {
  constructor() {
    this.relations = new Map();
    this.policies = new Map();
    this.functions = new Map();
    this.taintedFunctions = new Set();
    this.taintedPolicies = new Set();
    this.publicFirst = true;
  }

  resolve(parts) {
    if (parts.length === 2) return [parts[0], parts[1]];
    if (parts.length === 1 && this.publicFirst) return ["public", parts[0]];
    return null;
  }

  // Describes what a statement will do to the index. Called BEFORE the statement runs; apply() is called after it succeeded.
  effectOf(sql) {
    let m;

    // ---- session state that changes how unqualified names resolve
    if ((m = /^set\s+(?:session\s+|local\s+)?search_path\s*(?:=|to)\s*([\s\S]*)$/i.exec(sql))) {
      const v = m[1].trim().replace(/;\s*$/, "");
      return { type: "search-path", publicFirst: /^default$/i.test(v) || searchPathIsPublicFirst(v.replace(/'/g, "")) };
    }
    if (/^reset\s+search_path\b/i.test(sql)) return { type: "search-path", publicFirst: true };
    if ((m = /^select\s+(?:pg_catalog\.)?set_config\s*\(\s*'search_path'\s*,\s*'((?:[^']|'')*)'/i.exec(sql))) {
      return { type: "search-path", publicFirst: searchPathIsPublicFirst(m[1].replace(/''/g, "'")) };
    }

    // ---- creations
    if ((m = new RegExp(`^create\\s+(?:or\\s+replace\\s+)?(?:((?:global\\s+|local\\s+)?(?:temp|temporary)\\s+)|unlogged\\s+)?(?:recursive\\s+)?(${REL_KINDS})\\s+(if\\s+not\\s+exists\\s+)?`, "i").exec(sql))) {
      if (m[1]) return null; // temporary objects live in pg_temp, never in an audited schema
      const q = readQualified(sql, m[0].length);
      const r = q && this.resolve(q.parts);
      return r ? { type: "create-relation", schema: r[0], name: r[1], key: relKey(...r), ifNotExists: Boolean(m[3]) } : null;
    }
    if ((m = /^create\s+(?:or\s+replace\s+)?(?:function|procedure)\s+/i.exec(sql))) {
      const q = readQualified(sql, m[0].length);
      const r = q && this.resolve(q.parts);
      return r ? { type: "create-function", key: relKey(...r) } : null;
    }
    if ((m = /^create\s+policy\s+/i.exec(sql))) {
      const name = readIdent(sql, m[0].length);
      const on = name && /^\s+on\s+/i.exec(sql.slice(name.end));
      const q = on && readQualified(sql, name.end + on[0].length);
      const r = q && this.resolve(q.parts);
      return r ? { type: "create-policy", key: polKey(relKey(...r), name.value) } : null;
    }

    // ---- drops
    if ((m = new RegExp(`^drop\\s+(${REL_KINDS})\\s+(?:if\\s+exists\\s+)?`, "i").exec(sql))) {
      const keys = [];
      let pos = m[0].length;
      for (;;) {
        const q = readQualified(sql, pos);
        if (!q) break;
        const r = this.resolve(q.parts);
        if (r) keys.push(relKey(...r));
        pos = skipWs(sql, q.end);
        if (sql[pos] !== ",") break;
        pos++;
      }
      return { type: "drop-relations", keys };
    }
    if ((m = /^drop\s+policy\s+(?:if\s+exists\s+)?/i.exec(sql))) {
      const name = readIdent(sql, m[0].length);
      const on = name && /^\s+on\s+/i.exec(sql.slice(name.end));
      const q = on && readQualified(sql, name.end + on[0].length);
      const r = q && this.resolve(q.parts);
      return r ? { type: "taint-policy", key: polKey(relKey(...r), name.value), remove: true } : null;
    }
    if ((m = /^drop\s+(?:function|procedure|routine)\s+(?:if\s+exists\s+)?/i.exec(sql))) {
      const keys = [];
      let pos = m[0].length;
      for (;;) {
        const q = readQualified(sql, pos);
        if (!q) break;
        const r = this.resolve(q.parts);
        if (r) keys.push(relKey(...r));
        pos = skipWs(sql, skipParens(sql, q.end));
        if (sql[pos] !== ",") break;
        pos++;
      }
      return { type: "taint-functions", keys };
    }
    if ((m = /^drop\s+schema\s+(?:if\s+exists\s+)?/i.exec(sql))) {
      const schemas = [];
      let pos = m[0].length;
      for (;;) {
        const id = readIdent(sql, pos);
        if (!id) break;
        schemas.push(id.value);
        pos = skipWs(sql, id.end);
        if (sql[pos] !== ",") break;
        pos++;
      }
      return { type: "drop-schemas", schemas };
    }

    // ---- alterations that change identity or the meaning of a recorded definition
    if ((m = new RegExp(`^alter\\s+(${REL_KINDS})\\s+(?:if\\s+exists\\s+)?(?:only\\s+)?`, "i").exec(sql))) {
      const q = readQualified(sql, m[0].length);
      const r = q && this.resolve(q.parts);
      const rest = q ? sql.slice(q.end) : "";
      if (r && /^\s*\*?\s*(?:rename\s+to|set\s+schema)\b/i.test(rest)) return { type: "drop-relations", keys: [relKey(...r)] };
      return null;
    }
    if ((m = /^alter\s+policy\s+/i.exec(sql))) {
      const name = readIdent(sql, m[0].length);
      const on = name && /^\s+on\s+/i.exec(sql.slice(name.end));
      const q = on && readQualified(sql, name.end + on[0].length);
      const r = q && this.resolve(q.parts);
      return r ? { type: "taint-policy", key: polKey(relKey(...r), name.value) } : null;
    }
    if ((m = /^alter\s+(?:function|procedure|routine)\s+/i.exec(sql))) {
      const q = readQualified(sql, m[0].length);
      const r = q && this.resolve(q.parts);
      const rest = q ? sql.slice(skipParens(sql, q.end)) : "";
      if (r && /^\s*(?:rename\s+to|set\s+schema)\b/i.test(rest)) return { type: "taint-functions", keys: [relKey(...r)] };
      return null;
    }
    return null;
  }

  apply(effect, loc, { preExisting = false } = {}) {
    if (!effect) return;
    switch (effect.type) {
      case "search-path":
        this.publicFirst = effect.publicFirst;
        break;
      case "create-relation":
        if (effect.ifNotExists && preExisting) break; // statement was a no-op, the earlier definition stands
        this.relations.set(effect.key, loc);
        break;
      case "create-function":
        this.functions.set(effect.key, loc);
        break;
      case "create-policy":
        this.policies.set(effect.key, loc);
        this.taintedPolicies.delete(effect.key);
        break;
      case "drop-relations":
        for (const k of effect.keys) {
          this.relations.delete(k);
          for (const pk of [...this.policies.keys()]) if (pk.startsWith(k + sep)) this.policies.delete(pk);
        }
        break;
      case "taint-policy":
        this.policies.delete(effect.key);
        if (!effect.remove) this.taintedPolicies.add(effect.key);
        else this.taintedPolicies.delete(effect.key);
        break;
      case "taint-functions":
        for (const k of effect.keys) this.taintedFunctions.add(k);
        break;
      case "drop-schemas":
        for (const s of effect.schemas) {
          for (const map of [this.relations, this.policies, this.functions]) for (const k of [...map.keys()]) if (k.startsWith(s + ".")) map.delete(k);
          for (const k of [...this.taintedFunctions]) if (k.startsWith(s + ".")) this.taintedFunctions.delete(k);
        }
        break;
      default:
        break;
    }
  }

  relation(object) { return this.relations.get(object) ?? null; }
  policy(object, policy) {
    const k = polKey(object, policy);
    return this.taintedPolicies.has(k) ? null : this.policies.get(k) ?? null;
  }
  // Only when the catalog holds exactly one function of that name and nothing ever dropped or renamed one of that name.
  fn(schema, name, catalogCount) {
    const k = relKey(schema, name);
    if (catalogCount !== 1 || this.taintedFunctions.has(k)) return null;
    return this.functions.get(k) ?? null;
  }
}

const STATIC_POLICY_RULES = new Set(["POLICY-ALWAYS-TRUE", "USER-METADATA-POLICY", "POLICY-NO-IDENTITY", "STORAGE-BROAD-WRITE", "STORAGE-BROAD-READ"]);
const DEFINITION_RULES = new Set(["RLS-DISABLED", "RLS-NO-POLICY", "VIEW-DEFINER", "AUTH-USERS-EXPOSED", "MATVIEW-IN-API", "PROBE-FAILED"]);
const MAX_LOCATIONS = 20;

const usable = (l) => l && l.file;

// Returns the source locations of a finding as [{ file, line, endLine }], most relevant first, or [] when unknown.
//   fnCounts: Map "schema.name" -> number of functions with that name in the loaded catalog
export function locateFinding(f, index, fnCounts = new Map()) {
  const ev = f.evidence || {};
  const out = [];
  const add = (l) => { if (usable(l)) out.push({ file: l.file, line: l.line, endLine: l.endLine }); };

  if (STATIC_POLICY_RULES.has(f.rule)) {
    if (ev.policy) add(index.policy(f.object, ev.policy));
  } else if (f.rule === "POLICY-NO-RLS") {
    for (const name of ev.policies || []) { add(index.policy(f.object, name)); if (out.length) break; }
    if (!out.length) add(index.relation(f.object));
  } else if (DEFINITION_RULES.has(f.rule)) {
    add(index.relation(f.object));
  } else if (f.rule === "AUTH-INITPLAN") {
    for (const name of ev.policies || []) add(index.policy(f.object, name));
  } else if (f.rule === "DEFINER-FUNCTION" && ev.fn) {
    add(index.fn(ev.fn.schema, ev.fn.name, fnCounts.get(relKey(ev.fn.schema, ev.fn.name))));
  } else if (f.rule === "FUNC-SEARCH-PATH") {
    for (const r of ev.fns || []) add(index.fn(r.schema, r.name, fnCounts.get(relKey(r.schema, r.name))));
  }
  // de-duplicate (several policies can live in one statement range only by coincidence; same site twice adds nothing)
  const seen = new Set();
  return out.filter((l) => { const k = `${l.file}:${l.line}`; if (seen.has(k)) return false; seen.add(k); return true; }).slice(0, MAX_LOCATIONS);
}
