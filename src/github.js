import { SEVERITIES } from "./checks.js";
import { sentence } from "./text.js";

// GitHub Actions workflow commands (::error / ::warning).
// Escaping follows the official implementations (actions/toolkit packages/core/src/command.ts and
// actions/runner src/Runner.Common/ActionCommand.cs):
//   message data:  %  ->  %25    \r -> %0D    \n -> %0A
//   properties:    the same, plus  : -> %3A   , -> %2C
export const escapeData = (s) => String(s ?? "").replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
export const escapeProperty = (s) => escapeData(s).replace(/:/g, "%3A").replace(/,/g, "%2C");

const RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));
const MAX_MESSAGE = 4000;

export function workflowCommand(command, properties, message) {
  const props = Object.entries(properties).filter(([, v]) => v !== undefined && v !== null && v !== "");
  return `::${command}${props.length ? " " + props.map(([k, v]) => `${k}=${escapeProperty(v)}`).join(",") : ""}::${escapeData(message)}`;
}

const positive = (n) => Number.isInteger(n) && n > 0;

// One command per finding at MEDIUM or above: ::error for CRITICAL and HIGH, ::warning for MEDIUM.
// file / line / endLine are attached only when the finding carries a verified source location.
export function findingCommands(findings, { minSeverity = "MEDIUM" } = {}) {
  const limit = RANK[minSeverity];
  const out = [];
  for (const f of findings) {
    if (RANK[f.severity] > limit) continue;
    const loc = (f.locations || []).find((l) => l.file && positive(l.line));
    const message = `${sentence(f.title)} ${sentence(f.why)} Fix: ${f.fix}`.slice(0, MAX_MESSAGE);
    out.push(workflowCommand(RANK[f.severity] <= RANK.HIGH ? "error" : "warning", {
      title: `${f.severity} ${f.rule} ${f.object}`,
      file: loc?.file,
      line: loc ? loc.line : undefined,
      endLine: loc && positive(loc.endLine) && loc.endLine > loc.line ? loc.endLine : undefined,
    }, message));
  }
  return out;
}
