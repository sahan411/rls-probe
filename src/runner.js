import { Worker } from "node:worker_threads";

export const DEFAULT_TIMEOUT_SECONDS = 60;

export class AuditTimeoutError extends Error {
  constructor(seconds) {
    super(`the audit did not finish within ${seconds} second(s) and was aborted. A statement in the SQL may be blocking the sandbox, or the schema is very large; re-run with --timeout <seconds> to allow more time.`);
    this.name = "AuditTimeoutError";
    this.seconds = seconds;
  }
}

// Runs audit() / auditWithFix() in a worker thread so a time limit is enforceable: a worker is terminated even while the Postgres
// engine is stuck inside a long synchronous call (a timer on the same thread could never fire).
//   withFix: true  -> resolves { before, after, fix }; false -> resolves the audit result
export function runAudit(files, opts = {}, { withFix = false, timeoutSeconds = DEFAULT_TIMEOUT_SECONDS } = {}) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL("./audit-worker.js", import.meta.url), { workerData: { files, opts, withFix } });
    let settled = false;
    const finish = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      worker.terminate().then(() => fn(value), () => fn(value));
    };
    const timer = setTimeout(() => finish(reject, new AuditTimeoutError(timeoutSeconds)), Math.min(timeoutSeconds * 1000, 2 ** 31 - 1));
    worker.once("message", (m) => {
      if (m.ok) finish(resolve, m.result);
      else finish(reject, Object.assign(new Error(m.error.message), { stack: m.error.stack }));
    });
    worker.once("error", (e) => finish(reject, e));
    worker.once("exit", (code) => finish(reject, new Error(`the audit worker stopped unexpectedly (exit code ${code})`)));
  });
}
