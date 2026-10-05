// Worker-thread entry used by src/runner.js. Not a public API.
import { parentPort, workerData } from "node:worker_threads";
import { audit, auditWithFix } from "./audit.js";

try {
  const { files, opts, withFix } = workerData;
  const result = withFix ? await auditWithFix(files, opts) : await audit(files, opts);
  parentPort.postMessage({ ok: true, result });
} catch (e) {
  parentPort.postMessage({ ok: false, error: { message: String(e?.message ?? e), stack: e?.stack } });
}
