#!/usr/bin/env node
// Entry point of the composite GitHub Action (see action.yml). Reads the action inputs from RLS_* environment variables, runs
// the CLI, writes the step outputs to $GITHUB_OUTPUT and exits with the CLI's exit code, so a failing audit fails the step
// after its outputs, annotations and summary file have been written.
import { spawnSync } from "node:child_process";
import { appendFileSync, existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { CiInputError, buildArgs, formatOutputs, outputFiles, outputsFrom, parseInputs } from "../src/ci.js";
import { escapeData } from "../src/github.js";

const here = dirname(fileURLToPath(import.meta.url));

let inputs;
try {
  inputs = parseInputs(process.env);
} catch (e) {
  if (!(e instanceof CiInputError)) throw e;
  console.log(`::error title=rls-probe::${escapeData(e.message)}`);
  process.exit(64);
}

mkdirSync(inputs.outDir, { recursive: true });
const files = outputFiles(inputs.outDir);
// results of an earlier invocation in the same job must never be mistaken for this run's
for (const f of Object.values(files)) rmSync(f, { force: true });
const run = spawnSync(process.execPath, [join(here, "cli.mjs"), ...buildArgs(inputs)], { stdio: "inherit" });
const status = typeof run.status === "number" ? run.status : 1;
if (typeof run.status !== "number") {
  const why = run.error ? run.error.message : `terminated by signal ${run.signal}`;
  console.log(`::error title=rls-probe::${escapeData(`the audit did not complete: ${why}`)}`);
}

if (existsSync(files.json)) {
  try {
    const result = JSON.parse(readFileSync(files.json, "utf8"));
    const outputs = outputsFrom(result, inputs, { sarifWritten: existsSync(files.sarif) });
    if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, formatOutputs(outputs));
    else console.log(formatOutputs(outputs).trimEnd());
  } catch (e) {
    console.log(`::warning title=rls-probe::${escapeData(`could not write step outputs: ${e.message}`)}`);
  }
}
process.exitCode = status;
