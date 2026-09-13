#!/usr/bin/env node
// Build the docs site. The API reference is GENERATED from contracts/openapi.v1.yaml
// (never handwritten) so it stays in sync with the contract. Steps:
//   1. lint the spec (fails the build if the contract is invalid)
//   2. bundle external $refs -> public/openapi.bundled.json (machine-readable spec)
//   3. render the static API reference -> public/api.html (Redoc, self-contained)
//   4. copy the landing + quickstart page -> public/index.html
import { execFileSync } from "node:child_process";
import { mkdirSync, copyFileSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const SPEC = resolve(HERE, "..", "contracts", "openapi.v1.yaml");
const PUBLIC = join(HERE, "public");
// Run the CLI's JS entry with node directly (no shell), so spaces in the repo path
// ("trust infra") don't break argument splitting on Windows.
const redoclyCli = join(HERE, "node_modules", "@redocly", "cli", "bin", "cli.js");

function run(args) {
  console.log(`\n$ redocly ${args.join(" ")}`);
  execFileSync(process.execPath, [redoclyCli, ...args], { stdio: "inherit", cwd: HERE });
}

mkdirSync(PUBLIC, { recursive: true });

run(["lint", SPEC]);
run(["bundle", SPEC, "-o", join(PUBLIC, "openapi.bundled.json")]);
run(["build-docs", SPEC, "-o", join(PUBLIC, "api.html")]);

copyFileSync(join(HERE, "src", "index.html"), join(PUBLIC, "index.html"));
console.log(`\ncopied src/index.html -> public/index.html`);

// Sync sanity check: the rendered reference must actually contain the contract's
// operations. Fails loudly if the generator produced an empty/stale page.
const api = readFileSync(join(PUBLIC, "api.html"), "utf8");
for (const needle of ["/v1/authorize", "ti-decision-canon/1"]) {
  if (!api.includes(needle)) {
    console.error(`\nBUILD CHECK FAILED: "${needle}" not found in public/api.html`);
    process.exit(1);
  }
}
console.log("\n✓ docs built to public/ (index.html, api.html, openapi.bundled.json)");
