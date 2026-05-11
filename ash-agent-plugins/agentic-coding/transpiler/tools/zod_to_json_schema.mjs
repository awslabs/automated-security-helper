#!/usr/bin/env node
// Convert a Zod schema in the Continue.dev repo to JSON Schema (Draft 7).
//
// Usage:  node tools/zod_to_json_schema.mjs <repo-clone-dir> <output-path>
//
// Steps:
//   1. cd into the cloned Continue repo
//   2. npm install (in packages/config-yaml/) to resolve the workspace deps
//   3. Compile the TypeScript source via tsc
//   4. Dynamically import the compiled JS, then zod-to-json-schema
//   5. Run zod-to-json-schema on configYamlSchema
//   6. Write Draft-07 JSON Schema to <output-path>
//
// Why a separate script: Python doesn't have a Zod parser. We delegate the
// TypeScript compilation + Zod schema introspection to Node, then the Python
// refresher just consumes the resulting JSON file.
//
// Security: all subprocess calls use execFileSync with array args (no shell
// interpolation). The repoDir argument is validated for existence; the
// outputPath argument is only used as a write target. No user input is
// interpolated into a shell command.

import { existsSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const [, , repoDirArg, outputPathArg] = process.argv;
if (!repoDirArg || !outputPathArg) {
  console.error("Usage: node zod_to_json_schema.mjs <repo-clone-dir> <output-path>");
  process.exit(2);
}

const repoDir = resolve(repoDirArg);
const outputPath = resolve(outputPathArg);

if (!existsSync(repoDir)) {
  console.error(`Repo dir does not exist: ${repoDir}`);
  process.exit(2);
}

// Continue's config-yaml package depends on workspace deps. Install once at
// the package level (not the monorepo root) — fast and contained.
const pkgDir = join(repoDir, "packages", "config-yaml");
console.error(`Installing deps in ${pkgDir}...`);
execFileSync("npm", ["install", "--no-fund", "--no-audit", "--silent"], {
  cwd: pkgDir,
  stdio: ["ignore", "ignore", "inherit"],
});

// Install zod-to-json-schema as a peer dep — pinned to a recent stable.
console.error("Installing zod-to-json-schema...");
execFileSync(
  "npm",
  ["install", "--no-save", "--no-fund", "--no-audit", "--silent", "zod-to-json-schema@3.24.5"],
  { cwd: pkgDir, stdio: ["ignore", "ignore", "inherit"] }
);

// Compile the TypeScript source so we can import it from a Node ESM context.
console.error("Compiling Continue TypeScript...");
execFileSync(
  "npx",
  [
    "-y", "tsc",
    "--module", "nodenext",
    "--moduleResolution", "nodenext",
    "--target", "es2022",
    "--outDir", ".build",
    "--rootDir", "src",
    "--skipLibCheck",
    "--strict", "false",
    "--declaration", "false",
    "--resolveJsonModule",
    "src/schemas/index.ts",
  ],
  { cwd: pkgDir, stdio: ["ignore", "ignore", "inherit"] }
);

const compiledModule = pathToFileURL(join(pkgDir, ".build", "schemas", "index.js")).href;
console.error(`Importing ${compiledModule}`);
const { configYamlSchema } = await import(compiledModule);
if (!configYamlSchema) {
  console.error("configYamlSchema not exported by the compiled module");
  process.exit(1);
}

const { zodToJsonSchema } = await import(
  pathToFileURL(join(pkgDir, "node_modules", "zod-to-json-schema", "dist", "esm", "index.js")).href
);

const jsonSchema = zodToJsonSchema(configYamlSchema, {
  name: "ContinueConfig",
  $refStrategy: "none",  // inline refs — produces a single self-contained schema
  target: "jsonSchema7",
});

writeFileSync(outputPath, JSON.stringify(jsonSchema, null, 2) + "\n", "utf8");
console.error(`Wrote ${outputPath}`);
