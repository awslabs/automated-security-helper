// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Writes and verifies the committed buildspec files.
 *
 * Two modes:
 *
 *   node lib/buildspec-cli.js write   Rewrite the committed files.
 *   node lib/buildspec-cli.js check   Byte-compare the committed files against
 *                                     a fresh render; exit 1 on any difference.
 *
 * `check` exists so a CI drift gate does not have to shell out to git or reason
 * about the working tree. It reads the files as bytes and compares them to the
 * bytes the generator produces right now, which is the whole question the gate
 * is asking.
 *
 * Not exported from `index.ts`: this is tooling, not API.
 */

import * as fs from 'fs';
import * as path from 'path';
import { generatedBuildspecs } from './private/buildspec';

/** Package root, one level above the compiled `lib` directory. */
const PACKAGE_ROOT = path.resolve(__dirname, '..');

function write(): number {
  for (const spec of generatedBuildspecs()) {
    const target = path.join(PACKAGE_ROOT, spec.filename);
    fs.writeFileSync(target, spec.contents, { encoding: 'utf8' });
    process.stdout.write(`wrote ${spec.filename}\n`);
  }
  return 0;
}

function check(): number {
  const problems: string[] = [];

  for (const spec of generatedBuildspecs()) {
    const target = path.join(PACKAGE_ROOT, spec.filename);

    if (!fs.existsSync(target)) {
      problems.push(`${spec.filename}: missing`);
      continue;
    }

    // Compare bytes, not parsed YAML. A gate that compares parsed documents
    // passes when the committed file has been reformatted or re-commented by
    // hand, which is exactly the drift it is meant to catch.
    const onDisk = fs.readFileSync(target);
    const expected = Buffer.from(spec.contents, 'utf8');

    if (!onDisk.equals(expected)) {
      problems.push(
        `${spec.filename}: differs from generated output ` +
          `(on disk ${onDisk.length} bytes, generated ${expected.length} bytes)`,
      );
    }
  }

  if (problems.length > 0) {
    process.stderr.write('Generated buildspecs are out of date:\n');
    for (const problem of problems) {
      process.stderr.write(`  ${problem}\n`);
    }
    process.stderr.write(
      '\nRegenerate with:\n  cd deploy/cdk-constructs && npm ci && npm run generate:buildspec\n',
    );
    return 1;
  }

  process.stdout.write(
    `${generatedBuildspecs().length} generated buildspec(s) match the source of truth.\n`,
  );
  return 0;
}

function main(argv: string[]): number {
  const mode = argv[2];

  switch (mode) {
    case 'write':
      return write();
    case 'check':
      return check();
    default:
      process.stderr.write(`usage: ${path.basename(argv[1])} <write|check>\n`);
      return 2;
  }
}

process.exitCode = main(process.argv);
