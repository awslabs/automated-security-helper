// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Command-line front end for the `.vsix` contents check.
 *
 *     node out/verify-vsix.js ash-vscode.vsix
 *
 * Exits 0 when the archive carries only this extension's own output, 1 when it
 * carries anything else or is missing something it must have, and 2 when the
 * archive could not be read at all. The three codes are distinct because "the
 * artifact is wrong" and "the check could not run" must not look the same to a
 * CI step -- which is what would happen if an unreadable file produced the same
 * exit code as a clean one.
 *
 * `.vscodeignore` keeps the compiled form of this file out of the `.vsix`. It is
 * build tooling, and shipping it to users would put the checker inside the thing
 * it checks.
 */

import * as fs from 'fs';
import * as path from 'path';
import { describeProblems, inspectMembers, listZipMembers } from './vsix-contents';

export function verify(archive: string, out = process.stdout, err = process.stderr): number {
  let buffer: Buffer;
  try {
    buffer = fs.readFileSync(archive);
  } catch (readError) {
    err.write(`vsix contents: cannot read ${archive}: ${(readError as Error).message}\n`);
    return 2;
  }

  let members: string[];
  try {
    members = listZipMembers(buffer);
  } catch (parseError) {
    err.write(`vsix contents: ${archive}: ${(parseError as Error).message}\n`);
    return 2;
  }

  const verdict = inspectMembers(members);
  const problems = describeProblems(verdict);
  if (problems !== null) {
    err.write(`vsix contents check failed for ${archive}:\n${problems}\n`);
    return 1;
  }

  out.write(
    `vsix contents OK: ${archive} carries ${verdict.memberCount} member(s), all of them ` +
      'VSIX container files or this extension\'s own output.\n',
  );
  for (const member of members) {
    out.write(`  ${member}\n`);
  }
  return 0;
}

export function main(argv: readonly string[], out = process.stdout, err = process.stderr): number {
  const archive = argv[2];
  if (archive === undefined) {
    err.write(`usage: ${path.basename(argv[1] ?? 'verify-vsix.js')} <path-to.vsix>\n`);
    return 2;
  }
  return verify(archive, out, err);
}

/*
 * Only run when invoked as a program, not when imported. Without the guard,
 * requiring this module from a test would run `main` against the test runner's
 * own argv as an import side effect.
 */
if (require.main === module) {
  process.exitCode = main(process.argv);
}
