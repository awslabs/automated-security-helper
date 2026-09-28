// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Mocha entry point, loaded by @vscode/test-electron inside the extension host.
 *
 * TWO GUARDS AGAINST A VACUOUS PASS
 *
 * A runner that discovers no test files, or discovers them and executes none,
 * exits 0 and reads exactly like a green suite. Both are checked: discovery must
 * find at least one compiled `*.test.js`, and the finished runner must report a
 * non-zero test count. Without the second, deleting every `test()` from a file
 * would leave this reporting success.
 */

import * as fs from 'fs';
import * as path from 'path';
import Mocha from 'mocha';

function discover(directory: string): string[] {
  const found: string[] = [];
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      found.push(...discover(full));
    } else if (entry.name.endsWith('.test.js')) {
      found.push(full);
    }
  }
  return found.sort();
}

export function run(): Promise<void> {
  const mocha = new Mocha({
    ui: 'tdd',
    color: true,
    // Generous: the first assertion waits on a real child process, and a cold
    // extension host on a loaded CI box is slow to reach the first test.
    timeout: 120_000,
  });

  const files = discover(__dirname);
  if (files.length === 0) {
    return Promise.reject(
      new Error(
        `no compiled *.test.js under ${__dirname}. A run that discovers no ` +
          'tests must fail rather than report success having executed nothing.',
      ),
    );
  }
  for (const file of files) {
    mocha.addFile(file);
  }

  return new Promise<void>((resolve, reject) => {
    try {
      const runner = mocha.run((failures) => {
        const executed = runner.stats?.tests ?? 0;
        if (executed === 0) {
          reject(
            new Error(
              `${files.length} test file(s) were loaded but 0 tests ran. ` +
                'An empty run is not a pass.',
            ),
          );
          return;
        }
        if (failures > 0) {
          reject(new Error(`${failures} of ${executed} test(s) failed`));
          return;
        }
        resolve();
      });
    } catch (error) {
      reject(error instanceof Error ? error : new Error(String(error)));
    }
  });
}
