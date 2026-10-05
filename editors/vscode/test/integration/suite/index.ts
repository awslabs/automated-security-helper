// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Mocha entry point, loaded by @vscode/test-electron inside the extension host.
 *
 * Two guards against a vacuous pass. A runner that discovers no test files, or
 * loads them and executes none, exits 0 and reads exactly like a green suite, so
 * discovery must find at least one compiled `*.test.js` and the finished run must
 * report a non-zero test count.
 */

import * as fs from 'fs';
import * as path from 'path';
import Mocha from 'mocha';

export function run(): Promise<void> {
  const mocha = new Mocha({ ui: 'tdd', color: true, timeout: 120_000 });

  const files = fs
    .readdirSync(__dirname)
    .filter((name) => name.endsWith('.test.js'))
    .sort()
    .map((name) => path.join(__dirname, name));
  if (files.length === 0) {
    return Promise.reject(new Error(`no compiled *.test.js under ${__dirname}`));
  }
  for (const file of files) {
    mocha.addFile(file);
  }

  return new Promise<void>((resolve, reject) => {
    const runner = mocha.run((failures) => {
      const executed = runner.stats?.tests ?? 0;
      if (executed === 0) {
        reject(new Error(`${files.length} test file(s) loaded but 0 tests ran`));
      } else if (failures > 0) {
        reject(new Error(`${failures} of ${executed} integration test(s) failed`));
      } else {
        resolve();
      }
    });
  });
}
