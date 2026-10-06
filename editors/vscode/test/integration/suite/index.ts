// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Mocha entry point, loaded by @vscode/test-electron inside the extension host.
 *
 * Two guards against a vacuous pass. A runner that discovers no test files, or
 * loads them and executes none, exits 0 and reads exactly like a green suite, so
 * discovery must find at least one compiled `*.test.js` and the finished run must
 * report a non-zero test count.
 *
 * When ASH_IT_RESULTS_FILE is set, the run's test count and each failure's title
 * and message are written there as JSON. test/integration/vsix-e2e.ts reads it for
 * its negative control, which has to show a run failing for the reason it planted
 * and not merely failing.
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

  const failed: { title: string; message: string }[] = [];
  return new Promise<void>((resolve, reject) => {
    const runner = mocha.run((failures) => {
      const executed = runner.stats?.tests ?? 0;
      const resultsFile = process.env.ASH_IT_RESULTS_FILE ?? '';
      if (resultsFile !== '') {
        fs.writeFileSync(resultsFile, JSON.stringify({ executed, failures: failed }, null, 2));
      }
      if (executed === 0) {
        reject(new Error(`${files.length} test file(s) loaded but 0 tests ran`));
      } else if (failures > 0) {
        reject(new Error(`${failures} of ${executed} integration test(s) failed`));
      } else {
        resolve();
      }
    });
    runner.on('fail', (test, err: unknown) => {
      failed.push({
        title: test.fullTitle(),
        message: err instanceof Error ? err.message : String(err),
      });
    });
  });
}
