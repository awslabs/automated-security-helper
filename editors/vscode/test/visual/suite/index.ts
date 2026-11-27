// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Mocha entry point for the visual suite, loaded inside the extension host.
 *
 * The same two guards as test/integration/suite/index.ts against a vacuous pass: the
 * suite file must load, and the run must execute exactly one test per scenario in
 * test/visual/scenarios.ts. A run that silently skipped a capture would otherwise
 * exit 0 with one baseline never looked at.
 */

import * as fs from 'fs';
import * as path from 'path';
import Mocha from 'mocha';
import { VISUAL_SCENARIOS } from '../scenarios';

export function run(): Promise<void> {
  // No retries, and no bail: a mismatch in one picture leaves the workbench in the
  // state the next test expects, so every scenario is still compared and one run
  // reports every picture that changed.
  const mocha = new Mocha({ ui: 'tdd', color: false, timeout: 120_000 });
  const file = path.join(__dirname, 'snapshots.visual.js');
  if (!fs.existsSync(file)) {
    return Promise.reject(new Error(`the visual suite is not compiled: ${file}`));
  }
  mocha.addFile(file);

  const failed: { title: string; message: string }[] = [];
  return new Promise<void>((resolve, reject) => {
    const runner = mocha.run((failures) => {
      const executed = runner.stats?.tests ?? 0;
      const resultsFile = process.env.ASH_VISUAL_RESULTS_FILE ?? '';
      if (resultsFile !== '') {
        fs.writeFileSync(resultsFile, JSON.stringify({ executed, failures: failed }, null, 2));
      }
      if (failures > 0) {
        reject(new Error(`${failures} of ${executed} visual test(s) failed`));
      } else if (executed !== VISUAL_SCENARIOS.length + 1) {
        // One test per scenario plus the closing check for unused baselines.
        reject(new Error(`${executed} visual test(s) ran; expected ${VISUAL_SCENARIOS.length + 1}`));
      } else {
        resolve();
      }
    });
    runner.on('fail', (test, err: unknown) => {
      failed.push({ title: test.fullTitle(), message: err instanceof Error ? err.message : String(err) });
    });
  });
}
