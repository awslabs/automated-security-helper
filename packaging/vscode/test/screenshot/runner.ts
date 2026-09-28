// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Launches VS Code with session.ts instead of the test suite, for capturing a
 * screenshot.
 *
 * Deliberately separate from runTest.ts rather than a flag on it: that file is
 * the gate, and a gate that can be put into a mode where it holds a window open
 * for 45 seconds and asserts less is a gate with a second, weaker behavior
 * nobody reviews.
 *
 * Reuses the same VS Code build test-electron already downloaded, so this costs
 * no extra network.
 *
 * Usage, on a headless host -- note the display must already exist, because the
 * capture has to attach to the same one:
 *
 *     Xvfb :99 -screen 0 1600x1000x24 &
 *     DISPLAY=:99 node out/test/screenshot/runner.js &
 *     sleep 30 && DISPLAY=:99 import -window root shot.png
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runTests } from '@vscode/test-electron';

async function main(): Promise<void> {
  // __dirname is out/test/screenshot at run time.
  const extensionDevelopmentPath = path.resolve(__dirname, '../../../');
  const extensionTestsPath = path.resolve(__dirname, './session');
  const fixtures = path.join(extensionDevelopmentPath, 'test', 'fixtures');

  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ash-vscode-shot-'));
  const workspace = path.join(scratch, 'workspace');
  fs.cpSync(path.join(fixtures, 'workspace'), workspace, { recursive: true });

  console.log(`[screenshot-runner] workspace: ${workspace}`);

  await runTests({
    extensionDevelopmentPath,
    extensionTestsPath,
    extensionTestsEnv: {
      ASH_TEST_SCRATCH: scratch,
      ASH_TEST_WORKSPACE: workspace,
      ASH_TEST_SARIF_FIXTURE: path.join(fixtures, 'ash.sarif'),
      ...(process.env['ASH_SHOT_HOLD_MS'] !== undefined
        ? { ASH_SHOT_HOLD_MS: process.env['ASH_SHOT_HOLD_MS'] }
        : {}),
    },
    launchArgs: [
      workspace,
      '--disable-extensions',
      '--disable-gpu',
      '--no-sandbox',
      '--disable-dev-shm-usage',
      '--user-data-dir',
      path.join(scratch, 'user-data'),
    ],
  });

  fs.rmSync(scratch, { recursive: true, force: true });
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack : error);
  process.exit(1);
});
