// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Downloads a real VS Code build and runs the suite inside it.
 *
 * WHY THE WORKSPACE IS A TEMP COPY
 *
 * The extension writes ASH output under the folder it scans, and the stub CLI
 * the suite installs writes a SARIF report there. Pointing the window at
 * `test/fixtures/workspace` would leave generated files in the repository after
 * every run, so the fixture is copied into a temp directory and the window is
 * opened on the copy. Each run therefore starts from a known-empty state --
 * which matters, because a SARIF file left over from a previous run would let
 * the diagnostics test pass without the stub ever being invoked.
 *
 * HEADLESS
 *
 * VS Code is an Electron app and needs an X display. On a headless host run this
 * under Xvfb:
 *
 *     xvfb-run -a npm test
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runTests } from '@vscode/test-electron';

async function main(): Promise<void> {
  // __dirname is out/test at run time, so the package root is two levels up.
  const extensionDevelopmentPath = path.resolve(__dirname, '../../');
  const extensionTestsPath = path.resolve(__dirname, './suite/index');
  const fixtures = path.join(extensionDevelopmentPath, 'test', 'fixtures');

  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ash-vscode-test-'));
  const workspace = path.join(scratch, 'workspace');
  fs.cpSync(path.join(fixtures, 'workspace'), workspace, { recursive: true });

  const sarifFixture = path.join(fixtures, 'ash.sarif');
  if (!fs.existsSync(sarifFixture)) {
    throw new Error(`missing SARIF fixture at ${sarifFixture}`);
  }

  // THE REAL ARTIFACT, used as a fixture alongside the hand-written one.
  //
  // The hand-written fixture pins specific lines, severities and the nonconforming
  // `Level.error` spelling -- things a real report does not conveniently contain.
  // But it is written by the same person as the parser, so it cannot reveal a
  // WRONG ASSUMPTION about the shape of real output, and it did not: reading
  // `tool.driver.name` once per run looked correct against a fixture whose driver
  // name was a scanner-ish string and whose results all came from one tool. The
  // real report has 126 results from seven scanners in one run and a driver name
  // that is the product. It would have failed on day one.
  //
  // Not copied into test/fixtures: it is 15 MB, it is already tracked, and a copy
  // would drift from the original silently -- which is the same mistake as
  // transcribing the artifact gate's tables. Read from its tracked location so the
  // test tracks whatever ASH actually emits.
  //
  // Asserted present rather than skipped over. A suite that quietly stops
  // exercising the real artifact is a suite that reports success having checked
  // the easy case only.
  const repoRoot = path.resolve(extensionDevelopmentPath, '../../');
  const realReport = path.join(
    repoRoot,
    'tests',
    'test_data',
    'outputs',
    'ash_aggregated_results.json',
  );
  if (!fs.existsSync(realReport)) {
    throw new Error(
      `missing the real ASH report at ${realReport}. The suite asserts against ` +
        'real output, not only against a hand-written fixture; without it the ' +
        'attribution tests would silently stop running. If the file moved, ' +
        'update this path rather than deleting the assertions.',
    );
  }

  try {
    await runTests({
      extensionDevelopmentPath,
      extensionTestsPath,
      // Passed to the extension host so the suite does not have to re-derive
      // paths that this file already knows.
      extensionTestsEnv: {
        ASH_TEST_SCRATCH: scratch,
        ASH_TEST_WORKSPACE: workspace,
        ASH_TEST_SARIF_FIXTURE: sarifFixture,
        ASH_TEST_REAL_REPORT: realReport,
      },
      launchArgs: [
        workspace,
        // No other extension may contribute diagnostics into the collection
        // this suite inspects.
        '--disable-extensions',
        // Required on a headless container: there is no GPU, and Electron's
        // sandbox needs kernel features a container usually withholds.
        '--disable-gpu',
        '--no-sandbox',
        '--disable-dev-shm-usage',
        // Keeps the download's user data out of $HOME.
        '--user-data-dir',
        path.join(scratch, 'user-data'),
      ],
    });
  } finally {
    // Left on disk when the run fails, so the SARIF and the stub can be
    // inspected; removed on success to avoid filling /tmp across runs.
    if (process.exitCode === undefined || process.exitCode === 0) {
      fs.rmSync(scratch, { recursive: true, force: true });
    } else {
      console.log(`test scratch directory kept for inspection: ${scratch}`);
    }
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack : error);
  process.exit(1);
});
