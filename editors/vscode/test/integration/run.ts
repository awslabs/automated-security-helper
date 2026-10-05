// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Downloads a real VS Code build and runs test/integration/suite inside it, with
 * this extension loaded from source and a real CLI process behind every scan.
 *
 * WHAT IS REAL AND WHAT IS NOT
 *
 * VS Code, its extension host, the diagnostics API, command dispatch, settings
 * and `child_process` are all real. The CLI is one of two things:
 *
 *   stub (default, and what CI runs). test/integration/ash-stub.ts, behind shell
 *     wrappers named `ash` and `ashx` on the host's PATH. It replays scans captured
 *     from real `ash scan` runs (test/fixtures/scans/), exit status included.
 *   real. Set ASH_IT_REAL_ASH_DIR to a directory holding an installed `ash`, for
 *     example a virtualenv's bin/. The suite then runs genuine scans over the
 *     fixture, using `--scanners` to choose an outcome; see the suite for which.
 *
 * Both modes start with no `ashx` anywhere on PATH, so the first scan exercises
 * the ashx -> ash fallback. The suite adds one later. Both modes also get a
 * `crashing-ash` wrapper off PATH, which answers --version and then exits 1
 * having written nothing: a real ASH cannot be made to crash on demand.
 *
 * WHY THE WORKSPACE IS A TEMP COPY
 *
 * The scan writes under the folder it scans, and a report left over from a
 * previous run would let a diagnostics assertion pass without any scan having
 * run. A fresh directory per run starts empty.
 *
 * HEADLESS
 *
 * VS Code is an Electron app and needs a display. On a host without one:
 *
 *     xvfb-run -a npm run test:integration
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runTests } from '@vscode/test-electron';

function wrapper(node: string, stub: string, invokedAs: string): string {
  return `#!/bin/sh\nASH_STUB_INVOKED_AS=${invokedAs} exec "${node}" "${stub}" "$@"\n`;
}

async function main(): Promise<void> {
  // __dirname is out-integration/test/integration at run time.
  const packageRoot = path.resolve(__dirname, '..', '..', '..');
  const fixtures = path.join(packageRoot, 'test', 'fixtures');
  const stub = path.join(__dirname, 'ash-stub.js');
  const realAshDir = process.env.ASH_IT_REAL_ASH_DIR ?? '';
  const mode = realAshDir === '' ? 'stub' : 'real';

  if (process.platform === 'win32') {
    // The wrappers are POSIX shell scripts. Failing is better than a suite that
    // quietly runs nothing on the one platform it cannot serve.
    throw new Error('the integration suite needs a POSIX shell for its CLI wrappers');
  }
  if (mode === 'real' && !fs.existsSync(path.join(realAshDir, 'ash'))) {
    throw new Error(`ASH_IT_REAL_ASH_DIR is set but holds no "ash": ${realAshDir}`);
  }

  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ash-vscode-it-'));
  const workspace = path.join(scratch, 'workspace');
  const ashxDir = path.join(scratch, 'bin-ashx');
  const ashDir = mode === 'real' ? realAshDir : path.join(scratch, 'bin-ash');
  fs.mkdirSync(workspace, { recursive: true });
  fs.mkdirSync(ashxDir, { recursive: true });
  fs.copyFileSync(path.join(fixtures, 'planted_secret.py'), path.join(workspace, 'planted_secret.py'));

  if (mode === 'stub') {
    fs.mkdirSync(ashDir, { recursive: true });
    fs.writeFileSync(path.join(ashDir, 'ash'), wrapper(process.execPath, stub, 'ash'), { mode: 0o755 });
  }
  // Answers --version as ASH and then crashes, in both modes. Off PATH, so only a
  // test that configures its full path can reach it.
  const crashing = path.join(scratch, 'bin-crash', 'crashing-ash');
  fs.mkdirSync(path.dirname(crashing), { recursive: true });
  fs.writeFileSync(crashing, wrapper(process.execPath, stub, 'crash'), { mode: 0o755 });

  const scenarioFile = path.join(scratch, 'scenario.json');
  fs.writeFileSync(scenarioFile, JSON.stringify({ fixture: null, exitCode: 70 }));

  let failed = false;
  try {
    await runTests({
      version: process.env.ASH_IT_VSCODE_VERSION ?? 'stable',
      extensionDevelopmentPath: packageRoot,
      extensionTestsPath: path.join(__dirname, 'suite', 'index'),
      extensionTestsEnv: {
        ASH_IT_MODE: mode,
        ASH_IT_WORKSPACE: workspace,
        ASH_IT_ASHX_DIR: ashxDir,
        ASH_IT_ASH_DIR: ashDir,
        ASH_IT_ASHX_WRAPPER: mode === 'stub' ? wrapper(process.execPath, stub, 'ashx') : '',
        ASH_IT_CRASHING_EXECUTABLE: crashing,
        ASH_STUB_SCENARIO_FILE: scenarioFile,
        ASH_STUB_FIXTURES: fixtures,
        // ashx first, so adding one later takes over without a restart. Only the
        // system directories after it, so no `ash` or `ashx` installed on this
        // machine can answer instead of the one under test.
        PATH: [ashxDir, ashDir, '/usr/bin', '/bin'].join(path.delimiter),
      },
      launchArgs: [
        workspace,
        // Nothing else may contribute diagnostics to the files under test.
        '--disable-extensions',
        // A headless container has no GPU, and Electron's sandbox needs kernel
        // features a container usually withholds.
        '--disable-gpu',
        '--no-sandbox',
        '--disable-dev-shm-usage',
        '--disable-workspace-trust',
        // VS Code otherwise resolves the user's login-shell environment and puts
        // its PATH ahead of the one set above -- measured, it prepended ~/bin and
        // ~/.local/bin, so an installed scanner or a real `ash` on the developer's
        // machine answered instead of the one the test arranged.
        '--force-disable-user-env',
        '--user-data-dir',
        path.join(scratch, 'user-data'),
      ],
    });
  } catch (err) {
    failed = true;
    throw err;
  } finally {
    // Kept on failure so the scenario, the call log and the reports can be read.
    if (failed) {
      console.log(`integration scratch directory kept for inspection: ${scratch}`);
    } else {
      fs.rmSync(scratch, { recursive: true, force: true });
    }
  }
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.stack : error);
  process.exit(1);
});
