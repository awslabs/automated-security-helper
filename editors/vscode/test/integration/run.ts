// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Downloads a real VS Code build and runs test/integration/suite inside it, with
 * this extension loaded and a real CLI process behind every scan.
 *
 * WHAT IS REAL AND WHAT IS NOT
 *
 * VS Code, its extension host, the diagnostics API, command dispatch, settings
 * and `child_process` are all real. The CLI is one of two things:
 *
 *   stub (default). test/integration/ash-stub.ts, behind shell wrappers named
 *     `ash` and `ashx` on the host's PATH. It replays scans captured from real
 *     `ash scan` runs (test/fixtures/scans/), exit status included.
 *   real. Set ASH_IT_REAL_ASH_DIR to a directory holding an installed ASH, for
 *     example a virtualenv's bin/, with both the v4 command (the name in
 *     scripts/e2e/cli_name.json) and the legacy `ash`. The suite then runs genuine
 *     scans over the shared e2e fixtures (tests/e2e/fixtures) and judges each one
 *     with scripts/e2e/assert_outcome.py, the verdict every install channel uses.
 *
 * Both modes start with no `ashx` anywhere on PATH, so the first scan exercises
 * the ashx -> ash fallback. The suite adds one later. In real mode the two names
 * are symlinks to the installed entry points, each in its own directory, because
 * the installed bin/ holds both and putting it on PATH would leave nothing to
 * fall back from. Both modes also get a `crashing-ash` wrapper off PATH, which
 * answers --version and then exits 1 having written nothing: a real ASH cannot be
 * made to crash on demand.
 *
 * WHERE THE EXTENSION COMES FROM
 *
 * By default it is loaded from this source tree (extensionDevelopmentPath).
 * test/integration/vsix-e2e.ts instead installs the built .vsix into an
 * extensions directory of its own and passes that directory here; the suite then
 * requires that the extension answering its commands is the installed one, at the
 * installed version. See runSuite's `installed` option.
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

/** The legacy command name the extension falls back to. Fixed: it is the v3 name. */
export const LEGACY_CLI_NAME = 'ash';

/** The extension package root, from out-integration/test/integration at run time. */
export const PACKAGE_ROOT = path.resolve(__dirname, '..', '..', '..');

/** This package's manifest. */
export function manifest(): { readonly publisher: string; readonly name: string; readonly version: string } {
  return JSON.parse(fs.readFileSync(path.join(PACKAGE_ROOT, 'package.json'), 'utf8')) as {
    publisher: string;
    name: string;
    version: string;
  };
}

/** The extension's id, publisher.name, as VS Code and its CLI name it. */
export function extensionId(): string {
  const { publisher, name } = manifest();
  return `${publisher}.${name}`;
}

/** The repository root, two levels above editors/vscode. */
export const REPO_ROOT = path.resolve(PACKAGE_ROOT, '..', '..');

/** The v4 command name, read from the one place the e2e scripts take it from. */
export function cliName(): string {
  const file = path.join(REPO_ROOT, 'scripts', 'e2e', 'cli_name.json');
  const parsed = JSON.parse(fs.readFileSync(file, 'utf8')) as { cli_name?: unknown };
  if (typeof parsed.cli_name !== 'string' || parsed.cli_name === '') {
    throw new Error(`${file} names no cli_name`);
  }
  return parsed.cli_name;
}

export interface SuiteOptions {
  /** Directory holding an installed ASH; empty runs the stub. */
  readonly realAshDir: string;
  /**
   * Run against an extension installed into this extensions directory, which
   * must hold it at `version`, instead of the source tree.
   */
  readonly installed?: { readonly extensionsDir: string; readonly version: string };
  /** The cases file the real suite judges scans against. Default: the shared one. */
  readonly casesFile?: string;
  /** Where index.ts writes the run's test count and failures, as JSON. */
  readonly resultsFile?: string;
  /** Prefix for the scratch directory. */
  readonly label?: string;
}

/**
 * An empty extension to stand in as extensionDevelopmentPath, which runTests
 * requires, when the extension under test is an installed one.
 */
function hostExtension(scratch: string): string {
  const dir = path.join(scratch, 'host-extension');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(
    path.join(dir, 'package.json'),
    JSON.stringify({ name: 'ash-it-host', publisher: 'ash-it', version: '0.0.1', engines: { vscode: '^1.85.0' } }),
  );
  return dir;
}

/** Launch arguments every run here shares. */
function hostLaunchArgs(scratch: string): string[] {
  return [
    // A headless container has no GPU, and Electron's sandbox needs kernel
    // features a container usually withholds.
    '--disable-gpu',
    '--no-sandbox',
    '--disable-dev-shm-usage',
    '--disable-workspace-trust',
    // VS Code otherwise resolves the user's login-shell environment and puts
    // its PATH ahead of the one set below -- measured, it prepended ~/bin and
    // ~/.local/bin, so an installed scanner or a real `ash` on the developer's
    // machine answered instead of the one the test arranged.
    '--force-disable-user-env',
    '--user-data-dir',
    path.join(scratch, 'user-data'),
  ];
}

/**
 * Starts VS Code on an extensions directory an extension was uninstalled from and
 * requires that it does not load. See test/integration/absent/index.ts.
 */
export async function runAbsenceCheck(extensionsDir: string, id: string, resultsFile = ''): Promise<void> {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ash-vscode-absent-'));
  await runTests({
    version: process.env.ASH_IT_VSCODE_VERSION ?? 'stable',
    extensionDevelopmentPath: hostExtension(scratch),
    extensionTestsPath: path.join(__dirname, 'absent', 'index'),
    extensionTestsEnv: { ASH_IT_EXPECT_ABSENT_ID: id, ASH_IT_RESULTS_FILE: resultsFile },
    launchArgs: ['--extensions-dir', extensionsDir, ...hostLaunchArgs(scratch)],
  });
  fs.rmSync(scratch, { recursive: true, force: true });
}

function wrapper(node: string, stub: string, invokedAs: string): string {
  return `#!/bin/sh\nASH_STUB_INVOKED_AS=${invokedAs} exec "${node}" "${stub}" "$@"\n`;
}

/** An absolute path to the named program on PATH, or the name itself. */
function onPath(name: string): string {
  for (const dir of (process.env.PATH ?? '').split(path.delimiter)) {
    const candidate = path.join(dir, name);
    if (dir !== '' && fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return name;
}

/** Runs the suite once. Rejects when VS Code exits non-zero, which a failed test causes. */
export async function runSuite(options: SuiteOptions): Promise<void> {
  const fixtures = path.join(PACKAGE_ROOT, 'test', 'fixtures');
  const stub = path.join(__dirname, 'ash-stub.js');
  const realAshDir = options.realAshDir;
  const mode = realAshDir === '' ? 'stub' : 'real';
  const cli = cliName();

  if (process.platform === 'win32') {
    // The wrappers are POSIX shell scripts. Failing is better than a suite that
    // quietly runs nothing on the one platform it cannot serve.
    throw new Error('the integration suite needs a POSIX shell for its CLI wrappers');
  }
  if (mode === 'real') {
    for (const name of [cli, LEGACY_CLI_NAME]) {
      if (!fs.existsSync(path.join(realAshDir, name))) {
        throw new Error(`ASH_IT_REAL_ASH_DIR is set but holds no "${name}": ${realAshDir}`);
      }
    }
  }
  if (options.installed !== undefined && mode !== 'real') {
    throw new Error('an installed extension is only tested against a real ASH');
  }

  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), `${options.label ?? 'ash-vscode-it'}-`));
  const workspace = path.join(scratch, 'workspace');
  const ashxDir = path.join(scratch, 'bin-ashx');
  const ashDir = path.join(scratch, 'bin-ash');
  fs.mkdirSync(workspace, { recursive: true });
  fs.mkdirSync(ashxDir, { recursive: true });
  fs.mkdirSync(ashDir, { recursive: true });
  if (mode === 'stub') {
    fs.copyFileSync(path.join(fixtures, 'planted_secret.py'), path.join(workspace, 'planted_secret.py'));
    fs.writeFileSync(path.join(ashDir, LEGACY_CLI_NAME), wrapper(process.execPath, stub, 'ash'), {
      mode: 0o755,
    });
  } else {
    fs.symlinkSync(path.join(realAshDir, LEGACY_CLI_NAME), path.join(ashDir, LEGACY_CLI_NAME));
  }
  // Answers --version as ASH and then crashes, in both modes. Off PATH, so only a
  // test that configures its full path can reach it.
  const crashing = path.join(scratch, 'bin-crash', 'crashing-ash');
  fs.mkdirSync(path.dirname(crashing), { recursive: true });
  fs.writeFileSync(crashing, wrapper(process.execPath, stub, 'crash'), { mode: 0o755 });

  // Real mode only, and off PATH: the installed ASH behind a shell that answers the
  // --version probe at once and sleeps before a scan. A real scan of the fixture
  // finishes in about two seconds -- measured, it beat the timeout test's 2s limit --
  // so the timeout test cannot rely on a genuine scan being slow.
  const slow = path.join(scratch, 'bin-slow', 'slow-ash');
  if (mode === 'real') {
    fs.mkdirSync(path.dirname(slow), { recursive: true });
    const real = path.join(realAshDir, cli);
    fs.writeFileSync(
      slow,
      `#!/bin/sh\nif [ "$1" = "--version" ]; then exec "${real}" "$@"; fi\nsleep 120\nexec "${real}" "$@"\n`,
      { mode: 0o755 },
    );
  }

  const scenarioFile = path.join(scratch, 'scenario.json');
  fs.writeFileSync(scenarioFile, JSON.stringify({ fixture: null, exitCode: 70 }));

  // The source tree is the development extension unless an installed one is under
  // test. extensionDevelopmentPath is mandatory, so the installed run gets an empty
  // extension of its own there: loading this tree as well would register every
  // command twice, and which copy answered would be a race.
  let developmentPath = PACKAGE_ROOT;
  const launchArgs: string[] = [workspace];
  if (options.installed === undefined) {
    // Nothing else may contribute diagnostics to the files under test.
    launchArgs.push('--disable-extensions');
  } else {
    developmentPath = hostExtension(scratch);
    // Not --disable-extensions, which would disable the installed extension under
    // test. This directory holds that extension and nothing else; vsix-e2e.ts
    // checks its listing before every run.
    launchArgs.push('--extensions-dir', options.installed.extensionsDir);
  }
  launchArgs.push(...hostLaunchArgs(scratch));

  let failed = false;
  try {
    await runTests({
      version: process.env.ASH_IT_VSCODE_VERSION ?? 'stable',
      extensionDevelopmentPath: developmentPath,
      extensionTestsPath: path.join(__dirname, 'suite', 'index'),
      extensionTestsEnv: {
        ASH_IT_MODE: mode,
        ASH_IT_CLI_NAME: cli,
        ASH_IT_WORKSPACE: workspace,
        ASH_IT_ASHX_DIR: ashxDir,
        ASH_IT_ASH_DIR: ashDir,
        ASH_IT_REAL_ASH_DIR: realAshDir,
        ASH_IT_ASHX_WRAPPER: mode === 'stub' ? wrapper(process.execPath, stub, 'ashx') : '',
        ASH_IT_CRASHING_EXECUTABLE: crashing,
        ASH_IT_SLOW_EXECUTABLE: mode === 'real' ? slow : '',
        ASH_IT_E2E_FIXTURES: path.join(REPO_ROOT, 'tests', 'e2e', 'fixtures'),
        ASH_IT_CASES_FILE:
          options.casesFile ?? path.join(REPO_ROOT, 'tests', 'e2e', 'fixtures', 'cases.json'),
        ASH_IT_ASSERT_OUTCOME: path.join(REPO_ROOT, 'scripts', 'e2e', 'assert_outcome.py'),
        // Resolved here, on the caller's PATH, because the extension host's PATH
        // below is deliberately narrow.
        ASH_IT_PYTHON: process.env.ASH_IT_PYTHON ?? onPath('python3'),
        ASH_IT_EXTENSION_ID: extensionId(),
        ASH_IT_EXTENSIONS_DIR: options.installed?.extensionsDir ?? '',
        ASH_IT_EXPECT_VERSION: options.installed?.version ?? '',
        ASH_IT_RESULTS_FILE: options.resultsFile ?? '',
        ASH_STUB_SCENARIO_FILE: scenarioFile,
        ASH_STUB_FIXTURES: fixtures,
        // ashx first, so adding one later takes over without a restart. Only the
        // system directories after it, so no `ash` or `ashx` installed on this
        // machine can answer instead of the one under test.
        PATH: [ashxDir, ashDir, '/usr/bin', '/bin'].join(path.delimiter),
      },
      launchArgs,
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

if (require.main === module) {
  runSuite({ realAshDir: process.env.ASH_IT_REAL_ASH_DIR ?? '' }).catch((error: unknown) => {
    console.error(error instanceof Error ? error.stack : error);
    process.exit(1);
  });
}
