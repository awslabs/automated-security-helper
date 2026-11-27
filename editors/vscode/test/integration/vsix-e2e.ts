// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * The VS Code channel end to end: the built .vsix installed into a real VS Code
 * with its own CLI, the real-mode suite run against that installed copy and a
 * real ASH, then upgrade and uninstall.
 *
 *   ASH_IT_REAL_ASH_DIR  a bin/ directory holding the installed ASH (ashx and ash)
 *   ASH_IT_VSIX          the .vsix under test (N); default ash-vscode.vsix here
 *   ASH_IT_VSCODE_VERSION  the VS Code build; default stable
 *
 *     xvfb-run -a npm run test:e2e-vsix
 *
 * WHAT IT DOES, IN ORDER
 *
 * 1. Builds an N-1 .vsix from this tree with the version lowered, through
 *    `vsce package <version> --no-update-package-json`, so package.json is never
 *    rewritten. It is the same code under a lower version, which is what makes an
 *    install of N over it an upgrade rather than a reinstall.
 * 2. Negative control for the install step: a truncated copy of N must be refused
 *    by `code --install-extension`, and the extensions directory must stay empty.
 * 3. Fresh install of N into an empty extensions directory, listed with
 *    `--list-extensions --show-versions` and required to be exactly id@N. Then the
 *    real-mode suite against that installed copy: the suite's suiteSetup requires
 *    the extension answering its commands to be loaded from that directory at that
 *    version, and every scan is judged by scripts/e2e/assert_outcome.py.
 * 4. Negative control for the suite: the same run against a copy of cases.json
 *    whose findings case expects one finding more than the fixture has must fail,
 *    and must fail through assert_outcome's verdict, read back from the results
 *    file index.ts writes. A suite that passed it would be checking nothing.
 * 5. Uninstall of N. The listing must be empty, and a VS Code started on that
 *    extensions directory must not load the extension or register its commands
 *    (test/integration/absent/index.ts). That check is first run while N is still
 *    installed, where it must fail.
 * 6. Upgrade, in a second empty extensions directory: install N-1, list id@N-1,
 *    install N over it, list exactly id@N, and run the suite again so the upgraded
 *    install is shown loading N and scanning. Then uninstall it too.
 *
 * Nothing is published. Both archives stay in the scratch directory, and N-1
 * carries a version that was never released.
 */

import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { downloadAndUnzipVSCode, resolveCliPathFromVSCodeExecutablePath } from '@vscode/test-electron';
import { PACKAGE_ROOT, REPO_ROOT, extensionId, manifest, runAbsenceCheck, runSuite } from './run';

function say(message: string): void {
  console.log(`== ${message}`);
}

function fail(message: string): never {
  throw new Error(`FAIL: ${message}`);
}

/** The N-1 version: one minor lower, or one major lower at minor 0. */
export function previousVersion(version: string): string {
  const match = /^(\d+)\.(\d+)\.(\d+)$/.exec(version);
  if (match === null) {
    fail(`package.json version ${version} is not MAJOR.MINOR.PATCH`);
  }
  const [major, minor] = [Number(match[1]), Number(match[2])];
  if (minor > 0) {
    return `${major}.${minor - 1}.0`;
  }
  if (major > 0) {
    return `${major - 1}.0.0`;
  }
  fail(`there is no version below ${version} to build N-1 at`);
}

interface Cli {
  readonly path: string;
  readonly userDataDir: string;
}

function code(cli: Cli, extensionsDir: string, args: readonly string[]): { status: number | null; output: string } {
  const result = spawnSync(
    cli.path,
    ['--extensions-dir', extensionsDir, '--user-data-dir', cli.userDataDir, ...args],
    { encoding: 'utf8' },
  );
  return {
    status: result.status,
    output: `${result.stdout ?? ''}${result.stderr ?? ''}${result.error?.message ?? ''}`,
  };
}

/** The extensions VS Code's CLI lists for one extensions directory, as id@version. */
function listed(cli: Cli, extensionsDir: string): string[] {
  const result = code(cli, extensionsDir, ['--list-extensions', '--show-versions']);
  if (result.status !== 0) {
    fail(`--list-extensions exited ${String(result.status)}:\n${result.output}`);
  }
  return result.output
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => /^[\w.-]+@[\w.+-]+$/.test(line));
}

function expectListed(cli: Cli, extensionsDir: string, expected: readonly string[], when: string): void {
  const actual = listed(cli, extensionsDir);
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    fail(`${when}: expected ${JSON.stringify(expected)} installed, the CLI lists ${JSON.stringify(actual)}`);
  }
  say(`${when}: ${actual.length === 0 ? 'nothing installed' : actual.join(', ')}`);
}

function install(cli: Cli, extensionsDir: string, vsix: string): void {
  const result = code(cli, extensionsDir, ['--install-extension', vsix]);
  if (result.status !== 0) {
    fail(`--install-extension ${vsix} exited ${String(result.status)}:\n${result.output}`);
  }
}

async function uninstall(cli: Cli, extensionsDir: string, id: string): Promise<void> {
  const result = code(cli, extensionsDir, ['--uninstall-extension', id]);
  if (result.status !== 0) {
    fail(`--uninstall-extension ${id} exited ${String(result.status)}:\n${result.output}`);
  }
  expectListed(cli, extensionsDir, [], `after uninstalling ${id}`);
  // The listing reads extensions.json, and the CLI leaves the extension's folder on
  // disk (measured with 1.140.0), so the listing alone does not show the code can no
  // longer load. A VS Code started on the directory has to come up without it.
  await runAbsenceCheck(extensionsDir, id);
  say(`after uninstalling ${id}: a VS Code started on ${path.basename(extensionsDir)} does not load it`);
  const left = extensionFolders(extensionsDir, id);
  say(`after that start, ${left.length === 0 ? 'no folder' : left.join(', ')} left for ${id}`);
}

function extensionFolders(extensionsDir: string, id: string): string[] {
  return fs
    .readdirSync(extensionsDir)
    .filter((entry) => entry.toLowerCase().startsWith(`${id.toLowerCase()}-`))
    .filter((entry) => fs.statSync(path.join(extensionsDir, entry)).isDirectory());
}

interface Results {
  readonly executed: number;
  readonly failures: readonly { readonly title: string; readonly message: string }[];
}

async function main(): Promise<void> {
  const realAshDir = process.env.ASH_IT_REAL_ASH_DIR ?? '';
  if (realAshDir === '') {
    fail('ASH_IT_REAL_ASH_DIR must name the bin/ directory of an installed ASH');
  }
  const vsix = path.resolve(process.env.ASH_IT_VSIX ?? path.join(PACKAGE_ROOT, 'ash-vscode.vsix'));
  if (!fs.existsSync(vsix)) {
    fail(`no .vsix at ${vsix}; build it with npm run package`);
  }
  const id = extensionId();
  const version = manifest().version;
  const previous = previousVersion(version);
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ash-vscode-e2e-'));
  say(`${id}: N=${version} from ${vsix}, N-1=${previous}; scratch ${scratch}`);

  say(`building the N-1 .vsix at ${previous}`);
  const n1 = path.join(scratch, `ash-vscode-${previous}.vsix`);
  const built = spawnSync(
    'npx',
    ['--no-install', 'vsce', 'package', previous, '--no-update-package-json', '--out', n1],
    { cwd: PACKAGE_ROOT, encoding: 'utf8' },
  );
  if (built.status !== 0 || !fs.existsSync(n1)) {
    fail(`vsce package ${previous} exited ${String(built.status)}:\n${built.stdout}${built.stderr}`);
  }
  if (manifest().version !== version) {
    fail(`building N-1 rewrote package.json's version to ${manifest().version}`);
  }

  const executable = await downloadAndUnzipVSCode(process.env.ASH_IT_VSCODE_VERSION ?? 'stable');
  const cli: Cli = {
    path: resolveCliPathFromVSCodeExecutablePath(executable),
    userDataDir: path.join(scratch, 'cli-user-data'),
  };

  // 2. A damaged archive must be refused, or a green install below proves nothing.
  const fresh = path.join(scratch, 'extensions-fresh');
  fs.mkdirSync(fresh);
  expectListed(cli, fresh, [], 'before any install');
  const truncated = path.join(scratch, 'truncated.vsix');
  const bytes = fs.readFileSync(vsix);
  fs.writeFileSync(truncated, bytes.subarray(0, Math.floor(bytes.length / 2)));
  const refused = code(cli, fresh, ['--install-extension', truncated]);
  if (refused.status === 0) {
    fail(`a truncated .vsix installed with exit 0:\n${refused.output}`);
  }
  say(`negative control: a truncated .vsix was refused with exit ${String(refused.status)}`);
  expectListed(cli, fresh, [], 'after the refused install');

  // 3. Fresh install of N, and the suite against it.
  install(cli, fresh, vsix);
  expectListed(cli, fresh, [`${id}@${version}`], 'after a fresh install of N');
  say('real-mode suite against the freshly installed N');
  await runSuite({
    realAshDir,
    installed: { extensionsDir: fresh, version },
    label: 'ash-vscode-e2e-fresh',
  });

  // 4. The suite has to be able to fail, and through the shared verdict.
  const cases = JSON.parse(
    fs.readFileSync(path.join(REPO_ROOT, 'tests', 'e2e', 'fixtures', 'cases.json'), 'utf8'),
  ) as { cases: Record<string, { findings: number }> };
  const planted = cases.cases.findings.findings + 1;
  cases.cases.findings.findings = planted;
  const wrongCases = path.join(scratch, 'cases-wrong-count.json');
  fs.writeFileSync(wrongCases, JSON.stringify(cases, null, 2));
  const resultsFile = path.join(scratch, 'negative-results.json');
  say(`negative control: the suite with the findings case expecting ${planted} findings`);
  let negativePassed = false;
  try {
    await runSuite({
      realAshDir,
      installed: { extensionsDir: fresh, version },
      casesFile: wrongCases,
      resultsFile,
      label: 'ash-vscode-e2e-negative',
    });
    negativePassed = true;
  } catch {
    // Expected; what it failed on is checked below.
  }
  if (negativePassed) {
    fail(`the suite passed with the findings case expecting ${planted} findings`);
  }
  if (!fs.existsSync(resultsFile)) {
    fail('the negative run failed before its suite wrote any results, so it did not fail on the planted count');
  }
  const results = JSON.parse(fs.readFileSync(resultsFile, 'utf8')) as Results;
  const throughVerdict = results.failures.filter(
    (failure) =>
      failure.message.includes('assert_outcome rejected the findings scan') &&
      failure.message.includes(`expected exactly ${planted}`),
  );
  if (results.executed === 0 || throughVerdict.length === 0) {
    fail(
      `the negative run did not fail through assert_outcome on the planted count: ${JSON.stringify(results, null, 2)}`,
    );
  }
  say(
    `negative control: ${results.failures.length} of ${results.executed} test(s) failed, ` +
      `${throughVerdict.length} through assert_outcome ("expected exactly ${planted}")`,
  );

  // 5. Uninstall. The absence check is first run while N is still installed, where
  // it must fail, so its pass after uninstalling means something.
  let absentWhileInstalled = false;
  const absentResults = path.join(scratch, 'absent-while-installed.json');
  try {
    await runAbsenceCheck(fresh, id, absentResults);
    absentWhileInstalled = true;
  } catch {
    // Expected; what it failed on is checked below.
  }
  if (absentWhileInstalled) {
    fail(`the absence check passed with ${id} installed, so it cannot show an uninstall`);
  }
  const seen = fs.existsSync(absentResults)
    ? (JSON.parse(fs.readFileSync(absentResults, 'utf8')) as { loadedFrom: string | null })
    : { loadedFrom: null };
  if (seen.loadedFrom === null || !path.resolve(seen.loadedFrom).startsWith(path.resolve(fresh) + path.sep)) {
    fail(`the absence check failed, but not because it found ${id} loaded from ${fresh}: ${JSON.stringify(seen)}`);
  }
  say(`negative control: the absence check fails while N is installed (loaded from ${path.basename(seen.loadedFrom)})`);
  await uninstall(cli, fresh, id);

  // 6. Upgrade from N-1 to N, in a directory of its own.
  const upgrade = path.join(scratch, 'extensions-upgrade');
  fs.mkdirSync(upgrade);
  install(cli, upgrade, n1);
  expectListed(cli, upgrade, [`${id}@${previous}`], 'after installing N-1');
  install(cli, upgrade, vsix);
  expectListed(cli, upgrade, [`${id}@${version}`], 'after upgrading to N');
  say('real-mode suite against the upgraded install');
  await runSuite({
    realAshDir,
    installed: { extensionsDir: upgrade, version },
    label: 'ash-vscode-e2e-upgraded',
  });
  await uninstall(cli, upgrade, id);

  fs.rmSync(scratch, { recursive: true, force: true });
  say('OK: fresh install, scans, negative controls, uninstall and upgrade all passed');
}

if (require.main === module) {
  main().catch((error: unknown) => {
    console.error(error instanceof Error ? error.stack : error);
    process.exit(1);
  });
}
