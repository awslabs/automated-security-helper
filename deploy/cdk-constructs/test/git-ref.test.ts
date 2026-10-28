// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * The ASH ref is a tag, a branch name or a commit id before pip or uvx sees it.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The ref reaches git through the installer. pip clones the repository and then
 * runs `git show-ref <ref>` and `git checkout -q <ref>`, with the ref as its own
 * argument (measured with pip 25.0.1 and 21.3.1). git reads an argument that
 * starts with `-` as an option, so a ref of `-f` made `git checkout -q -f`
 * succeed and pip went on to build the default branch instead of failing. uv puts
 * the ref inside a refspec (`+refs/tags/<ref>:...`), so it never starts an
 * argument there, but the same check runs for both installers.
 *
 * A literal ref is checked when the construct or the generator renders it. A ref
 * deferred to a build environment variable (`$ASH_VERSION` in the generated
 * buildspecs) is checked by a shell command that runs before the installer.
 * These tests run one table of refs through both checks, so the two cannot
 * accept different things.
 */

import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { DEFAULT_ASH_REPOSITORY, installCommands } from '../src/private/commands';
import { ASHInstallMode } from '../src';
import { synthesizeWithStep } from './helpers';

/** Refs the checks accept: tags, branch names with slashes, and commit ids. */
const ACCEPTED = [
  'v3.7.0',
  'v1.2.3-rc.1',
  'main',
  'feature/x',
  'users/name/topic-1',
  'eddfeecf9adb672023ab7998688d54199b0a0441', // pragma: allowlist secret
];

/** Refs the checks refuse. The first two start with '-'. */
const REFUSED = [
  '-f',
  '--orphan',
  '-',
  '..',
  'v1..2',
  '.hidden',
  'feature/.hidden',
  'release.lock',
  'feature/x.lock/y',
  'a//b',
  '/abs',
  'trailing/',
  'trailing.',
  'has space',
  'semi;colon',
  'x@{1}',
  '--upload-pack=touch-marker',
];

function pip(version: string) {
  return installCommands({
    mode: ASHInstallMode.PIP,
    version,
    sourceRepository: DEFAULT_ASH_REPOSITORY,
  });
}

interface InstallRun {
  readonly status: number | null;
  readonly stderr: string;
  /** Every argv the stand-in `python3` and `uvx` were called with. */
  readonly installerCalls: string[];
}

/**
 * Run an install phase the way CodeBuild does: one shell, stopping at the first
 * failing command. `python3` and `uvx` are stand-ins that record their arguments.
 */
function runInstall(commands: string[], env: Record<string, string>): InstallRun {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ash-ref-'));
  try {
    const bin = path.join(dir, 'bin');
    fs.mkdirSync(bin);
    const log = path.join(dir, 'installer.log');
    for (const tool of ['python3', 'uvx']) {
      fs.writeFileSync(
        path.join(bin, tool),
        `#!/bin/sh\nprintf '%s\\n' "$(basename "$0") $*" >> '${log}'\n`,
        { mode: 0o755 },
      );
    }
    const script = commands
      .map((command) => `${command}\nash_rc=$?; [ "$ash_rc" -eq 0 ] || exit "$ash_rc"`)
      .join('\n');
    const run = spawnSync('sh', ['-c', script], {
      encoding: 'utf-8',
      env: { PATH: `${bin}:${process.env.PATH ?? '/usr/bin:/bin'}`, ...env },
    });
    return {
      status: run.status,
      stderr: run.stderr,
      installerCalls: fs.existsSync(log)
        ? fs.readFileSync(log, 'utf-8').split('\n').filter((line) => line !== '')
        : [],
    };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

describe('a literal ref is checked when it is rendered', () => {
  test.each(ACCEPTED)('accepts %s', (ref) => {
    expect(pip(ref)).toEqual([
      'python3 -m pip install --no-cache-dir --disable-pip-version-check ' +
        `"git+${DEFAULT_ASH_REPOSITORY}@${ref}"`,
    ]);
  });

  test.each(REFUSED)('refuses %j', (ref) => {
    expect(() => pip(ref)).toThrow(/version must be/);
  });

  test('ASHScanStep refuses a version that starts with -', () => {
    expect(() => synthesizeWithStep({ version: '-f' })).toThrow(/version must be/);
  });
});

describe('a ref deferred to an environment variable is checked before the installer runs', () => {
  test.each(ACCEPTED)('pip installs %s', (ref) => {
    const run = runInstall(pip('$ASH_VERSION'), { ASH_VERSION: ref });
    expect({ status: run.status, calls: run.installerCalls }).toEqual({
      status: 0,
      calls: [
        'python3 -m pip install --no-cache-dir --disable-pip-version-check ' +
          `git+${DEFAULT_ASH_REPOSITORY}@${ref}`,
      ],
    });
  });

  test.each(REFUSED)('pip never sees %j', (ref) => {
    const run = runInstall(pip('$ASH_VERSION'), { ASH_VERSION: ref });
    expect(run.installerCalls).toEqual([]);
    expect(run.status).not.toBe(0);
    expect(run.stderr).toContain('ASH_VERSION must be');
  });

  test('an unset variable is refused', () => {
    const run = runInstall(pip('$ASH_VERSION'), {});
    expect({ status: run.status === 0, calls: run.installerCalls }).toEqual({
      status: false,
      calls: [],
    });
  });

  test('the check names the variable the ref comes from', () => {
    const run = runInstall(pip('$MY_ASH_REF'), { MY_ASH_REF: '-f', ASH_VERSION: 'v3.7.0' });
    expect(run.installerCalls).toEqual([]);
    expect(run.stderr).toContain('MY_ASH_REF must be');
  });

  test.each(REFUSED)('the uvx install phase refuses %j', (ref) => {
    const commands = installCommands({
      mode: ASHInstallMode.UVX,
      version: '$ASH_VERSION',
      sourceRepository: DEFAULT_ASH_REPOSITORY,
    });
    expect(commands.length).toBeGreaterThan(0);
    const run = runInstall(commands, { ASH_VERSION: ref });
    expect(run.status).not.toBe(0);
  });

  test.each(ACCEPTED)('the uvx install phase accepts %s', (ref) => {
    const commands = installCommands({
      mode: ASHInstallMode.UVX,
      version: '$ASH_VERSION',
      sourceRepository: DEFAULT_ASH_REPOSITORY,
    });
    expect(runInstall(commands, { ASH_VERSION: ref }).status).toBe(0);
  });

  test('a literal ref needs no runtime check, and PREINSTALLED installs nothing', () => {
    expect(
      installCommands({
        mode: ASHInstallMode.UVX,
        version: 'v3.7.0',
        sourceRepository: DEFAULT_ASH_REPOSITORY,
      }),
    ).toEqual([]);
    expect(
      installCommands({
        mode: ASHInstallMode.PREINSTALLED,
        version: '$ASH_VERSION',
        sourceRepository: DEFAULT_ASH_REPOSITORY,
      }),
    ).toEqual([]);
  });

  test('ASHScanStep checks a deferred ref in every project it creates', () => {
    const { template } = synthesizeWithStep({ version: '$ASH_REF', shardCount: 2 });
    const projects = Object.values(template.findResources('AWS::CodeBuild::Project')).filter(
      (project: any) => String(project.Properties.Source.BuildSpec).includes('pip install'),
    );
    expect(projects.length).toBe(3);
    for (const project of projects as any[]) {
      const spec = JSON.parse(project.Properties.Source.BuildSpec);
      const run = runInstall(spec.phases.install.commands, { ASH_REF: '-f' });
      expect({ status: run.status === 0, calls: run.installerCalls }).toEqual({
        status: false,
        calls: [],
      });
    }
  });
});
