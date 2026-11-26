// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * The emitted ASH commands name the scan's subject when the ASH they run has one.
 *
 * ASH 3.9 scans a directory with `ash scan fs PATH` and merges shard results with
 * `ash results merge`; the subject-less `ash scan --source-dir PATH` and the
 * top-level `ash merge` still work there but print a deprecation line, and go in
 * ASH v4.0. The ref these commands install defaults to the release this package
 * came from, which is older than 3.9 until the release commit moves it, and a
 * caller may pin any older ref. So each command asks the installed ASH whether it
 * has the new spelling and uses the old one when it does not.
 *
 * These tests run the rendered commands in a real shell against a stand-in `ash`
 * that answers the help probe as each kind of release would, and record the command
 * line the stand-in was then run with. Nothing else is on PATH but the system
 * directories, so a command that reached for a real ASH, pip or a network fails.
 */

import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { mergeBuildspec, scanBuildspec, shardBuildspec } from '../src/private/buildspec';
import {
  DEFAULT_ASH_REPOSITORY,
  InstallOptions,
  mergeCommands,
  scanCommands,
  shardScanCommands,
} from '../src/private/commands';
import { ASHInstallMode, ASHSeverityThreshold } from '../src';

/**
 * A stand-in for an installed ASH.
 *
 * `ASH_STUB_RELEASE` says which release it answers as:
 *   - `3.9`: `scan fs --help` and `results merge --help` print their usage lines;
 *   - `3.8`: `scan fs --help` prints the subject-less scan's help, as click shows a
 *     command's help before it refuses an extra argument, and `results` is not a
 *     command;
 *   - `refusing`: both probes exit 5 with nothing on stdout.
 * The help it prints runs to thousands of lines, so a probe that stopped reading
 * early would leave the stand-in writing into a closed pipe. Every other call is
 * recorded, one line per call, and exits `ASH_STUB_EXIT`.
 */
const STAND_IN_ASH = `#!/bin/sh
long_help() {
  echo "$1"
  i=0
  while [ "$i" -lt 4000 ]; do
    echo "  --option-$i TEXT  A line of help."
    i=$((i + 1))
  done
}
case "$ASH_STUB_RELEASE:$*" in
  "3.9:scan fs --help") long_help " Usage: ash scan fs [OPTIONS] [PATH]"; exit 0 ;;
  "3.9:results merge --help") long_help " Usage: ash results merge [OPTIONS]"; exit 0 ;;
  "3.8:scan fs --help") long_help " Usage: ash scan [OPTIONS]"; exit 0 ;;
  "3.8:results merge --help") echo "Error: No such command 'results'." >&2; exit 5 ;;
  "refusing:scan fs --help" | "refusing:results merge --help")
    echo "Error: not a command line this release takes." >&2; exit 5 ;;
esac
printf '%s\\n' "$*" >> "$ASH_STUB_LOG"
exit "\${ASH_STUB_EXIT:-0}"
`;

const PIP: InstallOptions = {
  mode: ASHInstallMode.PIP,
  sourceRepository: DEFAULT_ASH_REPOSITORY,
};

type Release = '3.9' | '3.8' | 'refusing';

interface Ran {
  /** The command lines the stand-in recorded, one per call. */
  readonly calls: string[];
  /** The shell's exit status. */
  readonly status: number | null;
  readonly stderr: string;
}

let workRoot: string;

beforeAll(() => {
  workRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'ash-subject-probe-'));
});

afterAll(() => {
  fs.rmSync(workRoot, { recursive: true, force: true });
});

/** Run one rendered command in a fresh directory, with the stand-in first on PATH. */
function run(
  command: string,
  release: Release,
  options: { exit?: number; env?: Record<string, string>; shell?: string[] } = {},
): Ran {
  const dir = fs.mkdtempSync(path.join(workRoot, 'run-'));
  const bin = path.join(dir, 'bin');
  fs.mkdirSync(bin);
  const ash = path.join(bin, 'ash');
  fs.writeFileSync(ash, STAND_IN_ASH, { mode: 0o755 });
  const log = path.join(dir, 'ash.log');
  const shell = options.shell ?? ['sh', '-c'];
  const result = spawnSync(shell[0], [...shell.slice(1), command], {
    cwd: dir,
    env: {
      PATH: `${bin}:/usr/bin:/bin`,
      ASH_STUB_RELEASE: release,
      ASH_STUB_LOG: log,
      ASH_STUB_EXIT: String(options.exit ?? 0),
      ...(options.env ?? {}),
    },
    encoding: 'utf8',
    timeout: 60_000,
  });
  const calls = fs.existsSync(log)
    ? fs.readFileSync(log, 'utf8').split('\n').filter((line) => line !== '')
    : [];
  return { calls, status: result.status, stderr: result.stderr };
}

/** The one command a single-command renderer produced. */
function only(commands: string[]): string {
  expect(commands).toHaveLength(1);
  return commands[0];
}

/** The environment a generated buildspec declares, as the build would see it. */
function declaredEnvironment(spec: any): Record<string, string> {
  return Object.fromEntries(
    Object.entries(spec.env.variables as Record<string, unknown>).map(([k, v]) => [
      k,
      String(v),
    ]),
  );
}

const UNSHARDED = only(
  scanCommands(
    {
      sourceDirectory: '.',
      outputDirectory: '.ash/ash_output',
      severityThreshold: ASHSeverityThreshold.LOW,
      extraScanArguments: ['--log-level', 'INFO'],
    },
    PIP,
  ),
);

const SHARD = only(
  shardScanCommands(
    {
      sourceDirectory: '.',
      outputDirectory: '.ash/ash_output/shard-1',
      shardIndex: '1',
      shardCount: '3',
      severityThreshold: ASHSeverityThreshold.LOW,
      extraScanArguments: [],
    },
    PIP,
  ),
);

const MERGE = only(
  mergeCommands(['out/shard-0', 'out/shard-1'], '.ash/ash_output', ASHSeverityThreshold.HIGH, PIP),
);

describe('the unsharded scan names its subject on an ASH that has one', () => {
  test('an ASH with `scan fs` is given the directory as the subject\'s argument', () => {
    const ran = run(UNSHARDED, '3.9');
    expect(ran.calls).toEqual([
      'scan fs . --output-dir .ash/ash_output --min-severity low --fail-on-findings --log-level INFO',
    ]);
    expect(ran.status).toBe(0);
  });

  test.each<Release>(['3.8', 'refusing'])(
    'an ASH without `scan fs` (%s) is given --source-dir',
    (release) => {
      const ran = run(UNSHARDED, release);
      expect(ran.calls).toEqual([
        'scan --source-dir . --output-dir .ash/ash_output --min-severity low --fail-on-findings --log-level INFO',
      ]);
    },
  );

  test.each<Release>(['3.9', '3.8'])('the scan\'s exit status is the step\'s (%s)', (release) => {
    // The verdict: findings exit 2, and the probe in front must not change that.
    expect(run(UNSHARDED, release, { exit: 2 }).status).toBe(2);
    expect(run(UNSHARDED, release, { exit: 1 }).status).toBe(1);
  });

  test('the probe reads the whole help under pipefail, so it still finds the subject', () => {
    // grep -q stops at the first match and leaves ASH writing into a closed pipe;
    // under pipefail that pipe's failure would read as an ASH without the subject.
    const ran = run(UNSHARDED, '3.9', { shell: ['bash', '-o', 'pipefail', '-c'] });
    expect(ran.calls).toEqual([
      'scan fs . --output-dir .ash/ash_output --min-severity low --fail-on-findings --log-level INFO',
    ]);
  });
});

describe('a shard names its subject on an ASH that has one', () => {
  test('`scan fs` with the directory, then the shard options', () => {
    expect(run(SHARD, '3.9').calls).toEqual([
      'scan fs . --output-dir .ash/ash_output/shard-1 --shard-index 1 --shard-count 3 --no-fail-on-findings',
    ]);
  });

  test('--source-dir on an ASH without the subject', () => {
    expect(run(SHARD, '3.8').calls).toEqual([
      'scan --source-dir . --output-dir .ash/ash_output/shard-1 --shard-index 1 --shard-count 3 --no-fail-on-findings',
    ]);
  });
});

describe('the merge uses `ash results merge` on an ASH that has it', () => {
  test('`results merge` on an ASH with the results group', () => {
    const ran = run(MERGE, '3.9', { exit: 2 });
    expect(ran.calls).toEqual([
      'results merge --results out/shard-0 --results out/shard-1 --output-dir .ash/ash_output --min-severity high',
    ]);
    // The merge's exit status is the pipeline's verdict.
    expect(ran.status).toBe(2);
  });

  test.each<Release>(['3.8', 'refusing'])('`merge` on an ASH without it (%s)', (release) => {
    expect(run(MERGE, release).calls).toEqual([
      'merge --results out/shard-0 --results out/shard-1 --output-dir .ash/ash_output --min-severity high',
    ]);
  });
});

describe('the generated buildspecs name the subject on an ASH that has one', () => {
  function buildCommands(spec: any): string {
    // The commands of one phase run in one shell, in order.
    return (spec.phases.build.commands as string[]).join('\n');
  }

  test.each<[string, any, Record<string, string>, string, string]>([
    [
      'buildspec.yml',
      scanBuildspec(),
      {},
      'scan fs . --output-dir .ash/ash_output --min-severity low --fail-on-findings',
      'scan --source-dir . --output-dir .ash/ash_output --min-severity low --fail-on-findings',
    ],
    [
      'buildspec-shard.yml',
      shardBuildspec(),
      { ASH_SHARD_INDEX: '2', ASH_SHARD_COUNT: '4' },
      'scan fs . --output-dir .ash/ash_output --shard-index 2 --shard-count 4 --no-fail-on-findings',
      'scan --source-dir . --output-dir .ash/ash_output --shard-index 2 --shard-count 4 --no-fail-on-findings',
    ],
    [
      'buildspec-merge.yml',
      mergeBuildspec(),
      { ASH_SHARD_RESULTS: 'a/shard-0 a/shard-1' },
      'results merge --results a/shard-0 --results a/shard-1 --output-dir .ash/ash_output --min-severity low',
      'merge --results a/shard-0 --results a/shard-1 --output-dir .ash/ash_output --min-severity low',
    ],
  ])('%s', (_name, spec, overrides, withSubject, withoutSubject) => {
    const env = { ...declaredEnvironment(spec), ...overrides };
    expect(run(buildCommands(spec), '3.9', { env }).calls).toEqual([withSubject]);
    expect(run(buildCommands(spec), '3.8', { env }).calls).toEqual([withoutSubject]);
  });
});

describe('the stand-in itself', () => {
  test('control: a command that skips the probe is recorded as typed', () => {
    // Without this, a stand-in that recorded nothing would make every expectation
    // of an empty list pass.
    expect(run('ash scan --source-dir x', '3.9').calls).toEqual(['scan --source-dir x']);
  });

  test('control: the probes are answered, not recorded', () => {
    const ran = run('ash scan fs --help >/dev/null; ash results merge --help >/dev/null', '3.9');
    expect(ran.calls).toEqual([]);
    expect(ran.status).toBe(0);
  });
});
