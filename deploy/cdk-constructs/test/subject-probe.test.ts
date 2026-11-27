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
 * Only an answer picks the old spelling: a help that does not name the command, or
 * a usage error that refuses its first word. A probe that fails any other way (a
 * crash, an import error, an out-of-memory kill) says nothing about the ASH's
 * commands, so the step fails with the end of the probe's output and runs neither
 * spelling. Every run prints the spelling it chose and why to stderr.
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
 *   - `usage-error`: an ASH older than 3.9 that refuses the word with the usage error
 *     click gives (exit 5, "Got unexpected extra argument (fs)" and "No such command
 *     'results'") instead of showing help;
 *   - `crashing`: both probes die with a traceback and exit 1;
 *   - `unexplained-exit`: both probes exit 5 with an error that names neither word.
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
  "usage-error:scan fs --help")
    printf '%s\\n' "Usage: ash scan [OPTIONS]" "Try 'ash scan --help' for help." "" "Error: Got unexpected extra argument (fs)" >&2
    exit 5 ;;
  "usage-error:results merge --help") echo "Error: No such command 'results'." >&2; exit 5 ;;
  "crashing:scan fs --help" | "crashing:results merge --help")
    printf '%s\\n' "Traceback (most recent call last):" '  File "/usr/local/bin/ash", line 3, in <module>' "MemoryError" >&2
    exit 1 ;;
  "unexplained-exit:scan fs --help" | "unexplained-exit:results merge --help")
    echo "Error: not a command line this release takes." >&2; exit 5 ;;
esac
printf '%s\\n' "$*" >> "$ASH_STUB_LOG"
exit "\${ASH_STUB_EXIT:-0}"
`;

const PIP: InstallOptions = {
  mode: ASHInstallMode.PIP,
  sourceRepository: DEFAULT_ASH_REPOSITORY,
};

type Release = '3.9' | '3.8' | 'usage-error' | 'crashing' | 'unexplained-exit';

/** The releases whose probes do not answer, whichever command asks. */
const UNANSWERED: Release[] = ['crashing', 'unexplained-exit'];

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

  test.each<Release>(['3.8', 'usage-error'])(
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
    // A probe that stopped reading at the first match would leave ASH writing into a
    // closed pipe, and under pipefail that failure would read as a probe that did not
    // answer. This one captures all of the stand-in's thousands of help lines.
    const ran = run(UNSHARDED, '3.9', { shell: ['bash', '-o', 'pipefail', '-c'] });
    expect(ran.calls).toEqual([
      'scan fs . --output-dir .ash/ash_output --min-severity low --fail-on-findings --log-level INFO',
    ]);
  });
});

describe('a --source-dir among the extra arguments names the directory scanned', () => {
  // Before ASH 3.9 the scan named its own directory with --source-dir ahead of the
  // extra arguments, so a later --source-dir won and that directory was scanned.
  // ASH 3.9 refuses a --source-dir beside a PATH that names another directory, so
  // the caller's directory is the PATH there, and the only --source-dir before it.
  function unsharded(extraScanArguments: string[]): string {
    return only(
      scanCommands(
        {
          sourceDirectory: '.',
          outputDirectory: '.ash/ash_output',
          severityThreshold: ASHSeverityThreshold.LOW,
          extraScanArguments,
        },
        PIP,
      ),
    );
  }

  test.each<[string[], string, string]>([
    [['--source-dir', 'services/api'], 'services/api', ''],
    [['--source-dir=services/api'], 'services/api', ''],
    // The last one wins, as click resolves a repeated option.
    [['--log-level', 'INFO', '--source-dir', 'a', '--source-dir=b'], 'b', ' --log-level INFO'],
  ])('%j', (extraScanArguments, directory, rest) => {
    const options = `--output-dir .ash/ash_output --min-severity low --fail-on-findings${rest}`;
    const command = unsharded(extraScanArguments);
    expect(run(command, '3.9').calls).toEqual([`scan fs ${directory} ${options}`]);
    expect(run(command, '3.8').calls).toEqual([`scan --source-dir ${directory} ${options}`]);
  });

  test('a shard names it the same way', () => {
    const shard = only(
      shardScanCommands(
        {
          sourceDirectory: '.',
          outputDirectory: '.ash/ash_output/shard-1',
          shardIndex: '1',
          shardCount: '3',
          severityThreshold: ASHSeverityThreshold.LOW,
          extraScanArguments: ['--source-dir', 'services/api', '--offline'],
        },
        PIP,
      ),
    );
    const options =
      '--output-dir .ash/ash_output/shard-1 --shard-index 1 --shard-count 3 ' +
      '--no-fail-on-findings --offline';
    expect(run(shard, '3.9').calls).toEqual([`scan fs services/api ${options}`]);
    expect(run(shard, '3.8').calls).toEqual([`scan --source-dir services/api ${options}`]);
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

  test.each<Release>(['3.8', 'usage-error'])('`merge` on an ASH without it (%s)', (release) => {
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

  test.each<[string, any, Record<string, string>]>([
    ['buildspec.yml', scanBuildspec(), {}],
    ['buildspec-shard.yml', shardBuildspec(), { ASH_SHARD_INDEX: '2', ASH_SHARD_COUNT: '4' }],
    ['buildspec-merge.yml', mergeBuildspec(), { ASH_SHARD_RESULTS: 'a/shard-0 a/shard-1' }],
  ])('%s fails, and runs neither spelling, when the probe does not answer', (_name, spec, overrides) => {
    const env = { ...declaredEnvironment(spec), ...overrides };
    for (const release of UNANSWERED) {
      const ran = run(buildCommands(spec), release, { env });
      expect(ran.calls).toEqual([]);
      expect(ran.status).not.toBe(0);
      expect(ran.stderr).toContain('could not tell whether this ASH has');
    }
  });
});

describe('a probe that does not answer is not read as an older ASH', () => {
  // The older spelling is for an ASH that says it lacks the command. A probe that
  // crashed, or exited with an error that names neither word, says nothing about the
  // ASH. Read as an older one, it would run commands that an ASH 3.9 prints
  // deprecation lines for and drops in v4.0, and would do so without a word.
  const commands: [string, string, string][] = [
    ['the unsharded scan', UNSHARDED, 'ash scan fs'],
    ['a shard', SHARD, 'ash scan fs'],
    ['the merge', MERGE, 'ash results merge'],
  ];

  describe.each(UNANSWERED)('a probe that is %s', (release) => {
    test.each(commands)('%s runs neither spelling and fails', (_what, command, asked) => {
      const ran = run(command, release);
      expect(ran.calls).toEqual([]);
      expect(ran.status).toBe(1);
      expect(ran.stderr).toContain(`could not tell whether this ASH has '${asked}'`);
    });
  });

  test('the log has the probe\'s exit status and the end of what it printed', () => {
    const crashed = run(UNSHARDED, 'crashing').stderr;
    expect(crashed).toContain("'ash scan fs --help' exited 1");
    expect(crashed).toContain('MemoryError');
    const unexplained = run(MERGE, 'unexplained-exit').stderr;
    expect(unexplained).toContain("'ash results merge --help' exited 5");
    expect(unexplained).toContain('not a command line this release takes');
  });

  test('the step\'s exit status is not the probe\'s, so ASH\'s own codes stay ASH\'s', () => {
    // The merge's 1 and 2 and the scan's exit codes are verdicts. A probe that did
    // not answer is reported as a plain failure and never as one of them.
    expect(run(MERGE, 'unexplained-exit').status).toBe(1);
  });
});

describe('every run prints the spelling it chose and why', () => {
  test.each<[string, Release, string, string]>([
    ['the scan', '3.9', UNSHARDED, "scanning with 'ash scan fs': its help names 'scan fs'"],
    [
      'the scan',
      '3.8',
      UNSHARDED,
      "scanning with the older spelling: the help of 'ash scan fs --help' does not name 'scan fs'",
    ],
    [
      'the scan',
      'usage-error',
      UNSHARDED,
      "scanning with the older spelling: this ASH refused the word 'fs'",
    ],
    ['the merge', '3.9', MERGE, "merging with 'ash results merge': its help names 'results merge'"],
    [
      'the merge',
      '3.8',
      MERGE,
      "merging with the older spelling: this ASH refused the word 'results'",
    ],
    [
      'the merge',
      'usage-error',
      MERGE,
      "merging with the older spelling: this ASH refused the word 'results'",
    ],
  ])('%s on an ASH that answers as %s', (_what, release, command, said) => {
    expect(run(command, release).stderr).toContain(`ash: ${said}`);
  });

  test('the probe text never names the options the scan and merge are tested for', () => {
    // The step tests count `--source-dir` and `--results` in the rendered commands,
    // so the probe's own lines must carry neither.
    const dispatch = ' && if [ "$ash_spelling" = current ]; then ';
    expect(UNSHARDED).toContain(dispatch);
    expect(MERGE).toContain(dispatch);
    expect(UNSHARDED.split(dispatch)[0]).not.toContain('--source-dir');
    expect(MERGE.split(dispatch)[0]).not.toContain('--results');
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

  test('control: the releases that do not answer really fail their probes', () => {
    // The tests that expect neither spelling to run would also pass against a stand-in
    // whose probe quietly answered as an older ASH.
    const crashed = run('ash scan fs --help', 'crashing');
    expect(crashed.status).toBe(1);
    expect(crashed.stderr).toContain('MemoryError');
    const unexplained = run('ash results merge --help', 'unexplained-exit');
    expect(unexplained.status).toBe(5);
    expect(unexplained.stderr).not.toMatch(/unexpected extra argument|No such command/);
  });

  test('control: the usage-error release refuses the word, as an older ASH does', () => {
    const scan = run('ash scan fs --help', 'usage-error');
    expect(scan.status).toBe(5);
    expect(scan.stderr).toContain('Got unexpected extra argument (fs)');
    const merge = run('ash results merge --help', 'usage-error');
    expect(merge.status).toBe(5);
    expect(merge.stderr).toContain("No such command 'results'");
  });
});
