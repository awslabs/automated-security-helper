// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Tests for the CLI layer, including the identity probe.
 *
 * The probe's cases are drawn from measurement, not from imagination. On this
 * host, `ash --version` and `ash -V` both print
 * `awslabs/automated-security-helper v3.7.0`, and `ash -v` starts a verbose
 * logging session instead -- which is why the probe uses the long form. The
 * Almquist shell's `Illegal option --` is the string MSYS2's `ash` produces for
 * the same argument, and it is the one answer the probe must reject.
 *
 * `spawnSyncRunner` is exercised against real processes rather than a mock. A
 * runner that is only ever tested through a fake is a runner nobody has run, and
 * its arguments-and-encoding wiring is exactly where a silent failure would sit.
 */

import {
  ASH_FALLBACK_EXECUTABLE,
  ASH_IDENTITY_MARKER,
  CommandResult,
  CommandRunner,
  DEFAULT_EXECUTABLE,
  EXIT_ACTIONABLE_FINDINGS,
  LEGACY_EXECUTABLE,
  classifyExit,
  resolveExecutable,
  SARIF_RELATIVE_PATH,
  outputTail,
  probeAshIdentity,
  runScan,
  scanArgs,
  spawnSyncRunner,
} from '../src/ash-cli';

const MEASURED_VERSION = 'awslabs/automated-security-helper v3.7.0';

function runnerReturning(result: Partial<CommandResult>): CommandRunner {
  return () => ({ status: 0, stdout: '', stderr: '', ...result });
}

describe('probeAshIdentity', () => {
  it('accepts the string a real ash prints', () => {
    const probe = probeAshIdentity('ash', runnerReturning({ stdout: `${MEASURED_VERSION}\n` }));
    expect(probe).toEqual({ ok: true, version: MEASURED_VERSION });
  });

  it('accepts the marker on stderr, so the answer\'s stream does not decide the verdict', () => {
    const probe = probeAshIdentity('ash', runnerReturning({ stderr: MEASURED_VERSION }));
    expect(probe.ok).toBe(true);
  });

  it('rejects the Almquist shell and names the fallback entry point', () => {
    const probe = probeAshIdentity('ash', runnerReturning({ status: 2, stderr: 'ash: 0: Illegal option --' }));

    expect(probe.ok).toBe(false);
    if (probe.ok) {
      throw new Error('unreachable');
    }
    expect(probe.message).toContain('is not ASH');
    expect(probe.message).toContain(ASH_FALLBACK_EXECUTABLE);
    expect(probe.message).toContain('Almquist');
    // The refusal has to say why refusing beats scanning, because "it might have
    // worked" is the argument for trying anyway.
    expect(probe.message).toContain('would look exactly like a clean scan');
  });

  it('does not accept a bare "ash" in the output as proof of identity', () => {
    // A shell error message contains "ash". If the marker were the program name
    // rather than the distribution name, this would pass and the extension would
    // then scan with a shell.
    const probe = probeAshIdentity('ash', runnerReturning({ stderr: 'ash: bad option' }));
    expect(probe.ok).toBe(false);
    expect(ASH_IDENTITY_MARKER).not.toBe('ash');
  });

  it('reports a missing executable as a PATH problem', () => {
    const enoent = Object.assign(new Error('spawnSync ash ENOENT'), { code: 'ENOENT' });
    const probe = probeAshIdentity('ash', runnerReturning({ error: enoent }));

    expect(probe.ok).toBe(false);
    if (probe.ok) {
      throw new Error('unreachable');
    }
    expect(probe.message).toContain('not on PATH');
    expect(probe.message).toContain('ash.executablePath');
  });

  it('reports any other spawn failure with its own message', () => {
    const probe = probeAshIdentity('/root/ash', runnerReturning({ error: new Error('EACCES') }));

    expect(probe.ok).toBe(false);
    if (probe.ok) {
      throw new Error('unreachable');
    }
    expect(probe.message).toContain('EACCES');
    expect(probe.message).not.toContain('not on PATH');
  });

  it('reports an empty answer rather than treating silence as agreement', () => {
    const probe = probeAshIdentity('ash', runnerReturning({}));
    expect(probe.ok).toBe(false);
  });
});

describe('scanArgs', () => {
  it('passes the directories through and turns progress rendering off', () => {
    expect(scanArgs('/ws', '/ws/.ash/ash_output')).toEqual([
      'scan',
      '--source-dir',
      '/ws',
      '--output-dir',
      '/ws/.ash/ash_output',
      '--no-progress',
    ]);
  });

  it('appends extra arguments last, so a user cannot be overridden by the defaults', () => {
    expect(scanArgs('/ws', '/out', ['--offline'])).toEqual([
      'scan',
      '--source-dir',
      '/ws',
      '--output-dir',
      '/out',
      '--no-progress',
      '--offline',
    ]);
  });
});

describe('runScan', () => {
  it('calls the runner in the source directory', () => {
    const seen: { cwd?: string }[] = [];
    const run: CommandRunner = (_exe, _args, options) => {
      seen.push({ cwd: options.cwd });
      return { status: 0, stdout: '', stderr: '' };
    };

    runScan('ash', '/ws', '/out', run);

    expect(seen[0].cwd).toBe('/ws');
  });

  it('classifies 0 as clean and 2 as findings, because 2 is ASH\'s findings code', () => {
    expect(runScan('ash', '/ws', '/out', runnerReturning({ status: 0 })).verdict).toBe('clean');
    expect(
      runScan('ash', '/ws', '/out', runnerReturning({ status: EXIT_ACTIONABLE_FINDINGS })).verdict,
    ).toBe('findings');
  });

  it('classifies 1 as incomplete, not as a failure, so the caller looks for partial results', () => {
    expect(runScan('ash', '/ws', '/out', runnerReturning({ status: 1 })).verdict).toBe('incomplete');
  });

  it('classifies 3, 4, a signal and a start failure as failed', () => {
    for (const status of [3, 4, 127]) {
      expect(runScan('ash', '/ws', '/out', runnerReturning({ status })).verdict).toBe('failed');
    }
    expect(runScan('ash', '/ws', '/out', runnerReturning({ status: null })).verdict).toBe('failed');
    expect(classifyExit({ status: 0, stdout: '', stderr: '', error: new Error('x') })).toBe('failed');
  });
});

describe('resolveExecutable', () => {
  /** A PATH holding exactly the named executables, each answering as ASH. */
  function pathWith(...present: string[]): { run: CommandRunner; probed: string[] } {
    const probed: string[] = [];
    const run: CommandRunner = (executable) => {
      probed.push(executable);
      if (!present.includes(executable)) {
        return {
          status: null,
          stdout: '',
          stderr: '',
          error: Object.assign(new Error(`spawnSync ${executable} ENOENT`), { code: 'ENOENT' }),
        };
      }
      return { status: 0, stdout: MEASURED_VERSION, stderr: '' };
    };
    return { run, probed };
  }

  it('defaults to ashx and keeps it when it is installed', () => {
    const { run, probed } = pathWith('ashx', 'ash');

    expect(DEFAULT_EXECUTABLE).toBe('ashx');
    expect(resolveExecutable('', run)).toEqual({
      ok: true,
      executable: 'ashx',
      version: MEASURED_VERSION,
      fellBack: false,
    });
    expect(probed).toEqual(['ashx']);
  });

  it('falls back to ash only when ashx is not on PATH, and says it did', () => {
    const { run, probed } = pathWith('ash');

    expect(LEGACY_EXECUTABLE).toBe('ash');
    expect(resolveExecutable('', run)).toMatchObject({ ok: true, executable: 'ash', fellBack: true });
    expect(probed).toEqual(['ashx', 'ash']);
  });

  it('treats whitespace as unset', () => {
    expect(resolveExecutable('   ', pathWith('ash').run)).toMatchObject({ executable: 'ash' });
  });

  it('names both executables when neither is installed', () => {
    const resolved = resolveExecutable('', pathWith().run);

    expect(resolved.ok).toBe(false);
    expect(resolved.ok ? '' : resolved.message).toContain('Neither "ashx" nor "ash" is on PATH');
  });

  it('does not fall back when ashx answered and is not ASH', () => {
    // A name that resolved to something else is an error to report. Quietly
    // scanning with a different program would hide it.
    const probed: string[] = [];
    const run: CommandRunner = (executable) => {
      probed.push(executable);
      return { status: 2, stdout: '', stderr: 'ashx: 0: Illegal option --' };
    };

    const resolved = resolveExecutable('', run);

    expect(resolved.ok).toBe(false);
    expect(probed).toEqual(['ashx']);
  });

  it('reports why ash failed when ashx is missing and ash is not ASH', () => {
    const run: CommandRunner = (executable) =>
      executable === 'ashx'
        ? {
            status: null,
            stdout: '',
            stderr: '',
            error: Object.assign(new Error('ENOENT'), { code: 'ENOENT' }),
          }
        : { status: 2, stdout: '', stderr: 'ash: 0: Illegal option --' };

    const resolved = resolveExecutable('', run);

    expect(resolved.ok ? '' : resolved.message).toContain('Almquist');
  });

  it('uses a configured executable as given, with no fallback', () => {
    const { run, probed } = pathWith('ash');

    const resolved = resolveExecutable('ashx', run);

    expect(resolved.ok).toBe(false);
    expect(resolved.ok ? '' : resolved.message).toContain('not on PATH');
    expect(probed).toEqual(['ashx']);
  });

  it('runs a configured full path when it answers as ASH', () => {
    const { run, probed } = pathWith('/opt/ash/bin/ash');

    expect(resolveExecutable('/opt/ash/bin/ash', run)).toMatchObject({
      ok: true,
      executable: '/opt/ash/bin/ash',
      fellBack: false,
    });
    expect(probed).toEqual(['/opt/ash/bin/ash']);
  });
});

describe('SARIF_RELATIVE_PATH', () => {
  it('is where a measured ash scan wrote its report', () => {
    expect(SARIF_RELATIVE_PATH).toBe('reports/ash.sarif');
  });
});

describe('outputTail', () => {
  it('keeps the last lines, which is where ASH puts the reason', () => {
    const result: CommandResult = {
      status: 1,
      stdout: ['one', 'two', 'three'].join('\n'),
      stderr: 'four',
    };
    expect(outputTail(result, 2)).toBe('three\nfour');
  });

  it('drops blank lines and trailing whitespace', () => {
    expect(outputTail({ status: 1, stdout: 'a  \n\n\n', stderr: '' })).toBe('a');
  });

  it('returns an empty string when there was no output', () => {
    expect(outputTail({ status: 1, stdout: '', stderr: '' })).toBe('');
  });
});

describe('spawnSyncRunner', () => {
  it('captures stdout and the exit status of a real process', () => {
    const result = spawnSyncRunner(process.execPath, [
      '-e',
      'process.stdout.write("hello"); process.exit(2)',
    ]);

    expect(result.stdout).toBe('hello');
    expect(result.status).toBe(2);
    expect(result.error).toBeUndefined();
  });

  it('captures stderr separately from stdout', () => {
    const result = spawnSyncRunner(process.execPath, ['-e', 'process.stderr.write("boom")']);

    expect(result.stderr).toBe('boom');
    expect(result.stdout).toBe('');
    expect(result.status).toBe(0);
  });

  it('runs in the requested directory', () => {
    const result = spawnSyncRunner(process.execPath, ['-e', 'process.stdout.write(process.cwd())'], {
      cwd: __dirname,
    });

    expect(result.stdout).toBe(__dirname);
  });

  it('reports ENOENT as an error rather than as an exit code', () => {
    const result = spawnSyncRunner('a-command-that-does-not-exist-anywhere', ['--version']);

    expect(result.error).toBeDefined();
    expect((result.error as NodeJS.ErrnoException).code).toBe('ENOENT');
  });

  it('kills a process that outruns its timeout', () => {
    const result = spawnSyncRunner(
      process.execPath,
      ['-e', 'setTimeout(() => {}, 60000)'],
      { timeoutMs: 250 },
    );

    // A killed process has a null status and an ETIMEDOUT error. runScan reads
    // both as "did not complete", which is what keeps a timed-out scan from
    // publishing an empty result set.
    expect(result.status).toBeNull();
    expect(result.error).toBeDefined();
  });

  it('is accepted where a CommandRunner is expected, so the probe can use the real thing', () => {
    const probe = probeAshIdentity(
      process.execPath,
      spawnSyncRunner as CommandRunner,
    );
    // node --version prints v22.x, which does not name ASH. The probe must reject
    // it, which is the same code path an MSYS2 shell takes.
    expect(probe.ok).toBe(false);
  });
});
