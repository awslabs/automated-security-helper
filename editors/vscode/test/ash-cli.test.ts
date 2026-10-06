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
 * `probeRunner` and `spawnAsyncRunner` are exercised against real processes rather
 * than a mock. A runner that is only ever tested through a fake is a runner nobody
 * has run, and its arguments-and-encoding wiring is exactly where a silent failure
 * would sit.
 */

import { ChildProcess, SpawnOptions } from 'child_process';
import { EventEmitter } from 'events';
import { PassThrough } from 'stream';
import {
  ASH_FALLBACK_EXECUTABLE,
  ASH_IDENTITY_MARKER,
  CommandResult,
  CommandRunner,
  DEFAULT_EXECUTABLE,
  DEFAULT_TIMEOUT_MS,
  EXIT_ACTIONABLE_FINDINGS,
  LEGACY_EXECUTABLE,
  AsyncCommandOptions,
  AsyncCommandResult,
  AsyncCommandRunner,
  EXIT_DRAIN_MS,
  KILL_GRACE_MS,
  Spawner,
  TreeKiller,
  classifyExit,
  killProcessTree,
  spawnAsyncRunner,
  resolveExecutable,
  SARIF_RELATIVE_PATH,
  outputTail,
  probeAshIdentity,
  runScan,
  scanArgs,
  probeRunner,
} from '../src/ash-cli';

const MEASURED_VERSION = 'awslabs/automated-security-helper v3.7.0';

function runnerReturning(result: Partial<CommandResult>): CommandRunner {
  return () => Promise.resolve({ status: 0, stdout: '', stderr: '', ...result });
}

describe('probeAshIdentity', () => {
  it('accepts the string a real ash prints', async () => {
    const probe = await probeAshIdentity('ash', runnerReturning({ stdout: `${MEASURED_VERSION}\n` }));
    expect(probe).toEqual({ ok: true, version: MEASURED_VERSION });
  });

  it('accepts the marker on stderr, so the answer\'s stream does not decide the verdict', async () => {
    const probe = await probeAshIdentity('ash', runnerReturning({ stderr: MEASURED_VERSION }));
    expect(probe.ok).toBe(true);
  });

  it('rejects the Almquist shell and names the fallback entry point', async () => {
    const probe = await probeAshIdentity('ash', runnerReturning({ status: 2, stderr: 'ash: 0: Illegal option --' }));

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

  it('names MSYS2 and Git Bash on Windows', async () => {
    const probe = await probeAshIdentity(
      'ash',
      runnerReturning({ status: 2, stderr: 'ash: 0: Illegal option --' }),
      {},
      'win32',
    );

    expect(probe.ok).toBe(false);
    if (probe.ok) {
      throw new Error('unreachable');
    }
    expect(probe.message).toContain('MSYS2 and Git Bash');
    expect(probe.message).toContain(ASH_FALLBACK_EXECUTABLE);
  });

  it('does not blame Windows tools on Linux or macOS', async () => {
    // Measured on Alpine: BusyBox's `ash` prints this for --version. A message
    // about MSYS2 there sends the user looking for software they do not have.
    for (const platform of ['linux', 'darwin'] as const) {
      const probe = await probeAshIdentity(
        'ash',
        runnerReturning({ status: 1, stderr: "ash: bad option '--version'" }),
        {},
        platform,
      );

      expect(probe.ok).toBe(false);
      if (probe.ok) {
        throw new Error('unreachable');
      }
      expect(probe.message).not.toMatch(/Windows|MSYS2|Git Bash/);
      expect(probe.message).toContain('BusyBox');
      expect(probe.message).toContain(ASH_FALLBACK_EXECUTABLE);
      expect(probe.message).toContain('would look exactly like a clean scan');
    }
  });

  it('passes the platform through executable resolution', async () => {
    const resolution = await resolveExecutable(
      'ash',
      runnerReturning({ status: 1, stderr: "ash: bad option '--version'" }),
      {},
      'linux',
    );

    expect(resolution.ok).toBe(false);
    if (resolution.ok) {
      throw new Error('unreachable');
    }
    expect(resolution.message).not.toContain('MSYS2');
  });

  it('does not accept a bare "ash" in the output as proof of identity', async () => {
    // A shell error message contains "ash". If the marker were the program name
    // rather than the distribution name, this would pass and the extension would
    // then scan with a shell.
    const probe = await probeAshIdentity('ash', runnerReturning({ stderr: 'ash: bad option' }));
    expect(probe.ok).toBe(false);
    expect(ASH_IDENTITY_MARKER).not.toBe('ash');
  });

  it('reports a missing executable as a PATH problem', async () => {
    const enoent = Object.assign(new Error('spawn ash ENOENT'), { code: 'ENOENT' });
    const probe = await probeAshIdentity('ash', runnerReturning({ error: enoent }));

    expect(probe.ok).toBe(false);
    if (probe.ok) {
      throw new Error('unreachable');
    }
    expect(probe.message).toContain('not on PATH');
    expect(probe.message).toContain('ash.executablePath');
  });

  it('reports any other spawn failure with its own message', async () => {
    const probe = await probeAshIdentity('/root/ash', runnerReturning({ error: new Error('EACCES') }));

    expect(probe.ok).toBe(false);
    if (probe.ok) {
      throw new Error('unreachable');
    }
    expect(probe.message).toContain('EACCES');
    expect(probe.message).not.toContain('not on PATH');
  });

  it('refuses an executable that did not answer within the probe timeout', async () => {
    const probe = await probeAshIdentity('ash', runnerReturning({ status: null, timedOut: true }), {
      timeoutMs: 2000,
    });

    expect(probe.ok).toBe(false);
    expect(probe.ok ? '' : probe.message).toContain('did not answer within 2s');
    expect(probe.ok ? true : probe.notFound).toBeUndefined();
  });

  it('reports an empty answer rather than treating silence as agreement', async () => {
    const probe = await probeAshIdentity('ash', runnerReturning({}));
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

function asyncReturning(result: Partial<AsyncCommandResult>): AsyncCommandRunner {
  return () =>
    Promise.resolve({ status: 0, stdout: '', stderr: '', timedOut: false, cancelled: false, ...result });
}

describe('runScan', () => {
  it('passes the timeout and signal through and sets no working directory', async () => {
    const seen: AsyncCommandOptions[] = [];
    const signal = new AbortController().signal;
    const run: AsyncCommandRunner = (_exe, _args, options) => {
      seen.push(options);
      return asyncReturning({})('', [], {});
    };

    await runScan('ash', '/ws', '/out', run, [], { timeoutMs: 5000, signal });

    expect(seen[0]).toEqual({ timeoutMs: 5000, signal });
    expect(seen[0]).not.toHaveProperty('cwd');
  });

  it('classifies 0 as clean and 2 as findings, because 2 is ASH\'s findings code', async () => {
    expect((await runScan('ash', '/ws', '/out', asyncReturning({ status: 0 }))).verdict).toBe('clean');
    expect(
      (await runScan('ash', '/ws', '/out', asyncReturning({ status: EXIT_ACTIONABLE_FINDINGS })))
        .verdict,
    ).toBe('findings');
  });

  it('classifies 1 as incomplete, not as a failure, so the caller looks for partial results', async () => {
    expect((await runScan('ash', '/ws', '/out', asyncReturning({ status: 1 }))).verdict).toBe(
      'incomplete',
    );
  });

  it('classifies 3, 4, a signal and a start failure as failed', async () => {
    for (const status of [3, 4, 127]) {
      expect((await runScan('ash', '/ws', '/out', asyncReturning({ status }))).verdict).toBe('failed');
    }
    expect((await runScan('ash', '/ws', '/out', asyncReturning({ status: null }))).verdict).toBe(
      'failed',
    );
    expect(classifyExit({ status: 0, stdout: '', stderr: '', error: new Error('x') })).toBe('failed');
  });

  it('classifies a stopped scan by why it stopped, whatever its exit status', async () => {
    expect(
      (await runScan('ash', '/ws', '/out', asyncReturning({ status: 2, timedOut: true }))).verdict,
    ).toBe('timed-out');
    expect(
      (await runScan('ash', '/ws', '/out', asyncReturning({ status: null, cancelled: true }))).verdict,
    ).toBe('cancelled');
  });
});

describe('resolveExecutable', () => {
  /** A PATH holding exactly the named executables, each answering as ASH. */
  function pathWith(...present: string[]): { run: CommandRunner; probed: string[] } {
    const probed: string[] = [];
    const run: CommandRunner = (executable) => {
      probed.push(executable);
      if (!present.includes(executable)) {
        return Promise.resolve({
          status: null,
          stdout: '',
          stderr: '',
          error: Object.assign(new Error(`spawn ${executable} ENOENT`), { code: 'ENOENT' }),
        });
      }
      return Promise.resolve({ status: 0, stdout: MEASURED_VERSION, stderr: '' });
    };
    return { run, probed };
  }

  it('defaults to ashx and keeps it when it is installed', async () => {
    const { run, probed } = pathWith('ashx', 'ash');

    expect(DEFAULT_EXECUTABLE).toBe('ashx');
    expect(await resolveExecutable('', run)).toEqual({
      ok: true,
      executable: 'ashx',
      version: MEASURED_VERSION,
      fellBack: false,
    });
    expect(probed).toEqual(['ashx']);
  });

  it('falls back to ash only when ashx is not on PATH, and says it did', async () => {
    const { run, probed } = pathWith('ash');

    expect(LEGACY_EXECUTABLE).toBe('ash');
    expect(await resolveExecutable('', run)).toMatchObject({ ok: true, executable: 'ash', fellBack: true });
    expect(probed).toEqual(['ashx', 'ash']);
  });

  it('treats whitespace as unset', async () => {
    expect(await resolveExecutable('   ', pathWith('ash').run)).toMatchObject({ executable: 'ash' });
  });

  it('names both executables when neither is installed', async () => {
    const resolved = await resolveExecutable('', pathWith().run);

    expect(resolved.ok).toBe(false);
    expect(resolved.ok ? '' : resolved.message).toContain('Neither "ashx" nor "ash" is on PATH');
  });

  it('does not fall back when ashx answered and is not ASH', async () => {
    // A name that resolved to something else is an error to report. Quietly
    // scanning with a different program would hide it.
    const probed: string[] = [];
    const run: CommandRunner = (executable) => {
      probed.push(executable);
      return Promise.resolve({ status: 2, stdout: '', stderr: 'ashx: 0: Illegal option --' });
    };

    const resolved = await resolveExecutable('', run);

    expect(resolved.ok).toBe(false);
    expect(probed).toEqual(['ashx']);
  });

  it('reports why ash failed when ashx is missing and ash is not ASH', async () => {
    const run: CommandRunner = (executable) =>
      Promise.resolve(
        executable === 'ashx'
          ? {
              status: null,
              stdout: '',
              stderr: '',
              error: Object.assign(new Error('ENOENT'), { code: 'ENOENT' }),
            }
          : { status: 2, stdout: '', stderr: 'ash: 0: Illegal option --' },
      );

    const resolved = await resolveExecutable('', run);

    expect(resolved.ok ? '' : resolved.message).toContain('Almquist');
  });

  it('uses a configured executable as given, with no fallback', async () => {
    const { run, probed } = pathWith('ash');

    const resolved = await resolveExecutable('ashx', run);

    expect(resolved.ok).toBe(false);
    expect(resolved.ok ? '' : resolved.message).toContain('not on PATH');
    expect(probed).toEqual(['ashx']);
  });

  it('runs a configured full path when it answers as ASH', async () => {
    const { run, probed } = pathWith('/opt/ash/bin/ash');

    expect(await resolveExecutable('/opt/ash/bin/ash', run)).toMatchObject({
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

describe('probeRunner', () => {
  it('captures stdout, stderr and the exit status of a real process', async () => {
    const result = await probeRunner(process.execPath, [
      '-e',
      'process.stdout.write("hello"); process.stderr.write("boom"); process.exit(2)',
    ]);

    expect(result).toMatchObject({ status: 2, stdout: 'hello', stderr: 'boom', timedOut: false });
    expect(result.error).toBeUndefined();
  });

  it('runs in the host process\'s working directory, not one a caller picks', async () => {
    const result = await probeRunner(process.execPath, ['-e', 'process.stdout.write(process.cwd())']);

    expect(result.stdout).toBe(process.cwd());
  });

  it('reports ENOENT as an error rather than as an exit code', async () => {
    const result = await probeRunner('a-command-that-does-not-exist-anywhere', ['--version']);

    expect((result.error as NodeJS.ErrnoException).code).toBe('ENOENT');
  });

  it('stops a process that outruns its timeout', async () => {
    const result = await probeRunner(process.execPath, ['-e', 'setTimeout(() => {}, 60000)'], {
      timeoutMs: 250,
    });

    expect(result.timedOut).toBe(true);
    expect(result.status).toBeNull();
  });

  it('applies DEFAULT_TIMEOUT_MS when no timeout is named', async () => {
    const result = await probeRunner(process.execPath, ['--version']);

    expect(DEFAULT_TIMEOUT_MS).toBe(60_000);
    expect(result).toMatchObject({ status: 0, timedOut: false });
  });

  it('does not block: the event loop runs while the probe does', async () => {
    let ticks = 0;
    const ticker = setInterval(() => (ticks += 1), 10);
    try {
      await probeRunner(process.execPath, ['-e', 'setTimeout(() => {}, 300)']);
    } finally {
      clearInterval(ticker);
    }
    expect(ticks).toBeGreaterThan(5);
  });

  it('is what the probe uses for real, and rejects a program that is not ASH', async () => {
    // node --version prints v22.x, which does not name ASH. The probe must reject
    // it, which is the same code path an MSYS2 shell takes.
    const probe = await probeAshIdentity(process.execPath, probeRunner);
    expect(probe.ok).toBe(false);
  });
});

/** Whether a pid is alive. `kill(pid, 0)` signals nothing and throws ESRCH when it is gone. */
function alive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function waitUntil(predicate: () => boolean, ms: number): Promise<boolean> {
  const deadline = Date.now() + ms;
  while (Date.now() < deadline) {
    if (predicate()) {
      return true;
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  return predicate();
}

/**
 * A node script that starts a grandchild sleeping for a minute, prints the
 * grandchild's pid, and then sleeps itself: the shape of ASH running a scanner.
 */
const PARENT_WITH_GRANDCHILD = [
  "const { spawn } = require('child_process');",
  "const g = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 60000)'], { stdio: 'ignore' });",
  "process.stdout.write(String(g.pid) + '\\n');",
  'setTimeout(() => {}, 60000);',
].join(' ');

describe('spawnAsyncRunner', () => {
  it('captures stdout, stderr and the exit status of a normal run', async () => {
    const result = await spawnAsyncRunner(process.execPath, [
      '-e',
      'process.stdout.write("out"); process.stderr.write("err"); process.exit(2)',
    ]);

    expect(result).toEqual({ status: 2, stdout: 'out', stderr: 'err', timedOut: false, cancelled: false });
  });

  it('runs in the host process\'s working directory, not one a caller picks', async () => {
    const result = await spawnAsyncRunner(process.execPath, ['-e', 'process.stdout.write(process.cwd())']);

    expect(result.stdout).toBe(process.cwd());
  });

  it('resolves with ENOENT rather than rejecting when the executable does not exist', async () => {
    const result = await spawnAsyncRunner('ash-that-is-not-installed-anywhere', ['--version']);

    expect((result.error as NodeJS.ErrnoException).code).toBe('ENOENT');
    expect(result.status).toBeNull();
    expect(classifyExit(result)).toBe('failed');
  });

  it('does not block: the event loop runs while the child does', async () => {
    let ticks = 0;
    const ticker = setInterval(() => (ticks += 1), 10);
    try {
      await spawnAsyncRunner(process.execPath, ['-e', 'setTimeout(() => {}, 300)']);
    } finally {
      clearInterval(ticker);
    }
    expect(ticks).toBeGreaterThan(5);
  });

  it('stops the whole process tree when the timeout fires', async () => {
    let grandchild = 0;
    const started = Date.now();

    const result = await spawnAsyncRunner(process.execPath, ['-e', PARENT_WITH_GRANDCHILD], {
      timeoutMs: 800,
    });
    grandchild = Number(result.stdout.trim());

    expect(result.timedOut).toBe(true);
    expect(result.cancelled).toBe(false);
    expect(classifyExit(result)).toBe('timed-out');
    expect(Date.now() - started).toBeLessThan(KILL_GRACE_MS + 5000);
    expect(grandchild).toBeGreaterThan(0);
    // The scanner ASH started is gone too, not only ASH.
    expect(await waitUntil(() => !alive(grandchild), 3000)).toBe(true);
  });

  it('stops the whole process tree when the signal aborts', async () => {
    const controller = new AbortController();
    const pending = spawnAsyncRunner(process.execPath, ['-e', PARENT_WITH_GRANDCHILD], {
      signal: controller.signal,
    });
    await new Promise((resolve) => setTimeout(resolve, 500));
    controller.abort();

    const result = await pending;
    const grandchild = Number(result.stdout.trim());

    expect(result.cancelled).toBe(true);
    expect(result.timedOut).toBe(false);
    expect(classifyExit(result)).toBe('cancelled');
    expect(await waitUntil(() => !alive(grandchild), 3000)).toBe(true);
  });

  it('still SIGKILLs a grandchild that ignores SIGTERM after the parent has exited', async () => {
    // The parent exits on SIGTERM; its grandchild ignores SIGTERM and does not hold
    // the pipes, so 'close' fires while the grandchild is still running.
    const stubborn = [
      "const { spawn } = require('child_process');",
      "const g = spawn(process.execPath, ['-e', \"process.on('SIGTERM', () => {}); setTimeout(() => {}, 60000)\"], { stdio: 'ignore' });",
      "process.stdout.write(String(g.pid) + '\\n');",
      'setTimeout(() => {}, 60000);',
    ].join(' ');
    const result = await spawnAsyncRunner(process.execPath, ['-e', stubborn], { timeoutMs: 800 });
    const grandchild = Number(result.stdout.trim());

    expect(result.timedOut).toBe(true);
    expect(grandchild).toBeGreaterThan(0);
    // SIGTERM did not stop it; the SIGKILL after the grace does.
    expect(alive(grandchild)).toBe(true);
    expect(await waitUntil(() => !alive(grandchild), KILL_GRACE_MS + 3000)).toBe(true);
  }, KILL_GRACE_MS + 10_000);

  it('does not start a process for a signal that is already aborted', async () => {
    const controller = new AbortController();
    controller.abort();

    const result = await spawnAsyncRunner('ash-that-is-not-installed-anywhere', [], {
      signal: controller.signal,
    });

    expect(result).toMatchObject({ cancelled: true, status: null });
    expect(result.error).toBeUndefined();
  });

  it('keeps the tail of output past the capture cap', async () => {
    const result = await spawnAsyncRunner(process.execPath, [
      '-e',
      'process.stdout.write("x".repeat(5 * 1024 * 1024) + "END")',
    ]);

    expect(result.stdout.length).toBe(4 * 1024 * 1024);
    expect(result.stdout.endsWith('END')).toBe(true);
  });

  it('waits indefinitely when the timeout is 0', async () => {
    const result = await spawnAsyncRunner(process.execPath, ['-e', 'setTimeout(() => {}, 300)'], {
      timeoutMs: 0,
    });

    expect(result).toMatchObject({ status: 0, timedOut: false });
  });
});

/**
 * A child process that emits what the test tells it to and nothing else, so a
 * child that exits while something else still holds its pipes can be modelled
 * exactly: 'exit' arrives and 'close' never does.
 */
class FakeChild extends EventEmitter {
  public readonly stdout = new PassThrough();
  public readonly stderr = new PassThrough();
  public readonly pid = 4242;
  public readonly kill = jest.fn(() => true);
}

function fakeSpawner(child: FakeChild): Spawner {
  return () => child as unknown as ChildProcess;
}

const NO_KILL: TreeKiller = { platform: 'linux', kill: () => undefined, spawnTaskkill: () => undefined };

describe('spawnAsyncRunner environment', () => {
  // ASH reads ASH_DEBUG and ASH_VERBOSE as its log level when no flag is given.
  // With no `env` in the spawn options, Node hands the child the extension
  // host's own environment, so a user's ASH_DEBUG=true applies to scans started
  // from the editor. An `env` option would replace that environment wholesale.
  // Checked at the spawner seam because jest gives each test file its own copy
  // of process.env, which a real child would never see.
  it('passes no env option, so the child inherits ASH_DEBUG and ASH_VERBOSE', async () => {
    const child = new FakeChild();
    let seen: SpawnOptions | undefined;
    const spawner: Spawner = (_command, _args, options) => {
      seen = options;
      return child as unknown as ChildProcess;
    };

    const pending = spawnAsyncRunner('ash', ['scan'], {}, NO_KILL, spawner, 10);
    child.emit('exit', 0, null);
    child.emit('close', 0, null);
    await pending;

    expect(seen).toBeDefined();
    expect(seen).not.toHaveProperty('env');
  });
});

describe('spawnAsyncRunner when the pipes outlive the child', () => {
  it('settles after a short drain when the child exits and never closes', async () => {
    const child = new FakeChild();
    const pending = spawnAsyncRunner('ash', [], {}, NO_KILL, fakeSpawner(child), 50);
    child.stdout.write('partial output');
    await new Promise((resolve) => setImmediate(resolve));
    child.emit('exit', 2, null);

    const result = await pending;

    expect(result).toMatchObject({ status: 2, stdout: 'partial output', timedOut: false, cancelled: false });
    // The pipes are given up on, so a grandchild still writing to them cannot
    // keep the extension host's end open.
    expect(child.stdout.destroyed).toBe(true);
    expect(child.stderr.destroyed).toBe(true);
  });

  it('settles a cancelled scan whose child exits and never closes', async () => {
    const child = new FakeChild();
    const kills: [number, string][] = [];
    const killer: TreeKiller = { ...NO_KILL, kill: (pid, signal) => void kills.push([pid, signal]) };
    const controller = new AbortController();
    const pending = spawnAsyncRunner('ash', [], { signal: controller.signal }, killer, fakeSpawner(child), 50);

    controller.abort();
    expect(kills).toEqual([[-4242, 'SIGTERM']]);
    child.emit('exit', null, 'SIGTERM');

    const result = await pending;
    expect(result).toMatchObject({ status: null, cancelled: true, timedOut: false });
    expect(classifyExit(result)).toBe('cancelled');
  });

  it('still prefers close, which carries every byte, when it arrives inside the drain', async () => {
    const child = new FakeChild();
    const pending = spawnAsyncRunner('ash', [], {}, NO_KILL, fakeSpawner(child), 10_000);
    child.emit('exit', 0, null);
    child.stdout.end('late bytes');
    await new Promise((resolve) => setImmediate(resolve));
    child.emit('close', 0, null);

    expect(await pending).toMatchObject({ status: 0, stdout: 'late bytes' });
  });

  it('resolves a real cancel when a grandchild in its own session holds stdout', async () => {
    // setsid puts the grandchild outside the process group, so the group kill
    // cannot reach it, and it holds the stdout pipe, so 'close' never fires.
    // Before the drain this never resolved.
    const holder = [
      "const { spawn } = require('child_process');",
      "const g = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 60000)'], { detached: true, stdio: ['ignore', 'inherit', 'ignore'] });",
      "process.stdout.write(String(g.pid) + '\\n');",
      'setTimeout(() => {}, 60000);',
    ].join(' ');
    const controller = new AbortController();
    const pending = spawnAsyncRunner(process.execPath, ['-e', holder], { signal: controller.signal });
    await new Promise((resolve) => setTimeout(resolve, 500));
    controller.abort();
    const started = Date.now();

    const result = await pending;
    const grandchild = Number(result.stdout.trim());
    try {
      expect(result.cancelled).toBe(true);
      expect(Date.now() - started).toBeLessThan(EXIT_DRAIN_MS + 3000);
      expect(grandchild).toBeGreaterThan(0);
      // The documented limit: a process that left the group survives the stop.
      expect(alive(grandchild)).toBe(true);
    } finally {
      if (grandchild > 0 && alive(grandchild)) {
        process.kill(grandchild, 'SIGKILL');
      }
    }
  }, 15_000);
});

describe('killProcessTree', () => {
  function recording(platform: NodeJS.Platform): {
    killer: TreeKiller;
    kills: [number, string][];
    taskkills: (readonly string[])[];
  } {
    const kills: [number, string][] = [];
    const taskkills: (readonly string[])[] = [];
    return {
      kills,
      taskkills,
      killer: {
        platform,
        kill: (pid, signal) => {
          kills.push([pid, signal]);
        },
        spawnTaskkill: (args) => {
          taskkills.push(args);
        },
      },
    };
  }

  it('signals the process group on POSIX, SIGTERM then SIGKILL after the grace', async () => {
    const { killer, kills } = recording('linux');
    const child = { pid: 4242, kill: jest.fn() };

    killProcessTree(child, killer, 50);
    expect(kills).toEqual([[-4242, 'SIGTERM']]);
    await new Promise((resolve) => setTimeout(resolve, 120));

    expect(kills).toEqual([
      [-4242, 'SIGTERM'],
      [-4242, 'SIGKILL'],
    ]);
  });

  it('walks the tree with taskkill on Windows', () => {
    const { killer, kills, taskkills } = recording('win32');
    const child = { pid: 4242, kill: jest.fn() };

    expect(killProcessTree(child, killer)).toBeUndefined();

    expect(taskkills).toEqual([['/pid', '4242', '/T', '/F']]);
    expect(child.kill).toHaveBeenCalled();
    expect(kills).toEqual([]);
  });

  it('does nothing for a child that never got a pid', () => {
    const { killer, kills, taskkills } = recording('linux');

    expect(killProcessTree({ pid: undefined, kill: jest.fn() }, killer)).toBeUndefined();
    expect(kills).toEqual([]);
    expect(taskkills).toEqual([]);
  });

  it('treats a group that is already gone as stopped', () => {
    const killer: TreeKiller = {
      platform: 'linux',
      kill: () => {
        throw Object.assign(new Error('kill ESRCH'), { code: 'ESRCH' });
      },
      spawnTaskkill: () => undefined,
    };

    const timer = killProcessTree({ pid: 4242, kill: jest.fn() }, killer, 10);

    expect(timer).toBeDefined();
    clearTimeout(timer);
  });
});
