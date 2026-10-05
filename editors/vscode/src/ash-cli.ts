// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Invokes the `ash` CLI. Nothing here ships any part of ASH: the extension runs
 * whatever executable the user has, and reads the SARIF that executable writes.
 *
 * WHY THE IDENTITY PROBE EXISTS, WHICH IS NOT DEFENSIVENESS
 *
 * `ash` is a name MSYS2 already uses. It ships the Almquist shell as `ash`, so on
 * a Windows machine with MSYS2 or Git Bash ahead of ASH on PATH, spawning `ash`
 * starts a shell. That is not hypothetical: it has already shadowed ASH's entry
 * point in this project's own CI and produced `Illegal option --`.
 *
 * The reason it matters here more than in a terminal is the failure shape. A
 * shell handed `scan --source-dir ...` writes no SARIF, and an extension that
 * reads a missing SARIF as "no findings" would paint a clean editor. A clean
 * editor is exactly what a successful scan of clean code looks like, so the
 * wrong binary would be indistinguishable from safety. So the probe runs first
 * and refuses to scan at all unless the thing that answered identifies itself as
 * ASH.
 *
 * WHY THE PROBE READS THE OUTPUT AND NOT THE EXIT CODE
 *
 * Two collisions rule the exit code out. `ash scan` exits 2 for "actionable
 * findings detected", and the Almquist shell also exits 2 for an illegal option,
 * so a numeric test cannot tell them apart. Measured on this host:
 *
 *     $ ash --version
 *     awslabs/automated-security-helper v3.7.0
 *
 * `-V` prints the same string. `-v` is NOT a version flag -- it is `--verbose`,
 * and it starts a logging session -- which is why this file uses the long form.
 */

import { ChildProcess, SpawnOptions, spawn } from 'child_process';

/** What a spawned command produced. Modelled on `child_process.SpawnSyncReturns`. */
export interface CommandResult {
  /** Exit status, or null when the process was killed by a signal. */
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
  /** Set when the process could not be started at all, e.g. ENOENT. */
  readonly error?: Error;
  /** Set when the process outran its timeout and was stopped. */
  readonly timedOut?: boolean;
}

/**
 * There is no `cwd` here, or on AsyncCommandOptions, and that is deliberate.
 *
 * On Windows, libuv resolves a bare program name such as `ashx` by looking in the
 * child's working directory before PATH (src/win/process.c, search_path), trying
 * `.com` then `.exe`. A working directory of the workspace folder would therefore
 * let a cloned repository with `ashx.exe` at its root answer the identity probe and
 * run the scan in place of the real ASH. Both directories ASH needs are passed as
 * absolute arguments, so a working directory carries nothing the CLI reads. Leaving
 * the field out of the type means no caller can reintroduce it.
 */
export interface CommandOptions {
  readonly timeoutMs?: number;
}

/**
 * Runs the `--version` probe. Injected so tests drive every branch without a real
 * ASH on PATH. Asynchronous for the same reason the scan is: a cold Python start
 * can take seconds, and a synchronous wait holds the extension host -- every
 * extension in the window -- for all of it.
 */
export type CommandRunner = (
  executable: string,
  args: readonly string[],
  options: CommandOptions,
) => Promise<CommandResult>;

/**
 * How long the `--version` probe may take, in milliseconds. ASH answers in a few
 * seconds even cold; a minute bounds how long a wedged executable delays the scan.
 */
export const DEFAULT_TIMEOUT_MS = 60 * 1000;

/**
 * The default for `ash.scanTimeoutSeconds`. Generous on purpose: a first scan on a
 * cold host downloads scanner databases, and a timeout that fires on a healthy
 * scan teaches people to set it to 0.
 */
export const DEFAULT_SCAN_TIMEOUT_SECONDS = 30 * 60;

/** Grace between SIGTERM and SIGKILL when a scan is stopped. */
export const KILL_GRACE_MS = 5_000;

/**
 * How long to wait for the pipes to close after the child has exited.
 *
 * 'close' waits for every process holding the child's stdout and stderr, not
 * only the child. A grandchild that left the process group (setsid, or
 * `start_new_session` in Python) and kept the pipes would hold 'close' off
 * forever, and with it the progress notification and the one-scan-at-a-time
 * lock. After 'exit' the remaining output is normally already in the pipe, so a
 * short drain loses nothing a healthy run writes.
 */
export const EXIT_DRAIN_MS = 2_000;

/** `child_process.spawn`, injected so a child that exits without closing is testable. */
export type Spawner = (executable: string, args: string[], options: SpawnOptions) => ChildProcess;

/** Per-stream cap on captured output. The tail is kept; it holds the reason. */
const MAX_CAPTURED_CHARS = 4 * 1024 * 1024;

/**
 * The probe runner: `spawnAsyncRunner` with DEFAULT_TIMEOUT_MS unless the caller
 * names another limit.
 */
export function probeRunner(
  executable: string,
  args: readonly string[],
  options: CommandOptions = {},
): Promise<CommandResult> {
  return spawnAsyncRunner(executable, args, {
    timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
  });
}

/** No `cwd`, for the reason given on CommandOptions. */
export interface AsyncCommandOptions {
  /** Milliseconds before the process tree is stopped. 0 or less waits indefinitely. */
  readonly timeoutMs?: number;
  /** Aborting stops the process tree and resolves with `cancelled: true`. */
  readonly signal?: AbortSignal;
}

export interface AsyncCommandResult extends CommandResult {
  /** The timeout fired and the process tree was stopped. */
  readonly timedOut: boolean;
  /** The signal aborted and the process tree was stopped, or it never started. */
  readonly cancelled: boolean;
}

export type AsyncCommandRunner = (
  executable: string,
  args: readonly string[],
  options: AsyncCommandOptions,
) => Promise<AsyncCommandResult>;

/** How to stop a process tree. Injected so both platforms' arms are testable. */
export interface TreeKiller {
  readonly platform: NodeJS.Platform;
  /** `process.kill`. On POSIX a negative pid signals the whole process group. */
  readonly kill: (pid: number, signal: NodeJS.Signals) => void;
  /** Runs `taskkill`. Windows has no process groups to signal. */
  readonly spawnTaskkill: (args: readonly string[]) => void;
}

const realTreeKiller: TreeKiller = {
  platform: process.platform,
  kill: (pid, signal) => process.kill(pid, signal),
  spawnTaskkill: (args) => {
    spawn('taskkill', [...args], { windowsHide: true, stdio: 'ignore' }).on('error', () => {
      // A taskkill that cannot start leaves child.kill() in killProcessTree to
      // stop the direct child; there is no caller left to report it to.
    });
  },
};

/**
 * Stops a child and everything it started.
 *
 * ASH runs its scanners as subprocesses, so killing only the direct child leaves
 * semgrep or grype running and writing into the output directory after the scan
 * was reported stopped. On POSIX the child is started as a process-group leader
 * (`detached: true` below), so signalling `-pid` reaches the whole group: SIGTERM
 * first so ASH can stop its children, then SIGKILL after KILL_GRACE_MS. On Windows
 * `taskkill /T /F` walks the tree.
 *
 * Returns the SIGKILL timer, which is unref'd. Callers let it fire even after the
 * child closes: the rest of the group can outlive the leader.
 *
 * THE LIMIT OF A GROUP KILL. A process that put itself in a new session or group
 * (setsid, `start_new_session=True`) is no longer in the group and survives both
 * signals. No ASH code does that today; a scanner or a container CLI could. Such
 * a process is left running, and spawnAsyncRunner stops waiting for it after
 * EXIT_DRAIN_MS so the scan still settles.
 */
export function killProcessTree(
  child: Pick<ChildProcess, 'pid' | 'kill'>,
  killer: TreeKiller = realTreeKiller,
  graceMs: number = KILL_GRACE_MS,
): NodeJS.Timeout | undefined {
  const pid = child.pid;
  if (pid === undefined) {
    return undefined;
  }
  if (killer.platform === 'win32') {
    killer.spawnTaskkill(['/pid', String(pid), '/T', '/F']);
    child.kill();
    return undefined;
  }
  const signalGroup = (signal: NodeJS.Signals): void => {
    try {
      killer.kill(-pid, signal);
    } catch {
      // ESRCH: the group is already gone, which is the outcome wanted.
    }
  };
  signalGroup('SIGTERM');
  const timer = setTimeout(() => signalGroup('SIGKILL'), graceMs);
  timer.unref();
  return timer;
}

/** Appends to a capture buffer, keeping the tail when it outgrows the cap. */
function capture(buffer: string, chunk: string): string {
  const joined = buffer + chunk;
  return joined.length > MAX_CAPTURED_CHARS ? joined.slice(-MAX_CAPTURED_CHARS) : joined;
}

/**
 * The scan runner, over `child_process.spawn`. Never blocks the extension host.
 *
 * Resolves, never rejects: a process that could not start resolves with `error`
 * set, so the caller has one result type to classify.
 *
 * `shell` is deliberately left off. Passing the executable through a shell would
 * make a workspace path containing a space or a shell metacharacter part of the
 * command line, and on Windows it would reintroduce the very PATH lookup the
 * identity probe exists to constrain.
 */
export function spawnAsyncRunner(
  executable: string,
  args: readonly string[],
  options: AsyncCommandOptions = {},
  killer: TreeKiller = realTreeKiller,
  spawner: Spawner = spawn,
  drainMs: number = EXIT_DRAIN_MS,
): Promise<AsyncCommandResult> {
  return new Promise((resolve) => {
    if (options.signal?.aborted === true) {
      resolve({ status: null, stdout: '', stderr: '', timedOut: false, cancelled: true });
      return;
    }

    // No `cwd`: see CommandOptions. The child inherits the extension host's
    // working directory, which a workspace does not choose.
    const child = spawner(executable, [...args], {
      windowsHide: true,
      // A process-group leader on POSIX, so killProcessTree can signal the group.
      // Not on Windows, where detached means a new console window.
      detached: killer.platform !== 'win32',
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    let stoppedBecause: 'timeout' | 'cancel' | undefined;
    let settled = false;
    let drainTimer: NodeJS.Timeout | undefined;

    const stop = (why: 'timeout' | 'cancel'): void => {
      if (stoppedBecause !== undefined || settled) {
        return;
      }
      stoppedBecause = why;
      killProcessTree(child, killer);
    };
    const onAbort = (): void => stop('cancel');
    const timeoutMs = options.timeoutMs ?? 0;
    const timer = timeoutMs > 0 ? setTimeout(() => stop('timeout'), timeoutMs) : undefined;
    options.signal?.addEventListener('abort', onAbort, { once: true });

    const settle = (result: CommandResult): void => {
      if (settled) {
        return;
      }
      settled = true;
      if (timer !== undefined) {
        clearTimeout(timer);
      }
      if (drainTimer !== undefined) {
        clearTimeout(drainTimer);
      }
      // The SIGKILL timer is left to fire. 'close' means the direct child and its pipes
      // are done, not its process group: a scanner that ignored SIGTERM and does
      // not hold the pipes is still running, and the SIGKILL is what stops it.
      // The timer is unref'd, and signalling a group that is already gone is a
      // caught ESRCH.
      options.signal?.removeEventListener('abort', onAbort);
      resolve({
        ...result,
        timedOut: stoppedBecause === 'timeout',
        cancelled: stoppedBecause === 'cancel',
      });
    };

    // Both streams are drained: an unread pipe fills and blocks the child.
    child.stdout?.setEncoding('utf8');
    child.stderr?.setEncoding('utf8');
    child.stdout?.on('data', (chunk: string) => {
      stdout = capture(stdout, chunk);
    });
    child.stderr?.on('data', (chunk: string) => {
      stderr = capture(stderr, chunk);
    });
    child.on('error', (error) => settle({ status: null, stdout, stderr, error }));
    child.on('close', (code) => settle({ status: code, stdout, stderr }));
    // 'close' is preferred because it carries every byte, but it is not waited for
    // past EXIT_DRAIN_MS: after that whoever still holds the pipes is not the
    // child, and the streams are destroyed so this end lets go of them too.
    child.on('exit', (code) => {
      drainTimer = setTimeout(() => {
        child.stdout?.destroy();
        child.stderr?.destroy();
        settle({ status: code, stdout, stderr });
      }, drainMs);
    });
  });
}

/**
 * The substring that identifies ASH in its own `--version` output.
 *
 * It is the distribution name, not the string "ash": a bare "ash" would match
 * the Almquist shell's own error text on some builds, which is the one thing this
 * check has to exclude.
 */
export const ASH_IDENTITY_MARKER = 'automated-security-helper';

/**
 * The entry point to recommend when the probe fails.
 *
 * ASH installs three console scripts. `ash` is canonical, `ashv3` is deprecated
 * and names a version, and this one is kept indefinitely and silent precisely so
 * a host whose `ash` resolves elsewhere has something unambiguous to point at.
 */
export const ASH_FALLBACK_EXECUTABLE = 'automated-security-helper';

/**
 * The executable tried when `ash.executablePath` is empty.
 *
 * One constant each, so the CLI rename is a one-line change here. `ashx` is the v4
 * entry point; `ash` is tried next, and only when `ashx` is not on PATH at all, so
 * an install that predates the rename keeps working. A configured path is never
 * substituted: the user named a program, and running a different one would be a
 * surprise worse than the error.
 */
export const DEFAULT_EXECUTABLE = 'ashx';
export const LEGACY_EXECUTABLE = 'ash';

/**
 * ASH's exit codes, from `ash scan`'s own epilogue and `_compute_exit_code` in
 * automated_security_helper/interactions/run_ash_scan.py.
 *
 * 1 is two things. With results in hand it is `ScanIncompleteExit`: the scan
 * finished with partial coverage (a scanner ERROR or MISSING, lost targets, a
 * converter that never ran, an unevaluated rule, a stale content database), and
 * `fail_on_incomplete_scanners` defaults to true, so this is the ordinary result
 * of a scan on a host missing one tool. Without results it is a crash. The two
 * are told apart by whether this run wrote a report, never by the code alone.
 */
export const EXIT_NO_ACTIONABLE_FINDINGS = 0;
export const EXIT_INCOMPLETE_OR_ERROR = 1;
export const EXIT_ACTIONABLE_FINDINGS = 2;

export type IdentityProbe =
  | { readonly ok: true; readonly version: string }
  | {
      readonly ok: false;
      readonly message: string;
      /** The executable does not exist on PATH (ENOENT), as opposed to answering wrongly. */
      readonly notFound?: boolean;
    };

function combinedOutput(result: CommandResult): string {
  // ASH prints its version to stdout; a shell rejecting `--version` prints to
  // stderr. Both streams are searched so the probe cannot be fooled by which one
  // the answer arrived on.
  return `${result.stdout}\n${result.stderr}`;
}

function firstNonEmptyLine(text: string): string {
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (trimmed !== '') {
      return trimmed;
    }
  }
  return '';
}

/**
 * Confirms the configured executable is ASH.
 *
 * The failure message names `automated-security-helper` because that is the
 * action a user on an MSYS2 host has to take, and a message that only said "ash
 * not found" would send them to reinstall something they already have.
 */
export async function probeAshIdentity(
  executable: string,
  run: CommandRunner,
  options: CommandOptions = {},
): Promise<IdentityProbe> {
  const result = await run(executable, ['--version'], options);

  if (result.timedOut === true) {
    const limit = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    return {
      ok: false,
      message:
        `"${executable} --version" did not answer within ${Math.round(limit / 1000)}s and ` +
        'was stopped, so whether it is ASH is unknown. Refusing to scan.',
    };
  }

  if (result.error !== undefined) {
    const enoent = (result.error as NodeJS.ErrnoException).code === 'ENOENT';
    return {
      ok: false,
      notFound: enoent,
      message: enoent
        ? `Could not run "${executable}": it is not on PATH. Install ASH, or set ` +
          `ash.executablePath to its full path.`
        : `Could not run "${executable}": ${result.error.message}`,
    };
  }

  const output = combinedOutput(result);
  if (output.includes(ASH_IDENTITY_MARKER)) {
    return { ok: true, version: firstNonEmptyLine(output) };
  }

  return {
    ok: false,
    message:
      `"${executable}" answered, but it is not ASH: \`${executable} --version\` printed ` +
      `${JSON.stringify(firstNonEmptyLine(output))} instead of a string naming ` +
      `${ASH_IDENTITY_MARKER}. On Windows, MSYS2 and Git Bash ship the Almquist shell ` +
      `as "ash" and it shadows ASH on PATH. Set ash.executablePath to ` +
      `"${ASH_FALLBACK_EXECUTABLE}", which ASH installs for this case, or to ASH's ` +
      `full path. Refusing to scan: a shell writes no report, and an empty report ` +
      `would look exactly like a clean scan.`,
  };
}

/** The arguments for a workspace scan. */
export function scanArgs(
  sourceDir: string,
  outputDir: string,
  extra: readonly string[] = [],
): string[] {
  return [
    'scan',
    '--source-dir',
    sourceDir,
    '--output-dir',
    outputDir,
    // Progress rendering is Rich markup on a TTY. There is no TTY here, and the
    // bars would land in the captured output as escape sequences.
    '--no-progress',
    ...extra,
  ];
}

/** Where ASH writes the SARIF report, relative to its `--output-dir`. */
export const SARIF_RELATIVE_PATH = 'reports/ash.sarif';

/**
 * What the exit status says, before anyone looks for a report.
 *
 *   clean       exit 0.
 *   findings    exit 2. Findings make ASH exit 2 under the default
 *               `fail_on_findings: true`, so this is a normal scan.
 *   incomplete  exit 1. Partial results if this run wrote a report, a crash if it
 *               did not; the caller decides which by looking.
 *   failed      anything else: 3 and 4 (configuration errors), a signal, or a
 *               process that never started.
 *   timed-out   the scan outran `ash.scanTimeoutSeconds` and was stopped.
 *   cancelled   the user cancelled it.
 */
export type ExitVerdict = 'clean' | 'findings' | 'incomplete' | 'failed' | 'timed-out' | 'cancelled';

export function classifyExit(
  result: CommandResult & { readonly timedOut?: boolean; readonly cancelled?: boolean },
): ExitVerdict {
  // Before the status: a stopped process exits by signal, or with whatever code
  // ASH chose on SIGTERM, and neither says anything about the tree.
  if (result.cancelled === true) {
    return 'cancelled';
  }
  if (result.timedOut === true) {
    return 'timed-out';
  }
  if (result.error !== undefined) {
    return 'failed';
  }
  switch (result.status) {
    case EXIT_NO_ACTIONABLE_FINDINGS:
      return 'clean';
    case EXIT_ACTIONABLE_FINDINGS:
      return 'findings';
    case EXIT_INCOMPLETE_OR_ERROR:
      return 'incomplete';
    default:
      return 'failed';
  }
}

export interface ScanOutcome {
  /** The process result, so a caller can surface stderr on failure. */
  readonly result: CommandResult;
  readonly verdict: ExitVerdict;
}

export async function runScan(
  executable: string,
  sourceDir: string,
  outputDir: string,
  run: AsyncCommandRunner,
  extra: readonly string[] = [],
  options: AsyncCommandOptions = {},
): Promise<ScanOutcome> {
  const result = await run(executable, scanArgs(sourceDir, outputDir, extra), options);
  return { result, verdict: classifyExit(result) };
}

/** Which executable answered, and whether it was the fallback. */
export type ExecutableResolution =
  | {
      readonly ok: true;
      readonly executable: string;
      readonly version: string;
      /** True when `ashx` was not on PATH and `ash` answered instead. */
      readonly fellBack: boolean;
    }
  | { readonly ok: false; readonly message: string };

function isNotFound(probe: IdentityProbe): boolean {
  return !probe.ok && probe.notFound === true;
}

/**
 * Picks the executable to scan with.
 *
 * A non-empty `configured` value is probed as given and nothing else is tried.
 * An empty one tries DEFAULT_EXECUTABLE, then LEGACY_EXECUTABLE only when the
 * first is not found (ENOENT). An `ashx` that answers and is not ASH is an error,
 * not a reason to try `ash`: the name resolved to something, and scanning with a
 * different program would hide that.
 */
export async function resolveExecutable(
  configured: string,
  run: CommandRunner,
  options: CommandOptions = {},
): Promise<ExecutableResolution> {
  const explicit = configured.trim();
  if (explicit !== '') {
    const probe = await probeAshIdentity(explicit, run, options);
    return probe.ok
      ? { ok: true, executable: explicit, version: probe.version, fellBack: false }
      : { ok: false, message: probe.message };
  }

  const primary = await probeAshIdentity(DEFAULT_EXECUTABLE, run, options);
  if (primary.ok) {
    return { ok: true, executable: DEFAULT_EXECUTABLE, version: primary.version, fellBack: false };
  }
  if (!isNotFound(primary)) {
    return { ok: false, message: primary.message };
  }

  const legacy = await probeAshIdentity(LEGACY_EXECUTABLE, run, options);
  if (legacy.ok) {
    return { ok: true, executable: LEGACY_EXECUTABLE, version: legacy.version, fellBack: true };
  }
  if (isNotFound(legacy)) {
    return {
      ok: false,
      message:
        `Neither "${DEFAULT_EXECUTABLE}" nor "${LEGACY_EXECUTABLE}" is on PATH. Install ASH, ` +
        'or set ash.executablePath to its full path.',
    };
  }
  return { ok: false, message: legacy.message };
}

/**
 * The last few lines of a process's output, for an error message.
 *
 * ASH's own failure output is long and ends with the part that says what went
 * wrong, so the tail is the useful end. An error notification that carried the
 * whole of it would be unreadable and would push the reason off screen.
 */
export function outputTail(result: CommandResult, lines = 8): string {
  const text = `${result.stdout}\n${result.stderr}`
    .split('\n')
    .map((line) => line.trimEnd())
    .filter((line) => line !== '');
  return text.slice(-lines).join('\n');
}
