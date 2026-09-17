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

/** What a spawned command produced. Modelled on `child_process.SpawnSyncReturns`. */
export interface CommandResult {
  /** Exit status, or null when the process was killed by a signal. */
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
  /** Set when the process could not be started at all, e.g. ENOENT. */
  readonly error?: Error;
}

export interface CommandOptions {
  readonly cwd?: string;
  readonly timeoutMs?: number;
}

/** Injected so tests drive every branch without a real ASH on PATH. */
export type CommandRunner = (
  executable: string,
  args: readonly string[],
  options: CommandOptions,
) => CommandResult;

/** How long a scan may run before it is killed, in milliseconds. */
export const DEFAULT_TIMEOUT_MS = 15 * 60 * 1000;

/**
 * The real runner, over `child_process.spawnSync`.
 *
 * `shell` is deliberately left off. Passing the executable through a shell would
 * make a workspace path containing a space or a shell metacharacter part of the
 * command line, and on Windows it would reintroduce the very PATH lookup the
 * identity probe exists to constrain.
 */
export function spawnSyncRunner(
  executable: string,
  args: readonly string[],
  options: CommandOptions = {},
): CommandResult {
  // Required here rather than at module load so this file stays importable in a
  // test environment that stubs the module registry.
  /* eslint-disable-next-line @typescript-eslint/no-var-requires */
  const { spawnSync } = require('child_process') as typeof import('child_process');
  const result = spawnSync(executable, [...args], {
    cwd: options.cwd,
    encoding: 'utf8',
    timeout: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    // A scan on a large tree can print more than the 1 MiB default, and a
    // truncated stream raises ENOBUFS, which would be reported as "ASH failed"
    // on a scan that actually worked.
    maxBuffer: 64 * 1024 * 1024,
    windowsHide: true,
  });
  return {
    status: result.status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
    error: result.error,
  };
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

/** ASH's documented exit codes, from `ash scan`'s own epilogue. */
export const EXIT_NO_ACTIONABLE_FINDINGS = 0;
export const EXIT_EXECUTION_ERROR = 1;
export const EXIT_ACTIONABLE_FINDINGS = 2;

export type IdentityProbe =
  | { readonly ok: true; readonly version: string }
  | { readonly ok: false; readonly message: string };

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
export function probeAshIdentity(
  executable: string,
  run: CommandRunner,
  options: CommandOptions = {},
): IdentityProbe {
  const result = run(executable, ['--version'], options);

  if (result.error !== undefined) {
    const enoent = (result.error as NodeJS.ErrnoException).code === 'ENOENT';
    return {
      ok: false,
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

export interface ScanOutcome {
  /** The process result, so a caller can surface stderr on failure. */
  readonly result: CommandResult;
  /**
   * True when the exit code says the scan ran to completion, whether or not it
   * found anything. Findings make ASH exit 2 under this repository's default
   * `fail_on_findings: true`, so treating any non-zero code as failure would
   * report a broken scan every time the extension had something to show.
   */
  readonly completed: boolean;
}

export function runScan(
  executable: string,
  sourceDir: string,
  outputDir: string,
  run: CommandRunner,
  extra: readonly string[] = [],
  options: CommandOptions = {},
): ScanOutcome {
  const result = run(executable, scanArgs(sourceDir, outputDir, extra), {
    cwd: sourceDir,
    ...options,
  });
  const completed =
    result.error === undefined &&
    (result.status === EXIT_NO_ACTIONABLE_FINDINGS || result.status === EXIT_ACTIONABLE_FINDINGS);
  return { result, completed };
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
