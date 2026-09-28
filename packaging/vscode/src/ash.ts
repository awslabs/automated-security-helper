// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Invoking the `ash` CLI.
 *
 * This extension ships no scanner and no scanner assets. It runs the ASH the
 * user installed, and everything it reports comes from that process's own
 * output. The CLI contract it depends on, read from the CLI rather than assumed:
 *
 *   ash scan --source-dir <dir> --output-dir <dir>
 *
 * with the SARIF report written to `<output-dir>/reports/ash.sarif`. See
 * automated_security_helper/cli/scan.py for the two options and
 * automated_security_helper/interactions/run_ash_scan.py for the report path.
 */

import { spawn } from 'child_process';
import * as path from 'path';

/** Where `ash scan` puts its SARIF, relative to the output directory. */
export const SARIF_RELATIVE_PATH = path.join('reports', 'ash.sarif');

/** How long to wait for `ash scan` before killing it, when none is configured. */
export const DEFAULT_TIMEOUT_MS = 600_000;

/**
 * The exit codes that mean the scan ran to completion.
 *
 * READ FROM ASH'S OWN SOURCE, not inferred from a stub. The table printed by
 * automated_security_helper/interactions/run_ash_scan.py:2486-2494 and modelled as
 * WorkspaceExitCode in automated_security_helper/models/workspace.py:182-186:
 *
 *     0  SUCCESS               no actionable findings, or not configured to fail
 *     1  INTERNAL_ERROR        "scan errors / scanner failures"
 *     2  ACTIONABLE_FINDINGS   findings above threshold, with fail_on_findings
 *     3  INVALID_PROJECT_CONFIG
 *     4  WORKSPACE_ERROR
 *
 * So 2 IS A SUCCESSFUL SCAN and must not be treated as failure: `fail_on_findings`
 * defaults to true, which makes 2 the ordinary result of any scan that finds
 * something. Rejecting it would break the common case, which is presumably how
 * treating 1 as the findings code got adopted in the first place -- this extension
 * did exactly that, and its stub fixture encoded the same wrong belief, so the
 * suite could not catch it.
 *
 * 1 is the code that matters here: run_ash_scan.py:2499-2503 notes that "an
 * incomplete scan and a crash share exit 1". Both mean the report cannot be
 * trusted as a complete result, so both are failures for this consumer.
 */
export const SUCCESS_EXIT_CODES: ReadonlySet<number> = new Set([0, 2]);

/** A human-readable gloss for an ASH exit code, for error messages. */
export function describeExitCode(code: number): string {
  switch (code) {
    case 0:
      return 'success, no actionable findings';
    case 1:
      return 'error during execution -- a crash, or scanners that failed or were incomplete';
    case 2:
      return 'actionable findings above the configured threshold';
    case 3:
      return 'invalid project configuration';
    case 4:
      return 'workspace definition or policy error';
    default:
      return 'an exit code ASH does not document';
  }
}

/** Grace period between SIGTERM and SIGKILL when a scan is killed. */
const KILL_GRACE_MS = 5_000;

export type AshFailureReason = 'ash-not-found' | 'ash-timeout' | 'cancelled';

export type AshRunResult =
  | { readonly ok: true; readonly exitCode: number; readonly stderr: string }
  | {
      readonly ok: false;
      readonly reason: AshFailureReason;
      readonly command: string;
      readonly message: string;
    };

export interface AshRunOptions {
  readonly command: string;
  readonly sourceDir: string;
  readonly outputDir: string;
  /** Overrides the child's environment. Defaults to this process's. */
  readonly env?: NodeJS.ProcessEnv;
  /** Milliseconds before the scan is killed. 0 or negative disables the timeout. */
  readonly timeoutMs?: number;
  /** Aborting kills the scan and resolves with reason `cancelled`. */
  readonly signal?: AbortSignal;
}

/**
 * Resolves which executable to run.
 *
 * An empty or whitespace-only setting means "resolve `ash` from PATH", which is
 * what the default install gives. A configured value is used verbatim, so `~`
 * is NOT expanded -- the shell is not involved (see `runAshScan`), so a literal
 * `~/bin/ash` would be looked up as a directory named `~` and fail with ENOENT.
 * Failing visibly on a path the user can read back is better than silently
 * rewriting what they typed.
 */
export function resolveAshCommand(configured: string | undefined): string {
  const trimmed = (configured ?? '').trim();
  return trimmed.length > 0 ? trimmed : 'ash';
}

/**
 * Runs `ash scan` and resolves once the process exits, is killed, or fails to
 * start.
 *
 * A NON-ZERO EXIT IS NOT A FAILURE OF THIS FUNCTION. ASH exits non-zero when it
 * finds problems at or above the configured threshold, which is the normal
 * outcome of a useful scan -- so the exit code is returned rather than thrown
 * on, and the caller decides. What IS a failure is never having run, or never
 * finishing.
 *
 * `shell: false` (the default) on purpose. The workspace path goes into the
 * argument list, and with a shell a folder named `$(...)` or with a quote in it
 * would be interpreted rather than passed. It also means ENOENT reaches us as an
 * error event instead of becoming a shell's own 127, which is what makes the
 * "ash is not installed" case distinguishable from "ash ran and failed".
 *
 * NO `cwd` IS SET, AND THAT IS DELIBERATE. Both directories are passed as
 * absolute paths, so the child needs no particular working directory -- `cwd`
 * carried nothing the CLI reads. It also carried a Windows exposure: with
 * `shell: false` Node reaches `CreateProcessW` with an unqualified program name
 * when the command is a bare `ash`, and that function's search order includes the
 * PROCESS'S CURRENT DIRECTORY ahead of PATH. Setting `cwd` to the workspace
 * therefore let a repository containing `ash.exe` at its root win over the real
 * install, on a command whose whole purpose is scanning code you have reason to
 * distrust. Not setting it removes that, unconditionally and with no platform
 * check to get wrong.
 */
export function runAshScan(options: AshRunOptions): Promise<AshRunResult> {
  return new Promise((resolve) => {
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

    // Checked before spawning: an already-aborted signal must not start a
    // process that is then immediately killed.
    if (options.signal?.aborted === true) {
      resolve({
        ok: false,
        reason: 'cancelled',
        command: options.command,
        message: 'the scan was cancelled before it started.',
      });
      return;
    }

    const child = spawn(
      options.command,
      [
        'scan',
        '--source-dir',
        options.sourceDir,
        '--output-dir',
        options.outputDir,
      ],
      {
        env: options.env ?? process.env,
        shell: false,
      },
    );

    let stderr = '';
    let settled = false;
    let timer: NodeJS.Timeout | undefined;
    let killTimer: NodeJS.Timeout | undefined;
    // Set before the kill, so the `close` handler knows why the child died
    // rather than reporting a SIGTERM exit as an ordinary one.
    let killedBecause: 'ash-timeout' | 'cancelled' | undefined;

    const cleanup = (): void => {
      if (timer !== undefined) {
        clearTimeout(timer);
      }
      if (killTimer !== undefined) {
        clearTimeout(killTimer);
      }
      options.signal?.removeEventListener('abort', onAbort);
    };

    const settle = (result: AshRunResult): void => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      resolve(result);
    };

    /**
     * Kills the child and records why.
     *
     * SIGTERM first so ASH can finish writing whatever it has, then SIGKILL
     * after a grace period: a scanner subprocess that ignores SIGTERM would
     * otherwise keep the promise pending forever, which is the exact hang this
     * whole mechanism exists to end. The grace timer is unref'd so it cannot
     * hold the extension host open by itself.
     */
    const terminate = (why: 'ash-timeout' | 'cancelled'): void => {
      if (killedBecause !== undefined) {
        return;
      }
      killedBecause = why;
      child.kill('SIGTERM');
      killTimer = setTimeout(() => child.kill('SIGKILL'), KILL_GRACE_MS);
      killTimer.unref?.();
    };

    function onAbort(): void {
      terminate('cancelled');
    }

    if (timeoutMs > 0) {
      timer = setTimeout(() => terminate('ash-timeout'), timeoutMs);
    }
    options.signal?.addEventListener('abort', onAbort, { once: true });

    // Both streams are drained. An unread pipe fills its buffer and the child
    // blocks writing to it, which would hang a scan that produces a lot of
    // output -- a deadlock that only shows up on large workspaces.
    child.stdout?.on('data', () => {
      /* drained and discarded; the SARIF file is the output that matters */
    });
    child.stderr?.on('data', (chunk: Buffer) => {
      // Bounded: a failing scanner can emit megabytes, and all that is wanted
      // is enough to put in an error message.
      if (stderr.length < 8192) {
        stderr += chunk.toString('utf8');
      }
    });

    child.on('error', (error: NodeJS.ErrnoException) => {
      if (error.code === 'ENOENT') {
        settle({
          ok: false,
          reason: 'ash-not-found',
          command: options.command,
          message:
            `Could not run '${options.command}': no such executable. ` +
            'Install ASH (https://github.com/awslabs/automated-security-helper) ' +
            'or set `ash.executablePath` to its location.',
        });
        return;
      }
      // EACCES on a non-executable file, and anything else spawn can raise.
      // Reported through the same branch because the user's next action is the
      // same: fix the path or the install.
      settle({
        ok: false,
        reason: 'ash-not-found',
        command: options.command,
        message: `Could not run '${options.command}': ${error.message}`,
      });
    });

    child.on('close', (code, signal) => {
      if (killedBecause === 'ash-timeout') {
        settle({
          ok: false,
          reason: 'ash-timeout',
          command: options.command,
          message:
            `'${options.command} scan' did not finish within ` +
            `${Math.round(timeoutMs / 1000)}s and was stopped. Raise ` +
            '`ash.scanTimeoutSeconds` if large scans legitimately take longer, ' +
            'or set it to 0 to wait indefinitely.',
        });
        return;
      }
      if (killedBecause === 'cancelled') {
        settle({
          ok: false,
          reason: 'cancelled',
          command: options.command,
          message: `'${options.command} scan' was cancelled.`,
        });
        return;
      }
      // A killed process reports code null. Reporting that as 0 would read as a
      // clean scan, so it becomes a non-zero code the caller can act on.
      settle({
        ok: true,
        exitCode: code ?? (signal !== null ? 128 : 1),
        stderr,
      });
    });
  });
}
