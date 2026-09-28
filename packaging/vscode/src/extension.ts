// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Extension entry point: one command, one diagnostic collection.
 *
 * WHY THE COMMAND RETURNS A VALUE
 *
 * Every failure below is surfaced twice: once to the user through
 * `showErrorMessage`, and once to the caller as a `ScanOutcome`. The message is
 * what a person sees; the return value is what a test can assert on, because
 * nothing in the extension API lets a test observe that a notification was
 * shown. A command whose only failure signal is a modal is a command whose
 * failure path cannot be tested, and an untested failure path in this
 * repository's history is how "reported success having done nothing" happens.
 *
 * So there is no silent arm anywhere in `runScan`: every early return names a
 * reason, a scan that hangs is killed and named rather than waited on forever,
 * and -- the case this file got wrong first time -- a scan that SUCCEEDS while
 * quietly discarding findings says so too. See `surfaceShortfalls`.
 */

import * as fsSync from 'fs';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as vscode from 'vscode';

import {
  DEFAULT_TIMEOUT_MS,
  describeExitCode,
  resolveAshCommand,
  runAshScan,
  SARIF_RELATIVE_PATH,
  SUCCESS_EXIT_CODES,
} from './ash';
import { failedInvocations, parseScannerStatus } from './completeness';
import { publishFindings } from './diagnostics';
import { parseSarif, SarifParseError } from './sarif';

export const SCAN_COMMAND = 'ash.scan';

export const DEFAULT_OUTPUT_DIRECTORY = '.ash/ash_output';

/** Why a scan did not produce diagnostics. Absent when it did. */
export type ScanFailureReason =
  | 'no-workspace'
  | 'bad-output-directory'
  | 'ash-not-found'
  | 'ash-timeout'
  | 'cancelled'
  | 'ash-failed'
  | 'sarif-missing'
  | 'sarif-stale'
  | 'sarif-unreadable';

export interface ScanOutcome {
  readonly ok: boolean;
  readonly reason?: ScanFailureReason;
  readonly message?: string;
  /** Process exit code, when ASH actually ran. */
  readonly exitCode?: number;
  readonly diagnosticCount?: number;
  readonly fileCount?: number;
  /** Findings whose SARIF uri could not be resolved to a file on disk. */
  readonly unresolved?: number;
  /** Results with no physical location, so nowhere to draw. */
  readonly skipped?: number;
  /**
   * Results ASH suppressed, deliberately not published.
   *
   * Reported in the outcome and in the log, but NOT as a warning notification --
   * unlike `skipped` and `unresolved`. The distinction is whether the user wanted
   * the finding hidden: a suppression is their own configuration working, so
   * warning about it every scan would be noise, while a skipped finding is one
   * they would have wanted and cannot see.
   */
  readonly suppressed?: number;
  /** Results whose `kind` is not `fail`, so not problems. */
  readonly notFailures?: number;
  /** Scanners in ASH's roster, when the aggregated report was readable. */
  readonly scannersTotal?: number;
  /** Scanners that did not reach a verdict: ERROR or MISSING. */
  readonly scannersIncomplete?: readonly string[];
  /**
   * True when completeness could not be determined -- no aggregated report beside
   * the SARIF, or no roster in it. Distinct from an empty `scannersIncomplete`,
   * which means it WAS determined and everything ran.
   */
  readonly completenessUnknown?: boolean;
  /** Nonconforming `level` spellings coerced during parsing. See sarif.ts. */
  readonly nonconformingLevels?: readonly string[];
}

/**
 * Picks the folder to scan.
 *
 * The active editor's folder wins in a multi-root workspace, because that is
 * the one the user is looking at; otherwise the first folder. Returning
 * undefined for a window with no folder open is deliberate -- ASH scans a
 * directory, and there is no defensible directory to invent.
 */
function targetFolder(): vscode.WorkspaceFolder | undefined {
  const folders = vscode.workspace.workspaceFolders;
  if (folders === undefined || folders.length === 0) {
    return undefined;
  }
  const active = vscode.window.activeTextEditor?.document.uri;
  if (active !== undefined) {
    const owning = vscode.workspace.getWorkspaceFolder(active);
    if (owning !== undefined) {
      return owning;
    }
  }
  return folders[0];
}

/**
 * Resolves `ash.outputDirectory` inside the workspace folder, or explains why it
 * cannot.
 *
 * CONFINED ON PURPOSE, AND THE DOCUMENTATION IS WHAT THIS IS OBEYING. The
 * setting is described in package.json and the README as "relative to the
 * workspace folder". The first implementation did not enforce either half: it
 * branched on `path.isAbsolute` and used an absolute value verbatim, and its
 * relative branch was a bare `path.resolve`, so `../../../var/tmp/x` escaped.
 * The setting is workspace-scoped -- legitimately, since a project may want its
 * own output location -- which meant a cloned repository could direct ASH's
 * output anywhere the user could write.
 *
 * Confining it is the fix rather than rewriting the documentation, because the
 * documented behavior is also the safe one and nothing needs the escape. An
 * absolute path is refused instead of being silently rebased: a user who typed
 * one is asking for something this will not do, and should be told.
 */
/**
 * The real path of `target`, resolving symlinks as far as the path exists.
 *
 * The output directory usually does NOT exist yet -- ASH creates it -- so
 * `realpathSync` on the whole path throws ENOENT and tells us nothing. Walking up to
 * the nearest existing ancestor and resolving THAT is what catches the case that
 * matters: the escape is via an existing symlinked component, and a not-yet-created
 * leaf under a real directory cannot escape anywhere.
 *
 * Synchronous deliberately. This runs once per scan, before a subprocess that takes
 * seconds, and it is a guard -- making it async would let the caller forget to await
 * it, which is a worse failure than a blocked millisecond.
 */
function realPathOfNearestAncestor(target: string): string {
  let current = path.resolve(target);
  const unresolved: string[] = [];

  for (;;) {
    try {
      return path.join(fsSync.realpathSync(current), ...unresolved.reverse());
    } catch {
      const parent = path.dirname(current);
      if (parent === current) {
        // Reached the filesystem root without finding anything that exists. Nothing
        // to resolve, so the lexical path is the best available answer.
        return path.resolve(target);
      }
      unresolved.push(path.basename(current));
      current = parent;
    }
  }
}

export function resolveOutputDirectory(
  sourceDir: string,
  configured: string | undefined,
): { ok: true; dir: string } | { ok: false; message: string } {
  const trimmed = (configured ?? '').trim();
  const relative = trimmed.length > 0 ? trimmed : DEFAULT_OUTPUT_DIRECTORY;

  if (path.isAbsolute(relative)) {
    return {
      ok: false,
      message:
        `\`ash.outputDirectory\` is "${relative}", an absolute path. ` +
        'It must be relative to the workspace folder. Change it to a path inside ' +
        `the folder, or clear it to use the default (${DEFAULT_OUTPUT_DIRECTORY}).`,
    };
  }

  // REAL PATHS, NOT LEXICAL ONES. `path.resolve` never touches the filesystem, so a
  // purely textual containment check is defeated by a symlink: a repository can ship
  // `.vscode/settings.json` with `ash.outputDirectory: "out"` alongside a committed
  // `out -> ~/.ssh`, and `out` has no `..` in it to catch. The setting is
  // workspace-scoped, which is exactly the threat model this function's docstring
  // already names, so the check has to resolve links before comparing.
  const resolved = realPathOfNearestAncestor(path.resolve(sourceDir, relative));
  const fromRoot = path.relative(realPathOfNearestAncestor(sourceDir), resolved);
  // `..` at the front means it escaped; an absolute result means the join did
  // not stay under the root at all (a drive-relative path on Windows).
  if (
    fromRoot === '..' ||
    fromRoot.startsWith(`..${path.sep}`) ||
    path.isAbsolute(fromRoot)
  ) {
    return {
      ok: false,
      message:
        `\`ash.outputDirectory\` (${relative}) resolves to ${resolved}, which is ` +
        'outside the workspace folder. It must stay inside the folder it ' +
        'describes. Clear the setting to use the default ' +
        `(${DEFAULT_OUTPUT_DIRECTORY}).`,
    };
  }

  return { ok: true, dir: resolved };
}

/** The file's mtime in milliseconds, or undefined if it does not exist. */
async function mtimeMs(target: string): Promise<number | undefined> {
  try {
    return (await fs.stat(target)).mtimeMs;
  } catch {
    return undefined;
  }
}

/**
 * Removes the previous run's report, returning whether it is now certainly gone.
 *
 * WHY THE REPORT IS DELETED BEFORE EVERY SCAN. Without this, a run that fails
 * partway and writes nothing leaves the PREVIOUS run's report on disk, and reading
 * it presents old findings as this run's result. Combined with treating a failing
 * exit code as success -- which this extension did -- the user saw a completed scan
 * with stale results and no signal whatsoever. Deleting first makes the absence of
 * a report after the run unambiguous.
 *
 * A false return means the file could not be removed, not that it is present. The
 * caller falls back to comparing mtimes in that case, so a read-only output
 * directory degrades to a weaker check rather than to no check.
 */
async function removeStaleReport(target: string): Promise<boolean> {
  try {
    await fs.unlink(target);
    return true;
  } catch (error) {
    // Already absent is the outcome this wanted, not a failure.
    return (error as NodeJS.ErrnoException).code === 'ENOENT';
  }
}

/** Where ASH writes the aggregated report, beside the SARIF's parent directory. */
const AGGREGATED_RESULTS_FILE = 'ash_aggregated_results.json';

interface Completeness {
  readonly total: number | undefined;
  readonly incomplete: readonly string[];
  readonly unknown: boolean;
  readonly allSkipped: boolean;
  readonly invocationFailures: readonly string[];
}

/**
 * Reads the scanner roster and the SARIF's own invocation failures.
 *
 * Two sources because they answer different halves. The roster in
 * `ash_aggregated_results.json` is the only place a MISSING scanner appears at all;
 * `executionSuccessful: false` in the SARIF covers a scanner that ran, produced
 * parseable output, and exited outside its success codes. See completeness.ts for
 * why neither alone is sufficient.
 */
async function readCompleteness(
  outputDir: string,
  sarifText: string,
  log: vscode.LogOutputChannel,
): Promise<Completeness> {
  const invocationFailures = failedInvocations(sarifText).map((failure) => {
    const code = failure.exitCode === undefined ? '' : ` (exit ${failure.exitCode})`;
    const why = failure.description === undefined ? '' : `: ${failure.description}`;
    return `an invocation reported failure${code}${why}`;
  });

  const rosterPath = path.join(outputDir, AGGREGATED_RESULTS_FILE);
  let roster;
  try {
    roster = parseScannerStatus(await fs.readFile(rosterPath, 'utf8'));
  } catch {
    roster = undefined;
  }

  if (roster === undefined) {
    // "Cannot tell" is reported as such rather than as "all fine". A completeness
    // check that answers yes when it has no data is the defect it exists to prevent.
    log.warn(
      `no readable scanner roster at ${rosterPath}, so it cannot be confirmed that ` +
        'every selected scanner ran. Findings below are what ASH reported; whether ' +
        'that is every scanner you selected is unknown.',
    );
    return {
      total: undefined,
      incomplete: [],
      unknown: true,
      allSkipped: false,
      invocationFailures,
    };
  }

  return {
    total: roster.total,
    incomplete: roster.incomplete.map((scanner) => {
      const deps =
        scanner.dependenciesSatisfied === false
          ? ', dependencies unavailable'
          : '';
      return `${scanner.name} (${scanner.status}${deps})`;
    }),
    unknown: false,
    allSkipped: roster.allSkipped,
    invocationFailures,
  };
}

/**
 * Tells the user the scan answered a narrower question than they asked.
 *
 * A WARNING, unlike the suppression count. Suppression is the user's own
 * configuration working as intended; a scanner that never ran is not, and an empty
 * Problems panel means something different when two of nine scanners are absent.
 */
function surfaceCompleteness(
  log: vscode.LogOutputChannel,
  completeness: Completeness,
  diagnosticCount: number,
): void {
  for (const failure of completeness.invocationFailures) {
    log.warn(failure);
  }

  // "CANNOT TELL" IS A USER-FACING FACT, and this arm was missing. `readCompleteness`
  // logs it and its own comment claims it is "reported as such rather than as all
  // fine" -- but with `unknown` true, `allSkipped` is false and both problem lists
  // are empty, so this function returned before notifying anything. The only signal
  // was a line in an output channel nobody opens, which to the user is
  // indistinguishable from everything having run.
  if (completeness.unknown) {
    void vscode.window.showWarningMessage(
      'ASH: could not confirm that every selected scanner ran -- no readable ' +
        'scanner roster was written beside the report. The findings shown are ' +
        'real; whether they cover every scanner you selected is unknown.',
    );
    return;
  }

  if (completeness.allSkipped) {
    log.warn('every scanner in the roster was SKIPPED, so nothing was measured');
    void vscode.window.showWarningMessage(
      'ASH: every scanner was skipped, so this scan measured nothing. An empty ' +
        'Problems panel here says nothing about the code.',
    );
    return;
  }

  const problems = [...completeness.incomplete, ...completeness.invocationFailures];
  if (problems.length === 0) {
    return;
  }

  const ran =
    completeness.total === undefined
      ? ''
      : ` ${completeness.total - completeness.incomplete.length} of ${completeness.total} scanners reached a verdict;`;
  const detail = problems.join('; ');
  log.warn(`incomplete scan:${ran} ${detail}`);
  void vscode.window.showWarningMessage(
    `ASH: this scan is incomplete.${ran} ${detail}. ` +
      (diagnosticCount === 0
        ? 'The Problems panel is empty, but that is not the same as clean.'
        : 'The findings shown are real but may not be all of them.'),
  );
}

function fail(
  log: vscode.LogOutputChannel,
  reason: ScanFailureReason,
  message: string,
  extra: Partial<ScanOutcome> = {},
): ScanOutcome {
  log.error(message);
  void vscode.window.showErrorMessage(`ASH: ${message}`);
  return { ok: false, reason, message, ...extra };
}

/**
 * Reports everything a successful scan did NOT turn into a diagnostic.
 *
 * THIS IS THE FALSE-CLEAN THIS FILE SHIPPED. sarif.ts promises that a result it
 * cannot place is "reported to the caller AND surfaced", and only the first half
 * was true: `skipped` and `unresolved` were returned in the outcome and appeared
 * in no message, no warning, and not even in the info log, which reported only
 * the published counts.
 *
 * The scenario that makes it serious: a reporter regression emits SARIF where
 * every result lacks `physicalLocation`. Every result is skipped, no finding is
 * published, and the user sees `published 0 diagnostic(s) across 0 file(s)` from
 * a command that succeeded -- indistinguishable from a genuinely clean scan.
 * `unresolved` is worse still, because publishFindings subtracts it from
 * `diagnosticCount`, so findings leave the reported total with nothing saying
 * so.
 *
 * This repository already caught this exact shape once, in
 * tests/unit/.../test_mcp_scan_workflow.py: "An empty runs list is what a broken
 * reporter produces, and a client reading it sees a clean scan." Caught there,
 * shipped here.
 *
 * A warning rather than an error: the scan did run and what it published is
 * real. What must not happen is silence.
 */
function surfaceShortfalls(
  log: vscode.LogOutputChannel,
  skipped: number,
  unresolved: number,
  nonconformingLevels: readonly string[],
): void {
  if (nonconformingLevels.length > 0) {
    // A producer writing `Level.error` instead of `error` is a real defect this
    // project has shipped, and a consumer that silently corrects it keeps it
    // alive. The severities were mapped to what the spelling plainly meant, so
    // the findings are fine and only the report is not spec-compliant.
    const spellings = nonconformingLevels.join(', ');
    log.warn(`SARIF contained nonconforming level values: ${spellings}`);
    void vscode.window.showWarningMessage(
      `ASH: SARIF used nonconforming level values (${spellings}). ` +
        'Severities were mapped to their obvious meaning; the report is not spec-compliant.',
    );
  }

  const shortfalls: string[] = [];
  if (skipped > 0) {
    shortfalls.push(
      `${skipped} result(s) carried no source location, so they could not be ` +
        'shown in the editor',
    );
  }
  if (unresolved > 0) {
    shortfalls.push(
      `${unresolved} finding(s) named a file this extension could not resolve ` +
        'to a path on disk',
    );
  }
  if (shortfalls.length === 0) {
    return;
  }

  const detail = shortfalls.join('; ');
  log.warn(`findings not shown: ${detail}`);
  void vscode.window.showWarningMessage(
    `ASH: ${detail}. Open the ASH output channel for details. ` +
      'These findings are NOT in the Problems panel, so it is not a complete picture.',
  );
}

export async function runScan(
  collection: vscode.DiagnosticCollection,
  log: vscode.LogOutputChannel,
): Promise<ScanOutcome> {
  const folder = targetFolder();
  if (folder === undefined) {
    return fail(
      log,
      'no-workspace',
      'no folder is open, so there is nothing to scan. Open a folder and run the command again.',
    );
  }

  const settings = vscode.workspace.getConfiguration('ash', folder.uri);
  const command = resolveAshCommand(settings.get<string>('executablePath'));
  const sourceDir = folder.uri.fsPath;

  const output = resolveOutputDirectory(
    sourceDir,
    settings.get<string>('outputDirectory'),
  );
  if (!output.ok) {
    return fail(log, 'bad-output-directory', output.message);
  }
  const outputDir = output.dir;

  const configuredTimeout = settings.get<number>('scanTimeoutSeconds');
  const timeoutMs =
    typeof configuredTimeout === 'number' && configuredTimeout >= 0
      ? configuredTimeout * 1000
      : DEFAULT_TIMEOUT_MS;

  log.info(`running '${command} scan' on ${sourceDir} (output: ${outputDir})`);

  // Established BEFORE the scan so "is this report from this run" is answerable
  // afterwards. See removeStaleReport.
  const sarifPath = path.join(outputDir, SARIF_RELATIVE_PATH);
  const mtimeBefore = await mtimeMs(sarifPath);
  const previousRemoved = await removeStaleReport(sarifPath);
  if (!previousRemoved) {
    log.warn(
      `could not remove the previous report at ${sarifPath}; falling back to an ` +
        'mtime comparison to tell this run\'s output from the last one',
    );
  }

  const run = await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'ASH: scanning workspace',
      // Cancellable because a scan can take minutes and an `ash` that hangs
      // would otherwise leave this notification up with no way out. The token is
      // bridged to an AbortSignal, which is what actually kills the child.
      cancellable: true,
    },
    (_progress, token) => {
      const controller = new AbortController();
      const subscription = token.onCancellationRequested(() => {
        log.warn('scan cancelled by the user');
        controller.abort();
      });
      return runAshScan({
        command,
        sourceDir,
        outputDir,
        timeoutMs,
        signal: controller.signal,
      }).finally(() => subscription.dispose());
    },
  );

  if (!run.ok) {
    return fail(log, run.reason, run.message);
  }

  log.info(`'${command} scan' exited ${run.exitCode}`);

  // The last of the stderr, for whichever failure message needs it.
  const said =
    run.stderr.trim().length > 0
      ? ` ASH said: ${run.stderr.trim().split('\n').slice(-3).join(' ')}`
      : '';
  const codeDetail = `${run.exitCode} (${describeExitCode(run.exitCode)})`;

  // THE ORDER OF THE NEXT THREE CHECKS IS THE POINT.
  //
  // Report-existence first, then freshness, then the exit code. That ordering is
  // what lets each message name a distinct situation: "ASH wrote nothing", "the
  // report on disk is the previous run's", and "ASH broke partway and this report
  // is partial". Testing the exit code first would collapse all three into one
  // message and lose the distinction that tells a user what to do next.
  const mtimeAfter = await mtimeMs(sarifPath);

  if (mtimeAfter === undefined) {
    return fail(
      log,
      'sarif-missing',
      `no SARIF report at ${sarifPath} after '${command} scan' exited ${codeDetail}.${said}`,
      { exitCode: run.exitCode },
    );
  }

  // A report that predates this run. Only reachable when the pre-scan delete
  // failed, since otherwise its absence is what the branch above catches.
  const fresh =
    previousRemoved || mtimeBefore === undefined || mtimeAfter > mtimeBefore;
  if (!fresh) {
    return fail(
      log,
      'sarif-stale',
      `the SARIF report at ${sarifPath} was not rewritten by this run -- it is ` +
        `from a previous scan, and '${command} scan' exited ${codeDetail}. ` +
        'Showing it would present old findings as this run\'s result.' +
        said,
      { exitCode: run.exitCode },
    );
  }

  // Only now the exit code. The report exists and belongs to this run, so a
  // failing code means ASH got partway and stopped -- which makes the report
  // PARTIAL, not wrong. Refusing to publish it is deliberate: an incomplete
  // Problems panel that looks complete is the false-clean this whole extension
  // has been corrected for twice already. The message says how to see it anyway.
  if (!SUCCESS_EXIT_CODES.has(run.exitCode)) {
    return fail(
      log,
      'ash-failed',
      `'${command} scan' exited ${codeDetail}, so its report is incomplete and ` +
        'has not been published. Exit 2 would be a normal scan with findings; ' +
        'this is not that. Fix the error and re-run; the partial report is at ' +
        `${sarifPath}.${said}`,
      { exitCode: run.exitCode },
    );
  }

  let text: string;
  try {
    text = await fs.readFile(sarifPath, 'utf8');
  } catch {
    // Racing with something that removed the file between the stat above and
    // here. Rare, and it must not read as a clean scan.
    return fail(
      log,
      'sarif-missing',
      `the SARIF report at ${sarifPath} disappeared between being checked and ` +
        `being read, after '${command} scan' exited ${codeDetail}.${said}`,
      { exitCode: run.exitCode },
    );
  }

  let parsed;
  try {
    parsed = parseSarif(text);
  } catch (error) {
    const detail =
      error instanceof SarifParseError ? error.message : String(error);
    return fail(log, 'sarif-unreadable', `could not read ${sarifPath}: ${detail}`, {
      exitCode: run.exitCode,
    });
  }

  const published = publishFindings(collection, parsed.findings, sourceDir);

  // COMPLETENESS, REPORTED ALONGSIDE THE FINDINGS AND NEVER BLOCKING THEM.
  //
  // A developer who legitimately lacks grype should still get the other scanners'
  // results -- that is exactly what `fail_on_incomplete_scanners` defaulting False
  // exists to protect. So this does not refuse to publish, unlike the `ash-failed`
  // arm above. The difference: there, the report itself was partial and could not be
  // trusted; here the findings are sound and the QUESTION they answer is narrower
  // than the user thinks.
  const completeness = await readCompleteness(outputDir, text, log);

  surfaceShortfalls(
    log,
    parsed.skipped,
    published.unresolved,
    parsed.nonconformingLevels,
  );
  surfaceCompleteness(log, completeness, published.diagnosticCount);

  // Every count the outcome carries appears here too. The info line used to
  // report only the two published numbers, which made it possible to read the
  // log of a scan that discarded findings and see nothing about it.
  log.info(
    `published ${published.diagnosticCount} diagnostic(s) across ` +
      `${published.fileCount} file(s); ${parsed.suppressed} suppressed by ASH, ` +
      `${parsed.notFailures} not failures, ${parsed.skipped} result(s) skipped ` +
      `for having no location, ${published.unresolved} finding(s) unresolved`,
  );

  return {
    ok: true,
    exitCode: run.exitCode,
    diagnosticCount: published.diagnosticCount,
    fileCount: published.fileCount,
    unresolved: published.unresolved,
    skipped: parsed.skipped,
    suppressed: parsed.suppressed,
    notFailures: parsed.notFailures,
    nonconformingLevels: parsed.nonconformingLevels,
    ...(completeness.total !== undefined
      ? { scannersTotal: completeness.total }
      : {}),
    scannersIncomplete: completeness.incomplete,
    completenessUnknown: completeness.unknown,
  };
}

export function activate(context: vscode.ExtensionContext): void {
  const log = vscode.window.createOutputChannel('ASH', { log: true });
  const collection = vscode.languages.createDiagnosticCollection('ash');

  // Both are disposed with the extension. The collection especially: leaving it
  // behind keeps stale squiggles in the editor after a reload.
  context.subscriptions.push(log, collection);
  context.subscriptions.push(
    vscode.commands.registerCommand(SCAN_COMMAND, () => runScan(collection, log)),
  );

  log.info('ASH extension activated');
}

export function deactivate(): void {
  // Nothing beyond the disposables registered in activate().
}
