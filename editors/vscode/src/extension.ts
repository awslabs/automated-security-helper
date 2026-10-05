// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Extension entry point: registers the commands and owns the diagnostic
 * collection.
 *
 * WHAT THIS EXTENSION IS, AND WHAT IT DELIBERATELY IS NOT
 *
 * It shells out to the ASH CLI already on the machine and reads the SARIF and the
 * aggregated results that CLI writes. It carries no scanners, no rules, no copy of
 * ASH, and no runtime npm dependencies -- the VS Code API and Node's standard
 * library are enough to spawn a process and parse JSON. packaging/README.md forbids
 * third-party code in an artifact this project publishes, and a `.vsix` is such an
 * artifact, so src/vsix-contents.ts is the mechanical check that keeps it that way.
 *
 * WHY EVERY FAILURE PATH ENDS IN A MESSAGE AND NEVER IN AN EMPTY EDITOR
 *
 * Zero diagnostics is what a clean scan looks like. It is also what a missing
 * executable, a shadowed one, a crashed scan, an unwritten report, a stale report
 * from the previous run and a scan whose scanners never ran look like. Each of
 * those has to be distinguishable from safety at the moment it happens, so no
 * branch below returns quietly. `runScanCommand` reports which one occurred, and
 * its return value is what the test suites assert on.
 *
 * THE EXIT-CODE CONTRACT
 *
 * 0 is clean and 2 is findings; both publish. 1 is ASH's `ScanIncompleteExit` when
 * this run wrote results: the findings are real and the set is partial, so they are
 * published AND the scan is reported incomplete, never as a plain failure. 1 with no
 * report from this run is a crash. Anything else is a failure.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import {
  AsyncCommandRunner,
  CommandRunner,
  DEFAULT_EXECUTABLE,
  DEFAULT_SCAN_TIMEOUT_SECONDS,
  LEGACY_EXECUTABLE,
  SARIF_RELATIVE_PATH,
  outputTail,
  probeRunner,
  resolveExecutable,
  runScan,
  spawnAsyncRunner,
} from './ash-cli';
import {
  AGGREGATED_RESULTS_FILE,
  CoverageAssessment,
  assessCoverageText,
  describeGaps,
} from './coverage';
import { PublishSummary, publishFindings } from './diagnostics';
import { parseAshSarif } from './sarif';

export const COMMAND_SCAN = 'ash.scanWorkspace';
export const COMMAND_CLEAR = 'ash.clearFindings';
export const CONFIG_SECTION = 'ash';
/** Name shown on the Problems panel filter and on the output channel. */
export const COLLECTION_NAME = 'ash';
/** globalState key recording that the ashx-to-ash fallback notice was shown. */
export const FALLBACK_NOTICE_KEY = 'ash.legacyExecutableNoticeShown';

/** What a scan amounted to. Every value other than `ok` carries a `detail`. */
export type ScanStatus =
  | 'ok'
  | 'incomplete'
  | 'no-workspace'
  | 'wrong-executable'
  | 'scan-failed'
  | 'no-report'
  | 'stale-report'
  | 'unreadable-report'
  | 'cancelled';

/**
 * The only statuses that leave findings on screen. Every other one clears the
 * collection, the way the JetBrains plugin drops its annotations on any failure:
 * findings left over from an earlier scan, next to an error about this one, read
 * as this scan's result.
 */
const STATUSES_THAT_PUBLISH: ReadonlySet<ScanStatus> = new Set<ScanStatus>(['ok', 'incomplete']);

export interface ScanReport {
  readonly status: ScanStatus;
  /** Present only when the scan reached the publish step. */
  readonly summary?: PublishSummary;
  /** Human-readable detail; always set when status is not 'ok'. */
  readonly detail?: string;
  /** The executable that ran the scan, once one was resolved. */
  readonly executable?: string;
  /**
   * Set when `ashx` was not on PATH and `ash` ran instead: `shown` the first time,
   * `already-shown` once the persisted flag says the user has seen the notice.
   */
  readonly fallbackNotice?: 'shown' | 'already-shown';
  /** The scan's exit status, once it ran. */
  readonly exitCode?: number | null;
  /**
   * The coverage verdict read from ash_aggregated_results.json. `null` when this
   * run wrote no readable results file, which means "cannot tell" -- not complete.
   */
  readonly coverage?: CoverageAssessment | null;
}

/** The pieces of the host a scan needs, so a test can supply each one. */
export interface ScanHost {
  readonly collection: vscode.DiagnosticCollection;
  /** Runs the `--version` probe. */
  readonly run: CommandRunner;
  /** Runs the scan without blocking the extension host. */
  readonly runAsync: AsyncCommandRunner;
  /**
   * Runs `task` under a cancellable progress notification. The signal aborts
   * when the user presses Cancel.
   */
  readonly withProgress: <T>(title: string, task: (signal: AbortSignal) => Promise<T>) => Promise<T>;
  readonly readFile: (file: string) => string;
  /** Modification time in milliseconds, or undefined when the file does not exist. */
  readonly mtimeMs: (file: string) => number | undefined;
  /** Deletes a file. True when it is gone afterwards, including when it was never there. */
  readonly removeFile: (file: string) => boolean;
  readonly log: (line: string) => void;
  readonly showError: (message: string) => void;
  readonly showWarning: (message: string) => void;
  readonly showInfo: (message: string) => void;
  /** Whether the one-time fallback notice has been shown, persisted across sessions. */
  readonly fallbackNoticeShown: () => boolean;
  readonly recordFallbackNoticeShown: () => void;
}

export interface ScanSettings {
  /** Empty means "resolve ashx, then ash, from PATH". */
  readonly executablePath: string;
  readonly outputDirectory: string;
  readonly extraArguments: readonly string[];
  /** Seconds before the scan is stopped. 0 waits indefinitely. */
  readonly scanTimeoutSeconds: number;
}

export function readSettings(): ScanSettings {
  const config = vscode.workspace.getConfiguration(CONFIG_SECTION);
  // Each `get` carries the same default as package.json's contributes block. A
  // `get` without one returns undefined when a user has explicitly set the value
  // to null.
  return {
    executablePath: (config.get<string>('executablePath', '') ?? '').trim(),
    outputDirectory: config.get<string>('outputDirectory', '.ash/ash_output') || '.ash/ash_output',
    extraArguments: config.get<string[]>('extraArguments', []) ?? [],
    scanTimeoutSeconds: timeoutSetting(config.get<number>('scanTimeoutSeconds', DEFAULT_SCAN_TIMEOUT_SECONDS)),
  };
}

/** A usable timeout from the raw setting: a negative or non-number falls back to the default. */
function timeoutSetting(raw: unknown): number {
  return typeof raw === 'number' && Number.isFinite(raw) && raw >= 0 ? raw : DEFAULT_SCAN_TIMEOUT_SECONDS;
}

/** The message the one-time fallback notice shows. Exported so tests pin it. */
export const FALLBACK_NOTICE =
  `ASH: "${DEFAULT_EXECUTABLE}" is not on PATH, so this extension is running ` +
  `"${LEGACY_EXECUTABLE}" instead. That works, and this notice is shown once. Install a ` +
  `version of ASH that provides "${DEFAULT_EXECUTABLE}", or set ash.executablePath to ` +
  'pin an executable and stop the lookup.';

interface ReportFile {
  readonly file: string;
  readonly mtimeBefore: number | undefined;
  readonly removed: boolean;
}

/**
 * Removes the previous run's report before the scan, so a report that is present
 * afterwards can only be this run's.
 *
 * ASH clears its own output first too (`_discard_prior_run_artifacts` and the
 * orchestrator's `initialize`), but this extension cannot assume the executable on
 * PATH is a version that does, and a run that fails before that point leaves the
 * old report in place. When the delete itself fails -- a read-only directory -- the
 * modification time taken here is the fallback evidence.
 */
function prepareReportFile(host: ScanHost, file: string): ReportFile {
  const mtimeBefore = host.mtimeMs(file);
  const removed = host.removeFile(file);
  if (!removed) {
    host.log(
      `could not remove the previous ${file}; comparing modification times to tell this ` +
        "run's output from the last one",
    );
  }
  return { file, mtimeBefore, removed };
}

/** 'absent', 'stale' (from a previous run), or 'fresh' (written by this run). */
function reportFreshness(host: ScanHost, report: ReportFile): 'absent' | 'stale' | 'fresh' {
  const after = host.mtimeMs(report.file);
  if (after === undefined) {
    return 'absent';
  }
  if (report.removed || report.mtimeBefore === undefined || after > report.mtimeBefore) {
    return 'fresh';
  }
  return 'stale';
}

/** Reads the coverage verdict from this run's results file, or null when it cannot. */
function readCoverage(host: ScanHost, report: ReportFile): CoverageAssessment | null {
  const freshness = reportFreshness(host, report);
  if (freshness !== 'fresh') {
    host.log(
      freshness === 'absent'
        ? `no ${AGGREGATED_RESULTS_FILE} at ${report.file}`
        : `${report.file} is from a previous run and was not read`,
    );
    return null;
  }
  let text: string;
  try {
    text = host.readFile(report.file);
  } catch (err) {
    host.log(`${report.file}: ${(err as Error).message}`);
    return null;
  }
  const assessment = assessCoverageText(text);
  if (assessment === undefined) {
    host.log(`${report.file} is not an ASH aggregated results document`);
    return null;
  }
  return assessment;
}

/**
 * Runs one scan and publishes its findings.
 *
 * Exported and dependency-injected rather than closed over `activate`'s locals so
 * the whole of it -- including every failure branch -- is reachable from a test.
 */
export async function runScanCommand(
  host: ScanHost,
  sourceDir: string | undefined,
  settings: ScanSettings,
): Promise<ScanReport> {
  const report = await scanAndPublish(host, sourceDir, settings);
  if (!STATUSES_THAT_PUBLISH.has(report.status)) {
    host.collection.clear();
  }
  return report;
}

async function scanAndPublish(
  host: ScanHost,
  sourceDir: string | undefined,
  settings: ScanSettings,
): Promise<ScanReport> {
  if (sourceDir === undefined) {
    const detail = 'ASH: open a folder before scanning. There is no workspace folder to scan.';
    host.showError(detail);
    return { status: 'no-workspace', detail };
  }

  // No working directory on the probe or the scan: see CommandOptions in ash-cli.ts.
  const resolved = await resolveExecutable(settings.executablePath, host.run);
  if (!resolved.ok) {
    host.log(resolved.message);
    host.showError(`ASH: ${resolved.message}`);
    return { status: 'wrong-executable', detail: resolved.message };
  }
  const executable = resolved.executable;
  host.log(`Using ${executable}: ${resolved.version}`);
  let fallbackNotice: ScanReport['fallbackNotice'];
  if (resolved.fellBack) {
    host.log(`"${DEFAULT_EXECUTABLE}" is not on PATH; fell back to "${LEGACY_EXECUTABLE}"`);
    if (host.fallbackNoticeShown()) {
      fallbackNotice = 'already-shown';
    } else {
      host.recordFallbackNoticeShown();
      host.showInfo(FALLBACK_NOTICE);
      fallbackNotice = 'shown';
    }
  }

  const outputDir = path.isAbsolute(settings.outputDirectory)
    ? settings.outputDirectory
    : path.join(sourceDir, settings.outputDirectory);
  const sarif = prepareReportFile(host, path.join(outputDir, ...SARIF_RELATIVE_PATH.split('/')));
  const aggregated = prepareReportFile(host, path.join(outputDir, AGGREGATED_RESULTS_FILE));

  const timeoutMs = settings.scanTimeoutSeconds * 1000;
  const outcome = await host.withProgress('ASH: scanning workspace', (signal) =>
    runScan(executable, sourceDir, outputDir, host.runAsync, settings.extraArguments, {
      timeoutMs,
      signal,
    }),
  );
  const exitCode = outcome.result.status;
  const base = { executable, exitCode, fallbackNotice };

  if (outcome.verdict === 'cancelled') {
    const detail = 'the scan was cancelled, and its process tree was stopped.';
    host.log(detail);
    host.showInfo(`ASH: ${detail}`);
    return { ...base, status: 'cancelled', detail };
  }
  if (outcome.verdict === 'timed-out') {
    const detail =
      `the scan did not finish within ${settings.scanTimeoutSeconds}s and was stopped, ` +
      'along with every process it started. Raise ash.scanTimeoutSeconds if large scans ' +
      `legitimately take longer, or set it to 0 to wait indefinitely.\n${outputTail(outcome.result)}`;
    host.log(detail);
    host.showError(`ASH: ${detail.split('\n')[0]}`);
    return { ...base, status: 'scan-failed', detail };
  }

  if (outcome.verdict === 'failed') {
    // A configuration error (3, 4), a signal, or a process that never started.
    // Reported even if a report is lying around: publishing it would show the
    // previous run's findings as this one's.
    const detail =
      `the scan did not complete (exit ${String(exitCode)})` +
      (outcome.result.error === undefined ? '' : `: ${outcome.result.error.message}`) +
      `\n${outputTail(outcome.result)}`;
    host.log(detail);
    host.showError(`ASH: ${detail.split('\n')[0]}. See the ASH output channel.`);
    return { ...base, status: 'scan-failed', detail };
  }

  const sarifFreshness = reportFreshness(host, sarif);
  if (sarifFreshness === 'absent') {
    if (outcome.verdict === 'incomplete') {
      // Exit 1 and no results: the crash half of exit 1.
      const detail =
        `the scan exited 1 and wrote no SARIF report at ${sarif.file}, so it failed ` +
        `before producing results.\n${outputTail(outcome.result)}`;
      host.log(detail);
      host.showError(`ASH: ${detail.split('\n')[0]} See the ASH output channel.`);
      return { ...base, status: 'scan-failed', detail };
    }
    // A missing report is not an empty report, and an empty editor would read as
    // a clean tree.
    const detail =
      `the scan exited ${String(exitCode)} but wrote no SARIF report at ` +
      `${sarif.file}, so there are no findings to show and no evidence the tree is clean.`;
    host.log(detail);
    host.showError(`ASH: ${detail}`);
    return { ...base, status: 'no-report', detail };
  }
  if (sarifFreshness === 'stale') {
    const detail =
      `the SARIF report at ${sarif.file} was not rewritten by this run (exit ` +
      `${String(exitCode)}); it is from a previous scan, and showing it would present ` +
      "old findings as this run's result.";
    host.log(detail);
    host.showError(`ASH: ${detail}`);
    return { ...base, status: 'stale-report', detail };
  }

  let parsed;
  try {
    parsed = parseAshSarif(host.readFile(sarif.file));
  } catch (err) {
    const detail = `${sarif.file}: ${(err as Error).message}`;
    host.log(detail);
    host.showError(`ASH: ${detail}`);
    return { ...base, status: 'unreadable-report', detail };
  }

  const summary = publishFindings(host.collection, sourceDir, parsed);
  const coverage = readCoverage(host, aggregated);
  const tools = parsed.toolNames.length === 0 ? 'ASH' : parsed.toolNames.join(', ');
  host.log(
    `${tools}: ${summary.diagnostics} finding(s) across ${summary.files} file(s); ` +
      `${summary.suppressed} suppressed by ASH, ${summary.notFailures} not failures, ` +
      `${summary.unlocated} with no file location, ${summary.unresolved} naming no local file`,
  );
  surfaceShortfalls(host, summary);

  const incomplete = outcome.verdict === 'incomplete' || coverage?.coverage_complete === false;
  if (incomplete) {
    const detail = incompleteDetail(exitCode, coverage, summary);
    host.log(detail);
    host.showWarning(`ASH: ${detail}`);
    return { ...base, status: 'incomplete', summary, coverage, detail };
  }

  if (coverage === null) {
    // "Cannot tell" is a fact the user needs; it is not the same as complete.
    host.showWarning(
      `ASH: could not confirm that every selected scanner ran: this run wrote no readable ` +
        `${AGGREGATED_RESULTS_FILE} beside the report. The findings shown are real.`,
    );
  }
  host.showInfo(
    summary.diagnostics === 0
      ? `ASH: scan completed with no findings at or above the configured severity threshold.`
      : `ASH: ${summary.diagnostics} finding(s) in ${summary.files} file(s). See the Problems panel.`,
  );
  return { ...base, status: 'ok', summary, coverage };
}

function incompleteDetail(
  exitCode: number | null,
  coverage: CoverageAssessment | null,
  summary: PublishSummary,
): string {
  const gaps = coverage === null ? [] : describeGaps(coverage);
  const why =
    gaps.length > 0
      ? gaps.join('; ')
      : coverage === null
        ? `no readable ${AGGREGATED_RESULTS_FILE} was written, so which part is missing is unknown`
        : 'the results file names no gap this extension recognizes; see the ASH output channel';
  const shown =
    summary.diagnostics === 0
      ? 'The Problems panel is empty, but that is not the same as clean.'
      : `The ${summary.diagnostics} finding(s) shown are real but may not be all of them.`;
  return `the scan is incomplete (exit ${String(exitCode)}): ${why}. ${shown}`;
}

/** Findings the Problems panel cannot show, said out loud. Suppressions are not. */
function surfaceShortfalls(host: ScanHost, summary: PublishSummary): void {
  const missing: string[] = [];
  if (summary.unlocated > 0) {
    missing.push(`${summary.unlocated} finding(s) named no file`);
  }
  if (summary.unresolved > 0) {
    missing.push(`${summary.unresolved} finding(s) named a file with no path on this machine`);
  }
  if (missing.length > 0) {
    host.showError(
      `ASH: ${missing.join(' and ')} and cannot be placed in the editor. ` +
        'See the ASH output channel.',
    );
  }
}

/** The first workspace folder's path, or undefined when no folder is open. */
export function currentSourceDir(): string | undefined {
  const folders = vscode.workspace.workspaceFolders;
  return folders === undefined || folders.length === 0 ? undefined : folders[0].uri.fsPath;
}

function mtimeOf(file: string): number | undefined {
  try {
    return fs.statSync(file).mtimeMs;
  } catch {
    return undefined;
  }
}

function removeIfPresent(file: string): boolean {
  try {
    fs.unlinkSync(file);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === 'ENOENT';
  }
}

/**
 * The real host: the spawner, the filesystem, the notifications and the persisted
 * fallback flag.
 *
 * Exported so a test can build the same object `activate` builds and exercise its
 * members. Wiring that only exists inside `activate` is wiring nobody has run.
 */
export function createScanHost(
  collection: vscode.DiagnosticCollection,
  channel: vscode.OutputChannel,
  globalState: vscode.Memento,
): ScanHost {
  return {
    collection,
    run: probeRunner,
    runAsync: spawnAsyncRunner,
    withProgress: (title, task) =>
      Promise.resolve(
        vscode.window.withProgress(
          { location: vscode.ProgressLocation.Notification, title, cancellable: true },
          (_progress, token) => {
            const controller = new AbortController();
            const subscription = token.onCancellationRequested(() => controller.abort());
            return task(controller.signal).finally(() => subscription.dispose());
          },
        ),
      ),
    readFile: (file) => fs.readFileSync(file, 'utf8'),
    mtimeMs: mtimeOf,
    removeFile: removeIfPresent,
    log: (line) => channel.appendLine(line),
    // `void` and not `await`: a command handler that awaited a notification would
    // stay pending until the user dismissed it.
    showError: (message) => {
      void vscode.window.showErrorMessage(message);
    },
    showWarning: (message) => {
      void vscode.window.showWarningMessage(message);
    },
    showInfo: (message) => {
      void vscode.window.showInformationMessage(message);
    },
    fallbackNoticeShown: () => globalState.get<boolean>(FALLBACK_NOTICE_KEY, false),
    recordFallbackNoticeShown: () => {
      void globalState.update(FALLBACK_NOTICE_KEY, true);
    },
  };
}

export function activate(context: vscode.ExtensionContext): void {
  const collection = vscode.languages.createDiagnosticCollection(COLLECTION_NAME);
  const channel = vscode.window.createOutputChannel('ASH');
  context.subscriptions.push(collection, channel);

  const host = createScanHost(collection, channel, context.globalState);

  // One scan at a time. A second invocation while one runs gets the running
  // scan's result rather than a second process writing the same output directory.
  let running: Promise<ScanReport> | undefined;
  context.subscriptions.push(
    vscode.commands.registerCommand(COMMAND_SCAN, () => {
      running ??= runScanCommand(host, currentSourceDir(), readSettings()).finally(() => {
        running = undefined;
      });
      return running;
    }),
    vscode.commands.registerCommand(COMMAND_CLEAR, () => {
      collection.clear();
      channel.appendLine('Cleared ASH findings.');
    }),
  );
}

export function deactivate(): void {
  // Nothing to do: the diagnostic collection and the output channel are both in
  // `context.subscriptions`, which VS Code disposes on unload.
}
