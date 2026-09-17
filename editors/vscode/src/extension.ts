// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Extension entry point: registers the commands and owns the diagnostic
 * collection.
 *
 * WHAT THIS EXTENSION IS, AND WHAT IT DELIBERATELY IS NOT
 *
 * It shells out to the `ash` CLI already on the machine and reads the SARIF that
 * CLI writes. It carries no scanners, no rules, no copy of ASH, and no runtime
 * npm dependencies -- the VS Code API and Node's standard library are enough to
 * spawn a process and parse JSON. That is not minimalism for its own sake:
 * packaging/README.md forbids third-party code in an artifact this project
 * publishes, and a `.vsix` is such an artifact, so a runtime dependency would be
 * a boundary question rather than a packaging detail. src/vsix-contents.ts is the
 * mechanical check that keeps it that way.
 *
 * WHY EVERY FAILURE PATH ENDS IN A MESSAGE AND NEVER IN AN EMPTY EDITOR
 *
 * Zero diagnostics is what a clean scan looks like. It is also what a missing
 * `ash`, a shadowed `ash`, a crashed scan and an unwritten report look like, and
 * the whole reason this file is written the way it is: each of those five
 * outcomes has to be distinguishable from safety at the moment it happens. So no
 * branch below returns quietly. `runScanCommand` reports which one occurred, and
 * its return value is what the test suite asserts on.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import {
  CommandRunner,
  SARIF_RELATIVE_PATH,
  outputTail,
  probeAshIdentity,
  runScan,
  spawnSyncRunner,
} from './ash-cli';
import { PublishSummary, publishFindings } from './diagnostics';
import { parseAshSarif } from './sarif';

export const COMMAND_SCAN = 'ash.scanWorkspace';
export const COMMAND_CLEAR = 'ash.clearFindings';
export const CONFIG_SECTION = 'ash';
/** Name shown on the Problems panel filter and on the output channel. */
export const COLLECTION_NAME = 'ash';

/** Why a scan produced no diagnostics, when it produced none. */
export type ScanStatus =
  | 'ok'
  | 'no-workspace'
  | 'wrong-executable'
  | 'scan-failed'
  | 'no-report'
  | 'unreadable-report';

export interface ScanReport {
  readonly status: ScanStatus;
  /** Present only when the scan reached the publish step. */
  readonly summary?: PublishSummary;
  /** Human-readable detail; always set when status is not 'ok'. */
  readonly detail?: string;
}

/** The pieces of the host a scan needs, so a test can supply each one. */
export interface ScanHost {
  readonly collection: vscode.DiagnosticCollection;
  readonly run: CommandRunner;
  readonly readFile: (file: string) => string;
  readonly fileExists: (file: string) => boolean;
  readonly log: (line: string) => void;
  readonly showError: (message: string) => void;
  readonly showInfo: (message: string) => void;
}

export interface ScanSettings {
  readonly executablePath: string;
  readonly outputDirectory: string;
  readonly extraArguments: readonly string[];
}

export function readSettings(): ScanSettings {
  const config = vscode.workspace.getConfiguration(CONFIG_SECTION);
  // Each `get` carries the same default as package.json's contributes block. A
  // `get` without one returns undefined when a user has explicitly set the value
  // to null, and `undefined` as an executable name spawns nothing.
  return {
    executablePath: config.get<string>('executablePath', 'ash') || 'ash',
    outputDirectory: config.get<string>('outputDirectory', '.ash/ash_output') || '.ash/ash_output',
    extraArguments: config.get<string[]>('extraArguments', []) ?? [],
  };
}

/**
 * Runs one scan and publishes its findings.
 *
 * Exported and dependency-injected rather than closed over `activate`'s locals so
 * the whole of it -- including every failure branch -- is reachable from a test.
 */
export function runScanCommand(
  host: ScanHost,
  sourceDir: string | undefined,
  settings: ScanSettings,
): ScanReport {
  if (sourceDir === undefined) {
    const detail = 'ASH: open a folder before scanning. There is no workspace folder to scan.';
    host.showError(detail);
    return { status: 'no-workspace', detail };
  }

  const probe = probeAshIdentity(settings.executablePath, host.run, { cwd: sourceDir });
  if (!probe.ok) {
    host.log(probe.message);
    host.showError(`ASH: ${probe.message}`);
    return { status: 'wrong-executable', detail: probe.message };
  }
  host.log(`Using ${settings.executablePath}: ${probe.version}`);

  const outputDir = path.isAbsolute(settings.outputDirectory)
    ? settings.outputDirectory
    : path.join(sourceDir, settings.outputDirectory);

  const outcome = runScan(
    settings.executablePath,
    sourceDir,
    outputDir,
    host.run,
    settings.extraArguments,
    { cwd: sourceDir },
  );

  const sarifFile = path.join(outputDir, ...SARIF_RELATIVE_PATH.split('/'));

  if (!outcome.completed) {
    // Exit 2 means findings and is not a failure -- runScan already accounts for
    // that -- so reaching here is a real error, a signal, or a process that never
    // started. Report it even if a stale SARIF from a previous run is lying
    // around, because publishing that would show yesterday's findings as today's.
    const detail =
      `the scan did not complete (exit ${String(outcome.result.status)})` +
      (outcome.result.error === undefined ? '' : `: ${outcome.result.error.message}`) +
      `\n${outputTail(outcome.result)}`;
    host.log(detail);
    host.showError(`ASH: ${detail.split('\n')[0]}. See the ASH output channel.`);
    return { status: 'scan-failed', detail };
  }

  if (!host.fileExists(sarifFile)) {
    // The case that most needs saying out loud. A missing report is not an empty
    // report, and an empty editor would read as a clean tree.
    const detail =
      `the scan exited ${String(outcome.result.status)} but wrote no SARIF report at ` +
      `${sarifFile}, so there are no findings to show and no evidence the tree is clean.`;
    host.log(detail);
    host.showError(`ASH: ${detail}`);
    return { status: 'no-report', detail };
  }

  let parsed;
  try {
    parsed = parseAshSarif(host.readFile(sarifFile));
  } catch (err) {
    const detail = `${sarifFile}: ${(err as Error).message}`;
    host.log(detail);
    host.showError(`ASH: ${detail}`);
    return { status: 'unreadable-report', detail };
  }

  const summary = publishFindings(host.collection, sourceDir, parsed);
  const tools = parsed.toolNames.length === 0 ? 'ASH' : parsed.toolNames.join(', ');
  host.log(
    `${tools}: ${summary.diagnostics} finding(s) across ${summary.files} file(s)` +
      (summary.unlocated === 0 ? '' : `, plus ${summary.unlocated} with no file location`),
  );
  host.showInfo(
    summary.diagnostics === 0
      ? `ASH: scan completed with no findings at or above the configured severity threshold.`
      : `ASH: ${summary.diagnostics} finding(s) in ${summary.files} file(s). See the Problems panel.`,
  );
  if (summary.unlocated > 0) {
    // Not folded into the message above: a finding with no location cannot be
    // shown in the Problems panel at all, so it would otherwise be invisible.
    host.showError(
      `ASH: ${summary.unlocated} finding(s) named no file and cannot be placed in the editor. ` +
        'See the ASH output channel.',
    );
  }
  return { status: 'ok', summary };
}

/** The first workspace folder's path, or undefined when no folder is open. */
export function currentSourceDir(): string | undefined {
  const folders = vscode.workspace.workspaceFolders;
  return folders === undefined || folders.length === 0 ? undefined : folders[0].uri.fsPath;
}

/**
 * The real host: the spawner, the filesystem and the two notification calls.
 *
 * Exported so a test can build the same object `activate` builds and exercise its
 * members. Wiring that only exists inside `activate` is wiring nobody has run,
 * and a `readFile` that read the wrong encoding, or a `showError` that never
 * reached the window, would look identical to a clean scan from outside.
 */
export function createScanHost(
  collection: vscode.DiagnosticCollection,
  channel: vscode.OutputChannel,
): ScanHost {
  return {
    collection,
    run: spawnSyncRunner,
    readFile: (file) => fs.readFileSync(file, 'utf8'),
    fileExists: (file) => fs.existsSync(file),
    log: (line) => channel.appendLine(line),
    showError: (message) => {
      // `void` and not `await`: a command handler that awaited the notification
      // would stay pending until the user dismissed it, and VS Code would report
      // the command as still running.
      void vscode.window.showErrorMessage(message);
    },
    showInfo: (message) => {
      void vscode.window.showInformationMessage(message);
    },
  };
}

export function activate(context: vscode.ExtensionContext): void {
  const collection = vscode.languages.createDiagnosticCollection(COLLECTION_NAME);
  const channel = vscode.window.createOutputChannel('ASH');
  context.subscriptions.push(collection, channel);

  const host = createScanHost(collection, channel);

  context.subscriptions.push(
    vscode.commands.registerCommand(COMMAND_SCAN, () =>
      runScanCommand(host, currentSourceDir(), readSettings()),
    ),
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
