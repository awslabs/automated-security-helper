// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Structural snapshots of everything this extension puts in front of a user, so a
 * change to any of it fails until someone updates the snapshot on purpose and says
 * why in a `Snapshot-Update:` trailer. See test/visual/README.md for the workflow.
 *
 * THE INVENTORY, TAKEN FROM src/ AND package.json
 *
 * Surfaces the extension has, each snapshotted below:
 *
 *   - contributions in package.json: the two commands, the four settings with
 *     their descriptions and defaults, the untrusted-workspace capability text;
 *   - what activation registers: the commands, the diagnostic collection's name
 *     (the Problems panel's source filter), the output channel's name;
 *   - diagnostics: file, range, severity, message, source and code of each;
 *   - notifications, in the order raised and with their severity, for every
 *     outcome runScanCommand can reach, including the incomplete-scan (exit 1)
 *     warning and the one-time ashx -> ash fallback notice;
 *   - the progress notification's title and its Cancel button;
 *   - the output channel's text for each of those outcomes, and for Clear.
 *
 * Surfaces it does not have, so there is nothing to snapshot: tree views and
 * TreeItems, CodeLens, a hover provider (the hover a user sees over a finding is
 * VS Code's own rendering of the diagnostic, captured in the pixel suite), status
 * bar items, quick picks and input boxes, webviews, and custom editors.
 * `the extension still has no UI surface this file does not cover` below fails the
 * day one is added, so it cannot arrive without a snapshot.
 *
 * WHY THE HOST IS THE REAL ONE
 *
 * Notifications, the log and the progress call go through createScanHost, the
 * object activate() builds, into the vscode stub. Only the process and the
 * filesystem are replaced. A snapshot of a hand-built host would pin what this
 * file's author wired up, not what the extension does.
 *
 * Updating: `npm run snapshots -- --snapshot-update structural`. jest is configured
 * with `ci: true` in package.json, so a plain `npm test` never writes a snapshot,
 * new or changed.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import { AsyncCommandResult, CommandResult } from '../src/ash-cli';
import {
  ScanHost,
  ScanReport,
  ScanSettings,
  activate,
  createScanHost,
  runScanCommand,
} from '../src/extension';
import { DiagnosticCollection, DiagnosticSeverity, Memento, OutputChannel, progress, resetState, state } from './vscode-stub';

const PACKAGE_ROOT = path.resolve(__dirname, '..');
const FIXTURES = path.join(__dirname, 'fixtures');
const SOURCE_DIR = path.resolve('/workspace');
const OUTPUT_DIR = path.join(SOURCE_DIR, '.ash', 'ash_output');
const SARIF_FILE = path.join(OUTPUT_DIR, 'reports', 'ash.sarif');
const AGGREGATED_FILE = path.join(OUTPUT_DIR, 'ash_aggregated_results.json');
const ASH_VERSION = 'awslabs/automated-security-helper v3.7.0';

const SETTINGS: ScanSettings = {
  executablePath: '',
  outputDirectory: '.ash/ash_output',
  extraArguments: [],
  scanTimeoutSeconds: 1800,
};

/** Replaces the fixed workspace path, in any spelling, so the snapshot is platform-free. */
function normalize(text: string): string {
  const posix = SOURCE_DIR.split(path.sep).join('/');
  return text.split(SOURCE_DIR).join('<workspace>').split(posix).join('<workspace>');
}

function capturedScan(name: string): { sarif: string; aggregated: string; exitCode: number } {
  const dir = path.join(FIXTURES, 'scans', name);
  const restore = (text: string): string =>
    text
      .split('__ASH_SOURCE_DIR__')
      .join(JSON.stringify(SOURCE_DIR).slice(1, -1))
      .split('__ASH_OUTPUT_DIR__')
      .join(JSON.stringify(OUTPUT_DIR).slice(1, -1));
  return {
    sarif: restore(fs.readFileSync(path.join(dir, 'ash.sarif'), 'utf8')),
    aggregated: restore(fs.readFileSync(path.join(dir, 'ash_aggregated_results.json'), 'utf8')),
    exitCode: Number(fs.readFileSync(path.join(dir, 'exit-code'), 'utf8').trim()),
  };
}

interface Arrangement {
  /** What the scan writes, if anything. */
  readonly sarif?: string;
  readonly aggregated?: string;
  /** The scan's exit status; null is a process killed by a signal. */
  readonly status?: number | null;
  readonly spawnError?: Error;
  readonly timedOut?: boolean;
  readonly cancelled?: boolean;
  /** Executables that exist; each answers --version with `version`. */
  readonly onPath?: readonly string[];
  readonly version?: string;
  /** Files left by a previous run, and whether the extension can delete them. */
  readonly previous?: Readonly<Record<string, string>>;
  readonly undeletable?: boolean;
  readonly memento?: Memento;
}

function host(arrangement: Arrangement): { host: ScanHost; collection: DiagnosticCollection; channel: OutputChannel } {
  const collection = new DiagnosticCollection('ash');
  const channel = new OutputChannel('ASH');
  const real = createScanHost(
    collection as unknown as vscode.DiagnosticCollection,
    channel as unknown as vscode.OutputChannel,
    (arrangement.memento ?? new Memento()) as unknown as vscode.Memento,
  );
  let clock = 1000;
  const files = new Map<string, { text: string; mtime: number }>();
  for (const [file, text] of Object.entries(arrangement.previous ?? {})) {
    files.set(file, { text, mtime: clock });
  }
  const onPath = arrangement.onPath ?? ['ashx'];
  const execute = (executable: string, args: readonly string[]): CommandResult => {
    if (!onPath.includes(executable)) {
      return {
        status: null,
        stdout: '',
        stderr: '',
        error: Object.assign(new Error(`spawn ${executable} ENOENT`), { code: 'ENOENT' }),
      };
    }
    if (args[0] === '--version') {
      return { status: 0, stdout: arrangement.version ?? ASH_VERSION, stderr: '' };
    }
    for (const [file, text] of [
      [SARIF_FILE, arrangement.sarif],
      [AGGREGATED_FILE, arrangement.aggregated],
    ] as const) {
      if (text !== undefined) {
        clock += 1;
        files.set(file, { text, mtime: clock });
      }
    }
    return {
      status: 'status' in arrangement ? (arrangement.status as number | null) : 2,
      stdout: 'ASH scan output, last line',
      stderr: '',
      error: arrangement.spawnError,
    };
  };
  return {
    collection,
    channel,
    host: {
      ...real,
      run: (executable, args) => Promise.resolve(execute(executable, args)),
      runAsync: (executable, args): Promise<AsyncCommandResult> =>
        Promise.resolve({
          ...execute(executable, args),
          timedOut: arrangement.timedOut ?? false,
          cancelled: arrangement.cancelled ?? false,
        }),
      readFile: (file) => {
        const entry = files.get(file);
        if (entry === undefined) {
          throw new Error(`ENOENT: no such file, open '${file}'`);
        }
        return entry.text;
      },
      mtimeMs: (file) => files.get(file)?.mtime,
      removeFile: (file) => {
        if (arrangement.undeletable === true) {
          return !files.has(file);
        }
        files.delete(file);
        return true;
      },
    },
  };
}

const SEVERITY_NAMES: Readonly<Record<number, string>> = {
  [DiagnosticSeverity.Error]: 'Error',
  [DiagnosticSeverity.Warning]: 'Warning',
  [DiagnosticSeverity.Information]: 'Information',
  [DiagnosticSeverity.Hint]: 'Hint',
};

/** The Problems panel's content: per file, each diagnostic as VS Code would list it. */
function problems(collection: DiagnosticCollection): Record<string, unknown[]> {
  const out: Record<string, unknown[]> = {};
  for (const key of collection.uris().sort()) {
    const fsPath = key.replace(/^file:\/\//, '');
    const diagnostics = collection.get(vscode.Uri.file(fsPath)) ?? [];
    out[normalize(fsPath)] = diagnostics.map((d) => ({
      range: `${d.range.start.line}:${d.range.start.character}-${d.range.end.line}:${
        d.range.end.character === Number.MAX_SAFE_INTEGER ? 'EOL' : d.range.end.character
      }`,
      severity: SEVERITY_NAMES[d.severity],
      message: d.message,
      source: d.source,
      code: d.code,
    }));
  }
  return out;
}

/** Everything one scan put on screen, in a stable, path-free shape. */
async function render(
  arrangement: Arrangement,
  settings: ScanSettings = SETTINGS,
  sourceDir: string | undefined = SOURCE_DIR,
): Promise<unknown> {
  const built = host(arrangement);
  const report: ScanReport = await runScanCommand(built.host, sourceDir, settings);
  return JSON.parse(
    normalize(
      JSON.stringify({
        status: report.status,
        exitCode: report.exitCode,
        fallbackNotice: report.fallbackNotice,
        summary: report.summary,
        progress: progress.calls,
        notifications: state.notifications,
        output: built.channel.lines,
        problems: problems(built.collection),
      }),
    ),
  ) as unknown;
}

/** A SARIF report with one finding that names no file and one on a remote share. */
function sarifWithUnplaceableFindings(): string {
  const doc = JSON.parse(capturedScan('findings').sarif) as {
    runs: { results: Record<string, unknown>[] }[];
  };
  const results = doc.runs[0].results;
  const template = results.find((r) => !Array.isArray(r.suppressions) || r.suppressions.length === 0);
  if (template === undefined) {
    throw new Error('the findings fixture has no unsuppressed result to copy');
  }
  const unlocated = { ...JSON.parse(JSON.stringify(template)), locations: [] };
  const remote = JSON.parse(JSON.stringify(template)) as {
    locations: { physicalLocation: { artifactLocation: { uri: string } } }[];
  };
  remote.locations[0].physicalLocation.artifactLocation.uri = '//fileserver/share/app.py';
  results.push(unlocated, remote);
  return JSON.stringify(doc);
}

beforeEach(() => {
  resetState();
});

describe('the scan outcomes a user can see', () => {
  const findings = capturedScan('findings');
  const clean = capturedScan('clean');
  const incomplete = capturedScan('incomplete');
  const missing = capturedScan('missing');

  const cases: [string, () => Promise<unknown>][] = [
    [
      'findings, exit 2',
      () => render({ sarif: findings.sarif, aggregated: findings.aggregated, status: findings.exitCode }),
    ],
    ['clean, exit 0', () => render({ sarif: clean.sarif, aggregated: clean.aggregated, status: clean.exitCode })],
    [
      'incomplete, exit 1, a scanner errored',
      () => render({ sarif: incomplete.sarif, aggregated: incomplete.aggregated, status: incomplete.exitCode }),
    ],
    [
      'incomplete, exit 1, a scanner is missing',
      () => render({ sarif: missing.sarif, aggregated: missing.aggregated, status: missing.exitCode }),
    ],
    [
      'incomplete by coverage, exit 2',
      () => render({ sarif: incomplete.sarif, aggregated: incomplete.aggregated, status: 2 }),
    ],
    [
      'exit 1 with no report: a crash',
      () => render({ status: 1 }),
    ],
    ['exit 0 with no report', () => render({ status: 0 })],
    ['no aggregated results beside the report', () => render({ sarif: findings.sarif, status: 2 })],
    [
      'findings that cannot be placed in the editor',
      () => render({ sarif: sarifWithUnplaceableFindings(), aggregated: findings.aggregated, status: 2 }),
    ],
    [
      'a stale report the extension could not delete',
      () =>
        render({
          previous: { [SARIF_FILE]: findings.sarif, [AGGREGATED_FILE]: findings.aggregated },
          undeletable: true,
          status: 2,
        }),
    ],
    ['an unreadable report', () => render({ sarif: '{ not json', status: 2 })],
    ['a configuration error, exit 3', () => render({ status: 3 })],
    ['killed by a signal', () => render({ status: null })],
    ['the scan could not start', () => render({ status: null, spawnError: new Error('spawn EACCES') })],
    ['timed out', () => render({ status: null, timedOut: true })],
    ['cancelled', () => render({ status: null, cancelled: true })],
    ['no workspace folder', () => render({}, SETTINGS, undefined)],
    [
      'ash.outputDirectory is absolute',
      () => render({}, { ...SETTINGS, outputDirectory: path.resolve('/elsewhere') }),
    ],
    ['ash.outputDirectory escapes the workspace', () => render({}, { ...SETTINGS, outputDirectory: '../out' })],
    ['ash.outputDirectory is the workspace itself', () => render({}, { ...SETTINGS, outputDirectory: '.' })],
    ['ash.outputDirectory holds a NUL', () => render({}, { ...SETTINGS, outputDirectory: 'a\0b' })],
    [
      'ash.extraArguments sets --output-dir',
      () => render({}, { ...SETTINGS, extraArguments: ['--output-dir=/tmp/x'] }),
    ],
    ['neither ashx nor ash is on PATH', () => render({ onPath: [] })],
    ['ashx answers and is not ASH', () => render({ version: 'BusyBox v1.36.1 (ash)' })],
    [
      'a configured executable that does not exist',
      () => render({ onPath: [] }, { ...SETTINGS, executablePath: '/opt/ash/bin/ashx' }),
    ],
    [
      'ashx missing, ash present: the fallback notice, first time',
      () => render({ onPath: ['ash'], sarif: clean.sarif, aggregated: clean.aggregated, status: 0 }),
    ],
    [
      'ashx missing, ash present: the fallback notice already shown',
      () => {
        const memento = new Memento();
        memento.values.set('ash.legacyExecutableNoticeShown', true);
        return render({ onPath: ['ash'], memento, sarif: clean.sarif, aggregated: clean.aggregated, status: 0 });
      },
    ],
  ];

  test.each(cases)('%s', async (_name, run) => {
    expect(await run()).toMatchSnapshot();
  });
});

describe('what the manifest and activation present', () => {
  test('package.json contributions and the text around them', () => {
    const manifest = JSON.parse(fs.readFileSync(path.join(PACKAGE_ROOT, 'package.json'), 'utf8')) as Record<
      string,
      unknown
    >;
    // Everything a user reads in the Extensions view, the command palette and the
    // Settings editor. `version` is left out: it moves on every release and is not UI.
    const shown = Object.fromEntries(
      ['displayName', 'description', 'publisher', 'categories', 'engines', 'activationEvents', 'capabilities', 'contributes'].map(
        (key) => [key, manifest[key]],
      ),
    );
    expect(shown).toMatchSnapshot();
  });

  test('activation registers the commands, the Problems source and the output channel', async () => {
    const context = { subscriptions: [] as { dispose(): void }[], globalState: new Memento() };
    activate(context as unknown as vscode.ExtensionContext);
    await state.commands.get('ash.clearFindings')?.();
    expect({
      commands: [...state.commands.keys()].sort(),
      diagnosticCollections: state.collections.map((c) => c.name),
      outputChannels: state.channels.map((c) => ({ name: c.name, lines: c.lines })),
      notifications: state.notifications,
    }).toMatchSnapshot();
  });

  test('the extension still has no UI surface this file does not cover', () => {
    // The not-applicable list in the header, made mechanical. Each entry is the API
    // call or manifest key that would add the surface.
    const absent: Record<string, RegExp> = {
      'tree view': /\b(createTreeView|registerTreeDataProvider)\b/,
      CodeLens: /\bregisterCodeLensProvider\b/,
      'hover provider': /\bregisterHoverProvider\b/,
      'status bar item': /\bcreateStatusBarItem\b/,
      'quick pick or input box': /\b(showQuickPick|createQuickPick|showInputBox|createInputBox)\b/,
      webview: /\b(createWebviewPanel|registerWebviewViewProvider|registerWebviewPanelSerializer)\b/,
      'custom editor': /\bregisterCustomEditorProvider\b/,
      'code action': /\bregisterCodeActionsProvider\b/,
      'terminal or task': /\b(createTerminal|registerTaskProvider)\b/,
    };
    const sources = fs
      .readdirSync(path.join(PACKAGE_ROOT, 'src'))
      .filter((name) => name.endsWith('.ts'))
      .map((name) => fs.readFileSync(path.join(PACKAGE_ROOT, 'src', name), 'utf8'));
    expect(sources.length).toBeGreaterThan(0);
    const found = Object.entries(absent)
      .filter(([, pattern]) => sources.some((text) => pattern.test(text)))
      .map(([surface]) => surface);
    expect(found).toEqual([]);

    const contributes = (JSON.parse(fs.readFileSync(path.join(PACKAGE_ROOT, 'package.json'), 'utf8')) as {
      contributes: Record<string, unknown>;
    }).contributes;
    // Contribution points this file snapshots through the manifest test above.
    expect(Object.keys(contributes).sort()).toEqual(['commands', 'configuration']);
  });

  test('the not-applicable check sees a surface when there is one', () => {
    // Negative control for the test above: its patterns match the calls they name.
    expect(/\bcreateStatusBarItem\b/.test('vscode.window.createStatusBarItem()')).toBe(true);
    expect(/\b(createTreeView|registerTreeDataProvider)\b/.test('window.registerTreeDataProvider(id, p)')).toBe(
      true,
    );
  });
});
