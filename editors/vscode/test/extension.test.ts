// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * The suite's central assertion and the failure paths around it.
 *
 * WHAT THE CENTRAL ASSERTION IS
 *
 * A fixture carrying a planted AWS secret must produce a NON-ZERO count of
 * diagnostics in the editor model. Not "the command completed", not "a SARIF file
 * appeared": both of those are satisfied by a scan that saw nothing, because an
 * empty ASH scan exits 0 and still writes a report. `clean-scan.sarif` and
 * scans/clean are the negative controls and must produce ZERO.
 *
 * WHERE THE FIXTURES CAME FROM
 *
 * `planted-secret.sarif` is the real output of `ash scan --scanners detect-secrets
 * --no-progress` over an earlier, two-line version of test/fixtures/planted_secret.py,
 * with the scanning machine's path replaced by /workspace. The directories under
 * test/fixtures/scans/ are real `ash scan` runs captured on this branch, with the
 * source and output directories replaced by __ASH_SOURCE_DIR__ and
 * __ASH_OUTPUT_DIR__ and each run's exit status in `exit-code`:
 *
 *   findings    exit 2  --scanners detect-secrets, one result suppressed in config
 *   clean       exit 0  --scanners detect-secrets over a file with no secret
 *   incomplete  exit 1  --scanners semgrep,detect-secrets with semgrep unable to run
 *   missing     exit 1  --scanners cfn-nag,detect-secrets with cfn-nag not installed
 */

import * as path from 'path';
import * as vscode from 'vscode';
import { AsyncCommandOptions, CommandResult } from '../src/ash-cli';
import {
  COMMAND_CLEAR,
  COMMAND_SCAN,
  FALLBACK_NOTICE,
  FALLBACK_NOTICE_KEY,
  ScanHost,
  ScanSettings,
  activate,
  createScanHost,
  currentSourceDir,
  deactivate,
  readSettings,
  runScanCommand,
} from '../src/extension';
import {
  DiagnosticCollection,
  Memento,
  OutputChannel,
  progress,
  resetState,
  state,
} from './vscode-stub';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';

const FIXTURES = path.join(__dirname, 'fixtures');
const SOURCE_DIR = '/workspace';
const OUTPUT_DIR = path.join(SOURCE_DIR, '.ash', 'ash_output');
const SARIF_FILE = path.join(OUTPUT_DIR, 'reports', 'ash.sarif');
const AGGREGATED_FILE = path.join(OUTPUT_DIR, 'ash_aggregated_results.json');

const ASH_VERSION_OUTPUT = 'awslabs/automated-security-helper v3.7.0';

const SETTINGS: ScanSettings = {
  executablePath: '',
  outputDirectory: '.ash/ash_output',
  extraArguments: [],
  scanTimeoutSeconds: 1800,
};

/** One captured scan under test/fixtures/scans/, with its paths put back. */
function capturedScan(name: string): { sarif: string; aggregated: string; exitCode: number } {
  const dir = path.join(FIXTURES, 'scans', name);
  const restore = (text: string): string =>
    text.split('__ASH_SOURCE_DIR__').join(SOURCE_DIR).split('__ASH_OUTPUT_DIR__').join(OUTPUT_DIR);
  return {
    sarif: restore(readFileSync(path.join(dir, 'ash.sarif'), 'utf8')),
    aggregated: restore(readFileSync(path.join(dir, 'ash_aggregated_results.json'), 'utf8')),
    exitCode: Number(readFileSync(path.join(dir, 'exit-code'), 'utf8').trim()),
  };
}

interface HarnessOptions {
  /** What the scan writes to the SARIF path, if anything. */
  readonly sarifFixture?: string;
  readonly sarifText?: string;
  /** What the scan writes to ash_aggregated_results.json, if anything. */
  readonly aggregatedText?: string;
  /** Exit status of the scan invocation. ASH exits 2 when it finds something. */
  readonly scanStatus?: number | null;
  readonly scanError?: Error;
  /** Executables on the fake PATH. Each answers --version as ASH. */
  readonly onPath?: readonly string[];
  /** Output of `--version`, for every executable on PATH. */
  readonly versionOutput?: string;
  /** Files present before the scan, as left by a previous run. */
  readonly previous?: Readonly<Record<string, string>>;
  /** Files the extension cannot delete. */
  readonly undeletable?: readonly string[];
  /** Whether the scan rewrites the files it writes (false leaves the previous ones). */
  readonly scanWrites?: boolean;
  readonly memento?: Memento;
  /** The scan outran its timeout and was stopped. */
  readonly scanTimedOut?: boolean;
  /** The user pressed Cancel. */
  readonly scanCancelled?: boolean;
}

interface Harness {
  readonly host: ScanHost;
  readonly collection: DiagnosticCollection;
  readonly invocations: { executable: string; args: readonly string[] }[];
  readonly lines: string[];
  readonly files: Map<string, { text: string; mtime: number }>;
  readonly memento: Memento;
  /** What each async run was given, so a test can see the timeout and the signal. */
  readonly asyncOptions: AsyncCommandOptions[];
  readonly progressTitles: string[];
}

function harness(options: HarnessOptions = {}): Harness {
  const collection = new DiagnosticCollection('ash');
  const invocations: { executable: string; args: readonly string[] }[] = [];
  const lines: string[] = [];
  const memento = options.memento ?? new Memento();
  const onPath = options.onPath ?? ['ashx'];

  // A filesystem with a clock, so freshness is decided by real mtime comparisons.
  let clock = 1000;
  const files = new Map<string, { text: string; mtime: number }>();
  for (const [file, text] of Object.entries(options.previous ?? {})) {
    files.set(file, { text, mtime: clock });
  }
  const write = (file: string, text: string): void => {
    clock += 1;
    files.set(file, { text, mtime: clock });
  };

  const sarifText =
    options.sarifText ??
    (options.sarifFixture === undefined
      ? undefined
      : readFileSync(path.join(FIXTURES, options.sarifFixture), 'utf8'));

  const runSync = (executable: string, args: readonly string[]): CommandResult => {
    invocations.push({ executable, args });
    if (!onPath.includes(executable)) {
      return {
        status: null,
        stdout: '',
        stderr: '',
        error: Object.assign(new Error(`spawn ${executable} ENOENT`), { code: 'ENOENT' }),
      };
    }
    if (args[0] === '--version') {
      return { status: 0, stdout: options.versionOutput ?? ASH_VERSION_OUTPUT, stderr: '' };
    }
    if (options.scanWrites !== false) {
      if (sarifText !== undefined) {
        write(SARIF_FILE, sarifText);
      }
      if (options.aggregatedText !== undefined) {
        write(AGGREGATED_FILE, options.aggregatedText);
      }
    }
    return {
      // `?? 2` would be wrong here: `null` is the status of a process killed by a
      // signal and is one of the cases under test.
      status: 'scanStatus' in options ? (options.scanStatus as number | null) : 2,
      stdout: 'scan output',
      stderr: '',
      error: options.scanError,
    };
  };

  const asyncOptions: AsyncCommandOptions[] = [];
  const progressTitles: string[] = [];

  return {
    collection,
    invocations,
    lines,
    files,
    memento,
    asyncOptions,
    progressTitles,
    host: {
      collection: collection as unknown as vscode.DiagnosticCollection,
      run: (executable, args) => Promise.resolve(runSync(executable, args)),
      runAsync: (executable, args, runOptions) => {
        asyncOptions.push(runOptions);
        return Promise.resolve({
          ...runSync(executable, args),
          timedOut: options.scanTimedOut ?? false,
          cancelled: options.scanCancelled ?? false,
        });
      },
      withProgress: (title, task) => {
        progressTitles.push(title);
        return task(new AbortController().signal);
      },
      readFile: (file) => {
        const entry = files.get(file);
        if (entry === undefined) {
          throw new Error(`ENOENT: ${file}`);
        }
        return entry.text;
      },
      mtimeMs: (file) => files.get(file)?.mtime,
      removeFile: (file) => {
        if ((options.undeletable ?? []).includes(file)) {
          return !files.has(file);
        }
        files.delete(file);
        return true;
      },
      log: (line) => lines.push(line),
      showError: (message) => state.errors.push(message),
      showWarning: (message) => state.warnings.push(message),
      showInfo: (message) => state.infos.push(message),
      fallbackNoticeShown: () => memento.get<boolean>(FALLBACK_NOTICE_KEY, false),
      recordFallbackNoticeShown: () => {
        void memento.update(FALLBACK_NOTICE_KEY, true);
      },
    },
  };
}

/** A harness whose scan writes one captured run, exit status included. */
function captured(name: string, overrides: HarnessOptions = {}): Harness {
  const scan = capturedScan(name);
  return harness({
    sarifText: scan.sarif,
    aggregatedText: scan.aggregated,
    scanStatus: scan.exitCode,
    ...overrides,
  });
}

beforeEach(() => {
  resetState();
});

describe('a fixture with a planted secret reaches the editor model', () => {
  it('publishes a non-zero count of diagnostics', async () => {
    const { host, collection } = harness({ sarifFixture: 'planted-secret.sarif' });

    const report = await runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('ok');
    // The assertion this whole extension exists for. A zero here is what a
    // shadowed `ash`, a crashed scan and a clean tree all look like.
    expect(collection.totalDiagnostics()).toBeGreaterThan(0);
    expect(report.summary?.diagnostics).toBeGreaterThan(0);
  });

  it('publishes exactly the three findings the measured scan reported', async () => {
    const { host, collection } = harness({ sarifFixture: 'planted-secret.sarif' });

    const report = await runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.summary).toEqual({
      files: 1,
      diagnostics: 3,
      unlocated: 0,
      unresolved: 0,
      suppressed: 0,
      notFailures: 0,
    });
    expect(collection.totalDiagnostics()).toBe(3);

    const uri = vscode.Uri.file(path.join(SOURCE_DIR, 'planted_secret.py'));
    const diagnostics = collection.get(uri);
    expect(diagnostics).toHaveLength(3);
    expect(diagnostics?.map((diagnostic) => diagnostic.code).sort()).toEqual([
      'SECRET-AWS-ACCESS-KEY',
      'SECRET-BASE64-HIGH-ENTROPY-STRING',
      'SECRET-SECRET-KEYWORD',
    ]);
    // detect-secrets found all three on line 2 of the fixture. SARIF counts from
    // 1 and VS Code from 0, so line 2 is row 1.
    for (const diagnostic of diagnostics ?? []) {
      expect(diagnostic.range.start.line).toBe(1);
      expect(diagnostic.source).toBe('ASH (detect-secrets)');
    }
  });

  it('treats exit 2 as a completed scan, because that is ASH\'s findings code', async () => {
    const { host, invocations } = harness({ sarifFixture: 'planted-secret.sarif', scanStatus: 2 });

    expect((await runScanCommand(host, SOURCE_DIR, SETTINGS)).status).toBe('ok');
    expect(invocations[0].args).toEqual(['--version']);
    expect(invocations[1].args).toEqual([
      'scan',
      '--source-dir',
      SOURCE_DIR,
      '--output-dir',
      OUTPUT_DIR,
      '--no-progress',
    ]);
  });
});

describe('the negative control', () => {
  it('publishes zero diagnostics for a scan that found nothing', async () => {
    const { host, collection } = harness({ sarifFixture: 'clean-scan.sarif', scanStatus: 0 });

    const report = await runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('ok');
    expect(collection.totalDiagnostics()).toBe(0);
    expect(state.infos.join('\n')).toContain('no findings');
  });
});

describe('a re-scan does not leave stale findings on screen', () => {
  it('clears before publishing', async () => {
    const first = harness({ sarifFixture: 'planted-secret.sarif' });
    await runScanCommand(first.host, SOURCE_DIR, SETTINGS);
    expect(first.collection.totalDiagnostics()).toBe(3);

    // Same collection, second scan, nothing found. The fixed findings must go.
    const second: ScanHost = {
      ...harness({ sarifFixture: 'clean-scan.sarif', scanStatus: 0 }).host,
      collection: first.collection as unknown as vscode.DiagnosticCollection,
    };
    await runScanCommand(second, SOURCE_DIR, SETTINGS);

    expect(first.collection.totalDiagnostics()).toBe(0);
  });
});

describe('every way a scan can produce nothing is distinguishable from a clean tree', () => {
  it('refuses when no folder is open', async () => {
    const { host, collection } = harness({ sarifFixture: 'planted-secret.sarif' });

    const report = await runScanCommand(host, undefined, SETTINGS);

    expect(report.status).toBe('no-workspace');
    expect(collection.totalDiagnostics()).toBe(0);
    expect(state.errors.join('\n')).toContain('open a folder');
  });

  it('refuses when neither ashx nor ash is on PATH', async () => {
    const { host } = harness({ onPath: [] });

    const report = await runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('wrong-executable');
    expect(state.errors.join('\n')).toContain('Neither "ashx" nor "ash" is on PATH');
  });

  it('refuses when the Almquist shell answered instead of ASH', async () => {
    // What MSYS2's `ash` prints when handed --version. It is the collision the
    // entry-point contract exists for, and it must not scan.
    const { host, collection } = harness({ versionOutput: 'ash: 0: Illegal option --' });

    const report = await runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('wrong-executable');
    expect(collection.totalDiagnostics()).toBe(0);
    const shown = state.errors.join('\n');
    expect(shown).toContain('is not ASH');
    expect(shown).toContain('automated-security-helper');
    expect(shown).toContain('Almquist');
  });

  it('reports an exit 1 that wrote no report as a crash', async () => {
    const { host, collection } = harness({ scanStatus: 1 });

    const report = await runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('scan-failed');
    expect(report.detail).toContain('exited 1 and wrote no SARIF report');
    expect(collection.totalDiagnostics()).toBe(0);
    expect(state.errors.join('\n')).toContain('ASH:');
  });

  it('reports exit 3 and 4 as failures even with a report on disk', async () => {
    for (const scanStatus of [3, 4]) {
      resetState();
      const { host, collection } = harness({ sarifFixture: 'planted-secret.sarif', scanStatus });

      const report = await runScanCommand(host, SOURCE_DIR, SETTINGS);

      expect(report.status).toBe('scan-failed');
      expect(report.detail).toContain(`exit ${scanStatus}`);
      expect(collection.totalDiagnostics()).toBe(0);
    }
  });

  it('reports a scan killed by a signal', async () => {
    const { host } = harness({ sarifFixture: 'planted-secret.sarif', scanStatus: null });

    expect((await runScanCommand(host, SOURCE_DIR, SETTINGS)).status).toBe('scan-failed');
  });

  it('reports a scan that could not be started', async () => {
    const { host } = harness({ scanError: new Error('EACCES') });

    const report = await runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('scan-failed');
    expect(report.detail).toContain('EACCES');
  });

  it('reports an exit 0 that wrote no report at all', async () => {
    // The case that most needs a message. Exit 0 with no SARIF is what a
    // shadowed binary or a crashed reporter looks like, and an empty Problems
    // panel would read as a clean tree.
    const { host } = harness({ scanStatus: 0 });

    const report = await runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('no-report');
    expect(state.errors.join('\n')).toContain('no evidence the tree is clean');
  });

  it('reports a report that is not readable SARIF', async () => {
    const { host } = harness({ sarifText: '{"not": "sarif"}' });

    const report = await runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('unreadable-report');
    expect(report.detail).toContain('no "runs" array');
  });
});

describe('findings with no file location', () => {
  it('are counted and surfaced rather than dropped', async () => {
    const sarif = JSON.stringify({
      runs: [
        {
          tool: { driver: { name: 'AWS Labs - Automated Security Helper' } },
          results: [{ ruleId: 'NO-LOCATION', message: { text: 'nowhere' }, level: 'error' }],
        },
      ],
    });
    const { host, collection } = harness({ sarifText: sarif });

    const report = await runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('ok');
    expect(collection.totalDiagnostics()).toBe(0);
    expect(report.summary?.unlocated).toBe(1);
    expect(state.errors.join('\n')).toContain('named no file');
  });
});

describe('an absolute ash.outputDirectory', () => {
  it('is used as given rather than joined onto the workspace', async () => {
    const { host, invocations } = harness({ sarifFixture: 'planted-secret.sarif' });

    await runScanCommand(host, SOURCE_DIR, { ...SETTINGS, outputDirectory: '/tmp/elsewhere' });

    expect(invocations[1].args).toContain('/tmp/elsewhere');
    // No SARIF exists at that path in this harness, so the scan is reported as
    // having written none -- which is the point: the path was not rewritten.
    expect(state.errors.join('\n')).toContain('/tmp/elsewhere');
  });
});

describe('extra arguments', () => {
  it('are appended after the flags the extension controls', async () => {
    const { host, invocations } = harness({ sarifFixture: 'planted-secret.sarif' });

    await runScanCommand(host, SOURCE_DIR, {
      ...SETTINGS,
      extraArguments: ['--scanners', 'detect-secrets'],
    });

    expect(invocations[1].args.slice(-3)).toEqual(['--no-progress', '--scanners', 'detect-secrets']);
  });
});

describe('activation', () => {
  it('registers both commands and hands them a disposable collection', async () => {
    const subscriptions: { dispose(): void }[] = [];

    activate({ subscriptions, globalState: new Memento() } as unknown as vscode.ExtensionContext);

    expect([...state.commands.keys()].sort()).toEqual([COMMAND_CLEAR, COMMAND_SCAN]);
    expect(state.collections).toHaveLength(1);
    expect(state.channels).toHaveLength(1);
    // collection, channel, and one disposable per registered command.
    expect(subscriptions).toHaveLength(4);
  });

  it('scans through the registered command, and reports no workspace when none is open', async () => {
    activate({ subscriptions: [], globalState: new Memento() } as unknown as vscode.ExtensionContext);

    const report = await state.commands.get(COMMAND_SCAN)?.() as { status: string };

    expect(report.status).toBe('no-workspace');
  });

  it('clears findings through the registered command', async () => {
    activate({ subscriptions: [], globalState: new Memento() } as unknown as vscode.ExtensionContext);
    const collection = state.collections[0];
    collection.set(vscode.Uri.file('/workspace/a.py'), [
      new vscode.Diagnostic(new vscode.Range(0, 0, 0, 1), 'x'),
    ]);
    expect(collection.totalDiagnostics()).toBe(1);

    state.commands.get(COMMAND_CLEAR)?.();

    expect(collection.totalDiagnostics()).toBe(0);
    expect(state.channels[0].lines).toContain('Cleared ASH findings.');
  });

  it('deactivates without throwing', async () => {
    expect(() => deactivate()).not.toThrow();
  });
});

describe('the real host activate builds', () => {
  it('reads a real file, answers about a real path, and logs to the channel', async () => {
    const collection = new DiagnosticCollection('ash');
    const channel = new OutputChannel('ASH');
    const memento = new Memento();
    const host = createScanHost(
      collection as unknown as vscode.DiagnosticCollection,
      channel as unknown as vscode.OutputChannel,
      memento as unknown as vscode.Memento,
    );

    const fixture = path.join(FIXTURES, 'clean-scan.sarif');
    expect(host.mtimeMs(fixture)).toBeGreaterThan(0);
    expect(host.mtimeMs(path.join(FIXTURES, 'absent.sarif'))).toBeUndefined();
    // utf8 and not a Buffer: `readFileSync` without an encoding returns bytes,
    // and JSON.parse on a Buffer works by coercion, which would hide a real
    // encoding bug until a non-ASCII path appeared in a message.
    expect(typeof host.readFile(fixture)).toBe('string');
    expect(JSON.parse(host.readFile(fixture)).version).toBe('2.1.0');

    host.log('hello');
    expect(channel.lines).toEqual(['hello']);

    host.showError('bad');
    host.showWarning('careful');
    host.showInfo('good');
    expect(state.errors).toEqual(['bad']);
    expect(state.warnings).toEqual(['careful']);
    expect(state.infos).toEqual(['good']);

    expect(host.fallbackNoticeShown()).toBe(false);
    host.recordFallbackNoticeShown();
    expect(host.fallbackNoticeShown()).toBe(true);
    expect(memento.values.get(FALLBACK_NOTICE_KEY)).toBe(true);
  });

  it('removes a real file, and reports an absent one as already gone', async () => {
    const host = createScanHost(
      new DiagnosticCollection('ash') as unknown as vscode.DiagnosticCollection,
      new OutputChannel('ASH') as unknown as vscode.OutputChannel,
      new Memento() as unknown as vscode.Memento,
    );
    const dir = mkdtempSync(path.join(tmpdir(), 'ash-vscode-host-'));
    try {
      const file = path.join(dir, 'ash.sarif');
      writeFileSync(file, '{}');

      expect(host.removeFile(file)).toBe(true);
      expect(host.mtimeMs(file)).toBeUndefined();
      expect(host.removeFile(file)).toBe(true);
      // A directory cannot be unlinked; that is a failure to remove, not absence.
      expect(host.removeFile(dir)).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('spawns for real, so a missing executable is reported rather than scanned past', async () => {
    // End to end through the registered command with the real spawner: no
    // executable named this exists, so the probe must refuse. This is the one
    // test that proves activate wired the real probeRunner in.
    state.workspaceFolders = [{ uri: { fsPath: FIXTURES } }];
    state.configuration.set('ash.executablePath', 'ash-that-is-not-installed-anywhere');
    activate({ subscriptions: [], globalState: new Memento() } as unknown as vscode.ExtensionContext);

    const report = await state.commands.get(COMMAND_SCAN)?.() as { status: string; detail: string };

    expect(report.status).toBe('wrong-executable');
    expect(report.detail).toContain('not on PATH');
    expect(state.collections[0].totalDiagnostics()).toBe(0);
    expect(state.channels[0].lines.join('\n')).toContain('not on PATH');
  });
});

describe('settings and workspace resolution', () => {
  it('fall back to the defaults package.json contributes', async () => {
    expect(readSettings()).toEqual({
      executablePath: '',
      outputDirectory: '.ash/ash_output',
      extraArguments: [],
      scanTimeoutSeconds: 1800,
    });
  });

  it('take a configured timeout, including 0, and refuse a negative or non-number one', async () => {
    state.configuration.set('ash.scanTimeoutSeconds', 0);
    expect(readSettings().scanTimeoutSeconds).toBe(0);
    state.configuration.set('ash.scanTimeoutSeconds', 120);
    expect(readSettings().scanTimeoutSeconds).toBe(120);
    state.configuration.set('ash.scanTimeoutSeconds', -5);
    expect(readSettings().scanTimeoutSeconds).toBe(1800);
    state.configuration.set('ash.scanTimeoutSeconds', 'soon');
    expect(readSettings().scanTimeoutSeconds).toBe(1800);
  });

  it('take the configured values when they are set', async () => {
    state.configuration.set('ash.executablePath', '/opt/ash/bin/automated-security-helper');
    state.configuration.set('ash.outputDirectory', 'build/ash');
    state.configuration.set('ash.extraArguments', ['--offline']);

    expect(readSettings()).toEqual({
      executablePath: '/opt/ash/bin/automated-security-helper',
      outputDirectory: 'build/ash',
      extraArguments: ['--offline'],
      scanTimeoutSeconds: 1800,
    });
  });

  it('read an empty or blank executable as unset, which selects ashx then ash', async () => {
    state.configuration.set('ash.executablePath', '  ');
    state.configuration.set('ash.outputDirectory', '');

    expect(readSettings().executablePath).toBe('');
    expect(readSettings().outputDirectory).toBe('.ash/ash_output');
  });

  it('read a null executable as unset', async () => {
    state.configuration.set('ash.executablePath', null);

    expect(readSettings().executablePath).toBe('');
  });

  it('report no source directory when no folder is open', async () => {
    expect(currentSourceDir()).toBeUndefined();

    state.workspaceFolders = [];
    expect(currentSourceDir()).toBeUndefined();

    state.workspaceFolders = [{ uri: { fsPath: '/workspace' } }];
    expect(currentSourceDir()).toBe('/workspace');
  });
});

describe('the exit-code contract with real ASH output', () => {
  it('publishes an exit 2 scan and leaves the suppressed result out', async () => {
    const { host, collection } = captured('findings');

    const report = await runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('ok');
    expect(report.exitCode).toBe(2);
    expect(report.coverage?.coverage_complete).toBe(true);
    expect(report.summary).toMatchObject({ diagnostics: 2, suppressed: 1, files: 1 });
    const diagnostics = collection.get(vscode.Uri.file(path.join(SOURCE_DIR, 'planted_secret.py')));
    expect(diagnostics?.map((diagnostic) => diagnostic.code).sort()).toEqual([
      'SECRET-AWS-ACCESS-KEY',
      'SECRET-BASE64-HIGH-ENTROPY-STRING',
    ]);
    expect(state.warnings).toEqual([]);
  });

  it('reports an exit 0 scan with nothing found as clean, the negative control', async () => {
    const { host, collection } = captured('clean');

    const report = await runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('ok');
    expect(report.exitCode).toBe(0);
    expect(collection.totalDiagnostics()).toBe(0);
    expect(state.warnings).toEqual([]);
  });

  it('publishes the partial findings of an exit 1 scan and reports it incomplete', async () => {
    const { host, collection } = captured('incomplete');

    const report = await runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('incomplete');
    expect(report.exitCode).toBe(1);
    // Never a plain failure when results exist: the findings are on screen.
    expect(collection.totalDiagnostics()).toBe(3);
    expect(report.coverage?.coverage_complete).toBe(false);
    expect(report.coverage?.incomplete_scanners.map((row) => row.scanner)).toEqual(['semgrep']);
    const warning = state.warnings.join('\n');
    expect(warning).toContain('incomplete (exit 1)');
    expect(warning).toContain('scanner semgrep: ERROR');
    expect(warning).toContain('may not be all of them');
    expect(state.errors).toEqual([]);
  });

  it('says an empty panel is not clean when an exit 1 scan found nothing', async () => {
    const { host, collection } = captured('missing');

    const report = await runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('incomplete');
    expect(collection.totalDiagnostics()).toBe(0);
    expect(report.coverage?.incomplete_scanners.map((row) => row.scanner)).toEqual(['cfn-nag']);
    expect(state.warnings.join('\n')).toContain('not the same as clean');
  });

  it('reports incomplete from coverage_complete even when the gate let ASH exit 0', async () => {
    // fail_on_incomplete_scanners: false makes ASH exit 0 over a MISSING scanner.
    // The gap is still a fact the user needs.
    const { host } = captured('missing', { scanStatus: 0 });

    const report = await runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('incomplete');
    expect(report.detail).toContain('exit 0');
    expect(report.detail).toContain('scanner cfn-nag: MISSING');
  });

  it('reports an exit 1 scan whose results file is missing as incomplete, cause unknown', async () => {
    const scan = capturedScan('incomplete');
    const { host, collection } = harness({ sarifText: scan.sarif, scanStatus: 1 });

    const report = await runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('incomplete');
    expect(report.coverage).toBeNull();
    expect(collection.totalDiagnostics()).toBe(3);
    expect(report.detail).toContain('which part is missing is unknown');
  });

  it('reports an exit 1 scan whose results name no gap, rather than calling it complete', async () => {
    const scan = capturedScan('clean');
    const { host } = harness({ sarifText: scan.sarif, aggregatedText: scan.aggregated, scanStatus: 1 });

    const report = await runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('incomplete');
    expect(report.coverage?.coverage_complete).toBe(true);
    expect(report.detail).toContain('names no gap this extension recognizes');
  });

  it('warns that coverage is unknown when an exit 2 scan wrote no results file', async () => {
    const { host } = harness({ sarifFixture: 'planted-secret.sarif', scanStatus: 2 });

    const report = await runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('ok');
    expect(report.coverage).toBeNull();
    expect(state.warnings.join('\n')).toContain('could not confirm that every selected scanner ran');
  });

  it('treats an unparseable results file as unknown coverage, not as complete', async () => {
    const { host, lines } = harness({
      sarifFixture: 'planted-secret.sarif',
      aggregatedText: 'not json',
    });

    expect((await runScanCommand(host, SOURCE_DIR, SETTINGS)).coverage).toBeNull();
    expect(lines.join('\n')).toContain('is not an ASH aggregated results document');
  });
});

describe('a report from a previous run is never shown as this one', () => {
  const OLD = { [SARIF_FILE]: readFileSync(path.join(FIXTURES, 'planted-secret.sarif'), 'utf8') };

  it('deletes the previous report first, so a run that writes none reads as no report', async () => {
    const { host, collection, files } = harness({ previous: OLD, scanStatus: 0, scanWrites: false });

    const report = await runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('no-report');
    expect(files.has(SARIF_FILE)).toBe(false);
    expect(collection.totalDiagnostics()).toBe(0);
  });

  it('refuses a report it could not delete and the scan did not rewrite', async () => {
    const { host, collection, lines } = harness({
      previous: OLD,
      undeletable: [SARIF_FILE],
      scanStatus: 2,
      scanWrites: false,
    });

    const report = await runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('stale-report');
    expect(report.detail).toContain('from a previous scan');
    expect(collection.totalDiagnostics()).toBe(0);
    expect(lines.join('\n')).toContain('comparing modification times');
  });

  it('accepts a report it could not delete when the scan rewrote it', async () => {
    const { host, collection } = harness({
      previous: OLD,
      undeletable: [SARIF_FILE],
      sarifFixture: 'planted-secret.sarif',
    });

    expect((await runScanCommand(host, SOURCE_DIR, SETTINGS)).status).toBe('ok');
    expect(collection.totalDiagnostics()).toBe(3);
  });

  it('does not read a stale results file for coverage', async () => {
    const scan = capturedScan('missing');
    const { host, lines } = harness({
      previous: { [AGGREGATED_FILE]: scan.aggregated },
      undeletable: [AGGREGATED_FILE],
      sarifFixture: 'planted-secret.sarif',
    });

    const report = await runScanCommand(host, SOURCE_DIR, SETTINGS);

    // The stale file names cfn-nag MISSING. Reading it would report a gap this
    // run may not have.
    expect(report.coverage).toBeNull();
    expect(report.status).toBe('ok');
    expect(lines.join('\n')).toContain('is from a previous run and was not read');
  });

  it('reports a results file that vanished before it could be read as unknown', async () => {
    const { host } = harness({ sarifFixture: 'planted-secret.sarif', aggregatedText: '{}' });
    const flaky: ScanHost = {
      ...host,
      readFile: (file) => {
        if (file === AGGREGATED_FILE) {
          throw new Error('EIO');
        }
        return host.readFile(file);
      },
    };

    expect((await runScanCommand(flaky, SOURCE_DIR, SETTINGS)).coverage).toBeNull();
  });
});

describe('choosing the executable', () => {
  it('runs ashx by default', async () => {
    const { host, invocations } = captured('findings', { onPath: ['ashx', 'ash'] });

    const report = await runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.executable).toBe('ashx');
    expect(report.fallbackNotice).toBeUndefined();
    expect(invocations.map((call) => call.executable)).toEqual(['ashx', 'ashx']);
    expect(state.infos.join('\n')).not.toContain('is not on PATH');
  });

  it('falls back to ash when ashx is not installed, and says so once', async () => {
    const memento = new Memento();
    const first = captured('findings', { onPath: ['ash'], memento });

    const report = await runScanCommand(first.host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('ok');
    expect(report.executable).toBe('ash');
    expect(report.fallbackNotice).toBe('shown');
    expect(first.invocations.map((call) => call.executable)).toEqual(['ashx', 'ash', 'ash']);
    expect(state.infos.filter((message) => message === FALLBACK_NOTICE)).toHaveLength(1);
    expect(memento.values.get(FALLBACK_NOTICE_KEY)).toBe(true);

    // Persisted: a second scan, even through a new host, shows it no more.
    const second = captured('findings', { onPath: ['ash'], memento });
    expect((await runScanCommand(second.host, SOURCE_DIR, SETTINGS)).fallbackNotice).toBe('already-shown');
    expect(state.infos.filter((message) => message === FALLBACK_NOTICE)).toHaveLength(1);
    expect(second.lines.join('\n')).toContain('fell back to "ash"');
  });

  it('uses a configured executable as given and never falls back', async () => {
    const { host, invocations, collection } = captured('findings', { onPath: ['ash'] });

    const report = await runScanCommand(host, SOURCE_DIR, { ...SETTINGS, executablePath: 'ashx' });

    expect(report.status).toBe('wrong-executable');
    expect(invocations.map((call) => call.executable)).toEqual(['ashx']);
    expect(collection.totalDiagnostics()).toBe(0);
  });

  it('runs a configured legacy name without the fallback notice', async () => {
    const { host } = captured('findings', { onPath: ['ash'] });

    const report = await runScanCommand(host, SOURCE_DIR, { ...SETTINGS, executablePath: 'ash' });

    expect(report.executable).toBe('ash');
    expect(state.infos).not.toContain(FALLBACK_NOTICE);
  });
});

describe('findings the Problems panel cannot show', () => {
  it('are counted and surfaced when they name a file with no local path', async () => {
    const sarif = JSON.stringify({
      runs: [
        {
          results: [
            {
              ruleId: 'REMOTE',
              level: 'error',
              locations: [
                { physicalLocation: { artifactLocation: { uri: 'https://example.com/a.py' } } },
              ],
            },
          ],
        },
      ],
    });
    const { host, collection } = harness({ sarifText: sarif });

    const report = await runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.summary?.unresolved).toBe(1);
    expect(collection.totalDiagnostics()).toBe(0);
    expect(state.errors.join('\n')).toContain('named a file with no path on this machine');
  });
});

describe('the scan runs without blocking, and can be stopped', () => {
  it('runs under a cancellable progress notification with the configured timeout', async () => {
    const { host, asyncOptions, progressTitles } = captured('findings');

    await runScanCommand(host, SOURCE_DIR, { ...SETTINGS, scanTimeoutSeconds: 90 });

    expect(progressTitles).toEqual(['ASH: scanning workspace']);
    expect(asyncOptions[0].timeoutMs).toBe(90_000);
    expect(asyncOptions[0].signal).toBeDefined();
    expect(asyncOptions[0].cwd).toBe(SOURCE_DIR);
  });

  it('passes a timeout of 0 through, which waits indefinitely', async () => {
    const { host, asyncOptions } = captured('findings');

    await runScanCommand(host, SOURCE_DIR, { ...SETTINGS, scanTimeoutSeconds: 0 });

    expect(asyncOptions[0].timeoutMs).toBe(0);
  });

  it('reports a timed-out scan as failed, says how to raise the limit, and shows nothing', async () => {
    // The stopped scan had written a report before it was killed. Publishing it
    // would show a partial result as though the scan had finished.
    const { host, collection } = captured('findings', { scanTimedOut: true, scanStatus: null });

    const report = await runScanCommand(host, SOURCE_DIR, { ...SETTINGS, scanTimeoutSeconds: 60 });

    expect(report.status).toBe('scan-failed');
    expect(report.detail).toContain('did not finish within 60s');
    expect(report.detail).toContain('ash.scanTimeoutSeconds');
    expect(collection.totalDiagnostics()).toBe(0);
    expect(state.errors.join('\n')).toContain('did not finish within 60s');
  });

  it('reports a cancelled scan as cancelled and shows nothing from it', async () => {
    const { host, collection } = captured('findings', { scanCancelled: true, scanStatus: null });

    const report = await runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('cancelled');
    expect(collection.totalDiagnostics()).toBe(0);
    expect(state.infos.join('\n')).toContain('cancelled');
    expect(state.errors).toEqual([]);
  });

  it('bridges the progress notification\'s Cancel to the signal the runner gets', async () => {
    const memento = new Memento();
    const host = createScanHost(
      new DiagnosticCollection('ash') as unknown as vscode.DiagnosticCollection,
      new OutputChannel('ASH') as unknown as vscode.OutputChannel,
      memento as unknown as vscode.Memento,
    );
    let seen: AbortSignal | undefined;

    const pending = host.withProgress('ASH: scanning workspace', (signal) => {
      seen = signal;
      return new Promise<string>((resolve) => signal.addEventListener('abort', () => resolve('stopped')));
    });
    expect(progress.calls).toEqual([
      { location: vscode.ProgressLocation.Notification, title: 'ASH: scanning workspace', cancellable: true },
    ]);
    expect(seen?.aborted).toBe(false);
    progress.cancel?.();

    await expect(pending).resolves.toBe('stopped');
    expect(seen?.aborted).toBe(true);
  });
});

describe('one scan at a time', () => {
  it('hands a second invocation the running scan instead of starting another', async () => {
    state.workspaceFolders = [{ uri: { fsPath: FIXTURES } }];
    state.configuration.set('ash.executablePath', 'ash-that-is-not-installed-anywhere');
    activate({ subscriptions: [], globalState: new Memento() } as unknown as vscode.ExtensionContext);
    const scan = state.commands.get(COMMAND_SCAN) as () => Promise<{ status: string }>;

    const first = scan();
    const second = scan();

    expect(second).toBe(first);
    expect((await first).status).toBe('wrong-executable');
    // Once it settles, the next invocation starts a new scan.
    expect(scan()).not.toBe(first);
  });
});
