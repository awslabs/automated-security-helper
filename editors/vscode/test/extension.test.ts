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
 * empty ASH scan exits 0 and still writes a report. The same reasoning is written
 * out in packaging/deb/verify-in-container.sh, which asserts a non-zero SARIF
 * result count for the same reason at the package layer.
 *
 * The negative control is the other half. `clean-scan.sarif` is the same measured
 * document with `results` emptied, and the test below requires it to produce ZERO
 * diagnostics. Without that, an assertion of `>= 0` would pass on everything and
 * an assertion of `> 0` could be satisfied by a mapper that invented findings.
 *
 * WHERE THE FIXTURES CAME FROM
 *
 * `planted-secret.sarif` is the real output of
 * `ash scan --source-dir . --output-dir .ash/ash_output --scanners detect-secrets
 * --no-progress` over test/fixtures/planted_secret.py, with the scanning
 * machine's absolute path replaced by /workspace. That run exited 2 -- ASH's
 * "actionable findings detected" code -- and reported 3 results. Both numbers are
 * asserted below, so a fixture edited to something ASH would not produce fails
 * rather than passes.
 */

import * as path from 'path';
import * as vscode from 'vscode';
import { CommandResult } from '../src/ash-cli';
import {
  COMMAND_CLEAR,
  COMMAND_SCAN,
  ScanHost,
  ScanSettings,
  activate,
  createScanHost,
  currentSourceDir,
  deactivate,
  readSettings,
  runScanCommand,
} from '../src/extension';
import { DiagnosticCollection, OutputChannel, resetState, state } from './vscode-stub';
import { readFileSync } from 'fs';

const FIXTURES = path.join(__dirname, 'fixtures');
const SOURCE_DIR = '/workspace';
const OUTPUT_DIR = path.join(SOURCE_DIR, '.ash', 'ash_output');
const SARIF_FILE = path.join(OUTPUT_DIR, 'reports', 'ash.sarif');

const ASH_VERSION_OUTPUT = 'awslabs/automated-security-helper v3.7.0';

const SETTINGS: ScanSettings = {
  executablePath: 'ash',
  outputDirectory: '.ash/ash_output',
  extraArguments: [],
};

interface HarnessOptions {
  /** Which fixture the fake ASH "wrote" to the SARIF path, if any. */
  readonly sarifFixture?: string;
  /** Raw SARIF text, when a fixture would not express the case. */
  readonly sarifText?: string;
  /** Exit status of the scan invocation. ASH exits 2 when it finds something. */
  readonly scanStatus?: number | null;
  readonly scanError?: Error;
  /** Output of `--version`. Defaults to the measured real string. */
  readonly versionOutput?: string;
  readonly versionError?: Error;
}

interface Harness {
  readonly host: ScanHost;
  readonly collection: DiagnosticCollection;
  readonly invocations: { executable: string; args: readonly string[] }[];
}

function harness(options: HarnessOptions = {}): Harness {
  const collection = new DiagnosticCollection('ash');
  const invocations: { executable: string; args: readonly string[] }[] = [];
  const lines: string[] = [];

  const sarifText =
    options.sarifText ??
    (options.sarifFixture === undefined
      ? undefined
      : readFileSync(path.join(FIXTURES, options.sarifFixture), 'utf8'));

  const run = (executable: string, args: readonly string[]): CommandResult => {
    invocations.push({ executable, args });
    if (args[0] === '--version') {
      return {
        status: options.versionError === undefined ? 0 : null,
        stdout: options.versionOutput ?? ASH_VERSION_OUTPUT,
        stderr: '',
        error: options.versionError,
      };
    }
    return {
      // `?? 2` would be wrong here: `null` is the status of a process killed by a
      // signal and is one of the cases under test, and nullish coalescing would
      // quietly turn it into 2. The `in` check keeps "not specified" and
      // "specified as null" apart.
      status: 'scanStatus' in options ? (options.scanStatus as number | null) : 2,
      stdout: 'scan output',
      stderr: '',
      error: options.scanError,
    };
  };

  return {
    collection,
    invocations,
    host: {
      collection: collection as unknown as vscode.DiagnosticCollection,
      run,
      readFile: (file) => {
        if (file !== SARIF_FILE || sarifText === undefined) {
          throw new Error(`unexpected read of ${file}`);
        }
        return sarifText;
      },
      fileExists: (file) => file === SARIF_FILE && sarifText !== undefined,
      log: (line) => lines.push(line),
      showError: (message) => state.errors.push(message),
      showInfo: (message) => state.infos.push(message),
    },
  };
}

beforeEach(() => {
  resetState();
});

describe('a fixture with a planted secret reaches the editor model', () => {
  it('publishes a non-zero count of diagnostics', () => {
    const { host, collection } = harness({ sarifFixture: 'planted-secret.sarif' });

    const report = runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('ok');
    // The assertion this whole extension exists for. A zero here is what a
    // shadowed `ash`, a crashed scan and a clean tree all look like.
    expect(collection.totalDiagnostics()).toBeGreaterThan(0);
    expect(report.summary?.diagnostics).toBeGreaterThan(0);
  });

  it('publishes exactly the three findings the measured scan reported', () => {
    const { host, collection } = harness({ sarifFixture: 'planted-secret.sarif' });

    const report = runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.summary).toEqual({ files: 1, diagnostics: 3, unlocated: 0 });
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

  it('treats exit 2 as a completed scan, because that is ASH\'s findings code', () => {
    const { host, invocations } = harness({ sarifFixture: 'planted-secret.sarif', scanStatus: 2 });

    expect(runScanCommand(host, SOURCE_DIR, SETTINGS).status).toBe('ok');
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
  it('publishes zero diagnostics for a scan that found nothing', () => {
    const { host, collection } = harness({ sarifFixture: 'clean-scan.sarif', scanStatus: 0 });

    const report = runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('ok');
    expect(collection.totalDiagnostics()).toBe(0);
    expect(state.infos.join('\n')).toContain('no findings');
  });
});

describe('a re-scan does not leave stale findings on screen', () => {
  it('clears before publishing', () => {
    const first = harness({ sarifFixture: 'planted-secret.sarif' });
    runScanCommand(first.host, SOURCE_DIR, SETTINGS);
    expect(first.collection.totalDiagnostics()).toBe(3);

    // Same collection, second scan, nothing found. The fixed findings must go.
    const second: ScanHost = {
      ...harness({ sarifFixture: 'clean-scan.sarif', scanStatus: 0 }).host,
      collection: first.collection as unknown as vscode.DiagnosticCollection,
    };
    runScanCommand(second, SOURCE_DIR, SETTINGS);

    expect(first.collection.totalDiagnostics()).toBe(0);
  });
});

describe('every way a scan can produce nothing is distinguishable from a clean tree', () => {
  it('refuses when no folder is open', () => {
    const { host, collection } = harness({ sarifFixture: 'planted-secret.sarif' });

    const report = runScanCommand(host, undefined, SETTINGS);

    expect(report.status).toBe('no-workspace');
    expect(collection.totalDiagnostics()).toBe(0);
    expect(state.errors.join('\n')).toContain('open a folder');
  });

  it('refuses when the executable is not on PATH', () => {
    const enoent = Object.assign(new Error('spawnSync ash ENOENT'), { code: 'ENOENT' });
    const { host } = harness({ versionError: enoent });

    const report = runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('wrong-executable');
    expect(state.errors.join('\n')).toContain('not on PATH');
  });

  it('refuses when the Almquist shell answered instead of ASH', () => {
    // What MSYS2's `ash` prints when handed --version. It is the collision the
    // entry-point contract exists for, and it must not scan.
    const { host, collection } = harness({ versionOutput: 'ash: 0: Illegal option --' });

    const report = runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('wrong-executable');
    expect(collection.totalDiagnostics()).toBe(0);
    const shown = state.errors.join('\n');
    expect(shown).toContain('is not ASH');
    expect(shown).toContain('automated-security-helper');
    expect(shown).toContain('Almquist');
  });

  it('reports a scan that exited 1 rather than publishing a stale report', () => {
    const { host } = harness({ sarifFixture: 'planted-secret.sarif', scanStatus: 1 });

    const report = runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('scan-failed');
    expect(report.detail).toContain('did not complete');
    expect(state.errors.join('\n')).toContain('ASH:');
  });

  it('reports a scan killed by a signal', () => {
    const { host } = harness({ sarifFixture: 'planted-secret.sarif', scanStatus: null });

    expect(runScanCommand(host, SOURCE_DIR, SETTINGS).status).toBe('scan-failed');
  });

  it('reports a scan that could not be started', () => {
    const { host } = harness({ scanError: new Error('EACCES') });

    const report = runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('scan-failed');
    expect(report.detail).toContain('EACCES');
  });

  it('reports an exit 0 that wrote no report at all', () => {
    // The case that most needs a message. Exit 0 with no SARIF is what a
    // shadowed binary or a crashed reporter looks like, and an empty Problems
    // panel would read as a clean tree.
    const { host } = harness({ scanStatus: 0 });

    const report = runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('no-report');
    expect(state.errors.join('\n')).toContain('no evidence the tree is clean');
  });

  it('reports a report that is not readable SARIF', () => {
    const { host } = harness({ sarifText: '{"not": "sarif"}' });

    const report = runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('unreadable-report');
    expect(report.detail).toContain('no "runs" array');
  });
});

describe('findings with no file location', () => {
  it('are counted and surfaced rather than dropped', () => {
    const sarif = JSON.stringify({
      runs: [
        {
          tool: { driver: { name: 'AWS Labs - Automated Security Helper' } },
          results: [{ ruleId: 'NO-LOCATION', message: { text: 'nowhere' }, level: 'error' }],
        },
      ],
    });
    const { host, collection } = harness({ sarifText: sarif });

    const report = runScanCommand(host, SOURCE_DIR, SETTINGS);

    expect(report.status).toBe('ok');
    expect(collection.totalDiagnostics()).toBe(0);
    expect(report.summary?.unlocated).toBe(1);
    expect(state.errors.join('\n')).toContain('named no file');
  });
});

describe('an absolute ash.outputDirectory', () => {
  it('is used as given rather than joined onto the workspace', () => {
    const { host, invocations } = harness({ sarifFixture: 'planted-secret.sarif' });

    runScanCommand(host, SOURCE_DIR, { ...SETTINGS, outputDirectory: '/tmp/elsewhere' });

    expect(invocations[1].args).toContain('/tmp/elsewhere');
    // No SARIF exists at that path in this harness, so the scan is reported as
    // having written none -- which is the point: the path was not rewritten.
    expect(state.errors.join('\n')).toContain('/tmp/elsewhere');
  });
});

describe('extra arguments', () => {
  it('are appended after the flags the extension controls', () => {
    const { host, invocations } = harness({ sarifFixture: 'planted-secret.sarif' });

    runScanCommand(host, SOURCE_DIR, {
      ...SETTINGS,
      extraArguments: ['--scanners', 'detect-secrets'],
    });

    expect(invocations[1].args.slice(-3)).toEqual(['--no-progress', '--scanners', 'detect-secrets']);
  });
});

describe('activation', () => {
  it('registers both commands and hands them a disposable collection', () => {
    const subscriptions: { dispose(): void }[] = [];

    activate({ subscriptions } as unknown as vscode.ExtensionContext);

    expect([...state.commands.keys()].sort()).toEqual([COMMAND_CLEAR, COMMAND_SCAN]);
    expect(state.collections).toHaveLength(1);
    expect(state.channels).toHaveLength(1);
    // collection, channel, and one disposable per registered command.
    expect(subscriptions).toHaveLength(4);
  });

  it('scans through the registered command, and reports no workspace when none is open', () => {
    activate({ subscriptions: [] } as unknown as vscode.ExtensionContext);

    const report = state.commands.get(COMMAND_SCAN)?.() as { status: string };

    expect(report.status).toBe('no-workspace');
  });

  it('clears findings through the registered command', () => {
    activate({ subscriptions: [] } as unknown as vscode.ExtensionContext);
    const collection = state.collections[0];
    collection.set(vscode.Uri.file('/workspace/a.py'), [
      new vscode.Diagnostic(new vscode.Range(0, 0, 0, 1), 'x'),
    ]);
    expect(collection.totalDiagnostics()).toBe(1);

    state.commands.get(COMMAND_CLEAR)?.();

    expect(collection.totalDiagnostics()).toBe(0);
    expect(state.channels[0].lines).toContain('Cleared ASH findings.');
  });

  it('deactivates without throwing', () => {
    expect(() => deactivate()).not.toThrow();
  });
});

describe('the real host activate builds', () => {
  it('reads a real file, answers about a real path, and logs to the channel', () => {
    const collection = new DiagnosticCollection('ash');
    const channel = new OutputChannel('ASH');
    const host = createScanHost(
      collection as unknown as vscode.DiagnosticCollection,
      channel as unknown as vscode.OutputChannel,
    );

    const fixture = path.join(FIXTURES, 'clean-scan.sarif');
    expect(host.fileExists(fixture)).toBe(true);
    expect(host.fileExists(path.join(FIXTURES, 'absent.sarif'))).toBe(false);
    // utf8 and not a Buffer: `readFileSync` without an encoding returns bytes,
    // and JSON.parse on a Buffer works by coercion, which would hide a real
    // encoding bug until a non-ASCII path appeared in a message.
    expect(typeof host.readFile(fixture)).toBe('string');
    expect(JSON.parse(host.readFile(fixture)).version).toBe('2.1.0');

    host.log('hello');
    expect(channel.lines).toEqual(['hello']);

    host.showError('bad');
    host.showInfo('good');
    expect(state.errors).toEqual(['bad']);
    expect(state.infos).toEqual(['good']);
  });

  it('spawns for real, so a missing executable is reported rather than scanned past', () => {
    // End to end through the registered command with the real spawner: no
    // executable named this exists, so the probe must refuse. This is the one
    // test that proves activate wired the real spawnSyncRunner in.
    state.workspaceFolders = [{ uri: { fsPath: FIXTURES } }];
    state.configuration.set('ash.executablePath', 'ash-that-is-not-installed-anywhere');
    activate({ subscriptions: [] } as unknown as vscode.ExtensionContext);

    const report = state.commands.get(COMMAND_SCAN)?.() as { status: string; detail: string };

    expect(report.status).toBe('wrong-executable');
    expect(report.detail).toContain('not on PATH');
    expect(state.collections[0].totalDiagnostics()).toBe(0);
    expect(state.channels[0].lines.join('\n')).toContain('not on PATH');
  });
});

describe('settings and workspace resolution', () => {
  it('fall back to the defaults package.json contributes', () => {
    expect(readSettings()).toEqual({
      executablePath: 'ash',
      outputDirectory: '.ash/ash_output',
      extraArguments: [],
    });
  });

  it('take the configured values when they are set', () => {
    state.configuration.set('ash.executablePath', '/opt/ash/bin/automated-security-helper');
    state.configuration.set('ash.outputDirectory', 'build/ash');
    state.configuration.set('ash.extraArguments', ['--offline']);

    expect(readSettings()).toEqual({
      executablePath: '/opt/ash/bin/automated-security-helper',
      outputDirectory: 'build/ash',
      extraArguments: ['--offline'],
    });
  });

  it('replace an empty configured value with the default rather than spawning nothing', () => {
    state.configuration.set('ash.executablePath', '');
    state.configuration.set('ash.outputDirectory', '');

    expect(readSettings().executablePath).toBe('ash');
    expect(readSettings().outputDirectory).toBe('.ash/ash_output');
  });

  it('report no source directory when no folder is open', () => {
    expect(currentSourceDir()).toBeUndefined();

    state.workspaceFolders = [];
    expect(currentSourceDir()).toBeUndefined();

    state.workspaceFolders = [{ uri: { fsPath: '/workspace' } }];
    expect(currentSourceDir()).toBe('/workspace');
  });
});
