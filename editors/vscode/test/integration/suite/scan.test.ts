// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * End to end inside a real VS Code: the registered command runs a real child
 * process, and the assertions read the editor's own diagnostics API.
 *
 * The tests run in order and share one window, because the first one depends on
 * the PATH run.ts set up (no `ashx`) and a later one changes it (adds `ashx`).
 *
 * In stub mode each scenario replays a captured scan from test/fixtures/scans/.
 * In real mode (ASH_IT_REAL_ASH_DIR) the same outcomes come from genuine scans,
 * chosen with `--scanners` and a workspace `.ash/.ash.yaml`:
 *
 *   findings    detect-secrets with SECRET-SECRET-KEYWORD suppressed -> exit 2
 *   incomplete  cfn-nag,detect-secrets on a PATH without cfn-nag    -> exit 1
 *   clean       detect-secrets with SECRET-* suppressed              -> exit 0
 */

import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import type { ScanReport } from '../../../src/extension';

const MODE = process.env.ASH_IT_MODE ?? 'stub';
const WORKSPACE = process.env.ASH_IT_WORKSPACE ?? '';
const ASHX_DIR = process.env.ASH_IT_ASHX_DIR ?? '';
const ASH_DIR = process.env.ASH_IT_ASH_DIR ?? '';
const SCENARIO_FILE = process.env.ASH_STUB_SCENARIO_FILE ?? '';
const SECRET_FILE = vscode.Uri.file(path.join(WORKSPACE, 'planted_secret.py'));

type Outcome = 'findings' | 'incomplete' | 'clean';

interface Expected {
  readonly exitCode: number;
  readonly diagnostics: number;
  readonly suppressed: number;
  readonly incompleteScanner?: string;
}

const STUB_EXPECTED: Record<Outcome, Expected> = {
  findings: { exitCode: 2, diagnostics: 2, suppressed: 1 },
  incomplete: { exitCode: 1, diagnostics: 3, suppressed: 0, incompleteScanner: 'semgrep' },
  clean: { exitCode: 0, diagnostics: 0, suppressed: 0 },
};

const REAL_EXPECTED: Record<Outcome, Expected> = {
  findings: { exitCode: 2, diagnostics: 2, suppressed: 1 },
  incomplete: { exitCode: 1, diagnostics: 2, suppressed: 1, incompleteScanner: 'cfn-nag' },
  clean: { exitCode: 0, diagnostics: 0, suppressed: 3 },
};

function ashConfig(ruleId: string): string {
  return [
    'project_name: vscode-integration',
    'fail_on_findings: true',
    'global_settings:',
    '  suppressions:',
    `    - rule_id: "${ruleId}"`,
    '      path: planted_secret.py',
    '      reason: integration fixture',
    '',
  ].join('\n');
}

/**
 * Writes a setting and waits until the extension host reads it back.
 *
 * `update` resolves once the settings file is written, which is not the same as
 * the extension host's configuration having changed: measured, a scan started
 * straight after `update` read the previous `extraArguments` and ran the previous
 * scanner set. So the value is read back until it matches.
 */
async function setSetting(
  key: string,
  value: unknown,
  target: vscode.ConfigurationTarget,
): Promise<void> {
  await vscode.workspace.getConfiguration('ash').update(key, value, target);
  const wanted = JSON.stringify(value);
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const inspected = vscode.workspace.getConfiguration('ash').inspect(key);
    const current =
      target === vscode.ConfigurationTarget.Global ? inspected?.globalValue : inspected?.workspaceValue;
    if (JSON.stringify(current) === wanted) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`ash.${key} did not become ${wanted} in the extension host`);
}

/** Sets up one outcome for the next scan and returns what it must produce. */
async function arrange(outcome: Outcome): Promise<Expected> {
  if (MODE === 'stub') {
    fs.writeFileSync(SCENARIO_FILE, JSON.stringify({ fixture: outcome }));
    return STUB_EXPECTED[outcome];
  }
  fs.mkdirSync(path.join(WORKSPACE, '.ash'), { recursive: true });
  fs.writeFileSync(
    path.join(WORKSPACE, '.ash', '.ash.yaml'),
    ashConfig(outcome === 'clean' ? 'SECRET-*' : 'SECRET-SECRET-KEYWORD'),
  );
  const scanners = outcome === 'incomplete' ? 'cfn-nag,detect-secrets' : 'detect-secrets';
  await setSetting('extraArguments', ['--scanners', scanners], vscode.ConfigurationTarget.Workspace);
  return REAL_EXPECTED[outcome];
}

async function scan(): Promise<ScanReport> {
  const report = await vscode.commands.executeCommand<ScanReport>('ash.scanWorkspace');
  assert.ok(report !== undefined, 'the scan command returned nothing');
  return report;
}

function ashDiagnostics(uri: vscode.Uri): vscode.Diagnostic[] {
  return vscode.languages
    .getDiagnostics(uri)
    .filter((diagnostic) => (diagnostic.source ?? '').startsWith('ASH'));
}

/** Which stub wrappers the CLI was invoked through, in order. */
function invokedAs(): string[] {
  // Real mode logs only the wrappers run.ts wrote; the real `ash` logs nothing.
  const calls = `${SCENARIO_FILE}.calls`;
  if (!fs.existsSync(calls)) {
    return [];
  }
  return fs
    .readFileSync(calls, 'utf8')
    .trim()
    .split('\n')
    .map((line) => (JSON.parse(line) as { invokedAs: string }).invokedAs);
}

function resetCalls(): void {
  fs.rmSync(`${SCENARIO_FILE}.calls`, { force: true });
}

suite('ASH in a real VS Code', () => {
  suiteSetup(() => {
    assert.ok(WORKSPACE !== '' && fs.existsSync(WORKSPACE), `no workspace at ${WORKSPACE}`);
    assert.strictEqual(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath, WORKSPACE);
    assert.ok(!fs.existsSync(path.join(ASHX_DIR, 'ashx')), 'the suite must start with no ashx');
  });

  setup(() => resetCalls());

  test('runs ash when ashx is not installed, and shows the notice only once', async () => {
    const expected = await arrange('findings');

    const first = await scan();

    assert.strictEqual(first.executable, 'ash');
    assert.strictEqual(first.fallbackNotice, 'shown');
    assert.strictEqual(first.status, 'ok', first.detail);
    if (MODE === 'stub') {
      // ashx probed and missing, then ash probed and scanned.
      assert.deepStrictEqual(invokedAs(), ['ash', 'ash']);
    }

    const second = await scan();
    assert.strictEqual(second.executable, 'ash');
    assert.strictEqual(second.fallbackNotice, 'already-shown');
    assert.strictEqual(second.exitCode, expected.exitCode);
  });

  test('puts exit 2 findings in the editor and leaves the suppressed one out', async () => {
    const expected = await arrange('findings');

    const report = await scan();

    assert.strictEqual(report.status, 'ok', report.detail);
    assert.strictEqual(report.exitCode, 2);
    assert.strictEqual(report.coverage?.coverage_complete, true);
    assert.strictEqual(report.summary?.suppressed, expected.suppressed);
    const diagnostics = ashDiagnostics(SECRET_FILE);
    assert.strictEqual(diagnostics.length, expected.diagnostics);
    assert.deepStrictEqual(
      diagnostics.map((diagnostic) => String(diagnostic.code)).sort(),
      ['SECRET-AWS-ACCESS-KEY', 'SECRET-BASE64-HIGH-ENTROPY-STRING'],
    );
    for (const diagnostic of diagnostics) {
      assert.strictEqual(diagnostic.range.start.line, 24);
      assert.strictEqual(diagnostic.severity, vscode.DiagnosticSeverity.Error);
      assert.strictEqual(diagnostic.source, 'ASH (detect-secrets)');
    }
  });

  test('shows the partial findings of an exit 1 scan and reports it incomplete', async () => {
    const expected = await arrange('incomplete');

    const report = await scan();

    assert.strictEqual(report.status, 'incomplete', report.detail);
    assert.strictEqual(report.exitCode, 1);
    assert.strictEqual(report.coverage?.coverage_complete, false);
    assert.deepStrictEqual(
      report.coverage?.incomplete_scanners.map((row) => row.scanner),
      [expected.incompleteScanner],
    );
    assert.ok(
      (report.detail ?? '').includes(`scanner ${expected.incompleteScanner ?? ''}`),
      report.detail,
    );
    // Exit 1 with results is never a plain failure: the findings are on screen.
    assert.strictEqual(ashDiagnostics(SECRET_FILE).length, expected.diagnostics);
    assert.ok(expected.diagnostics > 0);
  });

  test('clears the editor for a clean exit 0 scan, the negative control', async () => {
    assert.ok(ashDiagnostics(SECRET_FILE).length > 0, 'the previous test left no findings to clear');
    await arrange('clean');

    const report = await scan();

    assert.strictEqual(report.status, 'ok', report.detail);
    assert.strictEqual(report.exitCode, 0);
    assert.strictEqual(ashDiagnostics(SECRET_FILE).length, 0);
  });

  test('reports an exit 1 that wrote nothing as a failed scan, not an incomplete one', async () => {
    // Configured by full path, which is also the explicit-path case succeeding:
    // it runs exactly what was named.
    await setSetting(
      'executablePath',
      process.env.ASH_IT_CRASHING_EXECUTABLE,
      vscode.ConfigurationTarget.Global,
    );
    try {
      const report = await scan();

      assert.strictEqual(report.executable, process.env.ASH_IT_CRASHING_EXECUTABLE);
      assert.strictEqual(report.status, 'scan-failed', report.detail);
      assert.strictEqual(report.exitCode, 1);
      assert.ok((report.detail ?? '').includes('exited 1 and wrote no SARIF report'), report.detail);
      assert.deepStrictEqual(invokedAs(), ['crash', 'crash']);
    } finally {
      await setSetting('executablePath', undefined, vscode.ConfigurationTarget.Global);
    }
  });

  test('stops a scan that outruns ash.scanTimeoutSeconds, without blocking the editor', async () => {
    // Findings on screen first, so the test also shows a failed scan clears them.
    await arrange('findings');
    await scan();
    assert.ok(ashDiagnostics(SECRET_FILE).length > 0);
    if (MODE === 'stub') {
      fs.writeFileSync(SCENARIO_FILE, JSON.stringify({ fixture: 'findings', hangSeconds: 120 }));
    }
    // In real mode no hang is needed: ASH takes several seconds to start, so a
    // genuine scan outruns 2s.
    await setSetting('scanTimeoutSeconds', 2, vscode.ConfigurationTarget.Global);
    try {
      const started = Date.now();
      let ticks = 0;
      const ticker = setInterval(() => (ticks += 1), 50);
      const report = await scan().finally(() => clearInterval(ticker));

      assert.strictEqual(report.status, 'scan-failed', report.detail);
      assert.ok((report.detail ?? '').includes('did not finish within 2s'), report.detail);
      assert.ok(Date.now() - started < 15_000, 'the timeout did not stop the scan');
      // The extension host kept running timers while the scan ran.
      assert.ok(ticks >= 10, `the extension host was blocked: ${ticks} ticks`);
      assert.strictEqual(ashDiagnostics(SECRET_FILE).length, 0);
    } finally {
      await setSetting('scanTimeoutSeconds', undefined, vscode.ConfigurationTarget.Global);
    }
  });

  test('runs ashx once it is installed', async () => {
    const ashx = path.join(ASHX_DIR, 'ashx');
    if (MODE === 'stub') {
      fs.writeFileSync(ashx, process.env.ASH_IT_ASHX_WRAPPER ?? '', { mode: 0o755 });
    } else {
      fs.symlinkSync(path.join(ASH_DIR, 'ash'), ashx);
    }
    const expected = await arrange('findings');

    const report = await scan();

    assert.strictEqual(report.executable, 'ashx');
    assert.strictEqual(report.fallbackNotice, undefined);
    assert.strictEqual(report.exitCode, expected.exitCode);
    if (MODE === 'stub') {
      assert.deepStrictEqual(invokedAs(), ['ashx', 'ashx']);
    }
  });

  test('uses a configured executable as given, with no fallback', async () => {
    const missing = path.join(ASHX_DIR, 'not-installed');
    await setSetting('executablePath', missing, vscode.ConfigurationTarget.Global);
    try {
      await arrange('findings');

      const report = await scan();

      assert.strictEqual(report.status, 'wrong-executable');
      assert.ok((report.detail ?? '').includes('not on PATH'), report.detail);
      assert.deepStrictEqual(invokedAs(), []);
    } finally {
      await setSetting('executablePath', undefined, vscode.ConfigurationTarget.Global);
    }
  });
});
