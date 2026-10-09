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
 * In real mode (ASH_IT_REAL_ASH_DIR) every scan is a genuine one over the shared
 * e2e cases in tests/e2e/fixtures/cases.json, the same three every install
 * channel runs: the workspace holds a copy of the case's fixture, the case's
 * scanners and args go in through `ash.extraArguments`, and its environment is
 * set on the extension host, whose environment the scan inherits. After each one,
 * scripts/e2e/assert_outcome.py judges the output directory the extension wrote,
 * so the editor-side assertions here and the channel-wide verdict cover the same
 * scan:
 *
 *   findings    detect-secrets                          -> exit 2, 3 findings
 *   incomplete  detect-secrets,opengrep, offline, no
 *               rule cache (see tests/e2e/README.md)    -> exit 1, opengrep MISSING
 *   clean       detect-secrets on a tree with no secret -> exit 0
 *
 * Three tests add a config to the findings case that suppresses
 * SECRET-SECRET-KEYWORD on leak.py: exit 2, 2 actionable findings, 1 suppressed.
 * The config is a workspace .ash/.ash.yaml, a root pyproject.toml with
 * [tool.ash], or a root .ashrc.yaml.
 */

import * as assert from 'assert';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import type { ScanReport } from '../../../src/extension';

const MODE = process.env.ASH_IT_MODE ?? 'stub';
const CLI_NAME = process.env.ASH_IT_CLI_NAME ?? 'ashx';
const WORKSPACE = process.env.ASH_IT_WORKSPACE ?? '';
const ASHX_DIR = process.env.ASH_IT_ASHX_DIR ?? '';
const REAL_ASH_DIR = process.env.ASH_IT_REAL_ASH_DIR ?? '';
const SCENARIO_FILE = process.env.ASH_STUB_SCENARIO_FILE ?? '';
const E2E_FIXTURES = process.env.ASH_IT_E2E_FIXTURES ?? '';
const CASES_FILE = process.env.ASH_IT_CASES_FILE ?? '';
const ASSERT_OUTCOME = process.env.ASH_IT_ASSERT_OUTCOME ?? '';
const PYTHON = process.env.ASH_IT_PYTHON ?? 'python3';
const EXTENSION_ID = process.env.ASH_IT_EXTENSION_ID ?? '';
const EXTENSIONS_DIR = process.env.ASH_IT_EXTENSIONS_DIR ?? '';
const EXPECT_VERSION = process.env.ASH_IT_EXPECT_VERSION ?? '';

/** The file each mode's findings land on. */
const SECRET_FILE = vscode.Uri.file(
  path.join(WORKSPACE, MODE === 'stub' ? 'planted_secret.py' : 'leak.py'),
);

/** Where the extension tells ASH to write, its `ash.outputDirectory` default. */
const OUTPUT_DIR = path.join(WORKSPACE, '.ash', 'ash_output');

type Outcome = 'findings' | 'incomplete' | 'clean';

interface Expected {
  readonly exitCode: number;
  readonly diagnostics: number;
  readonly suppressed: number;
  readonly incompleteScanner?: string;
}

/** One case from tests/e2e/fixtures/cases.json. */
interface E2eCase {
  readonly source: string;
  readonly scanners: readonly string[];
  readonly args?: readonly string[];
  readonly env?: Readonly<Record<string, string>>;
  readonly expect_rc: number;
  readonly findings?: number;
  readonly incomplete_scanner?: string;
}

const STUB_EXPECTED: Record<Outcome, Expected> = {
  findings: { exitCode: 2, diagnostics: 2, suppressed: 1 },
  incomplete: { exitCode: 1, diagnostics: 3, suppressed: 0, incompleteScanner: 'semgrep' },
  clean: { exitCode: 0, diagnostics: 0, suppressed: 0 },
};

/** The rules each mode's findings scan reports on SECRET_FILE, and on which line. */
const FINDINGS_RULES: Record<string, { readonly codes: readonly string[]; readonly line: number }> = {
  // The captured scan has SECRET-SECRET-KEYWORD suppressed.
  stub: { codes: ['SECRET-AWS-ACCESS-KEY', 'SECRET-BASE64-HIGH-ENTROPY-STRING'], line: 24 },
  // tests/e2e/README.md: detect-secrets reports these three on leak.py's line 3.
  real: {
    codes: ['SECRET-AWS-ACCESS-KEY', 'SECRET-BASE64-HIGH-ENTROPY-STRING', 'SECRET-SECRET-KEYWORD'],
    line: 2,
  },
};

function loadCase(outcome: Outcome): E2eCase {
  const parsed = JSON.parse(fs.readFileSync(CASES_FILE, 'utf8')) as {
    cases?: Record<string, E2eCase>;
  };
  const found = parsed.cases?.[outcome];
  assert.ok(found !== undefined, `${CASES_FILE} has no case "${outcome}"`);
  return found;
}

function realExpected(e2e: E2eCase): Expected {
  assert.ok(typeof e2e.findings === 'number', 'the real suite needs an exact finding count');
  return {
    exitCode: e2e.expect_rc,
    diagnostics: e2e.findings,
    // The e2e fixtures carry no suppressions.
    suppressed: 0,
    incompleteScanner: e2e.incomplete_scanner,
  };
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

/** Environment variables the previous real case set, to unset before the next. */
let caseEnvKeys: string[] = [];

/** Sets up one outcome for the next scan and returns what it must produce. */
async function arrange(outcome: Outcome): Promise<Expected> {
  if (MODE === 'stub') {
    fs.writeFileSync(SCENARIO_FILE, JSON.stringify({ fixture: outcome }));
    return STUB_EXPECTED[outcome];
  }
  const e2e = loadCase(outcome);
  // The workspace becomes exactly the case's fixture, apart from .vscode, which is
  // left alone; the previous output goes, so nothing judged below can be left over
  // from an earlier scan.
  for (const entry of fs.readdirSync(WORKSPACE)) {
    if (entry !== '.vscode') {
      fs.rmSync(path.join(WORKSPACE, entry), { recursive: true, force: true });
    }
  }
  fs.cpSync(path.join(E2E_FIXTURES, e2e.source), WORKSPACE, { recursive: true });
  // The scan is a child of this process with no `env` of its own, so it inherits
  // process.env as it is when the scan starts.
  for (const key of caseEnvKeys) {
    delete process.env[key];
  }
  caseEnvKeys = Object.keys(e2e.env ?? {});
  for (const [key, value] of Object.entries(e2e.env ?? {})) {
    process.env[key] = value;
  }
  // User settings: ash.extraArguments is machine-scoped, so VS Code refuses to
  // write it to the workspace's .vscode/settings.json.
  await setSetting(
    'extraArguments',
    ['--scanners', e2e.scanners.join(','), ...(e2e.args ?? [])],
    vscode.ConfigurationTarget.Global,
  );
  return realExpected(e2e);
}

/**
 * Real mode: the shared verdict over the output the extension's scan wrote. A
 * no-op in stub mode, whose replayed scans write no aggregated results.
 */
function assertContract(outcome: Outcome, report: ScanReport, findings?: number): void {
  if (MODE !== 'real') {
    return;
  }
  const verdict = spawnSync(
    PYTHON,
    [
      ASSERT_OUTCOME,
      '--case',
      outcome,
      '--cases',
      CASES_FILE,
      '--output-dir',
      OUTPUT_DIR,
      '--rc',
      String(report.exitCode),
      // assert_outcome counts actionable results only, so a suppression lowers it.
      ...(findings === undefined ? [] : ['--findings', String(findings)]),
    ],
    { encoding: 'utf8' },
  );
  assert.strictEqual(
    verdict.status,
    0,
    `assert_outcome rejected the ${outcome} scan:\n${verdict.stdout}${verdict.stderr}${verdict.error?.message ?? ''}`,
  );
}

/** Removes everything a previous scan wrote, leaving the workspace's sources. */
function clearOutput(): void {
  fs.rmSync(OUTPUT_DIR, { recursive: true, force: true });
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

/** Every ASH diagnostic in the window, on any file. */
function allAshDiagnostics(): number {
  return vscode.languages
    .getDiagnostics()
    .reduce(
      (total, [, diagnostics]) =>
        total + diagnostics.filter((diagnostic) => (diagnostic.source ?? '').startsWith('ASH')).length,
      0,
    );
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
    assert.ok(!fs.existsSync(path.join(ASHX_DIR, CLI_NAME)), `the suite must start with no ${CLI_NAME}`);
    if (EXTENSIONS_DIR !== '') {
      // The installed .vsix, and not some other copy, has to be what answers.
      const extension = vscode.extensions.getExtension(EXTENSION_ID);
      assert.ok(extension !== undefined, `${EXTENSION_ID} is not loaded`);
      assert.strictEqual((extension.packageJSON as { version?: string }).version, EXPECT_VERSION);
      const root = path.resolve(EXTENSIONS_DIR) + path.sep;
      assert.ok(
        path.resolve(extension.extensionPath).startsWith(root),
        `${EXTENSION_ID} was loaded from ${extension.extensionPath}, not from ${root}`,
      );
    }
  });

  setup(() => resetCalls());

  test('runs ash when ashx is not installed, and shows the notice only once', async () => {
    const expected = await arrange('findings');

    const first = await scan();

    assert.strictEqual(first.executable, 'ash');
    assert.strictEqual(first.fallbackNotice, 'shown');
    assert.strictEqual(first.status, 'ok', first.detail);
    assertContract('findings', first);
    if (MODE === 'stub') {
      // ashx probed and missing, then ash probed and scanned.
      assert.deepStrictEqual(invokedAs(), ['ash', 'ash']);
    }

    // The verdict below reads the output directory, so the first scan's output
    // goes first: a second scan that wrote nothing must not be judged on it.
    clearOutput();
    const second = await scan();
    assertContract('findings', second);
    assert.strictEqual(second.status, 'ok', second.detail);
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
    assertContract('findings', report);
    const rules = FINDINGS_RULES[MODE];
    const diagnostics = ashDiagnostics(SECRET_FILE);
    assert.strictEqual(diagnostics.length, expected.diagnostics);
    assert.strictEqual(allAshDiagnostics(), expected.diagnostics, 'findings landed on other files');
    assert.deepStrictEqual(
      diagnostics.map((diagnostic) => String(diagnostic.code)).sort(),
      rules.codes,
    );
    for (const diagnostic of diagnostics) {
      assert.strictEqual(diagnostic.range.start.line, rules.line);
      assert.strictEqual(diagnostic.severity, vscode.DiagnosticSeverity.Error);
      assert.strictEqual(diagnostic.source, 'ASH (detect-secrets)');
    }
  });

  test('leaves out a finding suppressed in .ash.yaml and counts it as suppressed', async () => {
    const expected = await arrange('findings');
    let suppressed: Expected = expected;
    if (MODE === 'real') {
      // The shared case carries no suppressions, so this one adds a single rule
      // to it: of the three detect-secrets reports on leak.py, two stay actionable.
      fs.mkdirSync(path.join(WORKSPACE, '.ash'), { recursive: true });
      fs.writeFileSync(
        path.join(WORKSPACE, '.ash', '.ash.yaml'),
        [
          'project_name: vscode-integration',
          'global_settings:',
          '  suppressions:',
          '    - rule_id: "SECRET-SECRET-KEYWORD"',
          '      path: leak.py',
          '      reason: integration fixture',
          '',
        ].join('\n'),
      );
      suppressed = { ...expected, diagnostics: expected.diagnostics - 1, suppressed: 1 };
    }

    const report = await scan();

    assert.strictEqual(report.status, 'ok', report.detail);
    assert.strictEqual(report.exitCode, suppressed.exitCode);
    assertContract('findings', report, suppressed.diagnostics);
    assert.strictEqual(report.summary?.suppressed, suppressed.suppressed);
    const diagnostics = ashDiagnostics(SECRET_FILE);
    assert.strictEqual(diagnostics.length, suppressed.diagnostics);
    assert.strictEqual(allAshDiagnostics(), suppressed.diagnostics, 'findings landed on other files');
    // Both modes suppress SECRET-SECRET-KEYWORD and keep the other two.
    assert.deepStrictEqual(
      diagnostics.map((diagnostic) => String(diagnostic.code)).sort(),
      ['SECRET-AWS-ACCESS-KEY', 'SECRET-BASE64-HIGH-ENTROPY-STRING'],
    );
  });

  // The extension passes the workspace folder as --source-dir and sets no working
  // directory (see CommandOptions in src/ash-cli.ts), so ASH has to find the
  // config from --source-dir alone. The two newer config sources are discovered
  // at the scan root only, so each gets the same suppression as the .ash.yaml
  // test above, and the same outcome is required of it.
  const NEWER_CONFIG_SOURCES: ReadonlyArray<{ readonly name: string; readonly body: string }> = [
    {
      name: 'pyproject.toml',
      body: [
        '[project]',
        'name = "vscode-integration"',
        '',
        '[tool.ash]',
        'project_name = "vscode-integration"',
        '',
        '[[tool.ash.global_settings.suppressions]]',
        'rule_id = "SECRET-SECRET-KEYWORD"',
        'path = "leak.py"',
        'reason = "integration fixture"',
        '',
      ].join('\n'),
    },
    {
      name: '.ashrc.yaml',
      body: [
        'project_name: vscode-integration',
        'global_settings:',
        '  suppressions:',
        '    - rule_id: "SECRET-SECRET-KEYWORD"',
        '      path: leak.py',
        '      reason: integration fixture',
        '',
      ].join('\n'),
    },
  ];

  for (const source of NEWER_CONFIG_SOURCES) {
    test(`leaves out a finding suppressed in ${source.name} at the workspace root`, async () => {
      const expected = await arrange('findings');
      let suppressed: Expected = expected;
      if (MODE === 'real') {
        fs.writeFileSync(path.join(WORKSPACE, source.name), source.body);
        suppressed = { ...expected, diagnostics: expected.diagnostics - 1, suppressed: 1 };
      }

      const report = await scan();

      assert.strictEqual(report.status, 'ok', report.detail);
      assert.strictEqual(report.exitCode, suppressed.exitCode);
      assertContract('findings', report, suppressed.diagnostics);
      assert.strictEqual(report.summary?.suppressed, suppressed.suppressed);
      const diagnostics = ashDiagnostics(SECRET_FILE);
      assert.deepStrictEqual(
        diagnostics.map((diagnostic) => String(diagnostic.code)).sort(),
        ['SECRET-AWS-ACCESS-KEY', 'SECRET-BASE64-HIGH-ENTROPY-STRING'],
      );
    });
  }

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
    assertContract('incomplete', report);
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
    assertContract('clean', report);
    assert.strictEqual(ashDiagnostics(SECRET_FILE).length, 0);
    assert.strictEqual(allAshDiagnostics(), 0);
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
    } else {
      // A genuine scan of the fixture can finish inside 2s, so real mode runs the
      // installed ASH behind a wrapper that sleeps first (see run.ts).
      await setSetting(
        'executablePath',
        process.env.ASH_IT_SLOW_EXECUTABLE,
        vscode.ConfigurationTarget.Global,
      );
    }
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
      if (MODE !== 'stub') {
        await setSetting('executablePath', undefined, vscode.ConfigurationTarget.Global);
      }
    }
  });

  test('runs ashx once it is installed', async () => {
    const ashx = path.join(ASHX_DIR, CLI_NAME);
    if (MODE === 'stub') {
      fs.writeFileSync(ashx, process.env.ASH_IT_ASHX_WRAPPER ?? '', { mode: 0o755 });
    } else {
      // The installed v4 entry point itself, not the legacy one under a new name.
      fs.symlinkSync(path.join(REAL_ASH_DIR, CLI_NAME), ashx);
    }
    const expected = await arrange('findings');

    const report = await scan();

    assert.strictEqual(report.executable, CLI_NAME);
    assert.strictEqual(report.fallbackNotice, undefined);
    assert.strictEqual(report.exitCode, expected.exitCode);
    assertContract('findings', report);
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
