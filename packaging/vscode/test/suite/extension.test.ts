// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Behavioral assertions against a real VS Code, not a mock.
 *
 * Everything here runs inside the extension host, so `vscode.languages
 * .getDiagnostics` returns what the editor would actually draw. That is the
 * point: a unit test over `toDiagnostic` proves the mapping function, and proves
 * nothing about whether the command is reachable, whether activation happened,
 * or whether the collection was ever published into.
 *
 * THE STUB CLI
 *
 * The happy path needs an `ash` that produces a known report. Installing the
 * real one would make the assertion depend on what a dozen third-party scanners
 * find in a fixture, which is neither stable nor the thing under test. So a
 * three-line shell script stands in: it parses `--output-dir` out of its own
 * argv exactly as the real CLI would, copies the fixture SARIF to
 * `<output-dir>/reports/ash.sarif`, and exits with a code the caller chooses.
 *
 * THE DEFAULT IS 2, not 1, and the distinction is the point. ASH exits 2 for
 * "actionable findings above threshold" and 1 for "error during execution" -- see
 * SUCCESS_EXIT_CODES in src/ash.ts. This stub defaulted to 1 to model a scan with
 * findings, which encoded the same wrong belief as the code it was testing, so no
 * assertion here could have caught it. The happy-path suite now asserts a successful
 * outcome from exit 2, and a separate suite asserts that exit 1 is refused.
 */

import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';

import { failedInvocations, parseScannerStatus } from '../../src/completeness';
import {
  LEVEL_TO_SEVERITY,
  resolveAbsolute,
  resolveFindingUri,
  toDiagnostic,
} from '../../src/diagnostics';
import {
  isFailure,
  isSuppressed,
  normalizeLevel,
  parseSarif,
  SarifParseError,
  unaggregatedToolName,
} from '../../src/sarif';
import {
  DEFAULT_OUTPUT_DIRECTORY,
  resolveOutputDirectory,
  SCAN_COMMAND,
  type ScanOutcome,
} from '../../src/extension';

const EXTENSION_ID = 'awslabs.automated-security-helper';

function requireEnv(name: string): string {
  const value = process.env[name];
  assert.ok(
    value !== undefined && value.length > 0,
    `${name} was not passed into the extension host by runTest.ts`,
  );
  return value;
}

const workspace = requireEnv('ASH_TEST_WORKSPACE');
const scratch = requireEnv('ASH_TEST_SCRATCH');
const sarifFixture = requireEnv('ASH_TEST_SARIF_FIXTURE');

/**
 * Writes an executable stand-in for the ash CLI and returns its path.
 *
 * `name` keeps the stubs for different fixtures apart, and `sarifPath` is the
 * report the stub will produce -- which is what lets one suite assert the normal
 * case and another assert a report whose results have no locations.
 */
/**
 * `null` and not `undefined` for "write no report", and that is load-bearing.
 *
 * A default parameter is selected when the argument is `undefined`, INCLUDING when
 * `undefined` is passed explicitly. So `installStubAsh('no-report', undefined, 1)`
 * quietly produced a stub that wrote the fixture, and two tests asserting on a
 * missing report were really asserting on a present one -- they failed, but for a
 * reason that had nothing to do with what they claimed to check. `null` does not
 * trigger a default.
 */
function installStubAsh(
  name = 'ash',
  sarifPath: string | null = sarifFixture,
  exitCode = 2,
  rosterPath: string | null = null,
): string {
  const binDir = path.join(scratch, `stub-bin-${name}`);
  fs.mkdirSync(binDir, { recursive: true });
  const stub = path.join(binDir, 'ash');
  // The fixture path is embedded rather than read from the environment: the
  // child's env comes from whatever the extension host inherited, and a test
  // that silently loses a variable would fall back to copying nothing and then
  // fail with a confusing "no SARIF report" instead of naming the real cause.
  fs.writeFileSync(
    stub,
    [
      '#!/bin/sh',
      '# Stands in for the ash CLI. Parses --output-dir the way the real one is',
      '# invoked, writes the fixture report, and exits with the code the test chose.',
      '# ASH uses 2 for "actionable findings" and 1 for "error during execution".',
      'set -e',
      'out=""',
      'while [ $# -gt 0 ]; do',
      '  case "$1" in',
      '    --output-dir) out="$2"; shift 2 ;;',
      '    *) shift ;;',
      '  esac',
      'done',
      'if [ -z "$out" ]; then',
      '  echo "stub ash: no --output-dir in argv" >&2',
      '  exit 64',
      'fi',
      'mkdir -p "$out/reports"',
      // `sarifPath` null models ASH dying before its reporter stage: the process
      // exits without writing a report at all.
      ...(sarifPath === null
        ? ['echo "stub ash: deliberately writing no report" >&2']
        : [
            `cp ${JSON.stringify(sarifPath)} "$out/reports/ash.sarif"`,
            'echo "stub ash: wrote $out/reports/ash.sarif"',
          ]),
      // EXIT 2, not 1, and the default matters. ASH exits 2 for "actionable
      // findings above threshold" and 1 for "error during execution" -- see
      // SUCCESS_EXIT_CODES in src/ash.ts. This stub used to exit 1 to model a
      // scan with findings, which encoded the same wrong belief as the code it was
      // testing, so no assertion here could have caught it.
      // The aggregated report, which is where the scanner roster lives. Written
      // beside the reports/ directory, as ASH does.
      ...(rosterPath === null
        ? []
        : [`cp ${JSON.stringify(rosterPath)} "$out/ash_aggregated_results.json"`]),
      `exit ${exitCode}`,
      '',
    ].join('\n'),
    { mode: 0o755 },
  );
  return stub;
}

/**
 * Records the warnings the extension raises, for the duration of one suite.
 *
 * Nothing in the extension API lets a test observe a notification, so the API is
 * replaced. That is the only way to assert the thing this suite exists to
 * assert: that a scan which discards findings SAYS SO. Asserting on the returned
 * outcome is not enough -- the outcome already carried `skipped` and
 * `unresolved` while the user was told nothing, which is precisely the defect.
 */
function captureWarnings(): {
  messages: string[];
  restore: () => void;
} {
  const messages: string[] = [];
  const surface = vscode.window as unknown as Record<string, unknown>;
  const original = surface['showWarningMessage'];
  surface['showWarningMessage'] = (message: string): Thenable<undefined> => {
    messages.push(message);
    return Promise.resolve(undefined);
  };
  return {
    messages,
    restore: () => {
      surface['showWarningMessage'] = original;
    },
  };
}

function fixtureUri(relative: string): vscode.Uri {
  return vscode.Uri.file(path.join(workspace, relative));
}

/** Diagnostics for a fixture file, ordered by line so assertions are stable. */
function diagnosticsFor(relative: string): vscode.Diagnostic[] {
  return [...vscode.languages.getDiagnostics(fixtureUri(relative))].sort(
    (a, b) => a.range.start.line - b.range.start.line,
  );
}

/**
 * `ConfigurationTarget.Global`, not Workspace, and that is load-bearing.
 *
 * `ash.executablePath` is declared `"scope": "machine"` precisely so a cloned
 * repository cannot name the program this extension executes from its own
 * `.vscode/settings.json`. VS Code enforces that by refusing the write, so a test
 * that sets it at Workspace level would silently configure nothing and then
 * assert against a stub that was never used.
 */
async function setExecutablePath(value: string | undefined): Promise<void> {
  await vscode.workspace
    .getConfiguration('ash')
    .update('executablePath', value, vscode.ConfigurationTarget.Global);
}

suite('ASH extension', () => {
  suiteSetup(async () => {
    // The window was opened on the fixture copy. If that is not what the
    // extension will scan, every assertion below is about the wrong directory.
    const folders = vscode.workspace.workspaceFolders ?? [];
    assert.strictEqual(
      folders.length,
      1,
      'expected exactly one workspace folder from launchArgs',
    );
    assert.strictEqual(folders[0].uri.fsPath, workspace);
  });

  test('activates', async () => {
    const extension = vscode.extensions.getExtension(EXTENSION_ID);
    assert.ok(extension !== undefined, `${EXTENSION_ID} was not found`);
    await extension.activate();
    assert.strictEqual(extension.isActive, true);
  });

  test('registers the scan command', async () => {
    const extension = vscode.extensions.getExtension(EXTENSION_ID);
    assert.ok(extension !== undefined);
    await extension.activate();

    const commands = await vscode.commands.getCommands(true);
    assert.ok(
      commands.includes(SCAN_COMMAND),
      `${SCAN_COMMAND} is not registered. Registered ash commands: ${commands
        .filter((c) => c.startsWith('ash.'))
        .join(', ')}`,
    );
  });

  // Runs before the happy path on purpose: it asserts the failure arm against a
  // window that has never had a successful scan, so a passing result cannot be
  // an artifact of state left behind by one.
  suite('when ash is not on PATH', () => {
    let savedPath: string | undefined;

    setup(async () => {
      savedPath = process.env['PATH'];
      // An empty directory rather than an unset PATH: unsetting it makes some
      // libc implementations fall back to a built-in default that could contain
      // a real ash, which would make this test's premise false without saying so.
      const emptyDir = path.join(scratch, 'empty-path');
      fs.mkdirSync(emptyDir, { recursive: true });
      process.env['PATH'] = emptyDir;
      await setExecutablePath(undefined);
    });

    teardown(async () => {
      if (savedPath !== undefined) {
        process.env['PATH'] = savedPath;
      }
    });

    test('surfaces the failure instead of silently doing nothing', async () => {
      const outcome = await vscode.commands.executeCommand<ScanOutcome>(
        SCAN_COMMAND,
      );

      assert.ok(outcome !== undefined, 'the command returned nothing at all');
      assert.strictEqual(outcome.ok, false, 'a missing ash must not report success');
      assert.strictEqual(outcome.reason, 'ash-not-found');
      assert.match(
        outcome.message ?? '',
        /ash/,
        'the surfaced message must name the executable it could not run',
      );
      assert.match(
        outcome.message ?? '',
        /ash\.executablePath|Install ASH/,
        'the message must tell the user what to do about it',
      );
      // Nothing was published, so nothing may be reported as published.
      assert.strictEqual(outcome.diagnosticCount, undefined);
    });
  });

  suite('with a scan that produces a report', () => {
    let outcome: ScanOutcome;
    let warnings: string[];
    let restore: () => void;

    suiteSetup(async () => {
      const stub = installStubAsh();
      await setExecutablePath(stub);

      const captured = captureWarnings();
      warnings = captured.messages;
      restore = captured.restore;

      const result = await vscode.commands.executeCommand<ScanOutcome>(
        SCAN_COMMAND,
      );
      assert.ok(result !== undefined, 'the command returned nothing at all');
      outcome = result;
    });

    suiteTeardown(async () => {
      restore();
      await setExecutablePath(undefined);
    });

    test('treats exit 2 as a successful scan with findings', () => {
      assert.strictEqual(
        outcome.ok,
        true,
        `scan failed: ${outcome.reason} ${outcome.message}`,
      );
      // 2 is ACTIONABLE_FINDINGS. With `fail_on_findings` defaulting true it is
      // the ordinary result of any scan that finds something, so rejecting it
      // would break the common case.
      assert.strictEqual(outcome.exitCode, 2);
    });

    test('publishes every locatable finding and counts the rest', () => {
      assert.strictEqual(outcome.diagnosticCount, 5);
      assert.strictEqual(outcome.fileCount, 2);
      // The fixture carries one result with no physical location.
      assert.strictEqual(outcome.skipped, 1);
      assert.strictEqual(outcome.unresolved, 0);
    });

    test('maps SARIF levels to severities on the right lines', () => {
      const appPy = diagnosticsFor('src/app.py');
      assert.strictEqual(
        appPy.length,
        3,
        `expected 3 diagnostics in src/app.py, got ${appPy.length}`,
      );

      // SARIF states lines 1-based; the editor counts from 0. These are the
      // fixture's 23, 28 and 33.
      assert.deepStrictEqual(
        appPy.map((d) => d.range.start.line),
        [22, 27, 32],
      );
      assert.deepStrictEqual(
        appPy.map((d) => d.severity),
        [
          vscode.DiagnosticSeverity.Error,
          vscode.DiagnosticSeverity.Warning,
          vscode.DiagnosticSeverity.Information,
        ],
      );
      assert.deepStrictEqual(
        appPy.map((d) => d.code),
        ['B602', 'B105', 'B108'],
      );

      // startColumn 12 on the first finding, 1-based, is column 11.
      assert.strictEqual(appPy[0].range.start.character, 11);
      assert.strictEqual(appPy[0].range.end.character, 75);
    });

    test('attributes findings to the file they name', () => {
      const infraPy = diagnosticsFor('src/infra.py');
      assert.strictEqual(infraPy.length, 2);
      assert.deepStrictEqual(
        infraPy.map((d) => d.range.start.line),
        [9, 11],
      );
      assert.deepStrictEqual(
        infraPy.map((d) => d.severity),
        [
          // `none` means the rule did not fire as a problem.
          vscode.DiagnosticSeverity.Hint,
          // `Level.error` -- coerced to the severity it plainly means rather
          // than downgraded to the default.
          vscode.DiagnosticSeverity.Error,
        ],
      );
    });

    // This suite's stub writes no roster (installStubAsh defaults rosterPath to
    // null), so completeness is genuinely unknown here -- as it was in three suites
    // while nothing asserted it and no notification was raised.
    test('reports unknown completeness as unknown, and says so to the user', () => {
      assert.strictEqual(outcome.completenessUnknown, true);
      assert.strictEqual(outcome.scannersTotal, undefined);
      const warning = warnings.find((m) => m.includes('could not confirm'));
      assert.ok(
        warning !== undefined,
        'a scan whose completeness cannot be determined must say so, not stay ' +
          `silent. Warnings: ${JSON.stringify(warnings)}`,
      );
      assert.match(warning, /unknown/);
    });

    test('reports the nonconforming level spelling rather than hiding it', () => {
      assert.deepStrictEqual(outcome.nonconformingLevels, ['Level.error']);
      assert.ok(
        warnings.some((m) => m.includes('Level.error')),
        `no warning named the nonconforming spelling. Warnings: ${JSON.stringify(warnings)}`,
      );
    });

    // Asserted on the REAL fixture, not only on the all-locationless one. A
    // mostly-good report with one unshowable result is the common case, and it is
    // the case where a shortfall is easiest to miss: four findings appear, the
    // panel looks populated, and nothing says the picture is incomplete.
    test('warns that one result could not be shown, even on a good report', () => {
      assert.strictEqual(outcome.skipped, 1);
      const shortfall = warnings.find((m) => m.includes('no source location'));
      assert.ok(
        shortfall !== undefined,
        'the fixture carries one result with no physical location and nothing ' +
          `warned about it. Warnings: ${JSON.stringify(warnings)}`,
      );
      assert.match(shortfall, /1 result\(s\)/);
    });

    // This fixture's results carry NO `properties.scanner_name`, so they exercise
    // the run-level fallback -- the real report populates scanner_name on all 126
    // results and never reaches it. Deliberate, and stated here so nobody "fixes"
    // the fixture by adding the field and silently retires that coverage.
    //
    // The source is a BARE `ASH`, not `ASH (automated-security-helper)`. This
    // fixture's driver.name is itself an aggregate spelling, so it names the product
    // rather than a scanner and is rejected. That it previously read as a plausible
    // scanner name is exactly why this fixture could not reveal the product-name
    // defect.
    test('renders a bare ASH source when no result names a scanner', () => {
      const [first] = diagnosticsFor('src/app.py');
      assert.strictEqual(first.source, 'ASH');
    });
  });

  // Table-level assertions. Cheap, and they pin the two conversions that the
  // integration assertions above can only observe through five sample points.
  suite('level mapping', () => {
    test('maps each SARIF level to the intended severity', () => {
      assert.strictEqual(
        LEVEL_TO_SEVERITY.error,
        vscode.DiagnosticSeverity.Error,
      );
      assert.strictEqual(
        LEVEL_TO_SEVERITY.warning,
        vscode.DiagnosticSeverity.Warning,
      );
      assert.strictEqual(
        LEVEL_TO_SEVERITY.note,
        vscode.DiagnosticSeverity.Information,
      );
      assert.strictEqual(LEVEL_TO_SEVERITY.none, vscode.DiagnosticSeverity.Hint);
    });

    test('spells levels as SARIF values, not as enum member names', () => {
      // The defect this guards: `str()` on a Python (str, Enum) member yields
      // "Level.error". A consumer keyed on the member name would accept that and
      // reject the spec spelling, which is the inverse of what SARIF requires.
      assert.deepStrictEqual(normalizeLevel('error'), { level: 'error' });
      assert.strictEqual(normalizeLevel('Level.error').level, 'error');
      assert.strictEqual(
        normalizeLevel('Level.error').nonconforming,
        'Level.error',
        'the nonconforming spelling must be reported, not quietly accepted',
      );
    });

    test('defaults an absent level to error without reporting it', () => {
      // Omitting `level` is legal, so it is not a nonconforming spelling. The
      // default is `error` to match what ASH's own schema model declares for
      // Result.level -- defaulting lower would shade every level-less result one
      // band below what ASH itself would call it. See DEFAULT_LEVEL in sarif.ts
      // for why this is recorded as a decision and not as a spec citation.
      assert.deepStrictEqual(normalizeLevel(undefined), { level: 'error' });
      assert.deepStrictEqual(normalizeLevel(null), { level: 'error' });
    });

    test('does not read a level out of an unrelated string', () => {
      // `rule.note` and NOT `rule.error`, and the choice is load-bearing. The
      // default is now `error`, so an unrelated string ending in `error` returns
      // `error` whether it was wrongly coerced from the string or correctly fell
      // back to the default -- the two paths become indistinguishable and the
      // assertion cannot fail. Picking a level that differs from the default
      // restores the discriminator.
      const unrelated = normalizeLevel('rule.note');
      assert.strictEqual(
        unrelated.level,
        'error',
        'only a `level.` stem may be coerced; any other dotted string is unknown ' +
          'and must take the default rather than the level it happens to contain',
      );
      assert.strictEqual(unrelated.nonconforming, 'rule.note');

      // The positive control for the same pair: a real `level.` stem IS coerced,
      // so this must NOT come back as the default.
      assert.strictEqual(normalizeLevel('Level.note').level, 'note');
    });

    // The three dispositions are decisions, not derivations, so they are pinned
    // here rather than left to a comment. `underReview` and `rejected` are
    // unexercised by the real report -- all 92 of its suppressions carry a null
    // state -- which is precisely why they need a test: nothing else would notice
    // if they flipped.
    test('honors suppression state, erring toward showing when undecided', () => {
      const withState = (state: unknown): Record<string, unknown> => ({
        suppressions: [{ kind: 'external', ...(state === 'omit' ? {} : { state }) }],
      });

      // Recorded suppression, state not filled in -- both spellings.
      assert.strictEqual(isSuppressed(withState('omit')), true, 'key absent');
      assert.strictEqual(isSuppressed(withState(null)), true, 'key present, null');
      assert.strictEqual(isSuppressed(withState('accepted')), true);

      // A suppression nobody has agreed to must not hide a finding.
      assert.strictEqual(isSuppressed(withState('underReview')), false);
      assert.strictEqual(isSuppressed(withState('rejected')), false);

      // No suppressions at all.
      assert.strictEqual(isSuppressed({}), false);
      assert.strictEqual(isSuppressed({ suppressions: [] }), false);
    });

    test('treats an unreadable state the same at every nesting depth', () => {
      // A FIFTH case the four dispositions did not cover, and it was inconsistent:
      // a bare non-record entry suppressed, while a record with a non-string state
      // fell through the string comparison and was SHOWN. The same nonsense meant
      // opposite things depending on depth, and one of them was the unsafe answer.
      assert.strictEqual(isSuppressed({ suppressions: [12345] }), true);
      assert.strictEqual(
        isSuppressed({ suppressions: [{ kind: 'external', state: 12345 }] }),
        true,
        'an unreadable state must not silently re-display a suppressed finding',
      );
      assert.strictEqual(
        isSuppressed({ suppressions: [{ state: { nested: true } }] }),
        true,
      );
    });

    test('reads a kind other than fail as not a problem', () => {
      assert.strictEqual(isFailure({}), true, 'absent kind defaults to fail');
      assert.strictEqual(isFailure({ kind: 'fail' }), true);
      for (const kind of [
        'informational',
        'pass',
        'notApplicable',
        'review',
        'open',
      ]) {
        assert.strictEqual(isFailure({ kind }), false, kind);
      }
    });

    test('refuses a document that is not SARIF', () => {
      assert.throws(() => parseSarif('{"not": "sarif"}'), SarifParseError);
      assert.throws(() => parseSarif('this is not json'), SarifParseError);
    });
  });

  // THE FALSE-CLEAN. A reporter regression that drops `physicalLocation` from
  // every result leaves nothing to publish, and the first version of this
  // extension reported that as a successful scan with no warning of any kind --
  // indistinguishable from a workspace with no findings. The counts were in the
  // returned outcome and in nothing a user reads.
  suite('when no result carries a location', () => {
    let outcome: ScanOutcome;
    let warnings: string[];
    let restore: () => void;

    suiteSetup(async () => {
      const locationless = path.join(scratch, 'locationless.sarif');
      fs.writeFileSync(
        locationless,
        JSON.stringify({
          version: '2.1.0',
          runs: [
            {
              tool: { driver: { name: 'automated-security-helper' } },
              results: [
                { ruleId: 'B602', level: 'error', message: { text: 'no location' } },
                { ruleId: 'B105', level: 'warning', message: { text: 'no location' } },
                { ruleId: 'B108', level: 'note', message: { text: 'no location' } },
              ],
            },
          ],
        }),
      );

      const stub = installStubAsh('locationless', locationless);
      await setExecutablePath(stub);

      const captured = captureWarnings();
      warnings = captured.messages;
      restore = captured.restore;

      const result = await vscode.commands.executeCommand<ScanOutcome>(
        SCAN_COMMAND,
      );
      assert.ok(result !== undefined);
      outcome = result;
    });

    suiteTeardown(async () => {
      restore();
      await setExecutablePath(undefined);
    });

    test('publishes nothing and counts every result as skipped', () => {
      assert.strictEqual(outcome.ok, true);
      assert.strictEqual(outcome.diagnosticCount, 0);
      assert.strictEqual(outcome.fileCount, 0);
      assert.strictEqual(outcome.skipped, 3);
    });

    test('SURFACES the shortfall rather than reading as a clean scan', () => {
      // The assertion the extension previously could not pass. Without it, the
      // three assertions above are all satisfied by the defective behavior too.
      const shortfall = warnings.find((m) => m.includes('no source location'));
      assert.ok(
        shortfall !== undefined,
        'no warning mentioned the skipped results. A scan that discarded every ' +
          'finding must not look like a clean workspace. Warnings seen: ' +
          JSON.stringify(warnings),
      );
      assert.match(shortfall, /3 result\(s\)/);
      assert.match(
        shortfall,
        /NOT in the Problems panel|not a complete picture/,
        'the warning must say the Problems panel is incomplete, which is the ' +
          'thing a user would otherwise wrongly trust',
      );
    });

    test('clears diagnostics from the previous scan', () => {
      // A scan's results are the complete current state, so the earlier
      // findings must be gone rather than lingering beside an empty report.
      assert.strictEqual(diagnosticsFor('src/app.py').length, 0);
      assert.strictEqual(diagnosticsFor('src/infra.py').length, 0);
    });
  });

  // AGAINST THE REAL ARTIFACT, not the hand-written fixture.
  //
  // 126 results from seven scanners in ONE run, with a `tool.driver.name` of
  // "AWS Labs - Automated Security Helper". This suite is what caught reading the
  // scanner from the run instead of from each result: against the fixture that
  // looked right, because the fixture has one tool and a scanner-ish driver name.
  suite('against real ASH output', () => {
    let outcome: ScanOutcome;
    let parsed: ReturnType<typeof parseSarif>;

    suiteSetup(async () => {
      const realReport = requireEnv('ASH_TEST_REAL_REPORT');
      // The aggregated results file wraps the log under a `sarif` key; what ASH
      // writes to reports/ash.sarif -- and therefore what this extension reads --
      // is that value on its own.
      const aggregated = JSON.parse(fs.readFileSync(realReport, 'utf8')) as {
        sarif?: unknown;
      };
      assert.ok(
        aggregated.sarif !== undefined,
        `${realReport} has no \`sarif\` key, so the shape this suite assumes is wrong`,
      );

      const bare = path.join(scratch, 'real-ash.sarif');
      fs.writeFileSync(bare, JSON.stringify(aggregated.sarif));
      parsed = parseSarif(fs.readFileSync(bare, 'utf8'));

      const stub = installStubAsh('real', bare);
      await setExecutablePath(stub);
      const result = await vscode.commands.executeCommand<ScanOutcome>(
        SCAN_COMMAND,
      );
      assert.ok(result !== undefined);
      outcome = result;
    });

    suiteTeardown(async () => {
      await setExecutablePath(undefined);
    });

    // BOTH numbers, labeled, because the relationship between them is the thing
    // worth pinning. An earlier version asserted only `findings.length === 126`,
    // which was the total result count -- so the test GUARDED the defect of
    // re-displaying every suppressed finding.
    test('accounts for all 126 results and surfaces only the 34 live ones', () => {
      assert.strictEqual(outcome.ok, true);
      assert.strictEqual(parsed.findings.length, 34, 'surfaced findings');
      assert.strictEqual(parsed.suppressed, 92, 'suppressed by ASH');
      assert.strictEqual(parsed.notFailures, 0, 'kind not fail and not suppressed');
      assert.strictEqual(parsed.skipped, 0, 'no physical location');
      // The arithmetic must close over the report: every result is in exactly one
      // bucket, so a result silently vanishing would break this even if each
      // individual count still looked plausible.
      assert.strictEqual(
        parsed.findings.length +
          parsed.suppressed +
          parsed.notFailures +
          parsed.skipped,
        126,
        'every result must be surfaced or counted in exactly one bucket',
      );
    });

    test('drops 7 suppressed results a level-based filter would have shown', () => {
      // Counts the population a level-based filter would have kept, from the raw
      // document, and asserts the difference against what suppression actually
      // removed. The previous version asserted `suppressed - 85 === 7`, which is
      // arithmetically `suppressed === 92` -- already asserted above -- and so
      // measured nothing new even though it discriminated.
      const raw = JSON.parse(
        fs.readFileSync(requireEnv('ASH_TEST_REAL_REPORT'), 'utf8'),
      ) as { sarif: { runs: { results: Record<string, unknown>[] }[] } };
      const results = raw.sarif.runs[0].results;
      const informationalNone = results.filter(
        (r) => r['kind'] === 'informational' && r['level'] === 'none',
      ).length;

      assert.strictEqual(informationalNone, 85, 'what a level-based filter catches');
      assert.strictEqual(parsed.suppressed, 92, 'what suppression catches');
      assert.strictEqual(
        parsed.suppressed - informationalNone,
        7,
        'the 7 suppressed results carrying kind=fail and a real level',
      );
    });

    test('records a nonconforming level even on a suppressed result', () => {
      // The producer-bug detector must not be scoped to publishable results. It was:
      // normalizeLevel ran after the suppression/kind/location filters, so on this
      // report it saw 34 of 126 and a `Level.error` spelling on any of the 92
      // suppressed ones was invisible.
      const suppressedOnly = parseSarif(
        JSON.stringify({
          version: '2.1.0',
          runs: [
            {
              tool: { driver: { name: 'AWS Labs - Automated Security Helper' } },
              results: [
                {
                  ruleId: 'X1',
                  kind: 'fail',
                  level: 'Level.error',
                  suppressions: [{ kind: 'external' }],
                  message: { text: 'suppressed AND misspelled' },
                  locations: [
                    {
                      physicalLocation: {
                        artifactLocation: { uri: 'a.py' },
                        region: { startLine: 1 },
                      },
                    },
                  ],
                },
              ],
            },
          ],
        }),
      );
      assert.strictEqual(suppressedOnly.findings.length, 0, 'nothing publishable');
      assert.strictEqual(suppressedOnly.suppressed, 1);
      assert.deepStrictEqual(
        suppressedOnly.nonconformingLevels,
        ['Level.error'],
        'a producer defect on a suppressed result is still a producer defect',
      );
    });

    test('attributes each finding to the scanner that raised it', () => {
      const scanners = new Set(parsed.findings.map((f) => f.toolName));
      // FIVE, not the seven in the report: cdk-nag's 4 findings and cfn-nag's 3
      // are all suppressed, so neither scanner has anything left to surface. That
      // is the correct outcome and it is why this list differs from the
      // extensions[] list in the report's tool block.
      assert.deepStrictEqual(
        [...scanners].sort(),
        ['bandit', 'checkov', 'detect-secrets', 'grype', 'semgrep'],
        'expected one scanner per result rather than one per run',
      );
    });

    test('never labels a finding with the product name', () => {
      // The exact string `tool.driver.name` carries. Reading it per run put this
      // on all 126 findings, so no diagnostic could be traced to its scanner.
      const product = 'AWS Labs - Automated Security Helper';
      assert.strictEqual(
        parsed.findings.filter((f) => f.toolName === product).length,
        0,
        `${product} is the product, not a scanner. It must never reach a diagnostic source.`,
      );
    });

    test('matches the per-scanner counts in the report', () => {
      const counts = new Map<string, number>();
      for (const finding of parsed.findings) {
        counts.set(finding.toolName, (counts.get(finding.toolName) ?? 0) + 1);
      }
      // Measured from properties.scanner_name in the real report. A count is not a
      // set, so the distinct-scanner assertion above does not imply these.
      assert.deepStrictEqual(Object.fromEntries([...counts].sort()), {
        bandit: 11,
        checkov: 4,
        'detect-secrets': 11,
        grype: 1,
        semgrep: 7,
      });
    });

    test('surfaces no suppressed level, so none and warning both vanish', () => {
      const levels = new Map<string, number>();
      for (const finding of parsed.findings) {
        levels.set(finding.level, (levels.get(finding.level) ?? 0) + 1);
      }
      // The report's own distribution is error 34, warning 5, note 2, none 85.
      // After suppressions: every `none` is gone (all 85 were suppressed), every
      // `warning` is gone (all 5 were suppressed), and 2 of the 34 errors were
      // suppressed inSource. So a level absent here is a fact about this report's
      // suppression config, not a gap in the level mapping -- which the
      // hand-written fixture covers for all four levels.
      assert.deepStrictEqual(Object.fromEntries([...levels].sort()), {
        error: 32,
        note: 2,
      });
      assert.deepStrictEqual(parsed.nonconformingLevels, []);
    });

    test('surfaces one grype finding at a scan-root-absolute path, not fourteen', () => {
      // 14 results carry a leading-slash uri like `/poetry.lock`; 13 of them are
      // suppressed. So the absolute-path defect misplaces exactly ONE finding on
      // this report, not fourteen -- worth pinning because the severity of that
      // bug was initially sized from the wrong number.
      const grype = parsed.findings.filter((f) => f.toolName === 'grype');
      assert.strictEqual(grype.length, 1);
      assert.ok(
        grype[0].uri.startsWith('/'),
        `expected a scan-root-absolute uri, got ${grype[0].uri}`,
      );
    });
  });

  // Exit 1 is "error during execution" -- a crash, or scanners that failed or were
  // incomplete. Either way the report cannot be trusted as a complete result. Both
  // this extension and its stub previously treated 1 as the findings code, so the
  // suite agreed with the bug.
  suite('when ash exits with an error code', () => {
    suiteTeardown(async () => {
      await setExecutablePath(undefined);
    });

    test('refuses to publish a partial report from exit 1', async () => {
      const stub = installStubAsh('failing', sarifFixture, 1);
      await setExecutablePath(stub);
      const outcome = await vscode.commands.executeCommand<ScanOutcome>(
        SCAN_COMMAND,
      );

      assert.ok(outcome !== undefined);
      assert.strictEqual(
        outcome.ok,
        false,
        'exit 1 is an execution error, not a scan that found things',
      );
      assert.strictEqual(outcome.reason, 'ash-failed');
      assert.strictEqual(outcome.exitCode, 1);
      assert.match(
        outcome.message ?? '',
        /incomplete/,
        'the message must say the report is incomplete rather than just echoing a number',
      );
      // Nothing was published, so nothing may be reported as published.
      assert.strictEqual(outcome.diagnosticCount, undefined);
    });

    test('names a missing report separately from a failing exit', async () => {
      // No report written at all -- ASH dying before its reporter stage. The
      // previous run's report cannot be mistaken for this one's, because it is
      // deleted before the scan starts.
      const stub = installStubAsh('no-report', null, 1);
      await setExecutablePath(stub);
      const outcome = await vscode.commands.executeCommand<ScanOutcome>(
        SCAN_COMMAND,
      );

      assert.ok(outcome !== undefined);
      assert.strictEqual(outcome.ok, false);
      const reportPath = path.join(
        workspace,
        '.ash',
        'ash_output',
        'reports',
        'ash.sarif',
      );
      assert.strictEqual(
        outcome.reason,
        'sarif-missing',
        `a report that was never written is a different situation from a partial ` +
          `one. Got ${outcome.reason}; report present=${fs.existsSync(reportPath)}`,
      );
      // The pre-scan delete is what makes the absence meaningful: without it the
      // previous test's report would still be here and would be read as this
      // run's result.
      assert.strictEqual(
        fs.existsSync(reportPath),
        false,
        'the previous run\'s report must have been removed before this scan',
      );
      assert.match(outcome.message ?? '', /no SARIF report/);
      // The message must carry the code AND its meaning, not the bare number.
      assert.match(outcome.message ?? '', /exited 1 \(error during execution/);
    });

    test('does not read a previous run\'s report as this run\'s result', async () => {
      // THE COMPOSED FAILURE this guard exists for: ASH fails and writes nothing,
      // the previous run's report is still on disk, and reading it would present
      // old findings as the current result.
      //
      // The pre-scan delete normally makes that unreachable, so this test forces
      // the fallback path by making the delete FAIL -- a read-only reports
      // directory -- and then asserts the mtime comparison catches it. Without the
      // fallback, a read-only output directory would silently degrade to no check.
      const reportsDir = path.join(workspace, '.ash', 'ash_output', 'reports');
      fs.mkdirSync(reportsDir, { recursive: true });
      const stalePath = path.join(reportsDir, 'ash.sarif');
      fs.copyFileSync(sarifFixture, stalePath);
      // Backdate it so "not rewritten by this run" is unambiguous even if the
      // filesystem's mtime granularity is coarse.
      const old = new Date(Date.now() - 600_000);
      fs.utimesSync(stalePath, old, old);
      fs.chmodSync(reportsDir, 0o500);

      try {
        const stub = installStubAsh('stale', null, 1);
        await setExecutablePath(stub);
        const outcome = await vscode.commands.executeCommand<ScanOutcome>(
          SCAN_COMMAND,
        );

        assert.ok(outcome !== undefined);
        assert.strictEqual(outcome.ok, false);
        assert.strictEqual(
          outcome.reason,
          'sarif-stale',
          `expected the stale report to be refused, got ${outcome.reason}: ${outcome.message}`,
        );
        assert.match(outcome.message ?? '', /previous scan/);
        assert.strictEqual(outcome.diagnosticCount, undefined);
      } finally {
        fs.chmodSync(reportsDir, 0o700);
        fs.rmSync(stalePath, { force: true });
      }
    });
  });

  // THE WORST FALSE-CLEAN, and the one the exit code cannot guard: a selected
  // scanner is MISSING, `fail_on_incomplete_scanners` defaults False, the scanners
  // that did run found nothing, ASH exits 0, and an empty Problems panel reads as
  // clean code.
  suite('when a selected scanner never ran', () => {
    let outcome: ScanOutcome;
    let warnings: string[];
    let restore: () => void;

    suiteSetup(async () => {
      // An empty-but-valid SARIF: the scanners that ran found nothing.
      const emptySarif = path.join(scratch, 'nothing-found.sarif');
      fs.writeFileSync(
        emptySarif,
        JSON.stringify({
          version: '2.1.0',
          runs: [
            {
              tool: { driver: { name: 'AWS Labs - Automated Security Helper' } },
              results: [],
            },
          ],
        }),
      );

      // A roster where two of four scanners did not reach a verdict. Statuses and
      // the `dependencies_satisfied` key match the real report's shape.
      const roster = path.join(scratch, 'roster-missing.json');
      fs.writeFileSync(
        roster,
        JSON.stringify({
          metadata: {
            scanner_status: {
              bandit: { status: 'PASSED', dependencies_satisfied: true, excluded: false },
              checkov: { status: 'PASSED', dependencies_satisfied: true, excluded: false },
              grype: { status: 'MISSING', dependencies_satisfied: false, excluded: false },
              semgrep: { status: 'ERROR', dependencies_satisfied: true, excluded: false },
            },
          },
        }),
      );

      // EXIT 0. The whole point: the code is legitimately success.
      const stub = installStubAsh('incomplete', emptySarif, 0, roster);
      await setExecutablePath(stub);

      const captured = captureWarnings();
      warnings = captured.messages;
      restore = captured.restore;

      const result = await vscode.commands.executeCommand<ScanOutcome>(
        SCAN_COMMAND,
      );
      assert.ok(result !== undefined);
      outcome = result;
    });

    suiteTeardown(async () => {
      restore();
      await setExecutablePath(undefined);
    });

    test('still succeeds and still publishes, because the findings are sound', () => {
      // Deliberately NOT a failure. A developer who legitimately lacks grype must
      // still get the other scanners' results -- that is what the False default
      // protects.
      assert.strictEqual(outcome.ok, true);
      assert.strictEqual(outcome.exitCode, 0);
      assert.strictEqual(outcome.diagnosticCount, 0);
    });

    test('reports which scanners did not reach a verdict', () => {
      assert.strictEqual(outcome.scannersTotal, 4);
      assert.strictEqual(outcome.completenessUnknown, false);
      assert.deepStrictEqual([...(outcome.scannersIncomplete ?? [])].sort(), [
        'grype (MISSING, dependencies unavailable)',
        'semgrep (ERROR)',
      ]);
    });

    test('WARNS that an empty panel is not the same as clean', () => {
      // The assertion the extension could not pass before. Without it, the two
      // above are satisfied by the defective behavior too: it published an empty
      // collection and returned ok.
      const warning = warnings.find((m) => m.includes('incomplete'));
      assert.ok(
        warning !== undefined,
        `no warning said the scan was incomplete. Warnings: ${JSON.stringify(warnings)}`,
      );
      assert.match(warning, /2 of 4 scanners/);
      assert.match(
        warning,
        /not the same as clean/,
        'with zero findings the warning must say precisely that an empty panel is not a clean verdict',
      );
    });
  });

  suite('reading the scanner roster', () => {
    test('finds no incompleteness in the real report', () => {
      const text = fs.readFileSync(requireEnv('ASH_TEST_REAL_REPORT'), 'utf8');
      const roster = parseScannerStatus(text);
      assert.ok(roster !== undefined, 'the real report must carry a roster');
      // The committed fixture is ASH 3.0.0-era: it has no `scanner_results` key at
      // all, so the roster comes from the metadata fallback. Pinned so that a
      // regenerated fixture carrying the declared field makes this test say so
      // rather than passing silently through the other branch.
      assert.strictEqual(roster.source, 'metadata.scanner_status');
      // NINE, not the seven that appear in tool.extensions. npm-audit and syft
      // have no extension and no invocation because they found nothing, and both
      // are PASSED -- which is why absence from the invocation list must never be
      // read as failure.
      assert.strictEqual(roster.total, 9);
      assert.deepStrictEqual(roster.incomplete, []);
      assert.strictEqual(roster.allSkipped, false);
    });

    // NOTHING IN THIS REPOSITORY EXERCISES `scanner_results` AGAINST REAL OUTPUT.
    // The committed fixture is 3.0.0-era and lacks the key entirely; a real 3.7.0
    // run populates it, and this suite has no such artifact. These are synthetic,
    // and that limitation is stated rather than left for a reader to assume the
    // branch is covered by the real-report test above.
    test('reads the declared scanner_results key, as ASH 3.7.0 populates it', () => {
      const roster = parseScannerStatus(
        JSON.stringify({
          scanner_results: {
            bandit: { status: 'PASSED', dependencies_satisfied: true },
            cdk_nag: { status: 'MISSING', dependencies_satisfied: false },
          },
        }),
      );
      assert.ok(roster !== undefined);
      assert.strictEqual(roster.source, 'scanner_results');
      assert.strictEqual(roster.total, 2);
      assert.deepStrictEqual(
        roster.incomplete.map((s) => `${s.name}:${s.status}`),
        ['cdk_nag:MISSING'],
      );
    });

    test('prefers the declared key when both are populated', () => {
      const roster = parseScannerStatus(
        JSON.stringify({
          scanner_results: { bandit: { status: 'MISSING' } },
          metadata: { scanner_status: { grype: { status: 'PASSED' } } },
        }),
      );
      assert.ok(roster !== undefined);
      assert.strictEqual(roster.source, 'scanner_results');
      assert.deepStrictEqual(
        roster.incomplete.map((s) => s.name),
        ['bandit'],
      );
    });

    test('falls back past an EMPTY declared key rather than reading it as complete', () => {
      // `scanner_results` defaults to an empty dict in the model
      // (default_factory=dict), so a document can carry the key with nothing in it.
      // Treating that as the roster would report every scan as fully complete.
      const roster = parseScannerStatus(
        JSON.stringify({
          scanner_results: {},
          metadata: { scanner_status: { grype: { status: 'ERROR' } } },
        }),
      );
      assert.ok(roster !== undefined);
      assert.strictEqual(roster.source, 'metadata.scanner_status');
      assert.deepStrictEqual(
        roster.incomplete.map((s) => s.name),
        ['grype'],
      );
    });

    test('cannot tell, rather than saying fine, when there is no roster', () => {
      assert.strictEqual(parseScannerStatus('{}'), undefined);
      assert.strictEqual(parseScannerStatus('{"metadata":{}}'), undefined);
      assert.strictEqual(
        parseScannerStatus('{"metadata":{"scanner_status":{}}}'),
        undefined,
        'an empty roster measured nothing and must not read as complete',
      );
      assert.strictEqual(parseScannerStatus('not json'), undefined);
    });

    test('treats an unreadable roster entry as incomplete, not as passing', () => {
      const roster = parseScannerStatus(
        JSON.stringify({ metadata: { scanner_status: { bandit: 'PASSED' } } }),
      );
      assert.ok(roster !== undefined);
      assert.deepStrictEqual(
        roster.incomplete.map((s) => s.status),
        ['UNREADABLE'],
      );
    });

    test('flags an all-skipped roster as having measured nothing', () => {
      const roster = parseScannerStatus(
        JSON.stringify({
          metadata: {
            scanner_status: {
              bandit: { status: 'SKIPPED' },
              grype: { status: 'SKIPPED' },
            },
          },
        }),
      );
      assert.ok(roster !== undefined);
      // SKIPPED is a COMPLETE status per the repository's own set, so `incomplete`
      // is empty -- and that is exactly why `allSkipped` is tracked separately. A
      // per-scanner check cannot see that the SET measured nothing.
      assert.deepStrictEqual(roster.incomplete, []);
      assert.strictEqual(roster.allSkipped, true);
    });
  });

  suite('reading invocation failures', () => {
    test('does not read a non-zero invocation exit code as failure', () => {
      // Measured on the real report: all 7 invocations are executionSuccessful
      // true and several carry exitCode 1, because a scanner-level 1 means "found
      // vulnerabilities" for grype and cfn-nag.
      const text = fs.readFileSync(requireEnv('ASH_TEST_REAL_REPORT'), 'utf8');
      const bare = JSON.stringify(
        (JSON.parse(text) as { sarif: unknown }).sarif,
      );
      assert.deepStrictEqual(failedInvocations(bare), []);
    });

    test('reports an explicitly unsuccessful invocation with its description', () => {
      const failures = failedInvocations(
        JSON.stringify({
          runs: [
            {
              invocations: [
                { executionSuccessful: true, exitCode: 1 },
                {
                  executionSuccessful: false,
                  exitCode: 127,
                  exitCodeDescription: 'command not found',
                },
                // An absent flag is not a claim of failure.
                { exitCode: 3 },
              ],
            },
          ],
        }),
      );
      assert.strictEqual(failures.length, 1);
      assert.strictEqual(failures[0].exitCode, 127);
      assert.strictEqual(failures[0].description, 'command not found');
    });
  });

  // The fallback arm of extractScannerName. Previously reachable only through a
  // fixture whose driver.name was `automated-security-helper` -- scanner-ish, so the
  // product-name defect could not show -- while the guard against the product name
  // ran against the real report, where scanner_name is present on all 126 results
  // and the fallback is unreachable. Near-miss coverage that read as real coverage.
  suite('attributing a result that names no scanner', () => {
    const productRun = (extra: Record<string, unknown>): string =>
      JSON.stringify({
        version: '2.1.0',
        runs: [
          {
            tool: { driver: { name: 'AWS Labs - Automated Security Helper' } },
            results: [
              {
                ruleId: 'X1',
                level: 'error',
                message: { text: 'no scanner named' },
                locations: [
                  {
                    physicalLocation: {
                      artifactLocation: { uri: 'a.py' },
                      region: { startLine: 1 },
                    },
                  },
                ],
                ...extra,
              },
            ],
          },
        ],
      });

    test('does not fall back to the product name', () => {
      // A result with NO `properties` at all, under a run whose driver.name is the
      // real product string. This is the combination no fixture had.
      const parsedReport = parseSarif(productRun({}));
      assert.strictEqual(parsedReport.findings.length, 1);
      assert.strictEqual(
        parsedReport.findings[0].toolName,
        '',
        'an unidentifiable scanner must be empty, not the product name',
      );
    });

    test('renders an unidentified scanner as a bare ASH source', () => {
      const [finding] = parseSarif(productRun({})).findings;
      assert.strictEqual(toDiagnostic(finding).source, 'ASH');
    });

    test('still prefers a real scanner name when one is present', () => {
      const parsedReport = parseSarif(
        productRun({ properties: { scanner_name: 'bandit' } }),
      );
      assert.strictEqual(parsedReport.findings[0].toolName, 'bandit');
      assert.strictEqual(
        toDiagnostic(parsedReport.findings[0]).source,
        'ASH (bandit)',
      );
    });

    test('rejects every spelling of the aggregate name', () => {
      for (const name of [
        'ASH',
        'ash',
        '  AWS Labs - Automated Security Helper  ',
        'automated-security-helper',
        'Automated Security Helper',
      ]) {
        assert.strictEqual(
          unaggregatedToolName(name),
          '',
          `${name} names the aggregate, not a scanner`,
        );
      }
      // A real scanner name must survive.
      assert.strictEqual(unaggregatedToolName('bandit'), 'bandit');
    });
  });

  // resolveAbsolute's two operative arms. Every earlier uri test used a root that
  // does not exist, so both existence checks failed and all of them returned through
  // the final arm -- the branches carrying the fix were executed by nothing.
  suite('resolving a scan-root-absolute path', () => {
    const root = '/ws';
    const oracle = (present: readonly string[]) => (candidate: string) =>
      present.includes(candidate);

    test('uses an absolute path that exists, as given', () => {
      assert.strictEqual(
        resolveAbsolute('/etc/hosts', root, oracle(['/etc/hosts'])),
        '/etc/hosts',
      );
    });

    test('rebases onto the root when only the joined path exists', () => {
      // grype emits `/poetry.lock` meaning `<scan root>/poetry.lock`.
      assert.strictEqual(
        resolveAbsolute('/poetry.lock', root, oracle(['/ws/poetry.lock'])),
        '/ws/poetry.lock',
      );
    });

    test('keeps the raw path when neither exists', () => {
      assert.strictEqual(
        resolveAbsolute('/nowhere.lock', root, oracle([])),
        '/nowhere.lock',
      );
    });

    test('is monotone: it never moves away from a path that exists', () => {
      // Both exist -- the absolute one wins, so a diagnostic on a real file is never
      // relocated. This is the direction that makes the heuristic safe.
      assert.strictEqual(
        resolveAbsolute(
          '/poetry.lock',
          root,
          oracle(['/poetry.lock', '/ws/poetry.lock']),
        ),
        '/poetry.lock',
      );
    });

    test('reaches those arms through resolveFindingUri, not only directly', () => {
      assert.strictEqual(
        resolveFindingUri('/poetry.lock', root, oracle(['/ws/poetry.lock']))?.fsPath,
        '/ws/poetry.lock',
      );
      // A relative uri must not be touched by the oracle at all.
      assert.strictEqual(
        resolveFindingUri('src/app.py', root, oracle([]))?.fsPath,
        path.join(root, 'src', 'app.py'),
      );
    });
  });

  suite('resolving a finding uri', () => {
    const root = '/workspace-root';

    test('resolves a relative path against the scanned root', () => {
      assert.strictEqual(
        resolveFindingUri('src/app.py', root)?.fsPath,
        path.join(root, 'src', 'app.py'),
      );
    });

    test('accepts an absolute path and every local file: form', () => {
      assert.strictEqual(resolveFindingUri('/abs/app.py', root)?.fsPath, '/abs/app.py');
      assert.strictEqual(
        resolveFindingUri('file:///abs/app.py', root)?.fsPath,
        '/abs/app.py',
      );
      // RFC 8089 permits a single slash. This form used to miss the `file://`
      // test AND the scheme guard, and became a phantom in-workspace path.
      assert.strictEqual(
        resolveFindingUri('file:/abs/app.py', root)?.fsPath,
        '/abs/app.py',
      );
      assert.strictEqual(
        resolveFindingUri('file://localhost/abs/app.py', root)?.fsPath,
        '/abs/app.py',
      );
    });

    test('does not turn a UNC host into a local path', () => {
      // The host used to be discarded, so this became the LOCAL path
      // `/share/app.py` -- a real file, and the wrong one.
      const resolved = resolveFindingUri('file://server/share/app.py', root);
      if (process.platform === 'win32') {
        assert.strictEqual(resolved?.fsPath, '\\\\server\\share\\app.py');
      } else {
        assert.strictEqual(
          resolved,
          undefined,
          'a UNC uri names no local path on this platform, so it must be ' +
            'unresolved rather than silently rebased to /share/app.py',
        );
      }
    });

    test('refuses a scheme it cannot open, single-slash forms included', () => {
      for (const raw of [
        'https://example.com/app.py',
        'data:text/plain,x',
        'urn:uuid:1',
        'http://example.com/app.py',
      ]) {
        assert.strictEqual(
          resolveFindingUri(raw, root),
          undefined,
          `${raw} must not resolve to a path under the workspace`,
        );
      }
    });

    test('does not read a Windows drive letter as a uri scheme', () => {
      // A one-character scheme is legal per RFC 3986, which is why the guard
      // requires two: otherwise `C:` matches and every absolute Windows path in
      // a report is discarded.
      assert.notStrictEqual(resolveFindingUri('C:\\src\\app.py', root), undefined);
    });
  });

  suite('confining the output directory', () => {
    const root = path.sep === '\\' ? 'C:\\ws' : '/ws';

    test('defaults when unset or blank', () => {
      for (const value of [undefined, '', '   ']) {
        const result = resolveOutputDirectory(root, value);
        assert.strictEqual(result.ok, true);
        assert.ok(
          result.ok && result.dir === path.resolve(root, DEFAULT_OUTPUT_DIRECTORY),
        );
      }
    });

    test('accepts a relative path inside the folder', () => {
      const result = resolveOutputDirectory(root, 'build/ash');
      assert.strictEqual(result.ok, true);
      assert.ok(result.ok && result.dir === path.resolve(root, 'build/ash'));
    });

    test('refuses a path that escapes the folder', () => {
      // The documented contract is "relative to the workspace folder". The first
      // implementation was a bare path.resolve, so this escaped -- and the
      // setting is workspace-scoped, so a cloned repository could direct output
      // anywhere the user could write.
      const result = resolveOutputDirectory(root, '../../../var/tmp/x');
      assert.strictEqual(result.ok, false);
      assert.ok(!result.ok && /outside the workspace folder/.test(result.message));
    });

    test('refuses an escape through a symlink, which a lexical check misses', () => {
      // `path.resolve` never touches the filesystem, so a purely textual containment
      // check passes `out` -- it has no `..` in it -- while `out` is a committed
      // symlink pointing outside the workspace. The setting is workspace-scoped,
      // which is precisely the threat model.
      const ws = path.join(scratch, 'symlink-ws');
      const outside = path.join(scratch, 'symlink-outside');
      fs.mkdirSync(ws, { recursive: true });
      fs.mkdirSync(outside, { recursive: true });
      const link = path.join(ws, 'out');
      fs.rmSync(link, { force: true, recursive: true });
      fs.symlinkSync(outside, link, 'dir');

      const escaped = resolveOutputDirectory(ws, 'out');
      assert.strictEqual(
        escaped.ok,
        false,
        'a symlink pointing outside the workspace must be refused',
      );
      assert.ok(!escaped.ok && /outside the workspace folder/.test(escaped.message));

      // A real directory inside the workspace still works, so the check has not
      // become a blanket refusal.
      const fine = resolveOutputDirectory(ws, 'build/ash');
      assert.strictEqual(fine.ok, true);
    });

    test('refuses an absolute path rather than rebasing it', () => {
      const absolute = path.sep === '\\' ? 'C:\\elsewhere' : '/elsewhere';
      const result = resolveOutputDirectory(root, absolute);
      assert.strictEqual(result.ok, false);
      assert.ok(!result.ok && /absolute path/.test(result.message));
    });
  });
});
