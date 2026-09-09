/**
 * The CI gate that fails on a cdk-nag finding depends on facts about this app and
 * about cdk-nag. These tests hold those facts up so the gate cannot quietly stop
 * measuring anything.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The `cdk-nag` job in .github/workflows/ash-iac-drift.yml reads the per-stack
 * compliance reports cdk-nag writes into the cloud assembly and fails on a row
 * whose Compliance is `Non-Compliant` or `UNKNOWN`. Two ways that gate could turn
 * into a no-op that reports success, neither of which the gate can detect about
 * itself:
 *
 *   1. bin/ash.ts stops registering the pack, or registers it on one Stack rather
 *      than on the App. The gate has a positive control for this, but the control
 *      is only as good as the assumption that running the app produces reports at
 *      all -- which is what the first test here measures, against bin/ash.ts
 *      itself rather than against a fixture that re-implements it.
 *   2. The literal string the gate matches on stops appearing. `Non-Compliant` is
 *      cdk-nag's own enum value, so a cdk-nag upgrade that renamed it, or a typo
 *      in the gate, would make every run report a clean repo forever. The second
 *      test forces a real finding and asserts the string turns up.
 *
 * WHAT THIS FILE DELIBERATELY DOES NOT DO
 * ---------------------------------------
 * It does not assert that this app has zero findings. That is the CI gate's job,
 * against a full synth, and duplicating the verdict here would mean a genuine
 * finding fails two things for one reason and the second failure adds nothing. The
 * tests here are about the MEASUREMENT being alive, not about the verdict.
 *
 * KNOWN LIMITATION
 * ----------------
 * Both tests are 2.x-shaped: they read `*-NagReport.csv` from the assembly, which
 * is an artifact of cdk-nag 2.x. On cdk-nag 3.x the pack becomes a validation
 * plugin and its findings move into validation-report.json instead, so these tests
 * and the CI gate have to move together with the pin. See deploy/cdk/README.md.
 */

import { execFileSync } from 'child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { App, Aspects, Stack } from 'aws-cdk-lib';
import { Bucket } from 'aws-cdk-lib/aws-s3';
import { AwsSolutionsChecks } from 'cdk-nag';

/** The Compliance values cdk-nag can write. Spelled out rather than imported from
 * cdk-nag's enums on purpose: the CI gate matches these as literal strings, so a
 * test that imported the enum would follow a rename silently and still pass while
 * the gate stopped matching. */
const FAILING_STATES = ['Non-Compliant', 'UNKNOWN'];
const PASSING_STATES = ['Compliant', 'Suppressed'];

interface ReportRow {
  ruleId: string;
  resourceId: string;
  compliance: string;
  exceptionReason: string;
  ruleLevel: string;
  ruleInfo: string;
}

/**
 * Parse one NagReport CSV.
 *
 * Hand-rolled rather than pulled in as a dependency because the format is fixed
 * and narrow: six columns, every field quoted by cdk-nag, `""` for an embedded
 * quote. The reasons in this repo's suppressions contain both commas and escaped
 * quotes, so a naive split on "," would corrupt them -- which is why this is
 * written out rather than approximated.
 */
function parseNagReport(csv: string): ReportRow[] {
  const rows: string[][] = [];
  let field = '';
  let record: string[] = [];
  let inQuotes = false;
  for (let i = 0; i < csv.length; i++) {
    const c = csv[i];
    if (inQuotes) {
      if (c === '"') {
        if (csv[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += c;
      }
    } else if (c === '"') {
      inQuotes = true;
    } else if (c === ',') {
      record.push(field);
      field = '';
    } else if (c === '\n') {
      record.push(field);
      rows.push(record);
      record = [];
      field = '';
    } else if (c !== '\r') {
      field += c;
    }
  }
  if (field !== '' || record.length > 0) {
    record.push(field);
    rows.push(record);
  }

  const [header, ...body] = rows;
  expect(header).toEqual([
    'Rule ID',
    'Resource ID',
    'Compliance',
    'Exception Reason',
    'Rule Level',
    'Rule Info',
  ]);
  return body
    .filter((r) => r.length === 6)
    .map(([ruleId, resourceId, compliance, exceptionReason, ruleLevel, ruleInfo]) => ({
      ruleId,
      resourceId,
      compliance,
      exceptionReason,
      ruleLevel,
      ruleInfo,
    }));
}

function readReports(outdir: string): Map<string, ReportRow[]> {
  const out = new Map<string, ReportRow[]>();
  for (const name of readdirSync(outdir)) {
    if (name.endsWith('-NagReport.csv')) {
      out.set(name, parseNagReport(readFileSync(join(outdir, name), 'utf8')));
    }
  }
  return out;
}

describe('the app itself registers cdk-nag over every stack', () => {
  // bin/ash.ts calls app.synth() at module scope, so it cannot be imported into
  // this process without writing an assembly. Run it as its own process with
  // CDK_OUTDIR pointed at a temporary directory: that measures the real entry
  // point, including the Aspects.of(app) call, rather than a fixture that
  // restates it. A test that built its own App and added the pack itself would
  // pass even if bin/ash.ts had stopped registering anything.
  let outdir: string;
  let reports: Map<string, ReportRow[]>;
  let stacks: string[];

  beforeAll(() => {
    outdir = mkdtempSync(join(tmpdir(), 'ash-nag-gate-app-'));
    execFileSync(
      process.execPath,
      ['-r', 'ts-node/register', join(__dirname, '..', 'bin', 'ash.ts')],
      {
        // No `env` spread of anything unusual: the app must produce the same
        // assembly it produces in CI. useEnvironment is deliberately unset, so
        // the stacks stay environment-agnostic.
        env: { ...process.env, CDK_OUTDIR: outdir, TS_NODE_PROJECT: join(__dirname, '..', 'tsconfig.json') },
        stdio: 'pipe',
      },
    );
    reports = readReports(outdir);
    stacks = readdirSync(outdir)
      .filter((n) => n.endsWith('.template.json'))
      .map((n) => n.replace(/\.template\.json$/, ''))
      .sort();
  }, 120_000);

  afterAll(() => {
    if (outdir) {
      rmSync(outdir, { recursive: true, force: true });
    }
  });

  test('running bin/ash.ts writes cdk-nag compliance reports', () => {
    // If this fails, the CI gate's first positive control is what will fire, and
    // its message is the one to read: the pack is not registered, or it was
    // constructed with `reports: false`.
    expect(reports.size).toBeGreaterThan(0);
  });

  test('the app synthesizes more than one stack, so app-wide registration is testable at all', () => {
    // The next test is only meaningful if there are several stacks: with one
    // stack, Aspects.of(stack) and Aspects.of(app) are indistinguishable. This
    // states that precondition rather than leaving it implicit.
    expect(stacks.length).toBeGreaterThan(1);
  });

  test('every synthesized stack is covered by a cdk-nag report', () => {
    // This is the failure the CI gate's second control exists for, asserted here
    // so it surfaces locally in seconds instead of in CI in minutes. A pack added
    // to one Stack leaves the others unscanned while they still report clean.
    const covered = new Set<string>();
    for (const [name, rows] of reports) {
      for (const stack of stacks) {
        if (name.includes(`-${stack}-NagReport.`)) {
          covered.add(stack);
        }
      }
      for (const row of rows) {
        const head = row.resourceId.split('/')[0];
        if (stacks.includes(head)) {
          covered.add(head);
        }
      }
    }
    expect([...covered].sort()).toEqual(stacks);
  });

  test('the reports carry rows, and every row is in a state the gate understands', () => {
    // An unrecognized Compliance value would be counted as passing by the CI
    // gate, which checks for the two failing states rather than for the two
    // passing ones. Asserting the closed set here is what makes that safe: a new
    // cdk-nag state fails this test rather than silently passing the gate.
    const rows = [...reports.values()].flat();
    expect(rows.length).toBeGreaterThan(0);
    const states = [...new Set(rows.map((r) => r.compliance))].sort();
    for (const state of states) {
      expect([...FAILING_STATES, ...PASSING_STATES]).toContain(state);
    }
  });

  test('the app evaluates both Error and Warning level rules, which is why the gate cannot use synth exit codes', () => {
    // The load-bearing fact behind this gate's whole design. cdk-nag raises an
    // ERROR-level finding as a CDK error, which fails synth; a WARNING-level
    // finding is only a warning and synth still exits 0. So a gate built on
    // synth's exit code would pass every Warning-level finding in silence.
    //
    // Asserted against the real app rather than a fixture, because it is a claim
    // about THIS app's resources: measured at the time of writing, 18 of the 19
    // AwsSolutions rules that evaluate here are Error level and AwsSolutions-CB5
    // is Warning level. Not pinned to CB5 by name -- the point is that the
    // Warning level is populated at all, and pinning the rule id would turn a
    // legitimate resource change into a failure here.
    //
    // If this ever fails because no Warning-level rule evaluates any more, the
    // gate's rationale has changed and the comment in the workflow that cites
    // this split has to change with it. It does NOT mean the gate can be
    // simplified to an exit-code check: a resource that reintroduces a
    // Warning-level rule would silently stop being gated.
    const rows = [...reports.values()].flat();
    const levels = new Set(rows.map((r) => r.ruleLevel));
    expect(levels.has('Error')).toBe(true);
    expect(levels.has('Warning')).toBe(true);
  });

  test('every suppressed row carries a reason', () => {
    // A suppression with an empty reason is a finding that was silenced rather
    // than justified. The report is where that shows up: cdk-nag copies the
    // reason into Exception Reason, and these strings ship inside the public
    // committed templates as well.
    for (const row of [...reports.values()].flat()) {
      if (row.compliance === 'Suppressed') {
        expect(row.exceptionReason.trim().length).toBeGreaterThan(0);
      }
    }
  });
});

describe('the string the CI gate matches on is reachable', () => {
  // Without this, a typo in the gate -- or a cdk-nag release that renamed the
  // enum value -- would make "zero Non-Compliant rows" mean "the predicate never
  // matches anything" while reading as a permanently clean repo. Forcing a real
  // finding is the only way to tell those two apart.
  let rows: ReportRow[];

  beforeAll(() => {
    const outdir = mkdtempSync(join(tmpdir(), 'ash-nag-gate-canary-'));
    try {
      const app = new App({ analyticsReporting: false, outdir });
      const stack = new Stack(app, 'NagCanary');
      // A bare Bucket violates several AwsSolutions rules -- no server access
      // logging (S1), no SSL-only bucket policy (S10). Which rule fires is not
      // the point and is not asserted; that a Non-Compliant row appears is.
      new Bucket(stack, 'Unhardened');
      // The same call shape bin/ash.ts uses, on purpose: if the registration API
      // changes under a cdk-nag upgrade, this fails to compile here rather than
      // silently producing no findings in CI.
      Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));
      app.synth();
      rows = [...readReports(outdir).values()].flat();
    } finally {
      rmSync(outdir, { recursive: true, force: true });
    }
  }, 120_000);

  test('a deliberately unhardened resource produces a Non-Compliant row', () => {
    const failing = rows.filter((r) => r.compliance === 'Non-Compliant');
    expect(failing.length).toBeGreaterThan(0);
    // Every finding must carry the rule id and level the gate reports to the
    // developer. A row with an empty Rule ID would produce a CI annotation that
    // names no rule, which is unactionable.
    for (const row of failing) {
      expect(row.ruleId).toMatch(/^AwsSolutions-/);
      expect(['Error', 'Warning']).toContain(row.ruleLevel);
    }
  });
});
