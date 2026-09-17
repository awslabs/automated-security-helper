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
 * WHAT THIS FILE DELIBERATELY DOES NOT DO, AND THE ONE EXCEPTION
 * --------------------------------------------------------------
 * The first three describe blocks do not assert that this app has zero findings. That is
 * the CI gate's job, against a full synth, and duplicating the verdict there would mean a
 * genuine finding fails two things for one reason while the second failure adds nothing.
 * Those tests are about the MEASUREMENT being alive, not about the verdict.
 *
 * The last block does assert it, in `there are no unsuppressed errors and no unsuppressed
 * findings`, and this paragraph used to deny that. The exception is not a lapse and is not
 * the duplication the rule above rejects: it is a PRECONDITION for the assertion beside
 * it. `every suppressed throw was absorbed by a CdkNagValidationFailure entry` is a claim
 * about the throws this app produces, and over an app that already had unsuppressed
 * findings it would be a claim about a state nobody intends to ship -- passing or failing
 * for reasons unrelated to absorption. So it is stated where it is cheap, in a run that has
 * already synthesized all five stacks in-process, and it is stated as the setup for the
 * next test rather than as a second gate. When it fails, read the CI gate's output rather
 * than this one.
 *
 * IT ALSO PINS ONE PIECE OF cdk-nag MECHANICS THIS REPOSITORY'S SUPPRESSION LAYOUT
 * DEPENDS ON: which suppression entry absorbs a rule that THROWS. The reasoning in
 * lib/ash-nag-suppressions.ts turns on it, an earlier version of that reasoning had it
 * backwards, and it is not something the compliance report can show -- the report
 * writes `Suppressed` for a suppressed throw and for a suppressed finding alike. The
 * last two describe blocks measure it against cdk-nag itself.
 *
 * WHICH BLOCKS NEED cdk.json's CONTEXT, STATED SO NOBODY HAS TO GUESS
 * -------------------------------------------------------------------
 * jest does not read `cdk.json`. Only the CDK CLI does, and it passes the `context`
 * block to the app in `CDK_CONTEXT_JSON`. A suite that builds its own `App` therefore
 * synthesizes a DIFFERENT artifact from the one that ships -- most consequentially with
 * `@aws-cdk/aws-iam:minimizePolicies` off, which leaves policy documents unmerged and
 * their `Action` arrays unsorted, and so changes which IAM5 findings exist at all.
 *
 *   * `the app itself registers cdk-nag over every stack` NEEDS it and now passes it in
 *     the subprocess env. It did not, and the assembly it measured differed from all
 *     five committed templates; see the note on that block.
 *   * `no throw in this app is absorbed by a wildcard reason` NEEDS it, because it is a
 *     claim about this app's real findings, and loads it into the `App` directly.
 *   * `the string the CI gate matches on is reachable` and `which suppression entry
 *     absorbs a rule that THROWS` do NOT need it and deliberately do not load it. Both
 *     build a minimal fixture -- one bare `Bucket`, one raw `AWS::IAM::Policy` -- to
 *     make a claim about cdk-nag's own behaviour rather than about this app's
 *     resources. Handing them the flags would add nothing and would suggest the
 *     fixtures are meant to resemble the shipped stacks, which they are not.
 *
 * Both blocks that load it assert non-vacuously that they did, because
 * `new App({ context: undefined })` is silently accepted.
 *
 * KNOWN LIMITATION
 * ----------------
 * The first two describe blocks are 2.x-shaped: they read `*-NagReport.csv` from the
 * assembly, which is an artifact of cdk-nag 2.x. On cdk-nag 3.x the pack becomes a
 * validation plugin and its findings move into validation-report.json instead, so
 * these tests and the CI gate have to move together with the pin. See
 * deploy/cdk/README.md.
 */

import { execFileSync } from 'child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

import { App, Aspects, CfnResource, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { Bucket } from 'aws-cdk-lib/aws-s3';
import {
  AwsSolutionsChecks,
  INagLogger,
  NagLoggerErrorData,
  NagLoggerNonComplianceData,
  NagLoggerSuppressedData,
  NagLoggerSuppressedErrorData,
  NagMessageLevel,
  NagPack,
  NagPackProps,
  NagPackSuppression,
  NagSuppressions,
  VALIDATION_FAILURE_ID,
} from 'cdk-nag';
import { IConstruct } from 'constructs';

import { AshAgentCoreStack } from '../lib/ash-agentcore-stack';
import { AshCodeCommitGateStack } from '../lib/ash-codecommit-gate-stack';
import { AshDistributedPipelineStack } from '../lib/ash-distributed-pipeline-stack';
import { AshFargateStack } from '../lib/ash-fargate-stack';
import { AshImagePipelineStack } from '../lib/ash-image-pipeline-stack';

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
  //
  // CDK_CONTEXT_JSON IS PASSED, AND WITHOUT IT THIS MEASURED A DIFFERENT ARTIFACT.
  // `cdk.json`'s `context` block reaches the app only through the CDK CLI, which hands
  // it over in that environment variable (`cxapi.CONTEXT_ENV`). Running bin/ash.ts as a
  // bare node process bypasses the CLI, so the assembly came out with
  // `@aws-cdk/aws-iam:minimizePolicies` OFF: measured against the committed templates,
  // the same policies had unsorted, unmerged `Action` arrays and a differently shaped
  // resource list, and all five templates differed. None of the assertions in this
  // block depended on that -- they are about the measurement being alive, not about any
  // verdict -- but a later assertion easily could, and the divergence cost one
  // environment variable to remove. With it set, all five come out byte-identical to
  // the committed templates.
  //
  // scripts/synth-templates.sh passes no `-c` flags of its own, so `cdk.json` is the
  // CLI's only context source and this reproduces it exactly. Path metadata needs no
  // handling: `pathMetadata: false` is a CLI setting rather than a context key, and
  // without the CLI the library emits no `aws:cdk:path` either way.
  //
  // NOT ASSERTED HERE, DELIBERATELY: that these templates equal the committed ones.
  // `scripts/synth-templates.sh --check` owns drift, and a genuine drift failing two
  // things for one reason makes the second failure noise.
  let outdir: string;
  let reports: Map<string, ReportRow[]>;
  let stacks: string[];
  const cdkJsonContext: Record<string, unknown> = JSON.parse(
    readFileSync(join(__dirname, '..', 'cdk.json'), 'utf8'),
  ).context;

  beforeAll(() => {
    outdir = mkdtempSync(join(tmpdir(), 'ash-nag-gate-app-'));
    execFileSync(
      process.execPath,
      ['-r', 'ts-node/register', join(__dirname, '..', 'bin', 'ash.ts')],
      {
        // useEnvironment stays unset, so the stacks stay environment-agnostic -- that
        // is what keeps an account id out of a public repository.
        env: {
          ...process.env,
          CDK_OUTDIR: outdir,
          CDK_CONTEXT_JSON: JSON.stringify(cdkJsonContext),
          TS_NODE_PROJECT: join(__dirname, '..', 'tsconfig.json'),
        },
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

  test('cdk.json context was read and handed to the subprocess', () => {
    // Non-vacuity for the block above, and the same control ash-hardening.test.ts
    // keeps. If the path breaks or cdk.json is restructured, `cdkJsonContext` becomes
    // undefined, `JSON.stringify(undefined)` is the string "undefined", the CDK
    // library's context parse fails soft, and every assertion below silently goes back
    // to measuring an unminimized artifact. Nothing else here would say so. Controlled
    // by renaming the `.context` property read above: this test fails and the other
    // fifteen pass.
    expect(cdkJsonContext).toBeDefined();
    expect(cdkJsonContext['@aws-cdk/aws-iam:minimizePolicies']).toBe(true);
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

/** The six INagLogger callbacks, flattened to `[verdict, reason]` rows. */
interface Absorbed {
  verdict: 'SUPPRESSED' | 'SUPPRESSED_ERROR' | 'ERROR' | 'NON_COMPLIANT';
  reason: string;
  logicalId: string;
}

class RecordingLogger implements INagLogger {
  readonly rows: Absorbed[] = [];
  private push(verdict: Absorbed['verdict'], resource: CfnResource, reason: string): void {
    this.rows.push({
      verdict,
      reason,
      logicalId: Stack.of(resource).resolve(resource.logicalId),
    });
  }
  onCompliance(): void {}
  onNonCompliance(data: NagLoggerNonComplianceData): void {
    this.push('NON_COMPLIANT', data.resource, data.findingId);
  }
  onNotApplicable(): void {}
  onSuppressed(data: NagLoggerSuppressedData): void {
    this.push('SUPPRESSED', data.resource, data.suppressionReason);
  }
  onError(data: NagLoggerErrorData): void {
    this.push('ERROR', data.resource, '');
  }
  onSuppressedError(data: NagLoggerSuppressedErrorData): void {
    this.push('SUPPRESSED_ERROR', data.resource, data.errorSuppressionReason);
  }
}

/** The message the stand-in rule throws, so a real error cannot be mistaken for it. */
const DELIBERATE_THROW = 'deliberate throw from the ash-nag-gate stand-in rule';

/**
 * A pack whose one rule is named `AwsSolutions-IAM5` and always throws.
 *
 * The real IAM5 throws only when a property resolves to a CloudFormation intrinsic,
 * which is awkward to force and would make the test about intrinsics rather than about
 * suppression matching. `packName` plus `ruleSuffixOverride` reproduce the exact ruleId
 * the matching logic sees -- `applyRule` builds it as `${packName}-${ruleSuffix}` -- so
 * the path under test is the same one `AwsSolutionsChecks` takes.
 */
class ThrowingIam5Pack extends NagPack {
  constructor(props?: NagPackProps) {
    super(props);
    this.packName = 'AwsSolutions';
  }
  visit(node: IConstruct): void {
    if (node instanceof CfnResource && node.cfnResourceType === 'AWS::IAM::Policy') {
      this.applyRule({
        ruleSuffixOverride: 'IAM5',
        info: 'stand-in for AwsSolutions-IAM5',
        explanation: 'throws unconditionally, so the validation-failure path is exercised',
        level: NagMessageLevel.ERROR,
        rule: () => {
          throw new Error(DELIBERATE_THROW);
        },
        node,
      });
    }
  }
}

/** Run the throwing pack over one `AWS::IAM::Policy` carrying `suppressions`. */
function absorbThrow(suppressions: NagPackSuppression[]): Absorbed[] {
  const outdir = mkdtempSync(join(tmpdir(), 'ash-nag-absorb-'));
  try {
    const app = new App({ analyticsReporting: false, outdir });
    const stack = new Stack(app, 'AbsorbStack');
    const policy = new CfnResource(stack, 'Policy', {
      type: 'AWS::IAM::Policy',
      properties: {
        PolicyName: 'p',
        PolicyDocument: { Version: '2012-10-17', Statement: [] },
      },
    });
    if (suppressions.length > 0) {
      NagSuppressions.addResourceSuppressions(policy, suppressions);
    }
    const logger = new RecordingLogger();
    // `reports: false` so nothing is written next to the assembly; the logger is the
    // measurement here, and the CSV cannot tell a suppressed throw from a suppressed
    // finding anyway.
    Aspects.of(app).add(new ThrowingIam5Pack({ reports: false, additionalLoggers: [logger] }));
    try {
      app.synth();
    } catch (error) {
      // An unsuppressed ERROR-level throw becomes a CDK error and fails synth, which
      // is the outcome the third case below is asserting. The logger rows are
      // collected during aspect visiting, so they survive it.
      if (!String(error).includes('AwsSolutions-IAM5')) {
        throw error;
      }
    }
    return logger.rows;
  } finally {
    rmSync(outdir, { recursive: true, force: true });
  }
}

describe('which suppression entry absorbs a rule that THROWS', () => {
  // WHY THIS EXISTS. lib/ash-nag-suppressions.ts drops the `CdkNagValidationFailure`
  // entry from about forty split CodeBuild policies, and the comment that licensed
  // that removal used to say an IAM5 throw would go unsuppressed and fail synth. It
  // does not. `NagPack.ignoreRule` matches a validation failure on EITHER the rule's
  // own id OR `CdkNagValidationFailure`, because the throw path passes `ruleId` rather
  // than `VALIDATION_FAILURE_ID` and `doesApply` short-circuits to true for any
  // suppression with no `appliesTo`. This file is where that is measured rather than
  // asserted in prose.
  //
  // WHAT BREAKS THESE: a cdk-nag release that changes either argument on the throw
  // path, or that stops treating an absent `appliesTo` as "always applies". Both would
  // invalidate the reasoning in ash-nag-suppressions.ts, and both are exactly the kind
  // of change a version bump can carry silently.

  test('an AwsSolutions-IAM5 entry absorbs an IAM5 throw', () => {
    const rows = absorbThrow([
      { id: 'AwsSolutions-IAM5', reason: 'the wildcard enumeration, which did not run here' },
    ]);
    expect(rows).toEqual([
      {
        verdict: 'SUPPRESSED_ERROR',
        reason: 'the wildcard enumeration, which did not run here',
        logicalId: 'Policy',
      },
    ]);
  });

  test('a CdkNagValidationFailure entry absorbs it when no IAM5 entry is present', () => {
    const rows = absorbThrow([
      { id: VALIDATION_FAILURE_ID, reason: 'the rule could not be evaluated at all' },
    ]);
    expect(rows).toEqual([
      {
        verdict: 'SUPPRESSED_ERROR',
        reason: 'the rule could not be evaluated at all',
        logicalId: 'Policy',
      },
    ]);
  });

  test('with both present, the first entry in array order wins', () => {
    // This is why `AGENTCORE_WILDCARD_POLICIES` leaves `LogsAccess` out, and why
    // test/ash-template-size.test.ts asserts no resource carries both. The loser is
    // metadata in a public template that no code path can reach, and if the winner is
    // the wildcard entry then the shipped explanation describes a rule that never ran.
    const iam5First = absorbThrow([
      { id: 'AwsSolutions-IAM5', reason: 'wildcard enumeration, applied first' },
      { id: VALIDATION_FAILURE_ID, reason: 'could not evaluate, applied second' },
    ]);
    expect(iam5First.map((r) => r.reason)).toEqual(['wildcard enumeration, applied first']);

    const validationFirst = absorbThrow([
      { id: VALIDATION_FAILURE_ID, reason: 'could not evaluate, applied first' },
      { id: 'AwsSolutions-IAM5', reason: 'wildcard enumeration, applied second' },
    ]);
    expect(validationFirst.map((r) => r.reason)).toEqual(['could not evaluate, applied first']);
  });

  test('with no entry at all the throw is an ERROR and synth fails', () => {
    // The positive control for the three above. If the stand-in rule stopped throwing,
    // or the pack stopped visiting, every test here would pass by recording nothing.
    const rows = absorbThrow([]);
    expect(rows).toEqual([{ verdict: 'ERROR', reason: '', logicalId: 'Policy' }]);
  });

  test('an unrelated rule id does not absorb an IAM5 throw', () => {
    // Rules out the reading that ANY suppression absorbs ANY throw, which would make
    // the first test above true for an uninteresting reason.
    const rows = absorbThrow([
      { id: 'AwsSolutions-IAM4', reason: 'a different rule, which must not match' },
    ]);
    expect(rows).toEqual([{ verdict: 'ERROR', reason: '', logicalId: 'Policy' }]);
  });
});

describe('no throw in this app is absorbed by a wildcard reason', () => {
  // The consequence of the mechanism above, measured over the real stacks. A throw
  // absorbed by an `AwsSolutions-*` entry ships that entry's reason as the explanation
  // for a rule that could not run -- so the template would carry, for instance, a
  // wildcard enumeration against a policy where IAM5 threw instead of evaluating.
  //
  // Constructed in-process rather than read out of the compliance report because the
  // report writes `Suppressed` for both `onSuppressed` and `onSuppressedError` and
  // records only the reason, so it cannot distinguish the two cases at all.
  //
  // WHAT BREAKS THIS: adding an `AwsSolutions-*` suppression to a resource where that
  // rule throws. Today there are seven throws in the app -- IAM5 on
  // AshAgentCore/RuntimeRole/LogsAccess, CB5 on the five CodeBuild projects, EC23 on
  // the MCP ingress rule -- and each one lands on a resource whose only entry is
  // `CdkNagValidationFailure`.
  const CDK_JSON_CONTEXT: Record<string, unknown> = JSON.parse(
    readFileSync(join(__dirname, '..', 'cdk.json'), 'utf8'),
  ).context;

  const STACK_FACTORIES: Record<string, (app: App, id: string) => Stack> = {
    AshImagePipeline: (app, id) => new AshImagePipelineStack(app, id),
    AshAgentCore: (app, id) => new AshAgentCoreStack(app, id),
    AshFargate: (app, id) => new AshFargateStack(app, id),
    AshCodeCommitGate: (app, id) => new AshCodeCommitGateStack(app, id),
    AshDistributedPipeline: (app, id) => new AshDistributedPipelineStack(app, id),
  };

  const observed: { stack: string; rows: Absorbed[]; template: any }[] = [];

  beforeAll(() => {
    // cdk.json's context has to be handed to the App explicitly: jest does not read
    // it, and without it these are not the stacks that ship. `minimizePolicies`
    // changes how many statements a policy document has, which changes IAM5's
    // findings, so measuring without it would measure a different app.
    expect(CDK_JSON_CONTEXT['@aws-cdk/aws-iam:minimizePolicies']).toBe(true);
    for (const [name, factory] of Object.entries(STACK_FACTORIES)) {
      const outdir = mkdtempSync(join(tmpdir(), `ash-nag-absorb-${name}-`));
      try {
        const app = new App({ analyticsReporting: false, context: CDK_JSON_CONTEXT, outdir });
        const stack = factory(app, name);
        const logger = new RecordingLogger();
        Aspects.of(app).add(
          new AwsSolutionsChecks({ verbose: true, reports: false, additionalLoggers: [logger] }),
        );
        const template = Template.fromStack(stack).toJSON();
        observed.push({ stack: name, rows: logger.rows, template });
      } finally {
        rmSync(outdir, { recursive: true, force: true });
      }
    }
  }, 180_000);

  test('the recording logger saw the app at all', () => {
    // Non-vacuity. `Template.fromStack` synthesizes, which is what runs the aspect; if
    // that ever stopped happening these tests would pass over an empty row set.
    expect(observed).toHaveLength(5);
    expect(observed.every(({ rows }) => rows.length > 0)).toBe(true);
  });

  test('there are no unsuppressed errors and no unsuppressed findings', () => {
    // Both directions, because they are different failures: an ERROR is a rule that
    // threw with nothing to absorb it, a NON_COMPLIANT is a rule that ran and failed.
    // The CI gate catches both against a full synth; this states them here so the
    // absorption assertion below is not being made over an app that is already red.
    const unsuppressed = observed.flatMap(({ stack, rows }) =>
      rows
        .filter((r) => r.verdict === 'ERROR' || r.verdict === 'NON_COMPLIANT')
        .map((r) => `${stack}/${r.logicalId} ${r.verdict} ${r.reason}`),
    );
    expect(unsuppressed).toEqual([]);
  });

  test('every suppressed throw was absorbed by a CdkNagValidationFailure entry', () => {
    const thrownPerStack: Record<string, number> = Object.fromEntries(
      Object.keys(STACK_FACTORIES).map((stack) => [stack, 0]),
    );
    for (const { stack, rows, template } of observed) {
      for (const row of rows) {
        if (row.verdict !== 'SUPPRESSED_ERROR') continue;
        thrownPerStack[stack]++;
        const entries: { id: string; reason: string }[] =
          template.Resources?.[row.logicalId]?.Metadata?.cdk_nag?.rules_to_suppress ?? [];
        // The recorded reason has to be the one attached under the
        // validation-failure id. Matching on the reason STRING rather than on the
        // presence of the id is what makes this catch the real defect: an entry could
        // be present and still lose the first-match race.
        expect({
          resource: `${stack}/${row.logicalId}`,
          absorbedByValidationFailureEntry: entries.some(
            (e) => e.id === VALIDATION_FAILURE_ID && e.reason === row.reason,
          ),
        }).toEqual({
          resource: `${stack}/${row.logicalId}`,
          absorbedByValidationFailureEntry: true,
        });
      }
    }
    // PINNED EXACTLY, PER STACK, AND NOT AS A FLOOR. This used to be
    // `expect(thrown).toBeGreaterThanOrEqual(7)`, justified as leaving room for "a
    // legitimately added throw". That reasoning is backwards: every throw here is a rule
    // that did not EVALUATE, so the number growing is the bad direction and a floor is
    // blind to it. Seven becoming twenty would have passed -- twenty rules silently not
    // running while the loop above cheerfully confirmed each one was absorbed.
    //
    // Per stack rather than as one total so a failure names where the throw appeared, and
    // so a throw moving between stacks is visible instead of cancelling out. The seven are
    // AwsSolutions-IAM5 on AshAgentCore/RuntimeRole/LogsAccess, whose ARNs are built from
    // pseudo-parameters; AwsSolutions-CB5 on the five AshDistributedPipeline CodeBuild
    // projects, whose build image is an Fn::Join over the ECR repository attributes; and
    // AwsSolutions-EC23 on the AshFargate MCP ingress rule, whose CidrIp is an Fn::Ref.
    //
    // WHAT BREAKS THIS, and both directions are worth a look rather than a re-pin: a new
    // resource whose property resolves to an intrinsic (the count goes up, and the question
    // is whether that rule can be made evaluable instead), or a cdk-nag release that
    // evaluates one of these (the count goes down, and the suppression should be removed
    // rather than the number lowered). Zero would also fail, which is what keeps a run that
    // recorded nothing from passing silently.
    expect(thrownPerStack).toEqual({
      AshAgentCore: 1,
      AshCodeCommitGate: 0,
      AshDistributedPipeline: 5,
      AshFargate: 1,
      AshImagePipeline: 0,
    });
  });
});
