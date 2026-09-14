/**
 * The committed templates are the deliverable, so their SIZE and their SHAPE are both
 * part of the contract.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * Four of the five committed templates were over CloudFormation's inline
 * `--template-body` cap, and nothing noticed. Every static gate passed: the app
 * synthesized, cdk-nag was clean, the drift gate matched. The templates are
 * committed specifically so an adopter can launch one, and for four of them
 * `aws cloudformation create-stack --template-body` failed outright.
 *
 * The console launch flow reads from an S3 URL and was never affected, which is
 * exactly why this went unseen — the documented happy path worked.
 *
 * WHAT THIS PINS, AND IN BOTH DIRECTIONS
 * --------------------------------------
 * A template moving from one list to the other is a documentation change, not
 * just a number change, because README.md tells adopters which launch method to
 * use. So this asserts the inline set stays under the cap AND that the S3-only
 * set stays over it. The second half looks strange but earns its place: without
 * it, a template that later shrank under the cap would keep being documented as
 * S3-only forever, and nobody would find out.
 *
 * The README cross-check is the point of the whole file. A size assertion alone
 * would pass while the table above it said something false.
 *
 * CONSTRAINT: this reads the COMMITTED templates, not a fresh synth. The drift
 * gate (`scripts/synth-templates.sh --check`) is what guarantees those are the
 * same bytes; duplicating a synth here would be slow and would measure something
 * the adopter never receives.
 *
 * WHICH GATE FIRES FIRST, BECAUSE THIS FILE USED TO CLAIM IT WAS THIS ONE
 * ----------------------------------------------------------------------
 * `templateBytes` is `fs.statSync().size` on a file under `templates/`. So for any
 * change that grows a template — a new resource, a longer suppression reason,
 * re-enabling path metadata — the sequence is:
 *
 *   1. The change lands in `lib/`. This file still measures the OLD committed bytes
 *      and passes. It says nothing at all.
 *   2. `scripts/synth-templates.sh --check` re-synthesizes and diffs. THAT is the gate
 *      that fires first, and it fires on every such change whether or not the size
 *      moved, because the committed bytes no longer match a fresh synth.
 *   3. Only once someone re-runs the synth and commits the new templates does this
 *      file get the new bytes and have anything to say.
 *
 * So this file is the gate on the DELIVERABLE, and the drift gate is the gate on the
 * source. Two earlier claims in this header had it backwards and are corrected in
 * place; if a size regression is ever reported as "the tests passed", step 2 is where
 * to look.
 *
 * WHY `"pathMetadata": false` IS SET IN cdk.json
 * ---------------------------------------------
 * Adding the optional `KmsKeyArn` parameter put the two inline-launchable
 * templates over the cap: AshAgentCore 50,666 to 52,174 and AshCodeCommitGate
 * 50,822 to 52,683, against a 51,200 limit. A `CfnParameter` with a description
 * and an `allowedPattern` costs about 448 bytes and its `CfnCondition` another
 * 96, and those two templates had 534 and 378 bytes of headroom, so it did not
 * fit by shortening a description or dropping a pattern.
 *
 * Disabling path metadata drops the per-resource `aws:cdk:path` entries and
 * brought them to 50,715 and 50,811, restoring roughly the original margin. That
 * kept every stack both inline-launchable AND able to take a customer-managed
 * key, which the alternatives did not: reclassifying both as S3-only would have
 * emptied the inline set entirely and made the central assertion here vacuous,
 * and suppressing the KMS rules on those two stacks alone would have left them
 * permanently unable to accept a key.
 *
 * The cost, stated rather than hidden: a committed template no longer records
 * which construct produced each resource. Re-synthesize locally with path
 * metadata enabled to recover that when debugging. Note also that it removed
 * four detect-secrets findings, because `aws:cdk:path` values were being flagged
 * as base64 high-entropy strings.
 *
 * Those five-digit figures are intra-branch measurements of states this branch passed
 * through, kept because they are what justified the decision. The against-`main`
 * deltas — the ones a reviewer diffing this PR will see — are in the table below.
 *
 * THE TEMPLATES ARE INDENTED, AND THAT IS NOT NEGOTIABLE: TRIVY CRASHES ON
 * SINGLE-LINE JSON
 * ----------------------------------------------------------------------------
 * `@aws-cdk/core:suppressTemplateIndentation` was set here for a while, and it is
 * the obvious thing to reach for: CloudFormation parses the body as JSON, so
 * indentation is bytes the 51,200 cap charges for and nothing reads. Removing it was
 * worth 12% to 21% per stack.
 *
 * It also made every one of the five templates unscannable. Measured directly against
 * trivy v0.69.3 -- the version this repository pins in Dockerfile's `TRIVY_VERSION`,
 * so it is the version ASH's own users get -- `trivy config` over the single-line
 * templates panics on all five, exits 2, and produces no result at all. Same trace
 * every time:
 *
 *   property.go:211 -> property.go:393
 *     -> adapters/cloudformation/aws/iam.getPolicies at policy.go:24
 *
 * The bug is upstream, in trivy: `AsRawStrings` slices its source lines
 * `[GetStartLine()-1 : GetEndLine()]` and range-checks only the upper bound. A
 * single-line JSON document reports start line 0, so the low bound is -1 and the
 * slice panics. It is reached only through the CloudFormation IAM-policy adapter,
 * which is why the crash needs a template with an IAM policy in it -- and every one
 * of these has several.
 *
 * Re-indented, all five scan at rc=0 and non-vacuously: AshAgentCore runs 34 tests
 * (28 successes, 6 failures), AshCodeCommitGate 36, AshDistributedPipeline 45,
 * AshFargate 74, AshImagePipeline 33.
 *
 * NOTHING USED TO PIN THAT, WHICH IS THE ONE REGRESSION THIS WHOLE FILE EXISTS FOR.
 * `git grep suppressTemplateIndentation` found only prose: no test, no lint, no gate.
 * Worse, the guard rail pointed the wrong way -- re-suppressing indentation SHRINKS
 * every template, so the size assertions below would pass MORE easily. There is an
 * accidental partial canary, and it is not enough to rely on: AshImagePipeline would
 * fall under the cap at a >=17.5% shrink and trip its S3-only assertion, while
 * AshFargate would not. `every committed template is indented` below is the real
 * check, and it is written against the bytes-per-line ratio so it holds for a
 * template of any size.
 *
 * WHERE THE BYTES CAME FROM INSTEAD: THE SUPPRESSION FAN-OUT
 * ---------------------------------------------------------
 * Indented and before any narrowing, the two inline stacks were 62,907 and 55,685 --
 * over by 11,707 and 4,485. What paid for that was `applyToChildren: true` on the
 * cdk-nag suppression helpers.
 *
 * `NagSuppressions.addResourceSuppressions(scope, ..., true)` walks the subtree and
 * writes the metadata onto every L1 it finds, so one IAM5 suppression on a role
 * landed a ~450-byte reason on the role, on its CodeBuild project, and on each of its
 * policies. Narrowing each helper to the resources that consume it changes no verdict
 * and, measured against `main`:
 *
 *   suppression entries shipped              129 -> 89
 *   of those, entries no rule consults        99 -> 17
 *   reasons cdk-nag base64-encoded            53 -> 0
 *
 * lib/ash-nag-suppressions.ts has the mechanism and the per-helper reasoning. Higher
 * entry counts appear in this branch's intermediate states; 129 is the number a
 * reviewer sees.
 *
 * The classification is cdk-nag's own per-(rule, resource) verdict, captured by
 * wrapping the six `INagLogger` callbacks on `AnnotationLogger.prototype`, and NOT a
 * reading of which rule looks applicable. That distinction is load-bearing: when a
 * rule THROWS on a resource cdk-nag emits SUPPRESSED_ERROR and writes no SUPPRESSED
 * row, so `AshAgentCore/RuntimeRole/LogsAccess` -- where IAM5 throws -- looks unused
 * to anything counting only SUPPRESSED. Dropping its entry on that reading turns a
 * SUPPRESSED_ERROR into an ERROR. Verified by running exactly that as a negative
 * control before relying on the narrowing, and pinned by
 * `AshAgentCore/RuntimeRole/LogsAccess keeps its CdkNagValidationFailure entry` below.
 *
 * A MEASUREMENT TRAP WORTH ONE PARAGRAPH, BECAUSE IT PRODUCED A WRONG READING HERE
 * FIRST. A wildcard detector that inspects only STRING `Resource` values reports "no
 * wildcard in this policy document" on policies cdk-nag has just raised an IAM5 finding
 * against. After the per-service split most of these ARNs are `Fn::Join` structures
 * whose literal tail is the wildcard -- `:*` for the log-stream suffix, `-*` for the
 * report group, `/*` for an object prefix -- so the `*` is inside an object, not a
 * string. It is the SERIALIZED form that has to be searched. The self-contradiction is
 * the tell: a policy reported as having no wildcard while a SUPPRESSED IAM5 row exists
 * against it. IAM5 also raises a finding per wildcard ACTION, which is a second thing
 * a resource-only detector misses entirely.
 *
 * The em-dash fix went with it, for the same defect class rather than for size.
 * cdk-nag base64-encodes any reason containing a non-ASCII character, which spends 4
 * bytes per 3 and reaches the adopter as an opaque blob. `.ash/.ash.yaml` records the
 * empty population from the other side.
 *
 * WHAT THE FIVE TEMPLATES MEASURE NOW, against a 51,200-byte cap, with `main` beside
 * each for the diff a reviewer reads:
 *
 *                            bytes    margin        on main    margin on main
 *   AshAgentCore            50,135    under 1,065    50,934     under     266
 *   AshCodeCommitGate       47,161    under 4,039    50,714     under     486
 *   AshDistributedPipeline 162,354    over  111,154 148,394     over  97,194
 *   AshFargate              69,391    over   18,191  76,674     over  25,474
 *   AshImagePipeline        62,961    over   11,761  68,435     over  17,235
 *
 * READ THE AGENTCORE MARGIN AS THIN, BECAUSE IT IS: 1,065 bytes, 2.1% of the cap, on
 * a stack whose suppression metadata grows with every resource added. A new resource
 * needing an IAM5 suppression costs roughly 550 bytes indented plus its own body, so
 * about two of them exhaust the headroom. It is nonetheless a 4.0x improvement on
 * `main`, which has 266 bytes -- less than one suppression entry -- and the earlier
 * description of the 266 as comfortable was wrong.
 *
 * AshDistributedPipeline is the one stack that GREW against `main`, by 13,960 bytes.
 * The per-service policy split trades one `DefaultPolicy` per role for one policy per
 * action service, which is more resources and more metadata. It is 111,154 bytes over
 * an S3-only cap either way, so it pays nothing for the trade and the other four
 * stacks collect it.
 *
 * The answer when the AgentCore margin runs out is NOT to unindent -- that is the
 * trivy panic above -- and is probably not more prose-tightening either, since the
 * fan-out is already gone and the reasons have since been LENGTHENED to cover the
 * wildcard-action findings they used to omit (see `suppressCodeBuildRoleWildcards`).
 * The remaining honest moves are narrowing the 17 entries no rule consults (all of
 * them in AshDistributedPipeline, so they buy AshAgentCore nothing; the helper header
 * says why they are pinned rather than removed) or reclassifying AshAgentCore as
 * S3-only. Reclassifying costs the inline set half its members and is a README
 * change, not just a list edit.
 *
 * ALSO MEASURED AND REJECTED: hoisting the child-policy suppressions up to the role.
 * It recovers nothing, because `applyToChildren` materialized a byte-identical reason
 * on the role and on each child either way. Reclassifying BOTH inline templates as
 * S3-only would empty the inline set and make the central assertion here vacuous,
 * which is the same objection the pathMetadata section above records.
 *
 * ONE MORE CONSEQUENCE, AND IT IS NOT IN THIS FILE: `.pre-commit-config.yaml` runs
 * `pretty-format-json --autofix --indent=2` over every JSON file except `.vscode/*`,
 * which claimed these templates. CDK indents by ONE space --
 * `Stack._synthesizeTemplate` does `indent = suppress ? undefined : 1` -- so that hook
 * disagrees with the committed output whether or not indentation is suppressed, and a
 * contributor running pre-commit would reflate them to two spaces and break the drift
 * gate. The templates directory is excluded from that hook for that reason, and the
 * exclusion is still needed now that the flag is gone.
 */

import * as fs from 'fs';
import * as path from 'path';

/**
 * "The maximum size of a template body that you can pass in a CreateStack,
 * UpdateStack, or ValidateTemplate request." — 51,200 bytes.
 * https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cloudformation-limits.html
 */
const INLINE_TEMPLATE_BODY_MAX_BYTES = 51_200;

/**
 * Held back from the cap so erosion surfaces while there is still room to act.
 *
 * `toBeLessThan(INLINE_TEMPLATE_BODY_MAX_BYTES)` is what this used to assert, and
 * 51,199 bytes passed it. A template one byte under a hard limit is not a passing
 * state, it is the last frame before an adopter's `create-stack` starts failing, and
 * a test that only says so at 51,200 gives whoever added the resource no room to fix
 * it in the same change.
 *
 * 512 bytes is deliberately just under what ONE indented IAM5 suppression entry costs
 * in this app (about 550, measured). So when the budget trips, the change that tripped
 * it can still be landed and then narrowed, rather than having to be reverted.
 */
const INLINE_RESERVE_BYTES = 512;
const INLINE_TEMPLATE_BUDGET_BYTES = INLINE_TEMPLATE_BODY_MAX_BYTES - INLINE_RESERVE_BYTES;

/**
 * The same page puts a template passed by S3 URL at 1 MB, which is why the
 * oversized templates have a launch path at all rather than a defect.
 */
const S3_TEMPLATE_BODY_MAX_BYTES = 1_048_576;

/** Launchable with `--template-body`. Keep in step with README.md. */
const INLINE_LAUNCHABLE = ['AshAgentCore', 'AshCodeCommitGate'];

/** Must be uploaded and launched with `--template-url`. Keep in step with README.md. */
const S3_URL_ONLY = ['AshDistributedPipeline', 'AshFargate', 'AshImagePipeline'];

const ALL_STACKS = [...INLINE_LAUNCHABLE, ...S3_URL_ONLY];

/**
 * Longest average line the committed templates may have.
 *
 * CDK indents by one space, so the real ratio is 32 to 108 bytes per line. Suppress
 * indentation and the whole template becomes ONE line, which puts the ratio at the
 * file size. Anything between those two is not a shape CDK produces, so 512 separates
 * them with room for a template that grows or shrinks. Expressed as a ratio rather
 * than a per-stack line count on purpose: a fixed floor would have to be revisited
 * every time a stack legitimately gains or loses resources.
 */
const MAX_BYTES_PER_LINE = 512;

/**
 * How many `rules_to_suppress` entries each committed template carries.
 *
 * Pinned per stack rather than only in total, so a regression names the template it
 * landed in. See the header: against `main` this is 129 -> 89, and 99 -> 17 of them
 * unconsulted.
 *
 * WHAT BREAKS THIS, and it is the point of pinning it at all: reintroducing
 * `applyToChildren: true` on any helper in lib/ash-nag-suppressions.ts. That walks the
 * subtree and writes the same reason onto every L1 under the scope, so the counts jump
 * rather than drift -- on `main` the same helpers produced 15, 15, 58, 21 and 20. It
 * catches the positional form of that argument too, which a source-text check cannot,
 * because `addResourceSuppressions`' third parameter is only named in the API.
 *
 * Adding a resource that genuinely needs a suppression is expected to change a number
 * here. Re-run `npm run synth`, put the new count in, and the diff makes the review
 * question visible: does the new entry get consulted, or is it an 18th inert one?
 */
const SUPPRESSION_ENTRIES: Record<string, number> = {
  AshAgentCore: 10,
  AshCodeCommitGate: 7,
  AshDistributedPipeline: 55,
  AshFargate: 9,
  AshImagePipeline: 8,
};

/** 89, spelled out so the total is asserted and not merely derived from the map. */
const SUPPRESSION_ENTRIES_TOTAL = 89;

/**
 * The entries no cdk-nag rule consults, named so the next reader can tell a known
 * inert entry from a new one.
 *
 * Every one is an `AwsSolutions-IAM5` entry on an `AWS::IAM::Policy` in
 * AshDistributedPipeline that IAM5 evaluates as COMPLIANT: the policy holds no
 * wildcard, so the suppression protects nothing and costs bytes. They are listed by
 * logical-id PREFIX because CDK appends a hash that moves when a construct moves.
 *
 * Why they stay rather than being removed is in the header of
 * lib/ash-nag-suppressions.ts: the grants behind them are written by aws-cdk-lib grant
 * helpers, so an allowlist of "policy groups that hold a wildcard" would be a claim
 * about aws-cdk-lib rather than about this app, and would rot on a CDK bump. The six
 * `CodePipelineActionRoleDefaultPolicy` entries are worse still -- their only handle is
 * the pipeline stage and action NAME.
 *
 * WHAT BREAKS THIS: a new inert entry has to either show up as an extra count in
 * `SUPPRESSION_ENTRIES` above or replace one of these, and either is a failure here.
 * An entry in this list that becomes consulted also fails, which is the direction that
 * means someone added a wildcard to a policy that was clean.
 */
const KNOWN_INERT_SUPPRESSIONS = [
  'Shard0ProjectRoleSsmAccess',
  'Shard0ProjectRoleSecretsmanagerAccess',
  'Shard1ProjectRoleSsmAccess',
  'Shard1ProjectRoleSecretsmanagerAccess',
  'Shard2ProjectRoleSsmAccess',
  'Shard2ProjectRoleSecretsmanagerAccess',
  'Shard3ProjectRoleSsmAccess',
  'Shard3ProjectRoleSecretsmanagerAccess',
  'MergeProjectRoleSsmAccess',
  'MergeProjectRoleSecretsmanagerAccess',
  'PipelineRoleStsAccess',
  'PipelineBuildImageBuildAshImageCodePipelineActionRoleDefaultPolicy',
  'PipelineScanShard0CodePipelineActionRoleDefaultPolicy',
  'PipelineScanShard1CodePipelineActionRoleDefaultPolicy',
  'PipelineScanShard2CodePipelineActionRoleDefaultPolicy',
  'PipelineScanShard3CodePipelineActionRoleDefaultPolicy',
  'PipelineMergeMergeAndGateCodePipelineActionRoleDefaultPolicy',
];

/**
 * Resource types a cdk-nag suppression is allowed to sit on.
 *
 * This is the sharpest artifact-side tell for the fan-out, because `applyToChildren`
 * put IAM5 reasons on `AWS::IAM::Role` resources -- 20-odd of them on `main` -- and a
 * role is not a resource IAM5 reads a policy document off. Every type here is one that
 * some rule in use actually evaluates: IAM5 reads `AWS::IAM::Policy`, ECS2 reads
 * `AWS::ECS::TaskDefinition`, SMG4 reads `AWS::SecretsManager::Secret`, CB5 reads
 * `AWS::CodeBuild::Project`, EC23 reads `AWS::EC2::SecurityGroupIngress`.
 */
const SUPPRESSIBLE_RESOURCE_TYPES = [
  'AWS::CodeBuild::Project',
  'AWS::EC2::SecurityGroupIngress',
  'AWS::ECS::TaskDefinition',
  'AWS::IAM::Policy',
  'AWS::SecretsManager::Secret',
];

const TEMPLATE_DIR = path.join(__dirname, '..', 'templates');
const LIB_DIR = path.join(__dirname, '..', 'lib');
const README = path.join(__dirname, '..', 'README.md');

function templatePath(stack: string): string {
  return path.join(TEMPLATE_DIR, `${stack}.template.json`);
}

function templateBytes(stack: string): number {
  return fs.statSync(templatePath(stack)).size;
}

function templateText(stack: string): string {
  return fs.readFileSync(templatePath(stack), 'utf8');
}

interface SuppressionEntry {
  logicalId: string;
  type: string;
  id: string;
  reason: string;
  encoded: boolean;
  appliesTo: unknown;
}

/** Every `Metadata.cdk_nag.rules_to_suppress` entry in one committed template. */
function suppressionEntries(stack: string): SuppressionEntry[] {
  const template = JSON.parse(templateText(stack));
  const out: SuppressionEntry[] = [];
  for (const [logicalId, resource] of Object.entries<any>(template.Resources ?? {})) {
    for (const entry of resource?.Metadata?.cdk_nag?.rules_to_suppress ?? []) {
      out.push({
        logicalId,
        type: resource.Type,
        id: entry.id,
        reason: entry.reason,
        encoded: Boolean(entry.is_reason_encoded),
        appliesTo: entry.applies_to,
      });
    }
  }
  return out;
}

describe('committed template sizes', () => {
  test('every committed template is classified exactly once', () => {
    // A new stack that landed in neither list would be undocumented, and its
    // launch method would be whatever the adopter guessed.
    const committed = fs
      .readdirSync(TEMPLATE_DIR)
      .filter((f) => f.endsWith('.template.json'))
      .map((f) => f.replace('.template.json', ''))
      .sort();
    expect(committed).toEqual([...ALL_STACKS].sort());
  });

  test.each(INLINE_LAUNCHABLE)('%s fits an inline --template-body, with reserve', (stack) => {
    const bytes = templateBytes(stack);
    // Two assertions rather than one, because they fail for different reasons and a
    // reader needs to know which. The hard cap is CloudFormation's; the budget is
    // this repository's early warning, and tripping only the budget means the
    // template still launches inline today.
    expect(bytes).toBeLessThan(INLINE_TEMPLATE_BODY_MAX_BYTES);
    expect(bytes).toBeLessThan(INLINE_TEMPLATE_BUDGET_BYTES);
  });

  test.each(S3_URL_ONLY)('%s is documented as S3-only and still needs to be', (stack) => {
    const bytes = templateBytes(stack);
    // If this fails because the template SHRANK below the cap, that is good
    // news: move it to INLINE_LAUNCHABLE and update the README table.
    expect(bytes).toBeGreaterThan(INLINE_TEMPLATE_BODY_MAX_BYTES);
    expect(bytes).toBeLessThan(S3_TEMPLATE_BODY_MAX_BYTES);
  });

  test.each(S3_URL_ONLY)('README tells adopters to launch %s by URL', (stack) => {
    const readme = fs.readFileSync(README, 'utf-8');
    const row = readme
      .split('\n')
      .find((line) => line.includes(`\`${stack}\``) && line.includes('--template-url'));
    expect(row).toBeDefined();
  });

  test.each(INLINE_LAUNCHABLE)('README tells adopters %s launches inline', (stack) => {
    const readme = fs.readFileSync(README, 'utf-8');
    const row = readme
      .split('\n')
      .find((line) => line.includes(`\`${stack}\``) && line.includes('--template-body'));
    expect(row).toBeDefined();
  });
});

describe('committed templates stay indented', () => {
  // The regression this whole file exists for had no gate at all, and the size
  // assertions above cannot be it: suppressing indentation SHRINKS every template,
  // so it makes them pass more easily. These two tests are the ones that fail.
  //
  // WHAT BREAKS THEM: setting `@aws-cdk/core:suppressTemplateIndentation` to true in
  // cdk.json's context and re-running `npm run synth`. `Stack._synthesizeTemplate`
  // then passes `indent = undefined` to `JSON.stringify`, the whole template becomes
  // one line, and trivy v0.69.3 panics on all five rather than scanning them.
  test.each(ALL_STACKS)('%s contains newlines', (stack) => {
    expect(templateText(stack)).toContain('\n');
  });

  test.each(ALL_STACKS)('%s averages well under one line per %i bytes', (stack) => {
    const text = templateText(stack);
    const lines = text.split('\n').length;
    // Reported as the ratio, not as a bare boolean, so a failure message says how
    // far off it is: a suppressed-indentation template lands at the file size.
    expect(Math.round(Buffer.byteLength(text, 'utf8') / lines)).toBeLessThan(
      MAX_BYTES_PER_LINE,
    );
  });
});

describe('the shipped cdk-nag suppression population', () => {
  test.each(Object.entries(SUPPRESSION_ENTRIES))(
    '%s ships exactly %i suppression entries',
    (stack, expected) => {
      expect(suppressionEntries(stack as string)).toHaveLength(expected as number);
    },
  );

  test('the five templates ship 89 suppression entries between them', () => {
    const total = ALL_STACKS.reduce((n, stack) => n + suppressionEntries(stack).length, 0);
    expect(total).toBe(SUPPRESSION_ENTRIES_TOTAL);
    // Non-vacuity for the map above: a typo that made every count 0 would satisfy
    // each per-stack test and this one would still catch it only if the map and the
    // constant disagree, so assert they agree by construction rather than by luck.
    expect(Object.values(SUPPRESSION_ENTRIES).reduce((a, b) => a + b, 0)).toBe(
      SUPPRESSION_ENTRIES_TOTAL,
    );
  });

  test('no shipped reason is base64-encoded', () => {
    // cdk-nag encodes any reason containing a non-ASCII character and records that
    // it did with a sibling `is_reason_encoded`. An encoded reason reaches an adopter
    // as an opaque blob in a public template, and costs 4 bytes per 3 doing it.
    // WHAT BREAKS THIS: one em dash, curly quote or non-breaking space in any reason
    // string in lib/ash-nag-suppressions.ts. `main` shipped 53 of these.
    const encoded = ALL_STACKS.flatMap((stack) =>
      suppressionEntries(stack)
        .filter((e) => e.encoded)
        .map((e) => `${stack}/${e.logicalId} ${e.id}`),
    );
    expect(encoded).toEqual([]);
  });

  test('every shipped reason is plain printable ASCII', () => {
    // NOT a second detector for the test above, and it is worth being exact about
    // that: putting an em dash back into a reason does NOT trip this one, because
    // cdk-nag base64-encodes it and base64 is ASCII. Verified by doing exactly that as
    // a negative control -- `no shipped reason is base64-encoded` fired and this one
    // passed.
    //
    // So this is the guard for the OTHER direction: a future cdk-nag that stops
    // encoding, or stops setting `is_reason_encoded`, and writes the raw character into
    // the template. That would leave the flag-based test above passing over an artifact
    // whose reasons are no longer ASCII. It cannot be tripped from this repository's
    // source while cdk-nag 2.38.2's encoding behavior holds.
    for (const stack of ALL_STACKS) {
      for (const entry of suppressionEntries(stack)) {
        expect(entry.reason).toMatch(/^[\x20-\x7E]+$/);
      }
    }
  });

  test('no shipped entry uses applies_to', () => {
    // `appliesTo` is what the header of lib/ash-nag-suppressions.ts refuses: it
    // embeds CDK logical ids, and a stale one fails OPEN -- the suppression stops
    // matching, or matches something else. It is also what makes the throw-absorption
    // rule in that file hold: `NagSuppressionHelper.doesApply` short-circuits to true
    // for a suppression with no `appliesTo`, so banning it app-wide is what makes an
    // `AwsSolutions-IAM5` entry absorb an IAM5 validation failure predictably.
    const granular = ALL_STACKS.flatMap((stack) =>
      suppressionEntries(stack)
        .filter((e) => e.appliesTo !== undefined)
        .map((e) => `${stack}/${e.logicalId} ${e.id}`),
    );
    expect(granular).toEqual([]);
  });

  test('every suppression sits on a resource type some rule in use evaluates', () => {
    // The fan-out's fingerprint. `applyToChildren` wrote IAM5 reasons onto
    // `AWS::IAM::Role` resources, and a role is not something IAM5 reads a policy
    // document off -- `IAM_POLICY_DOCUMENT_TYPES` in lib/ash-nag-suppressions.ts is
    // the same claim from the other side. Measured on `main`: 20 of the 129 entries
    // sat on roles.
    const offenders = ALL_STACKS.flatMap((stack) =>
      suppressionEntries(stack)
        .filter((e) => !SUPPRESSIBLE_RESOURCE_TYPES.includes(e.type))
        .map((e) => `${stack}/${e.logicalId} [${e.type}] ${e.id}`),
    );
    expect(offenders).toEqual([]);
  });

  test('lib/ names neither applyToChildren nor appliesTo outside prose', () => {
    // The source-side half. The artifact tests above catch the fan-out by its
    // consequences; this one fails the moment someone types the property, with a
    // message that names the file.
    //
    // Both identifiers appear many times in this repository's PROSE, explaining why
    // they are refused, so block comments and whole-line `//` comments are stripped
    // first. The strip is deliberately conservative -- it never touches a `//` that
    // appears mid-line, which could be inside a string -- and the non-vacuity
    // assertion below is what stops a strip that ate the whole file from passing.
    const files = fs.readdirSync(LIB_DIR).filter((f) => f.endsWith('.ts'));
    expect(files.length).toBeGreaterThan(0);
    let sawSuppressionCall = false;
    for (const file of files) {
      const code = fs
        .readFileSync(path.join(LIB_DIR, file), 'utf8')
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .split('\n')
        .filter((line) => !line.trimStart().startsWith('//'))
        .join('\n');
      if (code.includes('addResourceSuppressions')) {
        sawSuppressionCall = true;
      }
      expect(code).not.toContain('applyToChildren');
      expect(code).not.toContain('appliesTo');
    }
    // If the comment strip were too greedy the loop above would assert nothing at
    // all and still pass. This is the control: the call the helpers are built on has
    // to survive the strip.
    expect(sawSuppressionCall).toBe(true);
  });
});

describe('the suppressions whose placement is load-bearing', () => {
  test('AshAgentCore/RuntimeRole/LogsAccess keeps its CdkNagValidationFailure entry', () => {
    // IAM5 THROWS on this policy -- its ARNs are assembled from pseudo-parameters --
    // so cdk-nag emits SUPPRESSED_ERROR and writes no SUPPRESSED row. Anything
    // counting only SUPPRESSED reads the entry as unused; dropping it on that reading
    // turns a SUPPRESSED_ERROR into an ERROR and fails synth. This is the negative
    // control from the header, held as an assertion.
    const entries = suppressionEntries('AshAgentCore').filter((e) =>
      e.logicalId.startsWith('RuntimeRoleLogsAccess'),
    );
    expect(entries.map((e) => e.id)).toEqual(['CdkNagValidationFailure']);
  });

  test('AshAgentCore/RuntimeRole/LogsAccess carries no AwsSolutions-IAM5 entry', () => {
    // The half that used to hold only by accident. `NagPack.ignoreRule` matches a
    // validation failure on EITHER the rule's own id or `CdkNagValidationFailure`,
    // and returns on the FIRST match in `rules_to_suppress` order. So an IAM5 entry
    // added here would absorb the throw ahead of the entry above, and the template
    // would ship a wildcard enumeration as the explanation for a rule that could not
    // run. `AGENTCORE_WILDCARD_POLICIES` leaves `LogsAccess` out for exactly this
    // reason; this asserts it instead of trusting the comment.
    const ids = suppressionEntries('AshAgentCore')
      .filter((e) => e.logicalId.startsWith('RuntimeRoleLogsAccess'))
      .map((e) => e.id);
    expect(ids).not.toContain('AwsSolutions-IAM5');
  });

  test('no resource carries both a rule entry and a CdkNagValidationFailure entry', () => {
    // Generalizes the test above to the whole app. Two candidates on one resource
    // makes which reason gets recorded against a throw depend on the order the
    // helpers happened to run in, and the loser is metadata in a public template that
    // no code path can read.
    const doubled: string[] = [];
    for (const stack of ALL_STACKS) {
      const byResource = new Map<string, string[]>();
      for (const entry of suppressionEntries(stack)) {
        byResource.set(entry.logicalId, [...(byResource.get(entry.logicalId) ?? []), entry.id]);
      }
      for (const [logicalId, ids] of byResource) {
        if (ids.includes('CdkNagValidationFailure') && ids.some((id) => id !== 'CdkNagValidationFailure')) {
          doubled.push(`${stack}/${logicalId}: ${ids.join(', ')}`);
        }
      }
    }
    expect(doubled).toEqual([]);
  });

  test('the AshFargate task execution role does not carry the CodeBuild reason', () => {
    // It used to. `suppressCodeBuildRoleWildcards` was applied to this role, so the
    // template shipped a justification naming a per-build log stream, a report group
    // and S3 object keys on an ECS task execution role that has none of them. Its one
    // IAM5 finding is `Resource::*` on `ecr:GetAuthorizationToken`.
    //
    // WHAT BREAKS THIS: pointing that helper at this role again, or widening
    // `suppressTaskExecutionRoleWildcard`'s reason to mention CodeBuild.
    const entries = suppressionEntries('AshFargate').filter((e) =>
      e.logicalId.startsWith('TaskDefinitionExecutionRoleDefaultPolicy'),
    );
    expect(entries).toHaveLength(1);
    expect(entries[0].id).toBe('AwsSolutions-IAM5');
    expect(entries[0].reason).toContain('ecr:GetAuthorizationToken');
    expect(entries[0].reason).not.toMatch(/CodeBuild|report group|log stream/);
  });

  test('a policy with wildcard ACTIONS is suppressed by a reason that names one', () => {
    // AwsSolutions-IAM5 raises a finding per wildcard ACTION as well as per wildcard
    // RESOURCE. `AwsSolutions-IAM5[Action::kms:GenerateDataKey*]` and
    // `[Action::kms:ReEncrypt*]` are the ONLY two findings on every `KmsAccess` policy
    // the per-service split produces, and the reasons used to enumerate four resource
    // wildcards and stop -- so seven KmsAccess policies across five stacks suppressed
    // a finding their justification never mentioned. A suppression without evidence
    // for the thing suppressed is exactly what IAM5 exists to force.
    //
    // The requirement is derived from each policy's own document rather than from a
    // list written here: a policy carrying a wildcard action must be suppressed by a
    // reason that names one of THAT policy's wildcard actions. Policies whose only
    // wildcard is in the resource are not asked for anything, which is why the Lambda
    // log-group reason and the ECR-token reasons pass unchanged.
    //
    // WHAT BREAKS THIS: shortening a shared reason back to a resource-only
    // enumeration, or adding a `grant` whose action family is wildcarded to a role
    // whose reason does not cover that shape.
    let checked = 0;
    for (const stack of ALL_STACKS) {
      const template = JSON.parse(templateText(stack));
      for (const entry of suppressionEntries(stack)) {
        if (entry.id !== 'AwsSolutions-IAM5' || entry.type !== 'AWS::IAM::Policy') continue;
        const document = template.Resources[entry.logicalId].Properties?.PolicyDocument;
        const wildcardActions = ((document?.Statement ?? []) as any[])
          .flatMap((statement) =>
            Array.isArray(statement.Action) ? statement.Action : [statement.Action],
          )
          .filter((action) => typeof action === 'string' && action.includes('*'));
        if (wildcardActions.length === 0) continue;
        checked++;
        expect({
          resource: `${stack}/${entry.logicalId}`,
          namesOneOfItsWildcardActions: wildcardActions.some((action) =>
            entry.reason.includes(action),
          ),
        }).toEqual({ resource: `${stack}/${entry.logicalId}`, namesOneOfItsWildcardActions: true });
      }
    }
    // Non-vacuity. With no wildcard-action policy in the app the loop above asserts
    // nothing, and the KmsAccess and S3Access policies are the population it exists
    // for -- 12 of them at the time of writing.
    expect(checked).toBeGreaterThanOrEqual(12);
  });
});

describe('the entries no rule consults are the known ones', () => {
  test('there are exactly 17, all in AshDistributedPipeline', () => {
    expect(KNOWN_INERT_SUPPRESSIONS).toHaveLength(17);
    // Each prefix has to match exactly one resource carrying exactly one IAM5 entry.
    // A prefix that stopped matching would silently shrink the pinned set, so this
    // asserts the match rather than filtering by it.
    const entries = suppressionEntries('AshDistributedPipeline');
    for (const prefix of KNOWN_INERT_SUPPRESSIONS) {
      const matched = entries.filter((e) => e.logicalId.startsWith(prefix));
      expect({ prefix, ids: matched.map((e) => e.id) }).toEqual({
        prefix,
        ids: ['AwsSolutions-IAM5'],
      });
    }
  });

  test('no other stack ships an entry matching a known-inert prefix', () => {
    // A guard on the SCOPE of the claim above rather than a detector for a defect: the
    // "all 17 are in AshDistributedPipeline" statement is only true while these
    // pipeline-shaped prefixes match nothing in the other four templates. No change to
    // this app trips it -- it would take a construct in another stack being named to
    // collide -- and it is kept because the count above would then be understating
    // rather than because it is likely.
    for (const stack of ALL_STACKS.filter((s) => s !== 'AshDistributedPipeline')) {
      for (const entry of suppressionEntries(stack)) {
        for (const prefix of KNOWN_INERT_SUPPRESSIONS) {
          expect(`${stack}/${entry.logicalId}`).not.toContain(prefix);
        }
      }
    }
  });
});
