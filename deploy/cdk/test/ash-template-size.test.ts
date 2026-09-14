/**
 * The committed templates are the deliverable, so their SIZE is part of the
 * contract.
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
 * Consequence for this file: if path metadata is ever re-enabled, these two
 * templates go back over the cap and this test is what will say so.
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
 * AshFargate 74, AshImagePipeline 33. A security scanner that cannot read the
 * deliverable is worse than a deliverable that needs an S3 upload, and shipping an
 * artifact that crashes the scanner this repository is built around is not a
 * trade-off worth making for bytes.
 *
 * MEASURED AND REJECTED: unindenting per stack. Only the two inline templates need
 * the bytes, so leaving the other three indented sounds like it confines the damage.
 * It does not -- AshAgentCore has 17 IAM policy-document sites on that same adapter
 * path and panics on its own.
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
 * policies. Across the five templates that produced 298 suppression entries of which
 * 225 were never consulted by any rule. Narrowing each helper to the resources that
 * consume it leaves 89 entries, changes no verdict, and recovers 13,232 bytes from
 * AshAgentCore and 8,984 from AshCodeCommitGate. lib/ash-nag-suppressions.ts has the
 * mechanism and the per-helper reasoning.
 *
 * The classification is cdk-nag's own per-(rule, resource) verdict, captured by
 * wrapping the six `INagLogger` callbacks on `AnnotationLogger.prototype`, and NOT a
 * reading of which rule looks applicable. That distinction is load-bearing: when a
 * rule THROWS on a resource cdk-nag emits SUPPRESSED_ERROR and writes no SUPPRESSED
 * row, so `AshAgentCore/RuntimeRole/LogsAccess` -- where IAM5 throws -- looks unused
 * to anything counting only SUPPRESSED. Dropping its entry on that reading turns a
 * SUPPRESSED_ERROR into an ERROR. Verified by running exactly that as a negative
 * control before relying on the narrowing.
 *
 * The em-dash fix went with it, for the same defect class rather than for size.
 * cdk-nag base64-encodes any reason containing a non-ASCII character, which spends 4
 * bytes per 3 and reaches the adopter as an opaque blob. The app now synthesizes zero
 * `"is_reason_encoded": true` entries; `.ash/.ash.yaml` records that from the other
 * side.
 *
 * WHAT THE FIVE TEMPLATES MEASURE NOW, against a 51,200-byte cap:
 *
 *   AshAgentCore            49,675   under by   1,525
 *   AshCodeCommitGate       46,701   under by   4,499
 *   AshDistributedPipeline 156,350   over  by 105,150
 *   AshFargate              69,107   over  by  17,907
 *   AshImagePipeline        62,041   over  by  10,841
 *
 * READ THE AGENTCORE MARGIN AS THIN, BECAUSE IT IS: 1,525 bytes, 3.0% of the cap, on
 * a stack whose suppression metadata grows with every resource added. A new resource
 * needing an IAM5 suppression costs roughly 550 bytes indented plus its own body, so
 * about two of them exhaust the headroom. This test is what will say so first.
 *
 * The answer at that point is NOT to unindent -- that is the trivy panic above -- and
 * is probably not more prose-tightening either, since the fan-out is already gone. The
 * remaining honest moves are narrowing the 17 suppressions still written where the
 * rule merely passes (all of them in AshDistributedPipeline today, so they buy
 * AshAgentCore nothing) or reclassifying AshAgentCore as S3-only. Reclassifying costs
 * the inline set half its members and is a README change, not just a list edit.
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
 * The same page puts a template passed by S3 URL at 1 MB, which is why the
 * oversized templates have a launch path at all rather than a defect.
 */
const S3_TEMPLATE_BODY_MAX_BYTES = 1_048_576;

/** Launchable with `--template-body`. Keep in step with README.md. */
const INLINE_LAUNCHABLE = ['AshAgentCore', 'AshCodeCommitGate'];

/** Must be uploaded and launched with `--template-url`. Keep in step with README.md. */
const S3_URL_ONLY = ['AshDistributedPipeline', 'AshFargate', 'AshImagePipeline'];

const TEMPLATE_DIR = path.join(__dirname, '..', 'templates');
const README = path.join(__dirname, '..', 'README.md');

function templateBytes(stack: string): number {
  return fs.statSync(path.join(TEMPLATE_DIR, `${stack}.template.json`)).size;
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
    expect(committed).toEqual([...INLINE_LAUNCHABLE, ...S3_URL_ONLY].sort());
  });

  test.each(INLINE_LAUNCHABLE)('%s fits an inline --template-body', (stack) => {
    const bytes = templateBytes(stack);
    expect(bytes).toBeLessThan(INLINE_TEMPLATE_BODY_MAX_BYTES);
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
