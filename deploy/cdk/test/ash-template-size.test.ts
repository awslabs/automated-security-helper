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
