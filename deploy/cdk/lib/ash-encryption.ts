/**
 * The one customer-managed key each ASH stack owns, and everything that has to
 * be true for CloudWatch Logs to use it.
 *
 * WHY THIS IS A FUNCTION AND NOT FIVE COPIES OF `new kms.Key(...)`
 * ---------------------------------------------------------------
 * Every stack here already created an identical key for its CodeBuild projects.
 * Encrypting the log groups with the same key adds a key-policy statement that is
 * easy to write once and easy to forget on the sixth log group — and forgetting it
 * does not fail synth, it fails at deploy time with CloudWatch Logs refusing the
 * association. Creating the key and granting the log service in the same place
 * means a stack cannot have one without the other.
 *
 * The construct id is still `EncryptionKey` under the stack, so the logical id in
 * every committed template is unchanged by the move.
 *
 * WHY ONE KEY PER STACK RATHER THAN ONE PER LOG GROUP
 * --------------------------------------------------
 * AWS recommends a key per encrypted log group
 * (https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html),
 * and this deliberately does not follow that. The recommendation exists so that a
 * key policy can be narrowed to a single log group ARN; here every log group in a
 * stack sits inside one trust boundary — the same operators read all of them, and
 * the CodeBuild output the key already protects is the same material — so the
 * isolation a second key would buy is nil. The cost is not: a key per log group
 * would be six keys in the Fargate stack alone, each with a standing monthly
 * charge and its own policy to keep correct.
 *
 * WHY THE ENCRYPTION-CONTEXT CONDITION IS ACCOUNT-SCOPED
 * -----------------------------------------------------
 * The tighter form of the condition names the log group's ARN. It cannot be used
 * here: the key policy would reference the log groups, the log groups reference
 * the key, and CloudFormation rejects the cycle. AWS documents the account-scoped
 * variant for exactly this case — "limits the use of the AWS KMS key to the
 * specified account, but it can be used for any log group" — so that is what this
 * grants, and the boundary it enforces is the account rather than the log group.
 *
 * WHAT THE DEPLOYING PRINCIPAL NEEDS
 * ----------------------------------
 * `kms:DescribeKey` on this key. CloudWatch Logs requires it of whoever calls
 * `CreateLogGroup` with a `kmsKeyId`, and without it the log group fails to
 * create rather than being created unencrypted. The key's default policy grants
 * the account root `kms:*`, so any principal in the account whose own identity
 * policy allows KMS — which a console-launch admin has — satisfies it. A
 * deployment role with KMS carved out of it does not, and will fail on the first
 * log group.
 *
 * WHY THE LOG PRODUCERS NEED NO KMS PERMISSION OF THEIR OWN
 * --------------------------------------------------------
 * CloudWatch Logs does the encrypting, on its own service principal. A CodeBuild
 * project, a Lambda function or an ECS task writing into an encrypted group needs
 * nothing added to its role — which is why none of the roles in these stacks grew
 * a KMS statement for this.
 */

import { Aws, RemovalPolicy, Stack } from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';

/**
 * Create the stack's key and let CloudWatch Logs encrypt with it.
 *
 * Rotation is on. The key protects build output and log data, neither of which is
 * read by anything outside the stack, so a rotated key needs no coordination —
 * and CloudWatch Logs keeps decrypting data written under an earlier rotation of
 * the same key.
 *
 * RETAIN, because a deleted key takes every log group encrypted with it beyond
 * recovery. AWS states it plainly: "If you revoke CloudWatch Logs access to an
 * associated key or delete an associated KMS key, your encrypted data in
 * CloudWatch Logs can no longer be retrieved."
 */
export function ashEncryptionKey(scope: Stack): kms.Key {
  const key = new kms.Key(scope, 'EncryptionKey', {
    // Console-visible, and once the stack is gone this is most of what identifies
    // the key that outlived it. Two deliberate choices:
    //
    //   - It does not enumerate what it encrypts. It used to end "and the MCP auth
    //     secret", which is not true of AshImagePipeline: that stack has no
    //     AWS::SecretsManager::Secret and its key policy has exactly two statements.
    //     Keeping an enumeration true would mean threading a per-stack list through
    //     five call sites for a description field, and the actual coverage is
    //     readable from the key policy and from the `encryptionKey` arguments in
    //     lib/. So the field says what the key is, not what it happens to cover.
    //   - It names the stack. `AWS::StackName` renders as a pseudo-parameter, so it
    //     costs nothing in reproducibility and it is what makes a RETAINed key
    //     attributable to the deployment that created it after that deployment has
    //     been deleted.
    description:
      `Customer-managed key for the ASH stack ${Aws.STACK_NAME}. Encrypts every resource ` +
      'in that stack which accepts one. Retained when the stack is deleted, because ' +
      'deleting it would put the log data encrypted with it beyond recovery.',
    enableKeyRotation: true,
    removalPolicy: RemovalPolicy.RETAIN,
  });

  key.addToResourcePolicy(
    new iam.PolicyStatement({
      sid: 'AllowCloudWatchLogsEncryption',
      // Regional, not `logs.amazonaws.com`. CloudWatch Logs documents the
      // regionalized principal and adds that it "must be in the same AWS Region
      // where the KMS key is stored".
      principals: [new iam.ServicePrincipal(`logs.${Aws.REGION}.amazonaws.com`)],
      actions: [
        'kms:Encrypt',
        'kms:Decrypt',
        'kms:ReEncrypt*',
        'kms:GenerateDataKey*',
        'kms:Describe*',
      ],
      // A key policy's Resource is the key itself; "*" is the only value
      // CloudFormation accepts here and does not widen anything.
      resources: ['*'],
      conditions: {
        ArnLike: {
          'kms:EncryptionContext:aws:logs:arn': `arn:${Aws.PARTITION}:logs:${Aws.REGION}:${Aws.ACCOUNT_ID}:*`,
        },
      },
    }),
  );

  return key;
}
