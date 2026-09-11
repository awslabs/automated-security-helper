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
 * The tighter form of the condition names the log group's ARN. Given the way these
 * stacks create log groups, that is a CloudFormation cycle: CDK auto-names them, so
 * the only way to obtain a group's ARN is `Fn::GetAtt` on the group, which would
 * make the key policy reference the groups while the groups reference the key.
 *
 * That is a cycle given auto-naming, not unconditionally, and the difference is
 * worth stating because the unconditional claim is false. Setting an explicit
 * `logGroupName` prefixed with `${AWS::StackName}` would let the condition ARN be
 * built entirely from pseudo-parameters — `arn:${AWS::Partition}:logs:${AWS::Region}:
 * ${AWS::AccountId}:log-group:${AWS::StackName}-*` — with no GetAtt and therefore no
 * cycle. Considered and rejected for its cost: an explicit log-group name makes
 * every subsequent rename a replacement rather than an update, and replacing a log
 * group discards the log data in it. For a set of groups that exist to hold scan
 * output about an adopter's source, that trade is not worth a condition that
 * narrows the boundary from the account to a name prefix within the same account.
 *
 * So the account-scoped variant is what this grants — AWS documents it for exactly
 * this case, "limits the use of the AWS KMS key to the specified account, but it can
 * be used for any log group" — and the boundary it enforces is the account rather
 * than the log group.
 *
 * WHY THE LOG PRODUCERS NEED NO KMS PERMISSION OF THEIR OWN
 * --------------------------------------------------------
 * CloudWatch Logs does the encrypting, on its own service principal. That is what
 * the statement below grants, and it is why no CodeBuild project role, Lambda
 * execution role or ECS task role in these stacks gained a KMS statement.
 *
 * The one producer that does not write under its own workload role is VPC Flow
 * Logs: it writes through a separate delivery role, assumed by
 * `vpc-flow-logs.amazonaws.com`, and if that role needed key access and did not
 * have it the symptom would be silent — the flow log reports enabled, the log group
 * exists, and no records arrive. Checked against AWS documentation rather than
 * assumed:
 *
 *   - The flow-log role's required policy is five `logs:` actions and no KMS at all
 *     ("must include at least the following permissions"):
 *     https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-iam-role.html
 *   - The flow-log troubleshooting page enumerates the causes of `Access error`, and
 *     all three are the logs permissions or the trust relationship. KMS appears on
 *     that page only for the S3 destination:
 *     https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-troubleshooting.html
 *   - Where a flow-log destination's CMK does need a grant — S3 with SSE-KMS — AWS
 *     documents it as a KEY POLICY grant to a service principal, not as a role
 *     permission. So AWS does document this requirement when it applies:
 *     https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-s3-cmk-policy.html
 *
 * One qualification, because the blanket form of this claim is not what AWS says.
 * The CloudWatch Logs encryption page has a "Permissions for reading and writing
 * encrypted log data" section which names `PutLogEvents` and states that such a
 * principal "needs additional AWS KMS permissions", scoped by
 * `kms:ViaService: logs.<region>.amazonaws.com`. That describes the caller-attributed
 * route, where a principal's own credentials are forwarded to KMS; the statement
 * below is the service-principal route, which the same page's Step 2 introduces as
 * giving "the CloudWatch Logs service principal ... permission to use the key". This
 * key grants the service-principal route, so producers need nothing — but the reason
 * is that grant, not a general rule that log producers never need KMS.
 * https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html
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

  /**
   * An alias, so the key that outlives the stack is not just a uuid.
   *
   * `RemovalPolicy.RETAIN` above means a stack delete leaves the key behind. Without
   * an alias, what an operator then sees in the console and in `aws kms list-keys`
   * is a uuid whose only distinguishing feature is its description — and the README
   * tells them to consider cleaning it up. An alias makes it navigable, and makes
   * CloudTrail entries for key use legible while the stack is running.
   *
   * WHY THE NAME COMES FROM `AWS::StackName`
   * A fixed name would collide: two ASH deployments in one account are two stacks,
   * and the second launch would fail with `AlreadyExistsException` on the alias.
   * CloudFormation admits no two stacks of the same name in one region, so keying
   * the alias to the stack name is collision-free by construction rather than by
   * convention.
   *
   * WHY THE ALIAS IS *NOT* RETAINED, THOUGH THE KEY IS
   * The tempting symmetry is wrong. A retained alias would keep labelling the
   * retained key after a stack delete, but it would also make relaunching a stack of
   * the same name fail on `AlreadyExistsException`, with nothing in the template
   * explaining why — a harder trap than the one it fixes, and one that would strand
   * an adopter mid-launch. So the alias goes with the stack, and the after-delete
   * case is carried by the key's own description, which names the stack and cannot
   * be orphaned.
   */
  new kms.Alias(scope, 'EncryptionKeyAlias', {
    aliasName: `alias/ash-${Aws.STACK_NAME}`,
    targetKey: key,
  });

  return key;
}
