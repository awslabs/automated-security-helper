/**
 * Where the two oversized/sensitive parameters actually live, and how the
 * container gets at them.
 *
 * TWO VALUES CANNOT TRAVEL AS PLAIN CONTAINER ENVIRONMENT VARIABLES:
 *
 * 1. `AshBaseConfigYaml` is a whole document. It goes into an SSM parameter and
 *    the container is told the parameter NAME.
 * 2. `McpAuthHeaderValue` is a shared secret. It goes into Secrets Manager and
 *    the container is told the secret ARN. `AWS::BedrockAgentCore::Runtime`
 *    offers only a plain `EnvironmentVariables` map with no secret indirection,
 *    so putting the value there would print it in `DescribeStacks` output and in
 *    the resource's own configuration. Handing over the ARN and resolving it
 *    inside the container is the only way to keep it out of both.
 *
 * WHY BOTH RESOURCES ARE CREATED UNCONDITIONALLY
 * ----------------------------------------------
 * The obvious shape is a CloudFormation Condition that creates the SSM parameter
 * only when the adopter supplied a config. That was tried and rejected: a `Ref`
 * to a conditional resource is only legal inside an `Fn::If` guarded by the same
 * condition, which makes every IAM grant that mentions the resource ARN an
 * invalid template. Instead both resources always exist, their VALUES fall back
 * to a placeholder, and the condition only decides whether the container is told
 * the name/ARN. IAM stays statically valid and the entrypoint treats an empty
 * name as "nothing was supplied".
 *
 * The cost of that choice is one unused Secrets Manager secret (a few cents a
 * month) in deployments that do not enable ASH-level auth. Stated here so nobody
 * has to rediscover why it is there.
 */

import { CfnCondition, CfnParameter, Fn, RemovalPolicy, SecretValue, Stack } from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';

import {
  ashBaseConfigYaml,
  AshCustomerKey,
  mcpAllowedHost,
  mcpAuthHeaderName,
  mcpAuthHeaderValue,
  mcpMountPath,
  mcpStatelessHttp,
  SSM_STANDARD_TIER_MAX_BYTES,
} from './ash-config';
import { ASH_MATERIALIZED_CONFIG_PATH } from './ash-container-scripts';

/** Value stored when the adopter supplied no configuration document. */
const CONFIG_PLACEHOLDER = '# No ASH base configuration was supplied at deployment time.';

/** Value stored when ASH-level header auth is disabled. */
const SECRET_PLACEHOLDER = 'ash-mcp-auth-disabled';

export interface AshMcpRuntimeConfigProps {
  /**
   * Declare the MCP-serving parameters (`McpStatelessHttp`, `McpMountPath`,
   * `McpAllowedHost`, `McpAuthHeaderName`, `McpAuthHeaderValue`).
   *
   * The sharded executor and the pull-request gate do not serve MCP, so they
   * leave this off and get only the config parameter.
   */
  readonly includeMcpParameters: boolean;
  /** The adopter's optional customer-managed key, for the secret at rest. */
  readonly customerKey: AshCustomerKey;
}

/**
 * The SSM/Secrets-Manager backing store plus the environment map every ASH
 * container flavor expects.
 */
export class AshRuntimeConfig extends Construct {
  public readonly configParameter: ssm.StringParameter;
  public readonly authSecret: secretsmanager.Secret;

  /** `AshBaseConfigYaml`, declared once and reused by callers for outputs. */
  public readonly baseConfigYaml: CfnParameter;
  public readonly statelessHttp?: CfnParameter;
  public readonly mountPath?: CfnParameter;
  public readonly allowedHost?: CfnParameter;
  public readonly authHeaderName?: CfnParameter;
  public readonly authHeaderValue?: CfnParameter;

  private readonly hasConfig: CfnCondition;
  private readonly customerKey: AshCustomerKey;
  private readonly includeMcpParameters: boolean;
  /** Created on the first `grantRead`; see `grantCustomerKeyDecrypt`. */
  private customerKeyAccess?: iam.Policy;
  /**
   * True when BOTH `McpAuthHeaderName` and `McpAuthHeaderValue` were supplied.
   *
   * Public because AgentCore needs it for a second, unrelated reason: a custom
   * header only reaches the container if it is in the runtime's request-header
   * allowlist, so the allowlist has to appear exactly when auth is enabled.
   */
  public readonly headerAuthCondition?: CfnCondition;

  constructor(scope: Construct, id: string, props: AshMcpRuntimeConfigProps) {
    super(scope, id);
    const stack = Stack.of(this);
    this.customerKey = props.customerKey;
    this.includeMcpParameters = props.includeMcpParameters;

    this.baseConfigYaml = ashBaseConfigYaml(stack);
    this.hasConfig = new CfnCondition(this, 'HasBaseConfig', {
      expression: Fn.conditionNot(Fn.conditionEquals(this.baseConfigYaml.valueAsString, '')),
    });

    this.configParameter = new ssm.StringParameter(this, 'BaseConfig', {
      description:
        'ASH base configuration document, written to the container at start and applied ' +
        'through ASH_CONFIG. Edit here to change the deployment-wide config without a ' +
        'stack update; the next container start picks it up.',
      stringValue: Fn.conditionIf(
        this.hasConfig.logicalId,
        this.baseConfigYaml.valueAsString,
        CONFIG_PLACEHOLDER,
      ).toString(),
      // Advanced holds 8 KB against Standard's 4 KB. CloudFormation caps the
      // incoming parameter at 4096 bytes either way, so the extra headroom only
      // helps adopters who edit the parameter in place afterwards — which is
      // exactly the documented escape hatch for a config too large to paste.
      // https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-advanced-parameters.html
      tier: ssm.ParameterTier.ADVANCED,
    });

    if (!props.includeMcpParameters) {
      // Still create the secret so the class has one shape, but nothing reads it.
      this.authSecret = this.createAuthSecret(SecretValue.unsafePlainText(SECRET_PLACEHOLDER));
      return;
    }

    this.statelessHttp = mcpStatelessHttp(stack);
    this.mountPath = mcpMountPath(stack);
    this.allowedHost = mcpAllowedHost(stack);
    this.authHeaderName = mcpAuthHeaderName(stack);
    this.authHeaderValue = mcpAuthHeaderValue(stack);

    // Both halves must be present. A name with no value would start a server
    // that compares every request against an empty secret.
    this.headerAuthCondition = new CfnCondition(this, 'HasHeaderAuth', {
      expression: Fn.conditionAnd(
        Fn.conditionNot(Fn.conditionEquals(this.authHeaderName.valueAsString, '')),
        Fn.conditionNot(Fn.conditionEquals(this.authHeaderValue.valueAsString, '')),
      ),
    });

    this.authSecret = this.createAuthSecret(
      SecretValue.unsafePlainText(
        Fn.conditionIf(
          this.headerAuthCondition.logicalId,
          this.authHeaderValue.valueAsString,
          SECRET_PLACEHOLDER,
        ).toString(),
      ),
    );
  }

  /**
   * `unsafePlainText` is accurate but the name overstates the risk here: the
   * value it wraps is a `NoEcho` CloudFormation parameter reference, so what
   * lands in the template is `{"Ref": "McpAuthHeaderValue"}`, not the secret.
   * CDK's `checkSecretUsage` guard exists to stop a resolved secret being
   * embedded in a template, and no resolved secret is being embedded.
   */
  private createAuthSecret(value: SecretValue): secretsmanager.Secret {
    const secret = new secretsmanager.Secret(this, 'McpAuthHeaderSecret', {
      description:
        'Expected value of McpAuthHeaderName. The container is handed this ARN and ' +
        'resolves the value at start, so the secret never enters a task definition or a ' +
        'runtime environment-variable map.',
      secretStringValue: value,
      removalPolicy: RemovalPolicy.DESTROY,
    });

    /*
     * `KmsKeyId` IS SET THROUGH THE L1 AND NOT THROUGH THE L2 `encryptionKey` PROP.
     *
     * This is not a style preference, and doing it the obvious way produces an
     * invalid template. `Secret.grantRead` calls `encryptionKey.grantDecrypt(grantee)`
     * whenever the L2 prop is set, which puts the key ARN into an IAM statement's
     * `Resource` LIST. The ARN here is `Fn::If(HasKmsKey, <ref>, AWS::NoValue)`, and
     * `AWS::NoValue` inside a list removes the ELEMENT rather than the property, so
     * an adopter who supplied no key would get `"Resource": []` on that statement -
     * which CloudFormation rejects. `grantRead` is called on every target, so this
     * would break all four MCP-serving and gate stacks at deploy time while
     * synthesizing cleanly.
     *
     * Setting the property directly keeps the conditional value where it is safe: as
     * an entire property value, where `AWS::NoValue` means "omit this property".
     *
     * The grant `grantRead` would have added is still needed - a principal reading a
     * CMK-encrypted secret needs `kms:Decrypt` on the key ARN in its identity policy.
     * It is added instead by `grantCustomerKeyDecrypt` below, on a policy RESOURCE
     * gated by the same condition, which is the shape that survives an unset key.
     */
    (secret.node.defaultChild as secretsmanager.CfnSecret).addPropertyOverride(
      'KmsKeyId',
      this.customerKey.keyArnOrNoValue,
    );

    return secret;
  }

  /**
   * Environment variables for the MCP-serving flavor.
   *
   * `ASH_MCP_HOST` is pinned to `0.0.0.0` because AgentCore requires it and
   * because a container that bound loopback would be unreachable from any load
   * balancer. The DNS-rebinding consequence of that is handled by
   * `McpAllowedHost`, not by the bind address, or on AgentCore by the
   * `ASH_MCP_TRUST_UPSTREAM_HOST_CHECK` statement that stack adds.
   *
   * `ASH_MCP_TRANSPORT` names the transport the entrypoint starts. ASH reads it as
   * the operator's statement of how it is served, so every caller is treated as
   * remote even on code paths that read the transport from the environment rather
   * than from the running server. The Terraform modules set the same variable.
   */
  public mcpEnvironment(): Record<string, string> {
    if (!this.statelessHttp || !this.mountPath || !this.allowedHost || !this.authHeaderName || !this.headerAuthCondition) {
      throw new Error('mcpEnvironment() requires includeMcpParameters: true.');
    }
    return {
      ASH_CONFIG: ASH_MATERIALIZED_CONFIG_PATH,
      ASH_BASE_CONFIG_SSM_PARAMETER: this.configParameterNameOrEmpty(),
      ASH_MCP_TRANSPORT: 'streamable-http',
      ASH_MCP_HOST: '0.0.0.0',
      ASH_MCP_PORT: '8000',
      ASH_MCP_MOUNT_PATH: this.mountPath.valueAsString,
      ASH_MCP_STATELESS: this.statelessHttp.valueAsString,
      ASH_MCP_ALLOWED_HOST: this.allowedHost.valueAsString,
      ASH_MCP_AUTH_HEADER_NAME: this.authHeaderName.valueAsString,
      ASH_MCP_AUTH_HEADER_VALUE_SECRET_ARN: Fn.conditionIf(
        this.headerAuthCondition.logicalId,
        this.authSecret.secretArn,
        '',
      ).toString(),
    };
  }

  /**
   * The SSM parameter name, or an empty string when no config was supplied.
   *
   * The entrypoint keys off empty rather than off a missing variable so that a
   * deployment which later gains a config needs no image change.
   */
  public configParameterNameOrEmpty(): string {
    return Fn.conditionIf(
      this.hasConfig.logicalId,
      this.configParameter.parameterName,
      '',
    ).toString();
  }

  /**
   * Let a principal read the config parameter, and on the MCP targets the auth
   * secret.
   *
   * The parameter grant is unconditional even when the value is a placeholder.
   * That is the price of keeping the resource unconditional, and it grants nothing
   * an adopter did not deploy: the principal can read one parameter this stack owns.
   *
   * The secret grant follows the secret ARN, which reaches a container only through
   * `mcpEnvironment()`. On the sharded executor and the pull-request gate nothing
   * reads the secret, so they get no `GetSecretValue` on it: on the gate the role
   * that can approve pull requests would otherwise hold a grant no code path uses.
   *
   * The decrypt grant is narrower still: it exists only when `KmsKeyArn` was set,
   * and only on the targets that read the secret. See `grantCustomerKeyDecrypt`.
   */
  public grantRead(grantee: iam.IGrantable): void {
    this.configParameter.grantRead(grantee);
    if (this.includeMcpParameters) {
      this.authSecret.grantRead(grantee);
    }

    /*
     * The decrypt grant follows the secret ARN, not the secret, and so does the
     * `GetSecretValue` grant above.
     *
     * A principal can only need either if something hands it the ARN. The ARN
     * reaches a container through exactly one path, `mcpEnvironment()`, which throws
     * unless `includeMcpParameters` is true. So on the sharded executor and the
     * pull-request gate the secret is the placeholder nothing reads, and a grant
     * there would be permission on a value no code path touches. Verified against
     * the synthesized templates: neither AshCodeCommitGate nor
     * AshDistributedPipeline mentions `ASH_MCP_AUTH_HEADER_VALUE_SECRET_ARN`
     * anywhere. A future change that gives one of those targets the ARN has to move
     * it to `includeMcpParameters: true` to get both grants.
     */
    if (this.includeMcpParameters) {
      this.grantCustomerKeyDecrypt(grantee);
    }
  }

  /**
   * `kms:Decrypt` on the adopter's key, for principals that read the secret.
   *
   * WHY THIS IS A SEPARATE POLICY RESOURCE AND NOT A STATEMENT ON THE ROLE
   * ---------------------------------------------------------------------
   * Because the key ARN is conditional and a statement is not. Adding
   * `kms:Decrypt` to a grantee's existing default policy would put the key ARN in
   * that statement's `Resource` list unconditionally, and there is no value that
   * means "no key": the parameter's empty default would render `"Resource": [""]`,
   * which IAM rejects, and `AWS::NoValue` would render `"Resource": []`, which IAM
   * also rejects. Both synthesize cleanly and fail at deploy.
   *
   * A separate `AWS::IAM::Policy` can carry a CloudFormation `Condition`, so when
   * no key was supplied the whole resource is absent and no invalid statement can
   * exist. The policy is created on the first call rather than in the constructor,
   * so a stack that never grants read emits nothing - and CDK errors on a policy
   * attached to no principal, which would otherwise be the failure.
   *
   * WHY ONLY `kms:Decrypt`, AND ONLY FOR THE SECRET
   * ----------------------------------------------
   * It is the only permission of the four encrypted resource classes that a
   * principal created by this stack actually needs. Verified per service in the
   * `kmsKeyArn` doc comment: CloudWatch Logs wants the SERVICE principal in the key
   * POLICY, and ECR and Lambda want `kms:CreateGrant` on whoever runs the
   * deployment. Granting those here would grant them to the wrong identity and read
   * as though the requirement were met.
   */
  private grantCustomerKeyDecrypt(grantee: iam.IGrantable): void {
    if (!this.customerKeyAccess) {
      // `KeyAccess` rather than a more descriptive id, and no `sid`: both strings
      // land in the template twice over (the logical id is also the PolicyName), and
      // AshAgentCore has under 100 bytes of room beneath CloudFormation's inline
      // template limit. The description is in this comment, where it is free.
      this.customerKeyAccess = new iam.Policy(this, 'KeyAccess', {
        statements: [
          new iam.PolicyStatement({
            actions: ['kms:Decrypt'],
            // The bare parameter ref, NOT `keyArnOrNoValue`. This statement only
            // exists when the condition below is true, so the ref always resolves
            // to a real ARN and no `AWS::NoValue` can reach a list.
            resources: [this.customerKey.parameter.valueAsString],
          }),
        ],
      });
      const cfnPolicy = this.customerKeyAccess.node.defaultChild as iam.CfnPolicy;
      cfnPolicy.cfnOptions.condition = this.customerKey.condition;
    }

    const principal = grantee.grantPrincipal as Partial<iam.IRole>;
    if (typeof principal.attachInlinePolicy !== 'function') {
      // Loud rather than skipped. A grantee that is not a role would silently read
      // the secret and fail to decrypt it, which looks like a Secrets Manager
      // problem rather than a missing KMS grant.
      throw new Error(
        'AshRuntimeConfig.grantRead needs a grantee whose principal is a role, so the ' +
          'conditional kms:Decrypt policy can be attached to it.',
      );
    }
    principal.attachInlinePolicy(this.customerKeyAccess);
  }

  /**
   * The documented ceiling on the incoming CloudFormation parameter, re-exported
   * so tests can assert the two numbers have not drifted apart.
   */
  public static get ssmStandardTierMaxBytes(): number {
    return SSM_STANDARD_TIER_MAX_BYTES;
  }
}
