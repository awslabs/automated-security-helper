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
    return new secretsmanager.Secret(this, 'McpAuthHeaderSecret', {
      description:
        'Expected value of McpAuthHeaderName. The container is handed this ARN and ' +
        'resolves the value at start, so the secret never enters a task definition or a ' +
        'runtime environment-variable map.',
      secretStringValue: value,
      removalPolicy: RemovalPolicy.DESTROY,
    });
  }

  /**
   * Environment variables for the MCP-serving flavor.
   *
   * `ASH_MCP_HOST` is pinned to `0.0.0.0` because AgentCore requires it and
   * because a container that bound loopback would be unreachable from any load
   * balancer. The DNS-rebinding consequence of that is handled by
   * `McpAllowedHost`, not by the bind address.
   */
  public mcpEnvironment(): Record<string, string> {
    if (!this.statelessHttp || !this.mountPath || !this.allowedHost || !this.authHeaderName || !this.headerAuthCondition) {
      throw new Error('mcpEnvironment() requires includeMcpParameters: true.');
    }
    return {
      ASH_CONFIG: ASH_MATERIALIZED_CONFIG_PATH,
      ASH_BASE_CONFIG_SSM_PARAMETER: this.configParameterNameOrEmpty(),
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
   * Let a principal read the config parameter and the auth secret.
   *
   * Both grants are unconditional even when the corresponding value is a
   * placeholder. That is the price of keeping the resources unconditional, and it
   * grants nothing an adopter did not deploy: the principal can read one
   * parameter and one secret that this stack owns.
   */
  public grantRead(grantee: iam.IGrantable): void {
    this.configParameter.grantRead(grantee);
    this.authSecret.grantRead(grantee);
  }

  /**
   * The documented ceiling on the incoming CloudFormation parameter, re-exported
   * so tests can assert the two numbers have not drifted apart.
   */
  public static get ssmStandardTierMaxBytes(): number {
    return SSM_STANDARD_TIER_MAX_BYTES;
  }
}
