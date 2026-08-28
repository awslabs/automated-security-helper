/**
 * AgentCore is the target with the least forgiving contract, so these tests
 * assert the specific values that make it work rather than that a runtime exists.
 *
 * Each assertion below corresponds to a documented requirement. If AgentCore's
 * contract changes, one of these should fail and point at what to re-read.
 */

import { App, Stack } from 'aws-cdk-lib';
import { Capture, Match, Template } from 'aws-cdk-lib/assertions';

import { AshAgentCoreStack } from '../lib/ash-agentcore-stack';
import { ASH_PARAMETER_NAMES, DEFAULT_REBUILD_SCHEDULE } from '../lib/ash-config';

function synth(): Template {
  const app = new App({ analyticsReporting: false });
  return Template.fromStack(new AshAgentCoreStack(app, 'AshAgentCore'));
}

describe('AgentCore runtime contract', () => {
  const template = synth();

  test('the runtime declares the MCP protocol as a plain string', () => {
    // ProtocolConfiguration is `MCP | HTTP | A2A | AGUI`, a String — not an
    // object with a nested ServerProtocol. Asserting the string catches a
    // regression to the object shape, which would synthesize cleanly and fail at
    // deploy.
    template.hasResourceProperties('AWS::BedrockAgentCore::Runtime', {
      ProtocolConfiguration: 'MCP',
    });
  });

  test('the container image comes from an ECR repository in this template', () => {
    // The image must be the one this stack builds. A literal registry URI here
    // would mean ASH was being pulled from somewhere the adopter does not
    // control, which is the thing this whole design exists to avoid.
    const uri = new Capture();
    template.hasResourceProperties('AWS::BedrockAgentCore::Runtime', {
      AgentRuntimeArtifact: { ContainerConfiguration: { ContainerUri: uri } },
    });
    const rendered = JSON.stringify(uri.asObject());
    expect(rendered).toContain('dkr.ecr');
    expect(rendered).toContain('AWS::URLSuffix');
    // The moving MCP tag for the ARM64 build.
    expect(rendered).toContain('mcp-arm64');
  });

  test('the image is built for ARM64, which AgentCore requires', () => {
    // ARM64 shows up as the build compute type, because a native ARM image needs
    // ARM compute. ARM_CONTAINER is the CodeBuild environment type that provides it.
    template.hasResourceProperties('AWS::CodeBuild::Project', {
      Environment: Match.objectLike({ Type: 'ARM_CONTAINER' }),
    });
  });

  test('the baked entrypoint binds 0.0.0.0:8000 and posts to /mcp', () => {
    // The command cannot be a template property — ContainerConfiguration has only
    // ContainerUri — so it is asserted where it actually lives: the buildspec that
    // bakes the entrypoint into the image.
    const spec = new Capture();
    template.hasResourceProperties('AWS::CodeBuild::Project', {
      Source: Match.objectLike({ BuildSpec: spec }),
    });
    const buildSpec = JSON.stringify(spec.asObject());
    expect(buildSpec).toContain('ash mcp --transport streamable-http');
    expect(buildSpec).toContain('ASH_MCP_HOST:-0.0.0.0');
    expect(buildSpec).toContain('ASH_MCP_PORT:-8000');
    expect(buildSpec).toContain('ASH_MCP_MOUNT_PATH:-/mcp');
    // The buildspec is embedded as a JSON string, so quotes inside it arrive
    // escaped. Assert on the quote-free parts and leave the literal ENTRYPOINT
    // line to the ash-container-scripts test, which reads the source constant.
    expect(buildSpec).toContain('ENTRYPOINT');
    expect(buildSpec).toContain('ash-mcp-entrypoint.sh');
  });

  test('stateless HTTP defaults to true', () => {
    // AgentCore injects its own Mcp-Session-Id. A stateful ASH answers 404 to a
    // session it never issued, so this default is the difference between a
    // working runtime and one that fails every request.
    template.hasParameter(ASH_PARAMETER_NAMES.mcpStatelessHttp, {
      Default: 'true',
      AllowedValues: ['true', 'false'],
    });
    template.hasResourceProperties('AWS::BedrockAgentCore::Runtime', {
      EnvironmentVariables: Match.objectLike({
        ASH_MCP_STATELESS: { Ref: ASH_PARAMETER_NAMES.mcpStatelessHttp },
      }),
    });
  });

  test('the entrypoint passes the stateless flag in both directions', () => {
    // Relying on ASH's own default would break silently if that default changed.
    const spec = new Capture();
    template.hasResourceProperties('AWS::CodeBuild::Project', {
      Source: Match.objectLike({ BuildSpec: spec }),
    });
    const buildSpec = JSON.stringify(spec.asObject());
    expect(buildSpec).toContain('--stateless-http');
    expect(buildSpec).toContain('--no-stateless-http');
  });

  test('the runtime name contains no hyphens', () => {
    // AgentRuntimeName is matched against [a-zA-Z][a-zA-Z0-9_]{0,47}. Stack names
    // routinely contain hyphens, so they must be stripped rather than passed on.
    const name = new Capture();
    template.hasResourceProperties('AWS::BedrockAgentCore::Runtime', {
      AgentRuntimeName: name,
    });
    expect(JSON.stringify(name.asObject())).toEqual(
      JSON.stringify({ 'Fn::Join': ['', { 'Fn::Split': ['-', { Ref: 'AWS::StackName' }] }] }),
    );
  });

  test('the execution role trusts only AgentCore, scoped to this account', () => {
    template.hasResourceProperties('AWS::IAM::Role', {
      AssumeRolePolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: 'sts:AssumeRole',
            Principal: { Service: 'bedrock-agentcore.amazonaws.com' },
            Condition: Match.objectLike({
              StringEquals: { 'aws:SourceAccount': { Ref: 'AWS::AccountId' } },
            }),
          }),
        ]),
      }),
    });
  });

  test('the auth header is allowlisted only when auth is configured', () => {
    // A custom header does not reach the container unless the runtime allowlists
    // it. Guarding with Fn::If keeps the allowlist absent — not empty — when no
    // header is set, because an empty entry fails AgentCore's own pattern.
    const cfg = new Capture();
    template.hasResourceProperties('AWS::BedrockAgentCore::Runtime', {
      RequestHeaderConfiguration: cfg,
    });
    const rendered = cfg.asObject() as Record<string, unknown>;
    expect(Object.keys(rendered)).toEqual(['Fn::If']);
    const branches = (rendered['Fn::If'] as unknown[]);
    expect(branches[1]).toEqual({
      RequestHeaderAllowlist: [{ Ref: ASH_PARAMETER_NAMES.mcpAuthHeaderName }],
    });
    expect(branches[2]).toEqual({ Ref: 'AWS::NoValue' });
  });

  test('the runtime waits for the bootstrap build', () => {
    // Without this the runtime is created against an empty repository.
    const runtimes = template.findResources('AWS::BedrockAgentCore::Runtime');
    const [runtime] = Object.values(runtimes);
    const bootstraps = Object.keys(
      template.findResources('Custom::AshImageBootstrap'),
    );
    expect(bootstraps).toHaveLength(1);
    expect(runtime.DependsOn).toContain(bootstraps[0]);
  });

  test('the rebuild runs on the parameterized schedule', () => {
    // The default is referenced rather than spelled out here. This test is about
    // the rule reading the parameter; what the default may and may not be is
    // pinned in ash-image-build-scheduling.test.ts, which is also where the
    // reason lives — a rate() default fired on rule creation and raced the
    // bootstrap build.
    template.hasParameter(ASH_PARAMETER_NAMES.rebuildSchedule, {
      Default: DEFAULT_REBUILD_SCHEDULE,
    });
    template.hasResourceProperties('AWS::Events::Rule', {
      ScheduleExpression: { Ref: ASH_PARAMETER_NAMES.rebuildSchedule },
    });
  });

  test('the secret value is never written into the runtime environment', () => {
    // Only the ARN travels. If the value itself appeared here it would be
    // readable from the runtime's configuration.
    const env = new Capture();
    template.hasResourceProperties('AWS::BedrockAgentCore::Runtime', {
      EnvironmentVariables: env,
    });
    const rendered = JSON.stringify(env.asObject());
    expect(rendered).toContain('ASH_MCP_AUTH_HEADER_VALUE_SECRET_ARN');
    expect(rendered).not.toContain(`{"Ref":"${ASH_PARAMETER_NAMES.mcpAuthHeaderValue}"}`);
  });

  test('the auth header value parameter is NoEcho', () => {
    template.hasParameter(ASH_PARAMETER_NAMES.mcpAuthHeaderValue, { NoEcho: true });
  });

  test('the config document lands in an Advanced-tier SSM parameter', () => {
    // Advanced holds 8 KB against Standard's 4 KB, which is the documented escape
    // hatch for a config larger than a CloudFormation parameter can carry.
    template.hasResourceProperties('AWS::SSM::Parameter', { Tier: 'Advanced' });
  });
});

describe('AgentCore template portability', () => {
  test('no account id, and account references are pseudo-parameters', () => {
    const app = new App({ analyticsReporting: false });
    const stack: Stack = new AshAgentCoreStack(app, 'AshAgentCore');
    const json = JSON.stringify(Template.fromStack(stack).toJSON());

    // A 12-digit run is what an AWS account id looks like. This repository is
    // public, so one appearing in a committed template is a disclosure, not a
    // cosmetic problem.
    expect(json).not.toMatch(/\b\d{12}\b/);
    expect(json).toContain('AWS::AccountId');
  });

  test('no CDK asset parameters, so the template needs no bootstrap', () => {
    const app = new App({ analyticsReporting: false });
    const template = Template.fromStack(new AshAgentCoreStack(app, 'AshAgentCore'));
    const parameters = Object.keys(template.toJSON().Parameters ?? {});
    expect(parameters.filter((p) => p.startsWith('AssetParameters'))).toHaveLength(0);
    expect(parameters).not.toContain('BootstrapVersion');
  });
});
