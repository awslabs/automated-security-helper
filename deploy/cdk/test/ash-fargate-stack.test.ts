import { App } from 'aws-cdk-lib';
import { Capture, Match, Template } from 'aws-cdk-lib/assertions';

import { ASH_PARAMETER_NAMES } from '../lib/ash-config';
import { AshFargateStack } from '../lib/ash-fargate-stack';

const template = Template.fromStack(
  new AshFargateStack(new App({ analyticsReporting: false }), 'AshFargate'),
);

describe('Fargate MCP service', () => {
  test('the container listens on 8000 with the MCP image from this account', () => {
    const defs = new Capture();
    template.hasResourceProperties('AWS::ECS::TaskDefinition', {
      ContainerDefinitions: defs,
    });
    const rendered = JSON.stringify(defs.asArray());
    expect(rendered).toContain('"ContainerPort":8000');
    expect(rendered).toContain('mcp-amd64');
    expect(rendered).toContain('dkr.ecr');
  });

  test('DNS-rebinding protection stays on by defaulting the allowed host to the ALB', () => {
    // Binding 0.0.0.0 relaxes the MCP SDK's protection. Behind an ALB the Host
    // header is the ALB's own DNS name and that name is knowable, so
    // --allowed-host can keep the check enabled instead of switching it off.
    const defs = new Capture();
    template.hasResourceProperties('AWS::ECS::TaskDefinition', {
      ContainerDefinitions: defs,
    });
    const rendered = JSON.stringify(defs.asArray());
    expect(rendered).toContain('ASH_MCP_ALLOWED_HOST');
    expect(rendered).toContain('DNSName');
    expect(rendered).toContain(ASH_PARAMETER_NAMES.mcpAllowedHost);
  });

  test('the health check tolerates the MCP path answering only POST', () => {
    // A GET against the mount path is not a valid MCP request, so a default
    // 200-only check would fail a healthy server. 400-405 proves the process is
    // up and speaking HTTP.
    template.hasResourceProperties('AWS::ElasticLoadBalancingV2::TargetGroup', {
      Matcher: { HttpCode: '200,400-405' },
      Port: 8000,
    });
  });

  test('the load balancer is internal by default', () => {
    // The endpoint accepts source code and returns findings about it. Public by
    // default behind nothing but an optional header would be the wrong thing to
    // inherit.
    template.hasResourceProperties('AWS::ElasticLoadBalancingV2::LoadBalancer', {
      Scheme: 'internal',
    });
  });

  test('access logging is enabled without pinning a region', () => {
    const attrs = new Capture();
    template.hasResourceProperties('AWS::ElasticLoadBalancingV2::LoadBalancer', {
      LoadBalancerAttributes: attrs,
    });
    const rendered = JSON.stringify(attrs.asArray());
    expect(rendered).toContain('access_logs.s3.enabled');
    // The modern log-delivery service principal needs no per-region ELB account
    // id, which is what lets these templates stay region-agnostic.
    template.hasResourceProperties('AWS::S3::BucketPolicy', {
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Principal: { Service: 'logdelivery.elasticloadbalancing.amazonaws.com' },
            Action: 's3:PutObject',
          }),
        ]),
      }),
    });
  });

  test('a single task is not stopped during a deployment', () => {
    template.hasResourceProperties('AWS::ECS::Service', {
      DeploymentConfiguration: Match.objectLike({
        MinimumHealthyPercent: 100,
        MaximumPercent: 200,
      }),
    });
  });

  test('the service waits for the bootstrap build', () => {
    const services = template.findResources('AWS::ECS::Service');
    const [service] = Object.values(services);
    const [bootstrap] = Object.keys(template.findResources('Custom::AshImageBootstrap'));
    expect(service.DependsOn).toContain(bootstrap);
  });

  test('the VPC has flow logs', () => {
    template.resourceCountIs('AWS::EC2::FlowLog', 1);
  });

  test('the secret value never reaches the task definition', () => {
    const defs = new Capture();
    template.hasResourceProperties('AWS::ECS::TaskDefinition', {
      ContainerDefinitions: defs,
    });
    const rendered = JSON.stringify(defs.asArray());
    expect(rendered).toContain('ASH_MCP_AUTH_HEADER_VALUE_SECRET_ARN');
    expect(rendered).not.toContain(`{"Ref":"${ASH_PARAMETER_NAMES.mcpAuthHeaderValue}"}`);
  });
});
