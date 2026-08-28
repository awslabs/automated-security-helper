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

/**
 * The endpoint is closed on deployment, and the outputs have to say so.
 *
 * An observed stack had exactly one rule on the load balancer's security group —
 * allow-all egress, no ingress — because the listener is created with
 * `open: false`. The endpoint was therefore reachable from nowhere, including
 * from inside the VPC, while the `McpEndpoint` output described it as "reachable
 * from inside the VPC or over a peered/VPN path".
 *
 * Closed by default is a defensible posture for an endpoint that accepts source
 * code and returns findings about it. Claiming to be reachable when nothing can
 * reach you is not, so these tests pin the honesty of the outputs rather than
 * forcing the security group open.
 */
describe('the MCP endpoint is closed until the adopter opens it', () => {
  function albSecurityGroups(): [string, any][] {
    // The ALB's group is the one with egress to the container port. The service
    // has its own group, so matching on type alone would conflate them.
    return Object.entries<any>(template.findResources('AWS::EC2::SecurityGroup')).filter(
      ([, sg]) => (sg.Properties.GroupDescription?.['Fn::Join'] ?? []).length > 0
        || typeof sg.Properties.GroupDescription === 'string',
    );
  }

  test('the load balancer has exactly one security group', () => {
    // The stack indexes securityGroups[0] to publish the id. If the ALB ever had
    // two, that output would silently name only one of them.
    const albs = Object.values<any>(
      template.findResources('AWS::ElasticLoadBalancingV2::LoadBalancer'),
    );
    expect(albs).toHaveLength(1);
    expect(albs[0].Properties.SecurityGroups).toHaveLength(1);
  });

  test('no ingress is baked into a security group unconditionally', () => {
    // `open: false` is still the posture. The only port-80 ingress in the stack is
    // the McpIngressCidr rule, which is gated on a condition (asserted below).
    // An inline rule on the group itself could not be gated and would open the
    // endpoint for everyone.
    for (const [, sg] of albSecurityGroups()) {
      const ingress = sg.Properties.SecurityGroupIngress ?? [];
      for (const rule of ingress) {
        expect(rule.FromPort).not.toBe(80);
      }
    }
  });

  test('the McpIngressCidr rule exists but is conditional, so empty means closed', () => {
    /*
     * The parameter is deploy-time, so the rule cannot be included or excluded at
     * synth time. Gating the RESOURCE on a condition is what makes the empty
     * default emit no rule at all. Emitting it unconditionally with a conditional
     * CIDR would be wrong: no CIDR value means "no access", and 0.0.0.0/32 would
     * be a real rule that merely looked inert.
     */
    const rules = Object.entries<any>(
      template.findResources('AWS::EC2::SecurityGroupIngress'),
    ).filter(([, r]) => r.Properties.FromPort === 80);
    expect(rules).toHaveLength(1);

    const [, rule] = rules[0];
    expect(rule.Condition).toBeDefined();

    const condition = template.toJSON().Conditions[rule.Condition];
    const expression = JSON.stringify(condition);
    // Present exactly when the parameter is non-empty.
    expect(expression).toContain('Fn::Not');
    expect(expression).toContain(ASH_PARAMETER_NAMES.mcpIngressCidr);
    expect(expression).toContain('""');

    // The rule targets the load balancer's group and carries the parameter, not a
    // literal CIDR someone might have hardcoded.
    const albs = Object.values<any>(
      template.findResources('AWS::ElasticLoadBalancingV2::LoadBalancer'),
    );
    expect(JSON.stringify(rule.Properties.GroupId)).toBe(
      JSON.stringify(albs[0].Properties.SecurityGroups[0]),
    );
    expect(rule.Properties.CidrIp).toEqual({ Ref: ASH_PARAMETER_NAMES.mcpIngressCidr });
  });

  test('McpIngressCidr defaults to empty and rejects a bare address', () => {
    const param = template.toJSON().Parameters[ASH_PARAMETER_NAMES.mcpIngressCidr];
    expect(param).toBeDefined();
    // Empty default is what preserves the pre-existing closed posture, including
    // for an update of an already-deployed stack.
    expect(param.Default).toBe('');

    // A bare address silently becoming a /32 nobody intended is the mistake the
    // pattern exists to stop.
    const pattern = new RegExp(param.AllowedPattern);
    expect(pattern.test('')).toBe(true);
    expect(pattern.test('10.1.0.0/16')).toBe(true);
    expect(pattern.test('10.0.0.5/32')).toBe(true);
    expect(pattern.test('10.0.0.5')).toBe(false);
    expect(pattern.test('not-a-cidr')).toBe(false);
  });

  test('McpEndpoint does not claim to be reachable, and points at the fix', () => {
    const outputs = template.toJSON().Outputs;
    const description: string = outputs.McpEndpoint.Description;
    // The exact wording that was wrong. Asserting its absence is what makes this
    // a regression test rather than a restatement of the new string.
    expect(description).not.toContain('so reachable from inside the VPC');
    expect(description).toContain('not');
    expect(description).toContain('McpSecurityGroupId');
    // And it names the parameter that actually opens it, so the message is
    // actionable rather than merely accurate.
    expect(description).toContain(ASH_PARAMETER_NAMES.mcpIngressCidr);
  });

  test('McpSecurityGroupId gives the adopter something to act on', () => {
    const outputs = template.toJSON().Outputs;
    expect(outputs.McpSecurityGroupId).toBeDefined();
    expect(outputs.McpSecurityGroupId.Description).toContain('no ingress rule');
    expect(outputs.McpSecurityGroupId.Description).toContain(
      'authorize-security-group-ingress',
    );
    // The value must be the ALB's group, not a literal or the service's group.
    const albs = Object.values<any>(
      template.findResources('AWS::ElasticLoadBalancingV2::LoadBalancer'),
    );
    expect(JSON.stringify(outputs.McpSecurityGroupId.Value)).toBe(
      JSON.stringify(albs[0].Properties.SecurityGroups[0]),
    );
  });
});
