import { App } from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';

import { ASH_PARAMETER_NAMES } from '../lib/ash-config';
import { AshCodeCommitGateStack } from '../lib/ash-codecommit-gate-stack';

const template = Template.fromStack(
  new AshCodeCommitGateStack(new App({ analyticsReporting: false }), 'AshCodeCommitGate'),
);

describe('CodeCommit pull-request gate', () => {
  test('the repository is REFERENCED and never created', () => {
    // The single most important property of this stack. An adopter wiring a scan
    // into a repository full of history must not risk a stack rollback taking the
    // repository with it.
    template.resourceCountIs('AWS::CodeCommit::Repository', 0);
    template.hasParameter(ASH_PARAMETER_NAMES.codeCommitRepositoryArn, {
      Type: 'String',
      MinLength: 1,
    });
  });

  test('the repository ARN is required, with a pattern that rejects a bare name', () => {
    const parameter = template.toJSON().Parameters[ASH_PARAMETER_NAMES.codeCommitRepositoryArn];
    expect(parameter.Default).toBeUndefined();
    expect(parameter.AllowedPattern).toBeDefined();
    expect('my-repo').not.toMatch(new RegExp(parameter.AllowedPattern));
    // Assembled from parts rather than written out, so that no 12-digit literal
    // exists anywhere in this repository and the account-id scan can stay absolute.
    const exampleArn = `arn:aws:codecommit:us-east-1:${'1'.repeat(12)}:my-repo`;
    expect(exampleArn).toMatch(new RegExp(parameter.AllowedPattern));
  });

  test('the rule is scoped to that one repository and to pull-request events', () => {
    template.hasResourceProperties('AWS::Events::Rule', {
      EventPattern: Match.objectLike({
        source: ['aws.codecommit'],
        'detail-type': ['CodeCommit Pull Request State Change'],
        resources: [{ Ref: ASH_PARAMETER_NAMES.codeCommitRepositoryArn }],
        detail: { event: ['pullRequestCreated', 'pullRequestSourceBranchUpdated'] },
      }),
    });
  });

  test('closing or merging a pull request does not trigger a scan', () => {
    const rules = template.findResources('AWS::Events::Rule');
    const events = Object.values(rules)
      .map((r) => r.Properties?.EventPattern?.detail?.event)
      .filter(Boolean)
      .flat();
    expect(events).not.toContain('pullRequestStatusChanged');
  });

  test('the function can comment and vote, but only on that repository', () => {
    template.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Action: Match.arrayWith([
              'codecommit:GitPull',
              'codecommit:PostCommentForPullRequest',
              'codecommit:UpdatePullRequestApprovalState',
            ]),
            Resource: { Ref: ASH_PARAMETER_NAMES.codeCommitRepositoryArn },
          }),
        ]),
      }),
    });
  });

  test('the function grants itself no repository-write actions', () => {
    // A gate that could push, delete a branch, or merge would be a far larger
    // blast radius than commenting requires.
    const json = JSON.stringify(template.toJSON());
    for (const forbidden of [
      'codecommit:GitPush',
      'codecommit:DeleteRepository',
      'codecommit:DeleteBranch',
      'codecommit:MergePullRequestByFastForward',
      'codecommit:PutFile',
      'codecommit:CreateRepository',
    ]) {
      expect(json).not.toContain(forbidden);
    }
  });

  test('the function is a container image from this account, at Lambda maximums', () => {
    template.hasResourceProperties('AWS::Lambda::Function', {
      PackageType: 'Image',
      // 900 seconds is Lambda's ceiling, not a tuned value.
      Timeout: 900,
      EphemeralStorage: { Size: 4096 },
    });
  });

  test('the function waits for the bootstrap build', () => {
    const functions = template.findResources('AWS::Lambda::Function', {
      Properties: { PackageType: 'Image' },
    });
    const [fn] = Object.values(functions);
    const [bootstrap] = Object.keys(template.findResources('Custom::AshImageBootstrap'));
    expect(fn.DependsOn).toContain(bootstrap);
  });

  test('the lambda image bakes in the runtime interface client and the git transport', () => {
    // A container Lambda must speak the Lambda Runtime API, which ASH's image has
    // no notion of. git-remote-codecommit gives git the codecommit:// transport so
    // the handler can clone with the function role.
    const project = Object.values(template.findResources('AWS::CodeBuild::Project'))[0];
    const buildSpec = JSON.stringify(project.Properties.Source.BuildSpec);
    expect(buildSpec).toContain('awslambdaric');
    expect(buildSpec).toContain('git-remote-codecommit');
    expect(buildSpec).toContain('boto3');
  });

  test('the approval gate is off by default', () => {
    // On by default would start voting on pull requests in a repository the
    // adopter has only just pointed at this stack.
    template.hasParameter('ApprovalGate', { Default: 'false' });
  });

  test('the role ARN is output so an approval rule can name it', () => {
    // CloudFormation has no resource type for a CodeCommit approval rule template,
    // so the gate cannot be made binding declaratively. The output is how an
    // adopter finishes the job.
    const outputs = template.toJSON().Outputs;
    expect(outputs.ScanFunctionRoleArn).toBeDefined();
    expect(outputs.ScanFunctionRoleArn.Description).toContain('approval rule');
  });
});

/*
 * Optional VPC placement for the scan function.
 *
 * The switch is a CloudFormation condition, so it cannot be observed by synthesizing
 * twice. Instead this resolves the committed shape the way CloudFormation would for a
 * given pair of parameter values: just enough of Ref, Fn::Select, Fn::Equals, Fn::Not,
 * Fn::And, Fn::Or, Fn::EachMemberEquals and Fn::If to evaluate what the template uses,
 * and a throw for anything else so an unmodeled intrinsic cannot pass by accident.
 */
describe('the scan function joins a VPC only when the adopter supplies one', () => {
  const json = template.toJSON();
  const SCAN_FUNCTION = Object.keys(json.Resources).find(
    (id) =>
      json.Resources[id].Type === 'AWS::Lambda::Function' &&
      json.Resources[id].Properties?.PackageType === 'Image',
  )!;
  const SCAN_ROLE = json.Resources[SCAN_FUNCTION].Properties.Role['Fn::GetAtt'][0];
  const VPC_POLICY = Object.keys(json.Resources).find(
    (id) => json.Resources[id].Type === 'AWS::IAM::Policy' && json.Resources[id].Condition,
  )!;
  const SCAN_SG = Object.keys(json.Resources).find(
    (id) => json.Resources[id].Type === 'AWS::EC2::SecurityGroup',
  )!;
  const SET = { VpcId: 'vpc-0123456789abcdef0', VpcSubnetIds: 'subnet-0aaa,subnet-0bbb' };
  const NO_VALUE = Symbol('AWS::NoValue');

  function evaluate(parameters: Record<string, string>) {
    const params: Record<string, unknown> = {};
    for (const [name, spec] of Object.entries<any>(json.Parameters)) {
      const raw = parameters[name] ?? spec.Default ?? '';
      params[name] = spec.Type === 'CommaDelimitedList' ? String(raw).split(',') : raw;
    }
    const conditions: Record<string, boolean> = {};
    const resolve = (node: any): any => {
      if (Array.isArray(node)) return node.map(resolve).filter((v) => v !== NO_VALUE);
      if (node === null || typeof node !== 'object') return node;
      const keys = Object.keys(node);
      if (keys.length !== 1 || !(keys[0] === 'Ref' || keys[0].startsWith('Fn::'))) {
        const out: Record<string, unknown> = {};
        for (const k of keys) {
          const v = resolve(node[k]);
          if (v !== NO_VALUE) out[k] = v;
        }
        return out;
      }
      const [fn] = keys;
      const arg = node[fn];
      switch (fn) {
        case 'Ref':
          if (arg === 'AWS::NoValue') return NO_VALUE;
          return arg in params ? params[arg] : { Ref: arg };
        case 'Fn::Select':
          return resolve(arg[1])[arg[0]];
        case 'Fn::Equals':
          return resolve(arg[0]) === resolve(arg[1]);
        case 'Fn::Not':
          return !resolve(arg[0]);
        case 'Fn::And':
          return arg.every((a: any) => resolve(a) === true);
        case 'Fn::Or':
          return arg.some((a: any) => resolve(a) === true);
        case 'Fn::EachMemberEquals':
          return (resolve(arg[0]) as string[]).every((m) => m === resolve(arg[1]));
        case 'Fn::If':
          return conditions[arg[0]] ? resolve(arg[1]) : resolve(arg[2]);
        default:
          // Anything outside the VPC switch (GetAtt, Join, ...) is left unresolved.
          return node;
      }
    };
    for (const [name, expr] of Object.entries<any>(json.Conditions)) {
      conditions[name] = resolve(expr) === true;
    }
    const ruleViolations = Object.entries<any>(json.Rules ?? {})
      .filter(([, rule]) => rule.RuleCondition === undefined || resolve(rule.RuleCondition))
      .flatMap(([name, rule]) =>
        rule.Assertions.filter((a: any) => resolve(a.Assert) !== true).map(() => name),
      );
    return {
      fn: resolve(json.Resources[SCAN_FUNCTION].Properties),
      // The VPC policy, as CloudFormation would create it: present only when its
      // condition holds, and then attached to the scan role.
      rolePolicies: Object.values<any>(json.Resources)
        .filter(
          (r) =>
            r.Type === 'AWS::IAM::Policy' &&
            JSON.stringify(r.Properties.Roles) === JSON.stringify([{ Ref: SCAN_ROLE }]) &&
            r.Condition !== undefined &&
            conditions[r.Condition],
        )
        .map((r) => resolve(r.Properties)),
      tags: resolve(json.Resources[SCAN_FUNCTION].Properties.Tags ?? []),
      // Every resource and output CloudFormation would create under these values.
      created: Object.entries<any>(json.Resources)
        .filter(([, r]) => r.Condition === undefined || conditions[r.Condition])
        .map(([id]) => id),
      outputs: Object.entries<any>(json.Outputs ?? {})
        .filter(([, o]) => o.Condition === undefined || conditions[o.Condition])
        .map(([id, o]) => [id, resolve(o.Value)] as const),
      resolve,
      ruleViolations,
    };
  }

  test('the parameters exist, are optional, and default to empty', () => {
    expect(json.Parameters[ASH_PARAMETER_NAMES.vpcSubnetIds]).toMatchObject({
      Type: 'CommaDelimitedList',
      Default: '',
    });
    expect(json.Parameters[ASH_PARAMETER_NAMES.vpcId]).toMatchObject({ Type: 'String', Default: '' });
    // Adopter-supplied group ids were removed on purpose; see the stack's comment.
    expect(json.Parameters.VpcSecurityGroupIds).toBeUndefined();
  });

  test('unset: no security group, no VpcConfig, no grant, no output, launch allowed', () => {
    const { fn, rolePolicies, ruleViolations, created, outputs } = evaluate({});
    expect(fn.VpcConfig).toBeUndefined();
    expect(created).not.toContain(SCAN_SG);
    expect(rolePolicies).toEqual([]);
    expect(outputs.map(([id]) => id)).not.toContain('ScanSecurityGroupId');
    expect(ruleViolations).toEqual([]);
  });

  test('unset is covered by the per-resource LAMBDA_INSIDE_VPC suppression, with its reason', () => {
    const guard = json.Resources[SCAN_FUNCTION].Metadata?.guard;
    expect(guard.SuppressedRules).toEqual(['LAMBDA_INSIDE_VPC']);
    expect(guard.SuppressedRuleReasons.LAMBDA_INSIDE_VPC).toMatch(/egress open/);
    expect(guard.SuppressedRuleReasons.LAMBDA_INSIDE_VPC).toMatch(/VpcId and VpcSubnetIds/);
  });

  test('set: the stack creates a 443-only group in that VPC and wires VpcConfig to it', () => {
    const { fn, ruleViolations, created, outputs, resolve } = evaluate(SET);
    expect(created).toContain(SCAN_SG);
    expect(fn.VpcConfig).toEqual({
      SubnetIds: ['subnet-0aaa', 'subnet-0bbb'],
      SecurityGroupIds: [{ 'Fn::GetAtt': [SCAN_SG, 'GroupId'] }],
    });
    const sg = resolve(json.Resources[SCAN_SG].Properties);
    expect(sg.VpcId).toBe(SET.VpcId);
    expect(sg.SecurityGroupEgress).toEqual([
      expect.objectContaining({ IpProtocol: 'tcp', FromPort: 443, ToPort: 443, CidrIp: '0.0.0.0/0' }),
    ]);
    expect(sg.SecurityGroupIngress).toBeUndefined();
    expect(outputs).toContainEqual(['ScanSecurityGroupId', { 'Fn::GetAtt': [SCAN_SG, 'GroupId'] }]);
    expect(ruleViolations).toEqual([]);
  });

  test('set: the role gets the documented ENI grant, and function code is denied EC2', () => {
    const { rolePolicies } = evaluate(SET);
    // Action lists sorted first: this file builds the stack without cdk.json's
    // minimizePolicies, which is what sorts them in the shipped template.
    for (const policy of rolePolicies) {
      for (const statement of policy.PolicyDocument.Statement) {
        if (Array.isArray(statement.Action)) statement.Action.sort();
      }
    }
    // Exact, so a widened grant is a visible diff here as well as an IAM5 finding.
    expect(rolePolicies).toEqual([
      {
        PolicyName: expect.any(String),
        Roles: [{ Ref: SCAN_ROLE }],
        PolicyDocument: {
          Version: '2012-10-17',
          Statement: [
            {
              Sid: 'LambdaManagesNetworkInterfaces',
              Effect: 'Allow',
              Action: [
                'ec2:AssignPrivateIpAddresses',
                'ec2:CreateNetworkInterface',
                'ec2:DeleteNetworkInterface',
                'ec2:DescribeNetworkInterfaces',
                'ec2:DescribeSubnets',
                'ec2:UnassignPrivateIpAddresses',
              ],
              Resource: '*',
              Condition: { StringEquals: { 'aws:RequestedRegion': { Ref: 'AWS::Region' } } },
            },
            {
              Sid: 'FunctionCodeCannotUseThem',
              Effect: 'Deny',
              Action: 'ec2:*',
              Resource: '*',
              Condition: { Null: { 'lambda:SourceFunctionArn': 'false' } },
            },
          ],
        },
      },
    ]);
  });

  test('the function waits for the policy only when the policy exists', () => {
    // Lambda checks the role holds the ENI permissions at create time, so the policy has
    // to be created first. The ordering rides on a Ref inside an Fn::If on the same
    // condition, because a DependsOn would name a resource absent when it is false.
    expect(json.Resources[VPC_POLICY].Condition).toBe('ScanFunctionInVpc');
    expect(json.Resources[SCAN_FUNCTION].DependsOn ?? []).not.toContain(VPC_POLICY);
    expect(evaluate({}).tags).toEqual([]);
    expect(
      evaluate(SET).tags,
    ).toEqual([{ Key: 'ash:vpc-access-policy', Value: { Ref: VPC_POLICY } }]);
  });

  test('setting only one of VpcId and VpcSubnetIds is refused before anything is created', () => {
    expect(evaluate({ VpcId: SET.VpcId }).ruleViolations).toEqual(['VpcIdWithSubnets']);
    expect(evaluate({ VpcSubnetIds: 'subnet-0aaa' }).ruleViolations).toEqual(['VpcIdWithSubnets']);
  });
});
