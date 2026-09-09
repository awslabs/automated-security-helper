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
