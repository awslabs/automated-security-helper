/**
 * Control for the Terraform gate's image-build role scoping: the CDK image builds
 * already push only to the repository their own stack creates.
 *
 * The Terraform codecommit-gate module granted its image-build role the ECR push
 * actions on `repository/*`, every repository in the account and Region, while its
 * comment said the role was scoped to the module's repository. That module is tested
 * under deploy/terraform/modules/codecommit-gate/tests. This file pins the CDK side,
 * which grants push through `repository.grantPullPush`, so the two trees cannot drift
 * apart on this unnoticed.
 */

import { AshAgentCoreStack } from '../lib/ash-agentcore-stack';
import { AshCodeCommitGateStack } from '../lib/ash-codecommit-gate-stack';
import { AshDistributedPipelineStack } from '../lib/ash-distributed-pipeline-stack';
import { AshFargateStack } from '../lib/ash-fargate-stack';
import { AshImagePipelineStack } from '../lib/ash-image-pipeline-stack';
import { actionMatches, CfnResolver, CfnTemplate, roleOf, statementsForRole, synth } from './support/cfn';

const PUSH_ACTIONS = ['ecr:PutImage', 'ecr:InitiateLayerUpload', 'ecr:UploadLayerPart', 'ecr:CompleteLayerUpload'];

const TEMPLATES: Array<[string, CfnTemplate]> = [
  ['AshAgentCore', synth((app) => new AshAgentCoreStack(app, 'AshAgentCore'))],
  ['AshFargate', synth((app) => new AshFargateStack(app, 'AshFargate'))],
  ['AshCodeCommitGate', synth((app) => new AshCodeCommitGateStack(app, 'AshCodeCommitGate'))],
  ['AshDistributedPipeline', synth((app) => new AshDistributedPipelineStack(app, 'AshDistributedPipeline'))],
  ['AshImagePipeline', synth((app) => new AshImagePipelineStack(app, 'AshImagePipeline'))],
];

test.each(TEMPLATES)('%s: every role that can push to ECR pushes only to a repository this stack creates', (_name, template) => {
  const repositories = Object.keys(template.Resources).filter(
    (id) => template.Resources[id].Type === 'AWS::ECR::Repository',
  );
  const attributes = Object.fromEntries(repositories.map((id) => [`${id}.Arn`, `arn:aws:ecr:us-east-1:000000000000:repository/${id}`]));
  const resolver = new CfnResolver(template, { attributes });
  const owned = new Set(Object.values(attributes));

  const roles = Object.entries(template.Resources)
    .filter(([, resource]) => resource.Type === 'AWS::CodeBuild::Project')
    .map(([, resource]) => roleOf(resource.Properties?.ServiceRole));
  let pushers = 0;
  for (const role of new Set(roles)) {
    for (const statement of statementsForRole(template, role, resolver)) {
      if (statement.effect !== 'Allow') continue;
      if (!statement.actions.some((granted) => PUSH_ACTIONS.some((action) => actionMatches(granted, action)))) continue;
      pushers += 1;
      expect({ role, resources: statement.resources.filter((r) => !owned.has(r)) }).toEqual({ role, resources: [] });
    }
  }
  // At least one image build pushes, so the loop above checked something.
  expect(pushers).toBeGreaterThan(0);
});
