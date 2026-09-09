#!/usr/bin/env node
/**
 * The CDK app that produces the committed CloudFormation templates.
 *
 * TWO DECISIONS HERE ARE LOAD-BEARING FOR REPRODUCIBILITY AND FOR NOT LEAKING AN
 * ACCOUNT ID INTO A PUBLIC REPOSITORY.
 *
 * 1. STACKS ARE ENVIRONMENT-AGNOSTIC BY DEFAULT.
 *    No `env` is passed, so every account and region reference in the output is
 *    the CloudFormation pseudo-parameter `AWS::AccountId` / `AWS::Region`. Two
 *    consequences, both wanted:
 *      - The committed template contains no account id. Synthesizing with
 *        `env: { account: process.env.CDK_DEFAULT_ACCOUNT }` would bake in
 *        whichever account happened to run `cdk synth`, and this repository is
 *        public.
 *      - Output is identical on every machine, which is what a CI drift gate
 *        needs.
 *    `CDK_DEFAULT_ACCOUNT` / `CDK_DEFAULT_REGION` are still read — never
 *    hardcoded — but only when `-c useEnvironment=true` is passed, for adopters
 *    who want an environment-specific synth locally. THE COMMITTED TEMPLATES ARE
 *    NOT PRODUCED THAT WAY; see scripts/synth-templates.sh for the exact command.
 *
 * 2. NO ASSETS, SO NO BOOTSTRAP.
 *    Each stack defaults its own synthesizer — see `ashSynthesizer` in
 *    lib/ash-config.ts — so the `BootstrapVersion` parameter and the
 *    `CheckBootstrapVersion` rule are absent. That default deliberately lives on
 *    the stack rather than here: setting it only at this call site produced a
 *    stack that behaved one way when deployed and another way when constructed by
 *    a test.
 *
 * `analyticsReporting: false` removes the `CDKMetadata` resource. It carries a
 * version-keyed analytics blob that is noise in a committed template and one more
 * thing to churn on a library bump.
 */

import { App, Aspects, Environment } from 'aws-cdk-lib';
import { AwsSolutionsChecks } from 'cdk-nag';

import { AshAgentCoreStack } from '../lib/ash-agentcore-stack';
import { AshCodeCommitGateStack } from '../lib/ash-codecommit-gate-stack';
import { AshDistributedPipelineStack } from '../lib/ash-distributed-pipeline-stack';
import { AshFargateStack } from '../lib/ash-fargate-stack';
import { AshImagePipelineStack } from '../lib/ash-image-pipeline-stack';

const app = new App({ analyticsReporting: false });

/**
 * Read the environment only when explicitly asked to.
 *
 * Returning `undefined` yields an environment-agnostic stack, which is the
 * default and the shape the committed templates have.
 */
function resolveEnvironment(): Environment | undefined {
  if (app.node.tryGetContext('useEnvironment') !== 'true') {
    return undefined;
  }
  return {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION,
  };
}

const env = resolveEnvironment();

// Stack ids are the template file names under templates/. Keep them stable: a
// rename is a breaking change for anyone linking a one-click launch URL.
new AshImagePipelineStack(app, 'AshImagePipeline', { env });
new AshAgentCoreStack(app, 'AshAgentCore', { env });
new AshFargateStack(app, 'AshFargate', { env });
new AshCodeCommitGateStack(app, 'AshCodeCommitGate', { env });
new AshDistributedPipelineStack(app, 'AshDistributedPipeline', { env });

// cdk-nag runs over every stack on every synth, so a finding cannot be
// introduced without either being fixed or being suppressed with a stated
// reason. Suppressions live next to the resource that needs them.
Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));

app.synth();
