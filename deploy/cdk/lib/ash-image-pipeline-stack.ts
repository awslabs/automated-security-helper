/**
 * The image build on its own, for adopters running more than one ASH target.
 *
 * WHY A STANDALONE STACK WHEN EVERY TARGET ALREADY EMBEDS ONE
 * ----------------------------------------------------------
 * Each target stack embeds its own `AshImageBuild` so it is genuinely
 * one-click: launch the template, get a working deployment, no ordering to
 * remember. The cost of that is duplication — deploying all four targets gives
 * four ECR repositories and four CodeBuild projects, each rebuilding the same
 * ASH revision on the same schedule.
 *
 * This stack exists for the adopter who has decided that duplication is not
 * worth it. It builds every flavor on both architectures once, and its outputs
 * name the repository and the tags. Targets can then be pointed at it — by
 * editing the image reference in the target template, or by using the target
 * stacks as a starting point rather than as-is.
 *
 * WHAT WAS REJECTED: making the target stacks consume this by
 * `Fn::ImportValue`. It would break the one-click property outright — a console
 * launch of the AgentCore template would fail with an unresolved export until
 * this stack existed, with no hint of which stack to deploy first. Duplication
 * that works beats a dependency that fails opaquely.
 *
 * NOT A DEPLOY-TIME BOOTSTRAP: this stack has no workload to gate, so it does
 * not run a build during creation. The first image appears on the first
 * scheduled rebuild, or immediately if you start the project by hand. The
 * output tells you how.
 */

import { CfnOutput, RemovalPolicy, Stack, StackProps } from 'aws-cdk-lib';
import * as kms from 'aws-cdk-lib/aws-kms';
import { Construct } from 'constructs';

import {
  ashSynthesizer,
  AshCustomerKey,
  ashOfflineMode, ashVersion, rebuildSchedule,
} from './ash-config';
import { AshImageBuild } from './ash-image-build';

export class AshImagePipelineStack extends Stack {
  constructor(scope: Construct, id: string, props: StackProps = {}) {
    super(scope, id, {
      // Before ...props, so a caller can still override it.
      synthesizer: ashSynthesizer(),
      ...props,
      description:
        'Shared ASH image build: one ECR repository plus scheduled ARM64 and x86_64 ' +
        'CodeBuild projects. ASH publishes no public container image, so this build is what ' +
        'makes every ASH deployment target possible.',
    });

    const version = ashVersion(this);
    const offline = ashOfflineMode(this);
    const schedule = rebuildSchedule(this);
    // Shared by both architectures, so the two repositories and all four log
    // groups answer to one key rather than asking the adopter for two.
    const customerKey = new AshCustomerKey(this);

    // One customer-managed key per stack, shared by every CodeBuild project here.
    // Rotation is on: the key only protects build output, so a rotated key needs
    // no coordination with anything outside the stack.
    const encryptionKey = new kms.Key(this, 'EncryptionKey', {
      description: 'Encrypts ASH CodeBuild project output for this stack.',
      enableKeyRotation: true,
      removalPolicy: RemovalPolicy.RETAIN,
    });

    // ARM64 exists solely for AgentCore, which rejects an x86_64 image. It is a
    // separate project rather than a second buildspec because the build must run
    // on ARM compute to be native rather than emulated.
    const arm = new AshImageBuild(this, 'Arm64', {
      platform: 'arm64',
      flavors: ['mcp', 'cli'],
      ashVersion: version,
      offlineMode: offline,
      rebuildSchedule: schedule,
      bootstrapOnDeploy: false,
      encryptionKey,
      customerKey,
    });

    const amd = new AshImageBuild(this, 'Amd64', {
      platform: 'amd64',
      flavors: ['mcp', 'lambda', 'cli'],
      ashVersion: version,
      offlineMode: offline,
      rebuildSchedule: schedule,
      bootstrapOnDeploy: false,
      encryptionKey,
      customerKey,
    });

    new CfnOutput(this, 'Arm64RepositoryUri', {
      description: 'ARM64 repository. The mcp tag here is what AgentCore needs.',
      value: arm.repository.repositoryUri,
    });
    new CfnOutput(this, 'Arm64McpImageUri', { value: arm.imageUriForFlavor('mcp') });
    new CfnOutput(this, 'Arm64BuildProjectName', {
      description:
        'Start this to build the first ARM64 image now: ' +
        '`aws codebuild start-build --project-name <this>`. Nothing exists in the ' +
        'repository until a build has run.',
      value: arm.project.projectName,
    });

    new CfnOutput(this, 'Amd64RepositoryUri', { value: amd.repository.repositoryUri });
    new CfnOutput(this, 'Amd64McpImageUri', { value: amd.imageUriForFlavor('mcp') });
    new CfnOutput(this, 'Amd64LambdaImageUri', { value: amd.imageUriForFlavor('lambda') });
    new CfnOutput(this, 'Amd64CliImageUri', { value: amd.imageUriForFlavor('cli') });
    new CfnOutput(this, 'Amd64BuildProjectName', {
      description: 'Start this to build the first x86_64 images now.',
      value: amd.project.projectName,
    });
  }
}
