// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { App, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import * as pipelines from 'aws-cdk-lib/pipelines';
import { ASHScanStep, ASHScanStepProps } from '../src';

/** One action as it appears in the synthesized CodePipeline resource. */
export interface SynthesizedAction {
  readonly name: string;
  readonly runOrder: number;
  readonly inputs: string[];
  readonly outputs: string[];
  /** Commands from the `build` phase of the action's CodeBuild project. */
  readonly commands: string[];
}

/** Everything a test needs about one synthesized pipeline. */
export interface SynthesizedPipeline {
  readonly template: Template;
  /** Actions in the stage the ASH step was added to, in template order. */
  readonly actions: SynthesizedAction[];
}

/**
 * Synthesize a pipeline containing one `ASHScanStep` and read back what
 * CloudFormation would actually create.
 *
 * The stack is environment-agnostic on purpose. Pinning an account would put a
 * twelve-digit literal in a public repository for no benefit, and CDK Pipelines
 * synthesizes fine without one.
 */
export function synthesizeWithStep(
  props: Omit<ASHScanStepProps, 'input'>,
  stepId: string = 'SecurityScan',
): SynthesizedPipeline {
  const app = new App();
  const stack = new Stack(app, 'PipelineStack');

  const source = pipelines.CodePipelineSource.gitHub(
    'awslabs/automated-security-helper',
    'main',
  );

  const pipeline = new pipelines.CodePipeline(stack, 'Pipeline', {
    synth: new pipelines.ShellStep('Synth', {
      input: source,
      commands: ['npm ci', 'npx cdk synth'],
    }),
  });

  const step = new ASHScanStep(stepId, { input: source, ...props });
  pipeline.addWave('Security', { pre: [step] });

  const template = Template.fromStack(stack);
  return { template, actions: readActions(template, 'Security') };
}

/** Build a step without synthesizing, for validation tests. */
export function buildStep(
  props: Omit<ASHScanStepProps, 'input'>,
  stepId: string = 'SecurityScan',
): ASHScanStep {
  const app = new App();
  const stack = new Stack(app, 'PipelineStack');
  const source = pipelines.CodePipelineSource.gitHub(
    'awslabs/automated-security-helper',
    'main',
  );
  // Referenced so the source participates in the stack the same way it would in
  // a real pipeline; the step under test only needs its primaryOutput.
  void stack;
  return new ASHScanStep(stepId, { input: source, ...props });
}

/** Read the actions of one pipeline stage, resolving each one's buildspec. */
function readActions(template: Template, stageName: string): SynthesizedAction[] {
  const pipelines_ = template.findResources('AWS::CodePipeline::Pipeline');
  const logicalIds = Object.keys(pipelines_);
  if (logicalIds.length !== 1) {
    throw new Error(`expected exactly one pipeline, found ${logicalIds.length}`);
  }

  const stages = pipelines_[logicalIds[0]].Properties.Stages as any[];
  const stage = stages.find((s) => s.Name === stageName);
  if (!stage) {
    throw new Error(
      `stage ${stageName} not found; stages are ${stages.map((s) => s.Name).join(', ')}`,
    );
  }

  const buildSpecs = readBuildSpecs(template);

  return (stage.Actions as any[]).map((action) => ({
    name: action.Name as string,
    runOrder: action.RunOrder as number,
    inputs: ((action.InputArtifacts ?? []) as any[]).map((a) => a.Name as string),
    outputs: ((action.OutputArtifacts ?? []) as any[]).map((a) => a.Name as string),
    commands: commandsFor(action, buildSpecs),
  }));
}

/** Map every CodeBuild project's logical id to its parsed buildspec. */
function readBuildSpecs(template: Template): Map<string, any> {
  const specs = new Map<string, any>();
  const projects = template.findResources('AWS::CodeBuild::Project');

  for (const [logicalId, resource] of Object.entries(projects)) {
    const raw = (resource as any).Properties?.Source?.BuildSpec;
    if (typeof raw !== 'string') {
      // A buildspec containing CloudFormation tokens renders as Fn::Join. None of
      // this package's buildspecs do, so a non-string here means something
      // introduced a token and the test should say so rather than skip silently.
      throw new Error(
        `buildspec of ${logicalId} is not a plain string: ${JSON.stringify(raw)?.slice(0, 200)}`,
      );
    }
    specs.set(logicalId, JSON.parse(raw));
  }

  return specs;
}

/** Resolve the build-phase commands of the project an action points at. */
function commandsFor(action: any, buildSpecs: Map<string, any>): string[] {
  const projectName = action.Configuration?.ProjectName;
  const ref = projectName?.Ref ?? projectName?.['Fn::GetAtt']?.[0];
  if (typeof ref !== 'string') {
    return [];
  }
  const spec = buildSpecs.get(ref);
  return (spec?.phases?.build?.commands ?? []) as string[];
}
