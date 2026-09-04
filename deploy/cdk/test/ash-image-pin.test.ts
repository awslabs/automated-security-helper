/**
 * `AshImageTag` pins the image a WORKLOAD pulls, and must not touch the build.
 *
 * WHY THIS EXISTS
 * ---------------
 * Every build republishes the moving tag (`mcp-arm64` and friends), so a mutable
 * tag consumed by a running workload has no defined moment at which the workload
 * adopts a new image: a task replaced for any unrelated reason picks up whatever
 * the tag points at then. The version-qualified audit tag each build also pushes
 * is stable per ref, but nothing let an adopter point a workload at it. Documenting
 * "use the audit tag instead" without a parameter that accepts one is advice
 * nobody can act on.
 *
 * THE INVARIANT THAT MATTERS MOST IS THE NEGATIVE ONE
 * -------------------------------------------------
 * The override must reach the workload's image reference and NOTHING else. If it
 * leaked into the buildspec, two things would break at once: the build would tag
 * and push to a reference derived from an `Fn::If`, so the moving tag would stop
 * being published for anyone; and `sanitizeRefCommand` budgets the folded ref
 * against the 128-character Docker tag limit using the tag's real length, which a
 * token cannot provide. That is why `tagForFlavor` (build) and
 * `workloadTagForFlavor` (workload) are separate accessors, and why the assertion
 * below is that no buildspec mentions the condition at all.
 */

import { App, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';

import { AshAgentCoreStack } from '../lib/ash-agentcore-stack';
import { AshCodeCommitGateStack } from '../lib/ash-codecommit-gate-stack';
import { AshDistributedPipelineStack } from '../lib/ash-distributed-pipeline-stack';
import { AshFargateStack } from '../lib/ash-fargate-stack';
import { AshImagePipelineStack } from '../lib/ash-image-pipeline-stack';
import { ASH_PARAMETER_NAMES } from '../lib/ash-config';

type StackFactory = (app: App, id: string) => Stack;

const STACKS: Record<string, StackFactory> = {
  AshImagePipeline: (app, id) => new AshImagePipelineStack(app, id),
  AshAgentCore: (app, id) => new AshAgentCoreStack(app, id),
  AshFargate: (app, id) => new AshFargateStack(app, id),
  AshCodeCommitGate: (app, id) => new AshCodeCommitGateStack(app, id),
  AshDistributedPipeline: (app, id) => new AshDistributedPipelineStack(app, id),
};

/** Stacks that run a workload and therefore take the parameter. */
const WORKLOAD_STACKS = [
  'AshAgentCore',
  'AshFargate',
  'AshCodeCommitGate',
  'AshDistributedPipeline',
];

/** Stacks with no workload, which must NOT take it. */
const BUILD_ONLY_STACKS = ['AshImagePipeline'];

const TEMPLATES: Record<string, any> = Object.fromEntries(
  Object.keys(STACKS).map((name) => {
    const app = new App({ analyticsReporting: false });
    return [name, Template.fromStack(STACKS[name](app, name)).toJSON()];
  }),
);

const PARAM = ASH_PARAMETER_NAMES.ashImageTag;

/** Collapse an intrinsic tree into text, keeping Fn::If visible. */
function flatten(node: unknown): string {
  if (typeof node === 'string') return node;
  if (Array.isArray(node)) return node.map(flatten).join('');
  if (node && typeof node === 'object') {
    const obj = node as Record<string, any>;
    if (obj['Fn::Join']) {
      const [sep, parts] = obj['Fn::Join'];
      return (parts as unknown[]).map(flatten).join(sep as string);
    }
    if (obj['Fn::If']) {
      const [cond, a, b] = obj['Fn::If'];
      return `<IF:${cond}:${flatten(a)}|${flatten(b)}>`;
    }
    if (obj.Ref) return `<${obj.Ref}>`;
    if (obj['Fn::GetAtt']) return `<${(obj['Fn::GetAtt'] as string[]).join('.')}>`;
    return Object.values(obj).map(flatten).join('');
  }
  return String(node);
}

function pinCondition(stack: string): string | undefined {
  return Object.keys(TEMPLATES[stack].Conditions ?? {}).find((c) => c.includes('ImageTagPinned'));
}

describe('AshImageTag is offered exactly where a workload pulls an image', () => {
  test.each(WORKLOAD_STACKS)('%s declares the parameter, defaulting to the moving tag', (stack) => {
    const param = TEMPLATES[stack].Parameters?.[PARAM];
    expect(param).toBeDefined();
    // Empty default is what keeps existing deployments on their current behavior.
    expect(param.Default).toBe('');
    expect(param.Type).toBe('String');
  });

  test.each(BUILD_ONLY_STACKS)('%s does not declare it, having no workload', (stack) => {
    // This stack only builds images; its outputs report the moving tag URIs. A
    // parameter here would be a knob that changed nothing.
    expect(TEMPLATES[stack].Parameters?.[PARAM]).toBeUndefined();
    expect(pinCondition(stack)).toBeUndefined();
  });

  test.each(WORKLOAD_STACKS)('%s gates the pin on the parameter being non-empty', (stack) => {
    const condition = pinCondition(stack);
    expect(condition).toBeDefined();
    const expression = JSON.stringify(TEMPLATES[stack].Conditions[condition!]);
    expect(expression).toContain('Fn::Not');
    expect(expression).toContain(PARAM);
    expect(expression).toContain('""');
  });
});

describe('the pin reaches the workload and nothing else', () => {
  /** The property that carries the image reference, per workload type. */
  const IMAGE_REFERENCES: Record<string, [string, (props: any) => unknown]> = {
    AshAgentCore: [
      'AWS::BedrockAgentCore::Runtime',
      (p) => p.AgentRuntimeArtifact?.ContainerConfiguration?.ContainerUri,
    ],
    AshFargate: ['AWS::ECS::TaskDefinition', (p) => p.ContainerDefinitions],
    AshCodeCommitGate: ['AWS::Lambda::Function', (p) => p.Code?.ImageUri],
    AshDistributedPipeline: ['AWS::CodeBuild::Project', (p) => p.Environment?.Image],
  };

  test.each(WORKLOAD_STACKS)('%s image reference falls back to the moving tag', (stack) => {
    const [type, pick] = IMAGE_REFERENCES[stack];
    const condition = pinCondition(stack)!;
    const resources = Object.values<any>(TEMPLATES[stack].Resources).filter(
      (r) => r.Type === type,
    );
    expect(resources.length).toBeGreaterThan(0);

    const pinned = resources
      .map((r) => flatten(pick(r.Properties)))
      .filter((text) => text.includes(`<IF:${condition}:`));
    expect(pinned.length).toBeGreaterThan(0);

    for (const text of pinned) {
      // True branch is the parameter; false branch is the moving tag, so leaving
      // the parameter empty cannot change an existing deployment.
      expect(text).toContain(`<IF:${condition}:<${PARAM}>|`);
      expect(text).toMatch(/\|(mcp|lambda|cli)-(arm64|amd64)>/);
    }
  });

  test.each(Object.keys(STACKS))('%s never lets the pin into a buildspec', (stack) => {
    /*
     * The load-bearing negative. A pin inside the buildspec would make the build
     * tag and push through an Fn::If, so the moving tag would stop being
     * published at all -- and the folded-ref length budget in
     * sanitizeRefCommand would be computed from a token instead of the real tag.
     */
    const condition = pinCondition(stack);
    const projects = Object.values<any>(TEMPLATES[stack].Resources).filter(
      (r) => r.Type === 'AWS::CodeBuild::Project',
    );
    expect(projects.length).toBeGreaterThan(0);
    for (const project of projects) {
      const spec = flatten(project.Properties.Source.BuildSpec);
      expect(spec).not.toContain(PARAM);
      if (condition) expect(spec).not.toContain(condition);
    }
  });

  test.each(Object.keys(STACKS))('%s still publishes the plain moving tag', (stack) => {
    // The pin selects between tags; it must not stop either from being pushed.
    const projects = Object.values<any>(TEMPLATES[stack].Resources).filter(
      (r) => r.Type === 'AWS::CodeBuild::Project',
    );
    const pushes = projects.flatMap((project) => {
      const spec = flatten(project.Properties.Source.BuildSpec);
      return [...spec.matchAll(/docker push \\?"\$\{ASH_ECR_REPOSITORY_URI\}:([^"\\]+)/g)].map(
        (m) => m[1],
      );
    });
    expect(pushes.length).toBeGreaterThan(0);
    // At least one push target is a bare moving tag with no version suffix.
    expect(pushes.some((tag) => /^(mcp|lambda|cli)-(arm64|amd64)$/.test(tag))).toBe(true);
  });
});
