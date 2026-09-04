/**
 * Two defects that a synthesized template looked perfectly healthy with, and that
 * only a real deployment exposed.
 *
 * THE REBUILD SCHEDULE RACED THE BOOTSTRAP BUILD
 * ---------------------------------------------
 * `RebuildSchedule` defaulted to `rate(1 day)`, and an EventBridge rate
 * expression is anchored at rule creation — "a rate expression starts when you
 * create the scheduled event rule". Observed on a real stack: the rule was created
 * at 19:12:10 and started a CodeBuild run at 19:12:53, while the bootstrap build
 * begun at 19:12:39 was still going. Two concurrent ARM64 LARGE builds on every
 * deployment, both pushing the same moving tag into the same MUTABLE repository,
 * and only one of them visible to CloudFormation.
 *
 * THE BUILDSPEC WROTE BOTH CONTAINER SCRIPTS EVERY TIME
 * ---------------------------------------------------
 * So the CodeCommit gate handler was inlined into all five committed templates,
 * including two that build no Lambda at all. That is what pushed four of the five
 * over CloudFormation's 51,200-byte inline template cap. `ash-template-size.test.ts`
 * pins the resulting sizes; this file pins the cause, because a size assertion
 * alone would not say which script was the problem.
 *
 * These are structural assertions against the synthesized template, which is the
 * right level: both defects are properties of what CloudFormation receives.
 */

import { App, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';

import { AshAgentCoreStack } from '../lib/ash-agentcore-stack';
import { AshCodeCommitGateStack } from '../lib/ash-codecommit-gate-stack';
import { AshDistributedPipelineStack } from '../lib/ash-distributed-pipeline-stack';
import { AshFargateStack } from '../lib/ash-fargate-stack';
import { AshImagePipelineStack } from '../lib/ash-image-pipeline-stack';
import { DEFAULT_REBUILD_SCHEDULE } from '../lib/ash-config';

type StackFactory = (app: App, id: string) => Stack;

const STACKS: Record<string, StackFactory> = {
  AshImagePipeline: (app, id) => new AshImagePipelineStack(app, id),
  AshAgentCore: (app, id) => new AshAgentCoreStack(app, id),
  AshFargate: (app, id) => new AshFargateStack(app, id),
  AshCodeCommitGate: (app, id) => new AshCodeCommitGateStack(app, id),
  AshDistributedPipeline: (app, id) => new AshDistributedPipelineStack(app, id),
};

/** Collapse a CloudFormation `Fn::Join`/`Ref` tree back into text. */
function flatten(node: unknown): string {
  if (typeof node === 'string') return node;
  if (Array.isArray(node)) return node.map(flatten).join('');
  if (node && typeof node === 'object') {
    const obj = node as Record<string, any>;
    if (obj['Fn::Join']) {
      const [separator, parts] = obj['Fn::Join'];
      return (parts as unknown[]).map(flatten).join(separator as string);
    }
    if (obj.Ref) return `<${obj.Ref}>`;
    if (obj['Fn::GetAtt']) return `<${(obj['Fn::GetAtt'] as string[]).join('.')}>`;
  }
  return String(node);
}

function templateFor(stack: string): Template {
  const app = new App({ analyticsReporting: false });
  return Template.fromStack(STACKS[stack](app, stack));
}

const TEMPLATES: Record<string, Template> = Object.fromEntries(
  Object.keys(STACKS).map((name) => [name, templateFor(name)]),
);

const STACK_NAMES = Object.keys(STACKS);

describe('the default rebuild cadence does not fire on creation', () => {
  test('DEFAULT_REBUILD_SCHEDULE is a cron expression, not a rate expression', () => {
    // A rate() default is what produced the observed double build. cron() fires
    // only at the times it names, so a newly created rule stays quiet.
    expect(DEFAULT_REBUILD_SCHEDULE).toMatch(/^cron\(/);
    expect(DEFAULT_REBUILD_SCHEDULE).not.toMatch(/^rate\(/);
  });

  test.each(STACK_NAMES)('%s ships that default in its template', (stack) => {
    const parameters = TEMPLATES[stack].toJSON().Parameters ?? {};
    if (!parameters.RebuildSchedule) return; // Not every stack takes the parameter.
    expect(parameters.RebuildSchedule.Default).toBe(DEFAULT_REBUILD_SCHEDULE);
  });
});

describe('the rebuild schedule cannot run alongside the bootstrap build', () => {
  /** Logical ids of the bootstrap custom resources in one stack. */
  function bootstraps(template: Template): string[] {
    return Object.keys(template.findResources('Custom::AshImageBootstrap'));
  }

  /**
   * Only the rebuild rules. The CodeCommit gate stack also has a pull-request
   * event rule, which has nothing to do with image builds; asserting over every
   * `AWS::Events::Rule` would fail on it for the wrong reason.
   */
  function rebuildRules(template: Template): [string, any][] {
    return Object.entries<any>(template.findResources('AWS::Events::Rule')).filter(
      ([id]) => id.includes('RebuildSchedule'),
    );
  }

  test('the fixture actually contains bootstraps and rebuild rules', () => {
    // Both filters could silently match nothing after a rename, which would make
    // every assertion below vacuously true.
    const withBootstrap = STACK_NAMES.filter((s) => bootstraps(TEMPLATES[s]).length > 0);
    const withRules = STACK_NAMES.filter((s) => rebuildRules(TEMPLATES[s]).length > 0);
    expect(withBootstrap.length).toBeGreaterThanOrEqual(3);
    expect(withRules.length).toBeGreaterThanOrEqual(3);
  });

  test.each(STACK_NAMES)('%s withholds its rebuild rule until the image exists', (stack) => {
    const template = TEMPLATES[stack];
    const bootstrapIds = bootstraps(template);
    if (bootstrapIds.length === 0) {
      // AshImagePipeline and the sharded executor bootstrap another way, so there
      // is no build for a schedule to collide with. Nothing to order against.
      return;
    }
    for (const [ruleId, rule] of rebuildRules(template)) {
      const dependsOn: string[] = [].concat(rule.DependsOn ?? []);
      const ordered = bootstrapIds.some((id) => dependsOn.includes(id));
      expect(ordered).toBe(true);
      expect(ruleId).toBeTruthy();
    }
  });

  test.each(STACK_NAMES)('%s allows one concurrent build per image project', (stack) => {
    // Ordering only covers stack CREATE. On an UPDATE the rule already exists and
    // fires on its own schedule, so the project itself has to refuse the overlap
    // rather than let two builds publish the same mutable tag.
    const projects = Object.entries<any>(
      TEMPLATES[stack].findResources('AWS::CodeBuild::Project'),
    );
    const imageProjects = projects.filter(([, resource]) =>
      flatten(resource.Properties.Source.BuildSpec).includes('ASH_VERSION_TAG_SUFFIX'),
    );
    expect(imageProjects.length).toBeGreaterThan(0);
    for (const [, resource] of imageProjects) {
      expect(resource.Properties.ConcurrentBuildLimit).toBe(1);
    }
  });
});

describe('the buildspec writes only the scripts its flavors need', () => {
  const ENTRYPOINT = 'ash-src/ash-mcp-entrypoint.sh';
  const GATE_HANDLER = 'ash-src/ash_gate_handler.py';

  interface Spec {
    readonly name: string;
    readonly commands: string[];
  }

  function imageSpecs(): Spec[] {
    const found: Spec[] = [];
    for (const stack of STACK_NAMES) {
      for (const [id, resource] of Object.entries<any>(
        TEMPLATES[stack].findResources('AWS::CodeBuild::Project'),
      )) {
        const spec = JSON.parse(flatten(resource.Properties.Source.BuildSpec));
        const commands: string[] = spec.phases?.build?.commands ?? [];
        if (commands.some((c) => c.includes('ASH_VERSION_TAG_SUFFIX'))) {
          found.push({ name: `${stack}/${id}`, commands });
        }
      }
    }
    return found;
  }

  const SPECS = imageSpecs();
  const joined = (spec: Spec) => spec.commands.join('\n');
  const buildsMcp = (spec: Spec) => joined(spec).includes('-t "ash-mcp:local"');
  const buildsLambda = (spec: Spec) => joined(spec).includes('-t "ash-lambda:local"');

  test('there are image build projects to check, and they differ in flavor', () => {
    expect(SPECS.length).toBeGreaterThanOrEqual(6);
    // If every project built every flavor, an "only what it needs" assertion
    // would be satisfied by writing both scripts everywhere.
    expect(SPECS.some(buildsLambda)).toBe(true);
    expect(SPECS.some((s) => !buildsLambda(s))).toBe(true);
  });

  test.each(SPECS.map((s) => [s.name, s] as const))(
    '%s writes the MCP entrypoint exactly when it builds the mcp flavor',
    (_name, spec) => {
      expect(joined(spec).includes(ENTRYPOINT)).toBe(buildsMcp(spec));
    },
  );

  test.each(SPECS.map((s) => [s.name, s] as const))(
    '%s writes the gate handler exactly when it builds the lambda flavor',
    (_name, spec) => {
      // This is the defect as a property. The gate handler was written by every
      // build, so it reached templates whose stacks create no Lambda -- including
      // the sharded executor, which needs neither script.
      expect(joined(spec).includes(GATE_HANDLER)).toBe(buildsLambda(spec));
    },
  );
});
