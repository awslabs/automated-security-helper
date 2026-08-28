/**
 * Rollback must not destroy the evidence for the rollback.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * A Fargate deployment failed with "ECS Deployment Circuit Breaker was
 * triggered" and rolled back. The container stderr that would have said why was
 * in the stack's own `TaskLogs` group, and rollback had already deleted it —
 * CloudFormation removes everything a failed create made. The only group left
 * standing was the ECS-owned `containerinsights/.../performance` one, which
 * carries no stderr.
 *
 * WHY IT ASSERTS OVER EVERY GROUP RATHER THAN THE ONE THAT BIT US
 * -------------------------------------------------------------
 * Because the class was already half-broken in a way the source did not show.
 * The CodeCommit gate's `ScanLogs` was the only group that omitted
 * `removalPolicy`, so it inherited CDK's RETAIN default and survived; the four
 * that explicitly named a policy chose DESTROY. That split was invisible until
 * someone read `DeletionPolicy` out of a synthesized template — which is exactly
 * what this test does, and why it enumerates every group in every stack instead
 * of naming the one that was reported.
 *
 * CONSTRAINT THIS ALSO PINS: retention must stay finite. Retained groups are
 * teardown residuals, so an unbounded retention would let them accumulate cost
 * forever. `RetentionDays.INFINITE` emits no `RetentionInDays` property at all,
 * so "the property is present" is the assertion that catches it.
 */

import { App, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';

import { AshAgentCoreStack } from '../lib/ash-agentcore-stack';
import { AshCodeCommitGateStack } from '../lib/ash-codecommit-gate-stack';
import { AshDistributedPipelineStack } from '../lib/ash-distributed-pipeline-stack';
import { AshFargateStack } from '../lib/ash-fargate-stack';
import { AshImagePipelineStack } from '../lib/ash-image-pipeline-stack';
import { diagnosticLogGroupProps } from '../lib/ash-config';

type StackFactory = (app: App, id: string) => Stack;

const STACKS: Record<string, StackFactory> = {
  AshImagePipeline: (app, id) => new AshImagePipelineStack(app, id),
  AshAgentCore: (app, id) => new AshAgentCoreStack(app, id),
  AshFargate: (app, id) => new AshFargateStack(app, id),
  AshCodeCommitGate: (app, id) => new AshCodeCommitGateStack(app, id),
  AshDistributedPipeline: (app, id) => new AshDistributedPipelineStack(app, id),
};

const STACK_NAMES = Object.keys(STACKS);

const TEMPLATES: Record<string, Template> = Object.fromEntries(
  STACK_NAMES.map((name) => {
    const app = new App({ analyticsReporting: false });
    return [name, Template.fromStack(STACKS[name](app, name))];
  }),
);

function logGroups(stack: string): [string, any][] {
  return Object.entries<any>(TEMPLATES[stack].findResources('AWS::Logs::LogGroup'));
}

/** Every log group in every stack, as `Stack/LogicalId` plus its resource. */
const ALL_GROUPS: [string, string, any][] = STACK_NAMES.flatMap((stack) =>
  logGroups(stack).map(([id, resource]) => [`${stack}/${id}`, stack, resource] as [string, string, any]),
);

describe('diagnostic log groups survive a rollback', () => {
  test('the fixture found log groups in every stack', () => {
    // A findResources filter that matched nothing would make every assertion
    // below vacuously true.
    expect(ALL_GROUPS.length).toBeGreaterThanOrEqual(10);
    for (const stack of STACK_NAMES) {
      expect(logGroups(stack).length).toBeGreaterThan(0);
    }
  });

  test.each(ALL_GROUPS.map(([name, , resource]) => [name, resource] as const))(
    '%s is retained rather than deleted with the stack',
    (_name, resource) => {
      // This is the defect stated as a property over the whole class, so it holds
      // for log groups that do not exist yet.
      expect(resource.DeletionPolicy).toBe('Retain');
    },
  );

  test.each(ALL_GROUPS.map(([name, , resource]) => [name, resource] as const))(
    '%s still expires its events on a finite schedule',
    (_name, resource) => {
      // Retained groups are residuals. Without a bound they would accumulate
      // storage cost indefinitely. RetentionDays.INFINITE emits no property here.
      const days = resource.Properties?.RetentionInDays;
      expect(typeof days).toBe('number');
      expect(days).toBeGreaterThan(0);
    },
  );

  test('every group uses the shared policy rather than its own literal', () => {
    // The shared function is what stops this class being half-fixed again. If a
    // group drifts from it, the two assertions above might still pass while the
    // retention silently differed from every other group.
    const shared = diagnosticLogGroupProps();
    expect(shared.removalPolicy).toBe('retain');
    const distinct = new Set(ALL_GROUPS.map(([, , r]) => r.Properties?.RetentionInDays));
    expect(distinct.size).toBe(1);
  });

  test('no log group pins a physical name', () => {
    /*
     * Load-bearing for the retain decision. A retained group whose name was fixed
     * would collide with itself on the next create, so a stack that had rolled
     * back once could never be deployed again under the same name. Because
     * CloudFormation assigns the name, a re-created stack gets a fresh group and
     * the old one is left as an inert residual.
     */
    for (const [, , resource] of ALL_GROUPS) {
      expect(resource.Properties?.LogGroupName).toBeUndefined();
    }
  });
});
