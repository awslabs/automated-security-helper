/**
 * Drops a `DependsOn` entry when the resource already references its target.
 *
 * WHY THIS EXISTS. CloudFormation orders a resource after everything its
 * properties name through `Ref` or `Fn::GetAtt`, so a `DependsOn` on the same
 * target adds nothing. CDK emits that redundant entry in a few places it does not
 * expose a switch for: a Lambda function depends on its whole role construct (the
 * role and its default policy) while also reading the role's ARN, a CodePipeline
 * depends on its role while also reading the ARN, and an ECS service depends on
 * its target group while also passing the group's ARN. cfn-lint reports every one
 * as W3005. The CI gate runs cfn-lint with no rule ignored, so the templates have
 * to be clean rather than the warning silenced.
 *
 * WHAT IS REMOVED AND WHAT IS KEPT. Only a dependency whose target's logical id
 * appears in the resource's own rendered `Properties` as a `Ref` or a
 * `Fn::GetAtt` is dropped. Everything else stays, and in particular:
 *   - the role's default policy. A function reads the role's ARN, not the
 *     policy's, so the policy dependency is the only thing that stops the
 *     function from being created, and run by a custom resource, before its
 *     permissions are attached;
 *   - any reference inside `Fn::If`. Whether CloudFormation still infers an
 *     ordering from a branch the condition did not select is not something this
 *     code should bet on, so a reference there never counts.
 * The direction of every simplification is toward keeping a dependency. A missed
 * reference leaves a redundant entry that cfn-lint will report. A wrongly
 * dropped one would be a deploy-time race, which nothing offline would catch.
 *
 * WHEN IT RUNS. Construct-level dependencies (`node.addDependency`) become
 * `DependsOn` entries during CDK's prepare phase, after every aspect has run, so
 * neither a constructor nor an aspect can see them. `AshStackSynthesizer` calls
 * this from `synthesizeTemplate`, which CDK invokes after prepare and immediately
 * before it renders the template.
 *
 * `_toCloudFormation` is CDK-internal. It is used because it renders the resource
 * exactly as the template will hold it, overrides included, which is the only
 * thing a reference check can safely be run against. aws-cdk-lib is pinned by
 * package-lock.json, and if the method ever disappears this throws at synth
 * rather than silently keeping or dropping anything.
 */

import { CfnResource, Stack } from 'aws-cdk-lib';
import { IConstruct } from 'constructs';

/** One dropped dependency, for tests and for anyone debugging a template diff. */
export interface PrunedDependency {
  readonly source: string;
  readonly target: string;
}

interface RendersCloudFormation {
  _toCloudFormation(): unknown;
}

function renderedProperties(stack: Stack, resource: CfnResource): unknown {
  const renderable = resource as unknown as Partial<RendersCloudFormation>;
  if (typeof renderable._toCloudFormation !== 'function') {
    throw new Error(
      `CfnResource ${resource.node.path} has no _toCloudFormation. aws-cdk-lib changed an internal ` +
        'API that ash-implied-dependencies.ts relies on; update the reference check before synthesizing.',
    );
  }
  const rendered = stack.resolve(renderable._toCloudFormation()) as {
    Resources?: Record<string, { Properties?: unknown }>;
  };
  const logicalId = stack.resolve(resource.logicalId) as string;
  return rendered.Resources?.[logicalId]?.Properties;
}

/**
 * Logical ids named by `Ref` or `Fn::GetAtt` anywhere in `value`, except under
 * `Fn::If`.
 */
export function referencedLogicalIds(value: unknown, found: Set<string> = new Set()): Set<string> {
  if (Array.isArray(value)) {
    for (const item of value) {
      referencedLogicalIds(item, found);
    }
    return found;
  }
  if (value === null || typeof value !== 'object') {
    return found;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length === 1) {
    const [key] = keys;
    const arg = record[key];
    if (key === 'Fn::If') {
      return found;
    }
    if (key === 'Ref' && typeof arg === 'string') {
      found.add(arg);
      return found;
    }
    if (key === 'Fn::GetAtt') {
      if (Array.isArray(arg) && typeof arg[0] === 'string') {
        found.add(arg[0]);
      } else if (typeof arg === 'string') {
        found.add(arg.split('.')[0]);
      }
      return found;
    }
  }
  for (const key of keys) {
    referencedLogicalIds(record[key], found);
  }
  return found;
}

/** Removes every `DependsOn` entry in `stack` that a `Ref` or `Fn::GetAtt` already implies. */
export function pruneDependenciesImpliedByReferences(stack: Stack): PrunedDependency[] {
  const pruned: PrunedDependency[] = [];
  const resources = stack.node
    .findAll()
    .filter((c: IConstruct): c is CfnResource => CfnResource.isCfnResource(c) && Stack.of(c) === stack);

  for (const resource of resources) {
    const targets = resource
      .obtainDependencies()
      .filter((d): d is CfnResource => CfnResource.isCfnResource(d) && Stack.of(d) === stack);
    if (targets.length === 0) {
      continue;
    }
    const referenced = referencedLogicalIds(renderedProperties(stack, resource));
    for (const target of targets) {
      const targetId = stack.resolve(target.logicalId) as string;
      if (referenced.has(targetId)) {
        resource.removeResourceDependency(target);
        pruned.push({ source: stack.resolve(resource.logicalId) as string, target: targetId });
      }
    }
  }
  return pruned;
}
