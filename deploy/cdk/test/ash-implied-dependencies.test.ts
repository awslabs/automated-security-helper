/**
 * Tests for the DependsOn cleanup in lib/ash-implied-dependencies.ts.
 *
 * The cleanup removes entries from a template, so the cases that matter most are
 * the ones where it must NOT remove anything: a dependency the resource does not
 * reference, the role's default policy, and a reference that only exists under
 * Fn::If. The committed-template check at the bottom is the same property cfn-lint
 * W3005 checks in CI, kept here so a local `npm test` reports it too.
 */

import * as fs from 'fs';
import * as path from 'path';

import { App, CfnCondition, CfnParameter, CfnResource, Fn, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as sqs from 'aws-cdk-lib/aws-sqs';

import { ashSynthesizer } from '../lib/ash-config';
import { pruneDependenciesImpliedByReferences, referencedLogicalIds } from '../lib/ash-implied-dependencies';

type Resources = Record<string, { Type: string; Properties?: unknown; DependsOn?: string[] | string }>;

function newStack(): Stack {
  return new Stack(new App(), 'Probe', { synthesizer: ashSynthesizer() });
}

function resources(stack: Stack): Resources {
  return Template.fromStack(stack).toJSON().Resources as Resources;
}

function logicalIdOfType(res: Resources, type: string): string {
  const ids = Object.keys(res).filter((id) => res[id].Type === type);
  expect(ids).toHaveLength(1);
  return ids[0];
}

function dependsOn(res: Resources, id: string): string[] {
  const value = res[id].DependsOn ?? [];
  return Array.isArray(value) ? value : [value];
}

describe('referencedLogicalIds', () => {
  test('collects Ref and both Fn::GetAtt forms, including nested ones', () => {
    const found = referencedLogicalIds({
      A: { Ref: 'One' },
      B: [{ 'Fn::GetAtt': ['Two', 'Arn'] }, { 'Fn::Join': ['', [{ 'Fn::GetAtt': 'Three.Arn' }]] }],
      C: { Ref: 'AWS::Region' },
    });
    expect([...found].sort()).toEqual(['AWS::Region', 'One', 'Three', 'Two']);
  });

  test('ignores everything under Fn::If', () => {
    const found = referencedLogicalIds({ X: { 'Fn::If': ['Cond', { Ref: 'Hidden' }, { Ref: 'AWS::NoValue' }] } });
    expect(found.size).toBe(0);
  });

  test('a key that merely looks like Ref inside a larger object is not a reference', () => {
    expect(referencedLogicalIds({ Ref: 'NotAlone', Other: 1 }).size).toBe(0);
    expect(referencedLogicalIds('Ref').size).toBe(0);
    expect(referencedLogicalIds(null).size).toBe(0);
  });
});

describe('pruneDependenciesImpliedByReferences through ashSynthesizer', () => {
  test('a function keeps its default-policy dependency and loses only the role it reads by GetAtt', () => {
    const stack = newStack();
    const fn = new lambda.Function(stack, 'Fn', {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'index.handler',
      code: lambda.Code.fromInline('def handler(e, c):\n    return None\n'),
    });
    // A grant gives the role a default policy, which is what CDK makes the
    // function depend on alongside the role.
    new sqs.Queue(stack, 'Queue').grantSendMessages(fn);

    const res = resources(stack);
    const fnId = logicalIdOfType(res, 'AWS::Lambda::Function');
    const roleId = logicalIdOfType(res, 'AWS::IAM::Role');
    const policyId = logicalIdOfType(res, 'AWS::IAM::Policy');

    expect(dependsOn(res, fnId)).toEqual([policyId]);
    // The ordering the dropped entry used to state is still stated by the reference.
    expect(referencedLogicalIds(res[fnId].Properties).has(roleId)).toBe(true);
  });

  test('a dependency the resource does not reference is kept', () => {
    const stack = newStack();
    const a = new CfnResource(stack, 'A', { type: 'AWS::SQS::Queue' });
    const b = new CfnResource(stack, 'B', { type: 'AWS::SQS::Queue' });
    b.addResourceDependency(a);

    const res = resources(stack);
    expect(dependsOn(res, 'B')).toEqual(['A']);
  });

  test('a dependency referenced only under Fn::If is kept', () => {
    const stack = newStack();
    // Keyed on a parameter so the condition is not constant, which CDK's own
    // template validation would otherwise warn about.
    const param = new CfnParameter(stack, 'Choice', { type: 'String' });
    const cond = new CfnCondition(stack, 'Cond', { expression: Fn.conditionEquals(param.valueAsString, 'a') });
    const a = new CfnResource(stack, 'A', { type: 'AWS::SQS::Queue' });
    const b = new CfnResource(stack, 'B', {
      type: 'AWS::SNS::Topic',
      properties: { TopicName: Fn.conditionIf(cond.logicalId, a.ref, 'fallback') },
    });
    b.addResourceDependency(a);

    const res = resources(stack);
    expect(dependsOn(res, 'B')).toEqual(['A']);
  });

  test('a dependency referenced by Ref outside Fn::If is dropped and reported', () => {
    const stack = newStack();
    const a = new CfnResource(stack, 'A', { type: 'AWS::SQS::Queue' });
    const b = new CfnResource(stack, 'B', { type: 'AWS::SNS::Topic', properties: { TopicName: a.ref } });
    b.addResourceDependency(a);

    // Called directly so the return value can be inspected. The synthesizer runs
    // it again during synth, which must find nothing left to do.
    expect(pruneDependenciesImpliedByReferences(stack)).toEqual([{ source: 'B', target: 'A' }]);
    const res = resources(stack);
    expect(res.B.DependsOn).toBeUndefined();
  });

  test('a stack built with the plain DefaultStackSynthesizer is left alone (the cleanup is opt-in)', () => {
    const stack = new Stack(new App(), 'Plain');
    const a = new CfnResource(stack, 'A', { type: 'AWS::SQS::Queue' });
    const b = new CfnResource(stack, 'B', { type: 'AWS::SNS::Topic', properties: { TopicName: a.ref } });
    b.addResourceDependency(a);
    expect(dependsOn(resources(stack), 'B')).toEqual(['A']);
  });
});

describe('committed templates', () => {
  const dir = path.join(__dirname, '..', 'templates');
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.template.json'));

  test('there are templates to check', () => {
    expect(files.length).toBeGreaterThan(0);
  });

  test.each(files)('%s has no DependsOn entry its own properties already imply', (file) => {
    const template = JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8')) as { Resources: Resources };
    const redundant: string[] = [];
    for (const [id, resource] of Object.entries(template.Resources)) {
      const referenced = referencedLogicalIds(resource.Properties);
      for (const dep of dependsOn(template.Resources, id)) {
        if (referenced.has(dep)) {
          redundant.push(`${id} -> ${dep}`);
        }
      }
    }
    expect(redundant).toEqual([]);
  });
});
