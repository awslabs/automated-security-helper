/**
 * The McpAuthHeaderValue secret exists only on the targets that serve MCP.
 *
 * AshCodeCommitGate runs ASH as a one-shot Lambda and AshDistributedPipeline runs
 * sharded CodeBuild jobs. Neither serves an MCP endpoint, and neither hands the
 * secret's ARN to anything, so a secret there is a resource plus IAM read grants
 * on a value no code path uses. The shared Config construct used to create one
 * anyway, to keep a single class shape. These tests pin the narrower shape.
 *
 * They read the committed templates, which are what an adopter launches; the
 * template drift check keeps those equal to a fresh synth.
 */

import * as fs from 'fs';
import * as path from 'path';

import { App, Stack } from 'aws-cdk-lib';

import { AshCustomerKey } from '../lib/ash-config';
import { AshRuntimeConfig } from '../lib/ash-runtime-config';

const TEMPLATE_DIR = path.join(__dirname, '..', 'templates');

function template(stack: string): Record<string, any> {
  return JSON.parse(fs.readFileSync(path.join(TEMPLATE_DIR, `${stack}.template.json`), 'utf8'));
}

function resourcesOfType(stack: string, type: string): string[] {
  return Object.entries<any>(template(stack).Resources ?? {})
    .filter(([, resource]) => resource.Type === type)
    .map(([logicalId]) => logicalId);
}

/** Every IAM action string granted anywhere in the template, from any policy shape. */
function grantedActions(stack: string): string[] {
  const actions: string[] = [];
  const visit = (node: unknown): void => {
    if (Array.isArray(node)) {
      node.forEach(visit);
    } else if (node && typeof node === 'object') {
      for (const [key, value] of Object.entries(node)) {
        if (key === 'Action') {
          actions.push(...(Array.isArray(value) ? value : [value]).filter((a) => typeof a === 'string'));
        } else {
          visit(value);
        }
      }
    }
  };
  visit(template(stack).Resources);
  return actions;
}

const MCP_TARGETS = ['AshAgentCore', 'AshFargate'];
const NON_MCP_TARGETS = ['AshCodeCommitGate', 'AshDistributedPipeline'];

describe('the MCP auth secret is scoped to the targets that serve MCP', () => {
  test.each(NON_MCP_TARGETS)('%s creates no Secrets Manager secret', (stack) => {
    expect(resourcesOfType(stack, 'AWS::SecretsManager::Secret')).toEqual([]);
  });

  test.each(NON_MCP_TARGETS)('%s grants no Secrets Manager action', (stack) => {
    const actions = grantedActions(stack);
    // Non-vacuity: the walk must find the stack's real grants, or an empty list
    // would pass the assertion below for the wrong reason.
    expect(actions.length).toBeGreaterThan(0);
    expect(actions.filter((a) => a.toLowerCase().startsWith('secretsmanager:'))).toEqual([]);
  });

  test.each(NON_MCP_TARGETS)('%s does not declare the MCP auth parameters', (stack) => {
    const parameters = Object.keys(template(stack).Parameters ?? {});
    expect(parameters.filter((p) => p.startsWith('McpAuthHeader'))).toEqual([]);
  });

  // The positive side, so the assertions above are known to be able to see a
  // secret and a grant when one is there.
  test.each(MCP_TARGETS)('%s still creates exactly one secret and grants read on it', (stack) => {
    expect(resourcesOfType(stack, 'AWS::SecretsManager::Secret')).toHaveLength(1);
    expect(grantedActions(stack)).toContain('secretsmanager:GetSecretValue');
  });
});

describe('AshRuntimeConfig without MCP parameters', () => {
  function build(includeMcpParameters: boolean): AshRuntimeConfig {
    const stack = new Stack(new App({ analyticsReporting: false }), 'Probe');
    return new AshRuntimeConfig(stack, 'Config', {
      includeMcpParameters,
      customerKey: new AshCustomerKey(stack),
    });
  }

  test('has no auth secret, and asking for one fails at synth', () => {
    const config = build(false);
    expect(config.authSecret).toBeUndefined();
    expect(() => config.mcpAuthSecret()).toThrow(/includeMcpParameters: true/);
    expect(() => config.mcpEnvironment()).toThrow(/includeMcpParameters: true/);
  });

  test('with MCP parameters, the secret is there', () => {
    const config = build(true);
    expect(config.mcpAuthSecret()).toBe(config.authSecret);
  });
});
