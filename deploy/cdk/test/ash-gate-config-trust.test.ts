/**
 * The CodeCommit gate scans with the operator's configuration, never the pull request's.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The gate clones the pull request and runs `ash scan` over it. With no `--config`
 * and no `ASH_CONFIG`, ASH looks for a config inside the scanned tree
 * (`_discovered_config_path`, interactions/run_ash_scan.py), which here is the pull
 * request. The gate's verdict follows the operator's settings instead, including
 * `AshBaseConfigYaml`, which the stack stores in SSM and hands to the function by
 * name.
 *
 * What these tests require, observed at the boundary that matters -- what the real
 * handler hands to `ash`:
 *
 * - ash is always given a config file the operator controls, by `--config` or
 *   `ASH_CONFIG`, which makes ASH skip discovery (run_ash_scan.py:1900-1906). It
 *   exists when ash starts and lives outside the cloned tree.
 * - With `AshBaseConfigYaml` supplied, that file holds exactly the operator's
 *   document. With none supplied, it is still the operator's (a default), never a
 *   file from the pull request.
 * - The scan runs without the function's AWS credentials. The function's role
 *   comments on and votes on pull requests, and the scan needs neither.
 *
 * The handler is read per invocation, so the configuration is read per invocation
 * too: the Lambda image's ENTRYPOINT is the runtime interface client and runs no
 * script of ours, and an edit to the SSM parameter is meant to apply to the next
 * pull request without an image rebuild.
 */

import * as path from 'path';

import { AshCodeCommitGateStack } from '../lib/ash-codecommit-gate-stack';
import { ASH_MATERIALIZED_CONFIG_PATH } from '../lib/ash-container-scripts';
import { AshAgentCoreStack } from '../lib/ash-agentcore-stack';
import { AshDistributedPipelineStack } from '../lib/ash-distributed-pipeline-stack';
import { AshFargateStack } from '../lib/ash-fargate-stack';
import { ASH_PARAMETER_NAMES } from '../lib/ash-config';
import {
  actionMatches,
  CfnResolver,
  CfnResource,
  CfnTemplate,
  roleOf,
  statementsForRole,
  stringEnvironment,
  synth,
} from './support/cfn';
import {
  CREDENTIAL_VARIABLES,
  FUNCTION_CREDENTIALS,
  GateRun,
  isInside,
  PULL_REQUEST_CONFIG_MARKER,
  runGateHandler,
} from './support/gate-harness';

const GATE = synth((app) => new AshCodeCommitGateStack(app, 'AshCodeCommitGate'));

/** An operator's base configuration, recognizable wherever it lands. */
const OPERATOR_CONFIG = [
  'project_name: operator-base-config',
  'fail_on_findings: true',
  'global_settings:',
  '  severity_threshold: LOW',
  '',
].join('\n');

/** The pull-request scan function: the container-image Lambda, not the bootstrap starter. */
function scanFunction(template: CfnTemplate): [string, CfnResource] {
  const found = Object.entries(template.Resources).filter(
    ([, resource]) => resource.Type === 'AWS::Lambda::Function' && resource.Properties?.PackageType === 'Image',
  );
  if (found.length !== 1) {
    throw new Error(`expected exactly one container-image Lambda function, found ${found.length}`);
  }
  return found[0];
}

/** The scan function's environment at a launch with these parameter values. */
function gateEnvironment(parameters: Record<string, string> = {}): Record<string, string> {
  const resolver = new CfnResolver(GATE, { parameters });
  const [, fn] = scanFunction(GATE);
  const variables = fn.Properties?.Environment?.Variables;
  if (!variables) {
    throw new Error('the scan function declares no environment');
  }
  return stringEnvironment(resolver.resolve(variables));
}

function onlyAshCall(run: GateRun) {
  expect({ ashCalls: run.ash.length, outcome: run.outcome, stderr: run.stderr.slice(-2000) }).toEqual(
    expect.objectContaining({ ashCalls: 1 }),
  );
  return run.ash[0];
}

describe('CodeCommit gate harness (controls: these pass on the unmodified base)', () => {
  test('the real handler clones the pull request and hands the clone to ash', () => {
    const run = runGateHandler({ env: gateEnvironment(), ashExit: 0 });
    const ash = onlyAshCall(run);

    expect(run.cloneDir).not.toBeNull();
    expect(ash.argv[0]).toBe('scan');
    expect(ash.source_dir).toBe(run.cloneDir);
  });

  test('the environment ash records is the scan environment the handler built', () => {
    // The handler points HOME at its own writable workdir under /tmp. Seeing that
    // HOME in the record is what shows the record describes the scan's environment
    // and not the harness's.
    const run = runGateHandler({ env: gateEnvironment(), ashExit: 0 });
    const ash = onlyAshCall(run);

    expect(run.cloneDir).not.toBeNull();
    expect(ash.env.HOME).toBe(path.dirname(run.cloneDir as string));
  });

  test.each([
    [2, 'failed', 'REVOKE'],
    [0, 'passed', 'APPROVE'],
  ])('ash exit %i is reported as %s and votes %s when ApprovalGate is on', (exit, verdict, vote) => {
    const run = runGateHandler({ env: gateEnvironment({ ApprovalGate: 'true' }), ashExit: exit });

    expect(run.outcome).toEqual(expect.objectContaining({ verdict, exitCode: exit }));
    const votes = run.boto3.filter((call) => call.method === 'update_pull_request_approval_state');
    expect(votes.map((call) => call.kwargs?.approvalState)).toEqual([vote]);
  });
});

describe('CodeCommit gate: the operator decides the configuration', () => {
  test('with no base config, ash is given an operator config file outside the cloned tree', () => {
    const run = runGateHandler({ env: gateEnvironment(), ashExit: 0 });
    const ash = onlyAshCall(run);

    expect({
      effectiveConfig: ash.effective_config,
      exists: ash.effective_config_exists,
    }).toEqual({ effectiveConfig: expect.any(String), exists: true });
    expect(isInside(ash.effective_config as string, run.cloneDir as string)).toBe(false);
    expect(ash.effective_config_content ?? '').not.toContain(PULL_REQUEST_CONFIG_MARKER);
  });

  test('with AshBaseConfigYaml supplied, ash scans with exactly that document', () => {
    const env = gateEnvironment({ [ASH_PARAMETER_NAMES.ashBaseConfigYaml]: OPERATOR_CONFIG });
    const run = runGateHandler({ env, ashExit: 0, ssmValue: OPERATOR_CONFIG });
    const ash = onlyAshCall(run);

    expect(ash.effective_config_exists).toBe(true);
    expect(isInside(ash.effective_config as string, run.cloneDir as string)).toBe(false);
    expect((ash.effective_config_content ?? '').trimEnd()).toBe(OPERATOR_CONFIG.trimEnd());
  });

  test('a base config that cannot be read refuses the scan instead of falling back', () => {
    // Fail closed: an operator who supplied a config gets that config or no
    // verdict at all, never ASH's defaults (or the pull request's file) quietly.
    // The refusal still reaches the pull request and withdraws a standing
    // approval, like every other refusal in this handler.
    const env = gateEnvironment({
      [ASH_PARAMETER_NAMES.ashBaseConfigYaml]: OPERATOR_CONFIG,
      ApprovalGate: 'true',
    });
    const run = runGateHandler({ env, ashExit: 0, ssmValue: undefined });

    expect({ ashInvocations: run.ash.length }).toEqual({ ashInvocations: 0 });
    const votes = run.boto3.filter((call) => call.method === 'update_pull_request_approval_state');
    expect(votes.map((call) => call.kwargs?.approvalState)).toEqual(['REVOKE']);
    expect(run.boto3.some((call) => call.method === 'post_comment_for_pull_request')).toBe(true);
  });

  test('the scan runs without the function role credentials', () => {
    const run = runGateHandler({ env: gateEnvironment(), ashExit: 0 });
    const ash = onlyAshCall(run);

    const leaked = CREDENTIAL_VARIABLES.filter((name) => {
      const value = ash.env[name];
      return value !== null && value !== undefined && Object.values(FUNCTION_CREDENTIALS).includes(value);
    });
    expect(leaked).toEqual([]);
  });
});

describe('CodeCommit gate: the template describes what the function does', () => {
  /** Logical id of the scan function's role. */
  function scanRole(template: CfnTemplate): string {
    const [, fn] = scanFunction(template);
    return roleOf(fn.Properties?.Role);
  }

  function grantedActions(template: CfnTemplate, role: string, parameters: Record<string, string> = {}) {
    const resolver = new CfnResolver(template, { parameters });
    return statementsForRole(template, role, resolver)
      .filter((statement) => statement.effect === 'Allow')
      .flatMap((statement) => statement.actions);
  }

  test('the gate calls Systems Manager exactly when its descriptions and grants say it does', () => {
    const parameters = { [ASH_PARAMETER_NAMES.ashBaseConfigYaml]: OPERATOR_CONFIG };
    const run = runGateHandler({
      env: gateEnvironment(parameters),
      ashExit: 0,
      ssmValue: OPERATOR_CONFIG,
    });
    const callsSsm = run.boto3.some((call) => call.service === 'ssm' && call.method !== '__client__');

    const describe = (name: string) => String(GATE.Parameters?.[name]?.Description ?? '');
    const networkDescriptions = [
      describe(ASH_PARAMETER_NAMES.scanEgressCidr),
      describe(ASH_PARAMETER_NAMES.vpcSubnetIds),
    ].join(' ');
    const descriptionsNameSsm = /\bssm\b|systems manager/i.test(networkDescriptions);

    const grantsSsm = grantedActions(GATE, scanRole(GATE), parameters).some((action) =>
      actionMatches(action, 'ssm:GetParameter'),
    );

    expect({ callsSsm, descriptionsNameSsm, grantsSsm }).toEqual({
      callsSsm,
      descriptionsNameSsm: callsSsm,
      grantsSsm: callsSsm,
    });
  });

  test('the scan role holds no Secrets Manager grant, since the gate reads no secret', () => {
    const secretActions = grantedActions(GATE, scanRole(GATE)).filter((action) =>
      action.toLowerCase().startsWith('secretsmanager:'),
    );
    expect(secretActions).toEqual([]);
  });

  test.each([
    ['AshCodeCommitGate', GATE],
    ['AshAgentCore', synth((app) => new AshAgentCoreStack(app, 'AshAgentCore'))],
    ['AshFargate', synth((app) => new AshFargateStack(app, 'AshFargate'))],
    ['AshDistributedPipeline', synth((app) => new AshDistributedPipelineStack(app, 'AshDistributedPipeline'))],
  ])('%s describes AshBaseConfigYaml without naming a path nothing writes', (_name, template) => {
    // The description said the document is "written to .ash/.ash.yaml inside the
    // container". The targets write it to ASH_MATERIALIZED_CONFIG_PATH and point
    // ASH at it; nothing writes .ash/.ash.yaml, and a reader who goes looking for
    // it there finds nothing.
    const description = String(template.Parameters?.[ASH_PARAMETER_NAMES.ashBaseConfigYaml]?.Description);
    expect(description).not.toContain('.ash/.ash.yaml');
    for (const absolute of description.match(/\/[A-Za-z0-9._/-]+\.ya?ml/g) ?? []) {
      expect(absolute).toBe(ASH_MATERIALIZED_CONFIG_PATH);
    }
  });
});
