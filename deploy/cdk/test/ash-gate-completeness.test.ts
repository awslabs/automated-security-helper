/**
 * The CodeCommit gate refuses to scan with an ASH that cannot fail an incomplete scan.
 *
 * The gate passes `--fail-on-incomplete-scanners`, so a scan whose scanners never ran
 * is an error rather than a pass. An ASH whose `ash scan` has no such option (every
 * release up to v3.7.1) collects unknown options without using them, so there the
 * flag has no effect and a scan that ran nothing exits 0. So the handler asks
 * `ash scan --help`
 * once whether the option exists and refuses, with a comment and a REVOKE, when it
 * does not.
 */

import { AshCodeCommitGateStack } from '../lib/ash-codecommit-gate-stack';
import { CfnResolver, CfnResource, CfnTemplate, stringEnvironment, synth } from './support/cfn';
import { GateRun, runGateHandler } from './support/gate-harness';

const GATE = synth((app) => new AshCodeCommitGateStack(app, 'AshCodeCommitGate'));

function scanFunction(template: CfnTemplate): CfnResource {
  const found = Object.values(template.Resources).filter(
    (resource) => resource.Type === 'AWS::Lambda::Function' && resource.Properties?.PackageType === 'Image',
  );
  if (found.length !== 1) throw new Error(`expected one container-image Lambda, found ${found.length}`);
  return found[0];
}

function gateEnvironment(parameters: Record<string, string> = {}): Record<string, string> {
  const resolver = new CfnResolver(GATE, { parameters });
  return stringEnvironment(resolver.resolve(scanFunction(GATE).Properties?.Environment?.Variables));
}

function scanCalls(run: GateRun) {
  return run.ash.filter((call) => call.argv[0] === 'scan');
}

describe('the completeness flag', () => {
  test('ash is always told to fail a scan whose scanners did not all run', () => {
    const run = runGateHandler({ env: gateEnvironment(), ashExit: 0 });
    const [scan] = scanCalls(run);

    expect(scan.argv).toContain('--fail-on-incomplete-scanners');
  });

  test('an ASH whose ash scan lacks it is refused, with a comment and a REVOKE', () => {
    const run = runGateHandler({
      env: gateEnvironment({ ApprovalGate: 'true' }),
      ashExit: 0,
      ashScanHelp: 'missing',
    });

    expect(scanCalls(run)).toEqual([]);
    const votes = run.boto3.filter((call) => call.method === 'update_pull_request_approval_state');
    expect(votes.map((call) => call.kwargs?.approvalState)).toEqual(['REVOKE']);
    const comments = run.boto3.filter((call) => call.method === 'post_comment_for_pull_request');
    expect(comments.map((call) => String(call.kwargs?.content))).toEqual([
      expect.stringContaining('--fail-on-incomplete-scanners'),
    ]);
  });

  test('a probe that fails refuses rather than guessing', () => {
    const run = runGateHandler({
      env: gateEnvironment({ ApprovalGate: 'true' }),
      ashExit: 0,
      ashScanHelp: 'fails',
    });

    expect(scanCalls(run)).toEqual([]);
    const votes = run.boto3.filter((call) => call.method === 'update_pull_request_approval_state');
    expect(votes.map((call) => call.kwargs?.approvalState)).toEqual(['REVOKE']);
  });

  test('help printed in colour still counts', () => {
    const run = runGateHandler({ env: gateEnvironment(), ashExit: 0, ashScanHelp: 'coloured' });

    expect(scanCalls(run)).toHaveLength(1);
  });

  test('control: an ASH that has it scans and can pass', () => {
    const run = runGateHandler({ env: gateEnvironment({ ApprovalGate: 'true' }), ashExit: 0 });

    expect(scanCalls(run)).toHaveLength(1);
    expect(run.outcome).toEqual(expect.objectContaining({ verdict: 'passed' }));
  });
});
