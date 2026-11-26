/**
 * The CDK CodeCommit gate names the scan's subject when its ASH has one.
 *
 * ASH 3.9 scans a directory with `ash scan fs PATH`. The subject-less
 * `ash scan --source-dir PATH` still scans there but prints a deprecation line, and it
 * goes in ASH v4.0. The gate's image is built from `AshVersion`, which can name a
 * release older than 3.9 (the stack's default does until the release commit moves
 * it), and that release has no `fs` subject. So the handler asks the image's ASH once,
 * with the same probe that checks for `--fail-on-incomplete-scanners`, and scans the
 * way it answers. A gate that always used the new form would fail every pull request
 * on an older image; one that always used the old form would put a deprecation line
 * in every scan log on a current one. The Terraform gate does the same, which
 * tests/unit/deploy/test_codecommit_gate_scan_subject.py holds.
 */

import { AshCodeCommitGateStack } from '../lib/ash-codecommit-gate-stack';
import { CfnResolver, CfnResource, CfnTemplate, stringEnvironment, synth } from './support/cfn';
import { AshRelease, GateRun, runGateHandler } from './support/gate-harness';

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

function scans(run: GateRun) {
  return run.ash.filter((call) => call.argv[0] === 'scan');
}

describe('the directory the gate hands ash', () => {
  test('an ASH with the fs subject scans the clone as the subject\'s PATH', () => {
    const run = runGateHandler({ env: gateEnvironment(), ashExit: 0, ashRelease: 'with-subject' });

    expect(run.cloneDir).not.toBeNull();
    expect(scans(run)).toHaveLength(1);
    const [scan] = scans(run);
    expect(scan.argv.slice(0, 3)).toEqual(['scan', 'fs', run.cloneDir]);
    expect(scan.argv).not.toContain('--source-dir');
    expect(scan.argv).toContain('--fail-on-incomplete-scanners');
  });

  test('control: an ASH without it scans the clone with --source-dir', () => {
    const run = runGateHandler({ env: gateEnvironment(), ashExit: 0, ashRelease: 'without-subject' });

    expect(run.cloneDir).not.toBeNull();
    expect(scans(run)).toHaveLength(1);
    const [scan] = scans(run);
    expect(scan.argv[1]).not.toBe('fs');
    expect(scan.scan_path).toBeNull();
    expect(scan.source_dir).toBe(run.cloneDir);
    expect(scan.argv).toContain('--fail-on-incomplete-scanners');
  });

  test.each<AshRelease>(['with-subject', 'without-subject'])(
    'on an ASH %s the probes are not scans, and a clean scan passes',
    (release) => {
      const run = runGateHandler({
        env: gateEnvironment({ ApprovalGate: 'true' }),
        ashExit: 0,
        ashRelease: release,
      });

      expect(run.ash).toHaveLength(1);
      expect(run.outcome).toEqual(expect.objectContaining({ verdict: 'passed' }));
    },
  );

  test('control: an ASH with the subject whose help lacks the completeness flag is refused', () => {
    const run = runGateHandler({
      env: gateEnvironment({ ApprovalGate: 'true' }),
      ashExit: 0,
      ashScanHelp: 'missing',
      ashRelease: 'with-subject',
    });

    expect(scans(run)).toEqual([]);
    const votes = run.boto3.filter((call) => call.method === 'update_pull_request_approval_state');
    expect(votes.map((call) => call.kwargs?.approvalState)).toEqual(['REVOKE']);
  });
});
