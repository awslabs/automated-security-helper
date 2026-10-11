/**
 * What the CodeCommit gate scans by default.
 *
 * WHY CHANGEDFILESONLY IS OFF BY DEFAULT
 * --------------------------------------
 * With `--changed-files-only --base-ref <destination>`, ASH keeps only the findings
 * whose file appears in `git diff --name-only`. git prints a name with a non-ASCII
 * byte, a quote, a backslash or a control character C-quoted (`"\303\251.py"`),
 * which matches no scanned path, so findings in such a file are not counted, and
 * neither are findings in files the pull request did not touch. The gate scans the
 * whole tree unless an operator turns the narrowing on.
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

describe('ChangedFilesOnly', () => {
  test('defaults to false', () => {
    expect(GATE.Parameters?.ChangedFilesOnly?.Default).toBe('false');
  });

  test('says what turning it on costs', () => {
    expect(String(GATE.Parameters?.ChangedFilesOnly?.Description)).toMatch(/quot/i);
  });

  test('at the shipped defaults, ash scans the whole tree', () => {
    const run = runGateHandler({ env: gateEnvironment(), ashExit: 0 });
    const [scan] = scanCalls(run);

    expect(scan).toBeDefined();
    expect(scan.argv).not.toContain('--changed-files-only');
    expect(scan.argv).not.toContain('--base-ref');
  });

  test('control: an operator who turns it on gets the narrowed scan', () => {
    const run = runGateHandler({ env: gateEnvironment({ ChangedFilesOnly: 'true' }), ashExit: 0 });
    const [scan] = scanCalls(run);

    expect(scan.argv).toEqual(expect.arrayContaining(['--changed-files-only', '--base-ref']));
  });
});
