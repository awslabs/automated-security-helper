/**
 * The merge action, like each shard, hands ASH the operator's config or `{}`.
 *
 * The merge project sets `ASH_CONFIG` as a project variable, and its pre_build writes
 * the base config there, or `{}` (ASH's defaults) when none was supplied, so no ASH
 * config committed in the repository is read. ash-distributed-pipeline-results.test.ts
 * checks the shard; this checks the merge the same way, by running the committed
 * pre_build config command and build command against a stand-in `ash` that records
 * what it was given.
 */

import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { AshDistributedPipelineStack } from '../lib/ash-distributed-pipeline-stack';
import { CfnResolver, synth } from './support/cfn';
import { AshRecord, fakeAshScript, python3, readLines } from './support/gate-harness';

const PIPELINE = synth((app) => new AshDistributedPipelineStack(app, 'AshDistributedPipeline'));

function mergeSpec(): { preBuild: string[]; build: string[] } {
  const resolver = new CfnResolver(PIPELINE);
  const merge = Object.values(PIPELINE.Resources).find(
    (resource) =>
      resource.Type === 'AWS::CodeBuild::Project' &&
      String(resource.Properties?.Description ?? '').startsWith('Merges '),
  );
  if (!merge) throw new Error('no merge project in AshDistributedPipeline');
  const spec = JSON.parse(String(resolver.resolve(merge.Properties?.Source?.BuildSpec)));
  const preBuild = (spec.phases.pre_build.commands as string[]).filter((c) =>
    c.includes('ASH_BASE_CONFIG_SSM_PARAMETER'),
  );
  if (preBuild.length !== 1) throw new Error(`expected one config command, found ${preBuild.length}`);
  return { preBuild, build: spec.phases.build.commands as string[] };
}

function runMerge(baseConfig?: string): AshRecord[] {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ash-merge-config-'));
  try {
    const bin = path.join(dir, 'bin');
    const py = path.join(dir, 'py', 'boto3');
    fs.mkdirSync(bin);
    fs.mkdirSync(py, { recursive: true });
    const record = path.join(dir, 'ash.jsonl');
    fs.writeFileSync(path.join(bin, 'ash'), fakeAshScript(python3(), record, 0), { mode: 0o755 });
    fs.writeFileSync(
      path.join(py, '__init__.py'),
      [
        'class _C:',
        '    def get_parameter(self, **kwargs):',
        `        return {"Parameter": {"Value": ${JSON.stringify(baseConfig ?? '')}}}`,
        'def client(service, *a, **k):',
        '    return _C()',
        '',
      ].join('\n'),
    );
    const env = {
      PATH: `${bin}:${path.dirname(python3())}:${process.env.PATH ?? '/usr/bin:/bin'}`,
      PYTHONPATH: path.join(dir, 'py'),
      HOME: dir,
      ASH_CONFIG: path.join(dir, 'ash-config', '.ash.yaml'),
      ASH_BASE_CONFIG_SSM_PARAMETER: baseConfig === undefined ? '' : '/ash/base-config',
    };
    const { preBuild, build } = mergeSpec();
    for (const command of [...preBuild, ...build]) {
      spawnSync('sh', ['-c', command], { cwd: dir, env });
    }
    return readLines<AshRecord>(record);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('control: the merge build command runs ash merge', () => {
  const [ash] = runMerge('project_name: operator-base-config\n');
  expect(ash).toBeDefined();
  expect(ash.argv[0]).toBe('merge');
});

test('with a base config, ash merge is pointed at it', () => {
  const [ash] = runMerge('project_name: operator-base-config\n');
  expect({ exists: ash.effective_config_exists, content: ash.effective_config_content }).toEqual({
    exists: true,
    content: 'project_name: operator-base-config\n',
  });
});

test('with no base config, ash merge is pointed at `{}`, ASH\'s defaults', () => {
  const [ash] = runMerge();
  expect({ exists: ash.effective_config_exists, content: ash.effective_config_content }).toEqual({
    exists: true,
    content: '{}\n',
  });
});
