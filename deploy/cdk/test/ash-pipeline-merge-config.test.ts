/**
 * The merge action, like each shard, never hands ASH a config path that names no file.
 *
 * The merge project sets `ASH_CONFIG` as a project variable and its pre_build writes the
 * file only when a base config was supplied. ASH treats an explicit config path that
 * does not exist as a config error, so the build command unsets the variable, in its
 * own shell, when the file is absent. ash-distributed-pipeline-results.test.ts checks
 * the shard command; this checks the merge command the same way, by running the
 * committed build command against a stand-in `ash` that records what it was given.
 */

import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { AshDistributedPipelineStack } from '../lib/ash-distributed-pipeline-stack';
import { CfnResolver, synth } from './support/cfn';
import { AshRecord, fakeAshScript, python3, readLines } from './support/gate-harness';

const PIPELINE = synth((app) => new AshDistributedPipelineStack(app, 'AshDistributedPipeline'));

function mergeBuildCommands(): string[] {
  const resolver = new CfnResolver(PIPELINE);
  const merge = Object.values(PIPELINE.Resources).find(
    (resource) =>
      resource.Type === 'AWS::CodeBuild::Project' &&
      String(resource.Properties?.Description ?? '').startsWith('Merges '),
  );
  if (!merge) throw new Error('no merge project in AshDistributedPipeline');
  const spec = JSON.parse(String(resolver.resolve(merge.Properties?.Source?.BuildSpec)));
  return spec.phases.build.commands as string[];
}

function runMerge(configExists: boolean): AshRecord[] {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ash-merge-config-'));
  try {
    const bin = path.join(dir, 'bin');
    fs.mkdirSync(bin);
    const record = path.join(dir, 'ash.jsonl');
    fs.writeFileSync(path.join(bin, 'ash'), fakeAshScript(python3(), record, 0), { mode: 0o755 });
    const config = path.join(dir, 'ash-config', '.ash.yaml');
    if (configExists) {
      fs.mkdirSync(path.dirname(config), { recursive: true });
      fs.writeFileSync(config, 'project_name: operator-base-config\n');
    }
    for (const command of mergeBuildCommands()) {
      spawnSync('sh', ['-c', command], {
        cwd: dir,
        env: { PATH: `${bin}:${process.env.PATH ?? '/usr/bin:/bin'}`, HOME: dir, ASH_CONFIG: config },
      });
    }
    return readLines<AshRecord>(record);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('control: the merge build command runs ash merge', () => {
  const [ash] = runMerge(true);
  expect(ash).toBeDefined();
  expect(ash.argv[0]).toBe('merge');
});

test('with a base config, ash merge is pointed at it', () => {
  const [ash] = runMerge(true);
  expect({ exists: ash.effective_config_exists, content: ash.effective_config_content }).toEqual({
    exists: true,
    content: 'project_name: operator-base-config\n',
  });
});

test('with no base config, ash merge is pointed at no config at all', () => {
  const [ash] = runMerge(false);
  expect(ash.effective_config).toBeNull();
});
