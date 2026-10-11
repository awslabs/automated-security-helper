/**
 * Each shard can write only its own results, and every shard scans with a config that exists.
 *
 * WHY THE WRITE SCOPE MATTERS
 * ---------------------------
 * The merge action owns the pipeline's verdict, and it forms it from whatever sits
 * under `executions/<execution id>/` in the results bucket. Every shard project's
 * role could write anywhere in that bucket (`grantWrite` on `<bucket>/*`), and a
 * shard runs scanners over the repository being scanned. So one shard could replace
 * another shard's `ash_aggregated_results.json`, or the merged output, and the merge
 * would report a verdict about results nobody produced. Each shard needs to write
 * `executions/*\/shard-<its index>/*` and nothing else.
 *
 * The check is semantic: it asks whether any write grant on a shard's role COVERS a
 * concrete key, using IAM's wildcard rules, rather than comparing strings. A shard
 * must be able to write its own results key (the control) and must not be able to
 * write another shard's, the merged output, or another execution's anything.
 *
 * WHY THE CONFIG PATH MATTERS
 * ---------------------------
 * The shard projects set `ASH_CONFIG` as a project environment variable and write the
 * file only when a base config was supplied. With none, ASH used to treat a missing
 * `ASH_CONFIG` file as "use defaults". The config hardening makes an explicit config
 * path that does not exist refuse the scan with exit 3, so a pipeline deployed
 * without `AshBaseConfigYaml` would fail every shard. Whatever reaches `ash` has to be
 * a config file that exists, or no `ASH_CONFIG` at all. The phases are run in
 * separate shells, as the stack's own comment warns an `export` does not reliably
 * cross phases.
 */

import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { ASH_PARAMETER_NAMES } from '../lib/ash-config';
import { ASH_S3_SYNC_PATH } from '../lib/ash-container-scripts';
import { AshDistributedPipelineStack } from '../lib/ash-distributed-pipeline-stack';
import { actionMatches, CfnResolver, roleOf, statementsForRole, synth } from './support/cfn';
import { AshRecord, fakeAshScript, python3, readLines } from './support/gate-harness';

const PIPELINE = synth((app) => new AshDistributedPipelineStack(app, 'AshDistributedPipeline'));

/** Object-level writes, and the bucket-level ones that could redirect or destroy results. */
const WRITE_ACTIONS = [
  's3:PutObject',
  's3:PutObjectAcl',
  's3:PutObjectTagging',
  's3:PutObjectVersionTagging',
  's3:PutObjectRetention',
  's3:PutObjectLegalHold',
  's3:DeleteObject',
  's3:DeleteObjectVersion',
  's3:DeleteObjectTagging',
  's3:AbortMultipartUpload',
  's3:RestoreObject',
  's3:ReplicateObject',
  's3:PutBucketPolicy',
  's3:PutLifecycleConfiguration',
  's3:PutBucketVersioning',
  's3:DeleteBucket',
];

/** IAM resource matching: `*` is any run of characters, `?` is one. */
function resourceCovers(pattern: string, arn: string): boolean {
  const regex = new RegExp(
    '^' +
      pattern
        .split('')
        .map((ch) => (ch === '*' ? '.*' : ch === '?' ? '.' : ch.replace(/[.+^${}()|[\]\\/]/g, '\\$&')))
        .join('') +
      '$',
  );
  return regex.test(arn);
}

interface Shard {
  readonly index: number;
  readonly project: string;
  readonly role: string;
}

function shards(): Shard[] {
  const out: Shard[] = [];
  for (const [id, resource] of Object.entries(PIPELINE.Resources)) {
    if (resource.Type !== 'AWS::CodeBuild::Project') continue;
    const match = /^ASH scan shard (\d+) of \d+\./.exec(String(resource.Properties?.Description ?? ''));
    if (match) {
      out.push({ index: Number(match[1]), project: id, role: roleOf(resource.Properties?.ServiceRole) });
    }
  }
  return out.sort((a, b) => a.index - b.index);
}

const SHARDS = shards();
const RESULTS_BUCKET = Object.keys(PIPELINE.Resources).find(
  (id) => PIPELINE.Resources[id].Type === 'AWS::S3::Bucket' && id.startsWith('Results'),
) as string;
const RESULTS_ARN = `arn:aws:s3:::ash-results-bucket`;
const RESOLVER = new CfnResolver(PIPELINE, { attributes: { [`${RESULTS_BUCKET}.Arn`]: RESULTS_ARN } });

/** Every resource pattern a shard's role may apply an S3 write action to. */
function writableResources(shard: Shard): string[] {
  return statementsForRole(PIPELINE, shard.role, RESOLVER)
    .filter((statement) => statement.effect === 'Allow')
    .filter((statement) =>
      statement.actions.some((granted) => WRITE_ACTIONS.some((action) => actionMatches(granted, action))),
    )
    .flatMap((statement) => statement.resources);
}

function canWrite(shard: Shard, key: string): boolean {
  const arn = `${RESULTS_ARN}/${key}`;
  return writableResources(shard).some((pattern) => resourceCovers(pattern, arn));
}

test('the shard projects and the results bucket were found, so the cases below are not vacuous', () => {
  expect(SHARDS.length).toBeGreaterThan(1);
  expect(SHARDS.map((s) => s.index)).toEqual(SHARDS.map((_s, i) => i));
  expect(RESULTS_BUCKET).toBeDefined();
});

describe.each(SHARDS.map((s) => [s.index, s] as const))('shard %i', (index, shard) => {
  const other = (index + 1) % SHARDS.length;

  test('control: it can write its own results for an execution', () => {
    expect(canWrite(shard, `executions/exec-1/shard-${index}/ash_aggregated_results.json`)).toBe(true);
  });

  test('it cannot write another shard results, the merged output, or outside an execution', () => {
    const forbidden = [
      `executions/exec-1/shard-${other}/ash_aggregated_results.json`,
      'executions/exec-1/merged/ash_aggregated_results.json',
      `executions/exec-1/shard-${index}0/ash_aggregated_results.json`,
      `elsewhere/shard-${index}/ash_aggregated_results.json`,
    ].filter((key) => canWrite(shard, key));
    expect(forbidden).toEqual([]);
  });
});

describe('shard config path', () => {
  const shardSpec = (() => {
    const shard = SHARDS[0];
    const project = PIPELINE.Resources[shard.project];
    const spec = JSON.parse(String(RESOLVER.resolve(project.Properties?.Source?.BuildSpec)));
    return (parameters: Record<string, string>) => {
      const resolver = new CfnResolver(PIPELINE, { parameters });
      const variables: Record<string, string> = {};
      for (const variable of (project.Properties?.Environment?.EnvironmentVariables ?? []) as any[]) {
        variables[variable.Name] = String(resolver.resolve(variable.Value));
      }
      return { spec, variables };
    };
  })();

  function phaseScript(commands: string[]): string {
    return commands.map((command) => `${command}\nash_rc=$?; [ "$ash_rc" -eq 0 ] || exit "$ash_rc"`).join('\n');
  }

  function runShard(parameters: Record<string, string>, ssmValue?: string): AshRecord[] {
    const { spec, variables } = shardSpec(parameters);
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ash-shard-'));
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
          `        return {"Parameter": {"Value": ${JSON.stringify(ssmValue ?? '')}}}`,
          'def client(service, *a, **k):',
          '    return _C()',
          '',
        ].join('\n'),
      );
      // The buildspec writes its helper and its config under /tmp; both are moved
      // into this test's directory so parallel runs cannot see each other's files.
      const relocate = (commands: string[]) =>
        commands.map((c) => c.split(ASH_S3_SYNC_PATH).join(path.join(dir, 'ash-s3-sync.py')));
      const src = path.join(dir, 'src');
      fs.mkdirSync(src);
      const env = {
        ...variables,
        ASH_CONFIG: path.join(dir, 'ash-config', '.ash.yaml'),
        ASH_RESULTS_PREFIX: 'executions/exec-1',
        CODEBUILD_SRC_DIR: src,
        PATH: `${bin}:${path.dirname(python3())}:${process.env.PATH ?? '/usr/bin:/bin'}`,
        PYTHONPATH: path.join(dir, 'py'),
        HOME: dir,
      };
      spawnSync('sh', ['-c', phaseScript(relocate(spec.phases.pre_build.commands))], { cwd: src, env });
      spawnSync('sh', ['-c', phaseScript(relocate(spec.phases.build.commands))], { cwd: src, env });
      return readLines<AshRecord>(record);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }

  test('control: with a base config, the shard scans with that document', () => {
    const doc = 'project_name: operator-base-config\n';
    const [ash] = runShard({ [ASH_PARAMETER_NAMES.ashBaseConfigYaml]: doc }, doc);

    expect(ash).toBeDefined();
    expect(ash.effective_config_exists).toBe(true);
    expect(ash.effective_config_content).toBe(doc);
  });

  test('with no base config, ash is not pointed at a config file that does not exist', () => {
    const [ash] = runShard({});

    expect(ash).toBeDefined();
    expect({ configPath: ash.effective_config, exists: ash.effective_config_exists }).toEqual(
      ash.effective_config === null
        ? { configPath: null, exists: false }
        : { configPath: ash.effective_config, exists: true },
    );
  });
});
