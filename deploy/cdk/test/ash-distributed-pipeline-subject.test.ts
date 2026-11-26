/**
 * The distributed pipeline's shards and merge spell ASH's commands the way its ASH does.
 *
 * The shard and merge projects run inside the ASH image the pipeline builds from
 * `AshVersion`. ASH 3.9 scans a directory with `ash scan fs PATH` and merges with
 * `ash results merge`; the older spellings, `ash scan --source-dir PATH` and
 * `ash merge`, still run there but print a deprecation line, and they go in ASH v4.0.
 * An `AshVersion` older than 3.9 (the stack's default, until the release commit moves
 * it) has only the older spellings. So each command asks the installed ASH first and
 * runs the spelling it has. This runs the committed build commands against a
 * stand-in `ash` answering as each kind of release, and reads what it was given.
 */

import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { AshDistributedPipelineStack } from '../lib/ash-distributed-pipeline-stack';
import { CfnResolver, synth } from './support/cfn';
import { AshRecord, AshRelease, fakeAshScript, python3, readLines } from './support/gate-harness';

const PIPELINE = synth((app) => new AshDistributedPipelineStack(app, 'AshDistributedPipeline'));
const RESOLVER = new CfnResolver(PIPELINE);

/** The build-phase commands of the one project whose description `matches`. */
function buildCommands(matches: RegExp): string[] {
  const projects = Object.values(PIPELINE.Resources).filter(
    (resource) =>
      resource.Type === 'AWS::CodeBuild::Project' && matches.test(String(resource.Properties?.Description ?? '')),
  );
  if (projects.length === 0) throw new Error(`no CodeBuild project matches ${matches}`);
  const spec = JSON.parse(String(RESOLVER.resolve(projects[0].Properties?.Source?.BuildSpec)));
  return spec.phases.build.commands as string[];
}

const SHARD_BUILD = buildCommands(/^ASH scan shard 0 of \d+\./);
const MERGE_BUILD = buildCommands(/^Merges /);

/** Run `commands` with a stand-in `ash` answering as `release`, and return what it recorded. */
function run(commands: string[], release: AshRelease): { records: AshRecord[]; src: string } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ash-pipeline-subject-'));
  try {
    const bin = path.join(dir, 'bin');
    fs.mkdirSync(bin);
    const src = path.join(dir, 'src');
    fs.mkdirSync(src);
    const record = path.join(dir, 'ash.jsonl');
    fs.writeFileSync(path.join(bin, 'ash'), fakeAshScript(python3(), record, 0, 'listed', release), {
      mode: 0o755,
    });
    const env = {
      PATH: `${bin}:${path.dirname(python3())}:${process.env.PATH ?? '/usr/bin:/bin'}`,
      HOME: dir,
      CODEBUILD_SRC_DIR: src,
      ASH_SHARD_INDEX: '0',
      ASH_SHARD_COUNT: '4',
    };
    for (const command of commands) {
      // The shard's own results-file check fails here, as the stand-in writes no
      // results; what is read is the record of what ash was given.
      spawnSync('sh', ['-c', command], { cwd: dir, env });
    }
    return { records: readLines<AshRecord>(record), src };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('the shard and merge build commands were found, so the cases below are not vacuous', () => {
  expect(SHARD_BUILD.join('\n')).toContain('--shard-index');
  expect(MERGE_BUILD.join('\n')).toContain('--results ./shard-results/shard-0');
});

describe('on an ASH with the fs subject and the results group', () => {
  test('a shard scans the checkout as the subject\'s PATH', () => {
    const { records, src } = run(SHARD_BUILD, 'with-subject');

    expect(records).toHaveLength(1);
    expect(records[0].argv.slice(0, 3)).toEqual(['scan', 'fs', src]);
    expect(records[0].argv).not.toContain('--source-dir');
    expect(records[0].argv).toEqual(expect.arrayContaining(['--shard-index', '0', '--shard-count', '4']));
  });

  test('the merge runs `ash results merge` with one --results per shard', () => {
    const { records } = run(MERGE_BUILD, 'with-subject');

    expect(records).toHaveLength(1);
    expect(records[0].argv.slice(0, 2)).toEqual(['results', 'merge']);
    expect(records[0].argv.filter((word) => word === '--results')).toHaveLength(4);
  });
});

describe('control: on an ASH older than 3.9', () => {
  test('a shard scans the checkout with --source-dir', () => {
    const { records, src } = run(SHARD_BUILD, 'without-subject');

    expect(records).toHaveLength(1);
    expect(records[0].argv.slice(0, 3)).toEqual(['scan', '--source-dir', src]);
  });

  test('the merge runs `ash merge` with one --results per shard', () => {
    const { records } = run(MERGE_BUILD, 'without-subject');

    expect(records).toHaveLength(1);
    expect(records[0].argv[0]).toBe('merge');
    expect(records[0].argv.filter((word) => word === '--results')).toHaveLength(4);
  });
});
