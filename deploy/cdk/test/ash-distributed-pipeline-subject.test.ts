/**
 * The distributed pipeline's shards and merge spell ASH's commands the way its ASH does.
 *
 * The shard and merge projects run inside the ASH image the pipeline builds from
 * `AshVersion`. ASH 3.9 scans a directory with `ash scan fs PATH` and merges with
 * `ash results merge`; the older spellings, `ash scan --source-dir PATH` and
 * `ash merge`, still run there but print a deprecation line, and they go in ASH v4.0.
 * An `AshVersion` older than 3.9 (the stack's default, until the release commit moves
 * it) has only the older spellings. So each command asks the installed ASH first and
 * runs the spelling it has. Only an answer picks the older one: a probe that fails any
 * other way (a crash, an out-of-memory kill) fails the build with what it printed, and
 * every build prints the spelling it chose and why to stderr. This runs the committed
 * build commands against a stand-in `ash` answering as each kind of release, and reads
 * what it was given.
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

/** What `run` read: the stand-in's record, and what each command's shell did. */
interface Ran {
  /** The calls the stand-in recorded: every call but the help probes. */
  readonly records: AshRecord[];
  /** The checkout directory the commands were given. */
  readonly src: string;
  /** The exit status of each command's shell, in order. */
  readonly statuses: (number | null)[];
  /** What the shells wrote to stderr, all commands together. */
  readonly stderr: string;
}

/** Run `commands` with a stand-in `ash` answering as `release`, and return what it recorded. */
function run(commands: string[], release: AshRelease): Ran {
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
    const statuses: (number | null)[] = [];
    let stderr = '';
    for (const command of commands) {
      // The shard's own results-file check fails here, as the stand-in writes no
      // results; what is read is the record of what ash was given.
      const finished = spawnSync('sh', ['-c', command], { cwd: dir, env, encoding: 'utf-8' });
      statuses.push(finished.status);
      stderr += finished.stderr ?? '';
    }
    return { records: readLines<AshRecord>(record), src, statuses, stderr };
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

  test('a shard whose ASH refuses the word fs scans it with --source-dir too', () => {
    // A usage error that names the word is an answer, as the help of the subject-less
    // scan is: the ASH has no `fs` subject.
    const { records, src } = run(SHARD_BUILD, 'without-subject-refusing');

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

describe('a probe that does not answer is not read as an older ASH', () => {
  // The older spelling is for an ASH that says it lacks the command. In this release
  // the new spellings' probes crash, and the old spelling's own help answers as an
  // older ASH's would, so a build that took the crash for "no such command" would go on
  // to scan and merge with commands an ASH 3.9 prints deprecation lines for.
  test('a shard runs neither spelling and fails with what the probe printed', () => {
    const { records, statuses, stderr } = run(SHARD_BUILD, 'new-spellings-crash');

    expect(records).toEqual([]);
    expect(statuses).toEqual([1]);
    expect(stderr).toContain("could not tell whether this ASH has 'ash scan fs'");
    expect(stderr).toContain("'ash scan fs --help' exited 1");
    expect(stderr).toContain('MemoryError');
  });

  test('the merge runs neither spelling and fails with what the probe printed', () => {
    const { records, statuses, stderr } = run(MERGE_BUILD, 'new-spellings-crash');

    expect(records).toEqual([]);
    expect(statuses).toEqual([1]);
    expect(stderr).toContain("could not tell whether this ASH has 'ash results merge'");
    expect(stderr).toContain("'ash results merge --help' exited 1");
    expect(stderr).toContain('MemoryError');
  });
});

describe('every build prints the spelling it chose and why', () => {
  test.each<[AshRelease, string]>([
    ['with-subject', "scanning with 'ash scan fs': its help names 'scan fs'"],
    [
      'without-subject',
      "scanning with the older spelling: the help of 'ash scan fs --help' does not name 'scan fs'",
    ],
    ['without-subject-refusing', "scanning with the older spelling: this ASH refused the word 'fs'"],
  ])('a shard on an ASH %s says: %s', (release, said) => {
    expect(run(SHARD_BUILD, release).stderr).toContain(`ash: ${said}`);
  });

  test.each<[AshRelease, string]>([
    ['with-subject', "merging with 'ash results merge': its help names 'results merge'"],
    ['without-subject', "merging with the older spelling: this ASH refused the word 'results'"],
  ])('the merge on an ASH %s says: %s', (release, said) => {
    expect(run(MERGE_BUILD, release).stderr).toContain(`ash: ${said}`);
  });
});
