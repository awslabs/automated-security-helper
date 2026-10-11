/**
 * `AshVersion` accepts what its description promises: a tag, a branch, or a commit.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The parameter description says "ASH git ref (tag, branch, or full commit SHA)".
 * `git clone --branch` takes a tag or a branch and refuses a commit SHA, and so does
 * the Dockerfile's own clone when `INSTALL_ASH_REVISION` names a ref
 * (Dockerfile:99-103). So the image build fetches the one ref with `git fetch
 * --depth 1`, which accepts all three, and builds the fetched tree with
 * `INSTALL_ASH_REVISION=LOCAL` so the Dockerfile does not clone again, as the
 * Terraform image pipeline does
 * (deploy/terraform/modules/ash-image-pipeline/buildspec.yml.tftpl:31-51).
 *
 * Pinning a commit is not a corner case here: no released ASH has the CLI and MCP
 * surface these templates invoke, so a main commit is the reproducible pin an
 * adopter needs until a release has it.
 *
 * The build's own commands are run, out of the synthesized template, against a local
 * repository standing in for the ASH remote. `aws` and `docker` are stand-ins that
 * record their arguments; nothing is built and nothing reaches a network.
 */

import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { AshAgentCoreStack } from '../lib/ash-agentcore-stack';
import { AshCodeCommitGateStack } from '../lib/ash-codecommit-gate-stack';
import { AshDistributedPipelineStack } from '../lib/ash-distributed-pipeline-stack';
import { AshFargateStack } from '../lib/ash-fargate-stack';
import { AshImagePipelineStack } from '../lib/ash-image-pipeline-stack';
import { CfnResolver, CfnTemplate, synth } from './support/cfn';

const TEMPLATES: Array<[string, CfnTemplate]> = [
  ['AshAgentCore', synth((app) => new AshAgentCoreStack(app, 'AshAgentCore'))],
  ['AshFargate', synth((app) => new AshFargateStack(app, 'AshFargate'))],
  ['AshCodeCommitGate', synth((app) => new AshCodeCommitGateStack(app, 'AshCodeCommitGate'))],
  ['AshDistributedPipeline', synth((app) => new AshDistributedPipelineStack(app, 'AshDistributedPipeline'))],
  ['AshImagePipeline', synth((app) => new AshImagePipelineStack(app, 'AshImagePipeline'))],
];

interface ImageBuildSpec {
  readonly stack: string;
  readonly project: string;
  readonly preBuild: string[];
  readonly build: string[];
  readonly variables: Record<string, string>;
}

/** Every project that builds the ASH image: the ones whose build runs `docker build --target`. */
function imageBuilds(): ImageBuildSpec[] {
  const out: ImageBuildSpec[] = [];
  for (const [stack, template] of TEMPLATES) {
    const resolver = new CfnResolver(template);
    for (const [id, resource] of Object.entries(template.Resources)) {
      if (resource.Type !== 'AWS::CodeBuild::Project') continue;
      const spec = JSON.parse(String(resolver.resolve(resource.Properties?.Source?.BuildSpec)));
      const build: string[] = spec.phases?.build?.commands ?? [];
      if (!build.some((command) => command.includes('docker build') && command.includes('--target'))) continue;
      const variables: Record<string, string> = {};
      for (const variable of (resource.Properties?.Environment?.EnvironmentVariables ?? []) as any[]) {
        variables[variable.Name] = String(resolver.resolve(variable.Value));
      }
      out.push({ stack, project: id, preBuild: spec.phases?.pre_build?.commands ?? [], build, variables });
    }
  }
  return out;
}

const BUILDS = imageBuilds();

function git(cwd: string, ...args: string[]): string {
  const result = spawnSync('git', args, {
    cwd,
    encoding: 'utf-8',
    env: {
      PATH: process.env.PATH ?? '/usr/bin:/bin',
      HOME: cwd,
      GIT_CONFIG_NOSYSTEM: '1',
      GIT_AUTHOR_NAME: 'ash-test',
      GIT_AUTHOR_EMAIL: 'ash-test@example.invalid',
      GIT_COMMITTER_NAME: 'ash-test',
      GIT_COMMITTER_EMAIL: 'ash-test@example.invalid',
    },
  });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(' ')} failed: ${result.stderr}`);
  }
  return result.stdout.trim();
}

interface Fixture {
  readonly root: string;
  readonly remote: string;
  readonly tagCommit: string;
  readonly branchCommit: string;
  /** A commit that is neither a branch tip nor tagged: reachable only by its SHA. */
  readonly bareCommit: string;
}

/** A small repository with a tag, a slashed branch, and an untagged older commit. */
function makeFixture(): Fixture {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ash-ref-'));
  const work = path.join(root, 'work');
  fs.mkdirSync(work);
  git(work, 'init', '-q', '-b', 'main');
  fs.writeFileSync(path.join(work, 'marker'), 'one\n');
  git(work, 'add', 'marker');
  git(work, 'commit', '-q', '-m', 'one');
  const bareCommit = git(work, 'rev-parse', 'HEAD');
  fs.writeFileSync(path.join(work, 'marker'), 'two\n');
  git(work, 'commit', '-q', '-am', 'two');
  git(work, 'tag', 'v9.9.9');
  const tagCommit = git(work, 'rev-parse', 'HEAD');
  git(work, 'checkout', '-q', '-b', 'feature/x');
  fs.writeFileSync(path.join(work, 'marker'), 'three\n');
  git(work, 'commit', '-q', '-am', 'three');
  const branchCommit = git(work, 'rev-parse', 'HEAD');
  git(work, 'checkout', '-q', 'main');
  fs.writeFileSync(path.join(work, 'marker'), 'four\n');
  git(work, 'commit', '-q', '-am', 'four');
  const remote = path.join(root, 'ash.git');
  git(root, 'clone', '-q', '--bare', work, remote);
  // A hosted remote such as GitHub serves a fetch by commit id; a bare local one
  // does not unless told to, so this makes the stand-in behave like the real remote.
  git(remote, 'config', 'uploadpack.allowAnySHA1InWant', 'true');
  return { root, remote, tagCommit, branchCommit, bareCommit };
}

const FAKE_TOOL = (log: string) => `#!/bin/sh
printf '%s\\n' "$(basename "$0") $*" >> "${log}"
if [ "$(basename "$0")" = aws ]; then echo stand-in-registry-login; fi
exit 0
`;

interface BuildRun {
  readonly preBuildStatus: number | null;
  readonly buildStatus: number | null;
  readonly head: string | null;
  readonly dockerCalls: string[];
  readonly stderr: string;
}

/** Run one phase the way CodeBuild does: one shell, stopping at the first failing command. */
function phaseScript(commands: string[]): string {
  return commands.map((command) => `${command}\nash_rc=$?; [ "$ash_rc" -eq 0 ] || exit "$ash_rc"`).join('\n');
}

function runImageBuild(spec: ImageBuildSpec, fixture: Fixture, ref: string): BuildRun {
  const dir = fs.mkdtempSync(path.join(fixture.root, 'build-'));
  const bin = path.join(dir, 'bin');
  fs.mkdirSync(bin);
  const log = path.join(dir, 'tools.log');
  for (const tool of ['aws', 'docker']) {
    fs.writeFileSync(path.join(bin, tool), FAKE_TOOL(log), { mode: 0o755 });
  }
  const work = path.join(dir, 'src');
  fs.mkdirSync(work);
  const env = {
    ...spec.variables,
    PATH: `${bin}:${process.env.PATH ?? '/usr/bin:/bin'}`,
    HOME: dir,
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_TERMINAL_PROMPT: '0',
    ASH_VERSION: ref,
    ASH_REPOSITORY_URL: `file://${fixture.remote}`,
    CODEBUILD_SRC_DIR: work,
  };
  const pre = spawnSync('sh', ['-c', phaseScript(spec.preBuild)], { cwd: work, env, encoding: 'utf-8' });
  const build =
    pre.status === 0
      ? spawnSync('sh', ['-c', phaseScript(spec.build)], { cwd: work, env, encoding: 'utf-8' })
      : null;
  const headProbe = spawnSync('git', ['-C', path.join(work, 'ash-src'), 'rev-parse', 'HEAD'], {
    encoding: 'utf-8',
    env: { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: dir, GIT_CONFIG_NOSYSTEM: '1' },
  });
  const dockerCalls = fs.existsSync(log)
    ? fs.readFileSync(log, 'utf-8').split('\n').filter((line) => line.startsWith('docker '))
    : [];
  return {
    preBuildStatus: pre.status,
    buildStatus: build ? build.status : null,
    head: headProbe.status === 0 ? headProbe.stdout.trim() : null,
    dockerCalls,
    stderr: `${pre.stderr}${build?.stderr ?? ''}`.slice(-2000),
  };
}

let fixture: Fixture;
beforeAll(() => {
  fixture = makeFixture();
});
afterAll(() => {
  if (fixture) fs.rmSync(fixture.root, { recursive: true, force: true });
});

test('every image build project was found, so the cases below are not vacuous', () => {
  // AgentCore, Fargate, the gate and the pipeline each build once; AshImagePipeline
  // builds both architectures.
  expect(BUILDS.map((b) => b.stack).sort()).toEqual(
    ['AshAgentCore', 'AshCodeCommitGate', 'AshDistributedPipeline', 'AshFargate', 'AshImagePipeline', 'AshImagePipeline'].sort(),
  );
});

describe.each(BUILDS.map((b) => [`${b.stack}/${b.project}`, b] as const))('%s', (_label, spec) => {
  test('control: a tag builds that tag', () => {
    const run = runImageBuild(spec, fixture, 'v9.9.9');
    expect({ pre: run.preBuildStatus, head: run.head }).toEqual({ pre: 0, head: fixture.tagCommit });
  });

  test('control: a branch with a slash builds that branch', () => {
    const run = runImageBuild(spec, fixture, 'feature/x');
    expect({ pre: run.preBuildStatus, head: run.head }).toEqual({ pre: 0, head: fixture.branchCommit });
  });

  test('a full commit SHA builds exactly that commit', () => {
    const run = runImageBuild(spec, fixture, fixture.bareCommit);
    expect({ pre: run.preBuildStatus, head: run.head, stderr: run.preBuildStatus === 0 ? '' : run.stderr }).toEqual({
      pre: 0,
      head: fixture.bareCommit,
      stderr: '',
    });
  });

  test('the ASH stage is built from the fetched tree, not re-cloned by --branch inside docker', () => {
    const run = runImageBuild(spec, fixture, 'v9.9.9');
    const stageBuilds = run.dockerCalls.filter((call) => call.startsWith('docker build') && call.includes('--target'));

    expect(stageBuilds.length).toBeGreaterThan(0);
    for (const call of stageBuilds) {
      expect(call).toContain('INSTALL_ASH_REVISION=LOCAL');
    }
  });
});
