/**
 * The image build's tagging is tested by RUNNING it, not by snapshotting it.
 *
 * A real CodeBuild run deployed with `AshVersion=feat/distributed-execute-and-collect`
 * built the ASH image successfully and then failed on
 * `docker tag "ash-mcp:local" "<uri>:mcp-arm64-feat/distributed-execute-and-collect"`
 * with `Error parsing reference`, so the build reported FAILED and nothing
 * reached ECR. A snapshot of the buildspec would have been just as green before
 * that deployment as after it. These tests instead take the sanitizing shell out
 * of the synthesized template, execute it under `/bin/sh`, and check the tag it
 * produces against the Docker tag grammar.
 */

import { execFileSync } from 'node:child_process';

import { App, Stack } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';

import { AshAgentCoreStack } from '../lib/ash-agentcore-stack';
import { AshCodeCommitGateStack } from '../lib/ash-codecommit-gate-stack';
import { AshDistributedPipelineStack } from '../lib/ash-distributed-pipeline-stack';
import { AshFargateStack } from '../lib/ash-fargate-stack';
import { AshImagePipelineStack } from '../lib/ash-image-pipeline-stack';

/**
 * The tag grammar, transcribed from the canonical definition
 * (`tag := /[\w][\w.-]{0,127}/`).
 * https://pkg.go.dev/github.com/distribution/reference
 *
 * Anchored, and `\w` spelled out rather than written as `\w`: JavaScript's `\w`
 * happens to agree with Go's here, but relying on that would make the test read
 * as if the two regex dialects were interchangeable.
 */
const DOCKER_TAG = /^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$/;

type StackFactory = (app: App, id: string) => Stack;

const STACKS: Record<string, StackFactory> = {
  AshImagePipeline: (app, id) => new AshImagePipelineStack(app, id),
  AshAgentCore: (app, id) => new AshAgentCoreStack(app, id),
  AshFargate: (app, id) => new AshFargateStack(app, id),
  AshCodeCommitGate: (app, id) => new AshCodeCommitGateStack(app, id),
  AshDistributedPipeline: (app, id) => new AshDistributedPipelineStack(app, id),
};

/**
 * Collapse a CloudFormation `Fn::Join`/`Ref` tree back into text.
 *
 * The buildspec is one big `Fn::Join` because its `pre_build` phase interpolates
 * the region and account. Nothing in the `build` phase does, so flattening loses
 * nothing the tagging tests care about.
 */
function flatten(node: unknown): string {
  if (typeof node === 'string') return node;
  if (Array.isArray(node)) return node.map(flatten).join('');
  if (node && typeof node === 'object') {
    const obj = node as Record<string, any>;
    if (obj['Fn::Join']) {
      const [separator, parts] = obj['Fn::Join'];
      return (parts as unknown[]).map(flatten).join(separator as string);
    }
    if (obj.Ref) return `<${obj.Ref}>`;
    if (obj['Fn::GetAtt']) return `<${(obj['Fn::GetAtt'] as string[]).join('.')}>`;
  }
  return String(node);
}

interface BuildProject {
  readonly stack: string;
  readonly id: string;
  readonly commands: string[];
}

/** Every CodeBuild project in every stack, with its `build` phase commands. */
function buildProjects(): BuildProject[] {
  const found: BuildProject[] = [];
  for (const [stack, factory] of Object.entries(STACKS)) {
    const app = new App({ analyticsReporting: false });
    const template = Template.fromStack(factory(app, stack));
    for (const [id, resource] of Object.entries<any>(
      template.findResources('AWS::CodeBuild::Project'),
    )) {
      const spec = JSON.parse(flatten(resource.Properties.Source.BuildSpec));
      found.push({ stack, id, commands: spec.phases.build?.commands ?? [] });
    }
  }
  return found;
}

const PROJECTS = buildProjects();

/** Only the projects that tag and push an ASH image; the shard executor has others. */
const IMAGE_PROJECTS = PROJECTS.filter((p) =>
  p.commands.some((c) => c.startsWith('docker tag ')),
);

/** Every `docker tag`/`docker push` line, including the local `ash-cli:local` alias. */
function referenceCommands(project: BuildProject): string[] {
  return project.commands.filter((c) => /^docker (tag|push) /.test(c));
}

/**
 * The subset that names the ECR repository.
 *
 * The `cli` flavor also emits `docker tag "ash-base-ci:local" "ash-cli:local"`,
 * a purely local alias that carries no version and never reaches a registry.
 * Shape assertions about published tags have to exclude it or they fail on a
 * command that was never in scope.
 */
function registryCommands(project: BuildProject): string[] {
  return referenceCommands(project).filter((c) => c.includes('${ASH_ECR_REPOSITORY_URI}'));
}

/** A published tag with no version component, for example `mcp-arm64`. */
const MOVING_TAG = /"\$\{ASH_ECR_REPOSITORY_URI\}:(mcp|lambda|cli)-(arm64|amd64)"$/;

/** The one command that computes the folded suffix. */
function sanitizeCommand(project: BuildProject): string {
  const matches = project.commands.filter((c) => c.includes('ASH_VERSION_TAG_SUFFIX='));
  expect(matches).toHaveLength(1);
  return matches[0];
}

/**
 * The shell expressions the build uses as version-qualified tags.
 *
 * Read out of the real `docker tag` lines rather than reconstructed, so that
 * changing what those lines interpolate changes what these tests measure. An
 * earlier draft built its own `${tag}-${suffix}` string and therefore stayed
 * green when the sanitization was removed — it was testing the sanitizer in
 * isolation while the build tagged something else entirely.
 */
function versionedTagExpressions(project: BuildProject): string[] {
  const versioned = registryCommands(project).filter(
    (c) => c.startsWith('docker tag ') && !MOVING_TAG.test(c),
  );
  expect(versioned.length).toBeGreaterThanOrEqual(1);
  return versioned.map((command) => {
    const match = /\$\{ASH_ECR_REPOSITORY_URI\}:(.*)"$/.exec(command);
    expect(match).not.toBeNull();
    return match![1];
  });
}

describe('the image build tags something Docker can parse', () => {
  test('there is at least one project to check', () => {
    // A filter that silently matched nothing would make every test below vacuous.
    expect(IMAGE_PROJECTS.length).toBeGreaterThanOrEqual(6);
  });

  test.each(IMAGE_PROJECTS.map((p) => [`${p.stack}/${p.id}`, p] as const))(
    '%s never interpolates the raw git ref into a reference',
    (_name, project) => {
      // This is the defect, stated as a property. It holds for flavors and
      // architectures that do not exist yet, which a per-line assertion would not.
      for (const command of referenceCommands(project)) {
        expect(command).not.toContain('${ASH_VERSION}');
        expect(command).not.toContain('$ASH_VERSION"');
      }
    },
  );

  test.each(IMAGE_PROJECTS.map((p) => [`${p.stack}/${p.id}`, p] as const))(
    '%s derives its version-qualified tag from the folded suffix',
    (_name, project) => {
      const versioned = registryCommands(project).filter((c) =>
        c.includes('ASH_VERSION_TAG_SUFFIX'),
      );
      // One tag and one push per flavor.
      expect(versioned.length).toBeGreaterThanOrEqual(2);
      expect(versioned.length % 2).toBe(0);
    },
  );

  test.each(IMAGE_PROJECTS.map((p) => [`${p.stack}/${p.id}`, p] as const))(
    '%s leaves the moving tag alone',
    (_name, project) => {
      // The moving tag is what every workload pulls and what the scheduled rebuild
      // republishes. It carries no version component and must not acquire one.
      const moving = registryCommands(project).filter(
        (c) => !c.includes('ASH_VERSION_TAG_SUFFIX'),
      );
      expect(moving.length).toBeGreaterThanOrEqual(2);
      for (const command of moving) {
        expect(command).toMatch(MOVING_TAG);
      }
    },
  );

  test.each(IMAGE_PROJECTS.map((p) => [`${p.stack}/${p.id}`, p] as const))(
    '%s folds the ref with a character class matching the tag grammar',
    (_name, project) => {
      const command = sanitizeCommand(project);
      // The grammar's own character class, and a bound on the folded length. The
      // bound is read back from the command rather than hardcoded here, because it
      // is derived from the flavor set and differs between projects.
      expect(command).toContain("tr -c 'A-Za-z0-9._-' '-'");
      expect(command).toMatch(/cut -c1-\d+/);
      expect(command).toContain('sha256sum');
    },
  );
});

/**
 * Refs the sanitizer has to survive. Every entry is a distinct input, so the
 * tags they produce must all be distinct too.
 */
const REFS: Record<string, string> = {
  observed: 'feat/distributed-execute-and-collect',
  defaultTag: 'v3.7.0',
  release: 'release/1.2.3',
  dependabot: 'dependabot/npm_and_yarn/aws-cdk-lib-2.267.0',
  userBranch: 'users/someone/wip',
  commitSha: '0123456789abcdef0123456789abcdef01234567',
  leadingHyphen: '-foo',
  leadingDot: '.hidden',
  collisionSlash: 'feat/x',
  collisionHyphen: 'feat-x',
  withSpace: 'a branch with spaces',
  withNewline: 'line-one\nline-two',
  shellMetachars: '$(id)`id`;id',
  nonAscii: 'feature/café-résumé',
  veryLong: `feat/${'x'.repeat(400)}`,
  longSharedPrefixA: `feat/${'y'.repeat(200)}-alpha`,
  longSharedPrefixB: `feat/${'y'.repeat(200)}-beta`,
};

/**
 * Run a project's real sanitizing command and report the tags it would push.
 *
 * Both halves of the script come out of the synthesized template — the folding
 * command and the tag expressions the `docker tag` lines actually interpolate —
 * so this exercises what CodeBuild would run rather than a reimplementation.
 */
function composeTags(project: BuildProject, ref: string): string[] {
  const expressions = versionedTagExpressions(project);
  const script = [
    sanitizeCommand(project),
    ...expressions.map((expr) => `printf 'TAG=%s\\n' "${expr}"`),
  ].join('\n');
  const out = execFileSync('/bin/sh', ['-c', script], {
    env: { ...process.env, ASH_VERSION: ref },
    encoding: 'utf8',
  });
  const tags = out
    .split('\n')
    .filter((l) => l.startsWith('TAG='))
    .map((l) => l.slice('TAG='.length));
  expect(tags).toHaveLength(expressions.length);
  return tags;
}

describe('running the synthesized sanitizer', () => {
  // Three projects: a single arm64 flavor, a single amd64 flavor, and the
  // three-flavor build whose folded-length budget is the tightest. Running all
  // six against every ref would spawn a few hundred shells for no new coverage.
  const SAMPLES = ['AshAgentCore', 'AshCodeCommitGate', 'AshImagePipeline'].map(
    (stack) => IMAGE_PROJECTS.filter((p) => p.stack === stack),
  );

  test('the sample projects were found', () => {
    // Guards against a stack rename turning every test below into a no-op.
    for (const projects of SAMPLES) expect(projects.length).toBeGreaterThan(0);
  });

  const CASES = SAMPLES.flatMap((projects) =>
    projects.map((p) => [`${p.stack}/${p.id}`, p] as const),
  );

  describe.each(CASES)('%s', (_name, project) => {
    test.each(Object.entries(REFS))('%s produces a tag Docker accepts', (_label, ref) => {
      for (const tag of composeTags(project, ref)) {
        expect(tag).toMatch(DOCKER_TAG);
        // Redundant with the regex, but these are the two rules the deployment
        // actually broke, so name them.
        expect(tag).not.toContain('/');
        expect(tag.length).toBeLessThanOrEqual(128);
      }
    });

    test('distinct refs never land on the same tag', () => {
      // Folding is many-to-one, and the repository is MUTABLE, so a collision
      // would let one build overwrite another build's audit tag. `feat/x` versus
      // `feat-x` and the two 200-character shared-prefix refs are the cases the
      // digest exists for.
      const refs = Object.values(REFS);
      // Compare per flavor: two flavors of one ref legitimately differ only in
      // their prefix, which would make a flattened set look larger than it is.
      const perFlavor = refs.map((ref) => composeTags(project, ref));
      for (let flavor = 0; flavor < perFlavor[0].length; flavor += 1) {
        const tags = perFlavor.map((tags) => tags[flavor]);
        expect(new Set(tags).size).toBe(refs.length);
      }
    });

    test('the ref is quoted, so a ref cannot run a command', () => {
      // `$(id)` in a git ref reaching an unquoted expansion would execute.
      for (const tag of composeTags(project, '$(id)')) {
        expect(tag).not.toContain('uid=');
      }
    });

    test('a tag-safe ref survives recognizably', () => {
      // The digest is appended unconditionally, but the ref itself must still be
      // readable in the tag — that is what makes it usable as a rollback target.
      for (const tag of composeTags(project, 'v3.7.0')) {
        expect(tag).toContain('-v3.7.0-');
      }
    });

    test('the same ref always produces the same tag', () => {
      // A rebuild of a pinned ref has to republish one audit tag rather than
      // accumulate a new one on every schedule tick.
      expect(composeTags(project, 'v3.7.0')).toEqual(composeTags(project, 'v3.7.0'));
    });
  });
});
