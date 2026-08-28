// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import { Match } from 'aws-cdk-lib/assertions';
import { ASHInstallMode, ASHSeverityThreshold } from '../src';
import { buildStep, synthesizeWithStep, SynthesizedAction } from './helpers';

/** Actions this step created, i.e. everything except the pipeline's own steps. */
function ashActions(actions: SynthesizedAction[]): SynthesizedAction[] {
  return actions.filter((a) => a.name.startsWith('SecurityScan'));
}

describe('unsharded scan', () => {
  test('yields exactly one action', () => {
    const { actions } = synthesizeWithStep({ shardCount: 1 });
    const mine = ashActions(actions);

    expect(mine).toHaveLength(1);
    expect(mine[0].name).toBe('SecurityScan');
  });

  test('emits no shard flags', () => {
    const { actions } = synthesizeWithStep({ shardCount: 1 });
    const commands = ashActions(actions)[0].commands.join('\n');

    expect(commands).not.toContain('--shard-index');
    expect(commands).not.toContain('--shard-count');
  });

  test('owns the verdict, so it fails on findings', () => {
    const { actions } = synthesizeWithStep({ shardCount: 1 });
    const commands = ashActions(actions)[0].commands.join('\n');

    expect(commands).toContain('--fail-on-findings');
    expect(commands).not.toContain('--no-fail-on-findings');
  });

  test('is the default when shardCount is omitted', () => {
    const { actions } = synthesizeWithStep({});

    expect(ashActions(actions)).toHaveLength(1);
  });

  test('creates one CodeBuild project for the scan', () => {
    const { template } = synthesizeWithStep({ shardCount: 1 });

    template.hasResourceProperties('AWS::CodeBuild::Project', {
      Source: Match.objectLike({
        BuildSpec: Match.stringLikeRegexp('ash scan'),
      }),
    });
  });
});

describe('sharded scan', () => {
  test('yields three shard actions plus one merge action', () => {
    const { actions } = synthesizeWithStep({ shardCount: 3 });
    const mine = ashActions(actions);

    expect(mine.map((a) => a.name)).toEqual([
      'SecurityScanShard0',
      'SecurityScanShard1',
      'SecurityScanShard2',
      'SecurityScanMerge',
    ]);
  });

  test('shard actions carry zero-based indices 0, 1, 2 and the same count', () => {
    const { actions } = synthesizeWithStep({ shardCount: 3 });
    const shards = ashActions(actions).filter((a) => a.name.includes('Shard'));

    expect(shards).toHaveLength(3);
    shards.forEach((shard, index) => {
      const commands = shard.commands.join('\n');
      expect(commands).toContain(`--shard-index "${index}"`);
      expect(commands).toContain('--shard-count "3"');
    });
  });

  test('every shard runs in parallel at the same run order', () => {
    const { actions } = synthesizeWithStep({ shardCount: 3 });
    const shards = ashActions(actions).filter((a) => a.name.includes('Shard'));
    const runOrders = new Set(shards.map((a) => a.runOrder));

    expect(runOrders.size).toBe(1);
  });

  test('the merge action runs after every shard', () => {
    const { actions } = synthesizeWithStep({ shardCount: 3 });
    const mine = ashActions(actions);
    const merge = mine.find((a) => a.name.endsWith('Merge'))!;
    const shards = mine.filter((a) => a.name.includes('Shard'));

    for (const shard of shards) {
      expect(merge.runOrder).toBeGreaterThan(shard.runOrder);
    }
  });

  test("the merge action's inputs are exactly the shard outputs", () => {
    const { actions } = synthesizeWithStep({ shardCount: 3 });
    const mine = ashActions(actions);
    const merge = mine.find((a) => a.name.endsWith('Merge'))!;
    const shardOutputs = mine
      .filter((a) => a.name.includes('Shard'))
      .flatMap((a) => a.outputs);

    expect(shardOutputs).toHaveLength(3);
    expect(new Set(merge.inputs)).toEqual(new Set(shardOutputs));
  });

  test('the merge command reads one --results per shard output', () => {
    const { actions } = synthesizeWithStep({ shardCount: 3 });
    const mine = ashActions(actions);
    const merge = mine.find((a) => a.name.endsWith('Merge'))!;
    const command = merge.commands.join('\n');
    const shardOutputs = mine
      .filter((a) => a.name.includes('Shard'))
      .flatMap((a) => a.outputs);

    expect(command).toContain('ash merge');
    expect(command.match(/--results/g)).toHaveLength(3);

    // Each --results points at the CodeBuild directory for one shard artifact,
    // which is how the merge sees every shard's results and not just its own.
    for (const artifactName of shardOutputs) {
      expect(command).toContain(`--results "$CODEBUILD_SRC_DIR_${artifactName}"`);
    }
  });

  test('shards never gate, because a clean shard says nothing about the others', () => {
    const { actions } = synthesizeWithStep({ shardCount: 4 });
    const shards = ashActions(actions).filter((a) => a.name.includes('Shard'));

    expect(shards).toHaveLength(4);
    for (const shard of shards) {
      const commands = shard.commands.join('\n');
      expect(commands).toContain('--no-fail-on-findings');
    }
  });

  test('each shard writes to its own output directory', () => {
    const { actions } = synthesizeWithStep({ shardCount: 3 });
    const shards = ashActions(actions).filter((a) => a.name.includes('Shard'));

    const outputDirs = shards.map((shard) => {
      const match = shard.commands.join('\n').match(/--output-dir "([^"]+)"/);
      return match![1];
    });

    // ASH clears the output directory before scanning, so two shards sharing one
    // directory would delete each other's results.
    expect(new Set(outputDirs).size).toBe(3);
    expect(outputDirs).toEqual([
      '.ash/ash_output/shard-0',
      '.ash/ash_output/shard-1',
      '.ash/ash_output/shard-2',
    ]);
  });

  test('creates one CodeBuild project per shard plus one for the merge', () => {
    const { template } = synthesizeWithStep({ shardCount: 3 });
    const projects = template.findResources('AWS::CodeBuild::Project');
    // CDK prefixes logical ids with the construct path, so the step id appears
    // inside the id rather than at the start of it.
    const names = Object.keys(projects).filter((id) => id.includes('SecurityScan'));

    expect(names).toHaveLength(4);
    expect(names.filter((id) => id.includes('Shard'))).toHaveLength(3);
    expect(names.filter((id) => id.includes('Merge'))).toHaveLength(1);
  });
});

describe('shardCount validation', () => {
  test.each([0, -1, -10])('rejects %p', (shardCount) => {
    expect(() => buildStep({ shardCount })).toThrow(/at least 1/);
  });

  test.each([1.5, 2.0001])('rejects the non-integer %p', (shardCount) => {
    expect(() => buildStep({ shardCount })).toThrow(/whole number/);
  });

  test('rejects a count above the supported maximum', () => {
    expect(() => buildStep({ shardCount: 51 })).toThrow(/at most 50/);
  });

  test('accepts the boundary values 1 and 50', () => {
    expect(() => buildStep({ shardCount: 1 })).not.toThrow();
    expect(() => buildStep({ shardCount: 50 })).not.toThrow();
  });
});

describe('extraScanArguments', () => {
  test('passes unreserved arguments through', () => {
    const { actions } = synthesizeWithStep({
      extraScanArguments: ['--offline', '--verbose'],
    });
    const commands = ashActions(actions)[0].commands.join('\n');

    expect(commands).toContain('--offline --verbose');
  });

  test.each([
    '--shard-index',
    '--shard-count',
    '--fail-on-findings',
    '--no-fail-on-findings',
  ])('refuses %s, which would move the verdict', (argument) => {
    expect(() => buildStep({ extraScanArguments: [argument] })).toThrow(
      /cannot be passed through extraScanArguments/,
    );
  });

  test('refuses a reserved argument written with =', () => {
    expect(() => buildStep({ extraScanArguments: ['--shard-count=9'] })).toThrow(
      /cannot be passed through extraScanArguments/,
    );
  });
});

describe('severityThreshold', () => {
  test('defaults to low', () => {
    const { actions } = synthesizeWithStep({});

    expect(ashActions(actions)[0].commands.join('\n')).toContain('--min-severity low');
  });

  test.each([
    [ASHSeverityThreshold.CRITICAL, 'critical'],
    [ASHSeverityThreshold.HIGH, 'high'],
    [ASHSeverityThreshold.MEDIUM, 'medium'],
    [ASHSeverityThreshold.LOW, 'low'],
    [ASHSeverityThreshold.NONE, 'none'],
  ])('renders %s as --min-severity %s', (threshold, expected) => {
    const { actions } = synthesizeWithStep({ severityThreshold: threshold });

    expect(ashActions(actions)[0].commands.join('\n')).toContain(
      `--min-severity ${expected}`,
    );
  });
});

describe('install modes', () => {
  test('PIP installs the published distribution', () => {
    const { template } = synthesizeWithStep({ installMode: ASHInstallMode.PIP });

    template.hasResourceProperties('AWS::CodeBuild::Project', {
      Source: Match.objectLike({
        BuildSpec: Match.stringLikeRegexp('pip install .*automated-security-helper'),
      }),
    });
  });

  test('PIP pins the version when one is given', () => {
    const { template } = synthesizeWithStep({
      installMode: ASHInstallMode.PIP,
      version: '3.7.0',
    });

    template.hasResourceProperties('AWS::CodeBuild::Project', {
      Source: Match.objectLike({
        BuildSpec: Match.stringLikeRegexp('automated-security-helper==3.7.0'),
      }),
    });
  });

  test('PREINSTALLED emits no install commands', () => {
    const { template } = synthesizeWithStep({
      installMode: ASHInstallMode.PREINSTALLED,
    });
    const projects = template.findResources('AWS::CodeBuild::Project');

    const scan = Object.entries(projects).find(([id]) => id.includes('SecurityScan'));
    expect(scan).toBeDefined();
    const spec = JSON.parse((scan![1] as any).Properties.Source.BuildSpec);

    expect(spec.phases.install.commands).toEqual([]);
    expect(spec.phases.build.commands.join('\n')).toContain('ash scan');
  });

  test('UVX runs ash through uvx rather than installing it', () => {
    const { actions } = synthesizeWithStep({ installMode: ASHInstallMode.UVX });
    const commands = ashActions(actions)[0].commands.join('\n');

    expect(commands).toContain('uvx --from "automated-security-helper" ash scan');
  });

  test('GIT installs from the given ref', () => {
    const { template } = synthesizeWithStep({
      installMode: ASHInstallMode.GIT,
      version: 'feature/some-branch',
    });

    template.hasResourceProperties('AWS::CodeBuild::Project', {
      Source: Match.objectLike({
        BuildSpec: Match.stringLikeRegexp('git\\+https://github.com/awslabs/automated-security-helper@feature/some-branch'),
      }),
    });
  });

  test('GIT rejects a non-https repository at synth', () => {
    expect(() =>
      synthesizeWithStep({
        installMode: ASHInstallMode.GIT,
        sourceRepository: 'file:///etc/passwd',
      }),
    ).toThrow(/must be an https:\/\/ URL/);
  });

  test('GIT rejects a ref containing shell metacharacters at synth', () => {
    expect(() =>
      synthesizeWithStep({
        installMode: ASHInstallMode.GIT,
        version: 'main; rm -rf /',
      }),
    ).toThrow(/plain git ref/);
  });
});

describe('build environment', () => {
  test('defaults to an AWS-managed image, never a prebuilt ASH image', () => {
    const { template } = synthesizeWithStep({ shardCount: 2 });
    const projects = template.findResources('AWS::CodeBuild::Project');

    const images = Object.entries(projects)
      .filter(([id]) => id.includes('SecurityScan'))
      .map(([, resource]) => (resource as any).Properties.Environment.Image as string);

    // Assert the count first: a loop over an empty list would otherwise let this
    // test pass without checking a single image.
    expect(images).toHaveLength(3);
    for (const image of images) {
      // ASH publishes no image to any public registry, so the default has to be
      // a generic AWS-managed image that ASH is then installed into.
      expect(image).toMatch(/^aws\/codebuild\//);
      expect(image).not.toMatch(/ash/i);
    }
  });

  test('passes environment variables through to the project', () => {
    const { template } = synthesizeWithStep({
      environmentVariables: { ASH_OFFLINE: 'true' },
    });

    template.hasResourceProperties('AWS::CodeBuild::Project', {
      Environment: Match.objectLike({
        EnvironmentVariables: Match.arrayWith([
          Match.objectLike({ Name: 'ASH_OFFLINE', Value: 'true' }),
        ]),
      }),
    });
  });

  test('honours a custom output directory', () => {
    const { actions } = synthesizeWithStep({ outputDirectory: 'build/security' });
    const commands = ashActions(actions)[0].commands.join('\n');

    expect(commands).toContain('--output-dir "build/security"');
  });
});

describe('step wiring', () => {
  test('exposes the resolved configuration as readonly properties', () => {
    const step = buildStep({
      shardCount: 5,
      severityThreshold: ASHSeverityThreshold.MEDIUM,
      installMode: ASHInstallMode.UVX,
      outputDirectory: 'out',
    });

    expect(step.shardCount).toBe(5);
    expect(step.severityThreshold).toBe(ASHSeverityThreshold.MEDIUM);
    expect(step.installMode).toBe(ASHInstallMode.UVX);
    expect(step.outputDirectory).toBe('out');
  });

  test('declares a dependency on the input file set', () => {
    const step = buildStep({});

    expect(step.dependencyFileSets).toHaveLength(1);
  });

  test('rejects an input that produces no file set', () => {
    expect(
      () =>
        new (require('../src').ASHScanStep)('Broken', {
          input: { primaryOutput: undefined },
        }),
    ).toThrow(/does not produce a file set/);
  });
});
