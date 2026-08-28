// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as fs from 'fs';
import * as path from 'path';
import { generatedBuildspecs, mergeLoopCommands } from '../src/private/buildspec';
import { mergeCommands, shellArg } from '../src/private/commands';
import { ASHInstallMode } from '../src';
import { scalar, toYaml } from '../src/private/yaml';

const PACKAGE_ROOT = path.resolve(__dirname, '..');

describe('generated buildspecs are deterministic', () => {
  test('rendering twice produces byte-identical output', () => {
    const first = generatedBuildspecs();
    const second = generatedBuildspecs();

    expect(second.map((s) => s.filename)).toEqual(first.map((s) => s.filename));

    for (let i = 0; i < first.length; i++) {
      // Compare as bytes, which is what the CI drift gate compares.
      expect(Buffer.from(second[i].contents, 'utf8')).toEqual(
        Buffer.from(first[i].contents, 'utf8'),
      );
    }
  });

  test('rendering many times never varies', () => {
    const baseline = generatedBuildspecs().map((s) => s.contents);

    for (let attempt = 0; attempt < 25; attempt++) {
      expect(generatedBuildspecs().map((s) => s.contents)).toEqual(baseline);
    }
  });

  test('output contains nothing that changes between runs', () => {
    for (const spec of generatedBuildspecs()) {
      // A timestamp, hostname or absolute path would make the drift gate fail on
      // a machine difference rather than a real change.
      expect(spec.contents).not.toMatch(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/);
      expect(spec.contents).not.toContain(PACKAGE_ROOT);
      expect(spec.contents).not.toMatch(/\/home\/|\/Users\/|C:\\/);
    }
  });

  test('every file ends with exactly one newline and uses LF only', () => {
    for (const spec of generatedBuildspecs()) {
      expect(spec.contents.endsWith('\n')).toBe(true);
      expect(spec.contents.endsWith('\n\n')).toBe(false);
      expect(spec.contents).not.toContain('\r');
    }
  });
});

describe('committed buildspecs match the source of truth', () => {
  test.each(generatedBuildspecs().map((s) => s.filename))('%s is committed', (filename) => {
    expect(fs.existsSync(path.join(PACKAGE_ROOT, filename))).toBe(true);
  });

  test.each(generatedBuildspecs())('$filename is byte-identical on disk', (spec) => {
    const onDisk = fs.readFileSync(path.join(PACKAGE_ROOT, spec.filename));

    // This is the assertion the CI drift gate makes. It failing here means the
    // generator changed and `npm run buildspec` was not re-run.
    expect(onDisk.equals(Buffer.from(spec.contents, 'utf8'))).toBe(true);
  });
});

describe('verdict ownership in the generated buildspecs', () => {
  function contentsOf(filename: string): string {
    return generatedBuildspecs().find((s) => s.filename === filename)!.contents;
  }

  test('the unsharded buildspec fails on findings', () => {
    expect(contentsOf('buildspec.yml')).toContain('--fail-on-findings');
    expect(contentsOf('buildspec.yml')).not.toContain('--no-fail-on-findings');
  });

  test('the shard buildspec never fails on findings', () => {
    expect(contentsOf('buildspec-shard.yml')).toContain('--no-fail-on-findings');
  });

  test('the shard buildspec explains why gating on it is wrong', () => {
    // The comment is load-bearing: it is the only warning a non-CDK user, who
    // never sees the construct, gets before wiring the shard exit code to a gate.
    expect(contentsOf('buildspec-shard.yml')).toContain('never on a shard');
  });

  test('the merge buildspec refuses to report a verdict for zero shards', () => {
    expect(contentsOf('buildspec-merge.yml')).toContain('refusing to report a verdict');
  });

  test('each generated file names its regeneration command', () => {
    // The exact script name matters beyond documentation: the CI drift gate looks
    // it up in package.json, so a rename that misses one of these three places
    // leaves the gate regenerating nothing and comparing the file to itself.
    const scripts = require('../package.json').scripts as Record<string, string>;
    expect(scripts['generate:buildspec']).toBeDefined();

    for (const spec of generatedBuildspecs()) {
      expect(spec.contents).toContain('npm run generate:buildspec');
      expect(spec.contents).toContain('GENERATED FILE - DO NOT EDIT.');
    }
  });

  test('the generator scripts compile before they generate', () => {
    // Both run straight after a bare `npm ci`. Without the build step the
    // generator is missing from lib/ and exits MODULE_NOT_FOUND having written
    // nothing, which reads to a drift gate as "the generator produced no file".
    const scripts = require('../package.json').scripts as Record<string, string>;

    for (const name of ['generate:buildspec', 'check:buildspec']) {
      expect(scripts[name]).toContain('npm run build');
      expect(scripts[name]).toContain('lib/buildspec-cli.js');
    }
  });

  test('the unsharded buildspec is written to the exact path the gate checks', () => {
    // deploy/cdk-constructs/buildspec.yml is the only path the drift gate reads.
    expect(generatedBuildspecs().map((s) => s.filename)).toContain('buildspec.yml');
  });
});

describe('the env-driven merge loop matches the literal merge command', () => {
  test('expands to the same argument vector for three shards', () => {
    // The loop in buildspec-merge.yml and mergeCommands() are two renderings of
    // one contract. This pins them together: if either changes shape, this fails.
    const literal = mergeCommands(
      ['out/shard-0', 'out/shard-1', 'out/shard-2'],
      '.ash/ash_output',
      ASHInstallMode.PIP,
      undefined,
    )[0];

    expect(literal).toBe(
      'ash merge --results "out/shard-0" --results "out/shard-1" ' +
        '--results "out/shard-2" --output-dir ".ash/ash_output"',
    );

    const loop = mergeLoopCommands().join('\n');
    expect(loop).toContain('--results "$shard_dir"');
    expect(loop).toContain('ash merge "$@" --output-dir "$ASH_OUTPUT_DIR"');
  });

  test('mergeCommands refuses an empty results list', () => {
    expect(() => mergeCommands([], 'out', ASHInstallMode.PIP, undefined)).toThrow(
      /at least one results path/,
    );
  });
});

describe('shellArg', () => {
  test('quotes a plain path', () => {
    expect(shellArg('some/dir')).toBe('"some/dir"');
  });

  test('passes an environment variable reference through', () => {
    expect(shellArg('$ASH_OUTPUT_DIR')).toBe('"$ASH_OUTPUT_DIR"');
  });

  test.each([
    ['a double quote', 'out"dir'],
    ['a backtick', 'out`whoami`'],
    ['a command substitution', 'out$(whoami)'],
    ['a backslash', 'out\\dir'],
    ['a newline', 'out\ndir'],
  ])('rejects %s', (_label, value) => {
    expect(() => shellArg(value)).toThrow(/Refusing to build a shell command/);
  });

  test('a rejected value cannot reach the rendered command', () => {
    expect(() =>
      mergeCommands(['out; rm -rf $HOME'], 'out', ASHInstallMode.PIP, undefined),
    ).toThrow(/Refusing to build a shell command/);
  });
});

describe('yaml emitter', () => {
  test('quotes strings that would parse as numbers', () => {
    // Unquoted, `3.10` parses as the float 3.1 and a Python runtime silently
    // becomes 3.1. Every number-shaped string has to come back as a string.
    expect(scalar('3.10')).toBe("'3.10'");
    expect(scalar('0')).toBe("'0'");
    expect(scalar('1e5')).toBe("'1e5'");
  });

  test('quotes strings YAML would read as booleans or null', () => {
    expect(scalar('no')).toBe("'no'");
    expect(scalar('yes')).toBe("'yes'");
    expect(scalar('true')).toBe("'true'");
    expect(scalar('null')).toBe("'null'");
    expect(scalar('')).toBe("''");
  });

  test('leaves genuine numbers and booleans unquoted', () => {
    expect(scalar(0.2)).toBe('0.2');
    expect(scalar(3)).toBe('3');
    expect(scalar(true)).toBe('true');
  });

  test('emits plain scalars for letter-led identifiers', () => {
    expect(scalar('python')).toBe('python');
    expect(scalar('ash_output')).toBe('ash_output');
  });

  test('escapes a single quote by doubling it', () => {
    expect(scalar("it's")).toBe("'it''s'");
  });

  test('renders nested maps and sequences in insertion order', () => {
    const rendered = toYaml({
      version: 0.2,
      phases: {
        build: {
          commands: ['first', 'second'],
        },
      },
    });

    expect(rendered).toBe(
      ['version: 0.2', 'phases:', '  build:', '    commands:', '      - first', '      - second'].join(
        '\n',
      ),
    );
  });

  test('renders empty collections in flow style', () => {
    expect(toYaml({ commands: [], env: {} })).toBe('commands: []\nenv: {}');
  });
});
