// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Every file outside editors/vscode that a jest suite here reads must be in the
 * push and pull_request `paths:` filters of the workflow that runs the suite, or
 * a change to that file alone runs nothing. See test/repo-inputs.ts.
 */

import * as fs from 'fs';
import * as path from 'path';
import {
  GUARDED_WORKFLOWS,
  REPO_INPUTS,
  RepoInput,
  TYPESCRIPT_CI,
  VSCODE_EXTENSION,
  filterCovers,
  isCovered,
  packageEscapes,
  repoPath,
  uncovered,
  workflowPaths,
} from './repo-inputs';

const EVENTS = ['push', 'pull_request'] as const;
const CASES = GUARDED_WORKFLOWS.flatMap((workflow) => EVENTS.map((event) => [workflow, event] as const));

/**
 * The test sources jest loads: every *.test.ts outside the ignored integration/
 * and visual/ trees (package.json's jest testPathIgnorePatterns), plus whatever
 * they import from test/, transitively.
 */
function jestLoadedSources(): string[] {
  const testDir = __dirname;
  const pending = fs
    .readdirSync(testDir)
    .filter((name) => name.endsWith('.test.ts'))
    .map((name) => path.join(testDir, name));
  const seen = new Set<string>();
  while (pending.length > 0) {
    const file = pending.pop() as string;
    if (seen.has(file)) {
      continue;
    }
    seen.add(file);
    const source = fs.readFileSync(file, 'utf8');
    for (const match of source.matchAll(/from '(\.\/[^']+)'/g)) {
      pending.push(path.join(path.dirname(file), `${match[1]}.ts`));
    }
  }
  return [...seen].sort();
}

describe('the repo inputs the vscode jest suites read', () => {
  it('are guarded in both workflows that run the suites', () => {
    expect(GUARDED_WORKFLOWS).toEqual([TYPESCRIPT_CI, VSCODE_EXTENSION]);
  });

  it.each(CASES)('are all covered by %s on.%s.paths', (workflow, event) => {
    const filters = workflowPaths(fs.readFileSync(repoPath(workflow), 'utf8'), event);
    // The package itself must still be there, so this cannot pass by reading the
    // wrong block.
    expect(filters).toContain('editors/vscode/**');
    expect(uncovered(REPO_INPUTS, filters, workflow)).toEqual([]);
  });

  it.each(CASES)('have no stale exemption in %s on.%s.paths', (workflow, event) => {
    const filters = workflowPaths(fs.readFileSync(repoPath(workflow), 'utf8'), event);
    const stale = REPO_INPUTS.filter(
      (input) => input.exemptFrom?.[workflow] !== undefined && isCovered(filters, input.pattern),
    ).map((input) => input.pattern);
    expect(stale).toEqual([]);
  });

  it('exempt only from workflows that are guarded', () => {
    for (const input of REPO_INPUTS) {
      for (const workflow of Object.keys(input.exemptFrom ?? {})) {
        expect(GUARDED_WORKFLOWS).toContain(workflow);
      }
    }
  });

  it('are only reached through repoPath', () => {
    const sources = jestLoadedSources();
    // The scan must see the suites that do read outside the package.
    expect(sources.map((file) => path.basename(file))).toEqual(
      expect.arrayContaining(['real-report.test.ts', 'snapshot-policy.test.ts', 'repo-inputs.ts']),
    );
    const offenders: Record<string, string[]> = {};
    for (const file of sources) {
      if (path.basename(file) === 'repo-inputs.ts') {
        continue;
      }
      const found = packageEscapes(fs.readFileSync(file, 'utf8'));
      if (found.length > 0) {
        offenders[path.basename(file)] = found;
      }
    }
    expect(offenders).toEqual({});
  });

  it('name files that exist', () => {
    for (const input of REPO_INPUTS) {
      const base = input.pattern.endsWith('/**') ? input.pattern.slice(0, -'/**'.length) : input.pattern;
      expect(fs.existsSync(repoPath(base))).toBe(true);
    }
  });
});

describe('the checks, against planted defects', () => {
  const workflow = [
    'name: x',
    'on:',
    '  push:',
    '    branches:',
    '      - "**"',
    '    paths:',
    '      # a comment between entries',
    '      - "editors/vscode/**"',
    "      - '.github/**'",
    '      - tests/test_data/outputs/ash_aggregated_results.json',
    '  pull_request:',
    '    paths:',
    '      - "editors/vscode/**"',
    'jobs: {}',
  ].join('\n');

  it('reads each event\'s own paths block', () => {
    expect(workflowPaths(workflow, 'push')).toEqual([
      'editors/vscode/**',
      '.github/**',
      'tests/test_data/outputs/ash_aggregated_results.json',
    ]);
    expect(workflowPaths(workflow, 'pull_request')).toEqual(['editors/vscode/**']);
  });

  it('throws on a negated entry rather than crediting the entries before it', () => {
    const negated = workflow.replace(
      "      - '.github/**'",
      "      - '.github/**'\n      - \"!.github/workflows/**\"",
    );
    expect(negated).not.toBe(workflow);
    expect(() => workflowPaths(negated, 'push')).toThrow(/negated entry/);
    expect(workflowPaths(negated, 'pull_request')).toEqual(['editors/vscode/**']);
  });

  it('honors an exemption only for the workflow it names', () => {
    const inputs: RepoInput[] = [
      { pattern: 'a/**', readBy: 't', exemptFrom: { 'w1.yml': 'why' } },
      { pattern: 'b.json', readBy: 't' },
    ];
    expect(uncovered(inputs, ['x/**'], 'w1.yml')).toEqual(['b.json']);
    expect(uncovered(inputs, ['x/**'], 'w2.yml')).toEqual(['a/**', 'b.json']);
  });

  it('reports an input missing from a filter', () => {
    // The planted negative: pull_request lacks both repo inputs.
    expect(uncovered(REPO_INPUTS, workflowPaths(workflow, 'pull_request'))).toEqual(
      REPO_INPUTS.map((input) => input.pattern),
    );
    expect(uncovered(REPO_INPUTS, workflowPaths(workflow, 'push'))).toEqual([]);
  });

  it('throws rather than reading a missing or empty block as no entries', () => {
    expect(() => workflowPaths('name: x\njobs: {}', 'push')).toThrow(/no top-level "on:"/);
    expect(() => workflowPaths(workflow, 'merge_group')).toThrow(/no "on.merge_group"/);
    expect(() => workflowPaths('on:\n  push:\n    branches:\n      - "**"\n', 'push')).toThrow(
      /no "paths:"/,
    );
    expect(() => workflowPaths('on:\n  push:\n    paths:\njobs: {}\n', 'push')).toThrow(/is empty/);
    expect(() => workflowPaths('on:\n  push:\n    paths:\n      - [a, b]\n', 'push')).toThrow(
      /cannot read/,
    );
  });

  it('matches a filter only when it covers the whole input', () => {
    expect(filterCovers('tests/test_data/**', 'tests/test_data/outputs/a.json')).toBe(true);
    expect(filterCovers('.github/**', '.github/**')).toBe(true);
    expect(filterCovers('.github/workflows/**', '.github/**')).toBe(false);
    expect(filterCovers('tests/test_data/outputs/a.json', 'tests/test_data/outputs/b.json')).toBe(false);
    expect(filterCovers('tests/**', 'testsuite/a.json')).toBe(false);
  });

  it('flags a suite that climbs out of the package directly', () => {
    // Assembled at run time, because written out literally these planted calls
    // would be flagged by the scan of this very file above.
    const UP = `'${'..'}'`;
    const call = (fn: string, ...args: string[]): string => `path.${fn}(${args.join(', ')})`;
    expect(packageEscapes(call('resolve', '__dirname', UP, UP, UP, "'tests'", "'x.json'"))).toHaveLength(1);
    expect(packageEscapes(call('join', 'PACKAGE_ROOT', UP))).toHaveLength(1);
    expect(packageEscapes(call('join', '__dirname', `'${'..'}/${'..'}/x'`))).toHaveLength(1);
    // One level from test/ is the package root, and stays inside.
    expect(packageEscapes(call('join', '__dirname', UP, "'package.json'"))).toEqual([]);
    expect(packageEscapes(call('join', '__dirname', "'fixtures'"))).toEqual([]);
  });

  it('flags the escapes a flat match would miss', () => {
    const UP = `'${'..'}'`;
    const call = (fn: string, ...args: string[]): string => `path.${fn}(${args.join(', ')})`;
    // A nested call: the inner parenthesis ended the old capture.
    expect(packageEscapes(call('join', call('resolve', '__dirname'), UP, UP))).toHaveLength(1);
    // Template literals, assembled so this file's own text does not match.
    const template = (base: string, rest: string): string => '`$' + `{${base}}${rest}` + '`';
    expect(packageEscapes(template('__dirname', `/${'..'}/${'..'}/x`))).toHaveLength(1);
    expect(packageEscapes(template('PACKAGE_ROOT', `/${'..'}/x`))).toHaveLength(1);
    expect(packageEscapes(template('__dirname', '/fixtures/x'))).toEqual([]);
    const dirname = (inner: string): string => `path.dirname(${inner})`;
    expect(packageEscapes(dirname(dirname('__dirname')))).toHaveLength(1);
    // A parenthesis inside a string argument does not unbalance the call.
    expect(packageEscapes(call('join', '__dirname', "')'", UP, UP))).toHaveLength(1);
  });

  it('refuses an undeclared repo path', () => {
    expect(() => repoPath('tests/test_data/outputs/other.json')).toThrow(/not declared/);
    expect(() => repoPath('.githubx/a')).toThrow(/not declared/);
    expect(repoPath('.github/scripts/x.py')).toMatch(/\.github[\\/]scripts[\\/]x\.py$/);
  });

  it('refuses a path that is not normal, even under a declared directory', () => {
    // `.github/../tests/unit/x.py` matches `.github/**` by prefix and names an
    // undeclared file once joined.
    for (const bad of [
      `.github/${'..'}/tests/unit/x.py`,
      '.github/./x',
      '.github//x',
      '/.github/x',
      '.github\\x',
      `${'..'}/x`,
    ]) {
      expect(() => repoPath(bad)).toThrow(/not a normal repo-relative path/);
    }
  });
});
