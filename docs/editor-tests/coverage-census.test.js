// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Tests for the `node-test` exclusion kind of .github/scripts/assert-coverage-completeness.mjs.
//
// An entry of that kind excuses a production module from the coverage census because
// a node:test suite loads it. The entry is only true while its test file is tracked,
// reads as a test source and imports the module, so the census checks all three on
// every run. Each test below builds a small git repository of its own, writes an
// exclusions file beside it, runs the real census script in it and reads the exit
// code and the message, so no case depends on what the repository itself holds.
// The last test runs the census on the repository itself.

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(fileURLToPath(new URL('../../', import.meta.url)));
const census = path.join(repoRoot, '.github', 'scripts', 'assert-coverage-completeness.mjs');

const MODULE = 'src/mod.js';
const TEST = 'tests/mod.test.js';
const MODULE_SOURCE = 'export const mod = 1;\n';
const IMPORTING_SOURCE = "import { mod } from '../src/mod.js';\n";

function git(cwd, ...args) {
  const result = spawnSync('git', args, { cwd, encoding: 'utf8' });
  assert.equal(result.status, 0, `git ${args.join(' ')} failed: ${result.stderr}`);
  return result.stdout;
}

/** A node-test entry for MODULE whose test file is TEST, with any field replaced. */
function nodeTestEntry(overrides = {}) {
  return {
    kind: 'node-test',
    path: MODULE,
    reason: 'A node:test suite loads this module.',
    test: TEST,
    ...overrides,
  };
}

/** An entry that excuses a file by the kind that needs no test file. */
function noHarnessEntry(file) {
  return { kind: 'no-harness', path: file, reason: 'No harness exists for this file.' };
}

/**
 * A scratch repository holding `files`, with an exclusions file beside it. The
 * repository is staged, which is all `git ls-files` needs, and removed when the
 * test ends.
 */
function scratch(t, files, exclusions) {
  const root = mkdtempSync(path.join(tmpdir(), 'census-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const repo = path.join(root, 'repo');
  mkdirSync(repo);
  git(repo, 'init', '--quiet');
  for (const [name, text] of Object.entries(files)) {
    const file = path.join(repo, name);
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, text);
  }
  git(repo, 'add', '--all');
  const exclusionsFile = path.join(root, 'exclusions.json');
  writeFileSync(exclusionsFile, JSON.stringify({ exclusions }));
  return { repo, exclusionsFile };
}

function runCensus({ repo, exclusionsFile }) {
  return spawnSync(
    process.execPath,
    [census, '--exclusions', exclusionsFile, '--scope', 'outside', '--package', 'deploy/cdk'],
    { cwd: repo, encoding: 'utf8' },
  );
}

/** The census's verdict for a repository holding the module and a test file. */
function verdict(t, testSource, entry = nodeTestEntry(), extraFiles = {}, extraEntries = []) {
  return runCensus(
    scratch(
      t,
      { [MODULE]: MODULE_SOURCE, [TEST]: testSource, ...extraFiles },
      [entry, ...extraEntries],
    ),
  );
}

function assertFails(result, message) {
  assert.equal(result.status, 1, `stdout: ${result.stdout} stderr: ${result.stderr}`);
  assert.match(result.stderr, /Coverage completeness check failed/);
  assert.match(result.stderr, message);
  assert.equal(result.stdout, '');
}

function assertRefused(result, message) {
  assert.equal(result.status, 2, `stdout: ${result.stdout} stderr: ${result.stderr}`);
  assert.match(result.stderr, message);
  assert.equal(result.stdout, '');
}

test('control: a node-test entry whose test imports the module is accepted', (t) => {
  const result = verdict(t, IMPORTING_SOURCE);
  assert.equal(result.status, 0, `stdout: ${result.stdout} stderr: ${result.stderr}`);
  assert.match(result.stdout, /coverage completeness OK \(outside\)/);
  assert.match(result.stdout, /1 excluded by name/);
});

test('control: a production file named in no entry still fails the census', (t) => {
  const result = verdict(t, IMPORTING_SOURCE, nodeTestEntry(), { 'src/extra.js': MODULE_SOURCE });
  assertFails(result, /src\/extra\.js is measured by no coverage report and is named in no exclusion/);
});

test('an entry that names a test file which does not exist fails', (t) => {
  const result = verdict(t, IMPORTING_SOURCE, nodeTestEntry({ test: 'tests/gone.test.js' }));
  assertFails(
    result,
    /exclusion src\/mod\.js \(node-test\) names the test file tests\/gone\.test\.js, which is not tracked/,
  );
});

test('an entry whose test file does not import the module fails', (t) => {
  const result = verdict(t, "console.log('no import here');\n");
  assertFails(
    result,
    /exclusion src\/mod\.js \(node-test\) names tests\/mod\.test\.js, which does not import it/,
  );
});

test('an entry whose test file is not a test source fails', (t) => {
  const result = verdict(
    t,
    IMPORTING_SOURCE,
    nodeTestEntry({ test: 'src/helper.js' }),
    { 'src/helper.js': "import { mod } from './mod.js';\n" },
    [noHarnessEntry('src/helper.js')],
  );
  assertFails(
    result,
    /names src\/helper\.js as its test, but the census does not read that file as a test source/,
  );
});

const IMPORTING = {
  'a default import': "import mod from '../src/mod.js';\n",
  'a named import': "import { mod } from '../src/mod.js';\n",
  'a named import over several lines': "import {\n  one,\n  mod,\n} from '../src/mod.js';\n",
  'a namespace import': "import * as mod from '../src/mod.js';\n",
  'a side-effect import': "import '../src/mod.js';\n",
  'a re-export': "export { mod } from '../src/mod.js';\n",
  'a dynamic import': "const mod = await import('../src/mod.js');\n",
  'a double-quoted specifier': 'import { mod } from "../src/mod.js";\n',
  'a specifier with a dot segment': "import { mod } from '.././src/mod.js';\n",
  'an import after a comment holding a quote': "// it's imported next\nimport { mod } from '../src/mod.js';\n",
  'an import after a string holding two slashes':
    "const url = 'http://example.test/a';\nimport { mod } from '../src/mod.js';\n",
  'an import after a closed block comment': "/* the module */ import { mod } from '../src/mod.js';\n",
};

for (const [name, source] of Object.entries(IMPORTING)) {
  test(`a test file that has ${name} counts as importing the module`, (t) => {
    const result = verdict(t, source);
    assert.equal(result.status, 0, `stdout: ${result.stdout} stderr: ${result.stderr}`);
  });
}

const NOT_IMPORTING = {
  'no import': "console.log('nothing is loaded');\n",
  'an import of another module': "import { other } from '../src/other.js';\n",
  'an import of a bare package name': "import { mod } from 'mod.js';\n",
  'an import of a path above the module': "import { mod } from '../../src/mod.js';\n",
  'an import of a path that only ends like the module': "import { mod } from '../vendor/src/mod.js';\n",
  'an import in a line comment': "// import { mod } from '../src/mod.js';\n",
  'an import in a block comment': "/*\nimport { mod } from '../src/mod.js';\n*/\n",
  'an import in a comment after a string holding two slashes':
    "const url = 'http://example.test'; // import { mod } from '../src/mod.js';\n",
  'the module path as plain text': "const where = '../src/mod.js';\n",
  'an import statement written inside a string': 'const text = "import { mod } from \'../src/mod.js\'";\n',
};

for (const [name, source] of Object.entries(NOT_IMPORTING)) {
  test(`a test file that has ${name} does not count as importing the module`, (t) => {
    assertFails(verdict(t, source), /names tests\/mod\.test\.js, which does not import it/);
  });
}

test('a module with the same file name in another directory is not the module', (t) => {
  const result = verdict(
    t,
    "import { mod } from '../lib/mod.js';\n",
    nodeTestEntry(),
    { 'lib/mod.js': MODULE_SOURCE },
    [noHarnessEntry('lib/mod.js')],
  );
  assertFails(result, /names tests\/mod\.test\.js, which does not import it/);
});

test('a test file in a directory named test is a test source', (t) => {
  const result = runCensus(
    scratch(
      t,
      { [MODULE]: MODULE_SOURCE, 'test/mod-check.js': "import { mod } from '../src/mod.js';\n" },
      [nodeTestEntry({ test: 'test/mod-check.js' })],
    ),
  );
  assert.equal(result.status, 0, `stdout: ${result.stdout} stderr: ${result.stderr}`);
});

test('a node-test entry without a test field is refused', (t) => {
  const { test: _omitted, ...withoutTest } = nodeTestEntry();
  assertRefused(verdict(t, IMPORTING_SOURCE, withoutTest), /needs a non-empty "test"/);
});

test('a node-test entry with an empty test field is refused', (t) => {
  assertRefused(verdict(t, IMPORTING_SOURCE, nodeTestEntry({ test: '' })), /needs a non-empty "test"/);
});

test('a node-test entry whose test path leaves the repository is refused', (t) => {
  assertRefused(
    verdict(t, IMPORTING_SOURCE, nodeTestEntry({ test: '../outside.test.js' })),
    /test must be repository-relative/,
  );
  assertRefused(
    verdict(t, IMPORTING_SOURCE, nodeTestEntry({ test: '/tmp/outside.test.js' })),
    /test must be repository-relative/,
  );
});

test('a test field on an entry of another kind is refused', (t) => {
  const entry = { ...noHarnessEntry(MODULE), test: TEST };
  assertRefused(verdict(t, IMPORTING_SOURCE, entry), /has a "test" field, which only a node-test entry uses/);
});

test('an unknown kind is refused and the message lists node-test among the kinds', (t) => {
  assertRefused(
    verdict(t, IMPORTING_SOURCE, nodeTestEntry({ kind: 'node-tests' })),
    /expected one of harness-config, no-harness, node-test/,
  );
});

test('the repository census accepts the exclusions the repository commits', () => {
  const tracked = git(repoRoot, 'ls-files', '-z').split('\0');
  const packages = tracked
    .filter((name) => /^deploy\/[^/]+\/package\.json$/.test(name))
    .map((name) => path.posix.dirname(name));
  assert.ok(packages.length > 0, 'no deploy package is tracked, so the census would not run as CI runs it');
  const result = spawnSync(
    process.execPath,
    [
      census,
      '--exclusions',
      '.github/typescript-coverage-exclusions.json',
      '--scope',
      'outside',
      ...packages.flatMap((name) => ['--package', name]),
    ],
    { cwd: repoRoot, encoding: 'utf8' },
  );
  assert.equal(result.status, 0, `stdout: ${result.stdout} stderr: ${result.stderr}`);
  assert.match(result.stdout, /coverage completeness OK \(outside\)/);
});
