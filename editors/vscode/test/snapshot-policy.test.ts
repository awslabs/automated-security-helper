// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * The rules that make a snapshot change a decision rather than a side effect, for
 * this extension's two snapshot suites. Each has a negative control, so a check that
 * has stopped seeing anything cannot pass by default.
 *
 *   - Nothing CI runs passes an update flag: not this suite's `--snapshot-update`,
 *     not jest's `--updateSnapshot`/`--update-snapshot`/`-u`/`--ci=false`/`--no-ci`,
 *     not the visual suite's ASH_SNAPSHOT_UPDATE, not the JetBrains plugin's Gradle
 *     property in any of its spellings.
 *   - `npm test` runs `jest --ci`, so a new snapshot fails locally too instead of
 *     being written on first run. Proved by running it, not by reading the config:
 *     `"ci": true` in package.json's jest block did nothing, because jest's own
 *     command-line default for `--ci` (whether CI is set) overrides it.
 *   - The update path refuses to run under CI.
 *   - The pixel suite's container is pinned: base image by digest, VS Code by
 *     version and SHA-256, and the version is the one the integration job uses.
 *
 * Orphans and trailers are checked by .github/scripts/check-snapshot-trailers.py,
 * which has its own self-test.
 */

import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { REPO_ROOT, repoPath } from './repo-inputs';
import { UPDATE_ENV, UPDATE_FLAG, underCi, updateAllowed } from './update-policy';

const PACKAGE_ROOT = path.resolve(__dirname, '..');

// A `#` at line start or after whitespace starts a comment in YAML and shell; a note
// explaining the rule must not trip it, and nothing a comment says is executed.
const COMMENT = /(?:^|\s)#.*$/;

// The same forms as UPDATE_FLAGS in .github/scripts/check-snapshot-trailers.py,
// which checks the workflows without node; a form added here goes there too.
const BANNED: readonly RegExp[] = [
  // Prefix match, as core's policy test does, so --snapshot-update-anything is caught.
  new RegExp(UPDATE_FLAG),
  new RegExp(`\\b${UPDATE_ENV}\\b`),
  // jest's long flag in both spellings, and the two ways to turn --ci off.
  /--updateSnapshot/,
  /--update-snapshot/,
  /--no-ci\b/,
  /--ci[= ]false/,
  // jest's short flag, after a jest or npm test command (`npm t` and
  // `npm --prefix <dir> test` included).
  /\b(?:jest|npm\b.*\s(?:test|t))\b.*\s-u\b/,
  // The JetBrains plugin's Gradle property: -P with or without a space, the long
  // option, and the environment variable Gradle maps to it.
  /-P\s*snapshot-update/,
  /--project-prop(?:=|\s+)snapshot-update/,
  /ORG_GRADLE_PROJECT_snapshot-update/,
];

/**
 * For a line that starts a YAML scalar, the column its continuation lines must be
 * right of, and the scalar's first text. `key: value` (also `key: |`, `key: >-`)
 * continues right of the key's column, `- value` right of its dash. A bare `key:`
 * opens a mapping or sequence and starts no scalar.
 */
function scalarOwner(line: string): [number, string] | undefined {
  const [, lead, dashes, rest] = /^(\s*)((?:-\s+)*)(.*)$/.exec(line) ?? ['', '', '', line];
  const key = /^[^\s#'"][^:#]*:(?:\s+(\S.*))?$/.exec(rest);
  if (key !== null) {
    return key[1] === undefined ? undefined : [lead.length + dashes.length, key[1]];
  }
  if (dashes !== '') {
    return [lead.length + dashes.trimEnd().lastIndexOf('-'), rest];
  }
  return undefined;
}

/**
 * `text` with every YAML scalar continuation joined to its first line, the same way
 * logical_lines in the trailer script does: a `>` block, a plain or quoted scalar
 * continued on a more indented line, and a `|` block line ending in `\` all join,
 * so a flag on the line after its command is still seen with the command. Lines of
 * a `|` block are separate shell commands and stay separate.
 */
function logicalLines(text: string): string[] {
  const out: string[] = [];
  let ownerIndent: number | undefined;
  let literal = false;
  let joinsNext = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(COMMENT, '').trimEnd();
    if (line.trim() === '') {
      continue;
    }
    const indent = line.length - line.trimStart().length;
    if (ownerIndent !== undefined && indent > ownerIndent) {
      const body = line.trim();
      if (literal && !joinsNext) {
        out.push(body);
      } else {
        out[out.length - 1] = `${out[out.length - 1].replace(/\\$/, '').trimEnd()} ${body}`;
      }
      joinsNext = literal && body.endsWith('\\');
      continue;
    }
    out.push(line.trim());
    const owner = scalarOwner(line);
    ownerIndent = owner?.[0];
    literal = owner !== undefined && owner[1].startsWith('|');
    joinsNext = false;
  }
  return out;
}

function bannedIn(text: string): string[] {
  const lines = logicalLines(text);
  return BANNED.filter((pattern) => lines.some((line) => pattern.test(line))).map((pattern) => pattern.source);
}

/**
 * Runs the package's `test` script, exactly as package.json spells it, over one
 * probe test that asserts a snapshot that does not exist, outside CI. Returns its
 * exit status and whether the snapshot was written. `extra` is appended to the
 * script's own arguments, for the negative control.
 */
function runTestScriptOverNewSnapshot(extra: readonly string[]): { status: number | null; written: boolean; output: string } {
  const manifest = JSON.parse(fs.readFileSync(path.join(PACKAGE_ROOT, 'package.json'), 'utf8')) as {
    scripts: Record<string, string>;
  };
  const [program, ...args] = manifest.scripts.test.trim().split(/\s+/);
  expect(program).toBe('jest');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ash-vscode-snapshot-probe-'));
  try {
    fs.writeFileSync(
      path.join(dir, 'probe.test.js'),
      "test('probe', () => { expect('a snapshot nobody asked for').toMatchSnapshot(); });\n",
    );
    const env = { ...process.env };
    // A developer's shell: jest's --ci default would otherwise come from this run.
    delete env.CI;
    delete env.GITHUB_ACTIONS;
    delete env.JEST_WORKER_ID;
    const jest = path.join(PACKAGE_ROOT, 'node_modules', 'jest', 'bin', 'jest.js');
    const result = spawnSync(
      process.execPath,
      [jest, ...args, ...extra, '--roots', dir, '--testMatch', '**/probe.test.js', '--coverage=false'],
      { cwd: PACKAGE_ROOT, env, encoding: 'utf8' },
    );
    return {
      status: result.status,
      written: fs.existsSync(path.join(dir, '__snapshots__', 'probe.test.js.snap')),
      output: `${result.stdout}${result.stderr}`,
    };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

// The --policy checker in the trailer script names every update flag in order to look
// for them: in its pattern, its docstring and its self-test fixtures. It passes none,
// so it is the one file under .github/ exempt here, by exact path, and only while it
// is still that checker (the test below requires its policy function).
const POLICY_CHECKER = '.github/scripts/check-snapshot-trailers.py';

function filesUnder(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      return entry.name === '__pycache__' ? [] : filesUnder(full);
    }
    return [full];
  });
}

describe('no CI path updates a snapshot', () => {
  test('the scanner finds each form a workflow would use', () => {
    expect(bannedIn('run: npm run snapshots -- --snapshot-update visual')).not.toEqual([]);
    expect(bannedIn('run: npx jest --ci --updateSnapshot')).not.toEqual([]);
    expect(bannedIn('run: npm test -- -u')).not.toEqual([]);
    expect(bannedIn('run: npx jest --ci=false')).not.toEqual([]);
    expect(bannedIn('  env:\n    ASH_SNAPSHOT_UPDATE: "1"')).not.toEqual([]);
    expect(bannedIn('# never pass --snapshot-update in CI')).toEqual([]);
    expect(bannedIn('run: npm run snapshots -- visual')).toEqual([]);
    expect(bannedIn('run: uv run pytest -n auto tests/unit')).toEqual([]);
  });

  test.each([
    'run: npx jest --update-snapshot',
    'run: npx jest --no-ci',
    'run: npm t -- -u',
    'run: npm run test -- -u',
    'run: npm --prefix "editors/vscode" test -- -u',
    'run: >\n  npx jest --ci\n  -u',
    'run: npx jest --ci\n  -u',
    '- run: >-\n    npm test --\n    --update-snapshot',
    'run: |\n  npx jest --ci \\\n    -u',
    'run: ./gradlew test -P snapshot-update',
    'run: ./gradlew test --project-prop snapshot-update',
    'run: ./gradlew test --project-prop=snapshot-update',
    'env:\n  ORG_GRADLE_PROJECT_snapshot-update: "true"',
  ])('the scanner finds %j', (text) => {
    expect(bannedIn(text)).not.toEqual([]);
  });

  test('a -u given to another command in the same run block is not jest\'s', () => {
    const workflow = [
      'steps:',
      '  - run: |',
      '      npm test -- --ci',
      '      sort -u names.txt',
      '  - name: next step',
      '    run: echo -u',
    ].join('\n');
    expect(bannedIn(workflow)).toEqual([]);
  });

  test('no file under .github/ and no npm script passes one', () => {
    const files = filesUnder(repoPath('.github'));
    expect(files.some((file) => file.endsWith('ash-vscode-extension.yml'))).toBe(true);
    const checker = fs.readFileSync(repoPath(POLICY_CHECKER), 'utf8');
    expect(checker).toContain('def find_update_flags(');
    const offenders: Record<string, string[]> = {};
    for (const file of files) {
      if (path.relative(REPO_ROOT, file).split(path.sep).join('/') === POLICY_CHECKER) {
        continue;
      }
      const found = bannedIn(fs.readFileSync(file, 'utf8'));
      if (found.length > 0) {
        offenders[path.relative(REPO_ROOT, file)] = found;
      }
    }
    const manifest = JSON.parse(fs.readFileSync(path.join(PACKAGE_ROOT, 'package.json'), 'utf8')) as {
      scripts: Record<string, string>;
    };
    for (const [name, command] of Object.entries(manifest.scripts)) {
      const found = bannedIn(command);
      if (found.length > 0) {
        offenders[`package.json scripts.${name}`] = found;
      }
    }
    expect(offenders).toEqual({});
  });

  test('npm test never writes a snapshot it was not asked to, outside CI too', () => {
    // Without --ci, a local `npm test` writes every NEW snapshot silently, and only
    // CI (where jest detects CI itself) would refuse.
    const plain = runTestScriptOverNewSnapshot([]);
    expect(plain.written).toBe(false);
    expect(plain.status).not.toBe(0);
    expect(plain.output).toMatch(/not written/);
  }, 60_000);

  test('the probe sees a snapshot being written when one is', () => {
    // Negative control for the test above: the same run with --ci turned off writes
    // the snapshot and passes, so `written: false` there is the script's doing.
    const control = runTestScriptOverNewSnapshot(['--ci=false']);
    expect(control.output).toMatch(/1 written/);
    expect(control.written).toBe(true);
    expect(control.status).toBe(0);
  }, 60_000);
});

describe('the update path', () => {
  test('is refused under CI', () => {
    expect(() => updateAllowed(true, { CI: 'true' })).toThrow(/refused under CI/);
    expect(() => updateAllowed(true, { GITHUB_ACTIONS: 'true' })).toThrow(/Snapshot-Update/);
  });

  test('runs locally when asked, and compares when not', () => {
    expect(updateAllowed(true, {})).toBe(true);
    expect(updateAllowed(false, { CI: 'true' })).toBe(false);
    expect(underCi({ CI: 'false' })).toBe(false);
  });
});

describe('the pixel suite environment is pinned', () => {
  const dockerfile = fs.readFileSync(path.join(PACKAGE_ROOT, 'test', 'visual', 'Dockerfile'), 'utf8');

  test('base image by digest', () => {
    const froms = dockerfile.split('\n').filter((line) => /^FROM\s/.test(line));
    expect(froms.length).toBeGreaterThan(0);
    for (const from of froms) {
      expect(from).toMatch(/@sha256:[0-9a-f]{64}(\s|$)/);
    }
  });

  test('VS Code by version and SHA-256, the same version the integration job runs', () => {
    const version = /^ARG VSCODE_VERSION=(\S+)$/m.exec(dockerfile)?.[1];
    expect(version).toBe('1.140.0');
    expect(dockerfile).toMatch(/^ARG VSCODE_SHA256=[0-9a-f]{64}$/m);
    expect(dockerfile).toMatch(/sha256sum -c -/);
    const workflow = fs.readFileSync(
      repoPath('.github/workflows/ash-vscode-extension.yml'),
      'utf8',
    );
    expect(workflow).toContain(`ASH_IT_VSCODE_VERSION: "${version}"`);
  });

  test('Debian packages from a fixed snapshot', () => {
    expect(dockerfile).toMatch(/^ARG DEBIAN_SNAPSHOT=\d{8}T\d{6}Z$/m);
    expect(dockerfile).toContain('rm -f /etc/apt/sources.list.d/debian.sources');
  });
});
