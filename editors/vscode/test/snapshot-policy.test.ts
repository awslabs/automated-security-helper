// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * The rules that make a snapshot change a decision rather than a side effect, for
 * this extension's two snapshot suites. Each has a negative control, so a check that
 * has stopped seeing anything cannot pass by default.
 *
 *   - Nothing CI runs passes an update flag: not this suite's `--snapshot-update`,
 *     not jest's `--updateSnapshot`/`-u`/`--ci=false`, not the visual suite's
 *     ASH_SNAPSHOT_UPDATE.
 *   - jest is configured never to write a snapshot unasked (`ci: true`), so a new
 *     snapshot fails locally too instead of being written on first run.
 *   - The update path refuses to run under CI.
 *   - The pixel suite's container is pinned: base image by digest, VS Code by
 *     version and SHA-256, and the version is the one the integration job uses.
 *
 * Orphans and trailers are checked by .github/scripts/check-editor-snapshot-trailers.py,
 * which has its own self-test.
 */

import * as fs from 'fs';
import * as path from 'path';
import { UPDATE_ENV, UPDATE_FLAG, underCi, updateAllowed } from './update-policy';

const PACKAGE_ROOT = path.resolve(__dirname, '..');
const REPO_ROOT = path.resolve(PACKAGE_ROOT, '..', '..');

// A `#` at line start or after whitespace starts a comment in YAML and shell; a note
// explaining the rule must not trip it, and nothing a comment says is executed.
const COMMENT = /(?:^|\s)#.*$/gm;

const BANNED: readonly RegExp[] = [
  // Prefix match, as core's policy test does, so --snapshot-update-anything is caught.
  new RegExp(UPDATE_FLAG),
  /--updateSnapshot/,
  /--ci[= ]false/,
  new RegExp(`\\b${UPDATE_ENV}\\b`),
  // jest's short flag, on a jest or npm-test command line.
  /\b(?:jest|npm(?: run)? test|npx jest)\b[^\n]*\s-u\b/,
];

function bannedIn(text: string): string[] {
  const code = text.replace(COMMENT, '');
  return BANNED.filter((pattern) => pattern.test(code)).map((pattern) => pattern.source);
}

// The --policy checker in the trailer script names every update flag in order to look
// for them: in its pattern, its docstring and its self-test fixtures. It passes none,
// so it is the one file under .github/ exempt here, by exact path, and only while it
// is still that checker (the test below requires its policy function).
const POLICY_CHECKER = '.github/scripts/check-editor-snapshot-trailers.py';

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

  test('no file under .github/ and no npm script passes one', () => {
    const files = filesUnder(path.join(REPO_ROOT, '.github'));
    expect(files.some((file) => file.endsWith('ash-vscode-extension.yml'))).toBe(true);
    const checker = fs.readFileSync(path.join(REPO_ROOT, POLICY_CHECKER), 'utf8');
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

  test('jest never writes a snapshot it was not asked to', () => {
    const manifest = JSON.parse(fs.readFileSync(path.join(PACKAGE_ROOT, 'package.json'), 'utf8')) as {
      jest: { ci?: unknown };
    };
    // Without it, a local `npm test` writes every NEW snapshot silently, and only
    // CI (where jest detects CI itself) would refuse.
    expect(manifest.jest.ci).toBe(true);
  });
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
      path.join(REPO_ROOT, '.github', 'workflows', 'ash-vscode-extension.yml'),
      'utf8',
    );
    expect(workflow).toContain(`ASH_IT_VSCODE_VERSION: "${version}"`);
  });

  test('Debian packages from a fixed snapshot', () => {
    expect(dockerfile).toMatch(/^ARG DEBIAN_SNAPSHOT=\d{8}T\d{6}Z$/m);
    expect(dockerfile).toContain('rm -f /etc/apt/sources.list.d/debian.sources');
  });
});
