// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Tests for the publishing-boundary check over the built `.vsix`.
 *
 * The case that matters most is the one a passing build will never produce: an
 * archive carrying `extension/node_modules/`. `vsce package` bundles the
 * `dependencies` tree by default, so that archive is one `npm install --save`
 * away, and packaging/README.md rules it out for a published artifact. So it is
 * synthesized here and the check is required to reject it.
 *
 * The vacuous-pass cases are tested too, because an allowlist is a subset test and
 * a subset test passes on the empty set.
 */

import { mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import * as path from 'path';
import {
  describeProblems,
  inspectMembers,
  listZipMembers,
} from '../src/vsix-contents';
import { main, verify } from '../src/verify-vsix';
import { CLEAN_VSIX_MEMBERS, writeZip } from './zip';

function collector(): { write(text: string): void; text(): string } {
  const chunks: string[] = [];
  return { write: (text) => chunks.push(text), text: () => chunks.join('') };
}

describe('listZipMembers', () => {
  it('reads the member names of an archive it was given', () => {
    expect(listZipMembers(writeZip(CLEAN_VSIX_MEMBERS))).toEqual(
      CLEAN_VSIX_MEMBERS.map((entry) => entry.name),
    );
  });

  it('reads an archive with no members', () => {
    expect(listZipMembers(writeZip([]))).toEqual([]);
  });

  it('normalizes backslash separators a Windows writer might have used', () => {
    expect(listZipMembers(writeZip([{ name: 'extension\\out\\extension.js', data: 'x' }]))).toEqual([
      'extension/out/extension.js',
    ]);
  });

  it('refuses a buffer too short to hold an end-of-central-directory record', () => {
    expect(() => listZipMembers(Buffer.alloc(4))).toThrow(/shorter than an end-of-central-directory/);
  });

  it('refuses a buffer with no end-of-central-directory signature', () => {
    expect(() => listZipMembers(Buffer.alloc(100))).toThrow(/no end-of-central-directory signature/);
  });

  it('refuses a Zip64 archive instead of returning a short member list', () => {
    // The sentinels parse as real numbers. Reading them would yield a nonsense
    // offset and a truncated member list, which would then satisfy the allowlist.
    expect(() => listZipMembers(writeZip(CLEAN_VSIX_MEMBERS, { zip64Sentinel: true }))).toThrow(
      /Zip64/,
    );
  });

  it('refuses an archive whose entry count runs past the directory', () => {
    expect(() => listZipMembers(writeZip(CLEAN_VSIX_MEMBERS, { extraEntryCount: 5 }))).toThrow(
      /truncated ZIP central directory/,
    );
  });

  it('refuses an archive whose central directory claims to end past the file', () => {
    const zip = writeZip(CLEAN_VSIX_MEMBERS);
    // Overstate the central directory size in the EOCD.
    zip.writeUInt32LE(0xfffffff0, zip.length - 22 + 12);
    expect(() => listZipMembers(zip)).toThrow(/truncated ZIP archive/);
  });

  it('refuses an archive with a corrupt central-directory entry', () => {
    expect(() => listZipMembers(writeZip(CLEAN_VSIX_MEMBERS, { corruptEntry: 1 }))).toThrow(
      /no central-header signature/,
    );
  });

  it('refuses an archive whose last member name runs past the end of the file', () => {
    const zip = writeZip([{ name: 'extension/out/extension.js', data: 'x' }]);
    // Overstate the name length of the single central-directory entry. Its offset
    // is the size of the local header plus its body.
    const centralStart = 30 + 'extension/out/extension.js'.length + 1;
    zip.writeUInt16LE(0xfff0, centralStart + 28);
    expect(() => listZipMembers(zip)).toThrow(/runs past the end of the file/);
  });
});

describe('inspectMembers', () => {
  it('accepts an archive that carries only this extension\'s own output', () => {
    const verdict = inspectMembers(CLEAN_VSIX_MEMBERS.map((entry) => entry.name));

    expect(verdict.foreign).toEqual([]);
    expect(verdict.missing).toEqual([]);
    expect(verdict.bundledModules).toEqual([]);
    expect(describeProblems(verdict)).toBeNull();
  });

  it('accepts compiled output in a subdirectory of out/', () => {
    expect(
      inspectMembers([
        ...CLEAN_VSIX_MEMBERS.map((entry) => entry.name),
        'extension/out/private/helper.js',
      ]).foreign,
    ).toEqual([]);
  });

  it('accepts every spelling of the license and notice files vsce may write', () => {
    for (const name of [
      'extension/LICENSE',
      'extension/LICENSE.txt',
      'extension/LICENSE.md',
      'extension/license.txt',
      'extension/NOTICE',
      'extension/notice.md',
    ]) {
      expect(inspectMembers([name]).foreign).toEqual([]);
    }
  });

  it('accepts the case vsce lowercases the readme and changelog to', () => {
    // Measured: `README.md` and `CHANGELOG.md` on disk arrive as `readme.md` and
    // `changelog.md`. A case-sensitive allowlist built from the source tree
    // rejected the real archive on the first build.
    expect(
      inspectMembers([
        'extension/readme.md',
        'extension/changelog.md',
        'extension/README.md',
        'extension/CHANGELOG.md',
      ]).foreign,
    ).toEqual([]);
  });

  it('accepts directory entries, which carry no bytes', () => {
    expect(inspectMembers(['extension/', 'extension/out/']).foreign).toEqual([]);
  });

  it('rejects a bundled node_modules and says why', () => {
    const verdict = inspectMembers([
      ...CLEAN_VSIX_MEMBERS.map((entry) => entry.name),
      'extension/node_modules/semver/package.json',
      'extension/node_modules/semver/index.js',
    ]);

    expect(verdict.bundledModules).toHaveLength(2);
    const problems = describeProblems(verdict);
    expect(problems).toContain('third-party npm code');
    expect(problems).toContain('packaging/README.md');
    expect(problems).toContain('devDependencies');
    expect(problems).toContain('extension/node_modules/semver/index.js');
  });

  it('rejects source, maps and type declarations that leaked past .vscodeignore', () => {
    const verdict = inspectMembers([
      ...CLEAN_VSIX_MEMBERS.map((entry) => entry.name),
      'extension/src/extension.ts',
      'extension/out/extension.js.map',
      'extension/out/extension.d.ts',
      'extension/tsconfig.json',
    ]);

    expect(verdict.foreign).toEqual([
      'extension/src/extension.ts',
      'extension/out/extension.js.map',
      'extension/out/extension.d.ts',
      'extension/tsconfig.json',
    ]);
    expect(verdict.bundledModules).toEqual([]);
    expect(describeProblems(verdict)).toContain('match no allowlist pattern');
  });

  it('rejects a member outside the extension/ prefix', () => {
    expect(inspectMembers(['elsewhere/thing.js']).foreign).toEqual(['elsewhere/thing.js']);
  });

  it('rejects an empty archive rather than passing a subset test vacuously', () => {
    const verdict = inspectMembers([]);

    expect(verdict.foreign).toEqual([]);
    expect(verdict.missing).toEqual(['extension/package.json', 'extension/out/extension.js']);
    expect(describeProblems(verdict)).toContain('vacuous pass');
  });

  it('rejects an archive built before tsc ran', () => {
    const verdict = inspectMembers(
      CLEAN_VSIX_MEMBERS.map((entry) => entry.name).filter((name) => !name.startsWith('extension/out/')),
    );

    expect(verdict.missing).toEqual(['extension/out/extension.js']);
    expect(describeProblems(verdict)).toContain('extension/out/extension.js');
  });

  it('truncates long lists so the reason is not pushed off screen', () => {
    const many = Array.from({ length: 40 }, (_, i) => `extension/node_modules/pkg/f${i}.js`);
    const problems = describeProblems(inspectMembers([...CLEAN_VSIX_MEMBERS.map((e) => e.name), ...many]));
    expect(problems).toContain('40 member(s) under extension/node_modules/');
    expect(problems).toContain('extension/node_modules/pkg/f4.js');
    expect(problems).not.toContain('extension/node_modules/pkg/f5.js');
  });
});

describe('the verify-vsix command', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(path.join(tmpdir(), 'ash-vsix-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('exits 0 and lists the members of a clean archive', () => {
    const archive = path.join(dir, 'clean.vsix');
    writeFileSync(archive, writeZip(CLEAN_VSIX_MEMBERS));
    const out = collector();
    const err = collector();

    expect(verify(archive, out as never, err as never)).toBe(0);
    expect(out.text()).toContain('vsix contents OK');
    expect(out.text()).toContain('extension/out/extension.js');
    expect(err.text()).toBe('');
  });

  it('exits 1 when the archive carries third-party code', () => {
    const archive = path.join(dir, 'dirty.vsix');
    writeFileSync(
      archive,
      writeZip([...CLEAN_VSIX_MEMBERS, { name: 'extension/node_modules/semver/index.js', data: 'x' }]),
    );
    const err = collector();

    expect(verify(archive, collector() as never, err as never)).toBe(1);
    expect(err.text()).toContain('vsix contents check failed');
  });

  it('exits 2 when the file cannot be read, which is not the same as a clean archive', () => {
    const err = collector();

    expect(verify(path.join(dir, 'absent.vsix'), collector() as never, err as never)).toBe(2);
    expect(err.text()).toContain('cannot read');
  });

  it('exits 2 when the file is not a ZIP archive at all', () => {
    const archive = path.join(dir, 'not-a-zip.vsix');
    // Longer than an end-of-central-directory record on purpose, so this reaches
    // the signature search rather than stopping at the length check -- the length
    // check is covered by its own unit test above, and a 17-byte file would not
    // exercise this path.
    writeFileSync(archive, 'x'.repeat(500));
    const err = collector();

    expect(verify(archive, collector() as never, err as never)).toBe(2);
    expect(err.text()).toContain('no end-of-central-directory signature');
  });

  it('writes to the real streams when none are supplied', () => {
    // The default parameters are wiring, and wiring that no test exercises is
    // wiring nobody has run. Output goes to jest's own stdout, which is where a
    // CI step would look for it.
    const archive = path.join(dir, 'clean.vsix');
    writeFileSync(archive, writeZip(CLEAN_VSIX_MEMBERS));

    expect(verify(archive)).toBe(0);
    expect(main(['node', 'verify-vsix.js', archive])).toBe(0);
    expect(main(['node', 'verify-vsix.js'])).toBe(2);
  });

  it('prints usage and exits 2 when given no archive', () => {
    const err = collector();

    expect(main(['node', '/x/out/verify-vsix.js'], collector() as never, err as never)).toBe(2);
    expect(err.text()).toContain('usage: verify-vsix.js <path-to.vsix>');
  });

  it('names a fallback in the usage line when argv carries no script path', () => {
    const err = collector();
    expect(main(['node'], collector() as never, err as never)).toBe(2);
    expect(err.text()).toContain('verify-vsix.js');
  });

  it('verifies the archive named on the command line', () => {
    const archive = path.join(dir, 'clean.vsix');
    writeFileSync(archive, writeZip(CLEAN_VSIX_MEMBERS));

    expect(main(['node', 'verify-vsix.js', archive], collector() as never, collector() as never)).toBe(0);
  });
});
