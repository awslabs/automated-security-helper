// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * A minimal STORED-only ZIP writer, so the `.vsix` contents check can be tested
 * against archives whose member lists are chosen rather than found.
 *
 * WHY THE TESTS BUILD ARCHIVES INSTEAD OF COMMITTING THEM
 *
 * The interesting cases are the ones a real build will not produce on demand: an
 * archive with a bundled `node_modules`, one missing `out/extension.js`, one with
 * a Zip64 sentinel, one truncated mid-directory. Committing a fixture per case
 * would also mean committing files named `*.vsix`, and .gitignore:263 is a bare
 * `*.vsix` -- `git add` skips ignored files silently, so those fixtures would be
 * written, verified against, and then absent from every clean checkout. That has
 * already happened twice on this branch, to packaging/rpm/ash.spec and
 * packaging/msix/README.msix.
 *
 * STORED by default, so a planted body sits in the archive byte for byte. An
 * entry can ask for DEFLATE instead, which is what `vsce` writes, so the content
 * check is also tested over bodies it has to inflate before it can read them.
 */

import * as zlib from 'zlib';

export interface ZipEntry {
  readonly name: string;
  readonly data?: Buffer | string;
  /** Writes the body DEFLATE-compressed, as `vsce` does, instead of STORED. */
  readonly deflate?: boolean;
  /** Writes this compression method number into both headers, with the body stored as is. */
  readonly rawMethod?: number;
  /**
   * Writes a trailing data descriptor and sets general-purpose bit 3, as `vsce`
   * does: `signed` with the optional PK\x07\x08 signature, `unsigned` without.
   */
  readonly descriptor?: 'signed' | 'unsigned';
  /** Writes these bytes as the descriptor instead of the CRC and sizes it should repeat. */
  readonly descriptorBytes?: Buffer;
}

const LOCAL_SIGNATURE = 0x04034b50;
const CENTRAL_SIGNATURE = 0x02014b50;
const EOCD_SIGNATURE = 0x06054b50;

function bodyOf(entry: ZipEntry): Buffer {
  if (entry.data === undefined) {
    return Buffer.alloc(0);
  }
  return Buffer.isBuffer(entry.data) ? entry.data : Buffer.from(entry.data, 'utf8');
}

export interface WriteOptions {
  /** Writes the Zip64 "look elsewhere" sentinels into the EOCD. */
  readonly zip64Sentinel?: boolean;
  /** Overstates the entry count so the reader walks past the directory's end. */
  readonly extraEntryCount?: number;
  /** Corrupts the signature of the nth central-directory entry (0-based). */
  readonly corruptEntry?: number;
  /** Bytes written before the first local header, with every offset shifted to match. */
  readonly leading?: Buffer;
  /** Bytes written after the first member's record, with every later offset shifted to match. */
  readonly afterFirst?: Buffer;
  /** Bytes written between the last record and the central directory, with the offset shifted. */
  readonly beforeDirectory?: Buffer;
  /** Bytes written inside the central directory after its records, counted in its declared size. */
  readonly insideDirectory?: Buffer;
  /** Bytes written between the central directory and the end record, with neither offset moved. */
  readonly afterDirectory?: Buffer;
  /** The archive comment. */
  readonly comment?: Buffer;
  /** Bytes written after the end record and its comment. */
  readonly trailing?: Buffer;
  /** Points the central record of member n (0-based) at another local-header offset. */
  readonly centralOffsets?: Readonly<Record<number, number>>;
}

/** Builds a ZIP archive whose members are exactly `entries`, in order. */
export function writeZip(entries: readonly ZipEntry[], options: WriteOptions = {}): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  const leading = options.leading ?? Buffer.alloc(0);
  let offset = leading.length;

  entries.forEach((entry, index) => {
    const name = Buffer.from(entry.name, 'utf8');
    const plain = bodyOf(entry);
    const crc = zlib.crc32(plain);
    const body = entry.deflate === true ? zlib.deflateRawSync(plain) : plain;
    const method = entry.rawMethod ?? (entry.deflate === true ? 8 : 0);
    const flags = entry.descriptor === undefined ? 0 : 0x08;

    const local = Buffer.alloc(30 + name.length);
    local.writeUInt32LE(LOCAL_SIGNATURE, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(body.length, 18);
    local.writeUInt32LE(plain.length, 22);
    local.writeUInt16LE(name.length, 26);
    name.copy(local, 30);
    locals.push(local, body);
    let descriptor = Buffer.alloc(0);
    if (entry.descriptor !== undefined) {
      const signed = entry.descriptor === 'signed';
      descriptor = Buffer.alloc(signed ? 16 : 12);
      let at = 0;
      if (signed) {
        descriptor.writeUInt32LE(0x08074b50, 0);
        at = 4;
      }
      descriptor.writeUInt32LE(crc, at);
      descriptor.writeUInt32LE(body.length, at + 4);
      descriptor.writeUInt32LE(plain.length, at + 8);
      if (entry.descriptorBytes !== undefined) {
        descriptor = signed
          ? Buffer.concat([descriptor.subarray(0, 4), entry.descriptorBytes])
          : Buffer.from(entry.descriptorBytes);
      }
      locals.push(descriptor);
    }
    const gap = index === 0 && options.afterFirst !== undefined ? options.afterFirst : Buffer.alloc(0);
    locals.push(gap);

    const central = Buffer.alloc(46 + name.length);
    central.writeUInt32LE(index === options.corruptEntry ? 0xdeadbeef : CENTRAL_SIGNATURE, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(body.length, 20);
    central.writeUInt32LE(plain.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(options.centralOffsets?.[index] ?? offset, 42);
    name.copy(central, 46);
    centrals.push(central);

    offset += local.length + body.length + descriptor.length + gap.length;
  });

  const localBytes = Buffer.concat(locals);
  const beforeDirectory = options.beforeDirectory ?? Buffer.alloc(0);
  const afterDirectory = options.afterDirectory ?? Buffer.alloc(0);
  const centralBytes = Buffer.concat([...centrals, options.insideDirectory ?? Buffer.alloc(0)]);
  const comment = options.comment ?? Buffer.alloc(0);

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(EOCD_SIGNATURE, 0);
  const count = entries.length + (options.extraEntryCount ?? 0);
  eocd.writeUInt16LE(options.zip64Sentinel === true ? 0xffff : count, 8);
  eocd.writeUInt16LE(options.zip64Sentinel === true ? 0xffff : count, 10);
  eocd.writeUInt32LE(centralBytes.length, 12);
  eocd.writeUInt32LE(leading.length + localBytes.length + beforeDirectory.length, 16);
  eocd.writeUInt16LE(comment.length, 20);

  return Buffer.concat([
    leading,
    localBytes,
    beforeDirectory,
    centralBytes,
    afterDirectory,
    eocd,
    comment,
    options.trailing ?? Buffer.alloc(0),
  ]);
}

/**
 * The member list `vsce package` actually produced for this extension, in the
 * order and the spelling the archive carries.
 *
 * Copied from a real build rather than written from the source tree, because
 * `vsce` renames on the way in: `README.md` arrives as `readme.md`,
 * `CHANGELOG.md` as `changelog.md`, and `LICENSE` as `LICENSE.txt`. A baseline
 * assembled from the filenames on disk would have made these tests agree with an
 * allowlist that rejects the real artifact -- which is what happened on the first
 * build, on `extension/changelog.md`.
 *
 * `out/verify-vsix.js` is absent on purpose: `.vscodeignore` excludes it, because
 * the checker has no business inside the archive it checks.
 */
export const CLEAN_VSIX_MEMBERS: readonly ZipEntry[] = [
  { name: 'extension.vsixmanifest', data: '<PackageManifest/>' },
  { name: '[Content_Types].xml', data: '<Types/>' },
  { name: 'extension/package.json', data: '{}' },
  { name: 'extension/readme.md', data: '# ASH for VS Code' },
  { name: 'extension/NOTICE', data: 'Copyright' },
  { name: 'extension/LICENSE.txt', data: 'Apache-2.0' },
  { name: 'extension/changelog.md', data: '# Changelog' },
  { name: 'extension/out/vsix-contents.js', data: 'module.exports = {};' },
  { name: 'extension/out/sarif.js', data: 'module.exports = {};' },
  { name: 'extension/out/extension.js', data: 'module.exports = {};' },
  { name: 'extension/out/diagnostics.js', data: 'module.exports = {};' },
  { name: 'extension/out/ash-cli.js', data: 'module.exports = {};' },
];
