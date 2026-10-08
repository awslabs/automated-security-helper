// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Reads a built `.vsix` and asserts it carries nothing but this extension's own
 * output.
 *
 * WHY A CHECK OVER THE ARCHIVE AND NOT OVER package.json
 *
 * `vsce package` bundles the `dependencies` tree from `node_modules` into the
 * `.vsix` by default. This extension is published as a GitHub Release asset, and
 * packaging/README.md draws the line the release has to stay on: ASH's own code
 * may ship in a published artifact, third-party code never may. A `.vsix`
 * carrying npm packages would put someone else's code inside something we
 * publish.
 *
 * Reading `dependencies` from package.json would answer a different question --
 * what we intended -- and would miss every other way bytes get in: a stray
 * `node_modules` that `.vscodeignore` stopped covering after a rename, a
 * committed vendored file, a bundler output that pulled a dependency inline. The
 * archive is the artifact, so the archive is what gets opened.
 *
 * WHY THE RULE IS AN ALLOWLIST AND NOT A DENYLIST
 *
 * The same reason packaging/README.md gives for "exactly one bundled wheel"
 * rather than "no third-party wheels": a denylist needs a judgment call per
 * dependency, and it is enforced by whoever reviewed the build script that day.
 * An allowlist over member paths is mechanical -- every member either matches a
 * pattern derived from this package's own build output or it does not -- so
 * adding a dependency cannot pass by looking harmless.
 *
 * WHY THERE IS A REQUIRED-PRESENT CHECK ALONGSIDE THE ALLOWLIST
 *
 * A subset test passes vacuously on an empty set. A truncated archive, or one
 * built before `tsc` ran, satisfies "every member is allowed" by having no
 * members to disallow. This repository has shipped that shape before -- a jest
 * run reporting "0 total" and reading as a pass -- so the check also names the
 * members that must be there.
 *
 * NO ZIP LIBRARY IS USED, AND THAT IS THE POINT
 *
 * Adding a dependency to the checker that exists to keep dependencies out would
 * be its own answer to the question. Member names live in the ZIP central
 * directory as plain bytes, so reading them needs no library: this module walks
 * the central directory itself. Member bodies are DEFLATE streams, and Node's
 * built-in `zlib` inflates them, so the content check below adds no dependency
 * either.
 *
 * WHY THE NAMES ARE NOT ENOUGH, AND THE CONTENT IS READ TOO
 *
 * A name allowlist says what a member is called, not what it is. A tarball of
 * scanner binaries renamed `extension/out/x.js` matches OWN_OUTPUT, and so does
 * an ELF executable; both pass a check that only reads names, and both would
 * ship in a release asset. So every member's body is inflated and held to two
 * rules. The first is shared with .github/scripts/assert-artifact-contents.py,
 * the gate on the wheel and sdist: no archive or executable header in the first
 * MAGIC_READ_BYTES bytes, and no member over MAX_MEMBER_BYTES. The second is
 * positive and specific to this artifact: compiled output and the metadata files
 * must be UTF-8 text with no NUL byte, package.json must parse as a JSON object,
 * and the two container XML files must start with `<`. The denylist half catches
 * the formats it knows; the text half catches the ones it does not, because no
 * binary payload is valid NUL-free UTF-8 by accident.
 */

import * as zlib from 'zlib';

/** Archive-root members the VSIX container format itself requires. */
const CONTAINER_MEMBERS: readonly string[] = ['extension.vsixmanifest', '[Content_Types].xml'];

/**
 * Members under `extension/` that are this package's own non-compiled files, in
 * lowercase.
 *
 * WHY LOWERCASE, WHICH IS A MEASUREMENT AND NOT A PRECAUTION
 *
 * `vsce` renames some of these on the way in. Measured on the archive this package
 * actually builds, from `README.md`, `CHANGELOG.md`, `LICENSE` and `NOTICE` on
 * disk:
 *
 *     extension/package.json
 *     extension/readme.md        <- README.md, lowercased
 *     extension/changelog.md     <- CHANGELOG.md, lowercased
 *     extension/LICENSE.txt      <- LICENSE, case kept, .txt appended
 *     extension/NOTICE           <- unchanged
 *
 * A case-sensitive list built from the filenames on disk therefore rejects the
 * real archive, and the first build of this extension did exactly that: it failed
 * on `extension/changelog.md`. Comparing case-folded is what makes the rule
 * describe the artifact rather than the source directory.
 *
 * Both the bare and the `.txt`/`.md` spellings of the license and notice are
 * listed, because which one `vsce` writes depends on the extension of the file it
 * found and a rename should not fail the gate.
 */
const OWN_FILES: readonly string[] = [
  'extension/package.json',
  'extension/readme.md',
  'extension/changelog.md',
  'extension/license',
  'extension/license.txt',
  'extension/license.md',
  'extension/notice',
  'extension/notice.txt',
  'extension/notice.md',
];

/**
 * Compiled output of this package's own `src/`, as `tsc` emits it into `out/`.
 *
 * Case-sensitive, unlike OWN_FILES: `vsce` renames only the top-level metadata
 * files it recognises and copies everything else verbatim, so a member under
 * `out/` carries the name `tsc` gave it.
 */
const OWN_OUTPUT = /^extension\/out\/(?:[^/]+\/)*[^/]+\.js$/;

/**
 * Members that must be present.
 *
 * `out/extension.js` is the one the manifest's `main` points at, so an archive
 * without it installs and then activates nothing.
 */
const REQUIRED_MEMBERS: readonly string[] = ['extension/package.json', 'extension/out/extension.js'];

const EOCD_SIGNATURE = 0x06054b50;
const CENTRAL_HEADER_SIGNATURE = 0x02014b50;
/** A ZIP comment is a uint16 length, so the EOCD starts at most this far back. */
const MAX_COMMENT = 0xffff;
const EOCD_MIN_SIZE = 22;
const CENTRAL_HEADER_MIN_SIZE = 46;

/** One central-directory record: where a member's bytes are and how they are stored. */
export interface ZipDirectoryEntry {
  readonly name: string;
  /** 0 is STORED, 8 is DEFLATE. Anything else is refused when the body is read. */
  readonly method: number;
  readonly compressedSize: number;
  readonly uncompressedSize: number;
  readonly localHeaderOffset: number;
}

/**
 * Returns every member name in a ZIP archive, in central-directory order.
 *
 * Throws rather than returning a partial list. A truncated or Zip64 archive that
 * produced a short list would be indistinguishable from a small clean archive,
 * and this function's whole job is to be the census the allowlist is checked
 * against.
 */
export function listZipMembers(buffer: Buffer): string[] {
  return readZipDirectory(buffer).map((entry) => entry.name);
}

/** The central directory of a ZIP archive, in order. Throws on the same shapes listZipMembers does. */
export function readZipDirectory(buffer: Buffer): ZipDirectoryEntry[] {
  if (buffer.length < EOCD_MIN_SIZE) {
    throw new Error(`not a ZIP archive: ${buffer.length} bytes is shorter than an end-of-central-directory record`);
  }

  const searchFrom = Math.max(0, buffer.length - (MAX_COMMENT + EOCD_MIN_SIZE));
  let eocd = -1;
  // Scan backwards: the EOCD is at the end, and its signature can also appear
  // inside compressed data, so the LAST match is the right one.
  for (let i = buffer.length - EOCD_MIN_SIZE; i >= searchFrom; i -= 1) {
    if (buffer.readUInt32LE(i) === EOCD_SIGNATURE) {
      eocd = i;
      break;
    }
  }
  if (eocd === -1) {
    throw new Error('not a ZIP archive: no end-of-central-directory signature found');
  }

  const entryCount = buffer.readUInt16LE(eocd + 10);
  const directorySize = buffer.readUInt32LE(eocd + 12);
  const directoryOffset = buffer.readUInt32LE(eocd + 16);

  if (entryCount === 0xffff || directorySize === 0xffffffff || directoryOffset === 0xffffffff) {
    // These are Zip64's "look in the Zip64 record" sentinels. Parsing them as
    // real values yields a nonsense offset and a short member list, which would
    // read as a clean archive.
    throw new Error('Zip64 archive: this reader does not support it, so the member list cannot be trusted');
  }
  if (directoryOffset + directorySize > buffer.length) {
    throw new Error(
      `truncated ZIP archive: the central directory claims to end at byte ` +
        `${directoryOffset + directorySize} of a ${buffer.length}-byte file`,
    );
  }

  const members: ZipDirectoryEntry[] = [];
  let cursor = directoryOffset;
  for (let i = 0; i < entryCount; i += 1) {
    if (cursor + CENTRAL_HEADER_MIN_SIZE > buffer.length) {
      throw new Error(`truncated ZIP central directory: entry ${i + 1} of ${entryCount} runs past the end of the file`);
    }
    if (buffer.readUInt32LE(cursor) !== CENTRAL_HEADER_SIGNATURE) {
      throw new Error(`corrupt ZIP central directory: entry ${i + 1} of ${entryCount} has no central-header signature`);
    }
    const nameLength = buffer.readUInt16LE(cursor + 28);
    const extraLength = buffer.readUInt16LE(cursor + 30);
    const commentLength = buffer.readUInt16LE(cursor + 32);
    const nameStart = cursor + CENTRAL_HEADER_MIN_SIZE;
    const nameEnd = nameStart + nameLength;
    if (nameEnd > buffer.length) {
      throw new Error(`truncated ZIP central directory: the name of entry ${i + 1} runs past the end of the file`);
    }
    // ZIP stores names with forward slashes. Normalising backslashes anyway
    // because a Windows-built archive that used them would otherwise turn
    // `extension\out\extension.js` into an unrecognised member and fail for the
    // wrong reason.
    members.push({
      name: buffer.toString('utf8', nameStart, nameEnd).split('\\').join('/'),
      method: buffer.readUInt16LE(cursor + 10),
      compressedSize: buffer.readUInt32LE(cursor + 20),
      uncompressedSize: buffer.readUInt32LE(cursor + 24),
      localHeaderOffset: buffer.readUInt32LE(cursor + 42),
    });
    cursor = nameEnd + extraLength + commentLength;
  }

  return members;
}

// ---------------------------------------------------------------------------
// Content shape.
// ---------------------------------------------------------------------------

/**
 * How many bytes of each member are sniffed for a header. 512, the same as
 * MAGIC_READ_BYTES in .github/scripts/assert-artifact-contents.py, because a
 * tar's `ustar` identifier sits at offset 257 and one tar header block is 512
 * bytes. An 8-byte sniff reads a renamed tarball as the ASCII file name its
 * first header starts with, which was a live bypass in that gate.
 */
export const MAGIC_READ_BYTES = 512;

/**
 * Per-member size ceiling, the same value as MAX_MEMBER_BYTES in the shared
 * gate. The largest member of a real build is under 30 KB, so this is a tripwire
 * for bulk payload, two orders of magnitude clear of anything legitimate.
 */
export const MAX_MEMBER_BYTES = 4 * 1024 * 1024;

export interface Magic {
  readonly offset: number;
  readonly bytes: Buffer;
  readonly label: string;
}

function magic(offset: number, bytes: number[] | string, label: string): Magic {
  return { offset, bytes: typeof bytes === 'string' ? Buffer.from(bytes, 'latin1') : Buffer.from(bytes), label };
}

/**
 * Archive headers. Mirrors ARCHIVE_MAGICS in the shared gate entry for entry,
 * and test/vsix-contents.test.ts reads that file's table through python3 and
 * fails if the two differ, so a header added there cannot be missing here.
 */
export const ARCHIVE_MAGICS: readonly Magic[] = [
  magic(0, 'PK\x03\x04', 'ZIP'),
  magic(0, 'PK\x05\x06', 'ZIP (empty)'),
  magic(0, 'PK\x07\x08', 'ZIP (spanned)'),
  magic(0, [0x1f, 0x8b], 'gzip'),
  ...[1, 2, 3, 4, 5, 6, 7, 8, 9].map((level) => magic(0, `BZh${level}`, 'bzip2')),
  magic(0, [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00], 'xz'),
  magic(0, [0x28, 0xb5, 0x2f, 0xfd], 'zstd'),
  magic(0, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], '7-Zip'),
  magic(0, 'Rar!\x1a\x07', 'RAR'),
  magic(0, [0x04, 0x22, 0x4d, 0x18], 'LZ4'),
  magic(0, '!<arch>', 'ar'),
  magic(0, 'MSCF', 'Microsoft cabinet'),
  magic(0, [0xed, 0xab, 0xee, 0xdb], 'RPM'),
  magic(257, 'ustar', 'tar'),
];

/** Executable headers. Mirrors NATIVE_MAGICS in the shared gate, held to it the same way. */
export const NATIVE_MAGICS: readonly Magic[] = [
  magic(0, [0x7f, 0x45, 0x4c, 0x46], 'ELF'),
  magic(0, [0xfe, 0xed, 0xfa, 0xce], 'Mach-O'),
  magic(0, [0xfe, 0xed, 0xfa, 0xcf], 'Mach-O'),
  magic(0, [0xce, 0xfa, 0xed, 0xfe], 'Mach-O'),
  magic(0, [0xcf, 0xfa, 0xed, 0xfe], 'Mach-O'),
  magic(0, [0xca, 0xfe, 0xba, 0xbe], 'Mach-O universal'),
  magic(0, 'MZ', 'PE'),
];

/** The two leading signatures a ZIP artifact may start with, as ZIP_LEADING_MAGICS in the shared gate. */
const ZIP_LEADING_MAGICS: readonly Buffer[] = [Buffer.from('PK\x03\x04', 'latin1'), Buffer.from('PK\x05\x06', 'latin1')];

const LOCAL_HEADER_SIGNATURE = 0x04034b50;
const LOCAL_HEADER_MIN_SIZE = 30;
const METHOD_STORED = 0;
const METHOD_DEFLATE = 8;

/**
 * Returns a member's uncompressed body.
 *
 * Sizes come from the central directory, not the local header: `vsce` writes
 * its entries with a trailing data descriptor (general-purpose bit 3, measured
 * on a real build), which leaves the local header's size fields zero.
 *
 * Throws when the body cannot be read faithfully, for the reason listZipMembers
 * does: a member whose bytes were skipped is a member nobody inspected.
 */
export function readEntryData(buffer: Buffer, entry: ZipDirectoryEntry): Buffer {
  const header = entry.localHeaderOffset;
  if (header + LOCAL_HEADER_MIN_SIZE > buffer.length || buffer.readUInt32LE(header) !== LOCAL_HEADER_SIGNATURE) {
    throw new Error(`${entry.name}: no local file header at byte ${header}`);
  }
  const start = header + LOCAL_HEADER_MIN_SIZE + buffer.readUInt16LE(header + 26) + buffer.readUInt16LE(header + 28);
  const end = start + entry.compressedSize;
  if (end > buffer.length) {
    throw new Error(`${entry.name}: its data runs past the end of the file`);
  }
  if (entry.uncompressedSize > MAX_MEMBER_BYTES) {
    // Not inflated at all. The size verdict is reported by the caller from the
    // declared size, and inflating first would be the bulk read the ceiling
    // exists to refuse.
    return Buffer.alloc(0);
  }
  const raw = buffer.subarray(start, end);
  let body: Buffer;
  if (entry.method === METHOD_STORED) {
    body = raw;
  } else if (entry.method === METHOD_DEFLATE) {
    // Bounded, so a header that understates the size cannot turn this into a
    // decompression bomb. One byte over the ceiling is enough to notice a lie.
    try {
      body = zlib.inflateRawSync(raw, { maxOutputLength: MAX_MEMBER_BYTES + 1 });
    } catch (inflateError) {
      throw new Error(`${entry.name}: its DEFLATE stream does not inflate: ${(inflateError as Error).message}`);
    }
  } else {
    throw new Error(`${entry.name}: compression method ${entry.method} is not STORED or DEFLATE, so its body cannot be inspected`);
  }
  if (body.length !== entry.uncompressedSize) {
    throw new Error(
      `${entry.name}: inflates to ${body.length} bytes but the central directory declares ${entry.uncompressedSize}`,
    );
  }
  return body;
}

function matchesAt(data: Buffer, candidate: Magic): boolean {
  const end = candidate.offset + candidate.bytes.length;
  return end <= data.length && data.subarray(candidate.offset, end).equals(candidate.bytes);
}

const STRICT_UTF8 = new TextDecoder('utf-8', { fatal: true });

function textProblem(data: Buffer): string | null {
  if (data.includes(0)) {
    return `carries a NUL byte at offset ${data.indexOf(0)}, so it is not text`;
  }
  try {
    STRICT_UTF8.decode(data);
  } catch {
    return 'is not valid UTF-8, so it is not text';
  }
  return null;
}

/** What a member's body must look like, by the role its name gives it. */
type Role = 'text' | 'json-object' | 'xml' | 'none';

function roleOf(name: string): Role {
  if (name === 'extension/package.json') {
    return 'json-object';
  }
  if (CONTAINER_MEMBERS.includes(name)) {
    return 'xml';
  }
  if (OWN_OUTPUT.test(name) || OWN_FILES.includes(name.toLowerCase())) {
    return 'text';
  }
  return 'none';
}

/**
 * Returns why a member's body does not match what its name claims, or null.
 *
 * Exported so the rules can be tested over a body without building an archive.
 */
export function shapeProblem(name: string, declaredSize: number, data: Buffer): string | null {
  if (name.endsWith('/')) {
    // A directory entry is allowed by name because it carries no bytes. One that
    // does carry bytes is a payload with a name chosen to skip the allowlist.
    return declaredSize === 0 ? null : `is a directory entry that carries ${declaredSize} byte(s)`;
  }
  if (declaredSize > MAX_MEMBER_BYTES) {
    return `is ${declaredSize} bytes, over the ${MAX_MEMBER_BYTES}-byte per-member ceiling`;
  }
  const head = data.subarray(0, MAGIC_READ_BYTES);
  for (const candidate of ARCHIVE_MAGICS) {
    if (matchesAt(head, candidate)) {
      return `carries a ${candidate.label} archive header at byte ${candidate.offset}`;
    }
  }
  for (const candidate of NATIVE_MAGICS) {
    if (matchesAt(head, candidate)) {
      return `carries a ${candidate.label} executable header`;
    }
  }
  const role = roleOf(name);
  if (role === 'none') {
    // Already foreign by name; the name verdict reports it.
    return null;
  }
  const notText = textProblem(data);
  if (notText !== null) {
    return notText;
  }
  const text = data.toString('utf8').replace(/^\uFEFF/, '');
  if (role === 'json-object') {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return 'does not parse as JSON';
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return 'parses as JSON but not as an object, so it is not an extension manifest';
    }
  }
  if (role === 'xml' && !text.trimStart().startsWith('<')) {
    return 'does not start with `<`, so it is not XML';
  }
  return null;
}

export interface ShapeProblem {
  readonly member: string;
  readonly reason: string;
}

/**
 * Inspects a whole `.vsix`: the member names, as inspectMembers does, and every
 * member's body. This is what verify-vsix runs.
 */
export function inspectArchive(buffer: Buffer): ContentsVerdict {
  const misshapen: ShapeProblem[] = [];
  if (!ZIP_LEADING_MAGICS.some((leading) => buffer.subarray(0, leading.length).equals(leading))) {
    // A ZIP reader finds the directory from the END of the file, so a ZIP
    // appended to an executable still lists cleanly. Requiring the archive to
    // begin with a ZIP record is what refuses that.
    misshapen.push({ member: '(archive)', reason: 'does not begin with a ZIP record, so something precedes the archive' });
  }
  const entries = readZipDirectory(buffer);
  for (const entry of entries) {
    const reason = shapeProblem(entry.name, entry.uncompressedSize, readEntryData(buffer, entry));
    if (reason !== null) {
      misshapen.push({ member: entry.name, reason });
    }
  }
  return { ...inspectMembers(entries.map((entry) => entry.name)), misshapen };
}

export interface ContentsVerdict {
  readonly memberCount: number;
  /** Members that match no allowlist pattern, in archive order. */
  readonly foreign: readonly string[];
  /** Allowlist members that had to be present and were not. */
  readonly missing: readonly string[];
  /**
   * Foreign members that sit under `extension/node_modules/`, reported
   * separately because that is the specific failure the boundary exists to stop
   * and it deserves its own sentence in the error.
   */
  readonly bundledModules: readonly string[];
  /**
   * Members whose bodies do not match what their names claim. Empty from
   * inspectMembers, which reads names only; inspectArchive fills it.
   */
  readonly misshapen: readonly ShapeProblem[];
}

function isAllowed(member: string): boolean {
  // Directory entries. `vsce` does not write them, but a `zip` invocation would,
  // and a trailing-slash entry carries no bytes so it cannot smuggle anything.
  if (member.endsWith('/')) {
    return true;
  }
  return (
    CONTAINER_MEMBERS.includes(member) ||
    OWN_FILES.includes(member.toLowerCase()) ||
    OWN_OUTPUT.test(member)
  );
}

export function inspectMembers(members: readonly string[]): ContentsVerdict {
  const foreign = members.filter((member) => !isAllowed(member));
  return {
    memberCount: members.length,
    foreign,
    missing: REQUIRED_MEMBERS.filter((required) => !members.includes(required)),
    bundledModules: foreign.filter((member) => member.startsWith('extension/node_modules/')),
    misshapen: [],
  };
}

/** Formats a verdict for a person, or returns null when there is nothing wrong. */
export function describeProblems(verdict: ContentsVerdict): string | null {
  const lines: string[] = [];

  if (verdict.bundledModules.length > 0) {
    lines.push(
      `${verdict.bundledModules.length} member(s) under extension/node_modules/. ` +
        'That is third-party npm code inside an artifact this project publishes as a ' +
        'release asset, which packaging/README.md rules out. Move the package to ' +
        'devDependencies, or exclude it in .vscodeignore.',
    );
    for (const member of verdict.bundledModules.slice(0, 5)) {
      lines.push(`  ${member}`);
    }
  }

  const otherForeign = verdict.foreign.filter((member) => !verdict.bundledModules.includes(member));
  if (otherForeign.length > 0) {
    lines.push(
      `${otherForeign.length} member(s) match no allowlist pattern. Every member must be ` +
        'a VSIX container file, one of this package\'s own top-level files, or compiled ' +
        'output under extension/out/.',
    );
    for (const member of otherForeign.slice(0, 10)) {
      lines.push(`  ${member}`);
    }
  }

  if (verdict.misshapen.length > 0) {
    lines.push(
      `${verdict.misshapen.length} member(s) whose content does not match their name. A name ` +
        'allowlist says what a member is called, not what it is, so a renamed archive or ' +
        'executable is refused here.',
    );
    for (const problem of verdict.misshapen.slice(0, 10)) {
      lines.push(`  ${problem.member} ${problem.reason}`);
    }
  }

  if (verdict.missing.length > 0) {
    lines.push(
      `${verdict.missing.length} required member(s) absent: ${verdict.missing.join(', ')}. ` +
        'An archive missing these would satisfy the allowlist by carrying nothing, which ' +
        'is the vacuous pass this check exists to prevent.',
    );
  }

  return lines.length === 0 ? null : lines.join('\n');
}
