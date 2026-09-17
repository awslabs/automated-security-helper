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
 * directory as plain bytes, so reading them needs no decompression and no
 * library: this module walks the central directory itself.
 */

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

/**
 * Returns every member name in a ZIP archive, in central-directory order.
 *
 * Throws rather than returning a partial list. A truncated or Zip64 archive that
 * produced a short list would be indistinguishable from a small clean archive,
 * and this function's whole job is to be the census the allowlist is checked
 * against.
 */
export function listZipMembers(buffer: Buffer): string[] {
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

  const members: string[] = [];
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
    members.push(buffer.toString('utf8', nameStart, nameEnd).split('\\').join('/'));
    cursor = nameEnd + extraLength + commentLength;
  }

  return members;
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

  if (verdict.missing.length > 0) {
    lines.push(
      `${verdict.missing.length} required member(s) absent: ${verdict.missing.join(', ')}. ` +
        'An archive missing these would satisfy the allowlist by carrying nothing, which ' +
        'is the vacuous pass this check exists to prevent.',
    );
  }

  return lines.length === 0 ? null : lines.join('\n');
}
