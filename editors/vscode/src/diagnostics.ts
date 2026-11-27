// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Turns parsed SARIF findings into VS Code diagnostics and publishes them.
 *
 * WHY THE SUMMARY IS RETURNED RATHER THAN LOGGED
 *
 * `DiagnosticCollection.set` returns nothing, so a caller has no way to tell a
 * publish that placed findings from one that placed none. The counts here are
 * what the command handler asserts on and what the test suite asserts on, and
 * they are the reason "the scan completed" is never mistaken for "the scan found
 * nothing": a zero `diagnostics` count with a non-zero `unlocated` count is a
 * different fact from a clean scan, and both are visible from the return value.
 */

import * as fs from 'fs';
import * as path from 'path';
import { URL } from 'url';
import * as vscode from 'vscode';
import { AshFinding, ParsedSarif, SarifLevel, joinUriReference } from './sarif';

/** The `source` shown beside each diagnostic in the Problems panel. */
export const DIAGNOSTIC_SOURCE = 'ASH';

export interface PublishSummary {
  /** Number of files that received at least one diagnostic. */
  readonly files: number;
  /** Total diagnostics published across all files. */
  readonly diagnostics: number;
  /** Findings that named no file and so could not be placed. */
  readonly unlocated: number;
  /**
   * Findings that named a file this machine has no path for, or one on another
   * host: another URI scheme, a UNC or other remote-host path on any platform, a
   * Windows path off Windows. Counted and surfaced, because they are findings the
   * Problems panel cannot show.
   */
  readonly unresolved: number;
  /** Results ASH suppressed. Never published. */
  readonly suppressed: number;
  /** Results whose `kind` is not `fail`. Never published. */
  readonly notFailures: number;
}

const SEVERITY: Readonly<Record<SarifLevel, vscode.DiagnosticSeverity>> = {
  error: vscode.DiagnosticSeverity.Error,
  warning: vscode.DiagnosticSeverity.Warning,
  // `note` is informational, not a hint: a hint renders as a barely visible
  // three-dot underline that a reviewer scanning the Problems panel will not see.
  note: vscode.DiagnosticSeverity.Information,
  none: vscode.DiagnosticSeverity.Hint,
};

/**
 * The end column to use when SARIF supplied none.
 *
 * ASH's `region` carries `startLine`/`endLine` and no columns, so almost every
 * finding lands here. VS Code clamps a range end past the end of the line to the
 * line's real length, which gives a whole-line squiggle. A small literal such as
 * 200 would instead paint 200 columns of empty space on a short line.
 */
const WHOLE_LINE_END = Number.MAX_SAFE_INTEGER;

export function toRange(finding: AshFinding): vscode.Range {
  // SARIF counts lines and columns from 1; VS Code counts from 0.
  const startLine = finding.startLine - 1;
  const endLine = finding.endLine - 1;
  const startColumn = finding.startColumn === undefined ? 0 : finding.startColumn - 1;
  const endColumn = finding.endColumn === undefined ? WHOLE_LINE_END : finding.endColumn - 1;
  return new vscode.Range(startLine, startColumn, endLine, endColumn);
}

export function toDiagnostic(finding: AshFinding): vscode.Diagnostic {
  const diagnostic = new vscode.Diagnostic(
    toRange(finding),
    finding.message === '' ? finding.ruleId : finding.message,
    SEVERITY[finding.level],
  );
  // Two different scanners can report the same rule id shape, so the scanner
  // name goes in `source` when ASH gave one. Without it the Problems panel says
  // only "ASH" and a user cannot tell a secrets finding from a SAST one.
  diagnostic.source =
    finding.scannerName === undefined
      ? DIAGNOSTIC_SOURCE
      : `${DIAGNOSTIC_SOURCE} (${finding.scannerName})`;
  if (finding.ruleId !== '') {
    diagnostic.code = finding.ruleId;
  }
  return diagnostic;
}

/** Whether a path exists. Injected so every arm of the resolver is reachable from a test. */
export type ExistsOracle = (candidate: string) => boolean;

/** The host platform, injected for the same reason. Only `win32` changes behavior. */
export type Platform = NodeJS.Platform;

/**
 * Any URI scheme of TWO or more characters. RFC 3986 allows one, but a single
 * letter and a colon is a Windows drive (`C:\src\app.py`), and reading that as a
 * scheme would discard every absolute Windows path.
 */
const URI_SCHEME = /^[a-z][a-z0-9+.-]+:/i;

/** `C:\x`, `C:/x`. A drive-letter path, absolute on Windows. */
const WINDOWS_DRIVE_PATH = /^[a-z]:[\\/]/i;

/**
 * Two leading separators of either kind: `\\host\share\x`, `//host/share/x`,
 * `\\host/share`, `/\host\share`, and the `\\?\` and `\\.\` device forms.
 *
 * Windows reads every one of these as a path on another machine, and checking
 * whether such a file exists opens an SMB connection to that host and offers the
 * user's NTLM credentials. The path comes from a report the scanned repository
 * can influence, so it is refused before anything touches the filesystem, on
 * every platform, and the finding is counted as unresolved. POSIX would read
 * `//host/share` as the local `/host/share`, but no scanner ASH runs writes that
 * spelling for a local file, and a rule that differs by platform is a rule that
 * a Windows-only bypass hides in.
 */
const REMOTE_PATH = /^[\\/]{2}/;

function pathFor(platform: Platform): path.PlatformPath {
  return platform === 'win32' ? path.win32 : path.posix;
}

/**
 * Resolves a finding's location to a file, or returns undefined when it names
 * nothing on this machine.
 *
 * The SARIF `artifactLocation.uri` arrives in five shapes, and each is handled
 * rather than forced into a path:
 *
 *   - Relative, the shape ASH writes (measured: `planted_secret.py` for a file
 *     at the root of the scanned tree). Joined onto the scanned directory.
 *   - Relative to a `uriBaseId`. ASH's workspace mode writes `PROJECTROOT` with a
 *     project-relative uri and declares `PROJECTROOT` in the run's
 *     `originalUriBaseIds` as the project's `file://` URI. The parser resolves the
 *     base; an undeclared base id leaves the uri relative to the scanned directory.
 *   - `file:` URIs in every RFC 8089 form (`file:///p`, `file:/p`,
 *     `file://localhost/p`). A Windows drive URI, `file:///C:/x`, becomes `C:/x`.
 *     A real host, or a path that itself names one (`file:////host/share`), is
 *     unresolved: see REMOTE_PATH.
 *   - Absolute paths, POSIX or Windows. A Windows path on a non-Windows host
 *     names no local file and is unresolved rather than joined under the root.
 *     A UNC or other remote-host path is unresolved everywhere and is never
 *     passed to the existence check.
 *   - Any other scheme (`https:`, `urn:`, `data:`) has no file and is unresolved.
 *
 * POSIX absolute paths get one heuristic, with an existence check that makes it
 * monotone. grype writes scan-root-absolute paths such as `/poetry.lock` because
 * it ran with the source directory as its root; read literally those name files
 * at the filesystem root. So when the literal path does not exist and the same
 * path under the scanned directory does, the latter is used. A literal path that
 * exists is always used as given, and when neither exists the literal path is
 * kept so the finding stays visible.
 *
 * `..` is not clamped: a report can legitimately name a file above the scanned
 * root, and clamping would move the diagnostic to the wrong file.
 */
export function resolveFindingUri(
  sourceDir: string,
  finding: Pick<AshFinding, 'uri' | 'baseUri'>,
  exists: ExistsOracle = fs.existsSync,
  platform: Platform = process.platform,
): vscode.Uri | undefined {
  const raw =
    finding.baseUri === undefined || isAbsoluteReference(finding.uri, platform)
      ? finding.uri
      : joinUriReference(finding.baseUri, finding.uri);
  const native = pathFor(platform);

  if (/^file:/i.test(raw)) {
    const fsPath = fileUriToPath(raw, platform);
    return fsPath === undefined ? undefined : vscode.Uri.file(fsPath);
  }
  if (URI_SCHEME.test(raw) || REMOTE_PATH.test(raw)) {
    return undefined;
  }
  if (WINDOWS_DRIVE_PATH.test(raw)) {
    return platform === 'win32' ? vscode.Uri.file(native.normalize(raw)) : undefined;
  }
  if (native.isAbsolute(raw)) {
    return vscode.Uri.file(resolveScanRootAbsolute(sourceDir, raw, exists, native));
  }
  return vscode.Uri.file(native.resolve(sourceDir, raw));
}

/** Whether a uri stands on its own, so a base id must not be prefixed onto it. */
function isAbsoluteReference(uri: string, platform: Platform): boolean {
  return (
    URI_SCHEME.test(uri) ||
    WINDOWS_DRIVE_PATH.test(uri) ||
    REMOTE_PATH.test(uri) ||
    pathFor(platform).isAbsolute(uri)
  );
}

/**
 * The local path a `file:` URI names, or undefined.
 *
 * Malformed URIs and malformed percent-encoding are refused rather than used raw:
 * the undecoded form names a different file than the producer meant.
 */
export function fileUriToPath(raw: string, platform: Platform): string | undefined {
  let parsed: URL;
  let pathname: string;
  try {
    parsed = new URL(raw);
    pathname = decodeURIComponent(parsed.pathname);
  } catch {
    return undefined;
  }
  const host = parsed.hostname;
  if (host !== '' && host.toLowerCase() !== 'localhost') {
    // A real host is a share on another machine (see REMOTE_PATH). Taking only
    // the pathname would name a different file on this one.
    return undefined;
  }
  // `file:////host/share/x` has an empty host and the pathname `//host/share/x`,
  // and percent-encoded or backslash separators decode to the same shape.
  if (REMOTE_PATH.test(pathname)) {
    return undefined;
  }
  // `file:///C:/x` parses to the pathname `/C:/x`. The leading slash is URI
  // syntax, not part of the Windows path.
  if (/^\/[a-z]:\//i.test(pathname)) {
    const drivePath = pathname.slice(1);
    return platform === 'win32' ? path.win32.normalize(drivePath) : undefined;
  }
  // A pathname with one leading separator normalizes to one with one, so this
  // cannot produce a UNC path.
  return platform === 'win32' ? path.win32.normalize(pathname) : pathname;
}

function resolveScanRootAbsolute(
  sourceDir: string,
  raw: string,
  exists: ExistsOracle,
  native: path.PlatformPath,
): string {
  if (exists(raw)) {
    return raw;
  }
  // `join`, not `resolve`: resolve discards the first argument when the second is
  // absolute, which is the misreading this exists to correct.
  const underRoot = native.join(sourceDir, raw);
  return exists(underRoot) ? underRoot : raw;
}

/**
 * Replaces the collection's contents with the findings from one scan.
 *
 * `clear()` first, deliberately: a scan whose findings are a subset of the
 * previous run's must remove the ones that are gone. Setting without clearing
 * would leave a fixed finding on screen forever.
 */
export function publishFindings(
  collection: vscode.DiagnosticCollection,
  sourceDir: string,
  parsed: ParsedSarif,
  exists: ExistsOracle = fs.existsSync,
  platform: Platform = process.platform,
): PublishSummary {
  collection.clear();

  // Keyed on the resolved URI's string form: two SARIF spellings of one file
  // (`a.py` and `file:///ws/a.py`) must land in one entry, because `set` on the
  // same key a second time would replace the first group rather than add to it.
  const byFile = new Map<string, { uri: vscode.Uri; items: vscode.Diagnostic[] }>();
  let unresolved = 0;
  for (const finding of parsed.findings) {
    const uri = resolveFindingUri(sourceDir, finding, exists, platform);
    if (uri === undefined) {
      unresolved += 1;
      continue;
    }
    const key = uri.toString();
    const bucket = byFile.get(key) ?? { uri, items: [] };
    bucket.items.push(toDiagnostic(finding));
    byFile.set(key, bucket);
  }

  let diagnostics = 0;
  for (const { uri, items } of byFile.values()) {
    collection.set(uri, items);
    diagnostics += items.length;
  }

  return {
    files: byFile.size,
    diagnostics,
    unlocated: parsed.unlocated.length,
    unresolved,
    suppressed: parsed.suppressed,
    notFailures: parsed.notFailures,
  };
}
