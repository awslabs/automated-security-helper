// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Turns parsed SARIF findings into editor diagnostics.
 *
 * Two conversions live here and nowhere else, so there is one place to look
 * when either is wrong: SARIF level to `DiagnosticSeverity`, and SARIF's
 * 1-based line and column numbers to the editor's 0-based ones.
 */

import * as fs from 'fs';
import * as path from 'path';
import { URL } from 'url';
import * as vscode from 'vscode';

import type { ParsedFinding, SarifLevel } from './sarif';

/**
 * SARIF level to editor severity.
 *
 * Total over SarifLevel by type, not by a `default:` arm -- adding a level to
 * the union fails compilation here instead of falling through to some
 * arbitrary severity at run time. `note` maps to Information and `none` to
 * Hint: `none` means the rule did not fire as a problem, so it must not render
 * as one, and Hint is the only severity the editor draws without a squiggle.
 */
export const LEVEL_TO_SEVERITY: Readonly<
  Record<SarifLevel, vscode.DiagnosticSeverity>
> = {
  error: vscode.DiagnosticSeverity.Error,
  warning: vscode.DiagnosticSeverity.Warning,
  note: vscode.DiagnosticSeverity.Information,
  none: vscode.DiagnosticSeverity.Hint,
};

/**
 * Any URI scheme of two or more characters, anchored at the start.
 *
 * TWO CHARACTERS MINIMUM, AND THAT IS THE WHOLE POINT. RFC 3986 allows a
 * one-character scheme, but a single letter followed by a colon is a Windows
 * drive -- `C:\src\app.py` -- and reading that as a URI scheme would discard
 * every absolute Windows path. Requiring two characters separates `C:` from
 * `data:`, `urn:` and `https:` without a platform check.
 *
 * MATCHED WITHOUT `//`, which an earlier version required. That was a hole:
 * `file:/etc/passwd` (legal per RFC 8089), `data:text/plain,x` and `urn:uuid:1`
 * all have a single slash or none, so they matched neither this guard nor the
 * `file://` test, fell through to `path.resolve`, and became in-workspace
 * phantom paths -- counted as published, because nothing incremented the
 * unresolved tally. Verified for all three.
 *
 * Known and accepted imprecision: a relative path whose first segment ends in a
 * colon, such as `note:2024.txt`, reads as a scheme and is refused. That name is
 * ambiguous to every URI parser, and refusing it loses one diagnostic where
 * guessing risks writing to the wrong file.
 */
const URI_SCHEME = /^[a-z][a-z0-9+.-]+:/i;

/**
 * Resolves a SARIF `artifactLocation.uri` against the scanned root.
 *
 * ASH emits paths relative to the source directory, but SARIF permits an
 * absolute `file:` URI and an absolute path, and a report copied between
 * machines carries whichever the producer used. Those are handled; any other
 * scheme has no file to attach a diagnostic to and returns undefined rather than
 * being forced into a path.
 *
 * `..` is not special-cased away. A report legitimately references a file above
 * the scanned root when the output directory sits inside it, and clamping would
 * silently move the diagnostic to the wrong file. Out-of-workspace URIs simply
 * get diagnostics the user will not normally see, which is the honest outcome.
 */
/**
 * Whether a path exists. Injectable so `resolveAbsolute`'s branches are reachable
 * from a test without creating files.
 *
 * WHY THIS IS A PARAMETER. With `fs.existsSync` hardcoded, every test ran against a
 * root that does not exist, so BOTH existence checks failed and every case returned
 * through the final arm -- the two branches carrying the actual fix were never
 * executed by anything. An oracle makes each arm addressable and the monotonicity
 * property directly testable in both directions.
 */
export type ExistsOracle = (candidate: string) => boolean;

export function resolveFindingUri(
  raw: string,
  rootFsPath: string,
  exists: ExistsOracle = fs.existsSync,
): vscode.Uri | undefined {
  // Every `file:` form, not just `file://`: RFC 8089 permits `file:/path`, and
  // `URL` normalizes all of them to the same host-plus-pathname shape.
  if (/^file:/i.test(raw)) {
    let parsed: URL;
    try {
      parsed = new URL(raw);
    } catch {
      return undefined;
    }

    let pathname: string;
    try {
      pathname = decodeURIComponent(parsed.pathname);
    } catch {
      // Malformed percent-encoding. Refused rather than used raw, because the
      // undecoded form names a different file than the producer meant.
      return undefined;
    }

    // An empty host and `localhost` both mean "this machine" (RFC 8089).
    const host = parsed.hostname;
    if (host === '' || host.toLowerCase() === 'localhost') {
      return vscode.Uri.file(pathname);
    }

    // A REAL HOST IS A UNC PATH, AND ONLY WINDOWS CAN OPEN ONE.
    //
    // This was silently wrong: the host was discarded and only `pathname` used,
    // so `file://server/share/app.py` became the LOCAL absolute path
    // `/share/app.py` -- a different file on this machine, which the docstring's
    // own promise to return undefined rather than force a path was supposed to
    // prevent. Verified.
    //
    // On Windows the URI genuinely resolves, to `\\server\share\app.py`, and
    // `Uri.file` understands that form. Everywhere else there is no local path
    // it can mean, so undefined is the honest answer and the finding is counted
    // as unresolved rather than attached to the wrong file.
    if (process.platform === 'win32') {
      return vscode.Uri.file(`\\\\${host}${pathname.replace(/\//g, '\\')}`);
    }
    return undefined;
  }

  if (URI_SCHEME.test(raw)) {
    return undefined;
  }

  if (path.isAbsolute(raw)) {
    return vscode.Uri.file(resolveAbsolute(raw, rootFsPath, exists));
  }

  return vscode.Uri.file(path.resolve(rootFsPath, raw));
}

/**
 * Chooses between reading an absolute uri literally and reading it as relative to
 * the scanned root.
 *
 * WHY THIS IS NEEDED, measured from a real report rather than imagined. grype
 * emits SCAN-ROOT-ABSOLUTE paths -- `/poetry.lock`,
 * `/.venv/lib/python3.12/site-packages/jupyterlab/staging/yarn.lock` -- because it
 * ran with the source directory as its root, typically inside a container. Taken
 * literally those name files at the filesystem root, which do not exist, so 14 of
 * the 126 findings in tests/test_data/outputs/ash_aggregated_results.json landed
 * on paths nothing could open. They still appeared in the Problems panel, against
 * the wrong file.
 *
 * The rule is existence-checked rather than a blanket reinterpretation, which
 * makes it MONOTONE: a diagnostic can only move from a path that does not exist
 * to one that does, never the reverse. A genuinely absolute path that exists is
 * still used as given, so a report produced without a container is unaffected.
 *
 * When neither location exists the raw path is kept. That preserves the previous
 * behavior for the unknown case and keeps the finding visible -- guessing harder
 * would risk attaching it to an unrelated file, and dropping it would hide a real
 * finding.
 *
 * This is a heuristic, and it is the only one in this file. It is here rather than
 * in sarif.ts because it needs the filesystem, and sarif.ts is deliberately pure.
 */
export function resolveAbsolute(
  raw: string,
  rootFsPath: string,
  exists: ExistsOracle = fs.existsSync,
): string {
  if (exists(raw)) {
    return raw;
  }
  // `path.join`, not `path.resolve`: resolve() would discard rootFsPath entirely
  // on seeing an absolute second argument, which is the bug this is fixing.
  const underRoot = path.join(rootFsPath, raw);
  if (exists(underRoot)) {
    return underRoot;
  }
  return raw;
}

/**
 * The editor range for a finding.
 *
 * SARIF counts lines and columns from 1; `vscode.Position` counts from 0. The
 * subtraction is the whole function, and getting it wrong puts every diagnostic
 * one line off -- which looks plausible enough to ship.
 *
 * When the region gives no end column there is nothing to underline, so the
 * range runs to the end of the line. `Number.MAX_SAFE_INTEGER` is the
 * documented way to say that: the editor clamps a range to the real line length
 * when it resolves it against the document.
 */
export function findingRange(finding: ParsedFinding): vscode.Range {
  const startLine = finding.startLine - 1;
  const startColumn =
    finding.startColumn !== undefined ? finding.startColumn - 1 : 0;

  const endLine =
    finding.endLine !== undefined
      ? Math.max(startLine, finding.endLine - 1)
      : startLine;
  const endColumn =
    finding.endColumn !== undefined
      ? Math.max(0, finding.endColumn - 1)
      : Number.MAX_SAFE_INTEGER;

  return new vscode.Range(startLine, startColumn, endLine, endColumn);
}

function describe(finding: ParsedFinding): string {
  const message = finding.message.length > 0 ? finding.message : finding.ruleId;
  return message.length > 0 ? message : 'ASH reported a finding here.';
}

export function toDiagnostic(finding: ParsedFinding): vscode.Diagnostic {
  const diagnostic = new vscode.Diagnostic(
    findingRange(finding),
    describe(finding),
    LEVEL_TO_SEVERITY[finding.level],
  );
  // `source` is what the editor shows in parentheses after the message, and it
  // is what lets a user tell an ASH squiggle from another linter's.
  //
  // A bare `ASH` when the scanner could not be identified. The alternative --
  // naming the run-level tool -- puts the PRODUCT name where a scanner belongs, e.g.
  // `ASH (AWS Labs - Automated Security Helper)`, which tells the user nothing and
  // is the defect extractScannerName exists to prevent.
  diagnostic.source =
    finding.toolName.length > 0 ? `ASH (${finding.toolName})` : 'ASH';
  if (finding.ruleId.length > 0) {
    diagnostic.code = finding.ruleId;
  }
  return diagnostic;
}

/**
 * Groups findings by file and publishes them.
 *
 * The collection is replaced wholesale rather than added to: a scan's results
 * are the complete current state, so a finding fixed since the last run has to
 * disappear. `collection.clear()` before setting is what makes a re-scan
 * subtractive as well as additive.
 */
export function publishFindings(
  collection: vscode.DiagnosticCollection,
  findings: readonly ParsedFinding[],
  rootFsPath: string,
): { fileCount: number; diagnosticCount: number; unresolved: number } {
  const byFile = new Map<string, { uri: vscode.Uri; items: vscode.Diagnostic[] }>();
  let unresolved = 0;

  for (const finding of findings) {
    const uri = resolveFindingUri(finding.uri, rootFsPath);
    if (uri === undefined) {
      unresolved += 1;
      continue;
    }
    const key = uri.toString();
    const bucket = byFile.get(key) ?? { uri, items: [] };
    bucket.items.push(toDiagnostic(finding));
    byFile.set(key, bucket);
  }

  collection.clear();
  for (const { uri, items } of byFile.values()) {
    collection.set(uri, items);
  }

  return {
    fileCount: byFile.size,
    diagnosticCount: findings.length - unresolved,
    unresolved,
  };
}
