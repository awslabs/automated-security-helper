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

import * as path from 'path';
import * as vscode from 'vscode';
import { AshFinding, ParsedSarif, SarifLevel, groupByUri } from './sarif';

/** The `source` shown beside each diagnostic in the Problems panel. */
export const DIAGNOSTIC_SOURCE = 'ASH';

export interface PublishSummary {
  /** Number of files that received at least one diagnostic. */
  readonly files: number;
  /** Total diagnostics published across all files. */
  readonly diagnostics: number;
  /** Findings that named no file and so could not be placed. */
  readonly unlocated: number;
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

/**
 * Resolves a SARIF `artifactLocation.uri` against the scanned directory.
 *
 * ASH writes paths relative to `--source-dir` -- measured: `planted_secret.py`
 * for a file at the root of the scanned tree. The absolute and `file:` forms are
 * handled anyway because SARIF permits them and a future scanner plugin may
 * produce one; resolving those against the workspace root would build a path
 * like `/workspace//home/user/file.py` that matches no open document, so the
 * diagnostic would vanish rather than error.
 */
export function resolveUri(sourceDir: string, sarifUri: string): vscode.Uri {
  if (sarifUri.startsWith('file:')) {
    return vscode.Uri.parse(sarifUri);
  }
  if (path.isAbsolute(sarifUri)) {
    return vscode.Uri.file(sarifUri);
  }
  return vscode.Uri.file(path.join(sourceDir, sarifUri));
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
): PublishSummary {
  collection.clear();

  let diagnostics = 0;
  const grouped = groupByUri(parsed.findings);
  for (const [sarifUri, findings] of grouped) {
    const uri = resolveUri(sourceDir, sarifUri);
    collection.set(
      uri,
      findings.map((finding) => toDiagnostic(finding)),
    );
    diagnostics += findings.length;
  }

  return { files: grouped.size, diagnostics, unlocated: parsed.unlocated.length };
}
