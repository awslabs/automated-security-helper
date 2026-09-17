// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as path from 'path';
import * as vscode from 'vscode';
import {
  DIAGNOSTIC_SOURCE,
  publishFindings,
  resolveUri,
  toDiagnostic,
  toRange,
} from '../src/diagnostics';
import { AshFinding, ParsedSarif, SarifLevel } from '../src/sarif';
import { DiagnosticCollection } from './vscode-stub';

function finding(overrides: Partial<AshFinding> = {}): AshFinding {
  return {
    ruleId: 'SECRET-AWS-ACCESS-KEY',
    message: 'Secret of type \'AWS Access Key\' detected',
    level: 'error',
    uri: 'planted_secret.py',
    startLine: 2,
    endLine: 2,
    ...overrides,
  };
}

function parsed(findings: AshFinding[], unlocated: AshFinding[] = []): ParsedSarif {
  return { findings, unlocated, toolNames: ['AWS Labs - Automated Security Helper'] };
}

describe('toRange', () => {
  it('converts SARIF\'s 1-based lines to VS Code\'s 0-based rows', () => {
    const range = toRange(finding({ startLine: 2, endLine: 4 }));
    expect(range.start.line).toBe(1);
    expect(range.end.line).toBe(3);
  });

  it('spans the whole line when SARIF gave no columns, which is ASH\'s normal case', () => {
    const range = toRange(finding());
    expect(range.start.character).toBe(0);
    // VS Code clamps a range end past the end of the line to the line's length,
    // so a very large value paints the line. A small literal would paint empty
    // space past the end of a short line instead.
    expect(range.end.character).toBe(Number.MAX_SAFE_INTEGER);
  });

  it('uses the columns when SARIF gave them', () => {
    const range = toRange(finding({ startColumn: 5, endColumn: 12 }));
    expect(range.start.character).toBe(4);
    expect(range.end.character).toBe(11);
  });
});

describe('toDiagnostic', () => {
  const levels: [SarifLevel, vscode.DiagnosticSeverity][] = [
    ['error', vscode.DiagnosticSeverity.Error],
    ['warning', vscode.DiagnosticSeverity.Warning],
    // Information and not Hint: a hint renders as a three-dot underline a
    // reviewer scanning the Problems panel will not notice.
    ['note', vscode.DiagnosticSeverity.Information],
    ['none', vscode.DiagnosticSeverity.Hint],
  ];

  it.each(levels)('maps SARIF level %s to the matching severity', (level, severity) => {
    expect(toDiagnostic(finding({ level })).severity).toBe(severity);
  });

  it('puts the rule id in code and the scanner in source', () => {
    const diagnostic = toDiagnostic(finding({ scannerName: 'detect-secrets' }));
    expect(diagnostic.code).toBe('SECRET-AWS-ACCESS-KEY');
    expect(diagnostic.source).toBe(`${DIAGNOSTIC_SOURCE} (detect-secrets)`);
  });

  it('falls back to the bare source when ASH named no scanner', () => {
    expect(toDiagnostic(finding()).source).toBe(DIAGNOSTIC_SOURCE);
  });

  it('leaves code unset rather than empty when there is no rule id', () => {
    expect(toDiagnostic(finding({ ruleId: '' })).code).toBeUndefined();
  });

  it('shows the rule id when the message is empty, so no diagnostic is blank', () => {
    expect(toDiagnostic(finding({ message: '' })).message).toBe('SECRET-AWS-ACCESS-KEY');
  });
});

describe('resolveUri', () => {
  it('joins a relative SARIF path onto the scanned directory', () => {
    expect(resolveUri('/ws', 'src/a.py').fsPath).toBe(path.join('/ws', 'src/a.py'));
  });

  it('leaves an absolute SARIF path alone', () => {
    // Joining this onto the workspace root would build /ws/opt/x/a.py, which
    // matches no open document -- so the diagnostic would vanish rather than
    // error.
    expect(resolveUri('/ws', '/opt/x/a.py').fsPath).toBe('/opt/x/a.py');
  });

  it('parses a file: URI', () => {
    expect(resolveUri('/ws', 'file:///opt/x/a%20b.py').fsPath).toBe('/opt/x/a b.py');
  });
});

describe('publishFindings', () => {
  it('places every finding and reports the counts', () => {
    const collection = new DiagnosticCollection('ash');
    const summary = publishFindings(
      collection as unknown as vscode.DiagnosticCollection,
      '/ws',
      parsed([
        finding({ uri: 'a.py' }),
        finding({ uri: 'a.py', ruleId: 'SECRET-SECRET-KEYWORD' }),
        finding({ uri: 'b/c.py' }),
      ]),
    );

    expect(summary).toEqual({ files: 2, diagnostics: 3, unlocated: 0 });
    expect(collection.totalDiagnostics()).toBe(3);
    expect(collection.get(vscode.Uri.file(path.join('/ws', 'a.py')))).toHaveLength(2);
    expect(collection.get(vscode.Uri.file(path.join('/ws', 'b/c.py')))).toHaveLength(1);
  });

  it('clears the previous run before publishing', () => {
    const collection = new DiagnosticCollection('ash');
    collection.set(vscode.Uri.file('/ws/gone.py'), [
      new vscode.Diagnostic(new vscode.Range(0, 0, 0, 1), 'fixed already'),
    ]);

    publishFindings(
      collection as unknown as vscode.DiagnosticCollection,
      '/ws',
      parsed([finding({ uri: 'still-there.py' })]),
    );

    expect(collection.uris()).toEqual([vscode.Uri.file(path.join('/ws', 'still-there.py')).toString()]);
  });

  it('reports zero for a clean scan without inventing a file', () => {
    const collection = new DiagnosticCollection('ash');
    const summary = publishFindings(
      collection as unknown as vscode.DiagnosticCollection,
      '/ws',
      parsed([]),
    );

    expect(summary).toEqual({ files: 0, diagnostics: 0, unlocated: 0 });
    expect(collection.uris()).toEqual([]);
  });

  it('counts unlocated findings without placing them anywhere', () => {
    const collection = new DiagnosticCollection('ash');
    const summary = publishFindings(
      collection as unknown as vscode.DiagnosticCollection,
      '/ws',
      parsed([], [finding({ uri: '' })]),
    );

    expect(summary).toEqual({ files: 0, diagnostics: 0, unlocated: 1 });
  });
});
