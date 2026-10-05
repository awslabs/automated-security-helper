// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

import * as path from 'path';
import * as vscode from 'vscode';
import {
  DIAGNOSTIC_SOURCE,
  ExistsOracle,
  fileUriToPath,
  publishFindings,
  resolveFindingUri,
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
  return {
    findings,
    unlocated,
    toolNames: ['AWS Labs - Automated Security Helper'],
    suppressed: 0,
    notFailures: 0,
  };
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

/** No file exists. The default for every case that is not about the heuristic. */
const NOTHING: ExistsOracle = () => false;

function resolve(
  uri: string,
  options: { baseUri?: string; root?: string; exists?: ExistsOracle; platform?: NodeJS.Platform } = {},
): string | undefined {
  return resolveFindingUri(
    options.root ?? '/ws',
    { uri, baseUri: options.baseUri },
    options.exists ?? NOTHING,
    options.platform ?? 'linux',
  )?.fsPath;
}

describe('resolveFindingUri: the shapes ASH writes', () => {
  it('joins a relative SARIF path onto the scanned directory', () => {
    expect(resolve('src/a.py')).toBe('/ws/src/a.py');
  });

  it('keeps a relative path that climbs out of the root rather than clamping it', () => {
    expect(resolve('../sibling/a.py')).toBe('/sibling/a.py');
  });

  it('resolves a uriBaseId the run declares, which is how workspace mode writes paths', () => {
    // rebase_run_for_project: PROJECTROOT -> file:///ws/api/ and a
    // project-relative uri. Joined onto the workspace root instead, this
    // would name /ws/src/app.py, which is a different file.
    expect(resolve('src/app.py', { baseUri: 'file:///ws/api/' })).toBe('/ws/api/src/app.py');
  });

  it('resolves a base that has no trailing separator', () => {
    expect(resolve('src/app.py', { baseUri: 'file:///ws/api' })).toBe('/ws/api/src/app.py');
  });

  it('resolves a relative base against the scanned directory', () => {
    expect(resolve('app.py', { baseUri: 'api/' })).toBe('/ws/api/app.py');
  });

  it('ignores the base when the uri is already absolute', () => {
    expect(resolve('/opt/x/a.py', { baseUri: 'file:///ws/api/', exists: () => true })).toBe(
      '/opt/x/a.py',
    );
  });
});

describe('resolveFindingUri: file: URIs', () => {
  it('reads file:///, file:/ and file://localhost/ as the same local path', () => {
    expect(resolve('file:///opt/x/a.py')).toBe('/opt/x/a.py');
    expect(resolve('file:/opt/x/a.py')).toBe('/opt/x/a.py');
    expect(resolve('file://localhost/opt/x/a.py')).toBe('/opt/x/a.py');
  });

  it('decodes percent-encoding', () => {
    expect(resolve('file:///opt/x/a%20b.py')).toBe('/opt/x/a b.py');
  });

  it('refuses malformed percent-encoding rather than naming a different file', () => {
    expect(resolve('file:///opt/x/a%E0%A4%A.py')).toBeUndefined();
  });

  it('refuses a URI that does not parse', () => {
    expect(fileUriToPath('file://[bad', 'linux')).toBeUndefined();
  });

  it('refuses a UNC host off Windows rather than reading only its pathname', () => {
    // Taking the pathname alone would turn \\server\share\app.py into the local
    // /share/app.py, a different file on this machine.
    expect(resolve('file://server/share/app.py')).toBeUndefined();
  });

  it('opens a UNC host on Windows', () => {
    expect(resolve('file://server/share/app.py', { platform: 'win32' })).toBe(
      '\\\\server\\share\\app.py',
    );
  });

  it('reads a Windows drive URI on Windows, and refuses it elsewhere', () => {
    expect(resolve('file:///C:/repo/app.py', { platform: 'win32' })).toBe('C:\\repo\\app.py');
    expect(resolve('file:///C:/repo/app.py')).toBeUndefined();
  });

  it('normalizes a file: path on Windows', () => {
    expect(resolve('file:///repo/app.py', { platform: 'win32' })).toBe('\\repo\\app.py');
  });
});

describe('resolveFindingUri: Windows paths', () => {
  it('does not read a drive letter as a URI scheme', () => {
    expect(resolve('C:\\repo\\app.py', { platform: 'win32', root: 'C:\\repo' })).toBe(
      'C:\\repo\\app.py',
    );
    expect(resolve('C:/repo/app.py', { platform: 'win32', root: 'C:\\repo' })).toBe(
      'C:\\repo\\app.py',
    );
  });

  it('joins a backslash-relative path onto a Windows root', () => {
    expect(resolve('src\\app.py', { platform: 'win32', root: 'C:\\repo' })).toBe(
      'C:\\repo\\src\\app.py',
    );
  });

  it('opens a UNC path on Windows', () => {
    expect(resolve('\\\\server\\share\\app.py', { platform: 'win32' })).toBe(
      '\\\\server\\share\\app.py',
    );
  });

  it('refuses a Windows path on a POSIX host rather than joining it under the root', () => {
    // path.posix sees `C:\repo\app.py` as a relative filename, and joining it
    // would name /ws/C:\repo\app.py.
    expect(resolve('C:\\repo\\app.py')).toBeUndefined();
    expect(resolve('\\\\server\\share\\app.py')).toBeUndefined();
  });
});

describe('resolveFindingUri: other schemes', () => {
  it('has no file for https:, urn: or data:', () => {
    expect(resolve('https://example.com/a.py')).toBeUndefined();
    expect(resolve('urn:uuid:1234')).toBeUndefined();
    expect(resolve('data:text/plain,x')).toBeUndefined();
  });
});

describe('resolveFindingUri: scan-root-absolute paths', () => {
  it('uses an absolute path that exists as given', () => {
    expect(resolve('/poetry.lock', { exists: (p) => p === '/poetry.lock' })).toBe('/poetry.lock');
  });

  it('reads it under the root when only that location exists, which is grype\'s shape', () => {
    expect(resolve('/poetry.lock', { exists: (p) => p === '/ws/poetry.lock' })).toBe(
      '/ws/poetry.lock',
    );
  });

  it('prefers the literal path when both exist, so the heuristic only ever moves toward a file', () => {
    expect(resolve('/poetry.lock', { exists: () => true })).toBe('/poetry.lock');
  });

  it('keeps the literal path when neither exists, so the finding stays visible', () => {
    expect(resolve('/poetry.lock')).toBe('/poetry.lock');
  });

  it('checks the real filesystem by default', () => {
    expect(resolveFindingUri(__dirname, { uri: '/diagnostics.test.ts' })?.fsPath).toBe(
      path.join(__dirname, 'diagnostics.test.ts'),
    );
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

    expect(summary).toEqual({
      files: 2,
      diagnostics: 3,
      unlocated: 0,
      unresolved: 0,
      suppressed: 0,
      notFailures: 0,
    });
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

    expect(summary).toEqual({
      files: 0,
      diagnostics: 0,
      unlocated: 0,
      unresolved: 0,
      suppressed: 0,
      notFailures: 0,
    });
    expect(collection.uris()).toEqual([]);
  });

  it('counts unlocated findings without placing them anywhere', () => {
    const collection = new DiagnosticCollection('ash');
    const summary = publishFindings(
      collection as unknown as vscode.DiagnosticCollection,
      '/ws',
      parsed([], [finding({ uri: '' })]),
    );

    expect(summary.unlocated).toBe(1);
    expect(summary.diagnostics).toBe(0);
  });

  it('counts a finding with no local file as unresolved and publishes the rest', () => {
    const collection = new DiagnosticCollection('ash');
    const summary = publishFindings(
      collection as unknown as vscode.DiagnosticCollection,
      '/ws',
      parsed([finding({ uri: 'https://example.com/a.py' }), finding({ uri: 'a.py' })]),
      NOTHING,
      'linux',
    );

    expect(summary.unresolved).toBe(1);
    expect(summary.diagnostics).toBe(1);
    expect(collection.totalDiagnostics()).toBe(1);
  });

  it('puts two spellings of one file into one entry rather than replacing the first', () => {
    const collection = new DiagnosticCollection('ash');
    const summary = publishFindings(
      collection as unknown as vscode.DiagnosticCollection,
      '/ws',
      parsed([finding({ uri: 'a.py' }), finding({ uri: 'file:///ws/a.py' })]),
      NOTHING,
      'linux',
    );

    expect(summary).toMatchObject({ files: 1, diagnostics: 2 });
    expect(collection.get(vscode.Uri.file('/ws/a.py'))).toHaveLength(2);
  });

  it('passes the suppressed and non-failure counts through', () => {
    const collection = new DiagnosticCollection('ash');
    const summary = publishFindings(
      collection as unknown as vscode.DiagnosticCollection,
      '/ws',
      { ...parsed([]), suppressed: 4, notFailures: 2 },
    );

    expect(summary).toMatchObject({ suppressed: 4, notFailures: 2, diagnostics: 0 });
  });
});
