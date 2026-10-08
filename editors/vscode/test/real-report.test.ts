// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Parses and publishes a REAL ASH report, not a fixture written next to the parser.
 *
 * WHY THIS EXISTS
 *
 * Every other SARIF this package tests has one scanner in one run, and that
 * scanner (detect-secrets) is also the only `scanner_name` in it. That is the one
 * shape in which a run-level attribution and a per-result attribution give the
 * same answer, so a regression from reading `properties.scanner_name` per result
 * back to reading `tool.driver.name` per run would pass all of them. The real
 * report has seven scanners in ONE run, and its driver name is ASH itself.
 *
 * The numbers asserted here are the ones the JetBrains plugin pins for the same
 * file (editors/jetbrains/src/test/kotlin/.../AshRealReportTest.kt), so the two
 * IDEs are checked against each other as well as against the report. Measured on
 * the file below:
 *
 *   tool.driver.name  = "AWS Labs - Automated Security Helper"   (ASH, not a scanner)
 *   tool.driver.rules = 0 entries; tool.extensions = 7 scanners
 *   runs = 1, results = 126, 92 of them suppressed
 *   result.properties.scanner_name = the per-result scanner, present on all 126
 *
 * One JetBrains assertion has no VS Code counterpart, on purpose: the 30/4 split
 * of severities inherited from `tool.extensions[].rules` when result levels are
 * stripped. This extension does no rule-metadata lookup, so a result with no
 * level takes SARIF's default of `warning`. That arm is asserted below as what it
 * is, so a later rule lookup has to change this test deliberately.
 *
 * THE FILE IS THE REPOSITORY'S OWN TEST DATA, read in place rather than copied:
 * a 15 MB copy would go stale against the original. A missing file FAILS rather
 * than skipping, because a skipped suite looks like a passing one in a CI summary.
 */

import { existsSync, readFileSync } from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import { DIAGNOSTIC_SOURCE, publishFindings, resolveFindingUri } from '../src/diagnostics';
import { parseAshSarif } from '../src/sarif';
import { repoPath } from './repo-inputs';
import { DiagnosticCollection } from './vscode-stub';

const REPORT = repoPath('tests/test_data/outputs/ash_aggregated_results.json');

const ASH_DRIVER_NAME = 'AWS Labs - Automated Security Helper';

/** A checkout root the report's relative and grype root-absolute paths resolve into. */
const BASE = '/home/u/proj';

/** Everything under BASE exists and nothing else does, so the resolver's choice is deterministic. */
const underBase = (candidate: string): boolean => candidate.startsWith(`${BASE}/`);

type Json = Record<string, unknown>;

/**
 * The TOP-LEVEL `sarif` member, taken by parsing the container and asking for
 * the member by name. A text scan for `"sarif":` matches a reporter-config entry
 * inside `ash_config` first (`{"name": "sarif", ...}`), which has no runs; that
 * mistake once read as three parser defects in the JetBrains suite.
 */
function loadSarif(): Json {
  if (!existsSync(REPORT)) {
    throw new Error(
      `cannot find the real ASH report at ${REPORT}. This suite must not be skipped: it is the ` +
        'only VS Code coverage against SARIF with more than one scanner in a run.',
    );
  }
  const root = JSON.parse(readFileSync(REPORT, 'utf8')) as unknown;
  if (typeof root !== 'object' || root === null || Array.isArray(root)) {
    throw new Error('the report root is not a JSON object');
  }
  const sarif = (root as Json).sarif;
  if (typeof sarif !== 'object' || sarif === null || !Array.isArray((sarif as Json).runs)) {
    throw new Error('the report has no top-level "sarif" member with a "runs" array');
  }
  return sarif as Json;
}

const sarif = loadSarif();
const sarifText = JSON.stringify(sarif);
const parsed = parseAshSarif(sarifText);

function rawResults(doc: Json): Json[] {
  const out: Json[] = [];
  for (const run of doc.runs as Json[]) {
    for (const result of (run.results as Json[] | undefined) ?? []) {
      out.push(result);
    }
  }
  return out;
}

function countBy<T>(items: readonly T[], key: (item: T) => string): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const item of items) {
    const k = key(item);
    counts[k] = (counts[k] ?? 0) + 1;
  }
  return counts;
}

/** The surfaced set, per scanner. Identical to AshRealReportTest.perScannerCountsMatchTheReport. */
const PER_SCANNER = {
  'detect-secrets': 11,
  bandit: 11,
  semgrep: 7,
  checkov: 4,
  grype: 1,
};

describe('the real ASH report', () => {
  it('is the multi-scanner, single-run document the JetBrains suite measures', () => {
    const runs = sarif.runs as Json[];
    expect(runs).toHaveLength(1);
    expect(parsed.toolNames).toEqual([ASH_DRIVER_NAME]);
    expect(rawResults(sarif)).toHaveLength(126);
    // Seven scanners advertised in ONE run. A per-run read can attribute at most one.
    const tool = runs[0].tool as Json;
    expect((tool.extensions as unknown[]).length).toBe(7);
  });

  it('parses without losing results', () => {
    // 34 surfaced, 92 suppressed, 0 non-failures, 0 unlocated: the JetBrains numbers.
    expect(parsed.findings).toHaveLength(34);
    expect(parsed.suppressed).toBe(92);
    expect(parsed.notFailures).toBe(0);
    expect(parsed.unlocated).toHaveLength(0);
    // The closure invariant, against a total counted independently of the parser:
    // every result lands in exactly one bucket. Paired with the pinned counts
    // above, because all-zero buckets would also satisfy it on an empty total.
    const total = rawResults(sarif).length;
    expect(parsed.findings.length + parsed.unlocated.length + parsed.suppressed + parsed.notFailures).toBe(
      total,
    );
  });

  it('does not resurface in-source suppressed failures', () => {
    // 92 suppressed but only 85 are informational/none: 7 are kind=fail with a real
    // level (5 checkov warnings, 2 semgrep errors) and an inSource suppression.
    const raw = rawResults(sarif);
    const suppressedFailures = raw.filter(
      (r) => Array.isArray(r.suppressions) && r.suppressions.length > 0 && r.kind === 'fail',
    );
    expect(suppressedFailures).toHaveLength(7);
    expect(parsed.findings.filter((f) => f.scannerName === 'checkov' && f.level === 'warning')).toHaveLength(0);
    // All 5 warning-level results were the suppressed checkov ones.
    expect(parsed.findings.filter((f) => f.level === 'warning')).toHaveLength(0);
  });

  it('attributes each finding to its own scanner, not to ASH', () => {
    const scanners = new Set(parsed.findings.map((f) => f.scannerName));
    expect([...scanners].sort()).toEqual(['bandit', 'checkov', 'detect-secrets', 'grype', 'semgrep']);
    expect(parsed.findings.some((f) => f.scannerName === undefined)).toBe(false);
    expect(parsed.findings.some((f) => f.scannerName?.includes('Automated Security Helper'))).toBe(false);
  });

  it('matches the per-scanner counts', () => {
    // cdk-nag and cfn-nag are absent: every one of their findings is suppressed, so
    // 5 scanners surface while extensions[] advertises 7.
    expect(countBy(parsed.findings, (f) => f.scannerName ?? '<none>')).toEqual(PER_SCANNER);
  });

  it('keeps the report\'s own severities', () => {
    expect(countBy(parsed.findings, (f) => f.level)).toEqual({ error: 32, note: 2 });
  });

  it('gives a result with no level SARIF\'s default, because it does no rule lookup', () => {
    // Levels stripped structurally from every result. JetBrains resolves these
    // through tool.extensions[].rules and gets warning 30 / error 4; this parser
    // reads no rule metadata, so all 34 take `warning`. The count must not move:
    // stripping a level is not a reason to lose a finding.
    const stripped = JSON.parse(sarifText) as Json;
    for (const result of rawResults(stripped)) {
      delete result.level;
    }
    const reparsed = parseAshSarif(JSON.stringify(stripped));
    expect(reparsed.findings).toHaveLength(34);
    expect(countBy(reparsed.findings, (f) => f.level)).toEqual({ warning: 34 });
  });

  it('gives every finding a usable file and line, in both region shapes', () => {
    for (const f of parsed.findings) {
      expect(f.uri).not.toBe('');
      expect(f.startLine).toBeGreaterThanOrEqual(1);
      expect(f.endLine).toBeGreaterThanOrEqual(f.startLine);
      if (f.startColumn !== undefined) {
        expect(f.startColumn).toBeGreaterThanOrEqual(1);
      }
    }
    // 19 carry explicit end columns and 15 omit them, so both the column path and
    // the whole-line default run on real data.
    expect(parsed.findings.filter((f) => f.endColumn !== undefined)).toHaveLength(19);
    expect(parsed.findings.filter((f) => f.endColumn === undefined)).toHaveLength(15);
  });

  it('keeps every rule id', () => {
    expect(parsed.findings.filter((f) => f.ruleId === '')).toHaveLength(0);
  });
});

describe('the real ASH report, published', () => {
  const collection = new DiagnosticCollection('ash');
  const summary = publishFindings(
    collection as unknown as vscode.DiagnosticCollection,
    BASE,
    parsed,
    underBase,
    'linux',
  );
  const diagnostics = collection
    .uris()
    .flatMap((key) => [...(collection.get(vscode.Uri.parse(key)) ?? [])]);

  it('places all 34 findings and reports the suppressed count', () => {
    expect(summary).toMatchObject({
      diagnostics: 34,
      unlocated: 0,
      unresolved: 0,
      suppressed: 92,
      notFailures: 0,
    });
    expect(collection.totalDiagnostics()).toBe(34);
    expect(diagnostics).toHaveLength(34);
  });

  it('shows each finding\'s own scanner as its diagnostic source', () => {
    // Every diagnostic's source is `ASH (<properties.scanner_name>)`, and the
    // per-source counts are the per-scanner counts. Under a run-level read every
    // source would be `ASH (AWS Labs - Automated Security Helper)`.
    const expected: Record<string, number> = {};
    for (const [scanner, n] of Object.entries(PER_SCANNER)) {
      expected[`${DIAGNOSTIC_SOURCE} (${scanner})`] = n;
    }
    expect(countBy(diagnostics, (d) => d.source ?? '<none>')).toEqual(expected);
  });

  it('lands the grype /poetry.lock finding in the project, not at the filesystem root', () => {
    const poetry = parsed.findings.filter((f) => f.uri === '/poetry.lock');
    expect(poetry).toHaveLength(1);
    expect(poetry[0].scannerName).toBe('grype');
    expect(collection.uris()).toContain(vscode.Uri.file(`${BASE}/poetry.lock`).toString());
    expect(collection.uris()).not.toContain(vscode.Uri.file('/poetry.lock').toString());
  });
});

describe('the real report\'s grype root-absolute paths', () => {
  it('resolve under the project root, as a set', () => {
    // 14 results carry a URI beginning with '/', all grype, and none exists at that
    // absolute location. Taken from the raw results rather than the parsed
    // findings, because 13 of the 14 are informational and never reach the
    // resolver from this report -- a project where grype finds real
    // vulnerabilities would have every one of them in this shape.
    //
    // Compared as a set of resolved paths, not a count: a resolver that returned
    // the literal path would still produce 14 entries.
    const uris: string[] = [];
    for (const r of rawResults(sarif)) {
      const location = (r.locations as Json[] | undefined)?.[0];
      const physical = location?.physicalLocation as Json | undefined;
      const artifact = physical?.artifactLocation as Json | undefined;
      const uri = artifact?.uri;
      if (typeof uri === 'string' && uri.startsWith('/')) {
        uris.push(uri);
        expect(r.properties).toMatchObject({ scanner_name: 'grype' });
      }
    }
    expect(uris).toHaveLength(14);

    const resolved = new Set(uris.map((uri) => resolveFindingUri(BASE, { uri }, underBase, 'linux')?.fsPath));
    const expected = new Set(uris.map((uri) => path.posix.join(BASE, uri)));
    expect(resolved).toEqual(expected);
  });
});
