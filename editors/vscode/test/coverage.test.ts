// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * The coverage verdict, against the cases ASH's own assess_coverage was run on.
 *
 * test/fixtures/coverage-cases/cases.json is shared with
 * tests/unit/test_vscode_coverage_parity.py, which asserts ASH reaches each
 * recorded verdict. This file asserts src/coverage.ts reaches the same one, so the
 * two readers of the rule cannot drift apart without one suite failing.
 */

import { readFileSync } from 'fs';
import * as path from 'path';
import {
  CoverageAssessment,
  assessCoverage,
  assessCoverageText,
  describeGaps,
} from '../src/coverage';

const FIXTURES = path.join(__dirname, 'fixtures');

interface Case {
  readonly name: string;
  readonly base: string;
  readonly set: readonly [readonly (string | number)[], unknown][];
  readonly expect: Record<string, unknown>;
}

const CASES: readonly Case[] = (
  JSON.parse(readFileSync(path.join(FIXTURES, 'coverage-cases', 'cases.json'), 'utf8')) as {
    cases: Case[];
  }
).cases;

function applyEdits(document: unknown, edits: Case['set']): unknown {
  const edited = JSON.parse(JSON.stringify(document)) as Record<string | number, unknown>;
  for (const [keys, value] of edits) {
    let target = edited;
    for (const key of keys.slice(0, -1)) {
      target = target[key] as Record<string | number, unknown>;
    }
    target[keys[keys.length - 1]] = JSON.parse(JSON.stringify(value)) as unknown;
  }
  return edited;
}

function namesOnly(assessment: CoverageAssessment): Record<string, unknown> {
  return {
    coverage_complete: assessment.coverage_complete,
    incomplete_scanners: assessment.incomplete_scanners.map((row) => row.scanner),
    no_scanner_ran: assessment.no_scanner_ran,
    incomplete_converters: assessment.incomplete_converters.map((row) => row.converter),
    unevaluated_rules: assessment.unevaluated_rules,
    stale_content_databases: assessment.stale_content_databases,
  };
}

function base(name: string): Record<string, unknown> {
  return JSON.parse(
    readFileSync(path.join(FIXTURES, 'scans', name, 'ash_aggregated_results.json'), 'utf8'),
  ) as Record<string, unknown>;
}

describe('the cases ASH was run on', () => {
  it('are not an empty list, which would make the table below vacuous', () => {
    expect(CASES.length).toBeGreaterThanOrEqual(10);
    // Both verdicts are represented, so a reader that always answered one way fails.
    expect(CASES.some((c) => c.expect.coverage_complete === true)).toBe(true);
    expect(CASES.some((c) => c.expect.coverage_complete === false)).toBe(true);
  });

  it.each(CASES.map((c) => [c.name, c] as const))('%s', (_name, c) => {
    const document = applyEdits(
      JSON.parse(readFileSync(path.join(FIXTURES, c.base), 'utf8')),
      c.set,
    );

    const assessment = assessCoverage(document);

    expect(assessment).toBeDefined();
    expect(namesOnly(assessment as CoverageAssessment)).toEqual(c.expect);
  });
});

describe('details the shared cases do not pin', () => {
  it('names the reason and status for an ERROR and a MISSING scanner', () => {
    expect(assessCoverage(base('incomplete'))?.incomplete_scanners).toEqual([
      { scanner: 'semgrep', status: 'ERROR', reason: 'error', detail: 'ERROR' },
    ]);
    expect(assessCoverage(base('missing'))?.incomplete_scanners).toEqual([
      { scanner: 'cfn-nag', status: 'MISSING', reason: 'missing_dependencies', detail: 'MISSING' },
    ]);
  });

  it('reports the counts for a partial loss and the bare status for a total one', () => {
    const partial = base('findings');
    const reports = partial.additional_reports as Record<string, Record<string, Record<string, unknown>>>;
    reports['detect-secrets'].source.targets_attempted = 4;
    reports['detect-secrets'].source.targets_failed = 1;
    expect(assessCoverage(partial)?.incomplete_scanners[0]).toMatchObject({
      reason: 'partial_coverage',
      detail: 'FAILED (1 of 4 targets unevaluated)',
    });

    const total = base('incomplete');
    const totalReports = total.additional_reports as Record<string, Record<string, Record<string, unknown>>>;
    totalReports.semgrep.source.targets_attempted = 2;
    totalReports.semgrep.source.targets_failed = 2;
    expect(assessCoverage(total)?.incomplete_scanners[0].detail).toBe('ERROR');
  });

  it('does not read a JSON boolean as a target count', () => {
    const document = base('findings');
    const reports = document.additional_reports as Record<string, Record<string, Record<string, unknown>>>;
    reports['detect-secrets'].source.targets_attempted = true;
    reports['detect-secrets'].source.targets_failed = true;
    expect(assessCoverage(document)?.coverage_complete).toBe(true);
  });

  it('reports a status it cannot read as unrecognized rather than as passing', () => {
    const document = base('clean');
    (document.scanner_results as Record<string, Record<string, unknown>>)['detect-secrets'].status =
      undefined;
    expect(assessCoverage(document)?.incomplete_scanners).toEqual([
      {
        scanner: 'detect-secrets',
        status: 'UNREADABLE',
        reason: 'unrecognized_status',
        detail: 'UNREADABLE',
      },
    ]);
  });

  it('counts a failure recorded as any value but a string or null, which ASH would reject', () => {
    const document = base('clean');
    const converters = document.converter_results as Record<string, Record<string, unknown>>;
    converters.archive.failure = { error: 'boom' };
    converters.jupyter.failure = {};
    expect(assessCoverage(document)?.incomplete_converters).toEqual([
      { converter: 'archive', reason: '{"error":"boom"}' },
      { converter: 'jupyter', reason: '{}' },
    ]);
    converters.archive.failure = null;
    converters.jupyter.failure = 0;
    expect(assessCoverage(document)?.incomplete_converters).toEqual([{ converter: 'jupyter', reason: '0' }]);
  });

  it('skips malformed rows and notifications instead of throwing', () => {
    const document = base('clean');
    (document.converter_results as Record<string, unknown>).broken = 'not a row';
    const run = (document.sarif as { runs: Record<string, unknown>[] }).runs[0];
    (run.invocations as Record<string, unknown>[])[0].toolConfigurationNotifications = [
      { level: 'error', descriptor: { id: 'ASH-CONTENT-DB-STALE' } },
      // Empty, so ASH cannot read it and skips it, as it skips a record with no measured_at.
      { level: 'error', descriptor: { id: 'ASH-CONTENT-DB-STALE' }, properties: { content_database: {} } },
      {
        level: 'error',
        descriptor: { id: 'ASH-CONTENT-DB-STALE' },
        properties: { content_database: { name: 'bad-built', measured_at: '2026-10-01T00:00:00Z', built: 'yesterday' } },
      },
      // Readable and nameless: ASH names it ''.
      {
        level: 'error',
        descriptor: { id: 'ASH-CONTENT-DB-STALE' },
        properties: { content_database: { measured_at: '2026-10-01T00:00:00Z', built: '2026-01-01T00:00:00+00:00' } },
      },
    ];
    expect(assessCoverage(document)).toMatchObject({
      incomplete_converters: [],
      stale_content_databases: [''],
    });
  });

  it('reads every timestamp form ASH accepts', () => {
    const forms: Record<string, string> = {
      basic: '20261001T000000Z',
      'hour-only': '2026-10-01T00+00:00',
      comma: '2026-10-01 00:00:00,5+0530',
      week: '2026-W40-4T12:30-05',
      'any-separator': '2026-10-01\u{1F600}00:00:00.123456789+00:00:00.5',
      'z-separator': '2026-10-01Z00:00Z',
      mixed: '2026-10-01T00:0000Z',
      'date-only': '2026-10-01',
    };
    const document = base('clean');
    const run = (document.sarif as { runs: Record<string, unknown>[] }).runs[0];
    (run.invocations as Record<string, unknown>[])[0].toolConfigurationNotifications = Object.entries(forms).map(
      ([name, at]) => ({
        level: 'error',
        descriptor: { id: 'ASH-CONTENT-DB-STALE' },
        properties: { content_database: { name, measured_at: at } },
      }),
    );
    expect(assessCoverage(document)?.stale_content_databases).toEqual([
      'any-separator',
      'basic',
      'comma',
      'hour-only',
      'week',
    ]);
  });

  it('coerces converter fields as pydantic does', () => {
    const document = base('clean');
    document.converter_results = {
      'excluded-one': { failure: 'raised', excluded: 1 },
      'excluded-junk': { failure: 'raised', excluded: 'maybe' },
      'deps-zero': { dependencies_satisfied: 0 },
      'deps-two': { dependencies_satisfied: 2 },
      'deps-object': { dependencies_satisfied: {} },
      'cand-false': { dependencies_satisfied: false, candidate_inputs: false },
      'cand-true': { dependencies_satisfied: false, candidate_inputs: true },
      'cand-half': { dependencies_satisfied: false, candidate_inputs: 0.5 },
      'cand-blank': { dependencies_satisfied: false, candidate_inputs: ' ' },
      'cand-object': { dependencies_satisfied: false, candidate_inputs: {} },
    };
    expect(assessCoverage(document)?.incomplete_converters.map((row) => row.converter)).toEqual([
      'excluded-junk',
      'deps-zero',
      'deps-two',
      'deps-object',
      'cand-true',
      'cand-half',
      'cand-blank',
      'cand-object',
    ]);
  });

  it('cannot tell from a document that is not a results object', () => {
    expect(assessCoverage(null)).toBeUndefined();
    expect(assessCoverage([])).toBeUndefined();
    expect(assessCoverage({ runs: [] })).toBeUndefined();
    expect(assessCoverageText('not json')).toBeUndefined();
    expect(assessCoverageText('{"metadata": {}}')?.coverage_complete).toBe(true);
  });
});

describe('describeGaps', () => {
  it('says nothing about a complete scan', () => {
    expect(describeGaps(assessCoverage(base('findings')) as CoverageAssessment)).toEqual([]);
  });

  it('gives one line per gap, naming what is missing', () => {
    expect(
      describeGaps({
        coverage_complete: false,
        incomplete_scanners: [{ scanner: 'semgrep', status: 'ERROR', reason: 'error', detail: 'ERROR' }],
        no_scanner_ran: true,
        incomplete_converters: [{ converter: 'archive', reason: 'raised' }],
        unevaluated_rules: ['RULE-X'],
        stale_content_databases: ['grype-db'],
      }),
    ).toEqual([
      'scanner semgrep: ERROR',
      'no scanner ran to a verdict, so the scan measured nothing',
      'converter archive: raised',
      'rule not evaluated: RULE-X',
      'stale content database: grype-db',
    ]);
  });
});
