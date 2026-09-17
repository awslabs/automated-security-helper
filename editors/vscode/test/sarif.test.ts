// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Parser tests, against the measured fixture and against the shapes SARIF
 * permits that ASH does not currently emit.
 *
 * The second half matters as much as the first. ASH's SARIF is written by its own
 * reporter, and a scanner plugin can add results with columns, with several
 * locations, or with none -- so a parser that only handled today's exact shape
 * would break on a plugin rather than on a code change, and break quietly.
 */

import { readFileSync } from 'fs';
import * as path from 'path';
import { groupByUri, parseAshSarif } from '../src/sarif';

const FIXTURES = path.join(__dirname, 'fixtures');

function fixture(name: string): string {
  return readFileSync(path.join(FIXTURES, name), 'utf8');
}

describe('the measured ASH report', () => {
  const parsed = parseAshSarif(fixture('planted-secret.sarif'));

  it('yields one finding per SARIF result', () => {
    expect(parsed.findings).toHaveLength(3);
    expect(parsed.unlocated).toHaveLength(0);
  });

  it('names the tool that produced it', () => {
    expect(parsed.toolNames).toEqual(['AWS Labs - Automated Security Helper']);
  });

  it('reads the rule id, level and scanner name', () => {
    expect(parsed.findings.map((finding) => finding.ruleId)).toEqual([
      'SECRET-AWS-ACCESS-KEY',
      'SECRET-SECRET-KEYWORD',
      'SECRET-BASE64-HIGH-ENTROPY-STRING',
    ]);
    expect(new Set(parsed.findings.map((finding) => finding.level))).toEqual(new Set(['error']));
    expect(new Set(parsed.findings.map((finding) => finding.scannerName))).toEqual(
      new Set(['detect-secrets']),
    );
  });

  it('reads the path relative to the scanned directory', () => {
    expect(new Set(parsed.findings.map((finding) => finding.uri))).toEqual(
      new Set(['planted_secret.py']),
    );
  });

  it('reads line 2 and supplies no columns, because ASH supplies none', () => {
    for (const finding of parsed.findings) {
      expect(finding.startLine).toBe(2);
      expect(finding.endLine).toBe(2);
      // The measured region carries charOffset: -1 and byteOffset: -1, which are
      // "unknown" sentinels. Reading either as a column would place every
      // finding one character before the start of the file.
      expect(finding.startColumn).toBeUndefined();
      expect(finding.endColumn).toBeUndefined();
    }
  });
});

describe('the negative control fixture', () => {
  it('is a valid report with no results', () => {
    const parsed = parseAshSarif(fixture('clean-scan.sarif'));
    expect(parsed.findings).toHaveLength(0);
    expect(parsed.unlocated).toHaveLength(0);
    // Still a real report from a real tool: this is a clean scan, not a broken
    // one, and the two must not collapse into each other.
    expect(parsed.toolNames).toEqual(['AWS Labs - Automated Security Helper']);
  });
});

describe('a report that cannot be trusted', () => {
  it('throws on text that is not JSON', () => {
    expect(() => parseAshSarif('not json at all')).toThrow(/not valid JSON/);
  });

  it('throws on JSON that is not an object', () => {
    expect(() => parseAshSarif('[]')).toThrow(/not a JSON object/);
    expect(() => parseAshSarif('42')).toThrow(/not a JSON object/);
    expect(() => parseAshSarif('null')).toThrow(/not a JSON object/);
  });

  it('throws when there is no runs array, rather than reporting a clean scan', () => {
    expect(() => parseAshSarif('{"version":"2.1.0"}')).toThrow(/no "runs" array/);
    expect(() => parseAshSarif('{"runs":{}}')).toThrow(/no "runs" array/);
  });
});

describe('shapes SARIF permits', () => {
  it('accepts a run with no results', () => {
    expect(parseAshSarif('{"runs":[{}]}').findings).toHaveLength(0);
  });

  it('skips non-object entries in runs and results', () => {
    const parsed = parseAshSarif('{"runs":[null,7,{"results":[null,"x"]}]}');
    expect(parsed.findings).toHaveLength(0);
    expect(parsed.unlocated).toHaveLength(0);
  });

  it('records no tool name when the driver has none', () => {
    expect(parseAshSarif('{"runs":[{"tool":{"driver":{}}}]}').toolNames).toEqual([]);
    expect(parseAshSarif('{"runs":[{"tool":{"driver":{"name":""}}}]}').toolNames).toEqual([]);
    expect(parseAshSarif('{"runs":[{"tool":7}]}').toolNames).toEqual([]);
  });

  it('keeps columns when a result supplies them', () => {
    const parsed = parseAshSarif(
      JSON.stringify({
        runs: [
          {
            results: [
              {
                ruleId: 'R1',
                message: { text: 'm' },
                locations: [
                  {
                    physicalLocation: {
                      artifactLocation: { uri: 'a.ts' },
                      region: { startLine: 4, endLine: 6, startColumn: 3, endColumn: 9 },
                    },
                  },
                ],
              },
            ],
          },
        ],
      }),
    );
    expect(parsed.findings[0]).toMatchObject({
      startLine: 4,
      endLine: 6,
      startColumn: 3,
      endColumn: 9,
    });
  });

  it('rejects the -1 sentinels and zero rather than clamping them into real numbers', () => {
    const parsed = parseAshSarif(
      JSON.stringify({
        runs: [
          {
            results: [
              {
                locations: [
                  {
                    physicalLocation: {
                      artifactLocation: { uri: 'a.ts' },
                      region: { startLine: -1, endLine: 0, startColumn: -1, endColumn: 0 },
                    },
                  },
                ],
              },
            ],
          },
        ],
      }),
    );
    // An unusable region still names a file, so the finding lands on line 1 of
    // the right file rather than disappearing.
    expect(parsed.findings[0]).toMatchObject({ startLine: 1, endLine: 1 });
    expect(parsed.findings[0].startColumn).toBeUndefined();
    expect(parsed.findings[0].endColumn).toBeUndefined();
  });

  it('rejects a non-integer line', () => {
    const parsed = parseAshSarif(
      JSON.stringify({
        runs: [
          {
            results: [
              {
                locations: [
                  {
                    physicalLocation: {
                      artifactLocation: { uri: 'a.ts' },
                      region: { startLine: 2.5 },
                    },
                  },
                ],
              },
            ],
          },
        ],
      }),
    );
    expect(parsed.findings[0].startLine).toBe(1);
  });

  it('never builds an inverted range from an endLine before the startLine', () => {
    const parsed = parseAshSarif(
      JSON.stringify({
        runs: [
          {
            results: [
              {
                locations: [
                  {
                    physicalLocation: {
                      artifactLocation: { uri: 'a.ts' },
                      region: { startLine: 9, endLine: 4 },
                    },
                  },
                ],
              },
            ],
          },
        ],
      }),
    );
    expect(parsed.findings[0]).toMatchObject({ startLine: 9, endLine: 9 });
  });

  it('defaults an absent or unrecognised level to warning, which is SARIF\'s own default', () => {
    const withLevel = (level: unknown): string =>
      JSON.stringify({
        runs: [
          {
            results: [
              {
                level,
                locations: [{ physicalLocation: { artifactLocation: { uri: 'a.ts' } } }],
              },
            ],
          },
        ],
      });
    expect(parseAshSarif(withLevel(undefined)).findings[0].level).toBe('warning');
    expect(parseAshSarif(withLevel('shouty')).findings[0].level).toBe('warning');
    expect(parseAshSarif(withLevel(7)).findings[0].level).toBe('warning');
    expect(parseAshSarif(withLevel('note')).findings[0].level).toBe('note');
    expect(parseAshSarif(withLevel('none')).findings[0].level).toBe('none');
  });

  it('falls back to the rule id when there is no message text', () => {
    const parsed = parseAshSarif(
      JSON.stringify({
        runs: [
          {
            results: [
              {
                ruleId: 'R2',
                message: 'not an object',
                locations: [{ physicalLocation: { artifactLocation: { uri: 'a.ts' } } }],
              },
            ],
          },
        ],
      }),
    );
    expect(parsed.findings[0].message).toBe('');
    expect(parsed.findings[0].ruleId).toBe('R2');
  });

  it('treats an empty uri, an absent artifactLocation and a bad properties block as unlocated or unnamed', () => {
    const parsed = parseAshSarif(
      JSON.stringify({
        runs: [
          {
            results: [
              { locations: [{ physicalLocation: { artifactLocation: { uri: '' } } }] },
              { locations: [{ physicalLocation: {} }] },
              { locations: [{}] },
              { locations: [] },
              { properties: 'nope' },
              {
                properties: { scanner_name: '' },
                locations: [{ physicalLocation: { artifactLocation: { uri: 'a.ts' } } }],
              },
            ],
          },
        ],
      }),
    );
    expect(parsed.unlocated).toHaveLength(5);
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0].scannerName).toBeUndefined();
  });
});

describe('groupByUri', () => {
  it('groups by file and keeps SARIF order inside each group', () => {
    const parsed = parseAshSarif(
      JSON.stringify({
        runs: [
          {
            results: ['a.ts', 'b.ts', 'a.ts'].map((uri, index) => ({
              ruleId: `R${index}`,
              locations: [{ physicalLocation: { artifactLocation: { uri } } }],
            })),
          },
        ],
      }),
    );
    const grouped = groupByUri(parsed.findings);
    expect([...grouped.keys()]).toEqual(['a.ts', 'b.ts']);
    expect(grouped.get('a.ts')?.map((finding) => finding.ruleId)).toEqual(['R0', 'R2']);
  });

  it('returns an empty map for no findings', () => {
    expect(groupByUri([]).size).toBe(0);
  });
});
