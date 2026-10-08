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
import {
  groupByUri,
  isFailure,
  isSuppressed,
  joinUriReference,
  parseAshSarif,
  resolveBaseId,
} from '../src/sarif';

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

describe('a real report with an ASH suppression', () => {
  // scans/findings is `ash scan --scanners detect-secrets` over the planted secret
  // with a global_settings.suppressions entry for SECRET-SECRET-KEYWORD. ASH kept
  // that result in the SARIF with kind "fail" and level "error" and added a
  // `suppressions` entry, so only `suppressions` says it is hidden.
  const parsed = parseAshSarif(fixture('scans/findings/ash.sarif'));

  it('publishes the two unsuppressed findings and counts the third', () => {
    expect(parsed.findings.map((finding) => finding.ruleId).sort()).toEqual([
      'SECRET-AWS-ACCESS-KEY',
      'SECRET-BASE64-HIGH-ENTROPY-STRING',
    ]);
    expect(parsed.suppressed).toBe(1);
    expect(parsed.notFailures).toBe(0);
    expect(parsed.unlocated).toHaveLength(0);
  });

  it('reads the line ASH reported', () => {
    expect(new Set(parsed.findings.map((finding) => finding.startLine))).toEqual(new Set([25]));
  });
});

describe('isSuppressed', () => {
  it('is false with no suppressions, or an empty list', () => {
    expect(isSuppressed({})).toBe(false);
    expect(isSuppressed({ suppressions: [] })).toBe(false);
    expect(isSuppressed({ suppressions: 'yes' })).toBe(false);
  });

  it('honors a suppression whose state is absent, null or accepted', () => {
    expect(isSuppressed({ suppressions: [{ kind: 'inSource' }] })).toBe(true);
    expect(isSuppressed({ suppressions: [{ kind: 'external', state: null }] })).toBe(true);
    expect(isSuppressed({ suppressions: [{ kind: 'external', state: 'accepted' }] })).toBe(true);
  });

  it('shows a finding whose only suppression is under review or rejected', () => {
    expect(isSuppressed({ suppressions: [{ kind: 'external', state: 'underReview' }] })).toBe(false);
    expect(isSuppressed({ suppressions: [{ kind: 'external', state: 'rejected' }] })).toBe(false);
  });

  it('honors one effective suppression among ineffective ones', () => {
    expect(
      isSuppressed({ suppressions: [{ state: 'rejected' }, { state: 'accepted' }] }),
    ).toBe(true);
  });

  it('reads accepted in any case', () => {
    expect(isSuppressed({ suppressions: [{ kind: 'external', state: 'ACCEPTED' }] })).toBe(true);
  });

  // A state string that is none of the three SARIF values is not a decision
  // anybody made to hide the finding. Hiding it would let a typo, or a value
  // from a newer schema, silence a security finding.
  it('shows a finding whose only suppression has an unknown state string', () => {
    expect(isSuppressed({ suppressions: [{ kind: 'external', state: 'pending' }] })).toBe(false);
    expect(isSuppressed({ suppressions: [{ kind: 'external', state: '' }] })).toBe(false);
    expect(isSuppressed({ suppressions: [{ kind: 'external', state: 'accepted ' }] })).toBe(false);
  });

  // SARIF 2.1.0 section 3.35.3 names the property `status`; ASH's model writes
  // `state`. A spec-conformant producer's `rejected` must not be read as "no
  // status recorded" and hide the finding. Matches JetBrains' suppressionOf.
  it('reads the spec\'s `status` as well as ASH\'s `state`', () => {
    expect(isSuppressed({ suppressions: [{ kind: 'external', status: 'accepted' }] })).toBe(true);
    expect(isSuppressed({ suppressions: [{ kind: 'external', status: 'rejected' }] })).toBe(false);
    expect(isSuppressed({ suppressions: [{ kind: 'external', status: 'underReview' }] })).toBe(false);
    expect(isSuppressed({ suppressions: [{ kind: 'external', status: null }] })).toBe(true);
  });

  it('lets `status` decide when both are present, and falls back to `state` when it is null', () => {
    expect(isSuppressed({ suppressions: [{ status: 'rejected', state: 'accepted' }] })).toBe(false);
    expect(isSuppressed({ suppressions: [{ status: 'accepted', state: 'rejected' }] })).toBe(true);
    expect(isSuppressed({ suppressions: [{ status: null, state: 'rejected' }] })).toBe(false);
  });

  // JetBrains reads `status` only when it is a string, so a non-string `status`
  // falls through to `state`. Aligned here: it can only show a finding that
  // `state` says to show, never hide one.
  it('falls back to `state` when `status` is not a string', () => {
    expect(isSuppressed({ suppressions: [{ status: 7, state: 'rejected' }] })).toBe(false);
    expect(isSuppressed({ suppressions: [{ status: { x: 1 }, state: 'underReview' }] })).toBe(false);
    expect(isSuppressed({ suppressions: [{ status: 7, state: 'accepted' }] })).toBe(true);
    // Neither readable: still the unreadable-means-suppressed rule, in both IDEs.
    expect(isSuppressed({ suppressions: [{ status: 7 }] })).toBe(true);
  });

  it('honors a suppression it cannot read, at either depth', () => {
    expect(isSuppressed({ suppressions: [12345] })).toBe(true);
    expect(isSuppressed({ suppressions: [{ state: 12345 }] })).toBe(true);
  });
});

describe('isFailure', () => {
  it('reads an absent kind as fail, the model default', () => {
    expect(isFailure({})).toBe(true);
    expect(isFailure({ kind: null })).toBe(true);
    expect(isFailure({ kind: 'fail' })).toBe(true);
  });

  it('is false for the five kinds that are not problems', () => {
    for (const kind of ['pass', 'notApplicable', 'review', 'open', 'informational']) {
      expect(isFailure({ kind })).toBe(false);
    }
    expect(isFailure({ kind: 7 })).toBe(false);
  });
});

describe('suppressed and non-failure results in a parse', () => {
  it('are counted and never become findings, even without a location', () => {
    const text = JSON.stringify({
      runs: [
        {
          results: [
            { ruleId: 'A', suppressions: [{ kind: 'inSource' }] },
            { ruleId: 'B', kind: 'pass', locations: [{ physicalLocation: { artifactLocation: { uri: 'b.py' } } }] },
            { ruleId: 'C', locations: [{ physicalLocation: { artifactLocation: { uri: 'c.py' } } }] },
          ],
        },
      ],
    });

    const parsed = parseAshSarif(text);

    expect(parsed.findings.map((finding) => finding.ruleId)).toEqual(['C']);
    expect(parsed.suppressed).toBe(1);
    expect(parsed.notFailures).toBe(1);
    // The suppressed result had no location. Counting it as unlocated would fire
    // the "named no file" warning about a finding nobody wanted to see.
    expect(parsed.unlocated).toHaveLength(0);
  });
});

describe('uriBaseId', () => {
  const run = (artifactLocation: Record<string, unknown>, originalUriBaseIds?: unknown): string =>
    JSON.stringify({
      runs: [
        {
          originalUriBaseIds,
          results: [{ ruleId: 'R', locations: [{ physicalLocation: { artifactLocation } }] }],
        },
      ],
    });

  it('resolves the base the run declares, as workspace mode writes it', () => {
    const [finding] = parseAshSarif(
      run({ uri: 'src/app.py', uriBaseId: 'PROJECTROOT' }, { PROJECTROOT: { uri: 'file:///ws/api/' } }),
    ).findings;

    expect(finding.uriBaseId).toBe('PROJECTROOT');
    expect(finding.baseUri).toBe('file:///ws/api/');
  });

  it('leaves the base unresolved when the run does not declare it', () => {
    const [finding] = parseAshSarif(run({ uri: 'src/app.py', uriBaseId: 'SRCROOT' })).findings;

    expect(finding.uriBaseId).toBe('SRCROOT');
    expect(finding.baseUri).toBeUndefined();
  });

  it('ignores an empty uriBaseId', () => {
    const [finding] = parseAshSarif(run({ uri: 'a.py', uriBaseId: '' })).findings;

    expect(finding.uriBaseId).toBeUndefined();
  });
});

describe('resolveBaseId', () => {
  it('follows a nested base id', () => {
    const table = {
      ROOT: { uri: 'file:///ws/' },
      API: { uri: 'api/', uriBaseId: 'ROOT' },
    };
    expect(resolveBaseId(table, 'API')).toBe('file:///ws/api/');
  });

  it('returns a relative base as-is when it names no parent', () => {
    expect(resolveBaseId({ API: { uri: 'api/' } }, 'API')).toBe('api/');
  });

  it('gives up on a cycle, an undeclared parent, or a malformed entry', () => {
    expect(resolveBaseId({ A: { uri: 'a/', uriBaseId: 'B' }, B: { uri: 'b/', uriBaseId: 'A' } }, 'A')).toBeUndefined();
    expect(resolveBaseId({ A: { uri: 'a/', uriBaseId: 'MISSING' } }, 'A')).toBeUndefined();
    expect(resolveBaseId({ A: 'file:///ws/' }, 'A')).toBeUndefined();
    expect(resolveBaseId({ A: { uri: '' } }, 'A')).toBeUndefined();
    expect(resolveBaseId(undefined, 'A')).toBeUndefined();
  });
});

describe('joinUriReference', () => {
  it('puts exactly one separator between the parts', () => {
    expect(joinUriReference('file:///ws/', 'a.py')).toBe('file:///ws/a.py');
    expect(joinUriReference('file:///ws', 'a.py')).toBe('file:///ws/a.py');
    expect(joinUriReference('C:\\ws\\', 'a.py')).toBe('C:\\ws\\a.py');
  });
});
