// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Turns the SARIF ASH already writes into a flat list of findings.
 *
 * WHY THIS IS ITS OWN MODULE, AND WHY IT TOUCHES NO VS CODE API
 *
 * Everything the extension gets wrong about a finding is decided here: which
 * file it lands on, which line, and how many findings there are at all. Keeping
 * that in a module with no `vscode` import means the whole of it is exercised by
 * plain unit tests against real SARIF bytes, rather than only through a
 * DiagnosticCollection stub.
 *
 * WHAT THE SHAPES BELOW ARE DERIVED FROM
 *
 * A measured `ash scan --scanners detect-secrets` run against a file carrying
 * AWS's published example secret access key. Three fields of that output drive
 * decisions here that a reading of the SARIF 2.1.0 spec alone would get wrong:
 *
 *   - `region` carries `startLine` and `endLine` but NO `startColumn`. Column
 *     information is simply not there, so a mapper that assumed it would place
 *     every finding at column 0 of the wrong span.
 *   - `region.charOffset` and `region.byteOffset` are both `-1`. Those are
 *     "unknown" sentinels, not offsets. Read as offsets they would point one
 *     character before the start of the file.
 *   - `artifactLocation.index` is `-1` and `runs[0].artifacts` is absent, so the
 *     index cannot be resolved against an artifact table. The `uri` is the only
 *     usable location, and it is relative to the scanned source directory.
 *
 * WHY A LOCATION-LESS RESULT IS COUNTED RATHER THAN DROPPED
 *
 * SARIF permits a result with no location. Silently dropping those would let a
 * scan that found things report zero diagnostics, which is indistinguishable
 * from a clean scan -- the exact failure this extension exists to remove. So
 * they are parsed into `unlocated` and the caller is made to decide what to do
 * with a non-zero count of them.
 */

/** SARIF severity levels, in the spelling SARIF uses. */
export type SarifLevel = 'error' | 'warning' | 'note' | 'none';

const SARIF_LEVELS: ReadonlySet<string> = new Set(['error', 'warning', 'note', 'none']);

/** One SARIF result, reduced to the fields a diagnostic needs. */
export interface AshFinding {
  /** SARIF `ruleId`, e.g. SECRET-AWS-ACCESS-KEY. Empty string when absent. */
  readonly ruleId: string;
  /** SARIF `message.text`. */
  readonly message: string;
  readonly level: SarifLevel;
  /** POSIX path relative to the scanned source directory. */
  readonly uri: string;
  /** 1-based, as SARIF counts. */
  readonly startLine: number;
  /** 1-based and never less than startLine. */
  readonly endLine: number;
  /** 1-based when SARIF supplied one, otherwise undefined. */
  readonly startColumn?: number;
  readonly endColumn?: number;
  /** ASH puts the scanner that produced the result in `properties.scanner_name`. */
  readonly scannerName?: string;
}

export interface ParsedSarif {
  readonly findings: readonly AshFinding[];
  /**
   * Results that carried no usable file location. Counted, never dropped: see
   * the module comment.
   */
  readonly unlocated: readonly AshFinding[];
  /** `runs[].tool.driver.name`, in run order. Used to say what produced this. */
  readonly toolNames: readonly string[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asArray(value: unknown): readonly unknown[] {
  return Array.isArray(value) ? value : [];
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

/**
 * A SARIF line or column number, or undefined.
 *
 * Rejects zero and negatives rather than clamping them, because ASH writes `-1`
 * as an explicit "unknown" sentinel in sibling fields of the same object. A
 * clamp would turn "unknown" into "line 1", which reads as a real location.
 */
function asPositiveInt(value: unknown): number | undefined {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1) {
    return undefined;
  }
  return value;
}

function asLevel(value: unknown): SarifLevel {
  const text = asString(value);
  // SARIF's own default for a result with no level and no rule configuration is
  // `warning`. Defaulting to `error` would inflate every finding ASH left
  // unlabelled; defaulting to `none` would hide them behind an editor setting.
  return text !== undefined && SARIF_LEVELS.has(text) ? (text as SarifLevel) : 'warning';
}

function readLocation(result: Record<string, unknown>): {
  uri?: string;
  startLine: number;
  endLine: number;
  startColumn?: number;
  endColumn?: number;
} {
  const first = asArray(result.locations).find(isRecord);
  const physical = first !== undefined && isRecord(first.physicalLocation) ? first.physicalLocation : undefined;
  const artifact = physical !== undefined && isRecord(physical.artifactLocation) ? physical.artifactLocation : undefined;
  const region = physical !== undefined && isRecord(physical.region) ? physical.region : undefined;

  const uri = artifact === undefined ? undefined : asString(artifact.uri);
  const startLine = region === undefined ? undefined : asPositiveInt(region.startLine);
  const endLine = region === undefined ? undefined : asPositiveInt(region.endLine);
  const startColumn = region === undefined ? undefined : asPositiveInt(region.startColumn);
  const endColumn = region === undefined ? undefined : asPositiveInt(region.endColumn);

  // A result whose region is missing or unusable still names a file, and a
  // diagnostic on line 1 of the right file is more useful than no diagnostic.
  const start = startLine ?? 1;
  return {
    uri: uri === undefined || uri === '' ? undefined : uri,
    startLine: start,
    // `endLine` before `startLine` would build an inverted range. VS Code
    // tolerates that by swapping the ends, which silently moves the squiggle.
    endLine: endLine !== undefined && endLine >= start ? endLine : start,
    startColumn,
    endColumn,
  };
}

function readScannerName(result: Record<string, unknown>): string | undefined {
  if (!isRecord(result.properties)) {
    return undefined;
  }
  const name = asString(result.properties.scanner_name);
  return name === undefined || name === '' ? undefined : name;
}

/**
 * Parses a SARIF document.
 *
 * Throws on text that is not JSON, and on JSON that is not a SARIF log. Both are
 * deliberate: an unreadable report must not resolve to "no findings", which is
 * how a broken scan comes to look like a clean one.
 */
export function parseAshSarif(text: string): ParsedSarif {
  let doc: unknown;
  try {
    doc = JSON.parse(text) as unknown;
  } catch (err) {
    throw new Error(`the SARIF report is not valid JSON: ${(err as Error).message}`);
  }

  if (!isRecord(doc)) {
    throw new Error('the SARIF report is not a JSON object');
  }
  if (!Array.isArray(doc.runs)) {
    // An object with no `runs` array is not a SARIF log. Treating it as an empty
    // one would report a clean scan for a file ASH never wrote.
    throw new Error('the SARIF report has no "runs" array, so it is not a SARIF log');
  }

  const findings: AshFinding[] = [];
  const unlocated: AshFinding[] = [];
  const toolNames: string[] = [];

  for (const run of doc.runs) {
    if (!isRecord(run)) {
      continue;
    }
    const driver = isRecord(run.tool) && isRecord(run.tool.driver) ? run.tool.driver : undefined;
    const driverName = driver === undefined ? undefined : asString(driver.name);
    if (driverName !== undefined && driverName !== '') {
      toolNames.push(driverName);
    }

    for (const raw of asArray(run.results)) {
      if (!isRecord(raw)) {
        continue;
      }
      const location = readLocation(raw);
      const message = isRecord(raw.message) ? asString(raw.message.text) ?? '' : '';
      const finding: AshFinding = {
        ruleId: asString(raw.ruleId) ?? '',
        message,
        level: asLevel(raw.level),
        uri: location.uri ?? '',
        startLine: location.startLine,
        endLine: location.endLine,
        startColumn: location.startColumn,
        endColumn: location.endColumn,
        scannerName: readScannerName(raw),
      };
      if (location.uri === undefined) {
        unlocated.push(finding);
      } else {
        findings.push(finding);
      }
    }
  }

  return { findings, unlocated, toolNames };
}

/** Groups findings by their `uri`, preserving SARIF order within each file. */
export function groupByUri(findings: readonly AshFinding[]): Map<string, AshFinding[]> {
  const grouped = new Map<string, AshFinding[]>();
  for (const finding of findings) {
    const existing = grouped.get(finding.uri);
    if (existing === undefined) {
      grouped.set(finding.uri, [finding]);
    } else {
      existing.push(finding);
    }
  }
  return grouped;
}
