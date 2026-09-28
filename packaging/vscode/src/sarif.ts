// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * SARIF 2.1.0 reading, with no dependency on the `vscode` module.
 *
 * Kept free of `vscode` imports on purpose: this is the half of the extension
 * with all the parsing decisions in it, and a module that imports `vscode` can
 * only be exercised inside a running extension host. Severity mapping to
 * `vscode.DiagnosticSeverity` lives in diagnostics.ts, which is the only place
 * that needs the editor API.
 *
 * WHAT THIS DELIBERATELY DOES NOT DO
 *
 * It does not validate the document against the SARIF schema. It reads the
 * subset ASH populates -- runs[].results[].{level,message,ruleId,locations} --
 * and skips a result it cannot place, counting the skip rather than dropping it
 * silently. A finding this cannot locate is a finding the user never sees, so
 * the count is reported to the caller and surfaced.
 */

/** The four `level` values SARIF 2.1.0 defines for a `result`. */
export type SarifLevel = 'error' | 'warning' | 'note' | 'none';

const SARIF_LEVELS: ReadonlySet<string> = new Set<SarifLevel>([
  'error',
  'warning',
  'note',
  'none',
]);

/**
 * What an absent `level` is read as. Absence is legal, so it is NOT reported as a
 * nonconforming spelling.
 *
 * `error`, AND THIS IS A DECISION RATHER THAN A CITATION. An earlier version of
 * this comment claimed the SARIF spec makes the default `warning` and gave a
 * section number. I have no copy of the spec text and did not read it, so that
 * citation was unfounded; it is removed rather than corrected, because a section
 * number is the most citable-looking kind of claim and therefore the one that
 * propagates furthest unchecked.
 *
 * What IS verifiable, in this repository, is that ASH's own generated model
 * disagrees with itself depending on the object --
 * automated_security_helper/schemas/sarif_schema_model.py:
 *
 *     :1992-1997  Result.kind  default "fail"      Result.level  default "error"
 *     :166-168    ReportingConfiguration.level     default "warning"
 *
 * So the producer whose output this parses reads an absent Result.level as
 * `error`. Matching it is the safe direction for a security tool: the entire
 * family of defects this file has been corrected for was severities being
 * silently reduced, and defaulting to `warning` would reduce every level-less
 * result by one band relative to what ASH itself would say.
 *
 * MEASURED SCOPE: unexercised on real output. All 126 results in
 * tests/test_data/outputs/ash_aggregated_results.json carry an explicit level, so
 * nothing today reaches this constant. It is a latent choice, documented because
 * the previous latent choice in this file went the wrong way and was invisible.
 */
const DEFAULT_LEVEL: SarifLevel = 'error';

export interface ParsedFinding {
  /** The raw `artifactLocation.uri`, resolved by the caller against a root. */
  readonly uri: string;
  readonly level: SarifLevel;
  readonly message: string;
  readonly ruleId: string;
  readonly toolName: string;
  /** 1-based, as SARIF states it. Converted to 0-based in diagnostics.ts. */
  readonly startLine: number;
  readonly startColumn?: number;
  readonly endLine?: number;
  readonly endColumn?: number;
}

export interface ParsedSarif {
  readonly findings: readonly ParsedFinding[];
  /**
   * Distinct raw `level` spellings that are not SARIF values but were
   * recognizable enough to coerce -- today, Python enum member names.
   *
   * WHY THIS IS RETURNED RATHER THAN SWALLOWED
   *
   * A `(str, Enum)` member stringified by name gives `"Level.error"`, not
   * `"error"`. That has been a live defect in this repository's own SARIF
   * handling -- see the comment in
   * automated_security_helper/models/flat_vulnerability.py, where reading the
   * member instead of its `.value` sent every error-level result to the
   * MEDIUM fallback, one band below what it was owed.
   *
   * Two wrong ways to handle it here. Rejecting the spelling outright loses
   * real findings. Accepting it quietly maps the severity correctly and leaves
   * the producer bug invisible forever, which is how the original defect
   * survived. So: coerce it, AND hand the caller every spelling coerced, so the
   * extension can say so out loud. Downgrading loudly is the whole point.
   */
  readonly nonconformingLevels: readonly string[];
  /** Results that carry no usable physical location. */
  readonly skipped: number;
  /**
   * Results ASH suppressed, which are deliberately NOT in `findings`.
   *
   * A suppression mechanism whose output is re-displayed is not a suppression
   * mechanism. Someone who configured ASH to ignore their test data would
   * otherwise open the editor and see every one of those findings again, with
   * nothing saying they had been suppressed.
   */
  readonly suppressed: number;
  /**
   * Results whose `kind` is not a failure -- `pass`, `notApplicable`, `review`,
   * `open`, `informational`. Also not in `findings`.
   */
  readonly notFailures: number;
}

/** Thrown when the text is not JSON, or is JSON that is not a SARIF log. */
export class SarifParseError extends Error {}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asArray(value: unknown): readonly unknown[] {
  return Array.isArray(value) ? value : [];
}

/**
 * Maps a raw `level` onto a SARIF level, reporting the spelling when it had to
 * be corrected.
 *
 * `undefined` returns the SARIF default and reports nothing -- omitting the key
 * is legal. Anything else that is not one of the four values is reported.
 */
export function normalizeLevel(raw: unknown): {
  level: SarifLevel;
  nonconforming?: string;
} {
  if (raw === undefined || raw === null) {
    return { level: DEFAULT_LEVEL };
  }
  if (typeof raw !== 'string') {
    return { level: DEFAULT_LEVEL, nonconforming: JSON.stringify(raw) };
  }

  const lowered = raw.trim().toLowerCase();
  if (SARIF_LEVELS.has(lowered)) {
    // A pure case difference ("ERROR") is still not a SARIF value, so it is
    // reported, but it maps to the level it obviously means.
    return lowered === raw
      ? { level: lowered as SarifLevel }
      : { level: lowered as SarifLevel, nonconforming: raw };
  }

  // `Level.error`, `level.warning` -- a Python enum member name rather than its
  // value. Matched by exact prefix and whole remainder, not by substring: a
  // ruleId-like string that merely contains "error" must not be read as a level.
  const dot = lowered.indexOf('.');
  if (dot > 0) {
    const stem = lowered.slice(0, dot);
    const member = lowered.slice(dot + 1);
    if (stem === 'level' && SARIF_LEVELS.has(member)) {
      return { level: member as SarifLevel, nonconforming: raw };
    }
  }

  return { level: DEFAULT_LEVEL, nonconforming: raw };
}

/**
 * True when ASH suppressed this result, so it must not become a diagnostic.
 *
 * KEYED ON `suppressions`, NOT ON `level` OR `kind`, and that choice is the whole
 * substance of this function. Measured on
 * tests/test_data/outputs/ash_aggregated_results.json:
 *
 *     results with a non-empty `suppressions` array        92
 *     results with kind=informational AND level=none       85
 *
 * The two sets are NOT the same, and the difference runs in the dangerous
 * direction. Every `level: none` result is suppressed, but SEVEN more are
 * suppressed while carrying `kind: "fail"` and a real level -- 5 from checkov and
 * 2 from semgrep, each with `suppression.kind: "inSource"`, which is how an
 * in-source marker like a `# nosec` comment arrives. Filtering on the level or on
 * the kind would re-display all seven, so a user who suppressed a finding in their
 * own source would see it anyway. `level` is a severity; suppression is a state.
 *
 * HOW `state` IS TREATED, AND WHY THIS IS A DECISION AND NOT A CITATION.
 *
 * An earlier version of this comment said "`state` is honored per SARIF 2.1.0
 * section 3.27.23: it defaults to `accepted`". Two things were wrong with that and
 * the second is the worse one. The spec's property is reportedly named `status`,
 * not `state`; and I have no copy of the spec text, so the section number and the
 * default attributed to it were both unfounded. A claim dressed as a citation
 * travels further than a claim marked as a judgement, which is exactly why it must
 * not be dressed that way.
 *
 * What is verifiable here, in
 * automated_security_helper/schemas/sarif_schema_model.py:
 *
 *     :1611-1626  class Suppression, model_config extra="forbid"
 *                 kind:  Kind1  REQUIRED    -- inSource | external   (:114-116)
 *                 state: Optional[State]    -- accepted | underReview | rejected (:119-122)
 *
 * `extra="forbid"` means a `status` field would be REJECTED by ASH's own model, so
 * whatever the spec calls it, the key this code can ever see is `state`. Measured:
 * zero `status` keys across all 92 suppression objects.
 *
 * The three dispositions are chosen, not derived:
 *
 *   absent or null -> SUPPRESSED. Somebody recorded a suppression; the state
 *     simply was not filled in. Treating it as ineffective would re-display every
 *     finding in the real report.
 *   accepted       -> SUPPRESSED. Unambiguous.
 *   underReview    -> SHOWN. A suppression nobody has agreed to yet must not hide
 *     a finding: for a security tool, erring toward showing is the safe direction
 *     when the state is undecided.
 *   rejected       -> SHOWN. The team decided not to suppress it.
 *
 * MEASURED, and corrected from what this file said before: the `state` key is
 * PRESENT AND NULL on all 92 suppression objects -- it is not absent. The earlier
 * "absent on all 92" came from reading `dict.get('state')` returning None, which
 * cannot distinguish a missing key from a present-but-null one. Both reach the same
 * branch here so no behavior was wrong, but the measurement was, and the same
 * mistake made against a report that never had the field would have looked
 * identical.
 */
export function isSuppressed(result: Record<string, unknown>): boolean {
  const suppressions = result['suppressions'];
  if (!Array.isArray(suppressions) || suppressions.length === 0) {
    return false;
  }
  return suppressions.some((entry) => {
    if (!isRecord(entry)) {
      // A malformed suppression entry still says somebody meant to suppress
      // this. Treating it as effective is the safe direction: showing a finding
      // the user asked to hide is the defect being fixed.
      return true;
    }
    const state = entry['state'];
    if (state === undefined || state === null) {
      return true; // absent or null -- see the dispositions above
    }
    if (typeof state !== 'string') {
      // A FIFTH CASE the four dispositions above did not cover, and it used to land
      // on the unsafe side: `{state: 12345}` fell through to the string comparison,
      // which is false, so the finding was SHOWN -- while a non-record entry like a
      // bare `12345` was treated as suppressing. The same nonsense suppressed or
      // did not depending on how deeply it was nested. Unreadable means the same
      // thing at both depths: somebody recorded a suppression and the state cannot
      // be read, so honor the suppression.
      return true;
    }
    return state.toLowerCase() === 'accepted';
  });
}

/**
 * True when a result reports a failure.
 *
 * `kind` defaults to `fail` -- verifiable in this repository at
 * automated_security_helper/schemas/sarif_schema_model.py:1992-1993, where
 * `Result.kind` is declared `Optional[Kind]` with default `"fail"`. The six
 * permitted values are at :93-99: notApplicable, pass, fail, review, open,
 * informational.
 *
 * Only a failure belongs in a Problems view. The other five are statements about a
 * rule having been considered, not about a problem in the code.
 *
 * No spec section is cited here, deliberately. An earlier version cited two, for
 * this rule and for the kind/level pairing, and I have never opened the spec --
 * one of those citations turned out to name the wrong property entirely. The
 * in-repo schema model is the strongest thing I can actually check, so it is what
 * is cited.
 */
export function isFailure(result: Record<string, unknown>): boolean {
  const kind = result['kind'];
  if (kind === undefined || kind === null) {
    return true; // absent -- `fail` is the declared default; see above
  }
  return typeof kind === 'string' && kind.toLowerCase() === 'fail';
}

function extractMessage(result: Record<string, unknown>): string {
  const message = result['message'];
  if (isRecord(message) && typeof message['text'] === 'string') {
    return message['text'];
  }
  return '';
}

/**
 * The scanner that produced ONE result.
 *
 * READ PER RESULT, NOT PER RUN, AND THAT IS THE WHOLE POINT. An earlier version
 * read `tool.driver.name` once, outside the results loop, and applied it to every
 * finding. Both halves of that were wrong against real ASH output, measured
 * against tests/test_data/outputs/ash_aggregated_results.json:
 *
 *   - WRONG FIELD. `tool.driver.name` is "AWS Labs - Automated Security Helper",
 *     the product, so every diagnostic's source became that one 36-character
 *     string and no finding could be attributed to the tool that raised it.
 *
 *   - WRONG CARDINALITY, which is the structural error. That report puts 126
 *     results from SEVEN scanners (cfn-nag, detect-secrets, bandit, cdk-nag,
 *     checkov, grype, semgrep) in a SINGLE run. A run-level value cannot express
 *     per-finding attribution however good the field is, so moving the lookup
 *     inside the loop was the fix and changing the field alone would not have
 *     been.
 *
 * Precedence matches this repository's own reader --
 * `_extract_scanner_name_from_result` in
 * automated_security_helper/models/flat_vulnerability.py -- so the editor and the
 * Python reporters agree about which scanner owns a finding.
 *
 * `properties.scanner_name` is present on 126 of 126 real results, and
 * `properties.scanner_details.tool_name` on 126 of 126 as well, so in practice
 * the first branch always wins. The later branches are for reports this has not
 * seen; they are not known-dead, but they are known-unexercised by the one real
 * artifact available, and that is worth saying rather than implying they are
 * tested.
 *
 * NOT IMPLEMENTED: that function's last-resort arm, which reads `properties.tags`
 * when the run tool is ASH's generic aggregate name. It is unreachable while
 * `scanner_name` is populated, and guessing a scanner from a tag list is not
 * something to add on a path no measurement exercises.
 */
/**
 * Run-level tool names that name the AGGREGATE rather than a scanner.
 *
 * WHY A DENYLIST IS NEEDED AT ALL. The fallback chain used to end at
 * `tool.driver.name`, which on real ASH output is
 * "AWS Labs - Automated Security Helper" -- so a result carrying neither
 * `scanner_name` nor `scanner_details.tool_name` produced exactly the product-name
 * attribution this function was written to eliminate. The bug was reintroduced by
 * the fix's own last arm.
 *
 * Matched case-insensitively and whitespace-trimmed, against whole strings. This
 * mirrors the house pattern: `_extract_scanner_name_from_result` in
 * automated_security_helper/models/flat_vulnerability.py has the same special case,
 * phrased as "if the run tool is the generic ASH aggregate name".
 */
const AGGREGATE_TOOL_NAMES: ReadonlySet<string> = new Set([
  'ash',
  'aws labs - automated security helper',
  'automated security helper',
  'automated-security-helper',
  'automated_security_helper',
]);

/**
 * `''` when no scanner can be identified, which renders as a bare `ASH` source
 * rather than as `ASH (<product name>)`. Saying "ASH reported this" is honest;
 * naming the product as though it were the scanner is not.
 */
export function unaggregatedToolName(runToolName: string): string {
  return AGGREGATE_TOOL_NAMES.has(runToolName.trim().toLowerCase())
    ? ''
    : runToolName;
}

export function extractScannerName(
  result: Record<string, unknown>,
  runToolName: string,
): string {
  const properties = result['properties'];
  if (isRecord(properties)) {
    const direct = properties['scanner_name'];
    if (typeof direct === 'string' && direct.length > 0) {
      return direct;
    }
    const details = properties['scanner_details'];
    if (isRecord(details)) {
      const toolName = details['tool_name'];
      if (typeof toolName === 'string' && toolName.length > 0) {
        return toolName;
      }
    }
  }
  // The run-level name only if it names a scanner. See AGGREGATE_TOOL_NAMES: this
  // arm returned the product name before, which is the defect this whole function
  // exists to prevent.
  return unaggregatedToolName(runToolName);
}

/**
 * The first physical location of a result, or undefined when it has none.
 *
 * ASH results carry one location; SARIF permits many. Taking the first is the
 * convention every SARIF viewer uses, and a result with no physical location
 * (a configuration notification, say) has nowhere to be drawn -- hence the
 * skipped count rather than a diagnostic at line 1 of an arbitrary file.
 */
function extractLocation(
  result: Record<string, unknown>,
): { uri: string; region: Record<string, unknown> } | undefined {
  for (const location of asArray(result['locations'])) {
    if (!isRecord(location)) {
      continue;
    }
    const physical = location['physicalLocation'];
    if (!isRecord(physical)) {
      continue;
    }
    const artifact = physical['artifactLocation'];
    if (!isRecord(artifact) || typeof artifact['uri'] !== 'string') {
      continue;
    }
    const uri = artifact['uri'];
    if (uri.length === 0) {
      continue;
    }
    const region = isRecord(physical['region']) ? physical['region'] : {};
    return { uri, region };
  }
  return undefined;
}

/**
 * A positive integer from a SARIF region, or undefined.
 *
 * SARIF line and column numbers are 1-based, so 0 and negatives are malformed
 * rather than meaningful, and a non-integer cannot index a document. Returning
 * undefined for those lets the caller fall back rather than compute a range
 * from nonsense.
 */
function positiveInt(value: unknown): number | undefined {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1) {
    return undefined;
  }
  return value;
}

export function parseSarif(text: string): ParsedSarif {
  let document: unknown;
  try {
    document = JSON.parse(text);
  } catch (error) {
    throw new SarifParseError(
      `not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  if (!isRecord(document)) {
    throw new SarifParseError('top level of the document is not a JSON object');
  }
  if (!Array.isArray(document['runs'])) {
    throw new SarifParseError(
      'no `runs` array at the top level, so this is not a SARIF log',
    );
  }

  const findings: ParsedFinding[] = [];
  const nonconforming = new Set<string>();
  let skipped = 0;
  let suppressed = 0;
  let notFailures = 0;

  for (const run of asArray(document['runs'])) {
    if (!isRecord(run)) {
      continue;
    }

    // The run-level name, used ONLY as the per-result fallback below. It is not
    // the scanner: on real output it is the product, "AWS Labs - Automated
    // Security Helper". Rule metadata is deliberately not resolved from
    // `tool.driver.rules` -- on the real report that array is EMPTY, all 1,264
    // rules live in `tool.extensions[].rules`, and every result carries
    // `ruleIndex: -1` with a null `rule`. So any future work that wants a rule's
    // helpUri or description must read extensions[]; driver.rules is a dead end.
    // Nothing here reads either, because `result.ruleId` is populated on 126 of
    // 126 real results and is all the diagnostic needs.
    let runToolName = 'ASH';
    const tool = run['tool'];
    if (isRecord(tool) && isRecord(tool['driver'])) {
      const name = tool['driver']['name'];
      if (typeof name === 'string' && name.length > 0) {
        runToolName = name;
      }
    }

    for (const result of asArray(run['results'])) {
      if (!isRecord(result)) {
        skipped += 1;
        continue;
      }

      // THE LEVEL IS NORMALIZED FIRST, BEFORE ANY FILTER, and only for its side
      // effect of recording a nonconforming spelling. This detector's whole purpose
      // is to make a PRODUCER defect visible, and a producer that writes
      // `Level.error` does so regardless of whether the result is suppressed or
      // publishable. Reading it after the filters scoped it to the 34 surviving
      // results of 126, so the same bug on any of the 92 suppressed ones was
      // invisible -- the detector was silently narrowed to a quarter of the report.
      const { level, nonconforming: spelling } = normalizeLevel(result['level']);
      if (spelling !== undefined) {
        nonconforming.add(spelling);
      }

      // Checked BEFORE the location lookup, so a suppressed result with no
      // location is counted as suppressed rather than as skipped. The two counts
      // mean different things to the reader -- one is the user's configuration
      // working, the other is a finding they cannot see -- and a result landing in
      // the wrong bucket would make the warning about skipped findings fire for a
      // finding nobody wanted.
      if (isSuppressed(result)) {
        suppressed += 1;
        continue;
      }
      if (!isFailure(result)) {
        notFailures += 1;
        continue;
      }

      const location = extractLocation(result);
      if (location === undefined) {
        skipped += 1;
        continue;
      }

      const ruleId = typeof result['ruleId'] === 'string' ? result['ruleId'] : '';
      const startLine = positiveInt(location.region['startLine']) ?? 1;
      const startColumn = positiveInt(location.region['startColumn']);
      const endLine = positiveInt(location.region['endLine']);
      const endColumn = positiveInt(location.region['endColumn']);

      findings.push({
        uri: location.uri,
        level,
        message: extractMessage(result),
        ruleId,
        // Resolved per result, inside the loop. See extractScannerName.
        toolName: extractScannerName(result, runToolName),
        startLine,
        ...(startColumn !== undefined ? { startColumn } : {}),
        ...(endLine !== undefined ? { endLine } : {}),
        ...(endColumn !== undefined ? { endColumn } : {}),
      });
    }
  }

  return {
    findings,
    nonconformingLevels: [...nonconforming].sort(),
    skipped,
    suppressed,
    notFailures,
  };
}
