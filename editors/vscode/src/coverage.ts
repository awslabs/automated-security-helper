// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Answers "did the scan cover what was asked", which is a different question from
 * "was anything found", from `ash_aggregated_results.json`.
 *
 * WHERE `coverage_complete` LIVES, AND WHY THIS FILE COMPUTES IT
 *
 * `coverage_complete` is not a field of `ash_aggregated_results.json`. Nothing in
 * the `AshAggregatedResults` model (automated_security_helper/models/asharp_model.py)
 * carries it. ASH computes it on demand, for its MCP payloads, as
 *
 *     not coverage_has_gap(scan_incompleteness(results, gate=True).to_payload())
 *
 * in automated_security_helper/core/resource_management/scan_tracking.py
 * (`get_scan_results`, via `assess_coverage`) and scan_registry.py. Every input
 * that expression reads IS persisted in the results file, so this module asks the
 * same five questions of the file and returns the same field names
 * `ScanIncompleteness.to_payload()` uses
 * (automated_security_helper/interactions/run_ash_scan.py):
 *
 *   incomplete_scanners      a scanner whose status is not PASSED, FAILED or
 *                            SKIPPED (today ERROR and MISSING), or one that ran and
 *                            lost some of its targets (`targets_failed > 0` under
 *                            `additional_reports[<scanner>]`). A counter pair ASH cannot
 *                            read (a failure count with no attempt count, a non-integer
 *                            or negative count) grades the scanner ERROR.
 *   no_scanner_ran           scanners were recorded and none is PASSED or FAILED,
 *                            or none were recorded while `metadata.expected_scanners`
 *                            says the scan phase ran.
 *   incomplete_converters    a converter row that is not excluded and either
 *                            records a `failure` or has `dependencies_satisfied:
 *                            false` with candidate inputs.
 *   unevaluated_rules        an error-level `toolExecutionNotifications` entry,
 *                            unless every notApplicable result for its rule is
 *                            suppressed.
 *   stale_content_databases  an error-level `ASH-CONTENT-DB-STALE`
 *                            `toolConfigurationNotifications` entry with a non-empty
 *                            `content_database` record. One ASH cannot read back is
 *                            kept as stale, of unknown age, named "unknown" when the
 *                            record carries no name.
 *
 * gate=True on purpose, matching `assess_coverage`: an operator who turned
 * `fail_on_incomplete_scanners` off has accepted the gap, not asked to be told
 * there was none, so a scan that exited 0 can still be incomplete.
 *
 * WHAT WOULD MAKE THIS DRIFT, AND WHAT HOLDS IT
 *
 * It is a second reader of the same rule, so it can disagree with ASH. The fixtures
 * under test/fixtures/coverage-cases/ carry the verdict ASH's own `assess_coverage`
 * reaches on each one, recorded in cases.json, and three suites read that file:
 * test/coverage.test.ts asserts this module agrees,
 * tests/unit/test_vscode_coverage_parity.py asserts ASH does, and the JetBrains
 * plugin's AshCoverageParityTest asserts AshScannerStatus.kt does. A change on
 * any side that moves a verdict fails one of them.
 *
 * Known narrowing: scanner statuses are read from the persisted `scanner_results`,
 * which ASH rewrites from `get_unified_scanner_metrics` before writing the file, so
 * the status here is the one the operator was shown. A stale database's row is
 * reported only under `stale_content_databases`, as `scan_incompleteness` does.
 */

/** Statuses that mean the scanner reached a verdict or was not selected. */
const COMPLETE_SCANNER_STATUSES: ReadonlySet<string> = new Set(['PASSED', 'FAILED', 'SKIPPED']);

/** Statuses that mean the scanner executed and reached a verdict. */
const RAN_SCANNER_STATUSES: ReadonlySet<string> = new Set(['PASSED', 'FAILED']);

/** `STALE_NOTIFICATION_ID` in automated_security_helper/utils/content_db_staleness.py. */
export const STALE_CONTENT_DB_NOTIFICATION_ID = 'ASH-CONTENT-DB-STALE';

/** The file ASH writes beside `reports/`, in the output directory. */
export const AGGREGATED_RESULTS_FILE = 'ash_aggregated_results.json';

export interface IncompleteScanner {
  readonly scanner: string;
  readonly status: string;
  /** `missing_dependencies`, `error`, `partial_coverage` or `unrecognized_status`. */
  readonly reason: string;
  /** The status, followed by the unevaluated-target counts for a partial loss. */
  readonly detail: string;
}

export interface IncompleteConverter {
  readonly converter: string;
  readonly reason: string;
}

/** The fields of `ScanIncompleteness.to_payload()`, plus `coverage_complete`. */
export interface CoverageAssessment {
  readonly coverage_complete: boolean;
  readonly incomplete_scanners: readonly IncompleteScanner[];
  readonly no_scanner_ran: boolean;
  readonly incomplete_converters: readonly IncompleteConverter[];
  readonly unevaluated_rules: readonly string[];
  /** Database names, sorted. */
  readonly stale_content_databases: readonly string[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function records(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? value.filter(isRecord) : [];
}

/** An integer that is not a JSON boolean. `true` must never read as one target. */
function asCount(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isInteger(value) ? value : undefined;
}

/** `getattr(level, "value", level)` for a JSON value: the string, or undefined. */
function asText(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

/**
 * pydantic's lax bool, which is what a `ConverterStatusInfo` field holds once ASH has
 * loaded the file: a boolean, 0 or 1, or one of its accepted words in any case.
 * Undefined for anything else, a value pydantic would reject.
 */
function asPydanticBool(value: unknown): boolean | undefined {
  if (typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number') {
    return value === 0 ? false : value === 1 ? true : undefined;
  }
  if (typeof value === 'string') {
    const word = value.toLowerCase();
    if (['0', 'off', 'f', 'false', 'n', 'no'].includes(word)) {
      return false;
    }
    if (['1', 'on', 't', 'true', 'y', 'yes'].includes(word)) {
      return true;
    }
  }
  return undefined;
}

/**
 * pydantic's lax int: a whole number written as an integer, a float or a numeric
 * string, or a boolean as 1 or 0. Undefined for anything else.
 */
function asPydanticInt(value: unknown): number | undefined {
  if (typeof value === 'boolean') {
    return value ? 1 : 0;
  }
  const number =
    typeof value === 'number'
      ? value
      : typeof value === 'string' && value.trim() !== ''
        ? Number(value.trim())
        : Number.NaN;
  return Number.isInteger(number) ? number : undefined;
}

/**
 * A timestamp ASH's `parse_timestamp` accepts: `datetime.fromisoformat` after every
 * `Z` becomes `+00:00`, refused without a zone. The union of the forms Python 3.10
 * through 3.14 accept, measured by running ASH's own function under each interpreter
 * over 16,642 generated strings; the JetBrains plugin's AshScannerStatus.TIMESTAMP is
 * the same pattern. Field ranges are not checked, so an hour of 25, which ASH refuses
 * and skips, is counted here, toward a gap.
 */
const CLOCK = String.raw`\d{2}(:\d{2}(:\d{2})?|\d{2}(\d{2})?)?([.,]\d+)?`;
const TIMESTAMP = new RegExp(
  String.raw`^(\d{4}-\d{2}-\d{2}|\d{8}|\d{4}-W\d{2}(-\d)?|\d{4}W\d{2}\d?)[^Z]` + `${CLOCK}(Z|[+-]${CLOCK})$`,
  'u',
);

function isTimestamp(value: unknown): boolean {
  return typeof value === 'string' && TIMESTAMP.test(value.trim());
}

/**
 * Python truthiness for a JSON value, which is what `if failure:` tests. It differs
 * from JavaScript's on exactly the empty array and the empty object.
 */
function isTruthy(value: unknown): boolean {
  if (Array.isArray(value)) {
    return value.length > 0;
  }
  if (isRecord(value)) {
    return Object.keys(value).length > 0;
  }
  return Boolean(value);
}

function reasonFor(status: string): string {
  if (status === 'MISSING') {
    return 'missing_dependencies';
  }
  if (status === 'ERROR') {
    return 'error';
  }
  return COMPLETE_SCANNER_STATUSES.has(status) ? 'partial_coverage' : 'unrecognized_status';
}

/**
 * What the counters a scanner wrote say. `unusable` is ASH's poisoned pair
 * (`UNUSABLE_COUNTERS`): the scanner made a coverage claim nobody can read.
 */
interface TargetCounts {
  readonly attempted: number | undefined;
  readonly failed: number;
  readonly unusable: boolean;
}

/**
 * `(attempted, failed)` summed over every target report a scanner wrote. Mirrors
 * `target_counts` in automated_security_helper/core/unified_metrics.py: an absent
 * attempt count beside a zero or absent failure count is the absence of a claim, not
 * 0, but a counter that is present and unusable (not an integer, negative, a failure
 * count with no attempt count, an attempt count above zero with no failure count, or
 * more failures than attempts) poisons the pair, which ASH grades ERROR.
 */
function targetCounts(additionalReports: unknown, scanner: string): TargetCounts {
  const poisoned: TargetCounts = { attempted: undefined, failed: 0, unusable: true };
  if (!isRecord(additionalReports) || !isRecord(additionalReports[scanner])) {
    return { attempted: undefined, failed: 0, unusable: false };
  }
  let attempted: number | undefined;
  let failed = 0;
  for (const target of Object.values(additionalReports[scanner] as Record<string, unknown>)) {
    if (!isRecord(target)) {
      continue;
    }
    const rawAttempted = target.targets_attempted ?? undefined;
    const rawFailed = target.targets_failed ?? undefined;
    if (rawAttempted === undefined && rawFailed === undefined) {
      continue;
    }
    const tried = asCount(rawAttempted);
    const lost = asCount(rawFailed);
    if ((tried === undefined && rawAttempted !== undefined) || (lost === undefined && rawFailed !== undefined)) {
      return poisoned;
    }
    if ((tried !== undefined && tried < 0) || (lost !== undefined && lost < 0)) {
      return poisoned;
    }
    if (tried === undefined) {
      if (lost === 0) {
        // The zero default beside no attempt claim: still no claim.
        continue;
      }
      return poisoned;
    }
    if (lost === undefined && tried > 0) {
      return poisoned;
    }
    if (lost !== undefined && lost > tried) {
      return poisoned;
    }
    attempted = (attempted ?? 0) + tried;
    failed += lost ?? 0;
  }
  return { attempted, failed, unusable: false };
}

/** `(attempted, failed)` when the scanner ran and lost some of its targets, else undefined. */
function partialCoverage(counts: TargetCounts): { attempted: number; failed: number } | undefined {
  if (counts.attempted === undefined || counts.failed <= 0) {
    return undefined;
  }
  return { attempted: counts.attempted, failed: counts.failed };
}

/**
 * The name `_unreadable_record` gives a record it cannot read back: the record's own
 * name when it carries a truthy one, else "unknown".
 */
function unreadableName(record: unknown): string {
  if (isRecord(record) && isTruthy(record.name)) {
    const name = record.name;
    return typeof name === 'string' ? name : JSON.stringify(name);
  }
  return 'unknown';
}

function staleDatabases(sarif: unknown): string[] {
  const names = new Set<string>();
  for (const run of records(isRecord(sarif) ? sarif.runs : undefined)) {
    for (const invocation of records(run.invocations)) {
      for (const notification of records(invocation.toolConfigurationNotifications)) {
        const descriptor = isRecord(notification.descriptor) ? notification.descriptor : {};
        if (descriptor.id !== STALE_CONTENT_DB_NOTIFICATION_ID || notification.level !== 'error') {
          continue;
        }
        const properties = isRecord(notification.properties) ? notification.properties : {};
        const record = properties.content_database;
        // A falsy record (absent, null, empty) is skipped, as `stale_content_databases`
        // skips it. Any other record ASH cannot read (no `measured_at` timestamp, or a
        // `built` that is not one) is kept as a stale database of unknown age, named by
        // the record or "unknown", as `_unreadable_record` does.
        if (!isTruthy(record)) {
          continue;
        }
        const readable =
          isRecord(record) && isTimestamp(record.measured_at) && !(isTruthy(record.built) && !isTimestamp(record.built));
        names.add(readable ? (asText((record as Record<string, unknown>).name) ?? '') : unreadableName(record));
      }
    }
  }
  return [...names].sort();
}

function unevaluatedRules(sarif: unknown): string[] {
  const reported = new Set<string>();
  for (const run of records(isRecord(sarif) ? sarif.runs : undefined)) {
    const hasResult = new Set<string>();
    const unsuppressed = new Set<string>();
    for (const result of records(run.results)) {
      if (result.kind !== 'notApplicable') {
        continue;
      }
      const ruleId = asText(result.ruleId) ?? '';
      hasResult.add(ruleId);
      if (!Array.isArray(result.suppressions) || result.suppressions.length === 0) {
        unsuppressed.add(ruleId);
      }
    }
    for (const invocation of records(run.invocations)) {
      for (const notification of records(invocation.toolExecutionNotifications)) {
        if (notification.level !== 'error') {
          continue;
        }
        const associated = isRecord(notification.associatedRule) ? notification.associatedRule : {};
        const ruleId = asText(associated.id);
        if (ruleId !== undefined && ruleId !== '') {
          if (hasResult.has(ruleId) && !unsuppressed.has(ruleId)) {
            continue;
          }
          reported.add(ruleId);
          continue;
        }
        const message = isRecord(notification.message) ? asText(notification.message.text) : undefined;
        const text = (message ?? '').trim();
        reported.add(text === '' ? 'an unnamed rule' : text);
      }
    }
  }
  return [...reported].sort();
}

function incompleteConverters(converterResults: unknown): IncompleteConverter[] {
  const listed: IncompleteConverter[] = [];
  if (!isRecord(converterResults)) {
    return listed;
  }
  for (const [name, row] of Object.entries(converterResults)) {
    // Read as pydantic coerces a `ConverterStatusInfo` row: `"true"` is excluded, a
    // whitespace-only failure is none, and `"0"` or `0.0` candidate inputs exempt.
    if (!isRecord(row) || asPydanticBool(row.excluded) === true) {
      continue;
    }
    // A failure that is not a string or null, or a dependencies_satisfied that is not a
    // pydantic bool, makes the file one ASH's model rejects: read toward a gap.
    const failure = typeof row.failure === 'string' ? row.failure.trim() : row.failure;
    const unsatisfied =
      'dependencies_satisfied' in row && asPydanticBool(row.dependencies_satisfied) !== true;
    if (typeof failure === 'string' ? failure !== '' : failure !== undefined && failure !== null) {
      listed.push({
        converter: name,
        reason: typeof failure === 'string' ? failure : JSON.stringify(failure),
      });
    } else if (unsatisfied) {
      if (asPydanticInt(row.candidate_inputs) === 0) {
        continue;
      }
      listed.push({ converter: name, reason: 'dependencies unavailable, so it never ran' });
    }
  }
  return listed;
}

/**
 * The coverage verdict for one parsed `ash_aggregated_results.json`, or undefined
 * when the document is not a results object at all. Undefined means "cannot
 * tell", and the caller must say so rather than treat it as complete.
 */
export function assessCoverage(document: unknown): CoverageAssessment | undefined {
  if (!isRecord(document) || !isRecord(document.metadata)) {
    return undefined;
  }
  const stale = staleDatabases(document.sarif);
  const scannerResults = isRecord(document.scanner_results) ? document.scanner_results : {};

  const observed: [string, string][] = Object.keys(scannerResults)
    .sort()
    .map((name) => {
      const entry = scannerResults[name];
      const status = isRecord(entry) ? asText(entry.status) : undefined;
      // An unreadable status is not a passing one. ASH defaults an empty status to
      // PASSED only when its own statistics say the scanner ran clean, which this
      // file cannot re-derive, so it is reported as unrecognized.
      return [name, status ?? 'UNREADABLE'];
    })
    // A scanner whose counters are poisoned is graded ERROR whatever its row says, as
    // `get_unified_scanner_metrics` does: it made a coverage claim nobody can read.
    .map(([name, status]): [string, string] =>
      targetCounts(document.additional_reports, name).unusable ? [name, 'ERROR'] : [name, status],
    );

  const incomplete: IncompleteScanner[] = [];
  for (const [scanner, status] of observed) {
    const shortfall = partialCoverage(targetCounts(document.additional_reports, scanner));
    const statusIncomplete = !COMPLETE_SCANNER_STATUSES.has(status);
    if (shortfall === undefined) {
      if (statusIncomplete) {
        incomplete.push({ scanner, status, reason: reasonFor(status), detail: status });
      }
      continue;
    }
    const detail =
      statusIncomplete && shortfall.failed >= shortfall.attempted
        ? status
        : `${status} (${shortfall.failed} of ${shortfall.attempted} targets unevaluated)`;
    incomplete.push({ scanner, status, reason: reasonFor(status), detail });
  }

  const expected = Array.isArray(document.metadata.expected_scanners)
    ? document.metadata.expected_scanners
    : [];
  const noScannerRan =
    observed.length === 0
      ? expected.length > 0
      : !observed.some(([, status]) => RAN_SCANNER_STATUSES.has(status));

  const converters = incompleteConverters(document.converter_results);
  const rules = unevaluatedRules(document.sarif);

  return {
    coverage_complete: !(
      incomplete.length > 0 ||
      noScannerRan ||
      converters.length > 0 ||
      rules.length > 0 ||
      stale.length > 0
    ),
    incomplete_scanners: incomplete,
    no_scanner_ran: noScannerRan,
    incomplete_converters: converters,
    unevaluated_rules: rules,
    stale_content_databases: stale,
  };
}

/** Parses the file's text. Undefined for text that is not JSON. */
export function assessCoverageText(text: string): CoverageAssessment | undefined {
  let document: unknown;
  try {
    document = JSON.parse(text) as unknown;
  } catch {
    return undefined;
  }
  return assessCoverage(document);
}

/** One line per gap, for a notification and the output channel. Empty when complete. */
export function describeGaps(assessment: CoverageAssessment): string[] {
  const lines: string[] = [];
  for (const row of assessment.incomplete_scanners) {
    lines.push(`scanner ${row.scanner}: ${row.detail}`);
  }
  if (assessment.no_scanner_ran) {
    lines.push('no scanner ran to a verdict, so the scan measured nothing');
  }
  for (const row of assessment.incomplete_converters) {
    lines.push(`converter ${row.converter}: ${row.reason}`);
  }
  for (const rule of assessment.unevaluated_rules) {
    lines.push(`rule not evaluated: ${rule}`);
  }
  for (const name of assessment.stale_content_databases) {
    lines.push(`stale content database: ${name}`);
  }
  return lines;
}
