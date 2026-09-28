// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/**
 * Answering "did what I asked for actually run", which is a different question
 * from "was anything found".
 *
 * THE FALSE-CLEAN THIS EXISTS FOR. A selected scanner can be MISSING -- selected,
 * dependencies unavailable, never ran -- and `fail_on_incomplete_scanners` defaults
 * FALSE (automated_security_helper/config/ash_config.py), deliberately, so that a
 * host legitimately lacking a tool keeps its exit codes. So if the scanners that
 * DID run found nothing actionable, ASH exits 0, and an editor that reads only the
 * exit code paints an empty Problems panel over a scan where most scanners never
 * ran. The exit code is not wrong; it is answering the other question.
 *
 * WHERE THE SIGNAL IS, AND WHERE IT IS NOT -- measured, because the obvious answer
 * is wrong twice over.
 *
 * It was suggested that `sarif.runs[].invocations[].executionSuccessful` carries
 * this. It does not, for two independent reasons:
 *
 *   1. A FAILED SCANNER CONTRIBUTES NO INVOCATION AT ALL. In
 *      automated_security_helper/base/scanner_plugin.py the empty-results branch at
 *      :664-677 returns `_handle_empty_results()` -- a SarifReport with `runs=[]` --
 *      and `_inject_invocation`, the only place `executionSuccessful` is computed
 *      (:436), is at :682, AFTER it. So a scanner that fails writes no
 *      `executionSuccessful: false`; it writes nothing. The repository's own
 *      FOLLOWUPS.md records the same consequence independently.
 *
 *   2. ABSENCE FROM THE INVOCATION LIST DOES NOT MEAN FAILURE. Measured on
 *      tests/test_data/outputs/ash_aggregated_results.json: 9 scanners in
 *      `additional_reports`, but only 7 invocations and 7 `tool.extensions` --
 *      and the two missing ones, npm-audit and syft, are both PASSED. They have no
 *      invocation because they found nothing. So counting invocations against a
 *      roster would report two healthy scanners as failures.
 *
 * The authoritative signal is `metadata.scanner_status` in
 * `ash_aggregated_results.json`: one entry per selected scanner, carrying `status`,
 * `dependencies_satisfied` and `excluded`. That file is NOT the one this extension
 * reads for findings -- it sits beside it in the output directory -- which is why
 * this module exists rather than the check living in sarif.ts.
 *
 * `executionSuccessful: false` is still read, but ONLY as a supplement, and a real
 * ASH 3.7.0 run on a host missing most scanner tools has since proved that it cannot
 * be the mechanism:
 *
 *     detect-secrets   status=FAILED    executionSuccessful=TRUE
 *     cdk-nag          status=MISSING   no invocation at all
 *     8 invocations for 10 scanners
 *
 * The field reads TRUE for a scanner ASH itself marks FAILED. So it does not mean
 * what a SARIF consumer would reasonably assume, and a completeness check built on
 * it would have called that run complete. It is kept because a `false` is still
 * worth reporting when it appears; nothing is inferred from its absence.
 */

/**
 * Statuses that mean the scanner reached a verdict, mirroring
 * `_COMPLETE_SCANNER_STATUSES` at
 * automated_security_helper/interactions/run_ash_scan.py:238-244.
 *
 * SKIPPED is complete because it means "not selected". Note the caveat recorded at
 * :252-258 of that file: a per-scanner tolerance of SKIPPED cannot answer whether
 * the SET measured anything, since every entry being SKIPPED passes each individual
 * check while the run has shown the target to be neither clean nor dirty. That is
 * what `allSkipped` below is for.
 */
const COMPLETE_STATUSES: ReadonlySet<string> = new Set([
  'PASSED',
  'FAILED',
  'SKIPPED',
]);

/** One scanner that did not reach a verdict. */
export interface IncompleteScanner {
  readonly name: string;
  /** `ERROR` (ran and failed) or `MISSING` (selected, never ran). */
  readonly status: string;
  readonly dependenciesSatisfied: boolean | undefined;
}

export interface ScannerCompleteness {
  /** Scanners in the roster. */
  readonly total: number;
  readonly incomplete: readonly IncompleteScanner[];
  /**
   * Every scanner was SKIPPED, so nothing was measured at all. Distinguished from
   * `incomplete` being empty, which is the healthy case.
   */
  readonly allSkipped: boolean;
  /** Which key the roster was read from. Observable so a test can pin it. */
  readonly source: 'scanner_results' | 'metadata.scanner_status';
}

/**
 * Where a roster can live, in preference order.
 *
 * TWO KEYS BECAUSE ASH MOVED IT, and reading one makes the extension silently
 * version-specific. Measured:
 *
 *   * `scanner_results` is the DECLARED model field --
 *     `Dict[str, ScannerTargetStatusInfo]` at
 *     automated_security_helper/models/asharp_model.py:505, inside
 *     `class AshAggregatedResults` (:477), so it sits at the TOP LEVEL of the
 *     document. It is populated by ASH 3.7.0 and is ABSENT -- the key does not
 *     exist -- from the committed 3.0.0 fixture.
 *   * `metadata.scanner_status` is NOT in the models at all; it is written by
 *     helpers under `cli/`. It carries 9 entries in the committed 3.0.0 fixture.
 *
 * So the declared field is missing from the fixture and the present field is not in
 * the schema, and an arm that reads either one alone works only against the version
 * it happened to test.
 *
 * `scanner_results` is preferred when both are populated, because it is the field
 * the model declares.
 *
 * The two entry shapes are IDENTICAL, which is what makes this cheap:
 * `ScannerTargetStatusInfo` at :239-253 declares `status`, `dependencies_satisfied`
 * and `excluded` -- exactly the keys the fixture's `scanner_status` entries carry.
 * One parser serves both.
 */
const ROSTER_LOCATIONS: readonly {
  readonly source: ScannerCompleteness['source'];
  readonly read: (document: Record<string, unknown>) => unknown;
}[] = [
  { source: 'scanner_results', read: (d) => d['scanner_results'] },
  {
    source: 'metadata.scanner_status',
    read: (d) => (isRecord(d['metadata']) ? d['metadata']['scanner_status'] : undefined),
  },
];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Reads `metadata.scanner_status` out of an aggregated results document.
 *
 * Returns undefined when the document has no roster -- an older ASH, or a bare
 * SARIF copied without its sibling. Undefined means "cannot tell", and the caller
 * must report that rather than treating it as "all fine": a completeness check that
 * silently answers yes when it has no data is the shape of the defect it is here to
 * prevent.
 */
export function parseScannerStatus(text: string): ScannerCompleteness | undefined {
  let document: unknown;
  try {
    document = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (!isRecord(document)) {
    return undefined;
  }

  // First POPULATED location wins. An empty roster is treated as absent: it
  // measured nothing, so reporting it as complete would be the defect this module
  // exists to prevent.
  let roster: Record<string, unknown> | undefined;
  let source: ScannerCompleteness['source'] | undefined;
  for (const location of ROSTER_LOCATIONS) {
    const candidate = location.read(document);
    if (isRecord(candidate) && Object.keys(candidate).length > 0) {
      roster = candidate;
      source = location.source;
      break;
    }
  }
  if (roster === undefined || source === undefined) {
    return undefined;
  }

  const names = Object.keys(roster);

  const incomplete: IncompleteScanner[] = [];
  let skipped = 0;

  for (const name of names) {
    const entry = roster[name];
    // A roster entry that is not an object cannot be read. Counted as incomplete
    // rather than ignored -- an unreadable status is not a passing one.
    if (!isRecord(entry)) {
      incomplete.push({
        name,
        status: 'UNREADABLE',
        dependenciesSatisfied: undefined,
      });
      continue;
    }
    const raw = entry['status'];
    const status = typeof raw === 'string' ? raw.toUpperCase() : 'UNREADABLE';
    if (status === 'SKIPPED') {
      skipped += 1;
    }
    if (COMPLETE_STATUSES.has(status)) {
      continue;
    }
    const satisfied = entry['dependencies_satisfied'];
    incomplete.push({
      name,
      status,
      dependenciesSatisfied:
        typeof satisfied === 'boolean' ? satisfied : undefined,
    });
  }

  return {
    total: names.length,
    incomplete,
    allSkipped: skipped === names.length,
    source,
  };
}

/** One invocation that reported itself unsuccessful. */
export interface FailedInvocation {
  readonly exitCode: number | undefined;
  /**
   * `exitCodeDescription`, the scanner's own diagnostic text.
   *
   * 3.0.0-ERA AND LIKELY ABSENT. It appears in the committed fixture (a
   * psych-3.3.4 gem resolution warning from cfn-nag) and, per a real 3.7.0 run,
   * ASH 3.7.0 does not emit it at all. Its absence is therefore NOT a bug to chase.
   * Kept because it costs one field and is genuinely useful where present.
   *
   * Surfaced only for a FAILED invocation. The fixture carries it on a SUCCESSFUL
   * one, so reporting it unconditionally would be noise on a healthy scan -- which
   * also means this branch is doubly unlikely to fire: it needs both a `false`
   * flag and a field that current ASH omits.
   */
  readonly description: string | undefined;
}

/**
 * Invocations whose `executionSuccessful` is explicitly false.
 *
 * NOT keyed on `exitCode`. Measured: all 7 invocations in the real report are
 * `executionSuccessful: true`, and several carry `exitCode: 1`, because a
 * scanner-level 1 means "found vulnerabilities" for grype and cfn-nag. Treating a
 * non-zero invocation exit code as failure would report a healthy scan as broken.
 */
export function failedInvocations(sarifText: string): readonly FailedInvocation[] {
  let document: unknown;
  try {
    document = JSON.parse(sarifText);
  } catch {
    return [];
  }
  if (!isRecord(document) || !Array.isArray(document['runs'])) {
    return [];
  }

  const failures: FailedInvocation[] = [];
  for (const run of document['runs']) {
    if (!isRecord(run) || !Array.isArray(run['invocations'])) {
      continue;
    }
    for (const invocation of run['invocations']) {
      if (!isRecord(invocation)) {
        continue;
      }
      // Strictly false. An absent `executionSuccessful` is not a claim of failure,
      // and per the module comment a failing scanner omits the invocation entirely
      // rather than setting this to false.
      if (invocation['executionSuccessful'] !== false) {
        continue;
      }
      const code = invocation['exitCode'];
      const description = invocation['exitCodeDescription'];
      failures.push({
        exitCode: typeof code === 'number' ? code : undefined,
        description:
          typeof description === 'string' && description.trim().length > 0
            ? description.trim()
            : undefined,
      });
    }
  }
  return failures;
}
