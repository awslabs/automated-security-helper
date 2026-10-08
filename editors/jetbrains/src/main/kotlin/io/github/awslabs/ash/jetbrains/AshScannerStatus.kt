// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.google.gson.JsonSyntaxException

/**
 * Per-scanner completion status, so an empty Problems panel can be told apart from a panel that is
 * empty because nothing ran.
 *
 * THE FALSE-CLEAN PATH THIS EXISTS TO CLOSE. A selected scanner whose tool is not installed is
 * MISSING -- the ordinary state of a fresh machine or an air-gapped host. ASH now exits 1 for that
 * by default (`fail_on_incomplete_scanners` defaults to true, and the exit is ScanIncompleteExit),
 * and [AshScanRunner] treats exit 1 with a report as a PARTIAL scan. This file is what names the
 * scanners behind that verdict. It is also the only signal left when the gate is turned off in
 * the project's configuration: ASH then exits 0 over a scan that mostly did not happen, and a
 * consumer reading only the exit code and the findings paints an empty panel as a clean one.
 *
 * THE SIGNAL IS NOT IN `reports/ash.sarif`, AND IT IS NOT `invocations[].executionSuccessful`.
 * Measured on a real ASH 3.7.0 run over a host missing most scanner tools:
 *
 *   scanner_results:  cdk-nag MISSING, cfn-nag SKIPPED, detect-secrets FAILED, 7 others PASSED
 *   invocations:      8 entries, executionSuccessful TRUE on every single one
 *
 * So a FAILED scanner reports a successful invocation, and a MISSING one has no invocation at all --
 * cdk-nag, npm-audit and syft appear in `scanner_results` with no corresponding invocation. Reading
 * `executionSuccessful` would have found nothing wrong and reported the run as complete.
 * `exitCodeDescription` is absent from 3.7.0's invocations entirely, though the 3.0.0 fixture has it.
 *
 * The status lives in `ash_aggregated_results.json`, a sibling of `reports/`, which ASH writes even
 * when `--output-formats sarif` asks for nothing else. That is a second file, so this is a second
 * read -- and its ABSENCE is reported rather than assumed to mean "everything ran".
 *
 * A SCANNER ROSTER IS NOT THE WHOLE COVERAGE VERDICT. ASH's `coverage_complete` (MCP payloads,
 * `scan_tracking.assess_coverage`) is `not coverage_has_gap(scan_incompleteness(results,
 * gate=True))`, and that asks five questions, every input to which is persisted in this file:
 *
 *   incomplete scanners      not PASSED, FAILED or SKIPPED, or ran and lost some of its targets
 *                            (`targets_failed > 0` under `additional_reports[<scanner>]`)
 *   no scanner ran           none reached a verdict, or none were recorded while
 *                            `metadata.expected_scanners` says the scan phase ran
 *   incomplete converters    a converter row that is not excluded and records a `failure`, or
 *                            has `dependencies_satisfied: false` with candidate inputs
 *   unevaluated rules        an error-level `toolExecutionNotifications` entry, unless every
 *                            notApplicable result for its rule is suppressed
 *   stale content databases  an error-level `ASH-CONTENT-DB-STALE` configuration notification
 *
 * The last three have no scanner row. With `fail_on_incomplete_scanners: false` ASH exits 0 over
 * a stale database or an unevaluated rule, so a reader of the roster alone reports such a scan
 * complete. This reads all five, as editors/vscode/src/coverage.ts does, and AshCoverageParityTest
 * holds it to the verdicts in editors/vscode/test/fixtures/coverage-cases/cases.json, which
 * tests/unit/test_vscode_coverage_parity.py holds ASH to.
 *
 * Two deliberate differences from ASH, both toward reporting a gap: a status file with no roster
 * and no `expected_scanners` is "completeness unknown" here (ASH reads it as a convert-only run),
 * and statuses are compared case-insensitively.
 */
object AshScannerStatus {

    /** Where the status file sits, relative to `--output-dir`. */
    const val RELATIVE_PATH = "ash_aggregated_results.json"

    /**
     * Statuses that mean the scanner reached a verdict, spelled to match ASH's own
     * `_COMPLETE_SCANNER_STATUSES` at `interactions/run_ash_scan.py`.
     *
     * SKIPPED counts as complete because it means "not selected", not "failed to run" -- ASH's own
     * comment beside that set notes that per-entry tolerance of SKIPPED cannot answer whether the SET
     * measured anything, but per scanner it is not an incompleteness. The remaining members of
     * `ScannerStatus` (`enums.py`) are ERROR and MISSING, which are.
     */
    private val COMPLETE = setOf("PASSED", "FAILED", "SKIPPED")

    /**
     * The statuses that mean a scanner actually examined the target and reached a verdict.
     *
     * NARROWER THAN [COMPLETE], and deliberately, mirroring ASH's own note at
     * `run_ash_scan.py`: SKIPPED means "not selected", so it is complete per scanner while
     * saying nothing about whether the SET measured anything. A run where every scanner is SKIPPED has
     * an empty incomplete set and has shown the target to be neither clean nor dirty -- a state a
     * per-scanner complete/incomplete split structurally cannot see.
     */
    private val REACHED_A_VERDICT = setOf("PASSED", "FAILED")

    /**
     * The roster keys, in preference order.
     *
     * TWO KEYS BECAUSE ASH RENAMED IT, and the two are mutually exclusive rather than redundant.
     * Measured: a 3.7.0 report has top-level `scanner_results` and NO `metadata.scanner_status`; the
     * committed 3.0.0 fixture has `metadata.scanner_status` and NO `scanner_results`. Reading only
     * one makes every report of the other vintage report "completeness unknown" -- the safe
     * direction, but needlessly blind.
     */
    private val ROSTER_PATHS = listOf(
        listOf("scanner_results"),
        listOf("metadata", "scanner_status"),
    )

    /**
     * One scanner's roster entry.
     *
     * `status` IS THE ONLY FIELD HERE WORTH TRUSTING, and that was measured rather than assumed. The
     * 3.7.0 roster serializes all eight declared `ScannerTargetStatusInfo` fields plus an undeclared
     * `duration`, so it is genuinely richer than the legacy three-field key -- but two of the extra
     * fields carry no usable information in the observed report:
     *
     *  * `exit_code` IS 0 FOR EVERY SCANNER, including cdk-nag (MISSING) and detect-secrets
     *    (FAILED). Grouped by status: MISSING [0], FAILED [0], SKIPPED [0], PASSED [0] -- not one
     *    non-zero value anywhere. So it cannot distinguish a scanner that never ran from one that
     *    passed, and surfacing it would print "grype (ERROR, exit 0)", which implies the tool exited
     *    cleanly when it never started. DO NOT ADD IT to the warning. The per-target rows under
     *    `additional_reports` carry a different and truer value -- bandit reads exit_code 1 there
     *    while the roster says 0 -- so the roll-up loses it.
     *  * `dependencies_satisfied` WAS TRUE FOR A MISSING SCANNER (cdk-nag). It is still read, because
     *    a false value is real information where it appears, but its absence of a false value is not
     *    evidence that dependencies were fine.
     *
     * `finding_count` and `actionable_finding_count` ARE informative (bandit 3/0, detect-secrets
     * 1/1) and are simply not needed for a completeness verdict.
     */
    data class Scanner(
        val name: String,
        val status: String,
        /**
         * False means the scanner's tool was not available. Reported when false, but NOT relied on:
         * observed true on a MISSING scanner, so true says nothing.
         */
        val dependenciesSatisfied: Boolean = true,
        /** Deliberately switched off by configuration, so not a problem to report. */
        val excluded: Boolean = false,
        /**
         * Targets attempted, summed over the scanner's `additional_reports` rows, or null when no
         * row carries a count. Null is the absence of a claim, not zero: most scanners track no
         * per-target outcome, and ASH's `_partial_coverage` reads it the same way.
         */
        val targetsAttempted: Int? = null,
        /** Targets that were not evaluated, summed over the same rows. */
        val targetsFailed: Int = 0,
    ) {
        val isComplete: Boolean get() = status.uppercase() in COMPLETE
        val reachedAVerdict: Boolean get() = status.uppercase() in REACHED_A_VERDICT

        /**
         * The scanner ran and some of its input was not evaluated. A failure count with no
         * attempt count is not a claim, because there is no denominator to state.
         */
        val lostTargets: Boolean get() = targetsAttempted != null && targetsFailed > 0

        /** How this scanner should be described when it is the reason a scan is incomplete. */
        fun describe(): String {
            val why = if (!dependenciesSatisfied) ", dependencies unavailable" else ""
            // A total loss under a status that already says so would only repeat the status.
            val counts = if (lostTargets && (isComplete || targetsFailed < targetsAttempted!!)) {
                ", $targetsFailed of $targetsAttempted targets unevaluated"
            } else {
                ""
            }
            return "$name ($status$counts$why)"
        }
    }

    /** A converter that was meant to run and did not, with ASH's reason. */
    data class Converter(val name: String, val reason: String)

    /**
     * What one report says about scanner completeness.
     *
     * [available] false means the status file could not be read. That is reported to the user rather
     * than treated as "all scanners ran", because the whole point of this type is to stop an absence
     * of evidence reading as evidence of completeness.
     */
    data class Report(
        val available: Boolean,
        val scanners: List<Scanner> = emptyList(),
        val unavailableReason: String? = null,
        /** Which roster key supplied this, for the report and for diagnosing a future rename. */
        val source: String? = null,
        /** How many scanners `metadata.expected_scanners` says the scan phase meant to run. */
        val expectedScanners: Int = 0,
        /** Converters that were meant to run and did not, in the file's order. */
        val incompleteConverters: List<Converter> = emptyList(),
        /** Rules that raised instead of reaching a verdict, by id (or message), sorted. */
        val unevaluatedRules: List<String> = emptyList(),
        /** Content databases past their bound under the fail policy, by name, sorted. */
        val staleContentDatabases: List<String> = emptyList(),
    ) {
        val complete: List<Scanner> get() = scanners.filter { it.isComplete && !it.lostTargets }

        /**
         * Scanners that did not complete, or ran and lost some of their targets. An EXCLUDED
         * scanner whose status is incomplete is left out: it was deliberately switched off by
         * configuration, so reporting it as a problem would train the user to ignore this warning.
         */
        val incomplete: List<Scanner>
            get() = scanners.filter { (!it.isComplete && !it.excluded) || it.lostTargets }

        /** Scanners that actually examined the target. See [REACHED_A_VERDICT]. */
        val reachedAVerdict: List<Scanner> get() = scanners.filter { it.reachedAVerdict }

        /**
         * True when no scanner examined the target, even though nothing is individually incomplete.
         *
         * The all-SKIPPED case. A per-scanner split cannot see it, because SKIPPED is a complete
         * status; the set has to be asked separately. Also true when the roster is empty while
         * `metadata.expected_scanners` is not: the scan phase ran and had nothing to run, which
         * ASH's `no_scanner_ran` reports for the same reason.
         */
        val nothingMeasured: Boolean
            get() = available &&
                if (scanners.isEmpty()) expectedScanners > 0 else reachedAVerdict.isEmpty()

        /**
         * A phrase for the scan notification, or null when there is genuinely nothing to say.
         * Plain text: the caller escapes it, because every name in it comes from the report.
         */
        fun describeIncompleteness(): String? {
            val others = describeOtherGaps()
            if (!available) {
                return (
                    listOf(
                        "Scanner completeness is unknown: ${unavailableReason ?: "status file unreadable"}. " +
                            "An empty result list cannot be read as a clean scan.",
                    ) + others
                    ).joinToString(" ")
            }
            // BOTH FACTS, NOT THE FIRST ONE. An earlier version returned the nothing-measured
            // message first and short-circuited, which produced a factually wrong sentence: a run
            // with a single MISSING scanner reported "all 1 are skipped or excluded" when nothing
            // had been skipped. The two conditions are independent -- a run can have incomplete
            // scanners AND have had nothing reach a verdict -- so both are reported when both hold,
            // and the nothing-measured wording no longer asserts a cause it has not established.
            val parts = mutableListOf<String>()
            if (incomplete.isNotEmpty()) {
                val named = incomplete.sortedBy { it.name }.joinToString(", ") { it.describe() }
                parts += "${incomplete.size} of ${scanners.size} scanner(s) did not complete: " +
                    "$named. Findings from those scanners are absent, so this is not a complete " +
                    "answer."
            }
            if (nothingMeasured) {
                parts += if (scanners.isEmpty()) {
                    "No scanner examined this project -- the scan phase expected " +
                        "$expectedScanners and recorded none, so nothing here has been shown " +
                        "to be clean or unclean."
                } else {
                    "No scanner examined this project -- none of the ${scanners.size} " +
                        "reached a verdict, so nothing here has been shown to be clean or unclean."
                }
            }
            parts += others
            return parts.joinToString(" ").ifEmpty { null }
        }

        /** The three gaps that have no scanner row, which the roster cannot show. */
        private fun describeOtherGaps(): List<String> {
            val parts = mutableListOf<String>()
            if (incompleteConverters.isNotEmpty()) {
                val named = incompleteConverters.joinToString(", ") { "${it.name} (${it.reason})" }
                parts += "${incompleteConverters.size} converter(s) did not run: $named. Files " +
                    "they would have converted were not scanned."
            }
            if (unevaluatedRules.isNotEmpty()) {
                parts += "${unevaluatedRules.size} rule(s) were not evaluated: " +
                    "${unevaluatedRules.joinToString(", ")}. What they check is unknown, not clean."
            }
            if (staleContentDatabases.isNotEmpty()) {
                parts += "${staleContentDatabases.size} content database(s) are past their age " +
                    "bound: ${staleContentDatabases.joinToString(", ")}. Anything published since " +
                    "they were built is not reported."
            }
            return parts
        }
    }

    fun parse(jsonText: String): Report {
        val root = try {
            JsonParser.parseString(jsonText)
        } catch (e: JsonSyntaxException) {
            return Report(false, unavailableReason = "status file is not valid JSON: ${e.message}")
        }
        // JsonParser returns JsonNull rather than null for the literal `null`.
        if (!root.isJsonObject) {
            return Report(false, unavailableReason = "status file root is not a JSON object")
        }
        val document = root.asJsonObject
        var roster: JsonObject? = null
        var source: String? = null
        for (path in ROSTER_PATHS) {
            var node: JsonObject? = document
            for (segment in path) {
                node = node?.obj(segment)
            }
            if (node != null && node.size() > 0) {
                roster = node
                source = path.joinToString(".")
                break
            }
        }

        val sarif = document.obj("sarif")
        val expected = document.obj("metadata")?.get("expected_scanners")
            ?.takeIf { it.isJsonArray }?.asJsonArray?.size() ?: 0
        val converters = incompleteConverters(document.obj("converter_results"))
        val rules = unevaluatedRules(sarif)
        val stale = staleDatabases(sarif)

        if (roster == null) {
            // The scan phase ran (it records expected_scanners) and recorded no scanner: that is
            // a known answer, nothing measured, rather than an unreadable file.
            if (expected > 0) {
                return Report(
                    true,
                    source = "metadata.expected_scanners",
                    expectedScanners = expected,
                    incompleteConverters = converters,
                    unevaluatedRules = rules,
                    staleContentDatabases = stale,
                )
            }
            return Report(
                false,
                unavailableReason = "status file has none of " +
                    ROSTER_PATHS.joinToString(" or ") { it.joinToString(".") } +
                    " as a non-empty object, so no scanner reported a status",
                incompleteConverters = converters,
                unevaluatedRules = rules,
                staleContentDatabases = stale,
            )
        }

        val additionalReports = document.obj("additional_reports")
        val scanners = mutableListOf<Scanner>()
        for ((name, element) in roster.entrySet()) {
            val entry = element?.takeIf { it.isJsonObject }?.asJsonObject
            val status = entry?.get("status")
                ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }
                ?.asString
            val (attempted, failed) = targetCounts(additionalReports?.obj(name))
            // An entry with no readable status is INCOMPLETE rather than skipped over: a scanner this
            // cannot classify is a scanner it cannot vouch for. "UNKNOWN" is in neither COMPLETE nor
            // REACHED_A_VERDICT, so it counts against both.
            scanners.add(
                Scanner(
                    name = name,
                    status = status ?: "UNKNOWN",
                    dependenciesSatisfied = entry?.optBoolean("dependencies_satisfied") ?: true,
                    excluded = entry?.optBoolean("excluded") ?: false,
                    targetsAttempted = attempted,
                    targetsFailed = failed,
                ),
            )
        }
        return Report(
            true,
            scanners,
            source = source,
            expectedScanners = expected,
            incompleteConverters = converters,
            unevaluatedRules = rules,
            staleContentDatabases = stale,
        )
    }

    /** `STALE_NOTIFICATION_ID` in automated_security_helper/utils/content_db_staleness.py. */
    const val STALE_CONTENT_DB_NOTIFICATION_ID = "ASH-CONTENT-DB-STALE"

    /**
     * `(attempted, failed)` summed over every target row a scanner wrote under
     * `additional_reports`, as ASH's `target_counts` sums them. Attempted stays null when no row
     * carries a count.
     */
    private fun targetCounts(reports: JsonObject?): Pair<Int?, Int> {
        var attempted: Int? = null
        var failed = 0
        for ((_, element) in reports?.entrySet().orEmpty()) {
            val target = element.takeIf { it.isJsonObject }?.asJsonObject ?: continue
            target.count("targets_attempted")?.let { attempted = (attempted ?: 0) + it }
            failed += target.count("targets_failed") ?: 0
        }
        return attempted to failed
    }

    /**
     * Converters that were meant to run and did not. Excluded rows are skipped; a truthy
     * `failure` (Python truthiness, which is what ASH's `if failure:` tests) is a gap; so is
     * `dependencies_satisfied: false` unless the row says it had nothing to convert.
     */
    private fun incompleteConverters(rows: JsonObject?): List<Converter> {
        val listed = mutableListOf<Converter>()
        for ((name, element) in rows?.entrySet().orEmpty()) {
            val row = element.takeIf { it.isJsonObject }?.asJsonObject ?: continue
            if (row.optBoolean("excluded") == true) continue
            val failure = row.get("failure")
            if (failure != null && truthy(failure)) {
                val reason = failure.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString
                listed += Converter(name, reason ?: failure.toString())
            } else if (row.optBoolean("dependencies_satisfied") == false && row.count("candidate_inputs") != 0) {
                listed += Converter(name, "dependencies unavailable, so it never ran")
            }
        }
        return listed
    }

    /**
     * Error-level execution notifications, by rule id, or by message when the notification names
     * no rule. A rule is not reported when it has notApplicable results and every one of them is
     * suppressed: the operator has accepted that rule's gap.
     */
    private fun unevaluatedRules(sarif: JsonObject?): List<String> {
        val reported = sortedSetOf<String>()
        for (run in sarif.objects("runs")) {
            val hasResult = mutableSetOf<String>()
            val unsuppressed = mutableSetOf<String>()
            for (result in run.objects("results")) {
                if (result.text("kind") != "notApplicable") continue
                val ruleId = result.text("ruleId") ?: ""
                hasResult += ruleId
                val suppressions = result.get("suppressions")
                if (suppressions == null || !suppressions.isJsonArray || suppressions.asJsonArray.isEmpty) {
                    unsuppressed += ruleId
                }
            }
            for (invocation in run.objects("invocations")) {
                for (notification in invocation.objects("toolExecutionNotifications")) {
                    if (notification.text("level") != "error") continue
                    val ruleId = notification.obj("associatedRule")?.text("id")
                    if (!ruleId.isNullOrEmpty()) {
                        if (ruleId !in hasResult || ruleId in unsuppressed) reported += ruleId
                        continue
                    }
                    val message = notification.obj("message")?.text("text")?.trim().orEmpty()
                    reported += message.ifEmpty { "an unnamed rule" }
                }
            }
        }
        return reported.toList()
    }

    /** Names of content databases with an error-level staleness notification, sorted. */
    private fun staleDatabases(sarif: JsonObject?): List<String> {
        val names = sortedSetOf<String>()
        for (run in sarif.objects("runs")) {
            for (invocation in run.objects("invocations")) {
                for (notification in invocation.objects("toolConfigurationNotifications")) {
                    if (notification.obj("descriptor")?.text("id") != STALE_CONTENT_DB_NOTIFICATION_ID) continue
                    if (notification.text("level") != "error") continue
                    val record = notification.obj("properties")?.obj("content_database") ?: continue
                    names += record.text("name") ?: ""
                }
            }
        }
        return names.toList()
    }

    /** Reads a boolean, or null when the field is absent or not a boolean. */
    private fun JsonObject.optBoolean(name: String): Boolean? =
        get(name)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean

    private fun JsonObject.obj(name: String): JsonObject? =
        get(name)?.takeIf { it.isJsonObject }?.asJsonObject

    private fun JsonObject.text(name: String): String? =
        get(name)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString

    /** The object members of the array at `name`, or none. */
    private fun JsonObject?.objects(name: String): List<JsonObject> =
        this?.get(name)?.takeIf { it.isJsonArray }?.asJsonArray
            ?.filter { it.isJsonObject }?.map { it.asJsonObject }
            .orEmpty()

    /**
     * An integer written as one. A JSON boolean is never a count (`true` must not read as one
     * target), and neither is `4.0`, which Python reads as a float and ASH's `isinstance(x, int)`
     * refuses.
     */
    private fun JsonObject.count(name: String): Int? {
        val value = get(name)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isNumber } ?: return null
        return value.asJsonPrimitive.asString.toIntOrNull()
    }

    /** Python's truthiness for a JSON value. */
    private fun truthy(value: JsonElement): Boolean = when {
        value.isJsonNull -> false
        value.isJsonArray -> !value.asJsonArray.isEmpty
        value.isJsonObject -> value.asJsonObject.size() > 0
        value.asJsonPrimitive.isBoolean -> value.asBoolean
        value.asJsonPrimitive.isNumber -> value.asDouble != 0.0
        else -> value.asString.isNotEmpty()
    }

    /** Convenience for the empty case, so callers never have to build a Report by hand. */
    fun unavailable(reason: String): Report = Report(false, unavailableReason = reason)
}
