// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

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
    ) {
        val isComplete: Boolean get() = status.uppercase() in COMPLETE
        val reachedAVerdict: Boolean get() = status.uppercase() in REACHED_A_VERDICT

        /** How this scanner should be described when it is the reason a scan is incomplete. */
        fun describe(): String {
            val why = if (!dependenciesSatisfied) ", dependencies unavailable" else ""
            return "$name ($status$why)"
        }
    }

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
    ) {
        val complete: List<Scanner> get() = scanners.filter { it.isComplete }

        /**
         * Scanners that did not complete. An EXCLUDED scanner is left out: it was deliberately
         * switched off by configuration, so reporting it as a problem would train the user to
         * ignore this warning.
         */
        val incomplete: List<Scanner> get() = scanners.filter { !it.isComplete && !it.excluded }

        /** Scanners that actually examined the target. See [REACHED_A_VERDICT]. */
        val reachedAVerdict: List<Scanner> get() = scanners.filter { it.reachedAVerdict }

        /**
         * True when no scanner examined the target, even though nothing is individually incomplete.
         *
         * The all-SKIPPED case. A per-scanner split cannot see it, because SKIPPED is a complete
         * status; the set has to be asked separately.
         */
        val nothingMeasured: Boolean
            get() = available && scanners.isNotEmpty() && reachedAVerdict.isEmpty()

        /** A phrase for the scan notification, or null when there is genuinely nothing to say. */
        fun describeIncompleteness(): String? {
            if (!available) {
                return "Scanner completeness is unknown: ${unavailableReason ?: "status file unreadable"}. " +
                    "An empty result list cannot be read as a clean scan."
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
                parts += "No scanner examined this project -- none of the ${scanners.size} " +
                    "reached a verdict, so nothing here has been shown to be clean or unclean."
            }
            return parts.joinToString(" ").ifEmpty { null }
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
        var roster: JsonObject? = null
        var source: String? = null
        for (path in ROSTER_PATHS) {
            var node: JsonObject? = root.asJsonObject
            for (segment in path) {
                node = node?.get(segment)?.takeIf { it.isJsonObject }?.asJsonObject
            }
            if (node != null && node.size() > 0) {
                roster = node
                source = path.joinToString(".")
                break
            }
        }
        if (roster == null) {
            return Report(
                false,
                unavailableReason = "status file has none of " +
                    ROSTER_PATHS.joinToString(" or ") { it.joinToString(".") } +
                    " as a non-empty object, so no scanner reported a status",
            )
        }

        val scanners = mutableListOf<Scanner>()
        for ((name, element) in roster.entrySet()) {
            val entry = element?.takeIf { it.isJsonObject }?.asJsonObject
            val status = entry?.get("status")
                ?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }
                ?.asString
            // An entry with no readable status is INCOMPLETE rather than skipped over: a scanner this
            // cannot classify is a scanner it cannot vouch for. "UNKNOWN" is in neither COMPLETE nor
            // REACHED_A_VERDICT, so it counts against both.
            scanners.add(
                Scanner(
                    name = name,
                    status = status ?: "UNKNOWN",
                    dependenciesSatisfied = entry?.optBoolean("dependencies_satisfied") ?: true,
                    excluded = entry?.optBoolean("excluded") ?: false,
                ),
            )
        }
        return Report(true, scanners, source = source)
    }

    /** Reads a boolean, or null when the field is absent or not a boolean. */
    private fun JsonObject.optBoolean(name: String): Boolean? =
        get(name)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isBoolean }?.asBoolean

    /** Convenience for the empty case, so callers never have to build a Report by hand. */
    fun unavailable(reason: String): Report = Report(false, unavailableReason = reason)
}
