// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import com.intellij.notification.NotificationType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The four coverage gaps that are not a scanner's status: lost targets, converters, unevaluated
 * rules and stale content databases, plus the empty-roster scan phase.
 *
 * AshCoverageParityTest holds the verdicts to ASH's on the shared cases. This file covers the
 * shapes those cases do not contain, each of which is a way a malformed or older report could be
 * misread, and pins the wording the notification shows.
 */
class AshScannerStatusGapsTest {

    private val passed = """"scanner_results": {"bandit": {"status": "PASSED"}}"""

    private fun parse(vararg members: String) = AshScannerStatus.parse("{" + members.joinToString(",") + "}")

    private fun sarif(invocation: String, results: String = "[]") =
        """"sarif": {"runs": [{"results": $results, "invocations": [$invocation]}]}"""

    // ---- lost targets ----

    @Test
    fun aPartialLossIsIncompleteAndStatesTheCounts() {
        val report = parse(
            passed,
            """"additional_reports": {"bandit": {"a": {"targets_attempted": 3, "targets_failed": 1},
               "b": {"targets_attempted": 1}, "c": "not a row"}}""",
        )
        assertEquals(listOf("bandit"), report.incomplete.map { it.name })
        assertEquals("bandit (PASSED, 1 of 4 targets unevaluated)", report.incomplete.single().describe())
        assertTrue(report.complete.isEmpty())
    }

    @Test
    fun aTotalLossUnderAnIncompleteStatusDoesNotRepeatItself() {
        val scanner = AshScannerStatus.Scanner("grype", "ERROR", targetsAttempted = 2, targetsFailed = 2)
        assertEquals("grype (ERROR)", scanner.describe())
        val partial = AshScannerStatus.Scanner("grype", "ERROR", targetsAttempted = 3, targetsFailed = 2)
        assertEquals("grype (ERROR, 2 of 3 targets unevaluated)", partial.describe())
        val total = AshScannerStatus.Scanner("grype", "PASSED", targetsAttempted = 2, targetsFailed = 2)
        assertEquals("grype (PASSED, 2 of 2 targets unevaluated)", total.describe())
    }

    @Test
    fun countsThatAreNotIntegersAreNotClaims() {
        // true is not one target, 4.0 is a float to ASH, and a failure with no attempt count has
        // no denominator to state.
        val report = parse(
            passed,
            """"additional_reports": {"bandit": {"a": {"targets_attempted": true, "targets_failed": 1},
               "b": {"targets_attempted": 4.0, "targets_failed": "2"}}}""",
        )
        assertTrue(report.incomplete.isEmpty())
        assertNull(report.describeIncompleteness())
    }

    @Test
    fun anExcludedScannerThatLostTargetsIsStillIncomplete() {
        val report = parse(
            """"scanner_results": {"bandit": {"status": "PASSED"}, "grype": {"status": "MISSING", "excluded": true}}""",
            """"additional_reports": {"grype": {"x": {"targets_attempted": 2, "targets_failed": 1}}}""",
        )
        assertEquals(listOf("grype"), report.incomplete.map { it.name })
    }

    // ---- converters ----

    @Test
    fun aConverterFailureIsAnyValueButAnEmptyStringOrNull() {
        val report = parse(
            passed,
            """"converter_results": {
                "a": {"failure": "raised"},
                "b": {"failure": {"code": 3}},
                "c": {"failure": "", "dependencies_satisfied": false},
                "d": {"failure": 0},
                "e": {"failure": false},
                "f": {"failure": null},
                "g": {"failure": []},
                "h": {"failure": {}},
                "i": {"failure": "raised", "excluded": true},
                "j": {"dependencies_satisfied": false, "candidate_inputs": 0},
                "k": {"failure": 7},
                "l": "not a row"
            }""",
        )
        assertEquals(
            listOf(
                AshScannerStatus.Converter("a", "raised"),
                AshScannerStatus.Converter("b", """{"code":3}"""),
                AshScannerStatus.Converter("c", "dependencies unavailable, so it never ran"),
                // Not a string, so ASH's model rejects the file: each reads as a failure.
                AshScannerStatus.Converter("d", "0"),
                AshScannerStatus.Converter("e", "false"),
                AshScannerStatus.Converter("g", "[]"),
                AshScannerStatus.Converter("h", "{}"),
                AshScannerStatus.Converter("k", "7"),
            ),
            report.incompleteConverters,
        )
        assertTrue(
            report.describeIncompleteness()!!.contains(
                "8 converter(s) did not run: a (raised), b ({\"code\":3}), c (dependencies unavailable, so it never ran), " +
                    "d (0), e (false), g ([]), h ({}), k (7).",
            ),
        )
    }

    @Test
    fun converterFieldsAreCoercedAsPydanticCoercesThem() {
        // What ASH's ConverterStatusInfo holds after loading. Each row is one coercion.
        val report = parse(
            passed,
            """"converter_results": {
                "excluded-word": {"failure": "raised", "excluded": "YES"},
                "excluded-one": {"failure": "raised", "excluded": 1},
                "excluded-junk": {"failure": "raised", "excluded": "maybe"},
                "deps-word": {"dependencies_satisfied": "off"},
                "deps-zero": {"dependencies_satisfied": 0.0},
                "deps-two": {"dependencies_satisfied": 2},
                "deps-true-word": {"dependencies_satisfied": "t"},
                "deps-object": {"dependencies_satisfied": {}},
                "cand-float": {"dependencies_satisfied": false, "candidate_inputs": 0.0},
                "cand-string": {"dependencies_satisfied": false, "candidate_inputs": " 0 "},
                "cand-false": {"dependencies_satisfied": false, "candidate_inputs": false},
                "cand-true": {"dependencies_satisfied": false, "candidate_inputs": true},
                "cand-half": {"dependencies_satisfied": false, "candidate_inputs": 0.5},
                "cand-word": {"dependencies_satisfied": false, "candidate_inputs": "none"},
                "cand-huge": {"dependencies_satisfied": false, "candidate_inputs": 4294967296},
                "blank-failure": {"failure": "   "}
            }""",
        )
        assertEquals(
            listOf(
                "excluded-junk", "deps-word", "deps-zero", "deps-two", "deps-object",
                "cand-true", "cand-half", "cand-word", "cand-huge",
            ),
            report.incompleteConverters.map { it.name },
        )
    }

    // ---- unevaluated rules ----

    @Test
    fun unevaluatedRulesFollowAshsSuppressionRule() {
        val results = """[
            {"kind": "notApplicable", "ruleId": "ALL-SUPPRESSED", "suppressions": [{"kind": "external"}]},
            {"kind": "notApplicable", "ruleId": "ONE-OPEN", "suppressions": [{"kind": "external"}]},
            {"kind": "notApplicable", "ruleId": "ONE-OPEN", "suppressions": []},
            {"kind": "notApplicable", "ruleId": "NO-ARRAY", "suppressions": "x"},
            {"kind": "notApplicable"},
            {"kind": "fail", "ruleId": "FAILED-RESULT", "suppressions": [{"kind": "external"}]},
            "not a result"
        ]"""
        val notifications = listOf("ALL-SUPPRESSED", "ONE-OPEN", "NO-ARRAY", "FAILED-RESULT", "NO-RESULT")
            .joinToString(",") { """{"level": "error", "associatedRule": {"id": "$it"}}""" }
        val report = parse(
            passed,
            sarif(
                """{"toolExecutionNotifications": [$notifications,
                    {"level": "warning", "associatedRule": {"id": "WARNED"}},
                    {"level": "error", "associatedRule": {"id": ""}, "message": {"text": " by message "}},
                    {"level": "error"},
                    {"level": "error", "message": {"text": "   "}}]}""",
                results,
            ),
        )
        assertEquals(
            listOf("FAILED-RESULT", "NO-ARRAY", "NO-RESULT", "ONE-OPEN", "an unnamed rule", "by message"),
            report.unevaluatedRules,
        )
        assertTrue(report.describeIncompleteness()!!.contains("6 rule(s) were not evaluated: FAILED-RESULT,"))
    }

    @Test
    fun aSarifBlockOfTheWrongShapeHasNoRules() {
        for (shape in listOf(""""sarif": "x"""", """"sarif": {"runs": {}}""", """"sarif": {"runs": ["x", {}]}""")) {
            val report = parse(passed, shape)
            assertEquals(shape, emptyList<String>(), report.unevaluatedRules)
            assertEquals(shape, emptyList<String>(), report.staleContentDatabases)
        }
    }

    // ---- stale content databases ----

    @Test
    fun onlyAnErrorLevelStalenessRecordIsAGap() {
        fun stale(id: String, level: String, properties: String) =
            """{"descriptor": {"id": "$id"}, "level": "$level", "properties": $properties}"""
        fun db(name: String) = """{"content_database": {"name": "$name", "measured_at": "2026-10-01T00:00:00Z"}}"""
        val record = db("grype-db")
        val report = parse(
            passed,
            sarif(
                """{"toolConfigurationNotifications": [
                    ${stale("ASH-CONTENT-DB-STALE", "error", record)},
                    ${stale("ASH-CONTENT-DB-STALE", "error", db("a-db"))},
                    ${stale("ASH-CONTENT-DB-STALE", "error", """{"content_database": {"measured_at": "2026-10-01 00:00:00+00:00"}}""")},
                    ${stale("ASH-CONTENT-DB-STALE", "error", """{"content_database": {}}""")},
                    ${stale("ASH-CONTENT-DB-STALE", "error", """{"content_database": {"name": "no-time"}}""")},
                    ${stale("ASH-CONTENT-DB-STALE", "error", """{"content_database": {"name": "naive", "measured_at": "2026-10-01T00:00:00"}}""")},
                    ${stale("ASH-CONTENT-DB-STALE", "error", """{"content_database": {"name": "bad-built", "measured_at": "2026-10-01T00:00:00Z", "built": "yesterday"}}""")},
                    ${stale("ASH-CONTENT-DB-STALE", "error", """{"content_database": {"name": "built", "measured_at": "2026-10-01T00:00:00Z", "built": "2026-01-01T00:00:00.123456789+02:00"}}""")},
                    ${stale("ASH-CONTENT-DB-STALE", "error", """{"content_database": {"name": "num-time", "measured_at": 5}}""")},
                    ${stale("ASH-CONTENT-DB-STALE", "warning", db("warned"))},
                    ${stale("OTHER", "error", db("other"))},
                    ${stale("ASH-CONTENT-DB-STALE", "error", """{"content_database": "x"}""")},
                    {"level": "error", "properties": $record}]}""",
            ),
        )
        // Unreadable to ASH, and skipped: the empty record, no measured_at, a measured_at with no
        // zone or not a string, and a built that is not a timestamp.
        assertEquals(listOf("", "a-db", "built", "grype-db"), report.staleContentDatabases)
        assertTrue(
            report.describeIncompleteness()!!.contains(
                "4 content database(s) are past their age bound: , a-db, built, grype-db.",
            ),
        )
    }

    @Test
    fun everyTimestampFormAshAcceptsIsReadable() {
        // Forms Python's fromisoformat accepts (3.11 and later), and three it refuses: Z as the
        // separator (ASH turns every Z into +00:00 first), mixed time styles, and no zone.
        val forms = mapOf(
            "basic" to "20261001T000000Z",
            "hour-only" to "2026-10-01T00+00:00",
            "comma" to "2026-10-01 00:00:00,5+0530",
            "week" to "2026-W40-4T12:30-05",
            "any-separator" to "2026-10-01x00:00:00.123456789+00:00:00.5",
            "z-separator" to "2026-10-01Z00:00Z",
            "mixed" to "2026-10-01T00:0000Z",
            "date-only" to "2026-10-01",
        )
        val notifications = forms.entries.joinToString(",") { (name, at) ->
            """{"descriptor": {"id": "ASH-CONTENT-DB-STALE"}, "level": "error",
                "properties": {"content_database": {"name": "$name", "measured_at": "$at"}}}"""
        }
        val report = parse(passed, sarif("""{"toolConfigurationNotifications": [$notifications]}"""))
        assertEquals(listOf("any-separator", "basic", "comma", "hour-only", "week"), report.staleContentDatabases)
    }

    // ---- roster shapes ----

    @Test
    fun anEmptyRosterUnderAScanPhaseIsNothingMeasured() {
        val report = parse(
            """"scanner_results": {}""",
            """"metadata": {"expected_scanners": ["bandit", "grype"]}""",
        )
        assertTrue(report.available)
        assertTrue(report.nothingMeasured)
        assertEquals(
            "No scanner examined this project -- the scan phase expected 2 and recorded none, so " +
                "nothing here has been shown to be clean or unclean.",
            report.describeIncompleteness(),
        )
    }

    @Test
    fun anUnreadableRosterStillReportsTheOtherGaps() {
        val report = parse(
            """"metadata": {"expected_scanners": "not a list"}""",
            """"converter_results": {"archive": {"failure": "raised"}}""",
        )
        assertFalse(report.available)
        assertFalse(report.nothingMeasured)
        val described = report.describeIncompleteness()!!
        assertTrue(described, described.startsWith("Scanner completeness is unknown: "))
        assertTrue(described, described.endsWith("1 converter(s) did not run: archive (raised). Files they would have converted were not scanned."))
    }

    // ---- what the user is shown ----

    private fun exitZero(report: AshScannerStatus.Report) = AshScanRunner.Outcome.Completed(
        exitCode = 0,
        results = AshScanResults(emptyList(), emptyList()),
        sarifPath = "/p/reports/ash.sarif",
        scanners = report,
        versionLine = "awslabs/automated-security-helper v4.0.0",
        outputTail = "",
    )

    @Test
    fun anExitZeroScanWithAStaleDatabaseIsShownIncomplete() {
        val report = parse(
            passed,
            sarif(
                """{"toolConfigurationNotifications": [{"descriptor": {"id": "ASH-CONTENT-DB-STALE"},
                    "level": "error", "properties": {"content_database": {"name": "grype-db", "measured_at": "2026-10-01T00:00:00Z"}}}]}""",
            ),
        )
        val outcome = exitZero(report)
        assertFalse(outcome.coverageComplete)
        val message = AshScanController.report(outcome)
        assertEquals(NotificationType.WARNING, message.type)
        assertEquals("ASH scan incomplete", message.title)
        assertTrue(message.body, message.body.contains("ASH reported no findings, but the scan was NOT complete."))
        assertTrue(message.body, message.body.contains("content database(s) are past their age bound: grype-db."))
    }

    @Test
    fun textFromTheReportIsEscapedInTheNotification() {
        val report = parse(
            passed,
            sarif("""{"toolExecutionNotifications": [{"level": "error", "message": {"text": "<b>x</b> & y"}}]}"""),
        )
        val body = AshScanController.report(exitZero(report)).body
        assertTrue(body, body.contains("not evaluated: &lt;b&gt;x&lt;/b&gt; &amp; y."))
        assertFalse(body, body.contains("<b>x</b>"))
    }
}
