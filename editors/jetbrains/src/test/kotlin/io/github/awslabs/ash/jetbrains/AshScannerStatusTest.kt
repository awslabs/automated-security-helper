// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for telling "nothing was found" apart from "nothing ran".
 *
 * The shapes here are taken from a real ASH 3.7.0 run on a host missing most scanner tools, whose
 * `scanner_results` reported cdk-nag MISSING, cfn-nag SKIPPED, detect-secrets FAILED and seven
 * PASSED. That run exited 0.
 */
class AshScannerStatusTest {

    private fun statusFile(vararg entries: Pair<String, String>): String {
        val body = entries.joinToString(",") { (name, status) ->
            """"$name": {"status": "$status", "exit_code": 0, "excluded": false}"""
        }
        return """{"scanner_results": {$body}}"""
    }

    @Test
    fun ashsOwnCompleteStatusesAreTreatedAsComplete() {
        // Spelled to match _COMPLETE_SCANNER_STATUSES at run_ash_scan.py. SKIPPED is complete
        // because it means "not selected", not "failed to run".
        val report = AshScannerStatus.parse(
            statusFile("bandit" to "PASSED", "checkov" to "FAILED", "cfn-nag" to "SKIPPED"),
        )
        assertTrue(report.available)
        assertEquals(3, report.complete.size)
        assertEquals(emptyList<AshScannerStatus.Scanner>(), report.incomplete)
        assertNull("nothing to warn about", report.describeIncompleteness())
    }

    @Test
    fun missingAndErrorAreIncomplete() {
        // The remaining members of ScannerStatus (enums.py). MISSING is the false-clean case:
        // selected, dependencies unavailable, never ran.
        val report = AshScannerStatus.parse(
            statusFile("bandit" to "PASSED", "cdk-nag" to "MISSING", "grype" to "ERROR"),
        )
        assertTrue(report.available)
        assertEquals(listOf("bandit"), report.complete.map { it.name })
        assertEquals(listOf("cdk-nag", "grype"), report.incomplete.map { it.name }.sorted())

        val described = report.describeIncompleteness()
        assertNotNull(described)
        assertTrue("must name the scanners: $described", described!!.contains("cdk-nag (MISSING)"))
        assertTrue("must name the scanners: $described", described.contains("grype (ERROR)"))
        assertTrue(
            "must say the answer is incomplete rather than clean: $described",
            described.contains("not a complete answer"),
        )
    }

    @Test
    fun theRealRunsStatusesClassifyAsMeasured() {
        // Exactly what the real ASH 3.7.0 run produced.
        val report = AshScannerStatus.parse(
            statusFile(
                "cdk-nag" to "MISSING",
                "bandit" to "PASSED",
                "cfn-nag" to "SKIPPED",
                "checkov" to "PASSED",
                "detect-secrets" to "FAILED",
                "grype" to "PASSED",
                "npm-audit" to "PASSED",
                "opengrep" to "PASSED",
                "semgrep" to "PASSED",
                "syft" to "PASSED",
            ),
        )
        assertEquals(10, report.scanners.size)
        // Only cdk-nag is incomplete: FAILED and SKIPPED both mean the scanner reached a verdict.
        assertEquals(listOf("cdk-nag"), report.incomplete.map { it.name })
        assertEquals(9, report.complete.size)
        assertNotNull(
            "a MISSING scanner must produce a warning even though ASH exited 0",
            report.describeIncompleteness(),
        )
    }

    @Test
    fun bothRosterKeysAreRead() {
        // ASH RENAMED THE ROSTER, and the two keys are mutually exclusive rather than redundant.
        // Measured: a 3.7.0 report has top-level `scanner_results` and no `metadata.scanner_status`;
        // the committed 3.0.0 fixture has `metadata.scanner_status` and no `scanner_results`. Reading
        // only one makes every report of the other vintage report "completeness unknown".
        val threeSeven = """{"scanner_results": {"cdk-nag": {"status": "MISSING"}}}"""
        val threeZero =
            """{"metadata": {"scanner_status": {"cdk-nag": {"status": "MISSING"}}}}"""

        for ((label, text, expectedSource) in listOf(
            Triple("3.7.0", threeSeven, "scanner_results"),
            Triple("3.0.0", threeZero, "metadata.scanner_status"),
        )) {
            val report = AshScannerStatus.parse(text)
            assertTrue("$label roster must be found", report.available)
            assertEquals("$label source", expectedSource, report.source)
            assertEquals(listOf("cdk-nag"), report.incomplete.map { it.name })
        }
    }

    @Test
    fun everyScannerSkippedIsReportedEvenThoughNothingIsIncomplete() {
        // THE STATE A PER-SCANNER SPLIT CANNOT SEE. SKIPPED is a COMPLETE status, so the incomplete
        // set is empty -- and yet no scanner examined the target, so the run has shown the project to
        // be neither clean nor unclean. ASH's own note at run_ash_scan.py makes the same
        // point: per-entry tolerance of SKIPPED cannot answer whether the SET measured anything.
        val report = AshScannerStatus.parse(
            statusFile("bandit" to "SKIPPED", "checkov" to "SKIPPED", "grype" to "SKIPPED"),
        )
        assertTrue(report.available)
        assertEquals("nothing is individually incomplete", emptyList<String>(), report.incomplete.map { it.name })
        assertEquals("and nothing reached a verdict", emptyList<String>(), report.reachedAVerdict.map { it.name })
        assertTrue("so the SET must be flagged", report.nothingMeasured)

        val described = report.describeIncompleteness()
        assertNotNull("an all-skipped run must warn", described)
        assertTrue(
            "must say nothing was examined; was: $described",
            described!!.contains("No scanner examined this project"),
        )
        assertTrue(
            "must refuse to call it clean; was: $described",
            described.contains("clean or unclean"),
        )
        // And it must NOT claim an incompleteness that does not exist: SKIPPED is complete, so there
        // is no "did not complete" list to report here.
        assertFalse(
            "must not invent an incomplete scanner; was: $described",
            described.contains("did not complete"),
        )
    }

    @Test
    fun oneScannerReachingAVerdictIsEnoughToNotBeNothingMeasured() {
        // The positive control for the test above: if nothingMeasured fired whenever any scanner was
        // skipped, it would warn on almost every real run and be ignored.
        val report = AshScannerStatus.parse(
            statusFile("bandit" to "PASSED", "checkov" to "SKIPPED", "grype" to "SKIPPED"),
        )
        assertFalse(report.nothingMeasured)
        assertNull("a partially-skipped run with a real verdict is not a warning", report.describeIncompleteness())
    }

    @Test
    fun anExcludedScannerIsNotReportedAsAProblem() {
        // Excluded means deliberately switched off by configuration. Reporting it would train the
        // user to ignore this warning, which is worse than not showing it.
        val report = AshScannerStatus.parse(
            """{"scanner_results": {
                 "bandit": {"status": "PASSED", "excluded": false},
                 "grype":  {"status": "MISSING", "excluded": true}}}""",
        )
        assertTrue(report.available)
        assertEquals("an excluded scanner is not an incompleteness", emptyList<String>(), report.incomplete.map { it.name })
        assertNull(report.describeIncompleteness())
    }

    @Test
    fun unsatisfiedDependenciesAreNamedAsTheReason() {
        // dependencies_satisfied: false is the usual cause of MISSING -- the tool is not installed --
        // and saying so is the difference between an actionable warning and a puzzling one.
        // Two scanners, not one, and deliberately: with a single MISSING scanner nothing reaches a
        // verdict, so the nothing-measured arm also fires and the message carries both facts. Keeping
        // one PASSED isolates the dependency-naming behaviour being tested here.
        val report = AshScannerStatus.parse(
            """{"scanner_results": {
                 "bandit": {"status": "PASSED", "dependencies_satisfied": true},
                 "grype": {"status": "MISSING", "dependencies_satisfied": false}}}""",
        )
        val described = report.describeIncompleteness()
        assertNotNull(described)
        assertTrue(
            "must name the cause; was: $described",
            described!!.contains("dependencies unavailable"),
        )
        assertFalse(
            "one scanner reached a verdict, so this is not the nothing-measured case; was: $described",
            described.contains("No scanner examined"),
        )
    }

    @Test
    fun aMissingScannerWithNothingElseReportsBothFacts() {
        // The case that exposed an ordering defect: a single MISSING scanner is BOTH an incompleteness
        // and a run where nothing reached a verdict. An earlier version returned only the second and
        // said "all 1 are skipped or excluded", which was factually wrong -- nothing had been skipped.
        val report = AshScannerStatus.parse(
            """{"scanner_results": {"grype": {"status": "MISSING"}}}""",
        )
        val described = report.describeIncompleteness()
        assertNotNull(described)
        assertTrue("names the incomplete scanner; was: $described", described!!.contains("grype (MISSING)"))
        assertTrue("and says nothing was examined; was: $described", described.contains("No scanner examined"))
        assertFalse(
            "must not claim it was skipped or excluded; was: $described",
            described.contains("skipped or excluded"),
        )
    }

    @Test
    fun anUnreadableStatusFileIsNotTakenToMeanEverythingRan() {
        // The failure that would reintroduce the whole defect: absence of evidence read as evidence
        // of completeness.
        for (bad in listOf("", "{", "not json", "{}", """{"scanner_results": {}}""")) {
            val report = AshScannerStatus.parse(bad)
            assertFalse("input <$bad> must not read as available", report.available)
            val described = report.describeIncompleteness()
            assertNotNull("input <$bad> must still warn", described)
            assertTrue(
                "must say completeness is unknown: $described",
                described!!.contains("unknown"),
            )
            assertTrue(
                "must refuse to call it clean: $described",
                described.contains("cannot be read as a clean scan"),
            )
        }
    }

    @Test
    fun anEntryWithNoReadableStatusCountsAsIncomplete() {
        // A scanner this cannot classify is a scanner it cannot vouch for.
        val report = AshScannerStatus.parse(
            """{"scanner_results": {"bandit": {"status": "PASSED"}, "mystery": {}}}""",
        )
        assertTrue(report.available)
        assertEquals(listOf("mystery"), report.incomplete.map { it.name })
        assertEquals("UNKNOWN", report.incomplete.single().status)
    }

    @Test
    fun statusMatchingIsCaseInsensitive() {
        val report = AshScannerStatus.parse(statusFile("bandit" to "passed"))
        assertEquals(emptyList<AshScannerStatus.Scanner>(), report.incomplete)
    }

    @Test
    fun executionSuccessfulIsNotTheSignalAndIsNotConsulted() {
        // Documents the measurement that drove this design. On a real run where detect-secrets was
        // FAILED and cdk-nag MISSING, all 8 SARIF invocations reported executionSuccessful: true --
        // and MISSING scanners had no invocation at all. A checker built on invocations would have
        // reported that run complete.
        //
        // Asserted by construction: a status file is the only input this type accepts, so there is no
        // path by which an invocation could influence the verdict.
        val report = AshScannerStatus.parse(statusFile("cdk-nag" to "MISSING"))
        assertEquals(1, report.incomplete.size)
        assertNotNull(report.describeIncompleteness())
    }
}
