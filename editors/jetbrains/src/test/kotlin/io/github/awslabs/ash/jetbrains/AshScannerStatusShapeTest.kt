// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The status file in shapes no ASH version writes on purpose. Each must end as an explicit
 * verdict -- unavailable, or a scanner counted as incomplete -- and never as "complete".
 */
class AshScannerStatusShapeTest {

    @Test
    fun aRootThatIsNotAnObjectIsUnavailable() {
        for (text in listOf("null", "[1]", "\"x\"")) {
            val report = AshScannerStatus.parse(text)
            assertFalse(text, report.available)
            assertEquals("status file root is not a JSON object", report.unavailableReason)
        }
    }

    @Test
    fun aLegacyRosterUnderAMetadataThatIsNotAnObjectIsNotFound() {
        val report = AshScannerStatus.parse("""{"scanner_results": [], "metadata": "x"}""")
        assertFalse(report.available)
        assertTrue(report.unavailableReason, report.unavailableReason!!.contains("scanner_results or metadata.scanner_status"))
    }

    @Test
    fun entriesOfTheWrongShapeCountAsIncomplete() {
        val report = AshScannerStatus.parse(
            """{"scanner_results": {
                "a": 5,
                "b": {"status": 3},
                "c": {"status": "PASSED", "dependencies_satisfied": "no", "excluded": 1},
                "d": null
            }}""",
        )
        assertEquals(listOf("a", "b", "d"), report.incomplete.map { it.name })
        assertEquals(listOf("UNKNOWN", "UNKNOWN", "UNKNOWN"), report.incomplete.map { it.status })
        // A non-boolean flag is absent, so it takes its default. `excluded` is not read at all.
        val c = report.scanners.single { it.name == "c" }
        assertTrue(c.dependenciesSatisfied)
    }

    @Test
    fun nothingMeasuredNeedsAReadableNonEmptyRoster() {
        assertFalse(AshScannerStatus.unavailable("x").nothingMeasured)
        assertFalse(AshScannerStatus.Report(available = true).nothingMeasured)
        assertNull("an empty roster that was read says nothing", AshScannerStatus.Report(available = true).describeIncompleteness())
    }

    @Test
    fun anUnavailableReportWithNoReasonStillSaysCompletenessIsUnknown() {
        val text = AshScannerStatus.Report(available = false).describeIncompleteness()!!
        assertTrue(text, text.contains("Scanner completeness is unknown: status file unreadable"))
    }

    @Test
    fun aScannerWithUnavailableDependenciesSaysSo() {
        assertEquals("cfn-nag (MISSING, dependencies unavailable)", AshScannerStatus.Scanner("cfn-nag", "MISSING", dependenciesSatisfied = false).describe())
    }
}
