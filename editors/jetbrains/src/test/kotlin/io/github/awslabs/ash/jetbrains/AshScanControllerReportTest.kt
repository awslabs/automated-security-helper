// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import com.intellij.notification.NotificationType
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The notification a completed scan ends in, for each combination of exit code, scanner status
 * and report quality.
 *
 * The rule under test: anything short of full coverage is a WARNING titled "incomplete", even
 * with no findings and exit 0, and the body never says "no findings" without saying whether the
 * scan was complete.
 */
class AshScanControllerReportTest {

    private val complete = AshScannerStatus.parse("""{"scanner_results":{"bandit":{"status":"PASSED"}}}""")
    private val missing = AshScannerStatus.parse("""{"scanner_results":{"bandit":{"status":"PASSED"},"grype":{"status":"MISSING"}}}""")

    private fun finding(level: AshLevel) = AshFinding("a.py", 1, 1, 1, null, level, true, "R", "m", "s")

    private fun completed(
        exitCode: Int,
        findings: List<AshFinding> = emptyList(),
        scanners: AshScannerStatus.Report = complete,
        problems: List<String> = emptyList(),
        total: Int = findings.size,
        surfaced: Int = findings.size,
        suppressed: Int = 0,
        tail: String = "",
    ) = AshScanRunner.Outcome.Completed(
        exitCode = exitCode,
        results = AshScanResults(findings, problems, totalResults = total, suppressedResults = suppressed, surfacedResults = surfaced),
        sarifPath = "/p/.ash/ash_output/reports/ash.sarif",
        scanners = scanners,
        versionLine = "awslabs/automated-security-helper v4.0.0",
        outputTail = tail,
    )

    @Test
    fun aCompleteScanWithFindingsIsInformationalAndCountsBySeverity() {
        val message = AshScanController.report(completed(2, listOf(finding(AshLevel.ERROR), finding(AshLevel.NOTE), finding(AshLevel.ERROR))))
        assertEquals(NotificationType.INFORMATION, message.type)
        assertEquals("ASH scan finished", message.title)
        assertTrue(message.body, message.body.contains("3 finding(s): 2 error, 1 note."))
        assertTrue(message.body, message.body.contains("1 scanner(s) completed."))
        assertTrue(message.body, message.body.contains("v4.0.0, exit code 2."))
    }

    @Test
    fun exitZeroWithAMissingScannerIsStillIncomplete() {
        // fail_on_incomplete_scanners turned off: ASH exits 0 and only the status file knows.
        val message = AshScanController.report(completed(0, scanners = missing))
        assertEquals(NotificationType.WARNING, message.type)
        assertEquals("ASH scan incomplete", message.title)
        assertTrue(message.body, message.body.contains("ASH reported no findings, but the scan was NOT complete."))
        assertTrue(message.body, message.body.contains("grype (MISSING)"))
    }

    @Test
    fun exitOneWithNoFindingsSaysThatIsNotACleanResult() {
        val message = AshScanController.report(completed(1, scanners = missing))
        assertEquals("ASH scan incomplete", message.title)
        assertTrue(message.body, message.body.contains("INCOMPLETE (exit 1)"))
        assertTrue(message.body, message.body.contains("which is not a clean result"))
    }

    @Test
    fun exitOneWithNothingNamedAndNothingPrintedSaysSo() {
        val message = AshScanController.report(completed(1, scanners = complete, tail = "  "))
        assertTrue(message.body, message.body.contains("names no scanner that failed to complete"))
        assertTrue(message.body, message.body.contains("and it printed nothing."))
    }

    @Test
    fun outputIsEscapedBeforeItReachesAnHtmlBalloon() {
        val message = AshScanController.report(completed(1, scanners = complete, tail = "<b>&</b>"))
        assertTrue(message.body, message.body.contains("&lt;b&gt;&amp;&lt;/b&gt;"))
        assertFalse(message.body, message.body.contains("<b>&</b>"))
    }

    @Test
    fun unreadablePartsAndSuppressionsAreReportedAsGaps() {
        val problems = (1..12).map { "problem $it <x>" }
        val message = AshScanController.report(
            completed(2, listOf(finding(AshLevel.WARNING)), problems = problems, total = 3, suppressed = 2),
        )
        assertEquals(NotificationType.WARNING, message.type)
        assertEquals("ASH scan finished with gaps", message.title)
        assertTrue(message.body, message.body.contains("2 of 3 result(s) suppressed by the report."))
        assertTrue(message.body, message.body.contains("12 part(s) of the report could not be read"))
        assertTrue(message.body, message.body.contains("&bull; problem 10 &lt;x&gt;"))
        assertFalse("only the first ten are listed", message.body.contains("problem 11"))
        assertTrue(message.body, message.body.contains("&bull; ..."))
    }

    @Test
    fun aResultThatFellOutOfEveryBucketIsCalledAnInternalInconsistency() {
        val message = AshScanController.report(completed(2, listOf(finding(AshLevel.ERROR)), total = 5, surfaced = 1))
        assertTrue(message.body, message.body.contains("Internal inconsistency:</b> 5 result(s) were read but 1 were accounted for"))
    }

    @Test
    fun anUnreadableStatusFileIsIncompleteRatherThanSilent() {
        val message = AshScanController.report(completed(0, scanners = AshScannerStatus.unavailable("no status file at x")))
        assertEquals("ASH scan incomplete", message.title)
        assertTrue(message.body, message.body.contains("Scanner completeness is unknown: no status file at x"))
    }

    @Test
    fun pathsInTheReportAreEscaped() {
        val outcome = completed(0).copy(sarifPath = "/p/R&D <tmp>/reports/ash.sarif")
        val body = AshScanController.report(outcome).body
        assertTrue(body, body.contains("Report: /p/R&amp;D &lt;tmp&gt;/reports/ash.sarif"))
        assertFalse(body, body.contains("<tmp>"))
    }

    @Test
    fun pathEntriesInTheNotFoundMessageAreEscaped() {
        val notFound = AshCliLocator.resolve(
            configured = null,
            pathValue = "/opt/a&b:/opt/<x>",
            pathSeparator = ":",
            isExecutable = { false },
        ) as AshCliLocator.Outcome.NotFound
        val body = AshScanController.notFound(notFound).body
        assertTrue(body, body.contains("including: /opt/a&amp;b, /opt/&lt;x&gt;"))
        assertFalse(body, body.contains("<x>"))
    }
}
