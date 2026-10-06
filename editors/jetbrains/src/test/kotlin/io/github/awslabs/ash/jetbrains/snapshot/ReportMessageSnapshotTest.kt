// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains.snapshot

import io.github.awslabs.ash.jetbrains.AshFinding
import io.github.awslabs.ash.jetbrains.AshLevel
import io.github.awslabs.ash.jetbrains.AshScanController
import io.github.awslabs.ash.jetbrains.AshScanResults
import io.github.awslabs.ash.jetbrains.AshScanRunner
import io.github.awslabs.ash.jetbrains.AshScannerStatus
import org.junit.Test

/**
 * The completed-scan notification for the report shapes a stub replay cannot easily produce:
 * suppressions, unreadable parts, a counting inconsistency, an unknown status file, exit 0 with
 * a missing scanner, and ASH output that needs HTML escaping.
 *
 * NotificationSnapshotTest covers the shapes real captured runs produce, end to end. These are
 * built directly from [AshScanRunner.Outcome.Completed], the same way AshScanControllerReportTest
 * builds them, so every branch of [AshScanController.report] has its words pinned.
 */
class ReportMessageSnapshotTest {

    private val complete = AshScannerStatus.parse("""{"scanner_results":{"bandit":{"status":"PASSED"}}}""")
    private val missing = AshScannerStatus.parse(
        """{"scanner_results":{"bandit":{"status":"PASSED"},"grype":{"status":"MISSING"},"cfn-nag":{"status":"FAILED"}}}""",
    )

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
        sarifPath = "/project/.ash/ash_output/reports/ash.sarif",
        scanners = scanners,
        versionLine = "awslabs/automated-security-helper v4.0.0",
        outputTail = tail,
    )

    private fun assertSnapshot(name: String, outcome: AshScanRunner.Outcome.Completed) {
        val message = AshScanController.report(outcome)
        Snapshots.assertMatches(
            javaClass,
            name,
            "type=${message.type}\ntitle: ${message.title}\nbody:\n${message.body.replace("<br>", "<br>\n")}",
        )
    }

    @Test
    fun everySeverityCounted() = assertSnapshot(
        "all-severities",
        completed(2, listOf(finding(AshLevel.ERROR), finding(AshLevel.NOTE), finding(AshLevel.WARNING), finding(AshLevel.ERROR))),
    )

    @Test
    fun exitZeroWithMissingScanners() = assertSnapshot("exit0-missing-scanners", completed(0, scanners = missing))

    @Test
    fun exitOneWithFindingsAndMissingScanners() =
        assertSnapshot("exit1-findings-missing-scanners", completed(1, listOf(finding(AshLevel.WARNING)), scanners = missing))

    @Test
    fun exitOneWithNothingNamedAndNothingPrinted() =
        assertSnapshot("exit1-nothing-printed", completed(1, scanners = complete, tail = "  "))

    @Test
    fun ashOutputIsEscaped() = assertSnapshot("escaped-output", completed(1, scanners = complete, tail = "<b>&</b>"))

    @Test
    fun suppressionsAndUnreadableParts() = assertSnapshot(
        "gaps",
        completed(2, listOf(finding(AshLevel.WARNING)), problems = (1..12).map { "problem $it <x>" }, total = 3, suppressed = 2),
    )

    @Test
    fun aCountingInconsistency() =
        assertSnapshot("internal-inconsistency", completed(2, listOf(finding(AshLevel.ERROR)), total = 5, surfaced = 1))

    @Test
    fun anUnreadableStatusFile() =
        assertSnapshot("status-unavailable", completed(0, scanners = AshScannerStatus.unavailable("no status file at x")))
}
