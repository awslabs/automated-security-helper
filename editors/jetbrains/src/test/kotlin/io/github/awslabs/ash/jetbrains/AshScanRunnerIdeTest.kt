// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import com.intellij.notification.NotificationType
import com.intellij.openapi.progress.EmptyProgressIndicator
import com.intellij.testFramework.fixtures.BasePlatformTestCase
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import kotlin.concurrent.thread

/**
 * End-to-end tests for actually launching the CLI and reading what it wrote.
 *
 * WHAT THIS COVERS THAT NOTHING ELSE DOES. AshSarifParserTest proves SARIF is parsed
 * correctly from a string, and AshFindingInspectionIdeTest proves parsed findings become
 * editor highlights. Neither one starts a process. This covers the seam between them: that
 * [AshCliLocator] finds a real executable on a real PATH, that [AshScanRunner] launches it
 * with arguments it accepts, that it looks for the report where ASH actually writes it
 * (`<output-dir>/reports/ash.sarif`), and that a non-zero exit is not mistaken for failure.
 *
 * `ash` ITSELF IS STUBBED, and that is the point rather than a shortcut. The plugin's
 * contract is "run whatever `ash` is on PATH and read its SARIF"; a stub that writes a
 * fixture SARIF exercises exactly that contract, and does so deterministically. What it
 * does NOT cover is whether the real ASH CLI accepts these flags, which is a fact about
 * ASH and not about this plugin -- so the argument list is the thing to re-check against
 * `ash scan --help` if a future ASH renames a flag.
 *
 * Extends [BasePlatformTestCase] because [AshScanRunner] uses the platform's
 * `GeneralCommandLine` and `CapturingProcessHandler`, which need an Application.
 */
class AshScanRunnerIdeTest : BasePlatformTestCase() {

    private lateinit var workdir: Path

    override fun setUp() {
        super.setUp()
        workdir = Files.createTempDirectory("ash-runner-test-")
    }

    override fun tearDown() {
        try {
            workdir.toFile().deleteRecursively()
        } finally {
            super.tearDown()
        }
    }

    /**
     * Writes a stub ASH that answers `--version` the way ASH does and, for `scan`, emits
     * [sarifBody] to `<output-dir>/reports/ash.sarif`.
     *
     * @param exitCode the stub's exit status for `scan`. Defaults to 2, ASH's code for
     *   "actionable findings detected" -- the normal outcome of a scan that found something.
     * @param statusBody when given, written to `<output-dir>/ash_aggregated_results.json`, which
     *   real ASH writes on every scan.
     * @param versionOutput what `--version` prints. Real ASH prints the marker; a shell does not.
     */
    private fun stubAsh(
        sarifBody: String?,
        exitCode: Int = 2,
        statusBody: String? = null,
        versionOutput: String = "awslabs/automated-security-helper v4.0.0",
        name: String = "ash",
    ): Path {
        val bin = Files.createDirectories(workdir.resolve("bin"))
        val script = bin.resolve(name)
        // Parses --output-dir out of its own arguments, so the test asserts the runner
        // actually passes it rather than assuming a hard-coded location.
        val body = buildString {
            appendLine("#!/bin/sh")
            appendLine("if [ \"\$1\" = --version ]; then echo '$versionOutput'; exit 0; fi")
            appendLine("out=''")
            appendLine("while [ \$# -gt 0 ]; do")
            appendLine("  case \"\$1\" in --output-dir) out=\"\$2\"; shift 2;; *) shift;; esac")
            appendLine("done")
            appendLine("echo \"stub ash invoked, output-dir=\$out\"")
            if (sarifBody != null) {
                appendLine("mkdir -p \"\$out/reports\"")
                appendLine("cat > \"\$out/reports/ash.sarif\" <<'SARIF_EOF'")
                appendLine(sarifBody)
                appendLine("SARIF_EOF")
            } else {
                appendLine("echo 'stub ash: deliberately writing no report' >&2")
            }
            if (statusBody != null) {
                appendLine("cat > \"\$out/ash_aggregated_results.json\" <<'STATUS_EOF'")
                appendLine(statusBody)
                appendLine("STATUS_EOF")
            }
            appendLine("exit $exitCode")
        }
        Files.writeString(script, body)
        Files.setPosixFilePermissions(
            script,
            setOf(
                PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE,
                PosixFilePermission.OWNER_EXECUTE,
            ),
        )
        return script
    }

    private fun sarif(uri: String, level: String, line: Int) = """
        {
          "version": "2.1.0",
          "runs": [
            { "tool": { "driver": { "name": "stub" } },
              "results": [
                { "ruleId": "STUB1", "level": "$level",
                  "message": { "text": "stub finding" },
                  "locations": [ { "physicalLocation": {
                    "artifactLocation": { "uri": "$uri" },
                    "region": { "startLine": $line } } } ] }
              ] }
          ]
        }
    """.trimIndent()

    fun testLocatorFindsAStubOnARealPath() {
        val script = stubAsh(null)
        val outcome = AshCliLocator.resolve(configured = null, pathValue = script.parent.toString())
        assertEquals(AshCliLocator.Outcome.Found(script.toFile().absolutePath, AshCliLocator.Source.FALLBACK), outcome)
    }

    fun testRunnerLaunchesTheCliAndReadsTheSarifItWrote() {
        val source = Files.createDirectories(workdir.resolve("project"))
        Files.writeString(source.resolve("app.py"), "import os\nPASSWORD = 'x'\n")
        val output = Files.createDirectories(workdir.resolve("out"))
        val script = stubAsh(sarif("app.py", "error", 2))

        val outcome = AshScanRunner.run(script.toString(), source, output)

        val completed = outcome as AshScanRunner.Outcome.Completed
        // Exit 2 is a scan that found something, not a failed scan.
        assertEquals(2, completed.exitCode)
        assertEquals(output.resolve("reports/ash.sarif").toString(), completed.sarifPath)
        val finding = completed.results.findings.single()
        assertEquals(AshLevel.ERROR, finding.level)
        assertEquals(2, finding.startLine)
        assertEquals("app.py", finding.filePath)
        assertEquals(emptyList<String>(), completed.results.problems)
    }

    fun testMissingReportIsAFailureAndNotAnEmptyResult() {
        // The requirement this plugin must not break: a scan that produced no report has
        // told us nothing, and reporting it as "0 findings" would be a clean verdict over
        // an unread file. Exit 0 here specifically, so the ONLY thing marking this as a
        // failure is the absent report.
        val source = Files.createDirectories(workdir.resolve("project"))
        val output = Files.createDirectories(workdir.resolve("out"))
        val script = stubAsh(sarifBody = null, exitCode = 0)

        val outcome = AshScanRunner.run(script.toString(), source, output)

        val failed = outcome as AshScanRunner.Outcome.Failed
        assertTrue(
            "must say no SARIF was written; was: ${failed.summary}",
            failed.summary.contains("no SARIF"),
        )
        assertTrue(
            "must distinguish itself from finding nothing; was: ${failed.summary}",
            failed.summary.contains("not the same as finding nothing"),
        )
    }

    fun testStaleReportFromAPreviousRunIsNotReadAsThisRunsResult() {
        // A leftover report would present a failed scan as a successful one with stale
        // findings -- the exact shape of failure this plugin is required not to have.
        val source = Files.createDirectories(workdir.resolve("project"))
        val output = Files.createDirectories(workdir.resolve("out"))
        val stale = Files.createDirectories(output.resolve("reports")).resolve("ash.sarif")
        Files.writeString(stale, sarif("old.py", "error", 99))

        // exitCode 1 -- a genuine execution error -- rather than 2, which is a success code. What
        // this test is about is a run that produced no report at all.
        val script = stubAsh(sarifBody = null, exitCode = 1)
        val outcome = AshScanRunner.run(script.toString(), source, output)

        assertTrue(
            "a run that wrote no report must fail even when a previous report exists",
            outcome is AshScanRunner.Outcome.Failed,
        )
        assertFalse("the stale report must have been removed", Files.exists(stale))
    }

    fun testExitCodeOneWithAReportIsAPartialScanWhoseFindingsAreShown() {
        // ASH's exit 1 with results on disk is ScanIncompleteExit: the scan finished without
        // full coverage. Its findings are real, so they are read and returned, and the outcome
        // says the scan was partial so nothing presents it as complete.
        val source = Files.createDirectories(workdir.resolve("project"))
        val output = Files.createDirectories(workdir.resolve("out"))
        val script = stubAsh(
            sarif("app.py", "error", 2),
            exitCode = 1,
            statusBody = """{"scanner_results": {"bandit": {"status": "PASSED"}, "grype": {"status": "MISSING"}}}""",
        )

        val completed = AshScanRunner.run(script.toString(), source, output) as AshScanRunner.Outcome.Completed

        assertEquals(1, completed.exitCode)
        assertTrue("exit 1 must be marked partial", completed.partial)
        assertFalse("exit 1 is never complete coverage", completed.coverageComplete)
        assertEquals("the partial findings must be returned", 1, completed.results.findings.size)
        assertEquals(listOf("grype"), completed.scanners.incomplete.map { it.name })
    }

    fun testExitCodeOneWithoutAReportIsAFailure() {
        // The crash half of exit 1. Nothing was written, so there is nothing partial to show.
        val source = Files.createDirectories(workdir.resolve("project"))
        val output = Files.createDirectories(workdir.resolve("out"))
        val script = stubAsh(sarifBody = null, exitCode = 1)

        val failed = AshScanRunner.run(script.toString(), source, output) as AshScanRunner.Outcome.Failed

        assertTrue(failed.summary, failed.summary.contains("exited 1 and wrote no SARIF"))
        assertTrue("the output tail must be carried", failed.detail!!.contains("deliberately writing no report"))
    }

    fun testExitCodesOutsideTheContractAreFailuresEvenWithAReport() {
        // 3 is an invalid configuration and 4 a workspace error; 7 stands for any code ASH
        // adds later. A report on disk does not make any of them a scan.
        val source = Files.createDirectories(workdir.resolve("project"))
        for (code in listOf(3, 4, 7)) {
            val output = Files.createDirectories(workdir.resolve("out$code"))
            val script = stubAsh(sarif("app.py", "error", 2), exitCode = code)
            val failed = AshScanRunner.run(script.toString(), source, output) as AshScanRunner.Outcome.Failed
            assertTrue(failed.summary, failed.summary.contains("ASH exited $code"))
        }
    }

    fun testAnExecutableThatIsNotAshIsRefusedBeforeAnyScan() {
        // MSYS2's ash answers --version with a shell error. The scan must not run, and the
        // message must name the collision and the unambiguous entry point.
        val source = Files.createDirectories(workdir.resolve("project"))
        val output = Files.createDirectories(workdir.resolve("out"))
        val script = stubAsh(sarif("app.py", "error", 2), versionOutput = "ash: Illegal option --")

        val failed = AshScanRunner.run(script.toString(), source, output) as AshScanRunner.Outcome.Failed

        assertTrue(failed.summary, failed.summary.contains("is not ASH"))
        assertTrue(failed.summary, failed.summary.contains("MSYS2"))
        assertTrue(failed.summary, failed.summary.contains("automated-security-helper"))
        assertFalse("the scan must not have run", Files.exists(output.resolve("reports/ash.sarif")))
    }

    fun testAStaleStatusFileIsReportedAsUnknownRatherThanRead() {
        // Fails, naming the cause, when run as root: root ignores the mode this test sets.
        PermissionEnforcement.require(workdir)
        // The status file gets the same freshness guard as the SARIF. A previous run's roster
        // saying every scanner PASSED must not vouch for this run.
        val source = Files.createDirectories(workdir.resolve("project"))
        val output = Files.createDirectories(workdir.resolve("out"))
        // A status file that cannot be deleted: its directory is read-only. The runner reads
        // ash_aggregated_results.json from the output directory, so the output directory itself
        // is what has to refuse the delete. reports/ stays writable, so the SARIF is fresh.
        Files.writeString(output.resolve("ash_aggregated_results.json"), """{"scanner_results": {"bandit": {"status": "PASSED"}}}""")
        Files.createDirectories(output.resolve("reports"))
        val script = stubAsh(sarif("app.py", "error", 2))
        Files.setPosixFilePermissions(output, setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_EXECUTE))
        try {
            val completed = AshScanRunner.run(script.toString(), source, output) as AshScanRunner.Outcome.Completed
            assertFalse("a stale roster must not be read", completed.scanners.available)
            assertTrue(
                completed.scanners.unavailableReason,
                completed.scanners.unavailableReason!!.contains("from a previous run"),
            )
            assertFalse(completed.coverageComplete)
        } finally {
            Files.setPosixFilePermissions(
                output,
                setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE),
            )
        }
    }

    fun testExitCodeZeroAndTwoAreBothSuccessful() {
        // 0 is a clean scan, 2 is a scan that found something. Both ran.
        val source = Files.createDirectories(workdir.resolve("project"))
        for ((code, dir) in listOf(0 to "out0", 2 to "out2")) {
            val output = Files.createDirectories(workdir.resolve(dir))
            val script = stubAsh(sarif("app.py", "error", 2), exitCode = code)
            val outcome = AshScanRunner.run(script.toString(), source, output)
            assertTrue(
                "exit $code must be treated as a completed scan, was $outcome",
                outcome is AshScanRunner.Outcome.Completed,
            )
            assertEquals(code, (outcome as AshScanRunner.Outcome.Completed).exitCode)
        }
    }

    fun testScannerStatusIsReadFromTheSecondFile() {
        // The completeness signal is NOT in reports/ash.sarif. It is in ash_aggregated_results.json,
        // a sibling of reports/, which ASH writes even when --output-formats asks only for sarif.
        // This asserts the runner actually goes and reads it.
        val source = Files.createDirectories(workdir.resolve("project"))
        val output = Files.createDirectories(workdir.resolve("out"))
        // Written by the stub during the run, as ASH does. A file placed there beforehand would be
        // removed by the runner's freshness guard, which is the point of that guard.
        val script = stubAsh(
            sarif("app.py", "error", 2),
            statusBody = """{"scanner_results": {"bandit": {"status": "PASSED"},
                                    "cdk-nag": {"status": "MISSING"}}}""",
        )

        val completed = AshScanRunner.run(script.toString(), source, output)
            as AshScanRunner.Outcome.Completed

        assertTrue("the status file must have been read", completed.scanners.available)
        assertEquals(listOf("cdk-nag"), completed.scanners.incomplete.map { it.name })
        assertNotNull(
            "a MISSING scanner must produce an incompleteness message",
            completed.scanners.describeIncompleteness(),
        )
    }

    fun testAbsentScannerStatusFileIsReportedAsUnknownNotAsComplete() {
        // A stub run writes no aggregated results file. The runner must say completeness is unknown
        // rather than let an empty panel read as a clean scan.
        val source = Files.createDirectories(workdir.resolve("project"))
        val output = Files.createDirectories(workdir.resolve("out"))
        val script = stubAsh(sarif("app.py", "error", 2))

        val completed = AshScanRunner.run(script.toString(), source, output)
            as AshScanRunner.Outcome.Completed

        assertFalse(completed.scanners.available)
        val described = completed.scanners.describeIncompleteness()
        assertNotNull("an absent status file must still warn", described)
        assertTrue(
            "must say where it looked; was: $described",
            described!!.contains("ash_aggregated_results.json"),
        )
    }

    fun testUndeletableStaleReportIsRefusedRatherThanReadAsCurrent() {
        // Fails, naming the cause, when run as root: root ignores the mode this test sets.
        PermissionEnforcement.require(workdir)
        // THE DEGRADED PATH OF THE STALE-REPORT GUARD, which previously had no coverage at all. The
        // pre-run delete was wrapped in runCatching with the result discarded, so on a read-only
        // output directory the guard became no guard: the delete fails, ASH writes nothing, the
        // previous run's report is still there, and isRegularFile reads it as this run's result.
        //
        // Forced by making the reports/ directory non-writable, so the delete genuinely fails rather
        // than being simulated.
        val source = Files.createDirectories(workdir.resolve("project"))
        val output = Files.createDirectories(workdir.resolve("out"))
        val reports = Files.createDirectories(output.resolve("reports"))
        val stale = reports.resolve("ash.sarif")
        Files.writeString(stale, sarif("old.py", "error", 99))

        // A stub that writes nothing, so the only file present is the stale one. Its own attempt to
        // write would also fail against the read-only directory.
        val script = stubAsh(sarifBody = null, exitCode = 0)
        Files.setPosixFilePermissions(
            reports,
            setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_EXECUTE),
        )
        try {
            val outcome = AshScanRunner.run(script.toString(), source, output)

            val failed = outcome as AshScanRunner.Outcome.Failed
            assertTrue(
                "must say the previous report could not be removed; was: ${failed.summary}",
                failed.summary.contains("could not be removed"),
            )
            assertTrue(
                "must say it is the previous run's result; was: ${failed.summary}",
                failed.summary.contains("PREVIOUS run"),
            )
            assertTrue(
                "must point at the writability cause; was: ${failed.summary}",
                failed.summary.contains("writable"),
            )
        } finally {
            // Restored so tearDown can delete the tree.
            Files.setPosixFilePermissions(
                reports,
                setOf(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE,
                ),
            )
        }
    }

    fun testUnstartableExecutableIsReportedRatherThanThrowing() {
        val source = Files.createDirectories(workdir.resolve("project"))
        val output = Files.createDirectories(workdir.resolve("out"))
        val missing = workdir.resolve("bin").resolve("does-not-exist")

        val outcome = AshScanRunner.run(missing.toString(), source, output)

        val failed = outcome as AshScanRunner.Outcome.Failed
        assertTrue(
            "must name what could not start; was: ${failed.summary}",
            failed.summary.contains("Could not start"),
        )
    }

    fun testFindingsFromAStubScanReachTheServiceKeyedByAbsolutePath() {
        // The last untested link: a relative SARIF path from a real scan must resolve to
        // the key the inspection looks up. Asserted through the service rather than by
        // calling AshPathResolver directly, so the wiring is what is under test.
        val source = Files.createDirectories(workdir.resolve("project"))
        val output = Files.createDirectories(workdir.resolve("out"))
        val script = stubAsh(sarif("src/app.py", "warning", 5))

        val completed = AshScanRunner.run(script.toString(), source, output)
            as AshScanRunner.Outcome.Completed

        val service = AshScanService.getInstance(project)
        try {
            service.update(completed.results)
            // The light fixture project's basePath is what update() resolves against, so
            // the expected key is derived the same way rather than hard-coded.
            val expected = AshPathResolver.toAbsoluteKey("src/app.py", project.basePath)
            val found = service.findingsFor(expected)
            assertEquals("expected one finding under key $expected", 1, found.size)
            assertEquals(AshLevel.WARNING, found[0].level)
            assertEquals(5, found[0].startLine)
        } finally {
            service.clear()
        }
    }

    fun testStubIsActuallyExecutedRatherThanSilentlySkipped() {
        // Positive control for this whole class. If the stub never ran, every assertion
        // above about what it wrote would be measuring a file nobody created -- and the
        // "missing report" test would pass for the wrong reason.
        val source = Files.createDirectories(workdir.resolve("project"))
        val output = Files.createDirectories(workdir.resolve("out"))
        val script = stubAsh(sarif("a.py", "note", 1))

        AshScanRunner.run(script.toString(), source, output)

        val report = output.resolve("reports").resolve("ash.sarif")
        assertTrue("the stub must have written $report", Files.exists(report))
        assertTrue(
            "and the runner must have passed --output-dir, or the stub wrote elsewhere",
            Files.readString(report).contains("STUB1"),
        )
        assertTrue("stub script should still be executable", File(script.toString()).canExecute())
    }

    /** A stub whose `--version` answers like ASH and whose `scan` runs [scanBody] with `$out` and `$src` set. */
    private fun rawStub(scanBody: String, versionBody: String = "echo 'awslabs/automated-security-helper v4.0.0'"): Path {
        val bin = Files.createDirectories(workdir.resolve("bin"))
        val script = bin.resolve("ashx")
        Files.writeString(
            script,
            buildString {
                appendLine("#!/bin/sh")
                appendLine("if [ \"\$1\" = --version ]; then $versionBody; exit 0; fi")
                appendLine("out=''")
                appendLine("src=''")
                appendLine(
                    "while [ \$# -gt 0 ]; do case \"\$1\" in --output-dir) out=\"\$2\"; shift 2;; " +
                        "--source-dir) src=\"\$2\"; shift 2;; *) shift;; esac; done",
                )
                appendLine(scanBody)
            },
        )
        Files.setPosixFilePermissions(
            script,
            setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE),
        )
        return script
    }

    private fun dirs(): Pair<Path, Path> =
        Files.createDirectories(workdir.resolve("project")) to Files.createDirectories(workdir.resolve("out"))

    fun testAScanThatOutlivesItsDeadlineIsAFailure() {
        val (source, output) = dirs()
        val script = rawStub("sleep 20; exit 0")
        var outcome: AshScanRunner.Outcome? = null
        val worker = thread { outcome = AshScanRunner.run(script.toString(), source, output, timeoutMillis = 3_000) }
        val stubs = StubProcesses.awaitDescendants("sleep")
        worker.join(20_000)

        val failed = outcome as AshScanRunner.Outcome.Failed
        assertTrue(failed.summary, failed.summary.contains("timed out"))
        StubProcesses.assertAllExited(stubs)
    }

    fun testAnExecutableThatVanishesAfterTheProbeIsReported() {
        // The probe ran it; by the time the scan starts it is gone.
        val (source, output) = dirs()
        val script = rawStub(scanBody = "exit 0", versionBody = "rm -f -- \"\$0\"; echo 'awslabs/automated-security-helper v4.0.0'")
        val failed = AshScanRunner.run(script.toString(), source, output) as AshScanRunner.Outcome.Failed
        assertTrue(failed.summary, failed.summary.startsWith("Could not start"))
        assertNotNull(failed.detail)
    }

    fun testAReportThatCannotBeReadIsAFailureRatherThanEmpty() {
        // Fails, naming the cause, when run as root: root ignores the mode this test sets.
        PermissionEnforcement.require(workdir)
        val (source, output) = dirs()
        val script = rawStub("mkdir -p \"\$out/reports\"; echo '{}' > \"\$out/reports/ash.sarif\"; chmod 000 \"\$out/reports/ash.sarif\"; exit 0")
        try {
            val failed = AshScanRunner.run(script.toString(), source, output) as AshScanRunner.Outcome.Failed
            assertTrue(failed.summary, failed.summary.contains("could not be read"))
        } finally {
            output.resolve("reports/ash.sarif").toFile().setReadable(true)
        }
    }

    fun testAStatusFileThatCannotBeReadIsUnknownCompleteness() {
        // Fails, naming the cause, when run as root: root ignores the mode this test sets.
        PermissionEnforcement.require(workdir)
        val (source, output) = dirs()
        val status = "\"\$out/ash_aggregated_results.json\""
        val script = rawStub(
            "mkdir -p \"\$out/reports\"; echo '{\"runs\":[]}' > \"\$out/reports/ash.sarif\"; " +
                "echo '{}' > $status; chmod 000 $status; exit 0",
        )
        try {
            val completed = AshScanRunner.run(script.toString(), source, output) as AshScanRunner.Outcome.Completed
            assertFalse(completed.scanners.available)
            assertTrue(completed.scanners.unavailableReason, completed.scanners.unavailableReason!!.startsWith("could not read"))
        } finally {
            output.resolve("ash_aggregated_results.json").toFile().setReadable(true)
        }
    }

    fun testLongOutputIsCarriedAsItsTail() {
        val (source, output) = dirs()
        val script = rawStub("i=0; while [ \$i -lt 300 ]; do printf 'line-%04d\\n' \$i >&2; i=\$((i+1)); done; exit 3")
        val failed = AshScanRunner.run(script.toString(), source, output) as AshScanRunner.Outcome.Failed
        val detail = failed.detail!!
        assertTrue(detail.take(20), detail.startsWith("..."))
        assertEquals(1203, detail.length)
        assertTrue("the END is what is kept", detail.endsWith("line-0299"))
    }

    fun testADirectoryWhereTheReportGoesIsAFailureNotARead() {
        // The delete fails (a non-empty directory), nothing regular is there to be stale, and
        // ASH cannot write over it -- so there is no report, and that is what is said.
        val (source, output) = dirs()
        Files.createDirectories(output.resolve("reports/ash.sarif/inner"))
        val script = rawStub("cat > \"\$out/reports/ash.sarif\" < /dev/null 2>/dev/null; exit 0")
        val failed = AshScanRunner.run(script.toString(), source, output) as AshScanRunner.Outcome.Failed
        assertTrue(failed.summary, failed.summary.contains("wrote no SARIF"))
    }

    /** Waits for a stub to create [marker], so a test acts while the stub is mid-scan. */
    private fun awaitFile(marker: Path, timeoutMillis: Long = 30_000) {
        val deadline = System.currentTimeMillis() + timeoutMillis
        while (!Files.exists(marker)) {
            assertTrue("the stub never created $marker", System.currentTimeMillis() < deadline)
            Thread.sleep(20)
        }
    }

    private fun millisSince(startNanos: Long): Long = (System.nanoTime() - startNanos) / 1_000_000

    fun testTheScanRunsInTheSourceDirectorySoRelativeUrisMatchTheScannedTree() {
        // ASH writes SARIF URIs relative to its WORKING DIRECTORY, not to --source-dir. This stub
        // does the same: it records its cwd and writes the URI of $src/app.py relative to it. So a
        // runner that let the child inherit the IDE's cwd gets a URI like ../../tmp/.../app.py,
        // and every finding is keyed against a file that is not the one the user has open.
        //
        // The relative path is computed in POSIX sh, not with `realpath --relative-to`, which is
        // GNU-only and absent on macOS. A file under the cwd gets its path below it; anything else
        // gets its absolute path. Either way, a child in the wrong directory writes a URI that is
        // not `app.py`.
        val (source, output) = dirs()
        Files.writeString(source.resolve("app.py"), "x\n")
        val cwd = workdir.resolve("cwd.txt")
        val script = rawStub(
            "here=\$(pwd -P); printf '%s\\n' \"\$here\" > '$cwd'; f=\"\$(cd \"\$src\" && pwd -P)/app.py\"; " +
                "case \"\$f\" in \"\$here\"/*) rel=\"\${f#\"\$here\"/}\";; *) rel=\"\$f\";; esac; " +
                "mkdir -p \"\$out/reports\"; " +
                "printf '%s' '{\"version\":\"2.1.0\",\"runs\":[{\"results\":[{\"ruleId\":\"R\",\"level\":\"error\"," +
                "\"message\":{\"text\":\"m\"},\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":\"' " +
                "> \"\$out/reports/ash.sarif\"; " +
                "printf '%s' \"\$rel\" >> \"\$out/reports/ash.sarif\"; " +
                "printf '%s' '\"},\"region\":{\"startLine\":1}}}]}]}]}' >> \"\$out/reports/ash.sarif\"; exit 2",
        )

        val completed = AshScanRunner.run(script.toString(), source, output) as AshScanRunner.Outcome.Completed

        assertEquals("app.py", completed.results.findings.single().filePath)
        assertEquals("the child must run in the scanned directory", source.toRealPath().toString(), Files.readString(cwd).trim())
    }

    fun testTheProbeGivesTheChildNoStdinToWaitOn() {
        // A child that reads stdin must see end-of-file at once. Given an open pipe instead, this
        // one would wait out the probe's 30 s deadline and real ASH would be reported as not ASH.
        val script = rawStub("exit 0", versionBody = "read x; echo 'awslabs/automated-security-helper v4.0.0'")

        val start = System.nanoTime()
        val verdict = AshScanRunner.probe(script.toString())
        val elapsed = millisSince(start)

        assertTrue("$verdict", verdict is AshIdentityProbe.Verdict.IsAsh)
        assertTrue("the probe waited $elapsed ms on stdin", elapsed < 5_000)
    }

    fun testTheScanGivesTheChildNoStdinToWaitOn() {
        // The same for the scan, whose deadline is 30 minutes in the IDE.
        val (source, output) = dirs()
        val script = rawStub("read x; mkdir -p \"\$out/reports\"; echo '{\"runs\":[]}' > \"\$out/reports/ash.sarif\"; exit 0")

        val start = System.nanoTime()
        val outcome = AshScanRunner.run(script.toString(), source, output, timeoutMillis = 15_000)
        val elapsed = millisSince(start)

        assertTrue("$outcome", outcome is AshScanRunner.Outcome.Completed)
        assertTrue("the scan waited $elapsed ms on stdin", elapsed < 5_000)
    }

    fun testCancellingAScanSaysItWasCancelledRatherThanBlamingAnExitCode() {
        // Pressing Cancel kills the child, which then exits 137 (SIGKILL) or 143 (SIGTERM) on
        // POSIX and 1 on Windows. None of those is ASH's verdict, so none may be reported as one.
        val source = Files.createDirectories(workdir.resolve("project"))
        val started = workdir.resolve("started")
        val script = rawStub("touch '$started'; sleep 300; exit 0")
        val indicator = EmptyProgressIndicator()
        var messages: List<AshScanController.Message>? = null

        val worker = thread {
            messages = AshScanController.scan(project, script.toString(), indicator = indicator, sourceDir = source)
        }
        awaitFile(started)
        val stubs = StubProcesses.awaitDescendants("sleep")
        indicator.cancel()
        worker.join(20_000)

        assertFalse("the scan must stop when cancelled", worker.isAlive)
        val message = messages!!.single()
        assertEquals("ASH scan cancelled", message.title)
        assertEquals(NotificationType.WARNING, message.type)
        assertFalse("a cancel is not an exit code: ${message.body}", message.body.contains("exited"))
        StubProcesses.assertAllExited(stubs)
    }

    fun testCancellingDuringTheProbeStopsItAtOnceAndIsReportedAsCancelled() {
        // The probe has a 30 s deadline. A probe that ignored the indicator would hold a pressed
        // Cancel for all of it and then report the executable as not ASH, which it is.
        val (source, output) = dirs()
        val started = workdir.resolve("started")
        val script = rawStub("exit 0", versionBody = "touch '$started'; sleep 300")
        val indicator = EmptyProgressIndicator()
        var outcome: AshScanRunner.Outcome? = null

        val worker = thread { outcome = AshScanRunner.run(script.toString(), source, output, indicator) }
        awaitFile(started)
        val stubs = StubProcesses.awaitDescendants("sleep")
        val cancelledAt = System.nanoTime()
        indicator.cancel()
        worker.join(20_000)
        val elapsed = millisSince(cancelledAt)

        assertFalse("the probe must stop when cancelled", worker.isAlive)
        assertEquals(AshScanRunner.Outcome.Cancelled, outcome)
        assertTrue("the probe took $elapsed ms to honor the cancel", elapsed < 10_000)
        StubProcesses.assertAllExited(stubs)
    }

    fun testASecondScanWhileOneRunsIsRefusedAndTheFirstStillReportsItsResult() {
        // Two scans would share <project>/.ash/ash_output: the second's freshness guard deletes the
        // first's report, and either can read the other's file half-written. So the second is
        // refused, and the user gets the first one's result when it finishes.
        val source = Files.createDirectories(workdir.resolve("project"))
        val started = workdir.resolve("started")
        val release = workdir.resolve("release")
        val count = workdir.resolve("count")
        val script = rawStub(
            "echo run >> '$count'; touch '$started'; while [ ! -f '$release' ]; do sleep 0.05; done\n" +
                "mkdir -p \"\$out/reports\"\ncat > \"\$out/reports/ash.sarif\" <<'SARIF_EOF'\n" +
                sarif("app.py", "error", 2) + "\nSARIF_EOF\n" +
                "echo '{\"scanner_results\": {\"bandit\": {\"status\": \"PASSED\"}}}' > \"\$out/ash_aggregated_results.json\"\n" +
                "exit 2",
        )
        fun scan() = AshScanController.scan(project, script.toString(), sourceDir = source)

        var firstMessages: List<AshScanController.Message>? = null
        var secondMessages: List<AshScanController.Message>? = null
        val first = thread { firstMessages = scan() }
        try {
            awaitFile(started)
            val second = thread { secondMessages = scan() }
            second.join(10_000)
            assertFalse("a second scan must neither wait on the first nor run beside it", second.isAlive)
            val refused = secondMessages!!.single()
            assertEquals("ASH scan already running", refused.title)
            assertEquals(NotificationType.INFORMATION, refused.type)
            assertEquals("only one ASH process may have started", 1, Files.readAllLines(count).size)
        } finally {
            Files.writeString(release, "go")
            first.join(30_000)
        }
        assertEquals("ASH scan finished", firstMessages!!.single().title)

        // And the guard is released once the first finishes, failure or not.
        assertEquals("ASH scan finished", scan().single().title)
        assertEquals(2, Files.readAllLines(count).size)
        AshScanService.getInstance(project).clear()
    }

    fun testATruncatedOrNonSarifReportIsAFailureRatherThanNoFindings() {
        // A report that cannot be parsed has told us nothing. Reading it as "no findings" would put
        // a clean verdict over a file nobody could read.
        val source = Files.createDirectories(workdir.resolve("project"))
        val whole = sarif("app.py", "error", 2)
        val bodies = listOf(whole.substring(0, whole.length / 2), "[]", "{\"version\": \"2.1.0\"}")
        for ((i, body) in bodies.withIndex()) {
            val output = Files.createDirectories(workdir.resolve("out-bad-$i"))
            val script = stubAsh(sarifBody = body, exitCode = 2)
            val outcome = AshScanRunner.run(script.toString(), source, output)
            val failed = outcome as? AshScanRunner.Outcome.Failed
            assertNotNull("an unreadable report must fail the scan: $body -> $outcome", failed)
            assertTrue(failed!!.summary, failed.summary.contains("not a readable SARIF report"))
            assertTrue(failed.summary, failed.summary.contains("not the same as finding nothing"))
        }
    }
}
