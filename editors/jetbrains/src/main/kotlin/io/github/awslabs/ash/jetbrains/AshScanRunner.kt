// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import com.intellij.execution.configurations.GeneralCommandLine
import com.intellij.execution.process.CapturingProcessHandler
import com.intellij.execution.process.ProcessOutput
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.util.SystemInfo
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.FileTime

/**
 * Runs `scan` with the resolved ASH executable and reads what it wrote.
 *
 * THE EXIT-CODE CONTRACT, which is ASH's and not this plugin's:
 *
 *   0  the scan finished and found nothing actionable
 *   1  the scan finished WITHOUT FULL COVERAGE -- a selected scanner was MISSING or ERROR, no
 *      scanner reached a verdict, a converter failed, a rule went unevaluated, or a content
 *      database was past its bound -- and the results it did produce are on disk. ASH raises
 *      this as ScanIncompleteExit, and since fail_on_incomplete_scanners became the default it
 *      is the ordinary outcome on a host missing some scanner tools. Exit 1 is ALSO what a
 *      crash produces; the two are told apart by whether a report was written.
 *   2  the scan finished and found actionable findings
 *   3  the configuration is invalid; 4 is a workspace or policy error. Neither ran a scan.
 *
 * So exit 1 WITH a fresh report is shown: its findings are real, and hiding them because other
 * scanners did not run would make the IDE show less than the command line does. It is shown as
 * PARTIAL, in a warning that names what did not run, so an empty or short panel cannot be read
 * as a clean scan. Exit 1 with no report is a failure. Every other code outside 0..2 is a
 * failure, whether or not something was left on disk -- an allowlist, so a code ASH adds later
 * is refused until someone decides what it means.
 *
 * WHAT THE REPORT BEING PRESENT PROVES. Both files this reads are deleted before the run, so a
 * report on disk afterwards was written by this run. When a delete fails (a read-only output
 * directory), the file's modification time is the fallback, and it fails closed: a report whose
 * time did not move is refused as the previous run's.
 */
object AshScanRunner {

    /** Where `ash scan` writes its aggregated report, relative to `--output-dir`. */
    private const val SARIF_RELATIVE_PATH = "reports/ash.sarif"

    const val EXIT_CLEAN = 0
    const val EXIT_INCOMPLETE = 1
    const val EXIT_FINDINGS = 2

    /** The exit codes whose report is read. See the class note for why 1 is here. */
    private val READABLE_EXIT_CODES = setOf(EXIT_CLEAN, EXIT_INCOMPLETE, EXIT_FINDINGS)

    /** Characters of stdout/stderr carried into a message. Enough to diagnose, not enough to flood a balloon. */
    private const val OUTPUT_TAIL_CHARS = 1200

    sealed interface Outcome {
        /**
         * ASH ran and wrote a report this run, which was read.
         *
         * @param outputTail the end of ASH's own output, kept for the incomplete case: ASH prints
         *   the reasons a scan was incomplete there, and the status file can name fewer of them
         *   than the console does (an unevaluated rule or a stale database has no scanner row).
         */
        data class Completed(
            val exitCode: Int,
            val results: AshScanResults,
            val sarifPath: String,
            val scanners: AshScannerStatus.Report,
            val versionLine: String,
            val outputTail: String,
        ) : Outcome {
            /** ASH said the scan did not cover everything; the findings are what it did produce. */
            val partial: Boolean get() = exitCode == EXIT_INCOMPLETE

            /**
             * The same question ASH's MCP payload answers as `coverage_complete`: true only when
             * nothing names a gap. False when ASH exited 1, which is ASH's own verdict, and false
             * when the status file names a scanner that did not complete or shows nothing reached
             * a verdict, which catches a run made with fail_on_incomplete_scanners turned off.
             * Also false when the status file could not be read, because an unread file is not
             * evidence that every scanner ran.
             */
            val coverageComplete: Boolean
                get() = !partial && scanners.describeIncompleteness() == null
        }

        /** The scan did not get far enough to produce a readable report of this run. */
        data class Failed(val summary: String, val detail: String?) : Outcome

        /**
         * The user cancelled, and the child was killed. Its exit code is the kill's, not ASH's
         * verdict -- 137 or 143 on POSIX, 1 on Windows -- so it is not read as one.
         */
        data object Cancelled : Outcome
    }

    /**
     * @param executable what [AshCliLocator] resolved: an absolute path, or a configured value
     *   used as given.
     * @param indicator when given, the child process is killed if the user cancels. A cancel
     *   button that stops the progress bar while a full repository scan keeps running is worse
     *   than no cancel button.
     * @param timeoutMillis a ceiling that prevents an indefinitely hung child, not a
     *   performance budget.
     */
    fun run(
        executable: String,
        sourceDir: Path,
        outputDir: Path,
        indicator: ProgressIndicator? = null,
        timeoutMillis: Int = 30 * 60 * 1000,
    ): Outcome {
        val versionLine = when (val verdict = probe(executable)) {
            is AshIdentityProbe.Verdict.NotAsh -> return Outcome.Failed(verdict.message, null)
            is AshIdentityProbe.Verdict.IsAsh -> verdict.versionLine
        }

        val sarifPath = outputDir.resolve(SARIF_RELATIVE_PATH)
        val statusPath = outputDir.resolve(AshScannerStatus.RELATIVE_PATH)
        val sarifGuard = FreshnessGuard.prepare(sarifPath)
        val statusGuard = FreshnessGuard.prepare(statusPath)

        val commandLine = commandLine(
            executable,
            "scan",
            "--source-dir", sourceDir.toString(),
            "--output-dir", outputDir.toString(),
            // Only the SARIF is read, so asking for only the SARIF avoids paying for report
            // formats nothing here consumes. ash_aggregated_results.json is written regardless.
            "--output-formats", "sarif",
            // The IDE is not a terminal; progress rendering would go into the captured output
            // and make the tail unreadable.
            "--no-progress",
        )
            // LOAD-BEARING, not tidiness. ASH writes SARIF URIs relative to its WORKING DIRECTORY,
            // not to --source-dir: measured, a run from the project's parent recorded `src/leak.py`
            // where a run from the project recorded `leak.py`. AshScanService keys findings
            // against the scanned directory, so any other working directory misplaces every one.
            .withWorkDirectory(sourceDir.toFile())

        val output = try {
            val handler = CapturingProcessHandler(commandLine)
            if (indicator == null) {
                handler.runProcess(timeoutMillis)
            } else {
                handler.runProcessWithProgressIndicator(indicator, timeoutMillis, true)
            }
        } catch (e: Exception) {
            return Outcome.Failed("Could not start '$executable'.", "${e::class.simpleName}: ${e.message}")
        }
        val outputTail = tail(output)

        // Before every exit-code check. A killed child's exit code would otherwise be reported
        // as "ASH exited 137 ... an invalid configuration", or on Windows as "exited 1 and wrote
        // no SARIF", after the user pressed Cancel.
        if (output.isCancelled) return Outcome.Cancelled

        if (output.isTimeout) {
            return Outcome.Failed("ASH scan timed out after ${timeoutMillis / 60000} minute(s).", outputTail)
        }

        if (output.exitCode !in READABLE_EXIT_CODES) {
            return Outcome.Failed(
                "ASH exited ${output.exitCode}, which means the scan did not run: 3 is an " +
                    "invalid configuration and 4 a workspace or policy error, and any other code " +
                    "is not one this plugin knows. Nothing at $sarifPath is shown as a result.",
                outputTail,
            )
        }

        if (!Files.isRegularFile(sarifPath)) {
            val why = if (output.exitCode == EXIT_INCOMPLETE) {
                "ASH exited 1 and wrote no SARIF report at $sarifPath, so it stopped before " +
                    "producing results. No findings can be shown, and this is not the same as " +
                    "finding nothing."
            } else {
                "ASH scan finished with exit code ${output.exitCode} but wrote no SARIF report " +
                    "at $sarifPath. No findings can be shown, and this is not the same as " +
                    "finding nothing."
            }
            return Outcome.Failed(why, outputTail)
        }

        if (sarifGuard.isStale()) {
            return Outcome.Failed(
                "The previous report at $sarifPath could not be removed before the scan " +
                    "(${sarifGuard.deleteError}) and it has not been rewritten since, so it is " +
                    "the PREVIOUS run's result rather than this one's. Refusing to show it as " +
                    "current. Check that the output directory is writable.",
                outputTail,
            )
        }

        val text = try {
            Files.readString(sarifPath)
        } catch (e: Exception) {
            return Outcome.Failed(
                "ASH wrote $sarifPath but it could not be read.",
                "${e::class.simpleName}: ${e.message}",
            )
        }

        return Outcome.Completed(
            exitCode = output.exitCode,
            results = AshSarifParser.parse(text),
            sarifPath = sarifPath.toString(),
            scanners = readScannerStatus(statusPath, statusGuard),
            versionLine = versionLine,
            outputTail = outputTail,
        )
    }

    /**
     * Runs `<executable> --version` and classifies the answer. A process that cannot start is
     * reported as not ASH, with the reason, rather than thrown.
     */
    fun probe(executable: String): AshIdentityProbe.Verdict {
        val output = try {
            CapturingProcessHandler(commandLine(executable, "--version"))
                .runProcess(AshIdentityProbe.TIMEOUT_SECONDS * 1000)
        } catch (e: Exception) {
            return AshIdentityProbe.Verdict.NotAsh(
                "Could not start '$executable': ${e::class.simpleName}: ${e.message}. Install " +
                    "ASH, or set the full path to it in Settings | Tools | ASH.",
            )
        }
        return AshIdentityProbe.classify(executable, output.isTimeout, output.stdout + "\n" + output.stderr)
    }

    /**
     * A command line whose stdin is the null device.
     *
     * A shell invoked in a way it reads as interactive READS STDIN. With a pipe that is never
     * written or closed, that child would never exit and never write anything, and the scan
     * would wait on a process that is waiting on it. The probe's deadline bounds anything that
     * ignores EOF as well.
     */
    private fun commandLine(vararg args: String): GeneralCommandLine =
        GeneralCommandLine(*args).withInput(File(if (SystemInfo.isWindows) "NUL" else "/dev/null"))

    /**
     * Reads the per-scanner status file, or reports why it could not.
     *
     * Deliberately NOT fatal: the findings are still worth showing. What must not happen is
     * silently concluding that every scanner ran, so an unreadable or stale file becomes an
     * "unknown completeness" warning rather than nothing at all.
     */
    private fun readScannerStatus(path: Path, guard: FreshnessGuard): AshScannerStatus.Report {
        if (!Files.isRegularFile(path)) {
            return AshScannerStatus.unavailable("no status file at $path")
        }
        if (guard.isStale()) {
            return AshScannerStatus.unavailable(
                "$path is from a previous run: it could not be removed before the scan " +
                    "(${guard.deleteError}) and was not rewritten",
            )
        }
        return try {
            AshScannerStatus.parse(Files.readString(path))
        } catch (e: Exception) {
            AshScannerStatus.unavailable("could not read $path (${e::class.simpleName}: ${e.message})")
        }
    }

    private fun tail(output: ProcessOutput): String {
        val text = output.stderr.trim().ifBlank { output.stdout.trim() }
        if (text.length <= OUTPUT_TAIL_CHARS) return text
        return "..." + text.takeLast(OUTPUT_TAIL_CHARS)
    }

    /**
     * Removes a file before the run, and remembers enough to tell afterwards whether what is on
     * disk was written by this run.
     *
     * The failure of the delete is NOT swallowed. A delete that fails silently degrades the
     * guard to no guard in exactly the case it exists for: a read-only output directory where
     * ASH writes nothing, the previous run's report is still there, and it is read as this
     * run's. So a failed delete with a file present records the file's modification time, and
     * [isStale] fails closed on it: an unchanged or unreadable time is reported as stale.
     */
    internal class FreshnessGuard private constructor(
        private val path: Path,
        private val baseline: FileTime?,
        val deleteError: String?,
    ) {
        fun isStale(): Boolean {
            if (baseline == null) return false
            val current = runCatching { Files.getLastModifiedTime(path) }.getOrNull() ?: return true
            return current <= baseline
        }

        companion object {
            fun prepare(path: Path): FreshnessGuard {
                val deleted = runCatching { Files.deleteIfExists(path) }
                val error = deleted.exceptionOrNull() ?: return FreshnessGuard(path, null, null)
                val description = "${error::class.simpleName}: ${error.message}"
                if (!Files.isRegularFile(path)) return FreshnessGuard(path, null, description)
                val baseline = runCatching { Files.getLastModifiedTime(path) }.getOrNull()
                    ?: FileTime.fromMillis(Long.MAX_VALUE)
                return FreshnessGuard(path, baseline, description)
            }
        }
    }
}
