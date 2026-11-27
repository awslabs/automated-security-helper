// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import com.intellij.notification.NotificationType
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.project.Project
import java.nio.file.Files
import java.nio.file.Path

/**
 * One scan, from choosing the executable to the notification the user reads.
 *
 * Every arm ends either in findings the user can see or a notification saying why there are
 * none, and an incomplete scan ends in both. There is no path that finishes quietly having done
 * nothing. Each message is returned as well as shown, so a test can assert what the user was
 * told without depending on how the platform renders a balloon.
 */
object AshScanController {

    data class Message(val type: NotificationType, val title: String, val body: String)

    /**
     * Runs a scan over [project] and publishes the result.
     *
     * Must not be called on the EDT. Resolving the executable stats a file in every PATH entry,
     * and an unreachable network mount on PATH can take seconds to answer.
     *
     * @param configured the Settings value; see [AshCliLocator.resolve].
     * @param notice the once-per-session fallback notice. Injectable so a test gets a fresh one.
     * @param sourceDir what to scan: the project's base directory unless a test says otherwise.
     */
    fun scan(
        project: Project,
        configured: String?,
        pathValue: String? = System.getenv("PATH"),
        indicator: ProgressIndicator? = null,
        notice: AshCliLocator.FallbackNotice = AshCliLocator.fallbackNotice,
        sourceDir: Path? = project.basePath?.let { Path.of(it) },
    ): List<Message> {
        // A second scan while one runs is refused, not queued and not run beside it; the running
        // scan's notification is the answer to both clicks. The action is also disabled while a
        // scan runs, but that check and a click can race, so this is the one that decides.
        val service = AshScanService.getInstance(project)
        val messages = if (service.tryStartScan()) {
            try {
                run(project, sourceDir, configured, pathValue, indicator, notice)
            } finally {
                service.finishScan()
            }
        } else {
            listOf(
                Message(
                    NotificationType.INFORMATION,
                    "ASH scan already running",
                    "A scan of this project is already running, so another was not started. " +
                        "Its result is shown when it finishes.",
                ),
            )
        }
        for (message in messages) {
            AshNotifier.notify(project, message.title, message.body, message.type)
        }
        return messages
    }

    private fun run(
        project: Project,
        sourceDir: Path?,
        configured: String?,
        pathValue: String?,
        indicator: ProgressIndicator?,
        notice: AshCliLocator.FallbackNotice,
    ): List<Message> {
        if (sourceDir == null) {
            return listOf(
                Message(
                    NotificationType.ERROR,
                    "ASH scan not started",
                    "This project has no base directory on disk, so there is nothing to scan.",
                ),
            )
        }

        indicator?.text = "Looking for the ASH executable"
        val located = when (val outcome = AshCliLocator.resolve(configured, pathValue)) {
            is AshCliLocator.Outcome.NotFound -> return listOf(notFound(outcome))
            is AshCliLocator.Outcome.Found -> outcome
        }

        val messages = mutableListOf<Message>()
        if (located.source == AshCliLocator.Source.FALLBACK && notice.claim()) {
            messages += Message(
                NotificationType.INFORMATION,
                "ASH: using '${AshCliLocator.FALLBACK_NAME}'",
                escape(notice.message(located.path)),
            )
        }

        val outputDir = try {
            // Inside the project's own .ash directory, which is where ASH writes by default and
            // which ASH excludes from its own scan, so the SARIF the user can open is the one the
            // plugin read.
            Files.createDirectories(sourceDir.resolve(".ash").resolve("ash_output"))
        } catch (e: Exception) {
            messages += Message(
                NotificationType.ERROR,
                "ASH scan not started",
                escape("Could not create the output directory under ${sourceDir.resolve(".ash")}: ${e.message}"),
            )
            return messages
        }

        indicator?.text = "Running ${located.path} scan"
        val service = AshScanService.getInstance(project)
        when (val outcome = AshScanRunner.run(located.path, sourceDir, outputDir, indicator)) {
            is AshScanRunner.Outcome.Failed -> {
                // The previous run's findings are dropped. Leaving them on screen after a
                // failed scan would present stale results as current.
                service.clear()
                messages += Message(
                    NotificationType.ERROR,
                    "ASH scan failed",
                    escape(outcome.summary) + (outcome.detail?.let { "<br><br><pre>${escape(it)}</pre>" } ?: ""),
                )
            }

            is AshScanRunner.Outcome.Cancelled -> {
                // Cleared, as after a failure, because nothing on screen would be this run's
                // result. A cancel during the scan comes after the freshness guard removed the
                // report the previous findings came from. A cancel during the identity probe
                // comes before the guard, so that report is still on disk, but it is the
                // previous run's, and the message below says no findings are shown.
                service.clear()
                messages += Message(
                    NotificationType.WARNING,
                    "ASH scan cancelled",
                    "The scan was cancelled and ASH was stopped before it finished. No findings " +
                        "are shown, and this is not a clean result.",
                )
            }

            is AshScanRunner.Outcome.Completed -> {
                service.update(outcome.results, sourceDir.toString())
                messages += report(outcome)
            }
        }
        return messages
    }

    internal fun notFound(located: AshCliLocator.Outcome.NotFound) = Message(
        NotificationType.ERROR,
        "ASH CLI not found",
        buildString {
            append(escape(located.reason))
            if (located.searched.isNotEmpty()) {
                append("<br><br>Searched ${located.searched.size} PATH entr")
                append(if (located.searched.size == 1) "y" else "ies")
                append(", including: ")
                append(located.searched.take(6).joinToString(", ") { escape(it) })
                if (located.searched.size > 6) append(", ...")
            }
        },
    )

    /**
     * What the scan produced, including what it could not read and what did not run.
     *
     * An incomplete scan is a WARNING even when it found nothing, and that is the point: the
     * quiet, successful-looking run over a host missing half its scanners is the case an
     * informational balloon would let past.
     */
    internal fun report(outcome: AshScanRunner.Outcome.Completed): Message {
        val results = outcome.results
        val findings = results.findings
        val problems = results.problems
        val incompleteness = outcome.scanners.describeIncompleteness()

        val counts = AshLevel.entries
            .reversed()
            .mapNotNull { level ->
                val n = findings.count { it.level == level }
                if (n == 0) null else "$n ${level.sarifValue}"
            }
            .joinToString(", ")

        val body = buildString {
            if (outcome.partial) {
                append("ASH reported this scan INCOMPLETE (exit 1): it did not cover everything ")
                append("it was asked to. ")
                if (findings.isEmpty()) {
                    append("It produced no findings that can be shown, which is not a clean result.")
                } else {
                    append("Showing the ${findings.size} finding(s) it did produce: $counts. ")
                    append("Findings from the parts that did not run are absent.")
                }
            } else if (findings.isEmpty()) {
                if (incompleteness != null) {
                    append("ASH reported no findings, but the scan was NOT complete.")
                } else {
                    append("ASH reported no findings that can be shown in the editor.")
                }
            } else {
                append("${findings.size} finding(s): $counts.")
            }

            if (incompleteness != null) {
                // Escaped: scanner, converter and rule names and notification messages are the
                // report's text, not this plugin's markup.
                append("<br><br>${escape(incompleteness)}")
            } else if (outcome.partial) {
                // ASH's verdict, with nothing in the status file to name: the status file is
                // missing a reason ASH printed, so the console is where ASH said why.
                append("<br><br>The status file names no scanner that failed to complete; ")
                append("ASH's own output gives the reason")
                if (outcome.outputTail.isNotBlank()) {
                    append(":<br><pre>${escape(outcome.outputTail)}</pre>")
                } else {
                    append(", and it printed nothing.")
                }
            } else if (outcome.scanners.available) {
                append("<br>${outcome.scanners.complete.size} scanner(s) completed.")
            }
            // The suppressed count is shown because the difference between "ASH found 34" and
            // "ASH found 126 and your configuration suppressed 92" is the whole story of a scan.
            if (results.suppressedResults > 0) {
                append("<br>${results.suppressedResults} of ${results.totalResults} result(s) ")
                append("suppressed by the report.")
            }
            append("<br>${escape(outcome.versionLine)}, exit code ${outcome.exitCode}. ")
            append("Report: ${escape(outcome.sarifPath)}")
            // A result that fell out of every bucket is a counting bug in this plugin, not a
            // property of the scan, so it is reported as such rather than silently absorbed.
            if (!results.accountsForEveryResult) {
                val accounted = results.surfacedResults + results.suppressedResults +
                    results.noSeverityResults + results.unlocatableResults
                append(
                    "<br><b>Internal inconsistency:</b> ${results.totalResults} result(s) were " +
                        "read but $accounted were accounted for. Some findings may be missing " +
                        "from the editor.",
                )
            }
            if (problems.isNotEmpty()) {
                append("<br><br>${problems.size} part(s) of the report could not be read:<br>")
                append(problems.take(10).joinToString("<br>") { "&bull; ${escape(it)}" })
                if (problems.size > 10) append("<br>&bull; ...")
            }
        }

        return when {
            !outcome.coverageComplete -> Message(NotificationType.WARNING, "ASH scan incomplete", body)
            problems.isNotEmpty() -> Message(NotificationType.WARNING, "ASH scan finished with gaps", body)
            else -> Message(NotificationType.INFORMATION, "ASH scan finished", body)
        }
    }

    /**
     * Notification bodies are HTML, and nothing interpolated into them is: ASH's output, SARIF
     * text, file paths and PATH entries are all plain text, and a path may contain `&` or `<`.
     * Every interpolation goes through this; only the markup written here is left raw.
     */
    private fun escape(text: String): String =
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
}
