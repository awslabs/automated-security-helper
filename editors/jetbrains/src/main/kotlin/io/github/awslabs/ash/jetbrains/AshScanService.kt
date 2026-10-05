// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import com.intellij.codeInsight.daemon.DaemonCodeAnalyzer
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.Service
import com.intellij.openapi.components.service
import com.intellij.openapi.project.Project
import java.util.concurrent.atomic.AtomicReference

/**
 * Holds the findings from the most recent scan, keyed by absolute file path.
 *
 * The scan runs once, on demand; the inspection runs continuously as the user moves
 * around the project. This service is the seam between them. It keeps the last result
 * and nothing else -- no caching across sessions, no persistence -- because a stale
 * finding presented as current is worse than no finding: it points at a line the user
 * may already have fixed.
 */
@Service(Service.Level.PROJECT)
class AshScanService(private val project: Project) {

    /**
     * An [AtomicReference] rather than a plain field with a lock. The inspection reads
     * this from the highlighting pass on a pooled thread while the scan task writes it
     * from another; an unsynchronized field could hand the inspection a half-built map.
     */
    private val state = AtomicReference(State.EMPTY)

    data class State(
        val findingsByPath: Map<String, List<AshFinding>>,
        val problems: List<String>,
        val hasRun: Boolean,
    ) {
        companion object {
            val EMPTY = State(emptyMap(), emptyList(), hasRun = false)
        }
    }

    val current: State get() = state.get()

    /** Findings for one file, or empty. The key must already be normalized. */
    fun findingsFor(absolutePath: String): List<AshFinding> =
        state.get().findingsByPath[AshPathResolver.normalize(absolutePath)] ?: emptyList()

    /**
     * Replaces the held findings and asks the IDE to re-highlight.
     *
     * Without the [DaemonCodeAnalyzer] restart the new findings sit here unread until
     * something else happens to invalidate highlighting -- the scan would report success
     * and the editor would show nothing, which is the exact shape of failure this plugin
     * is required not to have.
     */
    /**
     * @param sourceRoot the directory the scan ran over, which is what ASH's relative paths are
     *   relative to. It defaults to the project's base directory because that is what the scan
     *   action scans; it is a parameter so the root used to key findings is always the root that
     *   was scanned, rather than two values that happen to agree.
     */
    fun update(results: AshScanResults, sourceRoot: String? = project.basePath) {
        val grouped = results.findings
            .groupBy { AshPathResolver.toAbsoluteKey(it.filePath, sourceRoot) }
        state.set(State(grouped, results.problems, hasRun = true))
        restartHighlighting()
    }

    fun clear() {
        state.set(State.EMPTY)
        restartHighlighting()
    }

    /**
     * DO NOT "FIX" THE DEPRECATION ON [DaemonCodeAnalyzer.restart]. The no-argument overload
     * is deprecated from build 253, and `verifyPlugin` reports it as one deprecated usage
     * against IU-253 and later while still returning Compatible. The replacement that takes
     * a reason string does not exist in build 252, which is this plugin's declared floor and
     * its compile target -- `DaemonCodeAnalyzer` in 2025.2.5 declares only `restart()` and
     * `restart(PsiFile)`. Calling the newer overload would raise the floor to 253 to silence
     * a warning.
     *
     * `restart(PsiFile)` is not the answer either: a scan updates findings across many files
     * at once, so the restart has to be project-wide.
     */
    private fun restartHighlighting() {
        if (project.isDisposed) return
        ApplicationManager.getApplication().invokeLater(
            { if (!project.isDisposed) @Suppress("DEPRECATION") DaemonCodeAnalyzer.getInstance(project).restart() },
            project.disposed,
        )
    }

    companion object {
        fun getInstance(project: Project): AshScanService = project.service()
    }
}
