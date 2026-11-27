// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

/**
 * Decides, from `<executable> --version`, whether the executable is ASH at all.
 *
 * WHY A SCAN IS PRECEDED BY THIS. `ash` is also the name of the Almquist shell, which MSYS2
 * ships on Windows and which has already shadowed ASH's entry point in this project's CI,
 * producing `Illegal option --`. JetBrains IDEs run on Windows, this plugin falls back to `ash`
 * when `ashx` is absent, and it spawns a process, so the collision reaches users here.
 *
 * It cannot be left to fail naturally, because of the SHAPE of the failure. A shell that does
 * not understand `scan --source-dir ...` writes an error and exits, ASH writes no SARIF, and the
 * user is told the scan failed with an error about a missing report rather than about the wrong
 * program having answered. Worse, a shell that happens to exit 0 is the shape this plugin must
 * never show as a clean scan.
 *
 * The test is a string in ASH's own output and not an exit code, because an exit code cannot
 * distinguish ASH from any other program that answers `--version`. `ash --version` prints
 * `awslabs/automated-security-helper v<version>` and exits 0.
 *
 * `--version` and not `-v`: `-v` is `--verbose` in ASH, so a probe using it would start a
 * verbose scan instead of printing a version.
 *
 * Kept free of IntelliJ imports; [AshScanRunner] runs the process and hands the output here.
 */
object AshIdentityProbe {

    /** The marker every ASH entry point prints from `--version`. */
    const val ASH_MARKER = "awslabs/automated-security-helper"

    /** Seconds the probe may take. Bounds anything that ignores EOF on stdin. */
    const val TIMEOUT_SECONDS = 30

    /** Phrases a shell prints when it rejects an option it does not know. */
    private val SHELL_TELLS = listOf("illegal option", "unknown option", "bad option", "syntax error")

    sealed interface Verdict {
        /** @param versionLine the line carrying [ASH_MARKER], for the scan report. */
        data class IsAsh(val versionLine: String) : Verdict

        data class NotAsh(val message: String) : Verdict
    }

    fun classify(executable: String, timedOut: Boolean, output: String): Verdict {
        if (timedOut) {
            return Verdict.NotAsh(
                "'$executable --version' did not finish within ${TIMEOUT_SECONDS}s. It was " +
                    "stopped, and no scan was run.",
            )
        }
        val versionLine = output.lineSequence().firstOrNull { it.contains(ASH_MARKER) }
        if (versionLine != null) return Verdict.IsAsh(versionLine.trim())
        return Verdict.NotAsh(notAshAdvice(executable, output))
    }

    private fun notAshAdvice(executable: String, output: String): String = buildString {
        append("'$executable' is not ASH: its --version output does not contain '$ASH_MARKER'.")
        val lowered = output.lowercase()
        if (SHELL_TELLS.any { lowered.contains(it) }) {
            append(
                " The output looks like a shell rejecting an option, which is what happens when " +
                    "MSYS2's Almquist shell, also called ash, comes first on PATH.",
            )
        }
        append(
            " Set the executable in Settings | Tools | ASH to 'automated-security-helper', " +
                "which is ASH's unambiguous entry point, or to the full path of ASH.",
        )
        // lineSequence() of any string, even an empty one, has a first element.
        val first = output.trim().lineSequence().first().trim()
        if (first.isNotEmpty()) append(" It printed: $first")
    }
}
