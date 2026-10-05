// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Decides which ASH executable a scan runs.
 *
 * THIS PLUGIN BUNDLES NOTHING. It invokes the ASH CLI the user installed, and ships no
 * scanner, no scanner wrapper and no scanner assets. So "is ASH on PATH" is not an edge case:
 * it is the single most likely reason this plugin does nothing on a fresh install, and a
 * not-found must therefore be an error the user sees, not a quiet absence of findings.
 *
 * THE RESOLUTION ORDER, and each step is a decision rather than a default:
 *
 *  1. A path configured in Settings | Tools | ASH is used AS GIVEN. It is not searched for, not
 *     checked for existence here, and not replaced by either name below. Someone who typed a
 *     path chose it, and quietly running a different binary would make the setting a
 *     suggestion. If it does not start, the scan reports that it could not start it.
 *  2. Otherwise [PRIMARY_NAME] on PATH.
 *  3. Otherwise [FALLBACK_NAME] on PATH, with a notice the first time it happens in an IDE
 *     session, so a user still on the older entry point knows the plugin noticed and which
 *     binary it ran. Once rather than per scan, because a balloon on every scan for a
 *     configuration the user may have chosen on purpose trains them to dismiss balloons.
 *  4. Otherwise [Outcome.NotFound], carrying the directories searched, because "not found"
 *     and "PATH was empty" have different fixes and look identical without them.
 *
 * Both names are constants and nothing else in the plugin spells either one, so renaming the
 * entry point is a one-line change here.
 *
 * Kept free of IntelliJ imports so it is testable without booting a platform.
 */
object AshCliLocator {

    /** The entry point looked for first. */
    const val PRIMARY_NAME = "ashx"

    /** The entry point used when [PRIMARY_NAME] is not on PATH. */
    const val FALLBACK_NAME = "ash"

    sealed interface Outcome {
        /**
         * @param path what to execute: an absolute path from a PATH search, or the configured
         *   value verbatim.
         * @param source how [path] was chosen, so the notification can say so.
         */
        data class Found(val path: String, val source: Source) : Outcome

        /**
         * @param searched the PATH entries actually examined.
         */
        data class NotFound(val searched: List<String>, val reason: String) : Outcome
    }

    enum class Source {
        /** From Settings | Tools | ASH, used as given. */
        CONFIGURED,

        /** [PRIMARY_NAME] found on PATH. */
        PRIMARY,

        /** [FALLBACK_NAME] found on PATH because [PRIMARY_NAME] was not. */
        FALLBACK,
    }

    /**
     * @param configured the Settings value. Blank means "not configured", so a field the user
     *   cleared goes back to the PATH search instead of trying to execute an empty string.
     * @param pathValue the PATH to search; defaults to the process's own. Injectable so a test
     *   can assert every arm without depending on what is installed on the machine running it.
     * @param isExecutable how executability is decided. Injectable for the same reason.
     * @param windows whether to search the way Windows does; see [candidatePasses].
     * @param pathExt the PATHEXT value that orders the Windows launcher extensions.
     */
    fun resolve(
        configured: String?,
        pathValue: String? = System.getenv("PATH"),
        pathSeparator: String = File.pathSeparator,
        isExecutable: (File) -> Boolean = { it.isFile && it.canExecute() },
        windows: Boolean = System.getProperty("os.name").orEmpty().startsWith("Windows", ignoreCase = true),
        pathExt: String? = System.getenv("PATHEXT"),
    ): Outcome {
        val trimmed = configured?.trim().orEmpty()
        if (trimmed.isNotEmpty()) return Outcome.Found(trimmed, Source.CONFIGURED)

        if (pathValue.isNullOrBlank()) {
            return Outcome.NotFound(
                emptyList(),
                "PATH is empty or unset, so there was nowhere to look for " +
                    "'$PRIMARY_NAME' or '$FALLBACK_NAME'. Set the full path to ASH in " +
                    "Settings | Tools | ASH.",
            )
        }

        val entries = pathValue.split(pathSeparator).filter { it.isNotBlank() }
        for (fileNames in candidatePasses(windows, pathExt)) {
            search(fileNames(PRIMARY_NAME), entries, isExecutable)?.let { return Outcome.Found(it, Source.PRIMARY) }
            search(fileNames(FALLBACK_NAME), entries, isExecutable)?.let { return Outcome.Found(it, Source.FALLBACK) }
        }

        return Outcome.NotFound(
            entries,
            "Neither '$PRIMARY_NAME' nor '$FALLBACK_NAME' was found on PATH. This plugin runs " +
                "the ASH CLI you installed; it does not bundle one. Install ASH (for example " +
                "'pipx install automated-security-helper' or 'uv tool install " +
                "automated-security-helper'), or set the full path to it in Settings | Tools | " +
                "ASH. An IDE started from a desktop launcher does not always inherit the PATH " +
                "a terminal has, so a full path is the reliable fix.",
        )
    }

    /** What Windows uses when PATHEXT is unset or blank. */
    private const val DEFAULT_PATHEXT = ".COM;.EXE;.BAT;.CMD"

    /**
     * The file names to try for a command name, in passes; each pass covers both names across
     * all of PATH before the next pass starts.
     *
     * POSIX: one pass, the bare name first. The launcher forms after it are harmless there,
     * where no such file exists.
     *
     * WINDOWS: the bare name goes LAST, in a pass of its own. Windows does not run an
     * extensionless file, and `canExecute()` is true there for any file that exists, so an
     * extensionless `ash` shell script in a Git for Windows PATH entry would otherwise win over
     * `ash.exe` and then fail to start. The first pass tries the PATHEXT extensions in PATHEXT
     * order, which is the order Windows itself uses. The bare name is still tried after that, so
     * a PATH holding only that file gets "could not start <file>" rather than "not found".
     */
    private fun candidatePasses(windows: Boolean, pathExt: String?): List<(String) -> List<String>> {
        if (!windows) return listOf { name -> listOf(name, "$name.exe", "$name.cmd", "$name.bat") }
        val extensions = pathExt?.takeIf { it.isNotBlank() } ?: DEFAULT_PATHEXT
        val ordered = extensions.split(';').map { it.trim().lowercase() }.filter { it.isNotEmpty() }
        return listOf({ name -> ordered.map { name + it } }, { name -> listOf(name) })
    }

    /** The first executable in [entries] with one of [candidateNames], or null. */
    private fun search(candidateNames: List<String>, entries: List<String>, isExecutable: (File) -> Boolean): String? {
        for (entry in entries) {
            for (candidateName in candidateNames) {
                val candidate = File(entry, candidateName)
                if (isExecutable(candidate)) return candidate.absolutePath
            }
        }
        return null
    }

    /**
     * Whether the fallback notice is still to be shown this session.
     *
     * A compare-and-set rather than a check followed by a write, because two scans can resolve
     * concurrently in two projects, and both seeing "not yet shown" would show it twice.
     */
    class FallbackNotice {
        private val shown = AtomicBoolean(false)

        /** True exactly once per instance: for the first caller, and never after. */
        fun claim(): Boolean = shown.compareAndSet(false, true)

        fun message(path: String): String =
            "'$PRIMARY_NAME' was not found on PATH, so this scan ran '$FALLBACK_NAME' " +
                "($path). Install a version of ASH that provides '$PRIMARY_NAME', or set the " +
                "executable in Settings | Tools | ASH to choose one explicitly. This notice is " +
                "shown once per IDE session."
    }

    /** The one notice instance for the running IDE. */
    val fallbackNotice = FallbackNotice()
}
