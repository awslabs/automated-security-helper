// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains.snapshot

import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption

/**
 * Text snapshots for what the plugin shows a user.
 *
 * WHY THIS EXISTS. A test that asserts `body.contains("exit code 2")` passes for any rewording of
 * the rest of the message, so a change to what the user reads lands without anyone deciding it.
 * A snapshot holds the whole rendered text, and a change to it fails until someone rewrites the
 * snapshot on purpose and commits it with a `Snapshot-Update: <reason>` trailer, which
 * .github/scripts/check-editor-snapshot-trailers.py enforces.
 *
 * WHY IT IS WRITTEN HERE. JUnit 4 has no snapshot support, and the libraries that add it either
 * bring a second test framework (the JUnit 5 extensions) or a dependency tree larger than this
 * file. The rules are the ones core ASH's syrupy suite follows, so a contributor meets one policy:
 *
 *  - A missing or different snapshot fails. Nothing is written unless the update flag is set.
 *  - The update flag is the Gradle property `snapshot-update` (`./gradlew test -Psnapshot-update`),
 *    the same name as pytest's `--snapshot-update`. Gradle turns it into the system property
 *    [UPDATE_PROPERTY], and refuses it, as this class does, when CI or GITHUB_ACTIONS is "true".
 *  - Every snapshot a test asserts is recorded in the usage file, and assert-snapshots-used.py
 *    fails the build on a snapshot file no test asserted. That covers a deleted or renamed test
 *    class, which a per-class check cannot see.
 *  - Normalization happens here and nowhere else: see [normalize]. A test passes the values to
 *    mask; it does not edit its own output.
 *
 * Layout: `<SNAPSHOT_DIR>/<owner simple name>/<name>.txt`, where SNAPSHOT_DIR is
 * `src/test/snapshots/__snapshots__`. The `__snapshots__` component is what core ASH's golden-file
 * check matches, so that script can absorb these files without a new pattern.
 */
object Snapshots {

    const val DIR_PROPERTY = "ash.snapshot.dir"
    const val UPDATE_PROPERTY = "ash.snapshot.update"
    const val USAGE_PROPERTY = "ash.snapshot.usage"

    private val NAME = Regex("[a-z0-9][a-z0-9._-]*")

    /** The configuration a run reads from system properties; a parameter so it can be tested. */
    data class Config(val dir: Path, val update: Boolean, val usage: Path?, val env: Map<String, String>) {
        init {
            if (update) {
                val ci = listOf("CI", "GITHUB_ACTIONS").filter { env[it].equals("true", ignoreCase = true) }
                require(ci.isEmpty()) {
                    "snapshot update refused: ${ci.joinToString(" and ")} is true. Snapshots are " +
                        "updated on a developer's machine and committed with a Snapshot-Update trailer; " +
                        "CI only compares."
                }
            }
        }

        companion object {
            fun fromSystem(): Config {
                val dir = System.getProperty(DIR_PROPERTY)
                    ?: error("$DIR_PROPERTY is not set; the snapshot tests run through Gradle's test task")
                return Config(
                    Path.of(dir),
                    System.getProperty(UPDATE_PROPERTY) == "true",
                    System.getProperty(USAGE_PROPERTY)?.let { Path.of(it) },
                    System.getenv(),
                )
            }
        }
    }

    /** What one assertion did, so the helper's own tests can check it without reading files. */
    enum class Result { MATCHED, WRITTEN }

    private val defaultConfig: Config by lazy { Config.fromSystem() }

    /** Snapshot ids asserted in this JVM, so the same id asserted twice fails instead of overwriting. */
    private val seen = mutableSetOf<String>()

    /**
     * Compares [actual], after [normalize] with [masks], against the snapshot `<owner>/<name>.txt`.
     *
     * @param masks literal value to the token that replaces it, such as a temp directory to
     *   `<SOURCE>`. Longest values are replaced first, so a path inside another is masked whole.
     */
    fun assertMatches(owner: Class<*>, name: String, actual: String, masks: Map<String, String> = emptyMap()): Result =
        assertMatches(defaultConfig, owner, name, actual, masks)

    @Synchronized
    fun assertMatches(
        config: Config,
        owner: Class<*>,
        name: String,
        actual: String,
        masks: Map<String, String> = emptyMap(),
    ): Result {
        require(NAME.matches(name)) { "snapshot name '$name' must match ${NAME.pattern}" }
        val id = "${owner.simpleName}/$name.txt"
        require(seen.add(config.dir.resolve(id).toString())) {
            "snapshot $id was asserted twice in one run; give each assertion its own name"
        }
        val file = config.dir.resolve(id)
        val text = normalize(actual, masks)
        recordUsage(config, id)

        if (!Files.exists(file)) {
            if (!config.update) {
                throw AssertionError(
                    "snapshot $id does not exist. Create it with `./gradlew test -Psnapshot-update`, " +
                        "read it, and commit it with a 'Snapshot-Update: <reason>' trailer.\n" +
                        "--- actual ---\n$text",
                )
            }
            Files.createDirectories(file.parent)
            Files.writeString(file, text)
            return Result.WRITTEN
        }

        val expected = Files.readString(file)
        if (expected == text) return Result.MATCHED
        if (config.update) {
            Files.writeString(file, text)
            return Result.WRITTEN
        }
        throw org.junit.ComparisonFailure(
            "snapshot $id differs from what the plugin now produces. If the change is intended, " +
                "run `./gradlew test -Psnapshot-update`, review `git diff`, and commit with a " +
                "'Snapshot-Update: <reason>' trailer.\n${lineDiff(expected, text)}",
            expected,
            text,
        )
    }

    private fun recordUsage(config: Config, id: String) {
        val usage = config.usage ?: return
        Files.createDirectories(usage.parent)
        Files.writeString(usage, "$id\n", StandardOpenOption.CREATE, StandardOpenOption.APPEND)
    }

    /**
     * The one normalization: CRLF and CR to LF, the [masks] applied longest first, trailing
     * whitespace stripped from each line, and exactly one final newline.
     *
     * Deliberately small. Every rule here hides a difference, and a hidden difference is one the
     * snapshot cannot catch, so anything a test can pin (a clock, a version, a path) is pinned or
     * masked by the caller naming it, rather than matched by a pattern here.
     */
    fun normalize(text: String, masks: Map<String, String> = emptyMap()): String {
        var out = text.replace("\r\n", "\n").replace('\r', '\n')
        for ((value, token) in masks.entries.sortedByDescending { it.key.length }) {
            require(value.isNotEmpty()) { "an empty mask would replace between every character" }
            out = out.replace(value, token)
        }
        return out.lines().joinToString("\n") { it.trimEnd() }.trimEnd('\n') + "\n"
    }

    /**
     * A line diff, `-` for the snapshot and `+` for the new output, from a longest common
     * subsequence. The snapshots are tens of lines, so the quadratic table costs nothing.
     */
    fun lineDiff(expected: String, actual: String): String {
        val a = expected.trimEnd('\n').split("\n")
        val b = actual.trimEnd('\n').split("\n")
        val lcs = Array(a.size + 1) { IntArray(b.size + 1) }
        for (i in a.indices.reversed()) {
            for (j in b.indices.reversed()) {
                lcs[i][j] = if (a[i] == b[j]) lcs[i + 1][j + 1] + 1 else maxOf(lcs[i + 1][j], lcs[i][j + 1])
            }
        }
        val out = StringBuilder()
        var i = 0
        var j = 0
        while (i < a.size || j < b.size) {
            when {
                i < a.size && j < b.size && a[i] == b[j] -> { out.append("  ").append(a[i]).append('\n'); i++; j++ }
                // Removals before additions at the same point, the order a unified diff uses.
                i < a.size && (j == b.size || lcs[i + 1][j] >= lcs[i][j + 1]) -> { out.append("- ").append(a[i]).append('\n'); i++ }
                else -> { out.append("+ ").append(b[j]).append('\n'); j++ }
            }
        }
        return out.toString()
    }
}
