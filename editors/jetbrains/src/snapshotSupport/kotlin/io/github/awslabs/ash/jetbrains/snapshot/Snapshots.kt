// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains.snapshot

import java.awt.image.BufferedImage
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import javax.imageio.ImageIO

/**
 * Text and image snapshots for what the plugin shows a user.
 *
 * WHY THIS EXISTS. A test that asserts `body.contains("exit code 2")` passes for any rewording of
 * the rest of the message, so a change to what the user reads lands without anyone deciding it.
 * A snapshot holds the whole rendered text, and a change to it fails until someone rewrites the
 * snapshot on purpose and commits it with a `Snapshot-Update: <reason>` trailer, which
 * .github/scripts/check-snapshot-trailers.py enforces.
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
 * Layout: `<SNAPSHOT_DIR>/<owner simple name>/<name>.txt` for text and `.png` for images, where
 * SNAPSHOT_DIR is `src/test/snapshots/__snapshots__` for the structural suite and
 * `src/uiTest/snapshots/__snapshots__` for the visual one. The `__snapshots__` component is what core
 * ASH's golden-file check matches, so that script can absorb these files without a new pattern.
 *
 * This file is compiled into both suites (build.gradle.kts adds src/snapshotSupport to each), so
 * the text and the pixel comparison share one set of rules.
 */
object Snapshots {

    const val DIR_PROPERTY = "ash.snapshot.dir"
    const val UPDATE_PROPERTY = "ash.snapshot.update"
    const val USAGE_PROPERTY = "ash.snapshot.usage"
    const val ACTUAL_PROPERTY = "ash.snapshot.actual"

    private val NAME = Regex("[a-z0-9][a-z0-9._-]*")

    /** The configuration a run reads from system properties; a parameter so it can be tested. */
    data class Config(
        val dir: Path,
        val update: Boolean,
        val usage: Path?,
        val env: Map<String, String>,
        /** Where a failed image comparison writes the rendered image and a diff, for a human. */
        val actualDir: Path? = null,
    ) {
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
                    System.getProperty(ACTUAL_PROPERTY)?.let { Path.of(it) },
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
        val id = register(config, owner, name, "txt")
        val file = config.dir.resolve(id)
        val text = normalize(actual, masks)

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

    /**
     * Validates the name, refuses a second assertion of the same id in this JVM, and records the id
     * as used before anything is compared, so a failing assertion is not also reported as an orphan.
     */
    private fun register(config: Config, owner: Class<*>, name: String, extension: String): String {
        require(NAME.matches(name)) { "snapshot name '$name' must match ${NAME.pattern}" }
        val id = "${owner.simpleName}/$name.$extension"
        require(seen.add(config.dir.resolve(id).toString())) {
            "snapshot $id was asserted twice in one run; give each assertion its own name"
        }
        config.usage?.let { usage ->
            Files.createDirectories(usage.parent)
            Files.writeString(usage, "$id\n", StandardOpenOption.CREATE, StandardOpenOption.APPEND)
        }
        return id
    }

    /**
     * Compares [actual] with the image snapshot `<owner>/<name>.png`, pixel for pixel.
     *
     * The comparison is exact: every pixel's ARGB value must be equal, and the sizes must be. There
     * is no tolerance parameter, on purpose. A tolerance is a statement about how much rendering
     * may vary between runs, and the only defensible value is one measured; the visual suite
     * renders identical pixels across repeated runs in its pinned environment, so the measured
     * variance is zero and so is the threshold. The decoded pixels are compared, not the PNG
     * bytes, so an encoder change cannot fail a run whose image is the same.
     *
     * On a mismatch the rendered image and a diff (changed pixels in red over a faded copy of the
     * snapshot) are written under [Config.actualDir] for review.
     */
    fun assertImageMatches(owner: Class<*>, name: String, actual: BufferedImage): Result =
        assertImageMatches(defaultConfig, owner, name, actual)

    @Synchronized
    fun assertImageMatches(config: Config, owner: Class<*>, name: String, actual: BufferedImage): Result {
        val id = register(config, owner, name, "png")
        val file = config.dir.resolve(id)
        val rendered = argb(actual)

        if (!Files.exists(file)) {
            if (!config.update) {
                val saved = saveActual(config, id, rendered, null)
                throw AssertionError(
                    "image snapshot $id does not exist. Create it with `-Psnapshot-update` in the " +
                        "visual suite's container, look at it, and commit it with a " +
                        "'Snapshot-Update: <reason>' trailer.$saved",
                )
            }
            writePng(file, rendered)
            return Result.WRITTEN
        }

        val expected = argb(ImageIO.read(file.toFile()) ?: error("$file is not a readable PNG"))
        val difference = compare(expected, rendered)
        if (difference == null) return Result.MATCHED
        if (config.update) {
            writePng(file, rendered)
            return Result.WRITTEN
        }
        val saved = saveActual(config, id, rendered, expected)
        throw AssertionError(
            "image snapshot $id differs: $difference. If the change is intended, rerun with " +
                "`-Psnapshot-update`, look at the new image, and commit it with a " +
                "'Snapshot-Update: <reason>' trailer.$saved",
        )
    }

    /** A copy in TYPE_INT_ARGB, so two images are compared as the same pixel format. */
    fun argb(image: BufferedImage): BufferedImage {
        if (image.type == BufferedImage.TYPE_INT_ARGB) return image
        val copy = BufferedImage(image.width, image.height, BufferedImage.TYPE_INT_ARGB)
        val g = copy.createGraphics()
        try {
            g.drawImage(image, 0, 0, null)
        } finally {
            g.dispose()
        }
        return copy
    }

    /** Null when the images are identical, otherwise what differs, in words. */
    fun compare(expected: BufferedImage, actual: BufferedImage): String? {
        if (expected.width != actual.width || expected.height != actual.height) {
            return "size ${actual.width}x${actual.height}, snapshot is ${expected.width}x${expected.height}"
        }
        var count = 0
        var minX = Int.MAX_VALUE
        var minY = Int.MAX_VALUE
        var maxX = -1
        var maxY = -1
        for (y in 0 until expected.height) {
            for (x in 0 until expected.width) {
                if (expected.getRGB(x, y) != actual.getRGB(x, y)) {
                    count++
                    minX = minOf(minX, x); minY = minOf(minY, y); maxX = maxOf(maxX, x); maxY = maxOf(maxY, y)
                }
            }
        }
        if (count == 0) return null
        return "$count of ${expected.width * expected.height} pixel(s) differ, within " +
            "x=$minX..$maxX y=$minY..$maxY"
    }

    private fun writePng(file: Path, image: BufferedImage) {
        Files.createDirectories(file.parent)
        check(ImageIO.write(image, "png", file.toFile())) { "no PNG writer available" }
    }

    private fun saveActual(config: Config, id: String, rendered: BufferedImage, expected: BufferedImage?): String {
        val dir = config.actualDir ?: return ""
        val base = dir.resolve(id.removeSuffix(".png"))
        writePng(Path.of("$base.actual.png"), rendered)
        if (expected != null && expected.width == rendered.width && expected.height == rendered.height) {
            val diff = BufferedImage(rendered.width, rendered.height, BufferedImage.TYPE_INT_ARGB)
            for (y in 0 until rendered.height) {
                for (x in 0 until rendered.width) {
                    val e = expected.getRGB(x, y)
                    diff.setRGB(x, y, if (e != rendered.getRGB(x, y)) 0xFFFF0000.toInt() else (e and 0x00FFFFFF) or 0x40000000)
                }
            }
            writePng(Path.of("$base.diff.png"), diff)
            return " Rendered: $base.actual.png, diff: $base.diff.png"
        }
        return " Rendered: $base.actual.png"
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
