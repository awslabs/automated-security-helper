// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains.snapshot

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.ComparisonFailure
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.awt.image.BufferedImage
import java.nio.file.Files
import java.nio.file.Path
import javax.imageio.ImageIO

/**
 * The snapshot helper's own rules, each against a scratch directory so no committed snapshot is
 * read or written. Every rule a snapshot suite relies on is a case here, because a helper that
 * quietly writes on a mismatch makes every snapshot test in the suite pass whatever it renders.
 */
class SnapshotsTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private fun config(update: Boolean = false, env: Map<String, String> = emptyMap()): Snapshots.Config {
        val root = tmp.root.toPath()
        return Snapshots.Config(root.resolve("__snapshots__"), update, root.resolve("usage.txt"), env, root.resolve("actual"))
    }

    private fun image(width: Int = 4, height: Int = 3, paint: (BufferedImage) -> Unit = {}): BufferedImage {
        val img = BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB)
        for (y in 0 until height) for (x in 0 until width) img.setRGB(x, y, 0xFF336699.toInt())
        paint(img)
        return img
    }

    private fun png(config: Snapshots.Config, name: String): Path = config.dir.resolve("SnapshotsTest").resolve("$name.png")

    private fun file(config: Snapshots.Config, name: String): Path =
        config.dir.resolve("SnapshotsTest").resolve("$name.txt")

    @Test
    fun aMissingSnapshotFailsAndWritesNothing() {
        val config = config()
        val error = assertThrows(AssertionError::class.java) {
            Snapshots.assertMatches(config, javaClass, "missing", "hello")
        }
        assertTrue(error.message, error.message!!.contains("does not exist"))
        assertTrue(error.message, error.message!!.contains("-Psnapshot-update"))
        assertFalse("nothing may be written without the update flag", Files.exists(file(config, "missing")))
    }

    @Test
    fun aMissingSnapshotIsWrittenOnlyWithTheUpdateFlag() {
        val config = config(update = true)
        assertEquals(Snapshots.Result.WRITTEN, Snapshots.assertMatches(config, javaClass, "created", "hello"))
        assertEquals("hello\n", Files.readString(file(config, "created")))
    }

    @Test
    fun aMatchingSnapshotPasses() {
        val config = config()
        Files.createDirectories(file(config, "same").parent)
        Files.writeString(file(config, "same"), "line one\nline two\n")
        assertEquals(Snapshots.Result.MATCHED, Snapshots.assertMatches(config, javaClass, "same", "line one\r\nline two"))
    }

    @Test
    fun aChangedSnapshotFailsWithALineDiffAndIsLeftAlone() {
        val config = config()
        Files.createDirectories(file(config, "changed").parent)
        Files.writeString(file(config, "changed"), "title\nold body\nfooter\n")
        val error = assertThrows(ComparisonFailure::class.java) {
            Snapshots.assertMatches(config, javaClass, "changed", "title\nnew body\nfooter")
        }
        assertTrue(error.message, error.message!!.contains("- old body\n+ new body\n"))
        assertEquals("title\nold body\nfooter\n", Files.readString(file(config, "changed")))
    }

    @Test
    fun aChangedSnapshotIsRewrittenOnlyWithTheUpdateFlag() {
        val config = config(update = true)
        Files.createDirectories(file(config, "rewritten").parent)
        Files.writeString(file(config, "rewritten"), "old\n")
        assertEquals(Snapshots.Result.WRITTEN, Snapshots.assertMatches(config, javaClass, "rewritten", "new"))
        assertEquals("new\n", Files.readString(file(config, "rewritten")))
    }

    @Test
    fun theUpdateFlagIsRefusedUnderCi() {
        for (env in listOf(mapOf("CI" to "true"), mapOf("GITHUB_ACTIONS" to "true"), mapOf("CI" to "TRUE"))) {
            val error = assertThrows(IllegalArgumentException::class.java) { config(update = true, env = env) }
            assertTrue(error.message, error.message!!.contains("snapshot update refused"))
        }
        // Comparing under CI is the normal case and must not be refused.
        config(update = false, env = mapOf("CI" to "true", "GITHUB_ACTIONS" to "true"))
        // A value other than "true" is not CI, the same rule core ASH's conftest applies.
        config(update = true, env = mapOf("CI" to "false"))
    }

    @Test
    fun theSameSnapshotAssertedTwiceInOneRunFails() {
        val config = config(update = true)
        Snapshots.assertMatches(config, javaClass, "twice", "a")
        val error = assertThrows(IllegalArgumentException::class.java) {
            Snapshots.assertMatches(config, javaClass, "twice", "a")
        }
        assertTrue(error.message, error.message!!.contains("asserted twice"))
    }

    @Test
    fun aNameThatIsNotAPlainFileNameIsRefused() {
        for (bad in listOf("../escape", "Upper", "with space", "", "a/b")) {
            assertThrows(bad, IllegalArgumentException::class.java) {
                Snapshots.assertMatches(config(update = true), javaClass, bad, "x")
            }
        }
    }

    @Test
    fun everyAssertionIsRecordedForTheOrphanCheck() {
        val config = config(update = true)
        Snapshots.assertMatches(config, javaClass, "used-one", "a")
        Snapshots.assertMatches(config, javaClass, "used-two", "b")
        assertEquals(
            listOf("SnapshotsTest/used-one.txt", "SnapshotsTest/used-two.txt"),
            Files.readAllLines(config.usage!!),
        )
    }

    @Test
    fun aFailedAssertionIsStillRecordedAsUsed() {
        // Otherwise a failing test would also report its snapshot as an orphan, and the second
        // message would point the reader at deleting the file the test is about.
        val config = config()
        assertThrows(AssertionError::class.java) { Snapshots.assertMatches(config, javaClass, "absent", "a") }
        assertEquals(listOf("SnapshotsTest/absent.txt"), Files.readAllLines(config.usage!!))
    }

    @Test
    fun normalizationMasksLongestValueFirstAndCleansLineEnds() {
        val masks = mapOf("/tmp/a" to "<A>", "/tmp/a/b" to "<B>")
        assertEquals(
            "<B>/x and <A>/y\nnext\n",
            Snapshots.normalize("/tmp/a/b/x and /tmp/a/y   \r\nnext\n\n\n", masks),
        )
        assertThrows(IllegalArgumentException::class.java) { Snapshots.normalize("x", mapOf("" to "<E>")) }
    }

    @Test
    fun lineDiffMarksRemovedAndAddedLines() {
        assertEquals("  a\n- b\n+ c\n  d\n+ e\n", Snapshots.lineDiff("a\nb\nd\n", "a\nc\nd\ne\n"))
    }

    private fun writeBaseline(config: Snapshots.Config, name: String, img: BufferedImage) {
        Files.createDirectories(png(config, name).parent)
        ImageIO.write(img, "png", png(config, name).toFile())
    }

    @Test
    fun aMissingImageFailsAndWritesOnlyTheReviewCopy() {
        val config = config()
        val error = assertThrows(AssertionError::class.java) {
            Snapshots.assertImageMatches(config, javaClass, "img-missing", image())
        }
        assertTrue(error.message, error.message!!.contains("does not exist"))
        assertFalse(Files.exists(png(config, "img-missing")))
        assertTrue("the rendered image is saved for review", Files.exists(config.actualDir!!.resolve("SnapshotsTest/img-missing.actual.png")))
    }

    @Test
    fun aMissingImageIsWrittenWithTheUpdateFlag() {
        val config = config(update = true)
        assertEquals(Snapshots.Result.WRITTEN, Snapshots.assertImageMatches(config, javaClass, "img-created", image()))
        assertEquals(0xFF336699.toInt(), ImageIO.read(png(config, "img-created").toFile()).getRGB(3, 2))
    }

    @Test
    fun anIdenticalImageMatchesWhateverItsPixelFormat() {
        val config = config()
        writeBaseline(config, "img-same", image())
        val rgb = BufferedImage(4, 3, BufferedImage.TYPE_INT_RGB)
        for (y in 0 until 3) for (x in 0 until 4) rgb.setRGB(x, y, 0x336699)
        assertEquals(Snapshots.Result.MATCHED, Snapshots.assertImageMatches(config, javaClass, "img-same", rgb))
    }

    @Test
    fun oneChangedPixelFailsWithItsLocationAndADiffImage() {
        val config = config()
        writeBaseline(config, "img-one-pixel", image())
        val error = assertThrows(AssertionError::class.java) {
            Snapshots.assertImageMatches(config, javaClass, "img-one-pixel", image { it.setRGB(2, 1, 0xFF336698.toInt()) })
        }
        assertTrue(error.message, error.message!!.contains("1 of 12 pixel(s) differ, within x=2..2 y=1..1"))
        val diff = ImageIO.read(config.actualDir!!.resolve("SnapshotsTest/img-one-pixel.diff.png").toFile())
        assertEquals(0xFFFF0000.toInt(), diff.getRGB(2, 1))
        assertEquals("the snapshot is left alone", 0xFF336699.toInt(), ImageIO.read(png(config, "img-one-pixel").toFile()).getRGB(2, 1))
    }

    @Test
    fun aChangedImageIsRewrittenOnlyWithTheUpdateFlag() {
        val config = config(update = true)
        writeBaseline(config, "img-rewritten", image())
        assertEquals(Snapshots.Result.WRITTEN, Snapshots.assertImageMatches(config, javaClass, "img-rewritten", image(width = 5)))
        assertEquals(5, ImageIO.read(png(config, "img-rewritten").toFile()).width)
    }

    @Test
    fun aDifferentSizeIsADifference() {
        assertEquals("size 5x3, snapshot is 4x3", Snapshots.compare(image(), image(width = 5)))
        assertEquals(null, Snapshots.compare(image(), image()))
    }
}
