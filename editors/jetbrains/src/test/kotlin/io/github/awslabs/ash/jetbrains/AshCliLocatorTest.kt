// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The resolution order: configured as given, then `ashx`, then `ash` with a notice, then a
 * not-found that says where it looked.
 *
 * Executability is injected, so every arm is asserted without depending on what the machine
 * running the test has installed. AshScanIntegrationTest repeats the fallback against real
 * files on a real PATH.
 */
class AshCliLocatorTest {

    private fun on(vararg present: String): (File) -> Boolean = { it.path in present.toSet() }

    @Test
    fun primaryIsPreferredWhenBothAreOnPath() {
        val outcome = AshCliLocator.resolve(
            configured = null,
            pathValue = "/a:/b",
            pathSeparator = ":",
            isExecutable = on("/a/ash", "/b/ashx"),
        )
        // ashx wins even though ash comes first on PATH: the order is by name, then by PATH.
        assertEquals(AshCliLocator.Outcome.Found(File("/b/ashx").absolutePath, AshCliLocator.Source.PRIMARY), outcome)
    }

    @Test
    fun fallbackIsUsedOnlyWhenPrimaryIsAbsent() {
        val outcome = AshCliLocator.resolve(
            configured = "",
            pathValue = "/a:/b",
            pathSeparator = ":",
            isExecutable = on("/b/ash"),
        )
        assertEquals(AshCliLocator.Outcome.Found(File("/b/ash").absolutePath, AshCliLocator.Source.FALLBACK), outcome)
    }

    @Test
    fun configuredPathIsUsedAsGivenWithoutSearching() {
        // Not looked up, not checked, not replaced -- even when ashx is on PATH, and even when
        // the configured value names nothing that exists.
        val searched = mutableListOf<File>()
        val outcome = AshCliLocator.resolve(
            configured = "  /opt/custom/automated-security-helper  ",
            pathValue = "/a",
            pathSeparator = ":",
            isExecutable = { searched += it; true },
        )
        assertEquals(
            AshCliLocator.Outcome.Found("/opt/custom/automated-security-helper", AshCliLocator.Source.CONFIGURED),
            outcome,
        )
        assertEquals("a configured value must not trigger a PATH search", emptyList<File>(), searched)
    }

    @Test
    fun blankConfiguredValueMeansSearchPath() {
        val outcome = AshCliLocator.resolve(configured = "   ", pathValue = "/a", pathSeparator = ":", isExecutable = on("/a/ashx"))
        assertEquals(AshCliLocator.Source.PRIMARY, (outcome as AshCliLocator.Outcome.Found).source)
    }

    @Test
    fun notFoundNamesBothExecutablesAndTheDirectoriesSearched() {
        val outcome = AshCliLocator.resolve(
            configured = null,
            pathValue = "/usr/bin::/opt/bin",
            pathSeparator = ":",
            isExecutable = { false },
        )
        val notFound = outcome as AshCliLocator.Outcome.NotFound
        // The empty entry between the two separators is not a directory anyone searched.
        assertEquals(listOf("/usr/bin", "/opt/bin"), notFound.searched)
        assertTrue(notFound.reason, notFound.reason.contains("'ashx'") && notFound.reason.contains("'ash'"))
        assertTrue("must say the plugin bundles nothing", notFound.reason.contains("does not bundle"))
    }

    @Test
    fun emptyOrUnsetPathIsItsOwnDiagnosis() {
        for (pathValue in listOf(null, "", "   ")) {
            val notFound = AshCliLocator.resolve(configured = null, pathValue = pathValue, isExecutable = { true })
                as AshCliLocator.Outcome.NotFound
            assertEquals(emptyList<String>(), notFound.searched)
            assertTrue(notFound.reason, notFound.reason.contains("PATH is empty or unset"))
        }
    }

    @Test
    fun windowsLauncherFormsAreFound() {
        for (name in listOf("ashx.exe", "ashx.cmd", "ashx.bat")) {
            val outcome = AshCliLocator.resolve(
                configured = null,
                pathValue = "/w",
                pathSeparator = ":",
                isExecutable = on("/w/$name"),
            )
            assertEquals(name, File((outcome as AshCliLocator.Outcome.Found).path).name)
        }
    }

    @Test
    fun theDefaultSearchUsesTheRealFilesystem() {
        // The default isExecutable is exercised once, against a directory that cannot hold
        // either name, so the not-found arm is reached through real File checks.
        val empty = kotlin.io.path.createTempDirectory("ash-locator-").toFile()
        try {
            val outcome = AshCliLocator.resolve(configured = null, pathValue = empty.path)
            assertTrue(outcome is AshCliLocator.Outcome.NotFound)
        } finally {
            empty.deleteRecursively()
        }
    }

    @Test
    fun fallbackNoticeIsClaimedExactlyOnce() {
        val notice = AshCliLocator.FallbackNotice()
        assertTrue("the first claim shows the notice", notice.claim())
        assertFalse("the second does not", notice.claim())
        assertFalse("nor any after", notice.claim())
        val message = notice.message("/b/ash")
        assertTrue(message, message.contains("'ashx' was not found") && message.contains("/b/ash"))
        assertTrue(message, message.contains("once per IDE session"))
    }
}
