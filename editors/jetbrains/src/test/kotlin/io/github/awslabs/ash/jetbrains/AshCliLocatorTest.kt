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

    /**
     * A bare `pip install automated-security-helper`, in any of its spellings. That name on PyPI
     * belongs to an unrelated third-party project, not to ASH, so a hint naming it installs a
     * stranger's package on the user's machine. ASH is installed from its git repository.
     */
    private val barePypiInstall = Regex(
        """(pipx|pip3?|uv\s+tool|uv\s+pip)\s+install\s+(-\S+\s+)*['"]?automated-security-helper(\[[^\]]*])?(['"\s),.]|$)""",
    )

    @Test
    fun theBarePypiPredicateCatchesEverySpellingAndSparesTheGitInstall() {
        // The planted negatives: each must be flagged, or the assertion below is vacuous.
        for (planted in listOf(
            "'pipx install automated-security-helper'",
            "uv tool install automated-security-helper",
            "pip install --upgrade \"automated-security-helper[symbols]\"",
            "uv pip install automated-security-helper, then",
        )) {
            assertTrue("not flagged: $planted", barePypiInstall.containsMatchIn(planted))
        }
        assertFalse(barePypiInstall.containsMatchIn("pipx install git+https://github.com/awslabs/automated-security-helper.git"))
        assertFalse(barePypiInstall.containsMatchIn("set this to `automated-security-helper`, which ASH installs"))
    }

    @Test
    fun theNotFoundHintInstallsAshFromItsRepositoryNeverFromPypi() {
        val notFound = AshCliLocator.resolve(configured = null, pathValue = "/usr/bin", isExecutable = { false })
            as AshCliLocator.Outcome.NotFound
        assertFalse("names a bare PyPI install: ${notFound.reason}", barePypiInstall.containsMatchIn(notFound.reason))
        assertTrue(
            notFound.reason,
            notFound.reason.contains("pipx install git+https://github.com/awslabs/automated-security-helper.git"),
        )
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

    private fun onWindows(pathValue: String, pathExt: String?, vararg present: String) = AshCliLocator.resolve(
        configured = null,
        pathValue = pathValue,
        pathSeparator = ";",
        isExecutable = on(*present),
        windows = true,
        pathExt = pathExt,
    ) as AshCliLocator.Outcome.Found

    @Test
    fun onWindowsALauncherFormBeatsAnExtensionlessFileEarlierOnPath() {
        // Git for Windows puts an extensionless `ash` shell script on PATH. Windows cannot run it,
        // and canExecute() is true there for any existing file, so it must not shadow ash.exe.
        val found = onWindows("/git/usr/bin;/py/Scripts", ".COM;.EXE;.BAT;.CMD", "/git/usr/bin/ash", "/py/Scripts/ash.exe")
        assertEquals(AshCliLocator.Outcome.Found(File("/py/Scripts/ash.exe").absolutePath, AshCliLocator.Source.FALLBACK), found)

        // And an extensionless primary does not beat a runnable fallback.
        val fallback = onWindows("/a;/b", null, "/a/ashx", "/b/ash.exe")
        assertEquals(File("/b/ash.exe").absolutePath, fallback.path)
    }

    @Test
    fun onWindowsTheExtensionsAreTriedInPathextOrder() {
        assertEquals("ashx.exe", File(onWindows("/w", ".COM;.EXE;.BAT;.CMD", "/w/ashx.cmd", "/w/ashx.exe").path).name)
        assertEquals("ashx.cmd", File(onWindows("/w", " .CMD ; ;.EXE", "/w/ashx.cmd", "/w/ashx.exe").path).name)
        // Unset or blank PATHEXT falls back to Windows' own default, in which .BAT precedes .CMD.
        for (pathExt in listOf(null, "  ")) {
            assertEquals("ashx.bat", File(onWindows("/w", pathExt, "/w/ashx.cmd", "/w/ashx.bat").path).name)
        }
    }

    @Test
    fun onWindowsAnExtensionlessFileIsTheLastResort() {
        // Tried after every launcher form, so a PATH holding only that file reports that it could
        // not start it rather than that nothing was found.
        assertEquals(File("/w/ashx").absolutePath, onWindows("/w", null, "/w/ashx").path)
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
