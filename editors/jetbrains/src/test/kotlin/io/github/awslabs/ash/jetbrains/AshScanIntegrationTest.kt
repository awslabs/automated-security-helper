// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import com.intellij.codeInsight.daemon.impl.HighlightInfo
import com.intellij.lang.annotation.HighlightSeverity
import com.intellij.notification.Notification
import com.intellij.notification.NotificationType
import com.intellij.notification.Notifications
import com.intellij.openapi.actionSystem.CommonDataKeys
import com.intellij.openapi.actionSystem.impl.SimpleDataContext
import com.intellij.testFramework.PlatformTestUtil
import com.intellij.testFramework.TestActionEvent
import com.intellij.testFramework.fixtures.BasePlatformTestCase
import com.intellij.testFramework.fixtures.TempDirTestFixture
import com.intellij.testFramework.fixtures.impl.TempDirTestFixtureImpl
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission

/**
 * A scan from the action's entry point to the highlights in the editor, headless, against a
 * project on disk.
 *
 * WHAT IS REAL AND WHAT IS NOT. The IDE is real: a booted headless platform, a project whose
 * files are on disk, the registered inspection, the real highlighting pass, the real process
 * launch, and the notifications delivered on the project's message bus. The ASH CLI is a shell
 * stub, and what it writes is NOT hand-written: it replays files a real ASH run produced over
 * this test's own fixture (see src/test/resources/real-cli/README.txt). So the parser, the
 * runner and the inspection are exercised against ASH's actual output for exit 2 and for the
 * exit-1 incomplete case, and the only thing standing in for ASH is the process that copies it.
 *
 * Running the real CLI here was the alternative. It needs ASH and a scanner toolchain inside
 * the build container, which would make this test's verdict depend on what that image ships --
 * the reason the replay was captured instead.
 *
 * Every positive assertion has a negative partner in this class: a clean scan must give zero
 * highlights, a failed scan must clear them, and a missing CLI must give none, so a plugin that
 * highlighted unconditionally could not pass.
 */
class AshScanIntegrationTest : BasePlatformTestCase() {

    private lateinit var bin: Path
    private val notifications = mutableListOf<Notification>()

    /** Real files on disk, so the scan's source directory and the editor's file are the same file. */
    override fun createTempDirTestFixture(): TempDirTestFixture = TempDirTestFixtureImpl()

    override fun setUp() {
        super.setUp()
        myFixture.enableInspections(AshFindingInspection())
        bin = Files.createTempDirectory("ash-integration-bin-")
        project.messageBus.connect(testRootDisposable).subscribe(
            Notifications.TOPIC,
            object : Notifications {
                override fun notify(notification: Notification) {
                    notifications += notification
                }
            },
        )
    }

    override fun tearDown() {
        try {
            AshScanService.getInstance(project).clear()
            AshSettings.getInstance().executablePath = ""
            bin.toFile().deleteRecursively()
        } finally {
            super.tearDown()
        }
    }

    private val sourceDir: Path get() = Path.of(myFixture.tempDirPath)

    private fun resource(name: String): Path =
        Path.of(requireNotNull(javaClass.getResource(name)) { "fixture $name is not on the test classpath" }.toURI())

    /**
     * A stub CLI named [name] that answers `--version` like ASH and, for `scan`, copies a captured
     * real run into `--output-dir` and exits [exitCode].
     *
     * @param capture a directory under real-cli/, or null to write no report at all.
     */
    private fun stub(name: String, capture: String?, exitCode: Int, sarifOverride: Path? = null, statusOverride: String? = null): Path {
        val script = bin.resolve(name)
        val sarif = sarifOverride ?: capture?.let { resource("/real-cli/$it/ash.sarif") }
        val status = capture?.let { resource("/real-cli/$it/ash_aggregated_results.json") }
        val console = capture?.let { javaClass.getResource("/real-cli/$it/console-tail.txt") }?.let { Path.of(it.toURI()) }
        val body = buildString {
            appendLine("#!/bin/sh")
            appendLine("if [ \"\$1\" = --version ]; then echo 'awslabs/automated-security-helper v3.7.0'; exit 0; fi")
            appendLine("out=''")
            appendLine("while [ \$# -gt 0 ]; do case \"\$1\" in --output-dir) out=\"\$2\"; shift 2;; *) shift;; esac; done")
            appendLine("echo \"$name scan\" > \"$bin/$name.ran\"")
            if (sarif != null) {
                appendLine("mkdir -p \"\$out/reports\"")
                appendLine("cp '$sarif' \"\$out/reports/ash.sarif\"")
            }
            if (statusOverride != null) {
                val file = bin.resolve("$name-status.json")
                Files.writeString(file, statusOverride)
                appendLine("cp '$file' \"\$out/ash_aggregated_results.json\"")
            } else if (status != null) {
                appendLine("cp '$status' \"\$out/ash_aggregated_results.json\"")
            }
            if (console != null) appendLine("cat '$console' >&2")
            appendLine("exit $exitCode")
        }
        Files.writeString(script, body)
        Files.setPosixFilePermissions(
            script,
            setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE),
        )
        return script
    }

    private fun ran(name: String): Boolean = Files.exists(bin.resolve("$name.ran"))

    /** Opens the planted-secret fixture as a real file in the scanned directory. */
    private fun openLeak() {
        val text = Files.readString(resource("/fixtures/leak.py"))
        myFixture.configureFromExistingVirtualFile(myFixture.tempDirFixture.createFile("leak.py", text))
    }

    private fun ashHighlights(): List<HighlightInfo> =
        myFixture.doHighlighting().filter { it.description?.startsWith("ASH") == true }

    private fun scan(configured: String? = null, notice: AshCliLocator.FallbackNotice = AshCliLocator.FallbackNotice()) =
        AshScanController.scan(project, configured, pathValue = bin.toString(), notice = notice, sourceDir = sourceDir)

    fun testExitTwoRealReportHighlightsThePlantedSecret() {
        openLeak()
        stub("ashx", "exit2", exitCode = 2)

        val messages = scan()

        val highlights = ashHighlights()
        assertEquals("one highlight per detect-secrets result on leak.py", 3, highlights.size)
        val secret = myFixture.editor.document.text.indexOf("wJalrXUtnFEMI")
        for (info in highlights) {
            assertEquals(HighlightSeverity.ERROR, info.severity)
            assertTrue("must cover the secret: ${info.description}", info.startOffset <= secret && info.endOffset > secret)
            assertTrue(info.description, info.description.startsWith("ASH [detect-secrets"))
        }
        val finished = messages.single()
        assertEquals(NotificationType.INFORMATION, finished.type)
        assertEquals("ASH scan finished", finished.title)
        assertTrue(finished.body, finished.body.contains("3 finding(s): 3 error"))
        assertTrue(finished.body, finished.body.contains("exit code 2"))
    }

    fun testExitOneIncompleteShowsThePartialFindingsAndSaysWhatDidNotRun() {
        openLeak()
        stub("ashx", "exit1", exitCode = 1)

        val messages = scan()

        assertEquals("the partial findings must reach the editor", 3, ashHighlights().size)
        val warning = messages.single()
        assertEquals(NotificationType.WARNING, warning.type)
        assertEquals("ASH scan incomplete", warning.title)
        assertTrue(warning.body, warning.body.contains("INCOMPLETE (exit 1)"))
        assertTrue(warning.body, warning.body.contains("Showing the 3 finding(s) it did produce"))
        assertTrue("must name the scanner that did not run: ${warning.body}", warning.body.contains("cfn-nag (MISSING)"))

        // And on the message bus, which is how the user actually meets it.
        PlatformTestUtil.dispatchAllEventsInIdeEventQueue()
        val delivered = notifications.single { it.groupId == AshNotifier.GROUP_ID }
        assertEquals(NotificationType.WARNING, delivered.type)
        assertEquals("ASH scan incomplete", delivered.title)
    }

    fun testExitOneWithNoScannerToNameCarriesAshsOwnReason() {
        // An unevaluated rule or a stale content database has no scanner row. ASH's console is
        // then the only place the reason is written, and it must reach the user.
        openLeak()
        stub(
            "ashx",
            "exit1",
            exitCode = 1,
            statusOverride = """{"scanner_results": {"detect-secrets": {"status": "FAILED"}}}""",
        )

        val warning = scan().single()

        assertEquals("ASH scan incomplete", warning.title)
        assertTrue(warning.body, warning.body.contains("names no scanner that failed to complete"))
        assertTrue(warning.body, warning.body.contains("Exiting because the scan was incomplete"))
        assertEquals(3, ashHighlights().size)
    }

    fun testExitOneWithNoReportIsAFailureAndShowsNothing() {
        openLeak()
        stub("ashx", capture = null, exitCode = 1)

        val failed = scan().single()

        assertEquals(NotificationType.ERROR, failed.type)
        assertEquals("ASH scan failed", failed.title)
        assertTrue(failed.body, failed.body.contains("exited 1 and wrote no SARIF"))
        assertEquals(0, ashHighlights().size)
    }

    fun testCleanRealScanProducesNoHighlights() {
        // The negative partner of the planted-secret test: the same file, a real clean SARIF.
        openLeak()
        stub("ashx", "exit2", exitCode = 0, sarifOverride = resource("/sarif/ash-clean-scan.sarif"))

        val messages = scan()

        assertEquals(0, ashHighlights().size)
        assertEquals("ASH scan finished", messages.single().title)
        assertTrue(messages.single().body, messages.single().body.contains("no findings"))
    }

    fun testFallsBackToAshWithANoticeShownOncePerSession() {
        openLeak()
        stub("ash", "exit2", exitCode = 2)
        val notice = AshCliLocator.FallbackNotice()

        val first = scan(notice = notice)

        assertTrue("the fallback must actually have run", ran("ash"))
        assertEquals(listOf("ASH: using 'ash'", "ASH scan finished"), first.map { it.title })
        assertEquals(NotificationType.INFORMATION, first[0].type)
        assertTrue(first[0].body, first[0].body.contains(bin.resolve("ash").toString()))
        assertEquals(3, ashHighlights().size)

        val second = scan(notice = notice)
        assertEquals("the notice is not repeated", listOf("ASH scan finished"), second.map { it.title })
    }

    fun testAshxIsPreferredOverAshAndNoNoticeIsShown() {
        openLeak()
        stub("ashx", "exit2", exitCode = 2)
        // If this one ran, the scan would fail with an unknown exit code.
        stub("ash", "exit2", exitCode = 9)

        val messages = scan()

        assertTrue(ran("ashx"))
        assertFalse("ash must not run when ashx is present", ran("ash"))
        assertEquals(listOf("ASH scan finished"), messages.map { it.title })
    }

    fun testConfiguredExecutableIsUsedAsGiven() {
        openLeak()
        val configured = stub("my-ash", "exit2", exitCode = 2)
        // Moved off the PATH directory, so only the configured value can reach it.
        val elsewhere = Files.createDirectories(bin.resolve("configured")).resolve("my-ash")
        Files.move(configured, elsewhere)
        stub("ashx", "exit2", exitCode = 9)

        val messages = scan(configured = elsewhere.toString())

        assertEquals(listOf("ASH scan finished"), messages.map { it.title })
        assertFalse("PATH must not be consulted when an executable is configured", ran("ashx"))
        assertEquals(3, ashHighlights().size)
    }

    fun testNoCliOnPathIsAnErrorNotAnEmptyPanel() {
        openLeak()

        val messages = scan()

        assertEquals(NotificationType.ERROR, messages.single().type)
        assertEquals("ASH CLI not found", messages.single().title)
        assertTrue(messages.single().body, messages.single().body.contains("Searched 1 PATH entry"))
        assertEquals(0, ashHighlights().size)
    }

    fun testNotFoundListsAtMostSixSearchedDirectoriesAndAnEmptyPathNone() {
        val many = (1..8).joinToString(java.io.File.pathSeparator) { bin.resolve("d$it").toString() }
        val listed = AshScanController.scan(project, null, pathValue = many, sourceDir = sourceDir).single()
        assertTrue(listed.body, listed.body.contains("Searched 8 PATH entries, including: "))
        assertTrue(listed.body, listed.body.contains("d6, ..."))
        assertFalse(listed.body, listed.body.contains("d7"))

        val none = AshScanController.scan(project, null, pathValue = "", sourceDir = sourceDir).single()
        assertTrue(none.body, none.body.contains("PATH is empty or unset"))
        assertFalse(none.body, none.body.contains("Searched"))
    }

    fun testAnExecutableThatIsNotAshEndsInAnErrorWithNoScan() {
        openLeak()
        val shell = bin.resolve("ashx")
        Files.writeString(shell, "#!/bin/sh\necho \"ash: Illegal option \$1\" >&2\nexit 2\n")
        shell.toFile().setExecutable(true)

        val failed = scan().single()

        assertEquals("ASH scan failed", failed.title)
        assertTrue(failed.body, failed.body.contains("is not ASH") && failed.body.contains("MSYS2"))
        assertFalse("the probe's verdict carries no output block", failed.body.contains("<pre>"))
        assertEquals(0, ashHighlights().size)
    }

    fun testAFailedScanClearsThePreviousFindings() {
        openLeak()
        stub("ashx", "exit2", exitCode = 2)
        scan()
        assertEquals(3, ashHighlights().size)

        stub("ashx", "exit2", exitCode = 3)
        val failed = scan().single()

        assertEquals("ASH scan failed", failed.title)
        assertTrue(failed.body, failed.body.contains("ASH exited 3"))
        assertEquals("stale findings must not survive a failed scan", 0, ashHighlights().size)
    }

    fun testAProjectWithNoDirectoryIsReportedRatherThanScanned() {
        val messages = AshScanController.scan(project, configured = null, pathValue = bin.toString(), sourceDir = null)
        assertEquals("ASH scan not started", messages.single().title)
    }

    fun testAnUncreatableOutputDirectoryIsReported() {
        // .ash exists as a FILE, so the output directory under it cannot be created.
        Files.writeString(sourceDir.resolve(".ash"), "not a directory")
        stub("ashx", "exit2", exitCode = 2)

        val messages = scan()

        assertEquals("ASH scan not started", messages.single().title)
        assertFalse("nothing may run without an output directory", ran("ashx"))
    }

    fun testTheActionRunsAScanWithTheConfiguredExecutable() {
        // The platform wiring: the action reads Settings, queues the background task, and the
        // task runs the controller. Driven through the action's own entry points.
        val configured = stub("ashx", "exit2", exitCode = 2)
        AshSettings.getInstance().executablePath = configured.toString()
        val action = AshScanAction()
        val event = TestActionEvent.createTestEvent(action, SimpleDataContext.getProjectContext(project))

        action.update(event)
        assertTrue("enabled with a project", event.presentation.isEnabled)
        action.actionPerformed(event)

        val deadline = System.currentTimeMillis() + 60_000
        while (!AshScanService.getInstance(project).current.hasRun && System.currentTimeMillis() < deadline) {
            PlatformTestUtil.dispatchAllEventsInIdeEventQueue()
            Thread.sleep(20)
        }
        assertTrue("the queued scan must have run the configured executable", ran("ashx"))
        assertTrue(AshScanService.getInstance(project).current.hasRun)

        val noProject = TestActionEvent.createTestEvent(action, SimpleDataContext.EMPTY_CONTEXT)
        action.update(noProject)
        assertFalse("disabled without a project", noProject.presentation.isEnabled)
        // Does nothing, and must not throw, without a project.
        action.actionPerformed(noProject)
        assertNull(noProject.getData(CommonDataKeys.PROJECT))
    }

    fun testATruncatedReportClearsThePreviousFindingsAndIsAnError() {
        openLeak()
        stub("ashx", "exit2", exitCode = 2)
        scan()
        assertEquals(3, ashHighlights().size)

        // The real exit-2 report cut in half, as a scan killed mid-write leaves it.
        val real = Files.readString(resource("/real-cli/exit2/ash.sarif"))
        val truncated = bin.resolve("truncated.sarif")
        Files.writeString(truncated, real.substring(0, real.length / 2))
        stub("ashx", "exit2", exitCode = 2, sarifOverride = truncated)

        val failed = scan().single()

        assertEquals(NotificationType.ERROR, failed.type)
        assertEquals("ASH scan failed", failed.title)
        assertTrue(failed.body, failed.body.contains("not a readable SARIF report"))
        assertEquals("findings from the previous run must not survive", 0, ashHighlights().size)
    }

    fun testTheActionIsDisabledWhileAScanRuns() {
        val action = AshScanAction()
        val event = TestActionEvent.createTestEvent(action, SimpleDataContext.getProjectContext(project))
        val service = AshScanService.getInstance(project)

        assertTrue(service.tryStartScan())
        try {
            action.update(event)
            assertFalse("disabled while a scan runs", event.presentation.isEnabled)
        } finally {
            service.finishScan()
        }
        action.update(event)
        assertTrue("enabled again once it finishes", event.presentation.isEnabled)
    }
}
