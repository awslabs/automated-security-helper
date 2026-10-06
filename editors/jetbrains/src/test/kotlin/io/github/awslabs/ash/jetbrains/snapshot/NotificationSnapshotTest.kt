// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains.snapshot

import com.intellij.notification.Notification
import com.intellij.notification.Notifications
import com.intellij.openapi.progress.EmptyProgressIndicator
import com.intellij.testFramework.PlatformTestUtil
import com.intellij.testFramework.fixtures.BasePlatformTestCase
import com.intellij.testFramework.fixtures.TempDirTestFixture
import com.intellij.testFramework.fixtures.impl.TempDirTestFixtureImpl
import io.github.awslabs.ash.jetbrains.AshCliLocator
import io.github.awslabs.ash.jetbrains.AshFindingInspection
import io.github.awslabs.ash.jetbrains.AshNotifier
import io.github.awslabs.ash.jetbrains.AshScanController
import io.github.awslabs.ash.jetbrains.AshScanService
import java.nio.file.Files
import java.nio.file.Path

/**
 * Every notification a scan can end in, exactly as the user receives it: delivered on the
 * project's message bus, with its group, type, title and HTML body, and the progress text the
 * scan showed on the way there.
 *
 * One scenario per arm of AshScanController and AshScanRunner that a user can reach, driven
 * through the same entry point the Tools menu action calls. The ASH CLI is [StubAshCli], replaying
 * a captured real run; the IDE, the process launch and the notification delivery are real.
 * AshScanIntegrationTest asserts the behavior of these arms; this class pins the words.
 *
 * Masked: the project directory as `<PROJECT>` and the stub's directory as `<BIN>`, both temp
 * paths that differ per run. Nothing else is masked, so a version, a count or a path rendered
 * differently fails here.
 */
class NotificationSnapshotTest : BasePlatformTestCase() {

    private lateinit var bin: Path
    private lateinit var stubs: StubAshCli
    private val delivered = mutableListOf<Notification>()

    override fun createTempDirTestFixture(): TempDirTestFixture = TempDirTestFixtureImpl()

    override fun setUp() {
        super.setUp()
        myFixture.enableInspections(AshFindingInspection())
        bin = Files.createTempDirectory("ash-snapshot-bin-")
        stubs = StubAshCli(bin)
        project.messageBus.connect(testRootDisposable).subscribe(
            Notifications.TOPIC,
            object : Notifications {
                override fun notify(notification: Notification) {
                    delivered += notification
                }
            },
        )
    }

    override fun tearDown() {
        try {
            AshScanService.getInstance(project).clear()
            bin.toFile().deleteRecursively()
        } finally {
            super.tearDown()
        }
    }

    private val sourceDir: Path get() = Path.of(myFixture.tempDirPath)

    /** Records every progress text a scan sets, which the IDE shows in the status bar. */
    private class RecordingIndicator : EmptyProgressIndicator() {
        val texts = mutableListOf<String>()
        override fun setText(text: String?) {
            super.setText(text)
            if (text != null) texts += text
        }
    }

    private fun openLeak() {
        val text = Files.readString(stubs.fixture("/fixtures/leak.py"))
        myFixture.configureFromExistingVirtualFile(myFixture.tempDirFixture.createFile("leak.py", text))
    }

    /**
     * Runs a scan and renders what reached the user. The messages the controller returned and
     * the notifications delivered on the bus must be the same list, so the snapshot of one is a
     * snapshot of both.
     */
    private fun scanAndRender(
        configured: String? = null,
        pathValue: String? = bin.toString(),
        notice: AshCliLocator.FallbackNotice = AshCliLocator.FallbackNotice(),
        indicator: RecordingIndicator = RecordingIndicator(),
        sourceDir: Path? = this.sourceDir,
    ): String {
        delivered.clear()
        val returned = AshScanController.scan(project, configured, pathValue, indicator, notice, sourceDir)
        PlatformTestUtil.dispatchAllEventsInIdeEventQueue()
        val ours = delivered.filter { it.groupId == AshNotifier.GROUP_ID }
        assertEquals(
            "the controller's messages and the delivered notifications must agree",
            returned.map { Triple(it.type, it.title, it.body) },
            ours.map { Triple(it.type, it.title, it.content) },
        )
        return buildString {
            append("progress:\n")
            if (indicator.texts.isEmpty()) append("  (none)\n")
            indicator.texts.forEach { append("  ").append(it).append('\n') }
            for (n in ours) {
                append("\nnotification group=").append(n.groupId).append(" type=").append(n.type).append('\n')
                append("title: ").append(n.title).append('\n')
                append("body:\n")
                append(n.content.replace("<br>", "<br>\n")).append('\n')
            }
        }
    }

    private fun assertSnapshot(name: String, rendered: String) {
        Snapshots.assertMatches(
            javaClass,
            name,
            rendered,
            masks = mapOf(sourceDir.toString() to "<PROJECT>", bin.toString() to "<BIN>"),
        )
    }

    fun testFindingsFromARealExitTwoReport() {
        openLeak()
        stubs.write("ashx", "exit2", exitCode = 2)
        assertSnapshot("exit2-findings", scanAndRender())
    }

    fun testIncompleteExitOneNamesTheScannerThatDidNotRun() {
        openLeak()
        stubs.write("ashx", "exit1", exitCode = 1)
        assertSnapshot("exit1-incomplete", scanAndRender())
    }

    fun testIncompleteExitOneWithNoScannerToNameQuotesAsh() {
        openLeak()
        stubs.write("ashx", "exit1", exitCode = 1, status = """{"scanner_results": {"detect-secrets": {"status": "FAILED"}}}""")
        assertSnapshot("exit1-no-scanner-named", scanAndRender())
    }

    fun testExitOneWithNoReport() {
        openLeak()
        stubs.write("ashx", capture = null, exitCode = 1)
        assertSnapshot("exit1-no-report", scanAndRender())
    }

    fun testCleanScan() {
        openLeak()
        stubs.write("ashx", "exit2", exitCode = 0, sarif = stubs.fixture("/sarif/ash-clean-scan.sarif"))
        assertSnapshot("clean", scanAndRender())
    }

    fun testFallbackFromAshxToAshAndItsOncePerSessionNotice() {
        openLeak()
        stubs.write("ash", "exit2", exitCode = 2)
        val notice = AshCliLocator.FallbackNotice()
        val first = scanAndRender(notice = notice)
        val second = scanAndRender(notice = notice)
        assertSnapshot("fallback-to-ash", "first scan:\n$first\nsecond scan:\n$second")
    }

    fun testNoCliOnPath() {
        assertSnapshot("not-found", scanAndRender())
    }

    fun testNoCliOnALongPath() {
        val many = (1..8).joinToString(java.io.File.pathSeparator) { bin.resolve("d$it").toString() }
        assertSnapshot("not-found-long-path", scanAndRender(pathValue = many))
    }

    fun testEmptyPath() {
        assertSnapshot("not-found-empty-path", scanAndRender(pathValue = ""))
    }

    fun testAnExecutableThatIsNotAsh() {
        stubs.writeScript("ashx", "#!/bin/sh\necho \"ash: Illegal option \$1\" >&2\nexit 2\n")
        assertSnapshot("not-ash", scanAndRender())
    }

    fun testAConfiguredExecutableThatCannotStart() {
        assertSnapshot("configured-cannot-start", scanAndRender(configured = bin.resolve("missing-ash").toString()))
    }

    fun testAnExitCodeThatMeansTheScanDidNotRun() {
        openLeak()
        stubs.write("ashx", "exit2", exitCode = 3)
        assertSnapshot("exit3-did-not-run", scanAndRender())
    }

    fun testATruncatedReport() {
        openLeak()
        val real = Files.readString(stubs.fixture("/real-cli/exit2/ash.sarif"))
        val truncated = bin.resolve("truncated.sarif")
        Files.writeString(truncated, real.substring(0, real.length / 2))
        stubs.write("ashx", "exit2", exitCode = 2, sarif = truncated)
        assertSnapshot("truncated-report", scanAndRender())
    }

    fun testACancelledScan() {
        stubs.write("ashx", "exit2", exitCode = 2)
        val indicator = RecordingIndicator()
        indicator.cancel()
        assertSnapshot("cancelled", scanAndRender(indicator = indicator))
    }

    fun testAProjectWithNoDirectory() {
        assertSnapshot("no-project-directory", scanAndRender(sourceDir = null))
    }

    fun testAnUncreatableOutputDirectory() {
        Files.writeString(sourceDir.resolve(".ash"), "not a directory")
        stubs.write("ashx", "exit2", exitCode = 2)
        assertSnapshot("output-dir-uncreatable", scanAndRender())
    }

    fun testAScanWhileOneIsRunning() {
        val service = AshScanService.getInstance(project)
        assertTrue(service.tryStartScan())
        try {
            assertSnapshot("already-running", scanAndRender())
        } finally {
            service.finishScan()
        }
    }
}
