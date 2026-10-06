// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.intellij.codeInsight.daemon.impl.HighlightInfo
import com.intellij.notification.NotificationType
import com.intellij.testFramework.fixtures.BasePlatformTestCase
import com.intellij.testFramework.fixtures.TempDirTestFixture
import com.intellij.testFramework.fixtures.impl.TempDirTestFixtureImpl
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import java.util.concurrent.TimeUnit

/**
 * The plugin driving a REAL ASH CLI built from this commit, headless, over the shared e2e
 * fixtures in tests/e2e/fixtures.
 *
 * AshScanIntegrationTest replays captured ASH output through a shell stub. This class runs the
 * installed CLI instead: the wheel the CI job builds from the checkout, installed into a fresh
 * venv. Each case in tests/e2e/fixtures/cases.json is scanned through AshScanController, the
 * same entry point the action uses, and judged twice:
 *
 *  - by scripts/e2e/assert_outcome.py over the output directory the plugin read, so this channel
 *    is held to the same verdict as every other e2e channel (exact exit code, both report files
 *    at their exact paths, the finding count in both, the selected scanners not SKIPPED, and for
 *    exit 1 the named scanner MISSING or ERROR); and
 *  - by what the user sees: the notification's type, title and text, the number of highlights
 *    in the editor, and the plugin's own reading of coverage completeness.
 *
 * HOW THE CASE REACHES THE CLI. The plugin's command line is fixed (`scan --source-dir
 * --output-dir --output-formats sarif --no-progress`) and has no setting for extra arguments,
 * while a case selects its scanners with `--scanners`, may add arguments, and may set
 * environment variables (the exit-1 trigger does). So the executable the plugin finds on PATH is
 * a three-line shell wrapper, written from the case, that sets the case's environment, appends
 * the case's arguments to `scan`, runs the real console script, and records the real exit code.
 * The wrapper adds nothing else, and assert_outcome's selected-scanner check fails if the
 * arguments did not arrive. The exit code it records is compared with the one the plugin
 * reported.
 *
 * ENVIRONMENT. ASH_JB_REAL_CLI_BIN must name a directory holding the installed `ashx` and `ash`
 * console scripts (a venv's bin). The `realCliTest` Gradle task is the only thing that runs this
 * class, and the class FAILS when the variable is missing or the scripts are not there. It never
 * skips: a suite that skips when its input is absent passes in exactly the case it exists for.
 * python3 must be on PATH for assert_outcome.py, which is standard library only.
 */
class AshScanRealCliTest : BasePlatformTestCase() {

    private lateinit var bin: Path

    override fun createTempDirTestFixture(): TempDirTestFixture = TempDirTestFixtureImpl()

    override fun setUp() {
        super.setUp()
        myFixture.enableInspections(AshFindingInspection())
        bin = Files.createTempDirectory("ash-real-cli-bin-")
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

    private val outputDir: Path get() = sourceDir.resolve(".ash").resolve("ash_output")

    /** The checkout. Gradle runs the tests from editors/jetbrains. */
    private val repoRoot: Path = Path.of("").toAbsolutePath().resolve("../..").normalize()

    private val casesFile: Path get() = repoRoot.resolve("tests/e2e/fixtures/cases.json")

    /** The installed console script named [name], or a failure that says what is missing. */
    private fun installed(name: String): Path {
        val dir = System.getenv(BIN_ENV)
        if (dir.isNullOrBlank()) {
            fail(
                "$BIN_ENV is not set. This suite drives a real ASH CLI and has nothing to run " +
                    "without one; it fails rather than skips. Point it at the bin directory of a " +
                    "venv the head wheel was installed into.",
            )
        }
        val path = Path.of(dir!!).resolve(name)
        assertTrue(
            "$BIN_ENV=$dir holds no executable '$name'. This suite fails rather than skips when " +
                "the CLI it was told to use is absent.",
            Files.isRegularFile(path) && Files.isExecutable(path),
        )
        return path
    }

    private fun case(name: String): JsonObject {
        val root = JsonParser.parseString(Files.readString(casesFile)).asJsonObject
        return requireNotNull(root.getAsJsonObject("cases").getAsJsonObject(name)) { "no case $name in $casesFile" }
    }

    /** The CLI name the e2e scripts share, which must be the name the plugin looks for first. */
    private fun sharedCliName(): String =
        JsonParser.parseString(Files.readString(repoRoot.resolve("scripts/e2e/cli_name.json")))
            .asJsonObject.get("cli_name").asString

    private fun quote(value: String): String = "'" + value.replace("'", "'\\''") + "'"

    /**
     * Writes [wrapperName] into the PATH directory: no inherited PYTHONPATH or PYTHONHOME, the
     * case's environment, then the real CLI with the case's scanners and arguments appended to
     * `scan`. Everything else passes through
     * unchanged, so the plugin's `--version` probe answers with the real CLI's version line.
     */
    private fun wrapper(wrapperName: String, real: Path, case: JsonObject): Path {
        val scanners = case.getAsJsonArray("scanners").joinToString(",") { it.asString }
        val extra = case.getAsJsonArray("args").map { quote(it.asString) }
        val script = bin.resolve(wrapperName)
        val body = buildString {
            appendLine("#!/bin/sh")
            // e2e-real-cli.sh puts a vendored defusedxml on PYTHONPATH for the Gradle census,
            // and the JVM, the plugin's process and this wrapper all inherit it. ASH itself
            // depends on defusedxml, so the inherited path would let a wheel that forgot that
            // requirement pass here and crash on a real fresh install. The CLI gets only what
            // its own venv holds.
            appendLine("unset PYTHONPATH PYTHONHOME")
            for ((key, value) in case.getAsJsonObject("env").entrySet()) {
                appendLine("export $key=${quote(value.asString)}")
            }
            appendLine("if [ \"\$1\" = scan ]; then")
            appendLine("  ${quote(real.toString())} \"\$@\" --scanners ${quote(scanners)} ${extra.joinToString(" ")}")
            appendLine("  rc=\$?")
            appendLine("  echo \"\$rc\" > ${quote(bin.resolve("$wrapperName.rc").toString())}")
            appendLine("  exit \"\$rc\"")
            appendLine("fi")
            appendLine("exec ${quote(real.toString())} \"\$@\"")
        }
        Files.writeString(script, body)
        Files.setPosixFilePermissions(
            script,
            setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE),
        )
        return script
    }

    /** The exit code the real CLI returned to the wrapper. */
    private fun realExitCode(wrapperName: String): Int {
        val file = bin.resolve("$wrapperName.rc")
        assertTrue("the wrapper never ran a scan, so the plugin did not reach the CLI", Files.isRegularFile(file))
        return Files.readString(file).trim().toInt()
    }

    /** Copies tests/e2e/fixtures/<source>/ into the project directory the plugin scans. */
    private fun copyFixture(case: JsonObject) {
        val source = repoRoot.resolve("tests/e2e/fixtures").resolve(case.get("source").asString)
        Files.list(source).use { files ->
            for (file in files) Files.copy(file, sourceDir.resolve(file.fileName))
        }
    }

    private fun open(fileName: String) {
        val text = Files.readString(sourceDir.resolve(fileName))
        myFixture.configureFromExistingVirtualFile(myFixture.tempDirFixture.createFile(fileName, text))
    }

    private fun ashHighlights(): List<HighlightInfo> =
        myFixture.doHighlighting().filter { it.description?.startsWith("ASH") == true }

    private data class AssertRun(val exitCode: Int, val output: String)

    /** scripts/e2e/assert_outcome.py over [outputDir], with [extra] flags after the case's own. */
    private fun assertOutcome(caseName: String, rc: Int, vararg extra: String): AssertRun {
        val command = listOf(
            "python3",
            repoRoot.resolve("scripts/e2e/assert_outcome.py").toString(),
            "--case", caseName,
            "--output-dir", outputDir.toString(),
            "--rc", rc.toString(),
            *extra,
        )
        val process = ProcessBuilder(command).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().readText()
        assertTrue("assert_outcome.py did not finish", process.waitFor(2, TimeUnit.MINUTES))
        return AssertRun(process.exitValue(), output)
    }

    /** The shared verdict on the real output, required to pass. */
    private fun requireSharedVerdict(caseName: String, rc: Int) {
        val run = assertOutcome(caseName, rc)
        assertEquals("assert_outcome.py rejected the real '$caseName' output:\n${run.output}", 0, run.exitCode)
    }

    /** The plugin's own completeness reading of the status file the real CLI wrote. */
    private fun pluginIncompleteness(): String? =
        AshScannerStatus.parse(Files.readString(outputDir.resolve(AshScannerStatus.RELATIVE_PATH)))
            .describeIncompleteness()

    /** One scan through the controller with only [wrapperName] on PATH. */
    private fun scanCase(caseName: String, wrapperName: String, realName: String): List<AshScanController.Message> {
        val case = case(caseName)
        copyFixture(case)
        wrapper(wrapperName, installed(realName), case)
        return AshScanController.scan(
            project,
            configured = null,
            pathValue = bin.toString(),
            notice = AshCliLocator.FallbackNotice(),
            sourceDir = sourceDir,
        )
    }

    fun testTheSharedCliNameIsThePluginsPrimaryName() {
        assertEquals(
            "scripts/e2e/cli_name.json and AshCliLocator.PRIMARY_NAME must agree, or this suite " +
                "would test a name the plugin does not look for first",
            AshCliLocator.PRIMARY_NAME,
            sharedCliName(),
        )
    }

    fun testFindingsCaseExitsTwoAndHighlightsEveryFinding() {
        val messages = scanCase("findings", AshCliLocator.PRIMARY_NAME, AshCliLocator.PRIMARY_NAME)
        val rc = realExitCode(AshCliLocator.PRIMARY_NAME)

        assertEquals(2, rc)
        requireSharedVerdict("findings", rc)

        val finished = messages.single()
        assertEquals(finished.body, NotificationType.INFORMATION, finished.type)
        assertEquals("ASH scan finished", finished.title)
        assertTrue(finished.body, finished.body.contains("3 finding(s)"))
        assertTrue(finished.body, finished.body.contains("exit code 2"))
        assertNull("the plugin must read the real status file as complete", pluginIncompleteness())

        open("leak.py")
        val highlights = ashHighlights()
        assertEquals("one highlight per real finding", 3, highlights.size)
        val secret = myFixture.editor.document.text.indexOf("wJalrXUtnFEMI")
        for (info in highlights) {
            assertTrue("must cover the secret: ${info.description}", info.startOffset <= secret && info.endOffset > secret)
            assertTrue(info.description, info.description.startsWith("ASH [detect-secrets"))
        }
    }

    fun testFindingsCaseJudgedWithAWrongCountIsRejected() {
        // The negative partner of the test above, on the same real output: the shared verdict
        // must be able to fail on a real scan, not only on the planted outputs of its self-test.
        scanCase("findings", AshCliLocator.PRIMARY_NAME, AshCliLocator.PRIMARY_NAME)
        val rc = realExitCode(AshCliLocator.PRIMARY_NAME)
        requireSharedVerdict("findings", rc)

        val wrongCount = assertOutcome("findings", rc, "--findings", "4")
        assertEquals("a wrong expected count must fail:\n${wrongCount.output}", 1, wrongCount.exitCode)
        assertTrue(wrongCount.output, wrongCount.output.contains("expected exactly 4"))

        val judgedAsClean = assertOutcome("clean", rc)
        assertEquals("a findings scan judged as the clean case must fail:\n${judgedAsClean.output}", 1, judgedAsClean.exitCode)
        assertTrue(judgedAsClean.output, judgedAsClean.output.contains("expected exactly 0"))
    }

    fun testCleanCaseExitsZeroAndHighlightsNothing() {
        val messages = scanCase("clean", AshCliLocator.PRIMARY_NAME, AshCliLocator.PRIMARY_NAME)
        val rc = realExitCode(AshCliLocator.PRIMARY_NAME)

        assertEquals(0, rc)
        requireSharedVerdict("clean", rc)

        val finished = messages.single()
        assertEquals(finished.body, NotificationType.INFORMATION, finished.type)
        assertEquals("ASH scan finished", finished.title)
        assertTrue(finished.body, finished.body.contains("no findings"))
        assertTrue(finished.body, finished.body.contains("exit code 0"))
        assertNull("the plugin must read the real status file as complete", pluginIncompleteness())

        open("app.py")
        assertEquals(0, ashHighlights().size)
    }

    fun testIncompleteCaseExitsOneShowsThePartialFindingsAndNamesTheScanner() {
        val case = case("incomplete")
        val missing = case.get("incomplete_scanner").asString
        val messages = scanCase("incomplete", AshCliLocator.PRIMARY_NAME, AshCliLocator.PRIMARY_NAME)
        val rc = realExitCode(AshCliLocator.PRIMARY_NAME)

        assertEquals(1, rc)
        requireSharedVerdict("incomplete", rc)

        val warning = messages.single()
        assertEquals(warning.body, NotificationType.WARNING, warning.type)
        assertEquals("ASH scan incomplete", warning.title)
        assertTrue(warning.body, warning.body.contains("INCOMPLETE (exit 1)"))
        assertTrue(warning.body, warning.body.contains("Showing the 3 finding(s) it did produce"))
        assertTrue("must name the scanner that did not run: ${warning.body}", warning.body.contains("$missing (MISSING)"))
        val incompleteness = pluginIncompleteness()
        assertNotNull("the plugin must read the real status file as incomplete", incompleteness)
        assertTrue(incompleteness!!, incompleteness.contains(missing))

        open("leak.py")
        assertEquals("the partial findings must reach the editor", 3, ashHighlights().size)
    }

    fun testFallsBackToTheRealAshWithANotice() {
        // Only `ash` on PATH: the installed fallback console script, not a copy of ashx.
        val messages = scanCase("findings", AshCliLocator.FALLBACK_NAME, AshCliLocator.FALLBACK_NAME)
        val rc = realExitCode(AshCliLocator.FALLBACK_NAME)

        assertEquals(2, rc)
        requireSharedVerdict("findings", rc)
        assertEquals(listOf("ASH: using 'ash'", "ASH scan finished"), messages.map { it.title })
        assertTrue(messages[0].body, messages[0].body.contains(bin.resolve(AshCliLocator.FALLBACK_NAME).toString()))
        assertTrue(messages[1].body, messages[1].body.contains("exit code 2"))

        open("leak.py")
        assertEquals(3, ashHighlights().size)
    }

    private companion object {
        const val BIN_ENV = "ASH_JB_REAL_CLI_BIN"
    }
}
