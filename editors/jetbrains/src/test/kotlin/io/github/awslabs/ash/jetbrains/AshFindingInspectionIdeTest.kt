// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import com.intellij.lang.annotation.HighlightSeverity
import com.intellij.codeInsight.daemon.impl.HighlightInfo
import com.intellij.testFramework.fixtures.BasePlatformTestCase

/**
 * The IDE-level assertion: a fixture SARIF produces real editor highlighting at the
 * expected lines, with the expected severities.
 *
 * This is not a mapping test with an IDE-shaped name. [BasePlatformTestCase] boots a real
 * Application and Project, `myFixture.doHighlighting()` runs the actual highlighting
 * pipeline, and what it returns is the [HighlightInfo] list the editor would render. So
 * this covers the whole chain the unit tests cannot: that the inspection is registered
 * for a language it was never named for, that [AshScanService] hands it the findings, that
 * the SARIF-to-document conversion lands on the right line in a real `Document`, that the
 * platform's bundled Gson resolves at runtime, and that [com.intellij.codeInspection.ProblemHighlightType]
 * becomes the severity intended rather than a flattened one.
 *
 * SARIF PATHS HERE ARE THE FIXTURE FILE'S OWN ABSOLUTE PATH, on purpose. The light test
 * fixture's project has no meaningful `basePath`, so a relative SARIF path would exercise
 * [AshPathResolver]'s project-root branch against a root that is a test artifact. That
 * branch is tested directly in AshPathResolverTest; what this test is for is the IDE
 * pipeline, so it removes the project-root variable rather than entangling the two.
 */
class AshFindingInspectionIdeTest : BasePlatformTestCase() {

    private val source = """
        import os
        value = eval(user_input)
        os.system("rm -rf /")
        print("ok")
    """.trimIndent()

    override fun setUp() {
        super.setUp()
        myFixture.enableInspections(AshFindingInspection())
    }

    override fun tearDown() {
        try {
            AshScanService.getInstance(project).clear()
        } finally {
            super.tearDown()
        }
    }

    /** Builds a one-run SARIF whose results point at [path]. */
    private fun sarifFor(path: String, vararg results: String): String = """
        {
          "version": "2.1.0",
          "runs": [
            {
              "tool": { "driver": { "name": "bandit", "rules": [
                { "id": "INHERITS", "defaultConfiguration": { "level": "error" } }
              ] } },
              "results": [ ${results.joinToString(",") { it.replace("@PATH@", path) }} ]
            }
          ]
        }
    """.trimIndent()

    private fun resultAt(ruleId: String, line: Int, level: String?): String = buildString {
        append("""{ "ruleId": "$ruleId", """)
        if (level != null) append(""""level": "$level", """)
        append(""""message": { "text": "$ruleId says line $line is a problem" }, """)
        append(""""locations": [ { "physicalLocation": { """)
        append(""""artifactLocation": { "uri": "@PATH@" }, """)
        append(""""region": { "startLine": $line } } } ] }""")
    }

    /** Maps each ASH highlight to `1-based line -> severity`, which is what a reader sees. */
    private fun ashHighlights(): List<Pair<Int, HighlightSeverity>> {
        val document = myFixture.editor.document
        return myFixture.doHighlighting()
            .filter { it.description?.startsWith("ASH") == true }
            .map { document.getLineNumber(it.startOffset) + 1 to it.severity }
            .sortedBy { it.first }
    }

    fun testFixtureSarifProducesHighlightsAtTheExpectedLinesAndSeverities() {
        val file = myFixture.configureByText("insecure.py", source)
        val path = file.virtualFile.path

        AshScanService.getInstance(project).update(
            AshSarifParser.parse(
                sarifFor(
                    path,
                    resultAt("B307", line = 2, level = "error"),
                    resultAt("B605", line = 3, level = "warning"),
                    resultAt("B101", line = 4, level = "note"),
                ),
            ),
        )

        assertEquals(
            listOf(
                2 to HighlightSeverity.ERROR,
                3 to HighlightSeverity.WARNING,
                4 to HighlightSeverity.WEAK_WARNING,
            ),
            ashHighlights(),
        )
    }

    fun testEnumReprLevelIsStillAnErrorInTheEditor() {
        // The severity-downgrade defect, asserted where the user would see it. A naive
        // consumer reads "Level.error", matches nothing, and renders this as a warning.
        val file = myFixture.configureByText("insecure.py", source)
        AshScanService.getInstance(project).update(
            AshSarifParser.parse(
                sarifFor(file.virtualFile.path, resultAt("B307", line = 2, level = "Level.error")),
            ),
        )
        assertEquals(listOf(2 to HighlightSeverity.ERROR), ashHighlights())
    }

    fun testLevelOmittedInheritsTheRuleDefaultInTheEditor() {
        val file = myFixture.configureByText("insecure.py", source)
        AshScanService.getInstance(project).update(
            AshSarifParser.parse(
                sarifFor(file.virtualFile.path, resultAt("INHERITS", line = 3, level = null)),
            ),
        )
        assertEquals(listOf(3 to HighlightSeverity.ERROR), ashHighlights())

        val tooltip = myFixture.doHighlighting().first { it.description?.startsWith("ASH") == true }
        assertTrue(
            "an inherited severity should say so; was: ${tooltip.description}",
            tooltip.description!!.contains("inherited"),
        )
    }

    fun testHighlightCoversTheReportedLineNotTheOneBelowIt() {
        // The off-by-one, asserted against real document text rather than a fake oracle.
        // A finding on line 2 must underline the eval line, and the assertion names the
        // text so an off-by-one shows up as "got print(\"ok\")" rather than as a number.
        val file = myFixture.configureByText("insecure.py", source)
        AshScanService.getInstance(project).update(
            AshSarifParser.parse(
                sarifFor(file.virtualFile.path, resultAt("B307", line = 2, level = "error")),
            ),
        )
        val info = myFixture.doHighlighting().single { it.description?.startsWith("ASH") == true }
        val highlighted = myFixture.editor.document.getText(
            com.intellij.openapi.util.TextRange(info.startOffset, info.endOffset),
        )
        assertEquals("value = eval(user_input)", highlighted)
    }

    fun testNoScanMeansNoAshHighlights() {
        // The negative control. Without it, a test suite where every finding is highlighted
        // cannot distinguish "the inspection works" from "the inspection highlights
        // everything".
        myFixture.configureByText("insecure.py", source)
        assertEquals(emptyList<Pair<Int, HighlightSeverity>>(), ashHighlights())
    }

    fun testFindingsForAnotherFileDoNotLeakIntoThisOne() {
        // The other half of the control: findings keyed to a different path must not appear
        // here. If they did, the test above would pass for the wrong reason -- every
        // finding showing up in every file.
        val file = myFixture.configureByText("insecure.py", source)
        val otherPath = file.virtualFile.parent.path + "/other.py"
        AshScanService.getInstance(project).update(
            AshSarifParser.parse(sarifFor(otherPath, resultAt("B307", line = 2, level = "error"))),
        )
        assertEquals(emptyList<Pair<Int, HighlightSeverity>>(), ashHighlights())
    }

    fun testFindingPastEndOfFileIsDroppedRatherThanClampedOntoRealCode() {
        // The file has 4 lines. A finding on line 40 is about a different revision, and
        // must not be pinned onto line 4.
        val file = myFixture.configureByText("insecure.py", source)
        AshScanService.getInstance(project).update(
            AshSarifParser.parse(
                sarifFor(file.virtualFile.path, resultAt("B307", line = 40, level = "error")),
            ),
        )
        assertEquals(emptyList<Pair<Int, HighlightSeverity>>(), ashHighlights())
    }

    fun testFindingsAppearInAFileTypeTheInspectionWasNeverRegisteredFor() {
        // The reason the inspection declares no language. ASH scans Terraform, Dockerfiles
        // and whatever else; a per-language registration would silently skip them.
        val file = myFixture.configureByText("main.tf", "resource \"aws_s3_bucket\" \"b\" {\n  acl = \"public-read\"\n}\n")
        AshScanService.getInstance(project).update(
            AshSarifParser.parse(
                sarifFor(file.virtualFile.path, resultAt("CKV_AWS_20", line = 2, level = "error")),
            ),
        )
        assertEquals(listOf(2 to HighlightSeverity.ERROR), ashHighlights())
    }

    fun testGsonResolvesInsideABootedPlatform() {
        // The parser reads JSON with the Gson the IntelliJ Platform bundles rather than a
        // declared dependency, which is how the plugin ships no third-party jar. That makes
        // "Gson is on the runtime classpath" an assumption, and this asserts it inside a
        // real platform instead of leaving it to be discovered by a user.
        val parsed = AshSarifParser.parse("""{"version":"2.1.0","runs":[]}""")
        assertEquals(emptyList<AshFinding>(), parsed.findings)
        assertEquals(emptyList<String>(), parsed.problems)
    }

    fun testAFindingWithNoAttributionOrSeverityIsStillLabeledAsAsh() {
        // Constructed directly, because the parser drops level-none findings and always fills a
        // scanner from the driver. The inspection must still render both without inventing one.
        val file = myFixture.configureByText("insecure.py", source)
        AshScanService.getInstance(project).update(
            AshScanResults(
                listOf(AshFinding(file.virtualFile.path, 2, 1, 2, null, AshLevel.NONE, true, null, "bare", null)),
                emptyList(),
            ),
        )
        val info = myFixture.doHighlighting().single { it.description?.startsWith("ASH") == true }
        assertEquals("ASH: bare", info.description)
        assertEquals(HighlightSeverity.INFORMATION, info.severity)
    }

    fun testAFileWithNoVirtualFileOrNoFindingsIsSkipped() {
        val inspection = AshFindingInspection()
        val manager = com.intellij.codeInspection.InspectionManager.getInstance(project)
        val inMemory = com.intellij.psi.PsiFileFactory.getInstance(project)
            .createFileFromText("scratch.txt", com.intellij.openapi.fileTypes.PlainTextFileType.INSTANCE, "x")
        assertNull("no file on disk, nothing to look findings up by", inspection.checkFile(inMemory, manager, false))
        val onDisk = myFixture.configureByText("insecure.py", source)
        assertNull("no findings, no descriptors", inspection.checkFile(onDisk, manager, false))
        assertEquals(AshFindingInspection.SHORT_NAME, inspection.shortName)
    }
}
