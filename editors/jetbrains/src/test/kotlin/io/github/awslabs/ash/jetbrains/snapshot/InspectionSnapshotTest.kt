// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains.snapshot

import com.intellij.codeInsight.daemon.impl.HighlightInfo
import com.intellij.codeInspection.InspectionManager
import com.intellij.codeInspection.ProblemHighlightType
import com.intellij.openapi.util.TextRange
import com.intellij.testFramework.fixtures.BasePlatformTestCase
import com.intellij.testFramework.fixtures.TempDirTestFixture
import com.intellij.testFramework.fixtures.impl.TempDirTestFixtureImpl
import io.github.awslabs.ash.jetbrains.AshCliLocator
import io.github.awslabs.ash.jetbrains.AshFindingInspection
import io.github.awslabs.ash.jetbrains.AshSarifParser
import io.github.awslabs.ash.jetbrains.AshScanController
import io.github.awslabs.ash.jetbrains.AshScanService
import java.nio.file.Files
import java.nio.file.Path

/**
 * What the editor shows for ASH findings: for every highlight, its range, its severity, how it
 * is styled (problem type, highlight type, text attributes key), the text it underlines, the
 * problem description, and the HTML tooltip the hover shows.
 *
 * The highlights come from the real highlighting pass over a real document, as in
 * AshFindingInspectionIdeTest. That class asserts lines and severities; this one pins the whole
 * rendering, so a change to the tooltip wording, to the attribution prefix or to how a range is
 * mapped onto the text fails here.
 */
class InspectionSnapshotTest : BasePlatformTestCase() {

    private lateinit var bin: Path

    override fun createTempDirTestFixture(): TempDirTestFixture = TempDirTestFixtureImpl()

    override fun setUp() {
        super.setUp()
        myFixture.enableInspections(AshFindingInspection())
        bin = Files.createTempDirectory("ash-snapshot-bin-")
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

    /**
     * The inspection's own problems for the open file, keyed by range and description, so each
     * highlight can be paired with the [ProblemHighlightType] that produced it. The highlight
     * alone does not say: LIKE_UNUSED_SYMBOL and WARNING both reach the editor at WARNING
     * severity, and only the type decides whether the code is underlined or greyed out.
     */
    private fun highlightTypes(): Map<Pair<TextRange, String>, ProblemHighlightType> {
        val problems = AshFindingInspection().checkFile(myFixture.file, InspectionManager.getInstance(project), true)
            ?: return emptyMap()
        return problems.associate { problem ->
            val element = problem.psiElement
            val range = problem.textRangeInElement?.shiftRight(element.textRange.startOffset) ?: element.textRange
            (range to problem.descriptionTemplate) to problem.highlightType
        }
    }

    private fun render(): String {
        val document = myFixture.editor.document
        val infos = myFixture.doHighlighting()
            .filter { it.description?.startsWith("ASH") == true }
            .sortedWith(compareBy<HighlightInfo>({ it.startOffset }, { it.endOffset }, { it.description }))
        val types = highlightTypes()
        return buildString {
            append("file: ").append(myFixture.file.name).append('\n')
            append("highlights: ").append(infos.size).append('\n')
            for (info in infos) {
                val start = document.getLineNumber(info.startOffset)
                val end = document.getLineNumber(info.endOffset)
                val startCol = info.startOffset - document.getLineStartOffset(start) + 1
                val endCol = info.endOffset - document.getLineStartOffset(end) + 1
                val problemType = types[TextRange(info.startOffset, info.endOffset) to info.description]
                append("\n").append("${start + 1}:$startCol-${end + 1}:$endCol ").append(info.severity.name).append('\n')
                // How the editor styles the range, which the severity does not determine: the
                // problem type the inspection chose, the text attributes key of the highlight type
                // it became, and the forced key, which wins over the type's own when one is set.
                append("  style: problem type ").append(problemType?.name ?: "<no matching problem>")
                append(", attributes ").append(info.type.attributesKey.externalName)
                append(", forced attributes ").append(info.forcedTextAttributesKey?.externalName ?: "none").append('\n')
                append("  text: ").append(document.getText(TextRange(info.startOffset, info.endOffset)).replace("\n", "\\n")).append('\n')
                append("  description: ").append(info.description).append('\n')
                append("  tooltip: ").append(info.toolTip).append('\n')
            }
        }
    }

    private fun sarif(path: String, vararg results: String) = """
        {"version": "2.1.0", "runs": [{
          "tool": {"driver": {"name": "bandit", "rules": [{"id": "INHERITS", "defaultConfiguration": {"level": "error"}}]}},
          "results": [${results.joinToString(",")}]
        }]}
    """.trimIndent().replace("@PATH@", path)

    private fun result(rule: String, level: String?, region: String, text: String = "$rule finding") = buildString {
        append("""{"ruleId": "$rule", """)
        if (level != null) append(""""level": "$level", """)
        append(""""message": {"text": "$text"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "@PATH@"}, "region": $region}}]}""")
    }

    fun testTheRealExitTwoReportOnThePlantedSecret() {
        val text = Files.readString(StubAshCli(bin).fixture("/fixtures/leak.py"))
        myFixture.configureFromExistingVirtualFile(myFixture.tempDirFixture.createFile("leak.py", text))
        StubAshCli(bin).write("ashx", "exit2", exitCode = 2)
        AshScanController.scan(project, null, bin.toString(), notice = AshCliLocator.FallbackNotice(), sourceDir = sourceDir)
        // The fixture's secret line is masked, and only that line: a committed snapshot quoting
        // it would be a second copy of the planted credential for the repository's own secret
        // scan to find, where .ash/.ash.yaml exempts exactly one, leak.py. The range on each
        // highlight still pins exactly what is underlined.
        val secretLine = text.lines()[1]
        assertTrue("the fixture's second line is the planted key", secretLine.contains("wJalrXUtnFEMI"))
        Snapshots.assertMatches(
            javaClass,
            "real-exit2-leak-py",
            render(),
            masks = mapOf(secretLine to "<leak.py line 2, the planted example key>"),
        )
    }

    fun testEverySeverityAndTheInheritedOne() {
        val file = myFixture.configureByText(
            "insecure.py",
            "import os\nvalue = eval(user_input)\nos.system(\"rm -rf /\")\nprint(\"ok\")\nassert value\n",
        )
        AshScanService.getInstance(project).update(
            AshSarifParser.parse(
                sarif(
                    file.virtualFile.path,
                    result("B307", "error", """{"startLine": 2}""", "Use of possibly insecure function - consider using safer ast.literal_eval."),
                    result("B605", "warning", """{"startLine": 3, "startColumn": 1, "endColumn": 22}""", "Starting a process with a shell."),
                    result("B101", "note", """{"startLine": 5}""", "Use of assert detected."),
                    result("INHERITS", null, """{"startLine": 4}""", "Level taken from the rule."),
                    result("B999", "Level.error", """{"startLine": 1}""", "An enum-repr level is still an error."),
                ),
            ),
            sourceDir.toString(),
        )
        Snapshots.assertMatches(javaClass, "every-severity", render())
    }

    fun testAMultiLineRegionInAFileTypeNoInspectionWasRegisteredFor() {
        val file = myFixture.configureByText(
            "main.tf",
            "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"b\"\n  acl    = \"public-read\"\n}\n",
        )
        AshScanService.getInstance(project).update(
            AshSarifParser.parse(
                sarif(
                    file.virtualFile.path,
                    result("CKV_AWS_20", "error", """{"startLine": 1, "endLine": 4}""", "S3 Bucket has an ACL defined which allows public READ access."),
                ),
            ),
            sourceDir.toString(),
        )
        Snapshots.assertMatches(javaClass, "terraform-multiline", render())
    }
}
