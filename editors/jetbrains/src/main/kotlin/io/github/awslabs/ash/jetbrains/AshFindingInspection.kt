// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import com.intellij.codeInspection.InspectionManager
import com.intellij.codeInspection.LocalInspectionTool
import com.intellij.codeInspection.ProblemDescriptor
import com.intellij.codeInspection.ProblemHighlightType
import com.intellij.openapi.editor.Document
import com.intellij.openapi.util.TextRange
import com.intellij.psi.PsiDocumentManager
import com.intellij.psi.PsiFile

/**
 * Surfaces the findings held by [AshScanService] in the editor.
 *
 * WHY AN INSPECTION AND NOT AN ANNOTATOR. Both the `annotator` and `externalAnnotator`
 * extension points are registered per language, so covering what ASH scans -- Python,
 * YAML, JSON, Terraform, Dockerfiles, JavaScript, plain text -- would mean enumerating
 * languages and silently missing whatever was left off the list. `localInspection` with
 * no `language` attribute is documented to run for every language, so a finding in a
 * file type nobody thought about still lands. It is also the path the platform test
 * fixtures exercise most directly, which is what makes the IDE-level assertion in
 * AshFindingInspectionIdeTest possible.
 *
 * The severity of each problem comes from the SARIF level of that finding, not from the
 * inspection's own configured severity -- [ProblemHighlightType] is set per problem. An
 * inspection-level severity would flatten error, warning and note into one, which is the
 * downgrade this plugin's whole severity path exists to prevent.
 */
class AshFindingInspection : LocalInspectionTool() {

    override fun getShortName(): String = SHORT_NAME

    /**
     * `runForWholeFile` is false and `checkFile` is used instead of a visitor, because
     * findings arrive keyed by file and line from an external process. There is no PSI
     * element to visit -- the finding may point at whitespace, or at a line in a file
     * with no PSI structure at all.
     */
    override fun checkFile(
        file: PsiFile,
        manager: InspectionManager,
        isOnTheFly: Boolean,
    ): Array<ProblemDescriptor>? {
        val virtualFile = file.virtualFile ?: return null
        val findings = AshScanService.getInstance(file.project).findingsFor(virtualFile.path)
        if (findings.isEmpty()) return null

        val document = PsiDocumentManager.getInstance(file.project).getDocument(file) ?: return null
        val oracle = DocumentLineOracle(document)
        val fileLength = document.textLength

        val descriptors = findings.mapNotNull { finding ->
            val offsets = AshRangeMapper.resolve(finding, oracle) ?: return@mapNotNull null
            // Guard against a range the document cannot host. createProblemDescriptor
            // throws on an out-of-bounds range, and one bad finding must not take down
            // highlighting for the whole file.
            if (offsets.start < 0 || offsets.end > fileLength || offsets.start >= offsets.end) {
                return@mapNotNull null
            }
            manager.createProblemDescriptor(
                file,
                TextRange(offsets.start, offsets.end),
                describe(finding),
                highlightTypeFor(finding.level),
                isOnTheFly,
            )
        }

        return if (descriptors.isEmpty()) null else descriptors.toTypedArray()
    }

    /**
     * The tooltip text.
     *
     * The rule id and the scanner are included because a security finding the user
     * cannot attribute is one they cannot look up or suppress. `(severity inherited from
     * rule)` is appended when the level came from `defaultConfiguration` rather than from
     * the result, so a reader can tell a scanner's own severity from a defaulted one.
     */
    private fun describe(finding: AshFinding): String {
        val attribution = listOfNotNull(finding.scannerName, finding.ruleId).joinToString(" ")
        val prefix = if (attribution.isBlank()) "ASH" else "ASH [$attribution]"
        val inherited = if (finding.levelExplicit) "" else " (severity inherited from rule default)"
        return "$prefix: ${finding.message}$inherited"
    }

    /**
     * Maps a SARIF level to how the IDE renders it.
     *
     * Read from [AshLevel] members, never from a string: the enum is the parsed result,
     * and the only place a level's text form is produced is [AshLevel.sarifValue].
     *
     * `none` maps to INFORMATION for completeness, but [AshSarifParser] drops `none`
     * findings before they reach here, so in practice this arm is unreachable. Kept
     * exhaustive rather than with an `else`, so adding a level to [AshLevel] is a
     * compile error here instead of a silent fall-through to the quietest option.
     */
    private fun highlightTypeFor(level: AshLevel): ProblemHighlightType = when (level) {
        AshLevel.ERROR -> ProblemHighlightType.GENERIC_ERROR
        AshLevel.WARNING -> ProblemHighlightType.WARNING
        AshLevel.NOTE -> ProblemHighlightType.WEAK_WARNING
        AshLevel.NONE -> ProblemHighlightType.INFORMATION
    }

    /** Adapts [Document] to the IDE-free interface [AshRangeMapper] is tested against. */
    private class DocumentLineOracle(private val document: Document) : AshRangeMapper.LineOracle {
        override val lineCount: Int get() = document.lineCount
        override fun lineStartOffset(line: Int): Int = document.getLineStartOffset(line)
        override fun lineEndOffset(line: Int): Int = document.getLineEndOffset(line)
    }

    companion object {
        const val SHORT_NAME: String = "AshFinding"
    }
}
