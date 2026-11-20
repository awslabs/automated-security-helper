// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import com.intellij.codeInsight.daemon.impl.HighlightInfo
import com.intellij.lang.annotation.HighlightSeverity
import com.intellij.testFramework.fixtures.BasePlatformTestCase

/**
 * The assertion this plugin exists to make.
 *
 * A NON-ZERO count of editor highlights, from real ASH SARIF, over a fixture carrying AWS's
 * published example secret access key -- the same value planted by
 * packaging/deb/verify-in-container.sh and by Formula/ash.rb's test block.
 *
 * WHY THE COUNT AND NOT SOMETHING EASIER TO ASSERT. A clean `ash scan` exits 0 and writes a
 * SARIF with zero results. So each of these would pass while the plugin showed an empty editor
 * over a real credential: the process completed, the exit code was 0, a SARIF file appeared,
 * the SARIF parsed. Only the count separates "ASH looked and found nothing" from "the plugin
 * failed to show what ASH found". [testACleanScanProducesNoHighlights] is the other half: it
 * holds the count to ZERO on a real clean scan, so an inspection that highlighted
 * unconditionally would fail rather than make its sibling pass.
 *
 * verify-in-container.sh refuses to run if leak.py stops carrying the planted value, and
 * assert-tests-ran.py refuses a run in which this suite did not report.
 */
class AnnotationCountTest : BasePlatformTestCase() {

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

    private fun read(resource: String): String =
        requireNotNull(javaClass.getResourceAsStream(resource)) { "fixture $resource is not on the test classpath" }
            .use { String(it.readAllBytes(), Charsets.UTF_8) }

    /**
     * Opens leak.py at [editorPath] under the fixture's source root and loads [sarifResource] as
     * the latest scan of that root, which is what ASH's relative `leak.py` URI is relative to.
     */
    private fun scanLeakWith(sarifResource: String, editorPath: String = "leak.py"): List<HighlightInfo> {
        val file = myFixture.addFileToProject(editorPath, read("/fixtures/leak.py"))
        myFixture.configureFromExistingVirtualFile(file.virtualFile)
        // The fixture's source root, which is the same directory for both editor paths.
        val root = file.virtualFile.path.removeSuffix("/$editorPath")
        AshScanService.getInstance(project).update(AshSarifParser.parse(read(sarifResource)), root)
        return myFixture.doHighlighting().filter { it.description?.startsWith("ASH") == true }
    }

    fun testAPlantedSecretProducesANonZeroNumberOfHighlights() {
        val highlights = scanLeakWith("/sarif/ash-detect-secrets.sarif")

        assertFalse(
            "0 highlights from a fixture planted with a secret. A green run that produced nothing " +
                "is the silent pass this test exists to refuse.",
            highlights.isEmpty(),
        )
        assertEquals("one highlight per SARIF result on this file", 3, highlights.size)
    }

    fun testEveryHighlightCoversTheSecretAtErrorSeverityAndNamesTheScanner() {
        val highlights = scanLeakWith("/sarif/ash-detect-secrets.sarif")
        val secret = myFixture.editor.document.text.indexOf("wJalrXUtnFEMI")
        assertTrue("the fixture must still contain the planted value", secret > 0)

        for (info in highlights) {
            // A zero-width range renders as nothing at all.
            assertTrue("empty range: ${info.description}", info.endOffset > info.startOffset)
            assertTrue(
                "[${info.startOffset},${info.endOffset}) does not cover the secret at $secret",
                info.startOffset <= secret && info.endOffset > secret,
            )
            assertEquals("ASH reports these at SARIF level 'error'", HighlightSeverity.ERROR, info.severity)
            assertTrue(
                "the message must name the scanner that spoke: ${info.description}",
                info.description.startsWith("ASH [detect-secrets"),
            )
        }
    }

    fun testACleanScanProducesNoHighlights() {
        assertEquals(
            "a clean scan must produce no highlights; an inspection that invented them would make " +
                "the non-zero assertion pass for the wrong reason",
            0,
            scanLeakWith("/sarif/ash-clean-scan.sarif").size,
        )
    }

    fun testFindingsForAnotherFileDoNotAnnotateThisOne() {
        // The SARIF says leak.py; the editor has vendor/leak.py. A suffix match would put the
        // findings on the wrong file.
        assertEquals(0, scanLeakWith("/sarif/ash-detect-secrets.sarif", editorPath = "vendor/leak.py").size)
    }
}
