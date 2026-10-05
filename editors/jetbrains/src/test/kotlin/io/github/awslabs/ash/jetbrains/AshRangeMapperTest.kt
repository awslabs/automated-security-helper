// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Tests for the 1-based SARIF to 0-based document conversion.
 *
 * The fake [AshRangeMapper.LineOracle] is built from real text, so the offsets it reports
 * are the ones a `Document` over the same text would report. That is what makes these
 * tests about the arithmetic rather than about the fake.
 */
class AshRangeMapperTest {

    /** A LineOracle over [text], with the same 0-based contract as `Document`. */
    private class TextOracle(text: String) : AshRangeMapper.LineOracle {
        private val starts = mutableListOf(0)
        private val ends = mutableListOf<Int>()

        init {
            var i = 0
            while (i < text.length) {
                if (text[i] == '\n') {
                    ends.add(i)
                    starts.add(i + 1)
                }
                i++
            }
            ends.add(text.length)
        }

        override val lineCount: Int get() = starts.size
        override fun lineStartOffset(line: Int): Int = starts[line]
        override fun lineEndOffset(line: Int): Int = ends[line]
    }

    //          offsets: 0123456789
    private val text = "alpha\nbravo\ncharlie\n"
    //  line 1 (doc 0) "alpha"   offsets 0..5
    //  line 2 (doc 1) "bravo"   offsets 6..11
    //  line 3 (doc 2) "charlie" offsets 12..19
    private val oracle = TextOracle(text)

    private fun finding(
        startLine: Int,
        startColumn: Int = 1,
        endLine: Int = startLine,
        endColumn: Int? = null,
    ) = AshFinding(
        filePath = "x",
        startLine = startLine,
        startColumn = startColumn,
        endLine = endLine,
        endColumn = endColumn,
        level = AshLevel.ERROR,
        levelExplicit = true,
        ruleId = "R",
        message = "m",
        scannerName = "s",
    )

    @Test
    fun sarifLineOneIsDocumentLineZero() {
        // The off-by-one, asserted at the boundary that matters most: a finding on SARIF
        // line 1 must highlight "alpha" at offsets 0..5, not "bravo" at 6..11.
        assertEquals(AshRangeMapper.Offsets(0, 5), AshRangeMapper.resolve(finding(1), oracle))
        assertEquals(AshRangeMapper.Offsets(6, 11), AshRangeMapper.resolve(finding(2), oracle))
        assertEquals(AshRangeMapper.Offsets(12, 19), AshRangeMapper.resolve(finding(3), oracle))
    }

    @Test
    fun sarifColumnOneIsTheFirstCharacter() {
        // startColumn 1 -> offset lineStart + 0.
        assertEquals(6, AshRangeMapper.resolve(finding(2, startColumn = 1), oracle)!!.start)
        // startColumn 3 -> offset lineStart + 2, i.e. the 'a' in "bravo".
        assertEquals(8, AshRangeMapper.resolve(finding(2, startColumn = 3), oracle)!!.start)
    }

    @Test
    fun endColumnIsExclusive() {
        // Section 3.30.8 defines endColumn as "one greater than the column number of the
        // last character in the region", so columns 1..3 on "bravo" cover "br" -- offsets
        // 6..8 -- and NOT "bra". An inclusive reading would over-highlight by one
        // character on every region a scanner reports.
        assertEquals(
            AshRangeMapper.Offsets(6, 8),
            AshRangeMapper.resolve(finding(2, startColumn = 1, endColumn = 3), oracle),
        )
    }

    @Test
    fun absentEndColumnHighlightsToEndOfLine() {
        // The spec's default for an absent endColumn resolves against the file, which is
        // the reason AshFinding keeps it null instead of guessing.
        assertEquals(
            AshRangeMapper.Offsets(6, 11),
            AshRangeMapper.resolve(finding(2, endColumn = null), oracle),
        )
    }

    @Test
    fun multiLineRegionSpansFromStartLineToEndLine() {
        // Lines 1..2, columns 3..3: from 'p' in "alpha" (offset 2) to before 'b' in
        // "bravo" (offset 6+2 = 8).
        assertEquals(
            AshRangeMapper.Offsets(2, 8),
            AshRangeMapper.resolve(finding(1, startColumn = 3, endLine = 2, endColumn = 3), oracle),
        )
    }

    @Test
    fun startLinePastEndOfDocumentIsRejectedNotClamped() {
        // A finding about a line the open file does not have is a finding about a
        // different revision. Putting it on the last line would assert something false
        // about code the user is reading.
        //
        // Deliberately measured against text WITHOUT a trailing newline, so line 4 is
        // genuinely absent. Against the newline-terminated `oracle`, line 4 is the real
        // empty final line -- `Document` counts it -- so this would return null for being
        // empty rather than for being out of range, and would pass while testing nothing
        // the name claims.
        val threeLines = TextOracle("alpha\nbravo\ncharlie")
        assertEquals(3, threeLines.lineCount)
        assertNull(AshRangeMapper.resolve(finding(4), threeLines))
        assertNull(AshRangeMapper.resolve(finding(99), threeLines))
        // The positive control: line 3 of the same oracle IS in range, so the two nulls
        // above are about the bound and not about the fake being broken.
        assertEquals(AshRangeMapper.Offsets(12, 19), AshRangeMapper.resolve(finding(3), threeLines))
    }

    @Test
    fun startLineZeroOrNegativeIsRejected() {
        // SARIF says startLine is a positive integer; 0 would convert to document line -1.
        assertNull(AshRangeMapper.resolve(finding(0), oracle))
        assertNull(AshRangeMapper.resolve(finding(-1), oracle))
    }

    @Test
    fun endLinePastEndOfDocumentIsTruncatedSoTheFindingSurvives() {
        // Unlike startLine, an over-long endLine still has a real place to put the
        // annotation, so it is truncated rather than dropped.
        assertEquals(
            AshRangeMapper.Offsets(12, 19),
            AshRangeMapper.resolve(finding(3, endLine = 40), oracle),
        )
    }

    @Test
    fun columnPastEndOfLineIsClampedToThatLine() {
        // A column past the end of a line -- what a scanner reporting against a different
        // revision produces -- must not spill the highlight into the following line.
        val resolved = AshRangeMapper.resolve(finding(2, startColumn = 80, endColumn = 200), oracle)!!
        assertEquals(11, resolved.end)
        // Degenerate after clamping, so it falls back to the whole line rather than
        // rendering an invisible zero-width annotation.
        assertEquals(6, resolved.start)
    }

    @Test
    fun invertedColumnsFallBackToTheWholeLine() {
        assertEquals(
            AshRangeMapper.Offsets(6, 11),
            AshRangeMapper.resolve(finding(2, startColumn = 4, endColumn = 2), oracle),
        )
    }

    @Test
    fun emptyLineYieldsNoRange() {
        // Nothing to underline, and a zero-width annotation would be invisible -- so this
        // returns null rather than a range that renders as nothing.
        val blank = TextOracle("alpha\n\ncharlie\n")
        assertNull(AshRangeMapper.resolve(finding(2), blank))
    }

    @Test
    fun lastLineWithoutTrailingNewlineIsUsable() {
        val noTrailing = TextOracle("alpha\nbravo")
        assertEquals(AshRangeMapper.Offsets(6, 11), AshRangeMapper.resolve(finding(2), noTrailing))
    }
}
