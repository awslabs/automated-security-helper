// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

/**
 * Turns a SARIF region into a character-offset range in a document.
 *
 * THE ONLY PLACE THE 1-BASED TO 0-BASED CONVERSION HAPPENS. SARIF lines and columns
 * are 1-based (sections 3.30.5 and 3.30.6); IntelliJ's `Document` lines and offsets
 * are 0-based. Isolated here, and behind [LineOracle] rather than behind `Document`,
 * so the arithmetic is tested directly on the JVM with no IDE booted. The alternative
 * -- doing the subtraction inline in the annotator -- puts the one piece of logic most
 * likely to be off by one in the one place hardest to test.
 *
 * Every out-of-range input returns null rather than a clamped range. A finding whose
 * line does not exist in the file the IDE has open is a finding about a different
 * version of that file, and putting it on the nearest line that does exist would
 * assert something false about code the user is reading.
 */
object AshRangeMapper {

    /** A document's line geometry, with 0-BASED line numbers, as `Document` exposes it. */
    interface LineOracle {
        val lineCount: Int

        /** Offset of the first character of [line], 0-based line number. */
        fun lineStartOffset(line: Int): Int

        /** Offset just past the last character of [line], excluding the line separator. */
        fun lineEndOffset(line: Int): Int
    }

    /** A half-open character range, `[start, end)`, in document offsets. */
    data class Offsets(val start: Int, val end: Int)

    /**
     * The range to highlight for [finding], or null if the finding does not fit the
     * document.
     *
     * Returning null for a non-empty range that would be empty is deliberate: an
     * annotation over zero characters is invisible, so a region whose columns collapse
     * is widened to the rest of the line rather than silently rendering nothing.
     */
    fun resolve(finding: AshFinding, doc: LineOracle): Offsets? {
        // SARIF line 1 is document line 0.
        val startLine0 = finding.startLine - 1
        val endLine0 = finding.endLine - 1
        if (startLine0 < 0 || startLine0 >= doc.lineCount) return null
        // A region whose end line is past the end of the document is truncated to the
        // last line rather than rejected: the start is in range, so there is a real
        // place to put the annotation, and the alternative loses the finding entirely.
        //
        // Truncated to the last line WITH CONTENT, not simply to lineCount - 1. A document
        // whose text ends in a newline has a final empty line that `Document` counts, so
        // clamping to the last index put the range's end past the last real character and
        // onto the line terminator. The annotation then rendered as a full-width bar
        // running into the following line instead of underlining the code. Backing off
        // over empty trailing lines keeps the highlight on text.
        var clampedEndLine0 = endLine0.coerceIn(startLine0, doc.lineCount - 1)
        while (clampedEndLine0 > startLine0 &&
            doc.lineEndOffset(clampedEndLine0) == doc.lineStartOffset(clampedEndLine0)
        ) {
            clampedEndLine0--
        }

        val startLineStart = doc.lineStartOffset(startLine0)
        val startLineEnd = doc.lineEndOffset(startLine0)
        val endLineStart = doc.lineStartOffset(clampedEndLine0)
        val endLineEnd = doc.lineEndOffset(clampedEndLine0)

        // SARIF column 1 is the first character, so offset = lineStart + (column - 1).
        // Clamped to the line's own end so a column past the end of a line -- which a
        // scanner reporting against a different revision will produce -- highlights to
        // end of line instead of spilling into the next one.
        val start = (startLineStart + (finding.startColumn - 1)).coerceIn(startLineStart, startLineEnd)

        // endColumn is EXCLUSIVE: section 3.30.8 defines it as "one greater than the
        // column number of the last character in the region". So the offset is
        // lineStart + (endColumn - 1), with no further adjustment -- the -1 converts
        // from 1-based to 0-based and the exclusivity is already in the value. Absent
        // endColumn means end of line, which is what the spec's default resolves to and
        // is the only reading that needs the document.
        val end = when (val endColumn = finding.endColumn) {
            null -> endLineEnd
            else -> (endLineStart + (endColumn - 1)).coerceIn(endLineStart, endLineEnd)
        }

        if (end > start) return Offsets(start, end)

        // Degenerate range. Fall back to the whole start line, and only give up if that
        // is empty too -- an annotation on a blank line has nothing to underline.
        if (startLineEnd > startLineStart) return Offsets(startLineStart, startLineEnd)
        return null
    }
}
