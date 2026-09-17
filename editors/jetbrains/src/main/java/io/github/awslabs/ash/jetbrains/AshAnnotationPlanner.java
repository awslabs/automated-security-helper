// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains;

import java.util.ArrayList;
import java.util.List;

/**
 * Turns findings into the exact ranges and messages the editor will highlight.
 *
 * <p>WHY THE WHOLE MAPPING LIVES HERE AND NOT IN THE ANNOTATOR
 *
 * <p>Everything that can be wrong about an annotation is decided in this class: which
 * findings belong to this file, where in the document each one starts and ends, and what it
 * says. {@link AshExternalAnnotator} then has no decisions left -- it hands a document's text
 * in and writes the results out. That split is what makes the count assertable: a test can
 * plant AWS's published example secret access key in a fixture, feed the SARIF a real
 * {@code ash scan} produced from it, and assert a NON-ZERO number of annotations, without an
 * IDE.
 *
 * <p>That assertion is the point. An ASH scan that finds nothing exits 0, so "the scan ran"
 * and "a SARIF appeared" are both satisfied by a scan that found nothing, and a plugin whose
 * test asserted either would pass while showing the user an empty editor over a real
 * credential. {@code packaging/deb/verify-in-container.sh} makes the same argument about the
 * .deb, and plants the same value.
 *
 * <p>HOW A FINDING IS MATCHED TO A FILE
 *
 * <p>ASH writes {@code artifactLocation.uri} relative to the scanned source directory --
 * measured: {@code "leak.py"} for a file at the root of the scan. So matching is by relative
 * path, computed by the caller, and compared with forward slashes on both sides because a
 * SARIF uri always uses them and a Windows path does not.
 *
 * <p>A suffix match is deliberately NOT used. It would attach a finding about
 * {@code src/config.py} to {@code vendor/src/config.py}, and putting a security warning on
 * the wrong file is worse than putting it on none.
 */
public final class AshAnnotationPlanner {

    private AshAnnotationPlanner() {}

    /**
     * One highlight the editor should draw.
     *
     * @param severity what {@link AshSeverity} made of the SARIF level
     * @param startOffset inclusive character offset into the document
     * @param endOffset exclusive character offset; always greater than {@code startOffset},
     *     because a zero-width range renders as nothing and would be a finding the user
     *     cannot see
     * @param message the text shown on hover
     * @param finding the finding this came from, so a caller can group or filter without
     *     re-parsing
     */
    public record PlannedAnnotation(
            AshSeverity severity,
            int startOffset,
            int endOffset,
            String message,
            AshFinding finding) {}

    /**
     * Plans the annotations for one file.
     *
     * @param findings every finding from the SARIF, for the whole scan
     * @param relativePath this file's path relative to the scanned root, with any separator
     * @param documentText the file's current text, which is what offsets are computed against
     * @return one entry per finding that belongs to this file and fits inside the document,
     *     in the order the SARIF listed them
     */
    public static List<PlannedAnnotation> plan(
            List<AshFinding> findings, String relativePath, String documentText) {
        String wanted = normalizeSeparators(relativePath);
        LineIndex lines = LineIndex.of(documentText);
        List<PlannedAnnotation> planned = new ArrayList<>();
        for (AshFinding finding : findings) {
            if (!wanted.equals(normalizeSeparators(finding.uri()))) {
                continue;
            }
            int[] range = rangeFor(finding, lines);
            if (range == null) {
                continue;
            }
            planned.add(
                    new PlannedAnnotation(
                            AshSeverity.fromSarifLevel(finding.level()),
                            range[0],
                            range[1],
                            describe(finding),
                            finding));
        }
        return planned;
    }

    /**
     * The offsets for one finding, or null when the finding cannot be placed.
     *
     * <p>Null happens when SARIF names a line the document does not have. That is not
     * hypothetical: the user edits the file after the scan, and by the time the annotator
     * runs the line is gone. Dropping it is right -- clamping to the last line would move a
     * warning onto unrelated code, and the next scan will place it correctly.
     */
    private static int[] rangeFor(AshFinding finding, LineIndex lines) {
        if (finding.startLine() > lines.lineCount()) {
            return null;
        }
        int endLine = Math.min(finding.endLine(), lines.lineCount());

        int start;
        if (finding.hasStartColumn()) {
            start = lines.offsetOf(finding.startLine(), finding.startColumn());
        } else {
            // No column in the SARIF, which is what ASH's detect-secrets output actually
            // looks like. Highlight from the first non-whitespace character of the line
            // rather than from column 1, so an indented assignment does not get its leading
            // spaces underlined.
            start = lines.firstNonWhitespaceOffset(finding.startLine());
        }

        int end;
        if (finding.hasEndColumn()) {
            // SARIF's endColumn is exclusive, so it is already an offset past the last
            // character. Getting this wrong by one is invisible in a screenshot and wrong in
            // every range.
            end = lines.offsetOf(endLine, finding.endColumn());
        } else {
            end = lines.endOfLineOffset(endLine);
        }

        if (end <= start) {
            // A blank line, or a column pair that collapsed. Widen to the line so the
            // finding is still visible; an empty range draws nothing.
            start = lines.startOfLineOffset(finding.startLine());
            end = Math.max(lines.endOfLineOffset(endLine), start + 1);
        }
        return new int[] {Math.min(start, lines.textLength()), Math.min(end, lines.textLength())};
    }

    /**
     * The hover text.
     *
     * <p>The rule id leads, because it is what a user searches for and what an ASH
     * suppression in {@code .ash/.ash.yaml} is keyed on. The scanner name is included when
     * ASH supplied one, so a user can tell which of ASH's scanners spoke without opening the
     * SARIF.
     */
    static String describe(AshFinding finding) {
        StringBuilder text = new StringBuilder("ASH ").append(finding.ruleId());
        if (!finding.scannerName().isBlank()) {
            text.append(" (").append(finding.scannerName()).append(")");
        }
        text.append(": ").append(finding.message());
        if (!AshSeverity.isKnownSarifLevel(finding.level())) {
            // Say so rather than silently defaulting. A level SARIF does not define means a
            // scanner ASH gained since this plugin was written, and the reader should know
            // the severity shown is this plugin's guess.
            text.append(" [SARIF level '")
                    .append(finding.level())
                    .append("' is not one SARIF defines; shown as a warning]");
        }
        return text.toString();
    }

    /** Backslashes to forward slashes, so a Windows relative path compares to a SARIF uri. */
    static String normalizeSeparators(String path) {
        return path == null ? "" : path.replace('\\', '/');
    }

    /**
     * Line starts for one document, so a (line, column) pair becomes an offset.
     *
     * <p>Handles LF, CRLF and a lone CR, because a SARIF column counts characters from the
     * start of the line and a document with CRLF endings has an extra character per line
     * before it. Getting that wrong shifts every annotation in the file by the number of
     * preceding lines, which looks like a plugin that works on small files.
     */
    static final class LineIndex {
        private final String text;
        private final int[] lineStarts;

        private LineIndex(String text, int[] lineStarts) {
            this.text = text;
            this.lineStarts = lineStarts;
        }

        static LineIndex of(String text) {
            String safe = text == null ? "" : text;
            List<Integer> starts = new ArrayList<>();
            starts.add(0);
            int i = 0;
            while (i < safe.length()) {
                char c = safe.charAt(i);
                if (c == '\r') {
                    i += (i + 1 < safe.length() && safe.charAt(i + 1) == '\n') ? 2 : 1;
                    starts.add(i);
                } else if (c == '\n') {
                    i++;
                    starts.add(i);
                } else {
                    i++;
                }
            }
            // A trailing newline produces a final empty line start equal to the length. Keep
            // it: SARIF can name that line, and dropping it would make the last real line
            // unreachable by number.
            int[] asArray = new int[starts.size()];
            for (int n = 0; n < starts.size(); n++) {
                asArray[n] = starts.get(n);
            }
            return new LineIndex(safe, asArray);
        }

        int lineCount() {
            return lineStarts.length;
        }

        int textLength() {
            return text.length();
        }

        /** @param line 1-based; clamped into range by the callers above. */
        int startOfLineOffset(int line) {
            return lineStarts[clampLine(line)];
        }

        /** The offset of a 1-based (line, column) pair, clamped to the line's end. */
        int offsetOf(int line, int column) {
            int start = startOfLineOffset(line);
            int end = endOfLineOffset(line);
            int offset = start + Math.max(0, column - 1);
            return Math.min(offset, end);
        }

        /** The offset just past the last character of the line, before its terminator. */
        int endOfLineOffset(int line) {
            int index = clampLine(line);
            int limit = (index + 1 < lineStarts.length) ? lineStarts[index + 1] : text.length();
            int end = limit;
            while (end > lineStarts[index]
                    && (text.charAt(end - 1) == '\n' || text.charAt(end - 1) == '\r')) {
                end--;
            }
            return end;
        }

        int firstNonWhitespaceOffset(int line) {
            int start = startOfLineOffset(line);
            int end = endOfLineOffset(line);
            int at = start;
            while (at < end && Character.isWhitespace(text.charAt(at))) {
                at++;
            }
            // An all-whitespace line has no non-whitespace character; the line start is the
            // only sensible anchor, and rangeFor widens the range from there.
            return at == end ? start : at;
        }

        private int clampLine(int line) {
            int index = line - 1;
            if (index < 0) {
                return 0;
            }
            return Math.min(index, lineStarts.length - 1);
        }
    }
}
