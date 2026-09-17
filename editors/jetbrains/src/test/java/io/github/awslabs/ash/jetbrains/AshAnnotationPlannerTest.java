// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Offsets, ranges, and the cases where a finding cannot be placed.
 *
 * <p>The off-by-one errors here are the ones a screenshot cannot show. A range shifted by the
 * number of preceding lines looks like a plugin that works on small files; an endColumn treated
 * as inclusive underlines one character too many on every finding in the repository.
 */
class AshAnnotationPlannerTest {

    @Test
    @DisplayName("a whole-line finding covers the line's text and not its indentation")
    void widensToTheLineWithoutIndentation() {
        String text = "first\n    SECRET = 1\nthird\n";
        List<AshAnnotationPlanner.PlannedAnnotation> planned =
                plan(text, finding(2, 2, AshFinding.ABSENT, AshFinding.ABSENT));

        assertEquals(1, planned.size());
        assertEquals(text.indexOf("SECRET"), planned.get(0).startOffset());
        assertEquals(text.indexOf("\nthird"), planned.get(0).endOffset());
    }

    @Test
    @DisplayName("columns are 1-based and endColumn is exclusive")
    void honorsExclusiveEndColumn() {
        String text = "abcdefgh\n";
        // startColumn 3, endColumn 6 means characters 3, 4 and 5 -- offsets 2 to 5.
        List<AshAnnotationPlanner.PlannedAnnotation> planned = plan(text, finding(1, 1, 3, 6));

        assertEquals(2, planned.get(0).startOffset());
        assertEquals(5, planned.get(0).endOffset());
    }

    @Test
    @DisplayName("CRLF line endings do not shift the offsets")
    void handlesCrlf() {
        // A SARIF column counts characters from the start of the line, and a CRLF document has
        // one extra character per preceding line. Getting this wrong shifts every annotation in
        // the file by the number of lines above it.
        String text = "one\r\ntwo\r\nSECRET\r\n";
        List<AshAnnotationPlanner.PlannedAnnotation> planned =
                plan(text, finding(3, 3, AshFinding.ABSENT, AshFinding.ABSENT));

        assertEquals(text.indexOf("SECRET"), planned.get(0).startOffset());
        assertEquals(text.indexOf("SECRET") + "SECRET".length(), planned.get(0).endOffset());
    }

    @Test
    @DisplayName("a lone CR is treated as a line ending")
    void handlesLoneCr() {
        String text = "one\rtwo\rSECRET\r";
        List<AshAnnotationPlanner.PlannedAnnotation> planned =
                plan(text, finding(3, 3, AshFinding.ABSENT, AshFinding.ABSENT));
        assertEquals(text.indexOf("SECRET"), planned.get(0).startOffset());
    }

    @Test
    @DisplayName("a multi-line finding spans from its first line to the end of its last")
    void spansMultipleLines() {
        String text = "one\ntwo\nthree\nfour\n";
        List<AshAnnotationPlanner.PlannedAnnotation> planned =
                plan(text, finding(2, 3, AshFinding.ABSENT, AshFinding.ABSENT));

        assertEquals(text.indexOf("two"), planned.get(0).startOffset());
        assertEquals(text.indexOf("three") + "three".length(), planned.get(0).endOffset());
    }

    @Test
    @DisplayName("a finding past the end of the document is dropped, not clamped")
    void dropsAFindingPastTheEnd() {
        // The user edited the file after the scan and the line is gone. Clamping to the last
        // line would move a security warning onto unrelated code, and the next scan will place
        // it correctly anyway.
        assertEquals(
                0,
                plan("only one line\n", finding(99, 99, AshFinding.ABSENT, AshFinding.ABSENT)).size());
    }

    @Test
    @DisplayName("an endLine past the end is clamped rather than dropping the finding")
    void clampsAnEndLinePastTheEnd() {
        String text = "one\ntwo\n";
        List<AshAnnotationPlanner.PlannedAnnotation> planned =
                plan(text, finding(1, 99, AshFinding.ABSENT, AshFinding.ABSENT));
        assertEquals(1, planned.size());
        assertTrue(planned.get(0).endOffset() <= text.length());
    }

    @Test
    @DisplayName("a blank line still produces a visible range")
    void widensAnEmptyRange() {
        // A zero-width range draws nothing, so a finding on a blank line would be counted and
        // invisible.
        String text = "one\n\nthree\n";
        List<AshAnnotationPlanner.PlannedAnnotation> planned =
                plan(text, finding(2, 2, AshFinding.ABSENT, AshFinding.ABSENT));

        assertEquals(1, planned.size());
        assertTrue(planned.get(0).endOffset() > planned.get(0).startOffset());
    }

    @Test
    @DisplayName("a collapsed column pair widens to the line")
    void widensACollapsedColumnPair() {
        String text = "abcdef\n";
        List<AshAnnotationPlanner.PlannedAnnotation> planned = plan(text, finding(1, 1, 4, 4));
        assertTrue(planned.get(0).endOffset() > planned.get(0).startOffset());
    }

    @Test
    @DisplayName("a column past the end of the line is clamped to the line's end")
    void clampsAColumnPastTheLine() {
        String text = "abc\ndefghij\n";
        List<AshAnnotationPlanner.PlannedAnnotation> planned = plan(text, finding(1, 1, 1, 99));
        assertEquals(0, planned.get(0).startOffset());
        assertEquals(3, planned.get(0).endOffset(), "must not run past the newline into line 2");
    }

    @Test
    @DisplayName("an all-whitespace line anchors at the line start")
    void handlesAnAllWhitespaceLine() {
        String text = "one\n    \nthree\n";
        List<AshAnnotationPlanner.PlannedAnnotation> planned =
                plan(text, finding(2, 2, AshFinding.ABSENT, AshFinding.ABSENT));
        assertEquals(text.indexOf("    "), planned.get(0).startOffset());
        assertTrue(planned.get(0).endOffset() > planned.get(0).startOffset());
    }

    @Test
    @DisplayName("a file with no trailing newline is handled")
    void handlesNoTrailingNewline() {
        String text = "one\ntwo";
        List<AshAnnotationPlanner.PlannedAnnotation> planned =
                plan(text, finding(2, 2, AshFinding.ABSENT, AshFinding.ABSENT));
        assertEquals(text.indexOf("two"), planned.get(0).startOffset());
        assertEquals(text.length(), planned.get(0).endOffset());
    }

    @Test
    @DisplayName("an empty document drops every finding rather than producing a range")
    void handlesAnEmptyDocument() {
        assertEquals(0, plan("", finding(2, 2, AshFinding.ABSENT, AshFinding.ABSENT)).size());
    }

    @Test
    @DisplayName("a Windows relative path matches a forward-slash SARIF uri")
    void normalizesSeparators() {
        AshFinding finding =
                new AshFinding(
                        "R", "error", "m", "src/main/leak.py", 1, 1,
                        AshFinding.ABSENT, AshFinding.ABSENT, "detect-secrets");

        assertEquals(
                1,
                AshAnnotationPlanner.plan(List.of(finding), "src\\main\\leak.py", "SECRET\n").size(),
                "a SARIF uri always uses forward slashes and a Windows relative path does not");
        assertEquals("a/b", AshAnnotationPlanner.normalizeSeparators("a\\b"));
        assertEquals("", AshAnnotationPlanner.normalizeSeparators(null));
    }

    @Test
    @DisplayName("a path that is only a suffix of the SARIF uri does not match")
    void refusesASuffixMatch() {
        // A suffix match would attach a finding about src/config.py to vendor/src/config.py,
        // and a security warning on the wrong file is worse than none.
        AshFinding finding =
                new AshFinding(
                        "R", "error", "m", "vendor/src/config.py", 1, 1,
                        AshFinding.ABSENT, AshFinding.ABSENT, "");
        assertEquals(
                0, AshAnnotationPlanner.plan(List.of(finding), "src/config.py", "x\n").size());
    }

    @Test
    @DisplayName("the message names the rule, the scanner, and the tool")
    void describesAFinding() {
        String described =
                AshAnnotationPlanner.describe(
                        new AshFinding(
                                "SECRET-AWS-ACCESS-KEY", "error", "Secret detected", "a.py", 1, 1,
                                AshFinding.ABSENT, AshFinding.ABSENT, "detect-secrets"));

        assertTrue(described.startsWith("ASH SECRET-AWS-ACCESS-KEY (detect-secrets): "), described);
        assertTrue(described.endsWith("Secret detected"), described);
    }

    @Test
    @DisplayName("the message omits an absent scanner name rather than showing empty parentheses")
    void describesAFindingWithNoScanner() {
        String described =
                AshAnnotationPlanner.describe(
                        new AshFinding("R", "error", "m", "a.py", 1, 1,
                                AshFinding.ABSENT, AshFinding.ABSENT, ""));
        assertEquals("ASH R: m", described);
    }

    @Test
    @DisplayName("an unrecognized SARIF level is disclosed in the message")
    void disclosesAGuessedSeverity() {
        // Saying so matters: the severity shown is this plugin's guess, and a reader who can see
        // that will look at the SARIF rather than trust the colour.
        String described =
                AshAnnotationPlanner.describe(
                        new AshFinding("R", "critical", "m", "a.py", 1, 1,
                                AshFinding.ABSENT, AshFinding.ABSENT, ""));
        assertTrue(described.contains("'critical' is not one SARIF defines"), described);
        assertTrue(described.contains("shown as a warning"), described);
    }

    @Test
    @DisplayName("annotations keep the SARIF's order and carry their finding")
    void preservesOrderAndCarriesTheFinding() {
        AshFinding first =
                new AshFinding("A", "error", "m", "a.py", 1, 1,
                        AshFinding.ABSENT, AshFinding.ABSENT, "");
        AshFinding second =
                new AshFinding("B", "note", "m", "a.py", 1, 1,
                        AshFinding.ABSENT, AshFinding.ABSENT, "");

        List<AshAnnotationPlanner.PlannedAnnotation> planned =
                AshAnnotationPlanner.plan(List.of(first, second), "a.py", "x\n");

        assertEquals(List.of("A", "B"), planned.stream().map(p -> p.finding().ruleId()).toList());
        assertEquals(AshSeverity.ERROR, planned.get(0).severity());
        assertEquals(AshSeverity.WEAK_WARNING, planned.get(1).severity());
    }

    @Test
    @DisplayName("a null document text is treated as empty rather than throwing")
    void toleratesNullText() {
        assertEquals(
                0,
                AshAnnotationPlanner.plan(
                                List.of(
                                        new AshFinding("R", "error", "m", "a.py", 1, 1,
                                                AshFinding.ABSENT, AshFinding.ABSENT, "")),
                                "a.py",
                                null)
                        .size());
    }

    private static AshFinding finding(int startLine, int endLine, int startColumn, int endColumn) {
        return new AshFinding(
                "RULE", "error", "message", "a.py", startLine, endLine, startColumn, endColumn, "s");
    }

    private static List<AshAnnotationPlanner.PlannedAnnotation> plan(
            String text, AshFinding finding) {
        return AshAnnotationPlanner.plan(List.of(finding), "a.py", text);
    }
}
