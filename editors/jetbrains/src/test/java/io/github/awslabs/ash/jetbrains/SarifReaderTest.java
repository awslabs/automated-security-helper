// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** What the reader makes of real ASH output, and of the shapes real output does not have. */
class SarifReaderTest {

    @Test
    @DisplayName("reads real ASH output exactly as ASH wrote it")
    void readsRealAshOutput() {
        SarifReader read = SarifReader.read(Fixtures.read(Fixtures.SARIF_WITH_FINDINGS));
        List<AshFinding> findings = read.findings();

        assertEquals(Fixtures.EXPECTED_FINDINGS, findings.size());
        assertEquals(0, read.skippedWithoutLocation());

        AshFinding first = findings.get(0);
        assertEquals("SECRET-AWS-ACCESS-KEY", first.ruleId());
        assertEquals("error", first.level());
        assertEquals(Fixtures.LEAK_URI, first.uri());
        assertEquals(2, first.startLine());
        assertEquals(2, first.endLine());
        assertEquals("detect-secrets", first.scannerName());
        assertTrue(first.message().contains("AWS Access Key"));

        // The measured shape, asserted so a future change to ASH's SARIF that adds columns
        // shows up here rather than as silently different highlight ranges.
        assertFalse(
                first.hasStartColumn(),
                "ASH's detect-secrets regions carry no startColumn; if that changes, the"
                        + " planner's whole-line fallback stops being what runs");
        assertFalse(first.hasEndColumn());

        assertEquals(
                List.of(
                        "SECRET-AWS-ACCESS-KEY",
                        "SECRET-BASE64-HIGH-ENTROPY-STRING",
                        "SECRET-SECRET-KEYWORD"),
                findings.stream().map(AshFinding::ruleId).toList(),
                "document order must be preserved, so annotations are stable between runs");
    }

    @Test
    @DisplayName("a real clean scan yields no findings and nothing skipped")
    void readsCleanOutput() {
        SarifReader read = SarifReader.read(Fixtures.read(Fixtures.SARIF_CLEAN));
        assertEquals(0, read.findings().size());
        assertEquals(0, read.skippedWithoutLocation());
    }

    @Test
    @DisplayName("collapses ASH's -1 sentinels to absent rather than treating them as columns")
    void treatsNegativeColumnsAsAbsent() {
        // charOffset: -1 and index: -1 are what ASH actually writes for "unknown". A reader
        // that took -1 as a value would place every annotation before the start of the file.
        AshFinding finding =
                only(
                        "{\"runs\":[{\"results\":[{\"ruleId\":\"R\",\"level\":\"warning\","
                                + "\"message\":{\"text\":\"m\"},\"locations\":[{\"physicalLocation\":"
                                + "{\"artifactLocation\":{\"uri\":\"a.py\",\"index\":-1},"
                                + "\"region\":{\"startLine\":3,\"endLine\":3,\"startColumn\":-1,"
                                + "\"endColumn\":-1,\"charOffset\":-1}}}]}]}]}");
        assertEquals(AshFinding.ABSENT, finding.startColumn());
        assertEquals(AshFinding.ABSENT, finding.endColumn());
        assertFalse(finding.hasStartColumn());
    }

    @Test
    @DisplayName("keeps real columns when SARIF supplies them")
    void keepsRealColumns() {
        AshFinding finding =
                only(
                        "{\"runs\":[{\"results\":[{\"ruleId\":\"R\",\"message\":{\"text\":\"m\"},"
                                + "\"locations\":[{\"physicalLocation\":{\"artifactLocation\":"
                                + "{\"uri\":\"a.py\"},\"region\":{\"startLine\":1,\"startColumn\":5,"
                                + "\"endColumn\":9}}}]}]}]}");
        assertEquals(5, finding.startColumn());
        assertEquals(9, finding.endColumn());
        assertTrue(finding.hasEndColumn());
    }

    @Test
    @DisplayName("defaults endLine to startLine, and refuses an endLine before it")
    void normalizesEndLine() {
        assertEquals(7, only(region("{\"startLine\":7}")).endLine());
        assertEquals(
                7,
                only(region("{\"startLine\":7,\"endLine\":2}")).endLine(),
                "an endLine before startLine would make every range empty");
        assertEquals(9, only(region("{\"startLine\":7,\"endLine\":9}")).endLine());
    }

    @Test
    @DisplayName("drops results with no line-bearing location and counts them")
    void countsResultsWithoutLocations() {
        // Real ASH behavior for scanners that report about a repository or a dependency graph
        // rather than about a place in a file. Placing them at line 1 would attach a security
        // warning to unrelated code, and the user could not tell it apart from a real one.
        SarifReader read =
                SarifReader.read(
                        "{\"runs\":[{\"results\":["
                                + "{\"ruleId\":\"A\",\"locations\":[]},"
                                + "{\"ruleId\":\"B\"},"
                                + "{\"ruleId\":\"C\",\"locations\":[{\"physicalLocation\":"
                                + "{\"artifactLocation\":{\"uri\":\"\"}}}]},"
                                + "{\"ruleId\":\"D\",\"locations\":[{\"physicalLocation\":"
                                + "{\"artifactLocation\":{\"uri\":\"a.py\"},\"region\":{}}}]},"
                                + "{\"ruleId\":\"E\",\"locations\":[{\"physicalLocation\":"
                                + "{\"artifactLocation\":{\"uri\":\"a.py\"},"
                                + "\"region\":{\"startLine\":0}}}]},"
                                + "{\"ruleId\":\"F\",\"locations\":[{\"physicalLocation\":"
                                + "{\"artifactLocation\":{\"uri\":\"a.py\"},"
                                + "\"region\":{\"startLine\":4}}}]}"
                                + "]}]}");
        assertEquals(List.of("F"), read.findings().stream().map(AshFinding::ruleId).toList());
        assertEquals(
                5,
                read.skippedWithoutLocation(),
                "the count must be reportable, so '0 annotations' can be explained");
    }

    @Test
    @DisplayName("substitutes placeholders for an absent ruleId and message")
    void substitutesPlaceholders() {
        AshFinding finding =
                only(
                        "{\"runs\":[{\"results\":[{\"locations\":[{\"physicalLocation\":"
                                + "{\"artifactLocation\":{\"uri\":\"a.py\"},"
                                + "\"region\":{\"startLine\":1}}}]}]}]}");
        assertEquals(SarifReader.UNKNOWN_RULE_ID, finding.ruleId());
        assertEquals(SarifReader.NO_MESSAGE, finding.message());
        assertEquals("", finding.level(), "an absent level is empty here and mapped later");
        assertEquals("", finding.scannerName());
    }

    @Test
    @DisplayName("reads results from every run, not only the first")
    void readsAllRuns() {
        SarifReader read =
                SarifReader.read(
                        "{\"runs\":["
                                + "{\"results\":[{\"ruleId\":\"one\",\"locations\":[{\"physicalLocation\":"
                                + "{\"artifactLocation\":{\"uri\":\"a.py\"},\"region\":{\"startLine\":1}}}]}]},"
                                + "{\"results\":[{\"ruleId\":\"two\",\"locations\":[{\"physicalLocation\":"
                                + "{\"artifactLocation\":{\"uri\":\"b.py\"},\"region\":{\"startLine\":1}}}]}]}"
                                + "]}");
        assertEquals(List.of("one", "two"), read.findings().stream().map(AshFinding::ruleId).toList());
    }

    @Test
    @DisplayName("a document with no runs is empty, not an error")
    void toleratesMissingRuns() {
        assertEquals(0, SarifReader.read("{}").findings().size());
        assertEquals(0, SarifReader.read("{\"runs\":[]}").findings().size());
        assertEquals(0, SarifReader.read("{\"runs\":[{}]}").findings().size());
        assertEquals(0, SarifReader.read("{\"runs\":\"not an array\"}").findings().size());
    }

    @Test
    @DisplayName("malformed SARIF throws rather than reading as a clean scan")
    void malformedSarifThrows() {
        // The distinction the whole plugin turns on. An unreadable SARIF and a clean SARIF
        // must not produce the same result, because one of them means a real finding may be
        // hidden.
        assertThrows(Json.SyntaxException.class, () -> SarifReader.read("{\"runs\": ["));
        assertThrows(Json.SyntaxException.class, () -> SarifReader.read(""));
    }

    @Test
    @DisplayName("the findings list cannot be modified by a caller")
    void findingsAreImmutable() {
        List<AshFinding> findings =
                SarifReader.read(Fixtures.read(Fixtures.SARIF_WITH_FINDINGS)).findings();
        assertThrows(UnsupportedOperationException.class, findings::clear);
    }

    private static String region(String regionJson) {
        return "{\"runs\":[{\"results\":[{\"ruleId\":\"R\",\"message\":{\"text\":\"m\"},"
                + "\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":\"a.py\"},"
                + "\"region\":"
                + regionJson
                + "}}]}]}]}";
    }

    private static AshFinding only(String sarif) {
        List<AshFinding> findings = SarifReader.read(sarif).findings();
        assertEquals(1, findings.size(), "this helper expects exactly one readable result");
        return findings.get(0);
    }
}
