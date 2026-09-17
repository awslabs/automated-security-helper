// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The assertion this plugin exists to make.
 *
 * <p>A NON-ZERO count of annotations, from real ASH SARIF, over a fixture carrying AWS's
 * published example secret access key -- the same value planted by
 * {@code packaging/deb/verify-in-container.sh} and by {@code Formula/ash.rb}'s test block.
 *
 * <p>WHY THE COUNT AND NOT SOMETHING EASIER TO ASSERT
 *
 * <p>Measured, on this fixture: a clean {@code ash scan} exits 0 and writes a SARIF with zero
 * results. So each of these would pass while the plugin showed an empty editor over a real
 * credential:
 *
 * <ul>
 *   <li>the process completed
 *   <li>the exit code was 0
 *   <li>a SARIF file appeared
 *   <li>the SARIF parsed
 * </ul>
 *
 * <p>Only the count separates "ASH looked and found nothing" from "the plugin failed to show
 * what ASH found". {@link #anEmptyScanProducesNoAnnotations} is the other half: it holds the
 * count to ZERO on a real clean scan, so a planner that returned annotations unconditionally
 * would fail rather than make its sibling pass.
 */
class AnnotationCountTest {

    @Test
    @DisplayName("a planted AWS secret produces a non-zero number of annotations")
    void aPlantedSecretProducesAnnotations() {
        List<AshFinding> findings =
                SarifReader.read(Fixtures.read(Fixtures.SARIF_WITH_FINDINGS)).findings();
        String leak = Fixtures.read(Fixtures.LEAK_FILE);

        List<AshAnnotationPlanner.PlannedAnnotation> annotations =
                AshAnnotationPlanner.plan(findings, Fixtures.LEAK_URI, leak);

        assertFalse(
                annotations.isEmpty(),
                "0 annotations from a fixture planted with a secret. A green run that produced"
                        + " nothing is the silent pass this whole branch removes: ASH's own scan of"
                        + " a clean tree exits 0 with an empty SARIF, so 'it ran' proves nothing.");
        assertEquals(
                Fixtures.EXPECTED_FINDINGS,
                annotations.size(),
                "expected one annotation per SARIF result on this file");
    }

    @Test
    @DisplayName("every annotation lands on the line the secret is on, with a non-empty range")
    void annotationsCoverTheSecret() {
        List<AshFinding> findings =
                SarifReader.read(Fixtures.read(Fixtures.SARIF_WITH_FINDINGS)).findings();
        String leak = Fixtures.read(Fixtures.LEAK_FILE);
        int secretOffset = leak.indexOf("wJalrXUtnFEMI");
        assertTrue(secretOffset > 0, "the fixture must still contain the planted value");

        List<AshAnnotationPlanner.PlannedAnnotation> annotations =
                AshAnnotationPlanner.plan(findings, Fixtures.LEAK_URI, leak);

        for (AshAnnotationPlanner.PlannedAnnotation annotation : annotations) {
            // A zero-width range renders as nothing at all, so a plugin could report the
            // right number of findings and show the user none of them.
            assertTrue(
                    annotation.endOffset() > annotation.startOffset(),
                    annotation.finding().ruleId() + " planned an empty range");
            assertTrue(
                    annotation.startOffset() <= secretOffset
                            && annotation.endOffset() >= secretOffset,
                    annotation.finding().ruleId()
                            + " planned ["
                            + annotation.startOffset()
                            + ","
                            + annotation.endOffset()
                            + ") which does not cover the secret at offset "
                            + secretOffset);
            assertEquals(
                    AshSeverity.ERROR,
                    annotation.severity(),
                    "ASH reports these at SARIF level 'error'");
            assertTrue(
                    annotation.message().startsWith("ASH "),
                    "the message must name the tool so a user can tell it from another linter");
            assertTrue(
                    annotation.message().contains("detect-secrets"),
                    "the message must name the scanner that spoke");
        }
    }

    @Test
    @DisplayName("a real clean scan produces exactly zero annotations")
    void anEmptyScanProducesNoAnnotations() {
        SarifReader read = SarifReader.read(Fixtures.read(Fixtures.SARIF_CLEAN));
        assertTrue(read.findings().isEmpty(), "the clean fixture must have no results");

        // Planned against the leaky file's own text, so the only reason the count is zero is
        // that the SARIF had nothing in it -- not that the document or path did not match.
        List<AshAnnotationPlanner.PlannedAnnotation> annotations =
                AshAnnotationPlanner.plan(
                        read.findings(), Fixtures.LEAK_URI, Fixtures.read(Fixtures.LEAK_FILE));

        assertEquals(
                0,
                annotations.size(),
                "a clean scan must produce no annotations; a planner that invented them would"
                        + " make the non-zero assertion above pass for the wrong reason");
    }

    @Test
    @DisplayName("findings for another file do not annotate this one")
    void findingsForAnotherFileAreNotShownHere() {
        List<AshFinding> findings =
                SarifReader.read(Fixtures.read(Fixtures.SARIF_WITH_FINDINGS)).findings();

        List<AshAnnotationPlanner.PlannedAnnotation> annotations =
                AshAnnotationPlanner.plan(
                        findings, "somewhere/else.py", Fixtures.read(Fixtures.LEAK_FILE));

        assertEquals(
                0,
                annotations.size(),
                "a finding must not be attached to a file it is not about; a suffix match would"
                        + " put this on vendor/leak.py too");
    }
}
