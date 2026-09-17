// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class AshSeverityTest {

    @ParameterizedTest
    @DisplayName("maps the four levels SARIF defines")
    @CsvSource({
        "error,ERROR",
        "warning,WARNING",
        "note,WEAK_WARNING",
        "none,INFORMATION",
        // Case and surrounding whitespace are normalized: SARIF says lowercase, and a
        // scanner that wrote "Error" would otherwise be silently downgraded to a warning.
        "ERROR,ERROR",
        "  Note  ,WEAK_WARNING",
    })
    void mapsKnownLevels(String level, AshSeverity expected) {
        assertEquals(expected, AshSeverity.fromSarifLevel(level));
        assertTrue(AshSeverity.isKnownSarifLevel(level));
    }

    @ParameterizedTest
    @DisplayName("an unknown level is reported as a warning, never dropped")
    @ValueSource(strings = {"", "   ", "critical", "high", "info", "fatal", "SEV2"})
    void unknownLevelsBecomeWarnings(String level) {
        // Dropping the finding would mean a result that exists in the SARIF and nowhere in
        // the editor, which is the silent-clean-file failure in a smaller form.
        assertEquals(AshSeverity.WARNING, AshSeverity.fromSarifLevel(level));
        assertFalse(AshSeverity.isKnownSarifLevel(level));
    }

    @Test
    @DisplayName("a null level is a warning and is not a known level")
    void nullLevel() {
        assertEquals(AshSeverity.WARNING, AshSeverity.fromSarifLevel(null));
        assertFalse(AshSeverity.isKnownSarifLevel(null));
    }

    @Test
    @DisplayName("none is shown rather than hidden")
    void noneIsStillShown() {
        // SARIF's "none" means the scanner expressed no severity, not that the finding is
        // uninteresting -- ASH's own severity threshold already decided what reached the
        // SARIF at all, so anything here is above it.
        assertEquals(AshSeverity.INFORMATION, AshSeverity.fromSarifLevel("none"));
    }
}
