// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class AshExecutableTest {

    @ParameterizedTest
    @DisplayName("an unset, empty or whitespace setting means the canonical entry point")
    @ValueSource(strings = {"", " ", "\t", "\n", "   \t  "})
    void blankMeansDefault(String configured) {
        assertEquals(AshExecutable.DEFAULT, AshExecutable.resolve(configured));
    }

    @Test
    @DisplayName("null means the canonical entry point")
    void nullMeansDefault() {
        assertEquals("ash", AshExecutable.resolve(null));
    }

    @Test
    @DisplayName("surrounding whitespace is stripped from a configured path")
    void stripsWhitespace() {
        // A path pasted from a terminal usually carries a trailing space, and ProcessBuilder
        // would then look for a program whose name ends in one -- reported as "not found",
        // pointing the user at a path that is visibly correct in the settings field.
        assertEquals("/opt/ash/bin/ash", AshExecutable.resolve("  /opt/ash/bin/ash  "));
        assertEquals("C:\\Tools\\ash.exe", AshExecutable.resolve("\tC:\\Tools\\ash.exe\n"));
    }

    @Test
    @DisplayName("a configured value is used as given")
    void usesConfiguredValue() {
        assertEquals(AshExecutable.UNAMBIGUOUS, AshExecutable.resolve(AshExecutable.UNAMBIGUOUS));
        assertEquals("/usr/local/bin/ash", AshExecutable.resolve("/usr/local/bin/ash"));
    }

    @Test
    @DisplayName("the deprecated spelling is recognized so the user can be told")
    void recognizesTheDeprecatedSpelling() {
        assertTrue(AshExecutable.looksDeprecated("ashv3"));
        assertTrue(AshExecutable.looksDeprecated("  ashv3  "));
        assertFalse(AshExecutable.looksDeprecated(""));
        assertFalse(AshExecutable.looksDeprecated("ash"));
        assertFalse(
                AshExecutable.looksDeprecated("/opt/bin/ashv3"),
                "a full path to it is the user's explicit choice and is not second-guessed");
    }

    @Test
    @DisplayName("the deprecation advice names the two supported spellings and not ashv3 as a fix")
    void deprecationAdviceRecommendsTheSupportedNames() {
        String advice = AshExecutable.deprecationAdvice();
        assertTrue(advice.contains(AshExecutable.DEFAULT));
        assertTrue(advice.contains(AshExecutable.UNAMBIGUOUS));
        assertTrue(advice.contains("deprecated"));
        assertTrue(advice.contains("stderr"), "say where the warning appears: " + advice);
    }
}
