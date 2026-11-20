// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for the SARIF level value/name distinction.
 *
 * [enumNameIsNotTheSarifValue] is the regression test for the defect class this type
 * exists to prevent, and it is written to FAIL if anyone ever changes the code to read
 * [AshLevel.name] -- which is why it asserts the inequality rather than only asserting
 * the value. A test that only checked `sarifValue == "error"` would still pass in a
 * codebase that had switched to `name`.
 */
class AshLevelTest {

    @Test
    fun enumNameIsNotTheSarifValue() {
        // The trap, stated as an assertion: these two differ for every member, so any
        // code path that reads the member name instead of the value produces a string
        // that matches no SARIF level.
        for (level in AshLevel.entries) {
            assertNotEquals(
                "AshLevel.${level.name}: name and sarifValue must not be conflated",
                level.name,
                level.sarifValue,
            )
        }
        assertEquals("error", AshLevel.ERROR.sarifValue)
        assertEquals("ERROR", AshLevel.ERROR.name)
        // toString() is the member name too, which is why nothing emits it.
        assertEquals("ERROR", AshLevel.ERROR.toString())
    }

    @Test
    fun parsesTheFourSarifLevels() {
        assertEquals(AshLevel.ERROR, AshLevel.fromSarif("error"))
        assertEquals(AshLevel.WARNING, AshLevel.fromSarif("warning"))
        assertEquals(AshLevel.NOTE, AshLevel.fromSarif("note"))
        assertEquals(AshLevel.NONE, AshLevel.fromSarif("none"))
    }

    @Test
    fun parsesAnEnumReprAsItsValue() {
        // The exact string ASH's own history shows leaking into consumers: Level is a
        // (str, Enum) mixin, so str(Level.error) is "Level.error". Read naively it
        // matches no level and the finding is silently downgraded to the default.
        assertEquals(AshLevel.ERROR, AshLevel.fromSarif("Level.error"))
        assertEquals(AshLevel.WARNING, AshLevel.fromSarif("Level.warning"))
        assertEquals(AshLevel.ERROR, AshLevel.fromSarif("SarifLevel.Level.error"))
        assertNull(
            "an enum repr is recovered, so it must not also be reported as unrecognized",
            AshLevel.describeUnrecognized("Level.error"),
        )
    }

    @Test
    fun isCaseAndWhitespaceInsensitive() {
        assertEquals(AshLevel.ERROR, AshLevel.fromSarif("ERROR"))
        assertEquals(AshLevel.ERROR, AshLevel.fromSarif("  Error  "))
    }

    @Test
    fun absentAndBlankAreNull() {
        assertNull(AshLevel.fromSarif(null))
        assertNull(AshLevel.fromSarif(""))
        assertNull(AshLevel.fromSarif("   "))
        // Blank is ABSENT, not unrecognized -- absent must fall through to the rule
        // default, so it must not produce a complaint.
        assertNull(AshLevel.describeUnrecognized(null))
        assertNull(AshLevel.describeUnrecognized("  "))
    }

    @Test
    fun unrecognizedIsReportedRatherThanGuessedAt() {
        assertNull(AshLevel.fromSarif("critical"))
        val described = AshLevel.describeUnrecognized("critical")
        assertTrue(
            "message should name the offending value; was: $described",
            described != null && described.contains("critical"),
        )
    }

    @Test
    fun specDefaultsAreTheOnesTheSpecStates() {
        // SARIF 2.1.0 section 3.27.10: level defaults to "warning" for a fail kind and
        // "none" for any other kind; section 3.27.9: kind itself defaults to "fail".
        assertEquals(AshLevel.WARNING, AshLevel.FAIL_DEFAULT)
        assertEquals(AshLevel.NONE, AshLevel.NON_FAIL_DEFAULT)
        assertEquals("fail", AshLevel.KIND_DEFAULT)
    }
}
