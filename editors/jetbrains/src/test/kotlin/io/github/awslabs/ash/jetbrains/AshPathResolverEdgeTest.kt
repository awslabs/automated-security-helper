// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import org.junit.Assert.assertEquals
import org.junit.Test

/** The path keys at the edges AshPathResolverTest does not reach. */
class AshPathResolverEdgeTest {

    private val nothingExists: (String) -> Boolean = { false }

    @Test
    fun aRootThatIsOnlySeparatorsIsNoRoot() {
        for (root in listOf("", "/", "//")) {
            assertEquals(root, "src/a.py", AshPathResolver.toAbsoluteKey("src/a.py", root, nothingExists))
        }
    }

    @Test
    fun anAbsolutePathWithNoRootIsLeftAsWritten() {
        assertEquals("/poetry.lock", AshPathResolver.toAbsoluteKey("/poetry.lock", null, nothingExists))
    }

    @Test
    fun aDriveLetterWithoutASeparatorIsNotAbsolute() {
        // `C:x` is drive-relative on Windows, which no scan root can resolve; it is joined like
        // any relative path rather than mistaken for an absolute one.
        assertEquals("/p/C:x/y", AshPathResolver.toAbsoluteKey("C:x/y", "/p", nothingExists))
        assertEquals("/p/C", AshPathResolver.toAbsoluteKey("C", "/p", nothingExists))
    }

    @Test
    fun parentSegmentsThatClimbPastTheStartAreKept() {
        assertEquals("../../x", AshPathResolver.toAbsoluteKey("../../x", null, nothingExists))
        assertEquals("../y", AshPathResolver.toAbsoluteKey("a/../../y", null, nothingExists))
        assertEquals("/p/b", AshPathResolver.toAbsoluteKey("./a/./../b", "/p", nothingExists))
    }
}
