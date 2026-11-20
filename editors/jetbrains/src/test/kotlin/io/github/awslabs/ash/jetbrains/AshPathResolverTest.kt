// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Tests that a SARIF path and an IDE path resolve to the same key.
 *
 * If they do not, the lookup in [AshScanService] matches nothing and the scan reports
 * findings that never appear in the editor -- a success with no visible effect, which is
 * indistinguishable from a clean scan.
 */
class AshPathResolverTest {

    @Test
    fun relativeSarifPathJoinsTheProjectRoot() {
        assertEquals(
            "/home/u/proj/src/app.py",
            AshPathResolver.toAbsoluteKey("src/app.py", "/home/u/proj"),
        )
    }

    @Test
    fun trailingSeparatorOnTheRootDoesNotDoubleUp() {
        assertEquals(
            "/home/u/proj/src/app.py",
            AshPathResolver.toAbsoluteKey("src/app.py", "/home/u/proj/"),
        )
    }

    @Test
    fun dotSlashPrefixIsStripped() {
        assertEquals(
            "/home/u/proj/src/app.py",
            AshPathResolver.toAbsoluteKey("./src/app.py", "/home/u/proj"),
        )
    }

    @Test
    fun absolutePathThatExistsIsLeftAlone() {
        // ASH can be pointed at a source dir outside the project, in which case its SARIF
        // carries genuinely absolute paths. Joining those onto the project root would produce
        // nonsense like /home/u/proj/home/u/other/a.py.
        assertEquals(
            "/elsewhere/a.py",
            AshPathResolver.toAbsoluteKey(
                "/elsewhere/a.py",
                "/home/u/proj",
                exists = { it == "/elsewhere/a.py" },
            ),
        )
    }

    @Test
    fun grypeScanRootRelativePathIsJoinedNotTakenAsAbsolute() {
        // grype reports paths relative to the scan root WITH a leading slash. `/poetry.lock` is
        // not a file at the filesystem root; it is poetry.lock in the scanned project. Taking it
        // as absolute produces a key no open file can ever match, so the finding vanishes
        // silently rather than appearing on the wrong file.
        assertEquals(
            "/home/u/proj/poetry.lock",
            AshPathResolver.toAbsoluteKey(
                "/poetry.lock",
                "/home/u/proj",
                exists = { it == "/home/u/proj/poetry.lock" },
            ),
        )
        assertEquals(
            "/home/u/proj/.venv/lib/python3.12/site-packages/jupyterlab/staging/yarn.lock",
            AshPathResolver.toAbsoluteKey(
                "/.venv/lib/python3.12/site-packages/jupyterlab/staging/yarn.lock",
                "/home/u/proj",
                exists = { it.startsWith("/home/u/proj/") },
            ),
        )
    }

    @Test
    fun theAbsoluteLocationWinsWhenBothExist() {
        // Order matters: a path that exists at the absolute location is absolute, even if a
        // same-named file also exists under the project root. Preferring the join would move a
        // correct resolution, which is the one thing the monotonicity property forbids.
        assertEquals(
            "/poetry.lock",
            AshPathResolver.toAbsoluteKey("/poetry.lock", "/home/u/proj", exists = { true }),
        )
    }

    @Test
    fun neitherExistingLeavesBehaviourUnchanged() {
        // The pre-fix result. Asserted so the fix is provably monotone: when nothing exists there
        // is nothing better to return, and the old key is kept rather than a guess substituted.
        assertEquals(
            "/nowhere/a.py",
            AshPathResolver.toAbsoluteKey("/nowhere/a.py", "/home/u/proj", exists = { false }),
        )
    }

    @Test
    fun windowsDrivePathIsNotJoinedOntoTheProjectRoot() {
        // The join arm strips a leading '/', which a drive path does not have, so joining would
        // produce `/home/u/proj/C:/x.tf`. That cannot exist, so step 3 returns the drive path
        // unchanged -- but assert it, because a future edit could make the join unconditional.
        assertEquals(
            "C:/code/a.cs",
            AshPathResolver.toAbsoluteKey("C:/code/a.cs", "/home/u/proj", exists = { false }),
        )
    }

    @Test
    fun windowsDrivePathIsTreatedAsAbsolute() {
        assertEquals("C:/code/a.cs", AshPathResolver.toAbsoluteKey("C:/code/a.cs", "D:/proj"))
    }

    @Test
    fun backslashesFoldToForwardSlashesOnBothSides() {
        // The two sides of the lookup must agree. A Windows IDE reports one separator and a
        // SARIF producer may write the other.
        assertEquals(
            AshPathResolver.toAbsoluteKey("src\\app.py", "C:\\proj"),
            AshPathResolver.toAbsoluteKey("src/app.py", "C:/proj"),
        )
        assertEquals("C:/proj/src/app.py", AshPathResolver.toAbsoluteKey("src\\app.py", "C:\\proj"))
    }

    @Test
    fun dotDotSegmentsAreCollapsed() {
        assertEquals(
            "/home/u/proj/app.py",
            AshPathResolver.toAbsoluteKey("src/../app.py", "/home/u/proj"),
        )
        assertEquals(
            "/home/u/app.py",
            AshPathResolver.toAbsoluteKey("../app.py", "/home/u/proj"),
        )
    }

    @Test
    fun missingProjectRootLeavesThePathRelative() {
        // Better a key that matches nothing than one silently rooted at the process
        // working directory, which would be wherever the IDE was launched from.
        assertEquals("src/app.py", AshPathResolver.toAbsoluteKey("src/app.py", null))
        assertEquals("src/app.py", AshPathResolver.toAbsoluteKey("src/app.py", ""))
    }

    @Test
    fun normalizeIsIdempotentAndSeparatorOnly() {
        assertEquals("a/b/c", AshPathResolver.normalize("a\\b\\c"))
        assertEquals("a/b/c", AshPathResolver.normalize(AshPathResolver.normalize("a\\b/c")))
    }
}
