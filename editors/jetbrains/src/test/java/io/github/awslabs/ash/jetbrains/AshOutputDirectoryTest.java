// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AshOutputDirectoryTest {

    @Test
    @DisplayName("the same project always gets the same directory")
    void isStableForOneProject(@TempDir Path base) {
        Path first = AshOutputDirectory.forProject(Path.of("/work/service"), base);
        Path second = AshOutputDirectory.forProject(Path.of("/work/service"), base);

        // Stability is what stops the temporary directory filling with one tree per scan, and
        // it has to survive an IDE restart, which is why the name is derived rather than
        // randomly generated.
        assertEquals(first, second);
    }

    @Test
    @DisplayName("two checkouts of the same repository get different directories")
    void separatesTwoCheckouts(@TempDir Path base) {
        // A project NAME would collide here, and each scan would then read the other
        // checkout's SARIF -- annotations from the wrong tree, with nothing to indicate it.
        assertNotEquals(
                AshOutputDirectory.forProject(Path.of("/work/a/service"), base),
                AshOutputDirectory.forProject(Path.of("/work/b/service"), base));
    }

    @Test
    @DisplayName("a relative and an absolute path to the same project agree")
    void normalizesThePath(@TempDir Path base) {
        Path direct = AshOutputDirectory.forProject(Path.of("/work/service"), base);
        Path viaParent = AshOutputDirectory.forProject(Path.of("/work/other/../service"), base);
        assertEquals(direct, viaParent);
    }

    @Test
    @DisplayName("the name is recognizable and the digest is the expected length")
    void namesTheDirectoryUsefully(@TempDir Path base) {
        String name = AshOutputDirectory.forProject(Path.of("/work/service"), base).getFileName().toString();

        assertTrue(name.startsWith(AshOutputDirectory.PREFIX), name);
        assertEquals(
                AshOutputDirectory.PREFIX.length() + AshOutputDirectory.NAME_LENGTH, name.length());
        assertTrue(
                name.substring(AshOutputDirectory.PREFIX.length()).matches("[0-9a-f]+"),
                "the suffix must be hex so the directory name is filesystem-safe everywhere: "
                        + name);
    }

    @Test
    @DisplayName("the directory is under the given base and never inside the project")
    void staysOutsideTheProject(@TempDir Path base) {
        Path project = Path.of("/work/service");
        Path output = AshOutputDirectory.forProject(project, base);

        assertTrue(output.startsWith(base));
        // AshScanPlan refuses an output directory inside the source directory; this is the
        // other side of that contract, checked here so the default wiring cannot violate it.
        assertTrue(new AshScanPlan("ash", project, output).command().size() > 0);
    }

    @Test
    @DisplayName("the single-argument form uses the JVM's temporary directory")
    void defaultsToTheTempDirectory() {
        Path output = AshOutputDirectory.forProject(Path.of("/work/service"));
        assertTrue(
                output.startsWith(Path.of(System.getProperty("java.io.tmpdir"))),
                "expected a path under java.io.tmpdir, got " + output);
    }
}
