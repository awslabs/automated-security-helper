// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class AshScanPlanTest {

    @Test
    @DisplayName("the scan command is the one the packaging verifications run")
    void buildsTheScanCommand(@TempDir Path temp) {
        Path source = temp.resolve("project");
        Path output = temp.resolve("out");
        AshScanPlan plan = new AshScanPlan("ash", source, output);

        assertEquals(
                List.of(
                        "ash",
                        "scan",
                        "--source-dir",
                        source.toString(),
                        "--output-dir",
                        output.toString(),
                        "--no-progress"),
                plan.command());
    }

    @Test
    @DisplayName("--no-progress is passed, so escape sequences do not end up in an error message")
    void passesNoProgress() {
        // ASH renders a progress display when it thinks it has a terminal. There is none here,
        // and the escape sequences would land in the captured stderr, where they are noise in
        // whatever message the user is shown.
        assertTrue(new AshScanPlan("ash", Path.of("/a"), Path.of("/b")).command()
                .contains("--no-progress"));
    }

    @Test
    @DisplayName("the version command uses --version and not -v")
    void buildsTheVersionCommand() {
        // -v is --verbose in ASH and has been for all of v3, so a probe using it would start a
        // verbose scan rather than print a version.
        assertEquals(
                List.of("automated-security-helper", "--version"),
                new AshScanPlan("automated-security-helper", Path.of("/a"), Path.of("/b"))
                        .versionCommand());
    }

    @Test
    @DisplayName("the SARIF path is the aggregate report, not the GHAS or per-scanner one")
    void resolvesTheAggregateSarifPath(@TempDir Path temp) {
        Path output = temp.resolve("out");
        Path sarif = new AshScanPlan("ash", temp.resolve("project"), output).sarifPath();

        // Measured from a real run: reports/ash.sarif sits alongside reports/ash.ghas.sarif and
        // scanners/<name>/source/results_sarif.sarif. The GHAS variant is reshaped for GitHub
        // code scanning and a per-scanner file is one scanner's view, so neither is the one to
        // read.
        assertEquals(output.resolve("reports").resolve("ash.sarif"), sarif);
        assertTrue(sarif.startsWith(output));
    }

    @Test
    @DisplayName("an output directory inside the scanned tree is refused")
    void refusesOutputInsideSource(@TempDir Path temp) {
        Path source = temp.resolve("project");
        // ASH's own default is .ash/ash_output under the source directory, which is right for a
        // command line and wrong here: the IDE indexes the project tree, so a scan's reports
        // become source the next scan reads and reports on. That reads as ASH finding new
        // problems rather than as a configuration mistake, which is why this is loud.
        IllegalArgumentException thrown =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> new AshScanPlan("ash", source, source.resolve(".ash/ash_output")));
        assertTrue(thrown.getMessage().contains("must not be inside"));
    }

    @Test
    @DisplayName("the source directory itself is refused as the output directory")
    void refusesOutputEqualToSource(@TempDir Path temp) {
        assertThrows(
                IllegalArgumentException.class, () -> new AshScanPlan("ash", temp, temp));
    }

    @Test
    @DisplayName("a sibling directory is accepted")
    void acceptsASibling(@TempDir Path temp) {
        AshScanPlan plan =
                new AshScanPlan("ash", temp.resolve("project"), temp.resolve("ash-output"));
        assertFalse(plan.command().isEmpty());
    }

    @ParameterizedTest
    @DisplayName("0 and 2 mean ASH ran; nothing else does")
    @ValueSource(ints = {0, 2})
    void acceptsAshsOwnExitCodes(int exitCode) {
        // 0 is a clean scan and 2 is findings at or above the threshold. Treating non-zero as
        // failure would discard the SARIF in exactly the case where it has findings in it.
        assertTrue(AshScanPlan.isUsableExitCode(exitCode));
    }

    @ParameterizedTest
    @DisplayName("any other exit code means the run produced no result to read")
    @ValueSource(ints = {1, 3, 42, 127, 130, -1, AshProcess.Outcome.TIMED_OUT_EXIT_CODE})
    void rejectsOtherExitCodes(int exitCode) {
        assertFalse(AshScanPlan.isUsableExitCode(exitCode));
    }
}
