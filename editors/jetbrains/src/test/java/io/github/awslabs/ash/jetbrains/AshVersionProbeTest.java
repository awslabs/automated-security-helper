// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The MSYS2 {@code ash} collision, exercised without an MSYS2 install or a Windows host.
 *
 * <p>The Almquist shell's output is quoted from what it produced in this project's own CI --
 * {@code Illegal option --} -- rather than invented, because the point of the check is that
 * this exact case does not render as a clean file.
 */
class AshVersionProbeTest {

    /** What a real {@code ash --version} prints. Measured. */
    private static final String REAL_ASH_OUTPUT = "awslabs/automated-security-helper v3.7.0";

    @Test
    @DisplayName("real ASH output is accepted and its version line is reported")
    void acceptsRealAsh() {
        AshVersionProbe.Result result =
                AshVersionProbe.classify("ash", outcome(0, REAL_ASH_OUTPUT, ""));

        assertEquals(AshVersionProbe.Verdict.IS_ASH, result.verdict());
        assertTrue(result.usable());
        assertEquals(REAL_ASH_OUTPUT, result.version());
        assertEquals("", result.message());
    }

    @Test
    @DisplayName("the marker is found on stderr too")
    void acceptsAshOnStderr() {
        // Not hypothetical: a deprecation warning goes to stderr, and a future ASH could send
        // the version there as well. Requiring stdout would reject a working install.
        assertTrue(AshVersionProbe.classify("ash", outcome(0, "", REAL_ASH_OUTPUT)).usable());
    }

    @Test
    @DisplayName("the version line is extracted from surrounding noise")
    void extractsTheVersionLineOnly() {
        AshVersionProbe.Result result =
                AshVersionProbe.classify(
                        "ashv3",
                        outcome(
                                0,
                                "WARNING: ashv3 is deprecated\n  " + REAL_ASH_OUTPUT + "  \nbye",
                                ""));
        assertEquals(REAL_ASH_OUTPUT, result.version());
    }

    @Test
    @DisplayName("MSYS2's Almquist shell is rejected, and the advice names the escape hatch")
    void rejectsTheAlmquistShell() {
        // The exact message this collision produced in CI.
        AshVersionProbe.Result result =
                AshVersionProbe.classify("ash", outcome(2, "", "ash: 0: Illegal option --"));

        assertEquals(AshVersionProbe.Verdict.NOT_ASH, result.verdict());
        assertFalse(
                result.usable(),
                "the wrong binary must not be allowed to scan; it writes no SARIF, and zero"
                        + " findings is what a clean file looks like");
        assertTrue(
                result.message().contains(AshExecutable.UNAMBIGUOUS),
                "the message must name automated-security-helper, which is kept indefinitely for"
                        + " exactly this case: " + result.message());
        assertTrue(
                result.message().contains("MSYS2"),
                "naming the likely cause saves the user working it out: " + result.message());
        assertTrue(result.message().contains("Illegal option"), "quote what it actually printed");
    }

    @Test
    @DisplayName("a shell whose wording is not recognized is still rejected")
    void rejectsAnUnrecognizedShell() {
        // Absence of the marker is what makes the check correct. The list of shell tells only
        // improves the wording, so a shell with a message nobody anticipated must still fail.
        AshVersionProbe.Result result =
                AshVersionProbe.classify("ash", outcome(1, "", "usage: ash [file]"));

        assertEquals(AshVersionProbe.Verdict.NOT_ASH, result.verdict());
        assertFalse(result.message().contains("MSYS2"), "do not guess a cause that was not seen");
        assertTrue(result.message().contains(AshExecutable.UNAMBIGUOUS));
    }

    @Test
    @DisplayName("a program that exits 0 without the marker is rejected")
    void rejectsAnotherToolThatExitsZero() {
        // An exit code cannot separate ASH from any other program that answers --version, and
        // there are many. This is why the test is a string in ASH's own output.
        AshVersionProbe.Result result =
                AshVersionProbe.classify("ash", outcome(0, "ash 0.5.11-1ubuntu1", ""));
        assertEquals(AshVersionProbe.Verdict.NOT_ASH, result.verdict());
    }

    @Test
    @DisplayName("a program that says nothing at all is rejected")
    void rejectsSilence() {
        AshVersionProbe.Result result = AshVersionProbe.classify("ash", outcome(0, "", ""));
        assertEquals(AshVersionProbe.Verdict.NOT_ASH, result.verdict());
        assertFalse(
                result.message().endsWith("It printed: "),
                "do not append an empty quote when there was no output: " + result.message());
    }

    @Test
    @DisplayName("a probe that hung is a timeout, not a wrong binary")
    void reportsATimeout() {
        AshVersionProbe.Result result =
                AshVersionProbe.classify(
                        "ash", new AshProcess.Outcome(
                                AshProcess.Outcome.TIMED_OUT_EXIT_CODE, "", "", true));

        assertEquals(AshVersionProbe.Verdict.TIMED_OUT, result.verdict());
        assertFalse(result.usable());
        assertTrue(
                result.message().contains(String.valueOf(AshProcess.PROBE_TIMEOUT.toSeconds())),
                "say how long it waited: " + result.message());
        assertTrue(result.message().contains("no scan was run"));
    }

    @Test
    @DisplayName("a program that could not start points at the settings page and at PATH")
    void reportsNotFound() {
        AshVersionProbe.Result result =
                AshVersionProbe.notFound("ash", "error=2, No such file or directory");

        assertEquals(AshVersionProbe.Verdict.NOT_FOUND, result.verdict());
        assertFalse(result.usable());
        assertTrue(result.message().contains("No such file or directory"));
        assertTrue(
                result.message().contains("PATH"),
                "an IDE from a desktop launcher does not inherit the shell's PATH, which is the"
                        + " most likely first report: " + result.message());
        assertTrue(result.message().contains("Settings | Tools | ASH"));
    }

    private static AshProcess.Outcome outcome(int exitCode, String stdout, String stderr) {
        return new AshProcess.Outcome(exitCode, stdout, stderr, false);
    }
}
