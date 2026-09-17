// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The process layer, exercised against a real child process.
 *
 * <p>WHY THE CHILD IS THE JVM'S OWN {@code java}
 *
 * <p>It is the one executable guaranteed to exist wherever these tests run, because they are
 * running on it. A POSIX shell would have made these tests skip on Windows, and a skipped test
 * is a test that cannot fail -- the same silent pass as a suite reporting zero tests.
 */
class AshProcessTest {

    private static final Path JAVA =
            Path.of(System.getProperty("java.home"), "bin", AshProcess.isWindows() ? "java.exe" : "java");

    @Test
    @DisplayName("stdin is redirected from the null device, so a shell cannot hang the IDE")
    void stdinIsClosed() {
        // The single most important line in AshProcess, asserted on the builder because
        // ProcessBuilder reports the redirect it was given. MSYS2's ash, invoked in a way it
        // reads as interactive, READS STDIN: with stdin inherited from the IDE that child
        // never exits and never writes anything, so the annotator waits on a process that is
        // waiting on it.
        ProcessBuilder builder = AshProcess.newBuilder(List.of("ash", "--version"), null);

        ProcessBuilder.Redirect input = builder.redirectInput();
        assertEquals(ProcessBuilder.Redirect.Type.READ, input.type());
        assertNotNull(input.file());
        assertEquals(AshProcess.nullFile().getPath(), input.file().getPath());
    }

    @Test
    @DisplayName("stderr is kept separate from stdout")
    void streamsAreNotMerged() {
        // redirectErrorStream(true) would avoid the pipe-deadlock the pumps exist for, and is
        // not used: the version probe needs to tell what a wrong binary wrote on stderr from
        // what ASH wrote on stdout, and merging throws that away.
        assertFalse(AshProcess.newBuilder(List.of("ash"), null).redirectErrorStream());
    }

    @Test
    @DisplayName("the working directory is set when one is given, and left alone when not")
    void setsWorkingDirectory(@TempDir Path temp) {
        assertEquals(
                temp.toFile(), AshProcess.newBuilder(List.of("ash"), temp).directory());
        assertEquals(null, AshProcess.newBuilder(List.of("ash"), null).directory());
    }

    @Test
    @DisplayName("an empty argv is rejected rather than producing an opaque spawn failure")
    void rejectsEmptyArgv() {
        assertThrows(
                IllegalArgumentException.class, () -> AshProcess.newBuilder(List.of(), null));
        assertThrows(IllegalArgumentException.class, () -> AshProcess.newBuilder(null, null));
    }

    @Test
    @DisplayName("captures both streams and the exit code of a real process")
    void capturesOutputAndExitCode() throws IOException {
        // `java -version` exits 0 and writes to STDERR, which makes it a real test of the
        // stderr pump rather than of the stdout one.
        AshProcess.Outcome outcome =
                AshProcess.run(
                        List.of(JAVA.toString(), "-version"), null, Duration.ofSeconds(60));

        assertFalse(outcome.timedOut());
        assertEquals(0, outcome.exitCode());
        assertTrue(
                outcome.stderr().toLowerCase(java.util.Locale.ROOT).contains("version"),
                "expected a version banner on stderr, got: " + outcome.combinedOutput());
        assertTrue(outcome.combinedOutput().contains("version"));
    }

    @Test
    @DisplayName("reports a non-zero exit code without treating it as an error")
    void reportsNonZeroExit() throws IOException {
        // ASH exits 2 when it finds something, so a non-zero code is not a failure signal in
        // this plugin and must arrive at the caller intact.
        AshProcess.Outcome outcome =
                AshProcess.run(
                        List.of(JAVA.toString(), "-XXnoSuchOption"), null, Duration.ofSeconds(60));

        assertFalse(outcome.timedOut());
        assertTrue(outcome.exitCode() != 0, "a bad JVM option must exit non-zero");
        assertFalse(outcome.combinedOutput().isBlank());
    }

    @Test
    @DisplayName("a deadline kills the child and says so rather than reporting an exit code")
    void enforcesTheDeadline() throws IOException {
        // A JVM start takes far more than a millisecond, so this reliably crosses the
        // deadline and exercises destroyForcibly plus the pump join.
        AshProcess.Outcome outcome =
                AshProcess.run(
                        List.of(JAVA.toString(), "-version"), null, Duration.ofMillis(1));

        assertTrue(outcome.timedOut(), "the deadline must be enforced");
        assertEquals(
                AshProcess.Outcome.TIMED_OUT_EXIT_CODE,
                outcome.exitCode(),
                "a timeout must not be reportable as a real exit code, or a caller could read"
                        + " it as ASH's own 0 or 2");
    }

    @Test
    @DisplayName("a program that does not exist raises IOException rather than an empty outcome")
    void missingProgramThrows(@TempDir Path temp) {
        Path absent = temp.resolve("definitely-not-a-program");
        assertFalse(Files.exists(absent));
        // This is the "no ash on PATH" case. It must reach the user as such: an empty outcome
        // would be indistinguishable from a scan that found nothing.
        assertThrows(
                IOException.class,
                () -> AshProcess.run(List.of(absent.toString()), null, Duration.ofSeconds(10)));
    }

    @Test
    @DisplayName("combinedOutput joins, or returns whichever stream spoke")
    void combinedOutputHandlesEachCase() {
        assertEquals("out", new AshProcess.Outcome(0, " out ", "  ", false).combinedOutput());
        assertEquals("err", new AshProcess.Outcome(0, "  ", " err ", false).combinedOutput());
        assertEquals("", new AshProcess.Outcome(0, "", "", false).combinedOutput());
        String both = new AshProcess.Outcome(0, "out", "err", false).combinedOutput();
        assertTrue(both.startsWith("out"));
        assertTrue(both.endsWith("err"));
    }

    @Test
    @DisplayName("the null device is named for the platform, including Windows")
    void nullDeviceIsPlatformCorrect() {
        // Windows is not hypothetical here: the ash name collision this class guards against
        // is a Windows condition, so NUL has to be right on the platform where it matters.
        String expected = AshProcess.isWindows() ? "NUL" : "/dev/null";
        assertEquals(expected, AshProcess.nullFile().getPath());
    }

    @Test
    @DisplayName("the two timeouts differ, and the scan's is the longer one")
    void timeoutsAreDistinct() {
        assertTrue(
                AshProcess.SCAN_TIMEOUT.compareTo(AshProcess.PROBE_TIMEOUT) > 0,
                "a repository scan is not fast; sharing the probe's deadline would kill it");
    }
}
