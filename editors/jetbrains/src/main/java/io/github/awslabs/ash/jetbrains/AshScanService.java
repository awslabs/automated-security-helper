// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

/**
 * Runs one scan end to end: probe the executable, scan, read the SARIF.
 *
 * <p>WHY THE PROCESS AND FILESYSTEM CALLS GO THROUGH INTERFACES
 *
 * <p>Not for the sake of abstraction. Every failure this class has to get right is a failure
 * of the environment -- the wrong binary answered, the process hung, the SARIF was not
 * written, the SARIF was truncated -- and none of those can be produced on demand by running
 * a real {@code ash}. {@link Spawner} and {@link SarifSource} let a test produce each one
 * exactly, so the branch that reports "ASH ran but wrote no SARIF" is exercised rather than
 * argued for. {@link #withRealEnvironment} is the wiring the plugin uses.
 *
 * <p>WHY EVERY FAILURE CARRIES A MESSAGE AND NONE RETURNS AN EMPTY LIST
 *
 * <p>An empty result is what a clean file looks like. So this class never has one shape for
 * "no findings" and "could not find out": {@link Result#failed} distinguishes them, and the
 * caller shows the message. That is the whole reason this plugin is more than a SARIF reader.
 */
public final class AshScanService {

    /** Runs a command. Implemented by {@link AshProcess#run} in production. */
    public interface Spawner {
        AshProcess.Outcome run(List<String> argv, Path workingDirectory, Duration timeout)
                throws IOException;
    }

    /** Reads the SARIF a scan wrote. Implemented by the filesystem in production. */
    public interface SarifSource {
        /** @return the SARIF text, or null when the file does not exist. */
        String read(Path sarifPath) throws IOException;
    }

    /**
     * The outcome of a scan.
     *
     * @param findings every finding in the SARIF, across all files, empty when the scan was
     *     clean or when it failed
     * @param error null on success; otherwise a sentence for the user
     * @param skippedWithoutLocation how many results had no line-bearing location, so a
     *     "nothing to show" can be explained rather than just shown
     */
    public record Result(List<AshFinding> findings, String error, int skippedWithoutLocation) {
        public boolean failed() {
            return error != null;
        }

        static Result of(SarifReader read) {
            return new Result(read.findings(), null, read.skippedWithoutLocation());
        }

        static Result failure(String message) {
            return new Result(List.of(), message, 0);
        }
    }

    private final Spawner spawner;
    private final SarifSource sarifSource;

    public AshScanService(Spawner spawner, SarifSource sarifSource) {
        this.spawner = spawner;
        this.sarifSource = sarifSource;
    }

    /** The production wiring: real processes, real files. */
    public static AshScanService withRealEnvironment() {
        return new AshScanService(
                AshProcess::run,
                path -> Files.exists(path) ? Files.readString(path, StandardCharsets.UTF_8) : null);
    }

    /**
     * Checks that {@code plan}'s executable is ASH.
     *
     * <p>Run before every scan rather than once at startup. PATH can change while the IDE is
     * open -- a user installs ASH, or a version manager rewrites a shim -- and a cached
     * "not found" would leave the plugin permanently silent until the IDE restarted, with no
     * indication that a restart is what it wants.
     */
    public AshVersionProbe.Result probe(AshScanPlan plan) {
        List<String> argv = plan.versionCommand();
        try {
            AshProcess.Outcome outcome =
                    spawner.run(argv, null, AshProcess.PROBE_TIMEOUT);
            return AshVersionProbe.classify(argv.get(0), outcome);
        } catch (IOException notStarted) {
            return AshVersionProbe.notFound(argv.get(0), describe(notStarted));
        }
    }

    /** Probes, scans, and reads. */
    public Result scan(AshScanPlan plan) {
        AshVersionProbe.Result probe = probe(plan);
        if (!probe.usable()) {
            return Result.failure(probe.message());
        }

        AshProcess.Outcome outcome;
        try {
            outcome = spawner.run(plan.command(), null, AshProcess.SCAN_TIMEOUT);
        } catch (IOException notStarted) {
            // The probe just succeeded, so this is not "ash is missing". Something changed
            // between the two calls, or the scan subcommand could not start; either way the
            // exception text is the only information there is.
            return Result.failure("ASH answered its version probe but the scan could not start: "
                    + describe(notStarted));
        }

        if (outcome.timedOut()) {
            return Result.failure(
                    "The ASH scan did not finish within "
                            + AshProcess.SCAN_TIMEOUT.toMinutes()
                            + " minutes and was stopped. No findings are being shown; this is not"
                            + " a clean result.");
        }

        if (!AshScanPlan.isUsableExitCode(outcome.exitCode())) {
            return Result.failure(
                    "ASH exited "
                            + outcome.exitCode()
                            + ", which is neither 0 (clean) nor 2 (findings), so it did not"
                            + " complete a scan. It printed: "
                            + firstLine(outcome.combinedOutput()));
        }

        String sarif;
        try {
            sarif = sarifSource.read(plan.sarifPath());
        } catch (IOException unreadable) {
            return Result.failure(
                    "ASH exited " + outcome.exitCode() + " but its SARIF at "
                            + plan.sarifPath() + " could not be read: " + describe(unreadable));
        }

        if (sarif == null) {
            // The case worth naming precisely. ASH exited with a code that means it ran, and
            // there is no SARIF, so there is nothing to show AND nothing to conclude. An
            // empty annotation list here would be reported to the user as a clean file.
            return Result.failure(
                    "ASH exited "
                            + outcome.exitCode()
                            + " but wrote no SARIF at "
                            + plan.sarifPath()
                            + ". Nothing can be concluded about this file from that run.");
        }

        try {
            return Result.of(SarifReader.read(sarif));
        } catch (Json.SyntaxException malformed) {
            return Result.failure(
                    "ASH's SARIF at " + plan.sarifPath() + " is not valid JSON: "
                            + malformed.getMessage());
        }
    }

    /** An exception's message, or its class name when it has none. */
    private static String describe(Exception exception) {
        String message = exception.getMessage();
        return (message == null || message.isBlank())
                ? exception.getClass().getSimpleName()
                : message;
    }

    private static String firstLine(String output) {
        if (output.isBlank()) {
            return "(nothing)";
        }
        return output.strip().split("\\R", 2)[0].strip();
    }
}
