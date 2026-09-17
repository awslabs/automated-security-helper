// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Every way a scan can fail, and the requirement that none of them looks like a clean file.
 *
 * <p>This is why {@link AshScanService} takes its process and filesystem access as interfaces.
 * Not one of these conditions can be produced on demand by running a real {@code ash}: the
 * wrong binary answering, the scan hanging, ASH exiting with a code that means neither clean
 * nor findings, the SARIF missing, the SARIF truncated. Each one is a distinct message here,
 * and the assertion in every case is that {@code failed()} is true -- because an empty findings
 * list is what a clean scan returns, and the two must never be the same shape.
 */
class AshScanServiceTest {

    private static final String REAL_ASH = "awslabs/automated-security-helper v3.7.0";

    @Test
    @DisplayName("the happy path returns the findings and no error")
    void readsFindings(@TempDir Path temp) {
        AshScanPlan plan = plan(temp);
        AshScanService service =
                new AshScanService(
                        recordingSpawner(ok(REAL_ASH), exit(2)),
                        path -> Fixtures.read(Fixtures.SARIF_WITH_FINDINGS));

        AshScanService.Result result = service.scan(plan);

        assertFalse(result.failed());
        assertEquals(Fixtures.EXPECTED_FINDINGS, result.findings().size());
        assertEquals(0, result.skippedWithoutLocation());
    }

    @Test
    @DisplayName("exit code 2 is a successful run, because that is what findings look like")
    void treatsExitTwoAsSuccess(@TempDir Path temp) {
        // The whole reason this plugin cannot use "non-zero means failure": ASH exits 2 when it
        // finds something, so that rule would discard the SARIF in exactly the case that
        // matters.
        AshScanService.Result result =
                new AshScanService(
                                recordingSpawner(ok(REAL_ASH), exit(2)),
                                path -> Fixtures.read(Fixtures.SARIF_WITH_FINDINGS))
                        .scan(plan(temp));
        assertFalse(result.failed());
        assertFalse(result.findings().isEmpty());
    }

    @Test
    @DisplayName("a clean scan is a success with zero findings and no error")
    void treatsExitZeroAsAClean(@TempDir Path temp) {
        AshScanService.Result result =
                new AshScanService(
                                recordingSpawner(ok(REAL_ASH), exit(0)),
                                path -> Fixtures.read(Fixtures.SARIF_CLEAN))
                        .scan(plan(temp));
        assertFalse(result.failed());
        assertTrue(result.findings().isEmpty());
    }

    @Test
    @DisplayName("the version probe runs before the scan, and a wrong binary stops it")
    void refusesToScanWhenTheProbeFails(@TempDir Path temp) {
        List<List<String>> spawned = new ArrayList<>();
        AshScanService service =
                new AshScanService(
                        (argv, cwd, timeout) -> {
                            spawned.add(argv);
                            return new AshProcess.Outcome(2, "", "ash: 0: Illegal option --", false);
                        },
                        path -> {
                            throw new AssertionError("the SARIF must not be read at all");
                        });

        AshScanService.Result result = service.scan(plan(temp));

        assertTrue(result.failed());
        assertTrue(result.error().contains(AshExecutable.UNAMBIGUOUS));
        assertEquals(1, spawned.size(), "the scan must not be attempted after a failed probe");
        assertTrue(spawned.get(0).contains("--version"));
    }

    @Test
    @DisplayName("a missing executable is reported, not returned as zero findings")
    void reportsAMissingExecutable(@TempDir Path temp) {
        AshScanService service =
                new AshScanService(
                        (argv, cwd, timeout) -> {
                            throw new IOException("error=2, No such file or directory");
                        },
                        path -> null);

        AshScanService.Result result = service.scan(plan(temp));

        assertTrue(result.failed());
        assertTrue(result.error().contains("No such file or directory"));
        assertTrue(result.findings().isEmpty());
    }

    @Test
    @DisplayName("an IOException with no message still produces a usable error")
    void handlesAnExceptionWithNoMessage(@TempDir Path temp) {
        AshScanService.Result result =
                new AshScanService(
                                (argv, cwd, timeout) -> {
                                    throw new IOException();
                                },
                                path -> null)
                        .scan(plan(temp));
        assertTrue(result.failed());
        assertTrue(result.error().contains("IOException"), result.error());
    }

    @Test
    @DisplayName("a probe that succeeds and a scan that cannot start are told apart")
    void reportsAScanThatCouldNotStart(@TempDir Path temp) {
        AshScanService service =
                new AshScanService(
                        (argv, cwd, timeout) -> {
                            if (argv.contains("--version")) {
                                return ok(REAL_ASH);
                            }
                            throw new IOException("Text file busy");
                        },
                        path -> null);

        AshScanService.Result result = service.scan(plan(temp));

        assertTrue(result.failed());
        assertTrue(
                result.error().contains("answered its version probe"),
                "this is not 'ash is missing', and saying so saves the user checking PATH: "
                        + result.error());
    }

    @Test
    @DisplayName("a scan that hit the deadline is reported as not clean")
    void reportsATimeout(@TempDir Path temp) {
        AshScanService.Result result =
                new AshScanService(
                                recordingSpawner(
                                        ok(REAL_ASH),
                                        new AshProcess.Outcome(
                                                AshProcess.Outcome.TIMED_OUT_EXIT_CODE, "", "", true)),
                                path -> null)
                        .scan(plan(temp));

        assertTrue(result.failed());
        assertTrue(
                result.error().contains("this is not a clean result"),
                "the user must not read a timeout as a clean file: " + result.error());
    }

    @Test
    @DisplayName("an exit code that is neither 0 nor 2 is reported with what ASH printed")
    void reportsAnUnusableExitCode(@TempDir Path temp) {
        AshScanService.Result result =
                new AshScanService(
                                recordingSpawner(
                                        ok(REAL_ASH),
                                        new AshProcess.Outcome(
                                                1, "", "Error: config not found\nmore detail", false)),
                                path -> null)
                        .scan(plan(temp));

        assertTrue(result.failed());
        assertTrue(result.error().contains("exited 1"));
        assertTrue(result.error().contains("Error: config not found"));
        assertFalse(result.error().contains("more detail"), "quote the first line, not the log");
    }

    @Test
    @DisplayName("an unusable exit code with no output still names the code")
    void reportsAnUnusableExitCodeWithNoOutput(@TempDir Path temp) {
        AshScanService.Result result =
                new AshScanService(
                                recordingSpawner(ok(REAL_ASH), new AshProcess.Outcome(9, "", "", false)),
                                path -> null)
                        .scan(plan(temp));
        assertTrue(result.error().contains("exited 9"));
        assertTrue(result.error().contains("(nothing)"), result.error());
    }

    @Test
    @DisplayName("ASH exiting cleanly with no SARIF is a failure, not a clean file")
    void reportsAMissingSarif(@TempDir Path temp) {
        // The case worth naming precisely. ASH exited with a code that means it ran, and there
        // is no SARIF, so there is nothing to show AND nothing to conclude. An empty annotation
        // list here would be shown to the user as a file with no findings.
        AshScanService.Result result =
                new AshScanService(recordingSpawner(ok(REAL_ASH), exit(0)), path -> null)
                        .scan(plan(temp));

        assertTrue(result.failed());
        assertTrue(result.error().contains("wrote no SARIF"));
        assertTrue(
                result.error().contains("Nothing can be concluded"),
                "the message has to say that explicitly: " + result.error());
    }

    @Test
    @DisplayName("a SARIF that cannot be read is a failure naming the path")
    void reportsAnUnreadableSarif(@TempDir Path temp) {
        AshScanService.Result result =
                new AshScanService(
                                recordingSpawner(ok(REAL_ASH), exit(2)),
                                path -> {
                                    throw new IOException("Permission denied");
                                })
                        .scan(plan(temp));

        assertTrue(result.failed());
        assertTrue(result.error().contains("Permission denied"));
        assertTrue(result.error().contains("ash.sarif"));
    }

    @Test
    @DisplayName("a truncated SARIF is a failure, not an empty result set")
    void reportsAMalformedSarif(@TempDir Path temp) {
        AshScanService.Result result =
                new AshScanService(
                                recordingSpawner(ok(REAL_ASH), exit(2)),
                                path -> "{\"runs\":[{\"results\":[")
                        .scan(plan(temp));

        assertTrue(result.failed());
        assertTrue(result.error().contains("not valid JSON"));
        assertTrue(result.error().contains("offset"), "say where: " + result.error());
    }

    @Test
    @DisplayName("skipped-without-location results are carried through so zero can be explained")
    void carriesTheSkippedCount(@TempDir Path temp) {
        AshScanService.Result result =
                new AshScanService(
                                recordingSpawner(ok(REAL_ASH), exit(2)),
                                path ->
                                        "{\"runs\":[{\"results\":["
                                                + "{\"ruleId\":\"A\",\"locations\":[]},"
                                                + "{\"ruleId\":\"B\",\"locations\":[]}]}]}")
                        .scan(plan(temp));

        assertFalse(result.failed());
        assertTrue(result.findings().isEmpty());
        assertEquals(2, result.skippedWithoutLocation());
    }

    @Test
    @DisplayName("probe() can be called on its own and reports the version")
    void probeIsUsableAlone(@TempDir Path temp) {
        AshVersionProbe.Result probe =
                new AshScanService(recordingSpawner(ok(REAL_ASH)), path -> null).probe(plan(temp));
        assertTrue(probe.usable());
        assertEquals(REAL_ASH, probe.version());
    }

    @Test
    @DisplayName("the production wiring can be constructed")
    void productionWiringExists() {
        // Not a behavior test: it exists so the default wiring is at least instantiated by the
        // suite rather than first exercised on a user's machine.
        assertNotNull(AshScanService.withRealEnvironment());
    }

    @Test
    @DisplayName("the probe is given the shorter deadline and the scan the longer one")
    void usesTheRightDeadlines(@TempDir Path temp) {
        List<Duration> timeouts = new ArrayList<>();
        AshScanService service =
                new AshScanService(
                        (argv, cwd, timeout) -> {
                            timeouts.add(timeout);
                            return argv.contains("--version") ? ok(REAL_ASH) : exit(0);
                        },
                        path -> Fixtures.read(Fixtures.SARIF_CLEAN));

        service.scan(plan(temp));

        assertEquals(List.of(AshProcess.PROBE_TIMEOUT, AshProcess.SCAN_TIMEOUT), timeouts);
    }

    private static AshScanPlan plan(Path temp) {
        return new AshScanPlan("ash", temp.resolve("project"), temp.resolve("out"));
    }

    private static AshProcess.Outcome ok(String stdout) {
        return new AshProcess.Outcome(0, stdout, "", false);
    }

    private static AshProcess.Outcome exit(int code) {
        return new AshProcess.Outcome(code, "", "", false);
    }

    /** Returns each outcome in turn, so a probe and a scan can be given different answers. */
    private static AshScanService.Spawner recordingSpawner(AshProcess.Outcome... outcomes) {
        List<AshProcess.Outcome> queue = new ArrayList<>(List.of(outcomes));
        return (argv, cwd, timeout) -> {
            if (queue.isEmpty()) {
                throw new AssertionError("spawned more processes than this test expected: " + argv);
            }
            return queue.remove(0);
        };
    }
}
