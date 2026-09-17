// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains;

import java.nio.file.Path;
import java.util.List;

/**
 * The command line for one scan, and where its SARIF will be.
 *
 * <p>WHY A NON-ZERO EXIT CODE IS NOT A FAILURE HERE
 *
 * <p>ASH exits 2 when it finds something at or above its configured severity threshold. That
 * is the whole point of the exit-code work this branch carries, and it means a plugin that
 * treated non-zero as failure would discard the SARIF in exactly the case where the SARIF
 * has findings in it. {@link #isUsableExitCode} names the codes that mean "ASH ran", and the
 * only real failure signal for this plugin is a SARIF that is absent or unparseable.
 *
 * <p>WHY THE OUTPUT DIRECTORY IS OUTSIDE THE PROJECT
 *
 * <p>ASH writes a tree of reports and per-scanner working files. Putting that under the
 * project would make the IDE index it, which means a scan's own output becomes source the
 * next scan reads, plus a burst of file-watcher events on every run. The caller supplies a
 * directory under the IDE's own scratch area instead.
 *
 * <p>WHY --no-progress AND NOT A PTY
 *
 * <p>ASH renders a progress display when it thinks it has a terminal. There is no terminal
 * here, and the escape sequences would end up in the captured stderr, where they are noise
 * in an error message. The packaging verifications pass the same flag for the same reason.
 */
public final class AshScanPlan {

    /**
     * Where ASH writes the aggregated SARIF, relative to the output directory.
     *
     * <p>Two segments, measured from a real run rather than assumed: {@code reports/ash.sarif}
     * alongside {@code reports/ash.ghas.sarif} and the per-scanner
     * {@code scanners/<name>/source/results_sarif.sarif}. The aggregate is the one to read --
     * the GHAS variant is reshaped for GitHub code scanning, and a per-scanner file is one
     * scanner's view.
     */
    static final String SARIF_RELATIVE_PATH = "reports/ash.sarif";

    private final String executable;
    private final Path sourceDirectory;
    private final Path outputDirectory;

    /**
     * @param executable already resolved by {@link AshExecutable#resolve}
     * @param sourceDirectory the tree to scan, normally the project root
     * @param outputDirectory where ASH may write; must not be inside {@code sourceDirectory}
     */
    public AshScanPlan(String executable, Path sourceDirectory, Path outputDirectory) {
        this.executable = executable;
        this.sourceDirectory = sourceDirectory;
        this.outputDirectory = outputDirectory;
        if (outputDirectory.normalize().startsWith(sourceDirectory.normalize())) {
            // Loud rather than merely slow. A scan whose output lands in its own input grows
            // a little on every run and the reports start reporting on themselves, which
            // reads as ASH finding new problems rather than as a configuration mistake.
            throw new IllegalArgumentException(
                    "the ASH output directory must not be inside the directory being scanned: "
                            + outputDirectory
                            + " is under "
                            + sourceDirectory);
        }
    }

    /** The full argv to hand to {@link AshProcess#run}. */
    public List<String> command() {
        return List.of(
                executable,
                "scan",
                "--source-dir",
                sourceDirectory.toString(),
                "--output-dir",
                outputDirectory.toString(),
                "--no-progress");
    }

    /** The argv for the identity probe. */
    public List<String> versionCommand() {
        return List.of(executable, "--version");
    }

    /** Where {@link #command} will have written the aggregated SARIF. */
    public Path sarifPath() {
        Path resolved = outputDirectory;
        for (String segment : SARIF_RELATIVE_PATH.split("/")) {
            resolved = resolved.resolve(segment);
        }
        return resolved;
    }

    /**
     * True for an exit code that means ASH ran to completion, whatever it found.
     *
     * <p>0 is a clean scan and 2 is findings at or above the threshold. Anything else -- and
     * in particular {@link AshProcess.Outcome#TIMED_OUT_EXIT_CODE} -- means the run did not
     * produce a result this plugin may read.
     */
    public static boolean isUsableExitCode(int exitCode) {
        return exitCode == 0 || exitCode == 2;
    }
}
