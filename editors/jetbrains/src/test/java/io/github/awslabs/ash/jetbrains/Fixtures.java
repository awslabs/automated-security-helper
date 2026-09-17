// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

/**
 * Loads the committed fixtures.
 *
 * <p>The two SARIF documents are REAL {@code ash scan} output, produced by running
 * {@code ash scan --scanners detect-secrets --no-progress} and then rewritten to remove host
 * paths and wall-clock timestamps. Nothing else about them was changed. A hand-written SARIF
 * would have tested the reader against an idea of ASH's shape rather than ASH's shape, and
 * the three differences that matter -- an empty {@code rules} array, regions with no columns,
 * and {@code -1} sentinels in {@code charOffset} and {@code index} -- are all things a reading
 * of the SARIF schema would have got wrong.
 *
 * <p>The exit codes are recorded here because they are the reason these two documents are
 * both needed. Both measured:
 *
 * <ul>
 *   <li>{@code ash-detect-secrets.sarif}: 3 results, exit code 2.
 *   <li>{@code ash-clean-scan.sarif}: 0 results, exit code 0.
 * </ul>
 *
 * <p>The second is the whole problem in one line. A scan that found nothing exits 0, so
 * "ASH ran and exited successfully" is satisfied by a scan that saw a real credential and
 * reported nothing. That is why every count assertion in this suite is on the NUMBER of
 * annotations and never on a process finishing or a file appearing.
 */
final class Fixtures {

    /** A real scan of a file carrying AWS's published example secret access key. */
    static final String SARIF_WITH_FINDINGS = "/sarif/ash-detect-secrets.sarif";

    /** A real scan of a file carrying nothing. Exit code 0, zero results. */
    static final String SARIF_CLEAN = "/sarif/ash-clean-scan.sarif";

    /**
     * The scanned file itself, planted with the same value as
     * {@code packaging/deb/verify-in-container.sh}.
     *
     * <p>The same value across the whole branch on purpose: one known secret means one thing
     * to look for when a verification anywhere reports nothing.
     */
    static final String LEAK_FILE = "/fixtures/leak.py";

    /** The path ASH wrote into the fixture's {@code artifactLocation.uri}, measured. */
    static final String LEAK_URI = "leak.py";

    /** How many results the findings fixture holds. Pinned so a truncated fixture fails. */
    static final int EXPECTED_FINDINGS = 3;

    private Fixtures() {}

    static String read(String resource) {
        try (InputStream stream = Fixtures.class.getResourceAsStream(resource)) {
            if (stream == null) {
                // Not an assertion failure but a missing fixture, which is a different
                // problem and must not read as "the code under test returned nothing".
                throw new IllegalStateException(
                        "fixture " + resource + " is not on the test classpath");
            }
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
