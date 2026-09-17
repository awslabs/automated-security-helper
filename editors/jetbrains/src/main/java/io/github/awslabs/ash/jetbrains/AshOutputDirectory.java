// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Picks where ASH may write its output for a given project.
 *
 * <p>WHY NOT INSIDE THE PROJECT, WHICH IS WHERE ASH DEFAULTS
 *
 * <p>{@code ash scan} writes {@code .ash/ash_output/} under the source directory by default,
 * and that is right for a command line. It is wrong under an IDE for two reasons that
 * compound: the IDE indexes the project tree, so a scan's own reports become source the next
 * scan reads and reports on, and every run produces a burst of file-watcher events that
 * re-trigger the annotation pass that started the scan.
 *
 * <p>{@link AshScanPlan} refuses an output directory inside the source directory rather than
 * trusting this class, because the check belongs next to the thing it protects.
 *
 * <p>WHY THE NAME IS A DIGEST AND NOT THE PROJECT'S NAME
 *
 * <p>A project name is not unique -- two checkouts of the same repository, or two projects
 * both called {@code service}, would share a directory and each scan would read the other's
 * SARIF. A digest of the absolute path is unique per checkout and stable across IDE restarts,
 * so a scan reuses its predecessor's directory instead of filling the temporary directory with
 * one tree per run. The first 16 hex characters are enough: this is a collision-avoidance
 * name, not a security boundary.
 */
public final class AshOutputDirectory {

    /** How many hex characters of the digest go into the directory name. */
    static final int NAME_LENGTH = 16;

    /** The prefix, so the directories are recognizable in a temporary directory listing. */
    static final String PREFIX = "ash-jetbrains-";

    private AshOutputDirectory() {}

    /** The output directory under the JVM's temporary directory. */
    public static Path forProject(Path projectRoot) {
        return forProject(projectRoot, Path.of(System.getProperty("java.io.tmpdir", "/tmp")));
    }

    /**
     * The output directory under an explicit base, which is what makes this testable.
     *
     * @param projectRoot the project's root; only its absolute textual form is used, so the
     *     directory does not have to exist
     * @param base where per-project directories are created
     */
    public static Path forProject(Path projectRoot, Path base) {
        return base.resolve(PREFIX + digestOf(projectRoot.toAbsolutePath().normalize().toString()));
    }

    private static String digestOf(String text) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(text.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash).substring(0, NAME_LENGTH);
        } catch (NoSuchAlgorithmException impossible) {
            // SHA-256 is required of every JRE by the platform specification. If it is
            // genuinely absent the JVM is not one this plugin can reason about, so this
            // fails loudly rather than falling back to a name that could collide.
            throw new IllegalStateException("this JVM has no SHA-256", impossible);
        }
    }
}
