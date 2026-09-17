// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains;

/**
 * A SARIF {@code level} translated into the four severities an IntelliJ annotation can
 * carry.
 *
 * <p>WHY THIS IS AN ENUM AND NOT A CALL TO HighlightSeverity
 *
 * <p>{@code com.intellij.lang.annotation.HighlightSeverity} lives in the platform, so a
 * mapping written against it can only be tested by starting an IDE. Keeping the decision
 * here means the interesting half -- which SARIF level becomes which severity, and what
 * happens to a level SARIF does not define -- is a plain unit test, and the platform-facing
 * half is one switch in {@link AshExternalAnnotator} with no decisions in it.
 *
 * <p>WHY AN UNKNOWN LEVEL BECOMES A WARNING AND NOT NOTHING
 *
 * <p>SARIF defines exactly {@code error}, {@code warning}, {@code note} and {@code none}.
 * A scanner ASH gains later could write something else, and dropping the result would mean
 * a finding that exists in the SARIF and nowhere in the editor -- the silent-clean-file
 * failure. So an unrecognized level is reported, at WARNING, and the level string travels
 * into the annotation message so the reader can see what it actually was.
 */
public enum AshSeverity {
    /** SARIF {@code error}. */
    ERROR,
    /** SARIF {@code warning}, and the fallback for any level this build does not know. */
    WARNING,
    /** SARIF {@code note}. */
    WEAK_WARNING,
    /**
     * SARIF {@code none}.
     *
     * <p>Still shown. {@code none} means the scanner expressed no severity, not that the
     * finding is uninteresting, and ASH's own severity threshold has already decided what
     * reaches the SARIF at all.
     */
    INFORMATION;

    /**
     * Maps a SARIF level string.
     *
     * @param level the level as SARIF wrote it; null, blank and unknown values all become
     *     {@link #WARNING}.
     */
    public static AshSeverity fromSarifLevel(String level) {
        if (level == null) {
            return WARNING;
        }
        switch (level.trim().toLowerCase(java.util.Locale.ROOT)) {
            case "error":
                return ERROR;
            case "warning":
                return WARNING;
            case "note":
                return WEAK_WARNING;
            case "none":
                return INFORMATION;
            default:
                return WARNING;
        }
    }

    /** True when the level is one SARIF defines, so a caller can say when it guessed. */
    public static boolean isKnownSarifLevel(String level) {
        if (level == null) {
            return false;
        }
        String normalized = level.trim().toLowerCase(java.util.Locale.ROOT);
        return "error".equals(normalized)
                || "warning".equals(normalized)
                || "note".equals(normalized)
                || "none".equals(normalized);
    }
}
