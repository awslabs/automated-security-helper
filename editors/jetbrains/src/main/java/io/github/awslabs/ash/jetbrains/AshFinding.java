// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains;

/**
 * One SARIF result, reduced to what an editor annotation needs.
 *
 * <p>WHY THE COLUMN FIELDS CAN BE ABSENT AND THE LINE FIELDS CANNOT
 *
 * <p>Measured against a real scan rather than read off the SARIF specification: ASH's
 * {@code region} for a detect-secrets finding carries {@code startLine} and {@code endLine}
 * and no column members at all, plus {@code charOffset: -1} and {@code byteOffset: -1},
 * which are sentinels for "not known" rather than offsets. So a plugin that required
 * columns would produce nothing for the scanner most likely to be installed, and one that
 * trusted {@code charOffset} would point every annotation at the character before the start
 * of the file.
 *
 * <p>{@link #ABSENT} is therefore what both column fields hold when SARIF did not say, and
 * {@link AshAnnotationPlanner} widens such a finding to the whole line. A whole-line
 * highlight is right for a secret anyway: the finding is about the assignment, not about
 * one character of it.
 *
 * @param ruleId the SARIF {@code ruleId}, for example {@code SECRET-AWS-ACCESS-KEY}. Never
 *     null; {@link SarifReader} substitutes a placeholder when SARIF omits it, because an
 *     annotation with no rule name gives the reader nothing to search for.
 * @param level the SARIF {@code level} as written, lowercased. Mapped by {@link AshSeverity}.
 * @param message the SARIF {@code message.text}.
 * @param uri the SARIF {@code artifactLocation.uri}, relative to the scanned source
 *     directory in ASH's output.
 * @param startLine 1-based, always present -- a result whose region has no start line is
 *     dropped by the reader rather than defaulted to line 1.
 * @param endLine 1-based and inclusive; equal to {@code startLine} for a single-line finding.
 * @param startColumn 1-based, or {@link #ABSENT}.
 * @param endColumn 1-based and exclusive per SARIF, or {@link #ABSENT}.
 * @param scannerName the ASH-specific {@code properties.scanner_name}, for example
 *     {@code detect-secrets}, or empty when absent. Shown in the annotation so a user can
 *     tell which of ASH's scanners spoke.
 */
public record AshFinding(
        String ruleId,
        String level,
        String message,
        String uri,
        int startLine,
        int endLine,
        int startColumn,
        int endColumn,
        String scannerName) {

    /**
     * The value both column fields take when SARIF supplied none.
     *
     * <p>Zero, not -1. SARIF columns are 1-based, so 0 is already outside the domain, and
     * ASH writes -1 into its own {@code charOffset} and {@code index} members as its
     * sentinel -- reusing -1 here would make a real ASH sentinel and this plugin's
     * "absent" marker the same value, so a bug that let one through as the other would
     * read as correct.
     */
    public static final int ABSENT = 0;

    /** True when SARIF gave a column for the start of the finding. */
    public boolean hasStartColumn() {
        return startColumn > ABSENT;
    }

    /** True when SARIF gave a column for the end of the finding. */
    public boolean hasEndColumn() {
        return endColumn > ABSENT;
    }
}
