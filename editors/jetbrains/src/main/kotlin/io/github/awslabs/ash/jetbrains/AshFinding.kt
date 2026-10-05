// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

/**
 * One ASH finding, in SARIF's own coordinates.
 *
 * LINE AND COLUMN NUMBERS HERE ARE 1-BASED, because SARIF's are: section 3.30.5
 * defines `startLine` as "a positive integer equal to the line number of the line
 * containing the first character in the region". IntelliJ's `Document` is 0-based.
 * The conversion happens in exactly one place, [AshRangeMapper], rather than at each
 * use site -- an off-by-one scattered across call sites is the kind of defect that
 * shows up as findings landing one line above where they belong, which reads as
 * plausible rather than as broken.
 *
 * @param filePath the SARIF `artifactLocation.uri`, scheme-stripped but otherwise
 *   untouched. Resolving it against a project root is the IDE layer's job; keeping
 *   it raw here is what lets the parser be tested without a project.
 * @param endLine per section 3.30.7, absent `endLine` defaults to `startLine`; that
 *   default is applied at parse time so this field is never null.
 * @param startColumn per section 3.30.6, absent `startColumn` defaults to 1; applied
 *   at parse time.
 * @param endColumn null means the SARIF omitted it. Section 3.30.8 says an absent
 *   `endColumn` defaults to "one greater than the column number of the last character
 *   on the line", which is a fact about the FILE and not about the SARIF -- the parser
 *   cannot compute it, so it stays null and [AshRangeMapper] resolves it against the
 *   real document. Substituting a guess here would silently truncate every
 *   region that omits the field.
 * @param levelExplicit whether [level] came from the SARIF or from the defaulting
 *   procedure. Carried so the annotator can say which, and so a test can tell a
 *   correctly-defaulted warning from one that was read off the wire.
 */
data class AshFinding(
    val filePath: String,
    val startLine: Int,
    val startColumn: Int,
    val endLine: Int,
    val endColumn: Int?,
    val level: AshLevel,
    val levelExplicit: Boolean,
    val ruleId: String?,
    val message: String,
    val scannerName: String?,
)

/**
 * Everything one SARIF file yielded: the findings, and every reason the parser could
 * not fully understand it.
 *
 * [problems] is not decoration. A SARIF whose results carry no location, or whose
 * `level` is a string this does not recognize, has lost information, and a parser
 * that returns a shorter list without saying so is indistinguishable from a clean
 * scan. The action surfaces this; see [AshScanAction].
 */
data class AshScanResults(
    val findings: List<AshFinding>,
    val problems: List<String>,
    /** Every `result` object seen, across every run. */
    val totalResults: Int = 0,
    /** Results dropped because the report says they are suppressed. */
    val suppressedResults: Int = 0,
    /**
     * Unsuppressed results that carry no severity, so there is nothing to show.
     *
     * NAMED FOR WHAT THE CHECK ESTABLISHES, not for the case that motivated it. This was
     * `notFailureResults`, which claimed more than the test behind it: the bucket is filled when the
     * RESOLVED level is `none`, and that catches both a non-`fail` kind AND an explicit
     * `level: "none"` on a `kind: "fail"` result. The second is legal SARIF and is not a non-failure.
     * Unexercised on the real report -- all 85 level-none results there are also informational and
     * suppressed -- but a bucket name that asserts an unverified property is how a future reader
     * concludes something the code never checked.
     */
    val noSeverityResults: Int = 0,
    /** Unsuppressed failures with no location this can put in an editor. */
    val unlocatableResults: Int = 0,
    /** Unsuppressed failures that produced at least one finding. */
    val surfacedResults: Int = 0,
    /**
     * Set when the document as a whole could not be read as SARIF -- not JSON (a truncated
     * write), a root that is not an object, or no `runs` array -- and null otherwise.
     *
     * Separate from [problems] because the two mean different things. A problem is one part of
     * a report that could not be read while the rest was; this is a report of which nothing
     * was read, so its zero findings are not a result and the scan has to fail on it.
     */
    val unreadableReason: String? = null,
) {
    /**
     * Whether every result landed in exactly one bucket.
     *
     * WHAT THIS CATCHES: a result that falls out of the parser without being counted anywhere -- a
     * new early `return` in the result loop, a bucket increment omitted on a branch. Individual
     * counts can each look plausible while one result disappears between them, and this fails on
     * that even when every separate number still looks reasonable.
     *
     * WHAT IT DOES NOT CATCH, stated because an earlier version of this comment claimed the
     * opposite: the grype root-absolute path defect. That finding WAS produced and WAS counted --
     * `surfaced` incremented for it -- and then failed to match any open file downstream, in
     * `AshPathResolver`, which runs after the parser and after this tally. The invariant holds
     * identically before and after that fix, so it is no evidence about it. A MISPLACED finding is
     * not a VANISHED one, and only `AshPathResolverTest` plus the real-report path assertions cover
     * the misplaced class. Do not delete those believing this covers them.
     *
     * Counted in RESULTS, not findings, because one result with several locations legitimately
     * produces several findings, so `findings.size` is not comparable to `totalResults`.
     *
     * VACUOUSLY TRUE ON ZEROES, so never assert it alone. [EMPTY] and every `parse` failure path
     * return all-zero counts, which satisfy it. Pair it with an expected [totalResults] so the
     * assertion has a denominator.
     */
    val accountsForEveryResult: Boolean
        get() = suppressedResults + noSeverityResults + unlocatableResults + surfacedResults ==
            totalResults

    companion object {
        val EMPTY = AshScanResults(emptyList(), emptyList())
    }
}
