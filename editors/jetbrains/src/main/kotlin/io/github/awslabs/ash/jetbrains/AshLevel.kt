// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

/**
 * A SARIF `level`, as the four values SARIF 2.1.0 defines.
 *
 * READ THE VALUE, NEVER THE MEMBER NAME. This is the whole reason this type has a
 * [sarifValue] field instead of relying on [name]. The failure it exists to prevent
 * is live in ASH's own history: `Level` on the Python side is a `(str, Enum)` mixin
 * rather than a `StrEnum`, so `Enum.__str__` wins and `str(Level.error)` renders
 * `"Level.error"` -- a string that matches no SARIF level and no lookup table. Two
 * things hide it. `Level.error == "error"` is True, so equality cannot tell the two
 * shapes apart, and the member is truthy, so a falsy guard never fires. The
 * consequence in a consumer is not a crash: it is a finding that silently falls
 * through every severity branch and lands on the default, which downgrades a real
 * error to a warning or an informational note.
 *
 * Kotlin has the same trap in a different costume. `AshLevel.ERROR.toString()` is
 * `"ERROR"`, `AshLevel.ERROR.name` is `"ERROR"`, and neither is the SARIF value
 * `"error"`. Anything that emits or compares a level goes through [sarifValue].
 *
 * [fromSarif] additionally accepts an enum-repr-shaped string, because the string
 * `"Level.error"` demonstrably reaches consumers of SARIF produced in this
 * ecosystem. Accepting it is not an endorsement of producing it -- it is refusing to
 * silently downgrade a finding whose producer had that bug.
 */
enum class AshLevel(val sarifValue: String) {
    NONE("none"),
    NOTE("note"),
    WARNING("warning"),
    ERROR("error"),
    ;

    companion object {
        /**
         * The level for a result whose `kind` is `"fail"` and for which neither the
         * result nor its rule supplies a `level`.
         *
         * SARIF 2.1.0 section 3.27.10, quoted from the errata01 OS text: "IF level has
         * not yet been set THEN SET level to \"warning\"". The procedure it ends
         * consults, in order, a `ruleConfigurationOverrides` entry and then the rule's
         * `defaultConfiguration.level`. Defaulting to anything quieter would mean a
         * scanner that omits `level` -- which is the normal way to inherit severity
         * from the rule -- has its findings demoted by this plugin rather than by its
         * author.
         *
         * The DEFAULT IS KIND-DEPENDENT and this constant is only half of it; see
         * [NON_FAIL_DEFAULT]. Treating "warning" as the single default would promote
         * every `notApplicable` and `pass` result into a visible warning.
         *
         * THE SPEC AND ASH'S OWN MODEL DISAGREE HERE, and this follows the spec. ASH's
         * `sarif_schema_model.py` declares `Result.level` defaulting to `"error"` (with
         * `Result.kind` defaulting to `"fail"`), described there as the reachable case because every
         * third-party SARIF ASH ingests arrives through `model_validate`. The spec procedure quoted
         * above ends at `"warning"`.
         *
         * Warning is kept, for two reasons. This parser consumes `reports/ash.sarif`, which ASH
         * itself produced -- so ASH has ALREADY applied its `error` default during ingestion, and an
         * absent level in a final report should not occur. Measured: all 126 results in the real
         * report carry an explicit level, so this path is unexercised either way. And if an absent
         * level does reach here, it came from somewhere ASH's model did not touch, which is exactly
         * the case the format's own procedure governs. Defaulting to `error` would also make a
         * finding whose severity nobody stated the loudest thing on screen, which is a false
         * precision rather than a safe one.
         *
         * IF THIS IS EVER CHANGED TO `ERROR`, say in the comment that it follows the producer over
         * the spec procedure and why, because the next reader will find the spec text and change it
         * back. And sweep for assertions whose expected value would then equal the new default: a
         * `!= FAIL_DEFAULT` discriminator silently stops discriminating when the default moves to
         * the value it was excluding. `AshRealReportTest` had one and it is now a distribution
         * assertion for that reason.
         */
        val FAIL_DEFAULT: AshLevel = WARNING

        /**
         * The level for a result whose `kind` is anything other than `"fail"`.
         *
         * Section 3.27.10: "If kind has any value other than \"fail\", then if level is
         * absent, it SHALL default to \"none\", and if it is present, it SHALL have the
         * value \"none\"." So a `pass`, `open`, `informational` or `notApplicable`
         * result is never a severity this surfaces.
         */
        val NON_FAIL_DEFAULT: AshLevel = NONE

        /**
         * The `kind` SARIF 2.1.0 section 3.27.9 assigns when the property is absent:
         * "If kind is absent, it SHALL default to \"fail\"." This matters because the
         * common case -- a scanner that writes `level` and omits `kind` -- must be
         * read as a real finding, not as a non-failure.
         */
        const val KIND_DEFAULT: String = "fail"

        private val BY_VALUE: Map<String, AshLevel> = entries.associateBy { it.sarifValue }

        /**
         * Parses a SARIF `level`, or returns null when the input carries no usable
         * level.
         *
         * Null means ABSENT, and absent is not the same as unrecognized: an absent
         * level must fall through to rule metadata (see
         * [AshSarifParser]), while an unrecognized one has already lost its
         * information. Both return null here, and the caller distinguishes them by
         * whether the raw string was blank -- [describeUnrecognized] exists so the
         * unrecognized case can be surfaced instead of absorbed.
         */
        fun fromSarif(raw: String?): AshLevel? {
            val normalized = normalize(raw) ?: return null
            return BY_VALUE[normalized]
        }

        /**
         * The reason a non-blank level did not parse, or null if it did parse or was
         * blank. Callers turn this into a user-visible warning; a level this cannot
         * read is a severity it must not guess at silently.
         */
        fun describeUnrecognized(raw: String?): String? {
            val normalized = normalize(raw) ?: return null
            if (BY_VALUE.containsKey(normalized)) return null
            return "unrecognized SARIF level ${'"'}$raw${'"'}; " +
                "expected one of ${entries.joinToString(", ") { it.sarifValue }}"
        }

        /**
         * Trims, strips an enum-repr prefix, and lowercases. Returns null for blank.
         *
         * Taking the text after the LAST '.' is safe rather than merely convenient:
         * no SARIF level contains a dot, so for well-formed input this is the
         * identity. For `"Level.error"` it recovers `"error"`, and for a nested repr
         * like `"SarifLevel.Level.error"` it still recovers `"error"`.
         */
        private fun normalize(raw: String?): String? {
            val trimmed = raw?.trim() ?: return null
            if (trimmed.isEmpty()) return null
            return trimmed.substringAfterLast('.').trim().lowercase()
        }
    }
}
