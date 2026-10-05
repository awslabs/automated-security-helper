// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.google.gson.JsonSyntaxException

/**
 * Reads an ASH SARIF report into [AshScanResults].
 *
 * WHY GSON AND NOT A DECLARED DEPENDENCY. The hard constraint on this plugin is that
 * it ships no third-party code. Gson is bundled inside the IntelliJ Platform, so
 * importing it adds nothing to the distributable ZIP -- the build declares no
 * `implementation` dependency at all, which is why `lib/` in the built plugin contains
 * exactly one jar. The cost of that choice is a coupling to a library the platform
 * bundles but does not promise: if a future IDE dropped Gson, this would fail at
 * class-load time rather than at compile time. Two things make that visible rather
 * than latent. `verifyPlugin` resolves every referenced class against real IDE
 * distributions and reports a missing one, and AshFindingInspectionIdeTest exercises this
 * parser inside a booted platform, so the class actually resolving is asserted rather
 * than assumed.
 *
 * Section references below are to SARIF 2.1.0 errata01 OS. The defaulting rules are
 * quoted rather than paraphrased where getting them wrong would change a severity,
 * because every one of them is a place where a plausible guess is also wrong.
 */
object AshSarifParser {

    /** Cap on recorded problems, so a systematically broken SARIF cannot produce a notification the size of the file. */
    private const val MAX_PROBLEMS = 50

    fun parse(sarifText: String): AshScanResults {
        val root = try {
            JsonParser.parseString(sarifText)
        } catch (e: JsonSyntaxException) {
            return AshScanResults(
                emptyList(),
                listOf("SARIF is not valid JSON: ${e.message}"),
            )
        }

        // JsonParser returns JsonNull rather than null for the literal `null`, so this one test
        // covers it as well as an array or a bare value.
        if (!root.isJsonObject) {
            return AshScanResults(emptyList(), listOf("SARIF root is not a JSON object."))
        }

        val runs = root.asJsonObject.optArray("runs")
            ?: return AshScanResults(
                emptyList(),
                listOf("SARIF has no ${'"'}runs${'"'} array; nothing to read."),
            )

        val findings = mutableListOf<AshFinding>()
        val problems = mutableListOf<String>()
        val tally = Tally()

        runs.forEachIndexed { runIndex, runElement ->
            val run = runElement.asObjectOrNull()
            if (run == null) {
                problems.addCapped("runs[$runIndex] is not an object; skipped.")
                return@forEachIndexed
            }
            parseRun(run, runIndex, findings, problems, tally)
        }

        return AshScanResults(
            findings = findings,
            problems = problems,
            totalResults = tally.total,
            suppressedResults = tally.suppressed,
            noSeverityResults = tally.noSeverity,
            unlocatableResults = tally.unlocatable,
            surfacedResults = tally.surfaced,
        )
    }

    /**
     * Per-result bucket counts, so every result can be shown to have landed somewhere.
     *
     * A class rather than four local vars because [parseRun] needs to mutate them across runs, and
     * because the closure invariant on [AshScanResults] is only meaningful if nothing can increment
     * one bucket without the total.
     */
    private class Tally {
        var total = 0
        var suppressed = 0
        var noSeverity = 0
        var unlocatable = 0
        var surfaced = 0
    }

    private fun parseRun(
        run: JsonObject,
        runIndex: Int,
        findings: MutableList<AshFinding>,
        problems: MutableList<String>,
        tally: Tally,
    ) {
        // The DRIVER name is a FALLBACK, never the answer on its own.
        //
        // ASH aggregates every scanner into ONE run: the driver is ASH itself
        // ("AWS Labs - Automated Security Helper") and the individual tools are
        // `tool.extensions`. Measured on tests/test_data/outputs/ash_aggregated_results.json --
        // 1 run, 126 results, 7 extensions (cfn-nag, detect-secrets, bandit, cdk-nag, checkov,
        // grype, semgrep). So reading the scanner once per run and attaching it to every finding
        // is wrong twice over: wrong VALUE, because every finding would be attributed to the
        // 36-character driver name, and wrong CARDINALITY, because one run legitimately holds
        // seven scanners. Per-result attribution lives in `properties.scanner_name`, which that
        // report carries on all 126 results.
        //
        // Kept as a fallback rather than dropped because a single-tool SARIF -- what a scanner
        // writes before ASH aggregates it, and what any other producer writes -- does put the
        // tool in `driver.name` and has no `scanner_name` property.
        val driverName = run.optObject("tool")?.optObject("driver")?.optString("name")
        val ruleIndex = RuleIndex.of(run)
        val results = run.optArray("results") ?: return

        results.forEachIndexed { i, resultElement ->
            val result = resultElement.asObjectOrNull()
            if (result == null) {
                problems.addCapped("runs[$runIndex].results[$i] is not an object; skipped.")
                return@forEachIndexed
            }
            val where = "runs[$runIndex].results[$i]"
            tally.total++

            // SUPPRESSION IS CHECKED FIRST, BEFORE ANYTHING ELSE ABOUT THIS RESULT.
            //
            // Two reasons it has to be first. A suppressed result with no usable location would
            // otherwise be counted as "unshowable" and complained about in the notification --
            // warning the user about findings nobody wanted to see. And suppression is a state
            // while level is a severity: filtering on `level == none` catches the wrong set.
            //
            // Measured on the real report: 92 of 126 results are suppressed, but only 85 are
            // `kind=informational, level=none`. The other SEVEN are `kind=fail` with real
            // severities -- 5 checkov warnings and 2 semgrep errors -- every one of them
            // `kind: "inSource"`, meaning a developer wrote the suppression next to the code. A
            // level-based filter re-displays exactly those, which is the worst version of this:
            // the most deliberate suppressions are the ones it ignores.
            val suppression = suppressionOf(result)
            if (suppression == Suppression.SUPPRESSED) {
                tally.suppressed++
                return@forEachIndexed
            }

            val resolved = resolveLevel(result, ruleIndex, where, problems)

            // NO SEVERITY TO SHOW. Two distinct cases reach here and the bucket is named for the
            // property they share rather than for the commoner one: a non-`fail` kind, which section
            // 3.27.10 says resolves to `none`, AND an explicit `level: "none"` on a `kind: "fail"`
            // result, which is legal SARIF and is not a non-failure. Only the first occurs in the
            // real report, so calling the bucket "not a failure" asserted something untested.
            //
            // Kept as a SEPARATE check from suppression rather than folded into one predicate,
            // because the two answer different questions and a result can satisfy either alone -- an
            // unsuppressed informational result is legal, and so is a suppressed failure.
            if (resolved.level == AshLevel.NONE) {
                tally.noSeverity++
                return@forEachIndexed
            }

            val message = result.optObject("message")?.optString("text")?.takeIf { it.isNotBlank() }
                ?: "ASH reported a finding with no message text."
            val ruleId = result.optString("ruleId")

            // Read PER RESULT, inside this loop, not once per run. See the note on driverName.
            val scannerName = result.optObject("properties")
                ?.optString("scanner_name")
                ?.takeIf { it.isNotBlank() }
                ?: driverName

            val locations = result.optArray("locations")
            if (locations == null || locations.size() == 0) {
                // Surfaced, not silently dropped. A finding with no location cannot be
                // put on a line, but a scan that reports twelve findings and shows
                // three must say where the other nine went.
                tally.unlocatable++
                problems.addCapped(
                    "$where (${ruleId ?: "no ruleId"}) has no locations; it cannot be " +
                        "shown in the editor.",
                )
                return@forEachIndexed
            }

            var anyUsable = false
            locations.forEach { locationElement ->
                val finding = parseLocation(
                    locationElement,
                    level = resolved.level,
                    levelExplicit = resolved.explicit,
                    ruleId = ruleId,
                    message = message,
                    scannerName = scannerName,
                )
                if (finding != null) {
                    findings.add(finding)
                    anyUsable = true
                }
            }
            if (anyUsable) {
                tally.surfaced++
            } else {
                tally.unlocatable++
                problems.addCapped(
                    "$where (${ruleId ?: "no ruleId"}) has ${locations.size()} " +
                        "location(s) but none with a file path and start line.",
                )
            }
        }
    }

    private fun parseLocation(
        locationElement: JsonElement,
        level: AshLevel,
        levelExplicit: Boolean,
        ruleId: String?,
        message: String,
        scannerName: String?,
    ): AshFinding? {
        val physical = locationElement.asObjectOrNull()
            ?.optObject("physicalLocation")
            ?: return null

        val uri = physical.optObject("artifactLocation")?.optString("uri")
            ?: return null
        // Null means the URI names something this cannot put in an editor -- a non-file scheme, or a
        // remote host. Refused rather than coerced into a project-relative path.
        val path = stripUriScheme(uri) ?: return null

        val region = physical.optObject("region")

        // No startLine means this is not a line/column text region -- it may be a
        // binary region (charOffset/byteOffset, sections 3.30.9 and 3.30.11) or a
        // whole-file location. Either way there is no line to annotate, so it is not
        // a usable finding for an editor annotator.
        val startLine = region?.optInt("startLine") ?: return null
        if (startLine < 1) return null

        // Section 3.30.6: absent startColumn defaults to 1.
        val startColumn = region.optInt("startColumn")?.takeIf { it >= 1 } ?: 1
        // Section 3.30.7: absent endLine defaults to startLine.
        val endLine = region.optInt("endLine")?.takeIf { it >= startLine } ?: startLine
        // Section 3.30.8: absent endColumn means end-of-line, which depends on the
        // file. Left null for AshRangeMapper to resolve; see AshFinding's docs.
        val endColumn = region.optInt("endColumn")?.takeIf { it >= 1 }

        return AshFinding(
            filePath = path,
            startLine = startLine,
            startColumn = startColumn,
            endLine = endLine,
            endColumn = endColumn,
            level = level,
            levelExplicit = levelExplicit,
            ruleId = ruleId,
            message = message,
            scannerName = scannerName,
        )
    }

    /**
     * Implements the section 3.27.10 procedure for determining a result's level.
     *
     * The order is load-bearing and each step is a place a shortcut would be wrong:
     *
     *  1. `kind` defaults to `"fail"` when absent (section 3.27.9). Reading an absent
     *     kind as anything else would silently discard every finding from a scanner
     *     that omits the field, which is most of them.
     *  2. A non-fail kind resolves to `"none"` whatever `level` says. The spec is
     *     explicit that a present level "SHALL have the value none" in that case, so
     *     trusting an inconsistent producer's level here would surface a
     *     `notApplicable` result as an error.
     *  3. An explicit `level` wins.
     *  4. Then `ruleConfigurationOverrides`, then the rule's
     *     `defaultConfiguration.level`.
     *  5. Then `"warning"`.
     *
     * An unrecognized level string is reported and then treated as absent, so it falls
     * through to the rule default rather than being silently mapped to something.
     */
    private fun resolveLevel(
        result: JsonObject,
        ruleIndex: RuleIndex,
        where: String,
        problems: MutableList<String>,
    ): ResolvedLevel {
        val kind = result.optString("kind")?.let(::token) ?: AshLevel.KIND_DEFAULT
        if (kind != AshLevel.KIND_DEFAULT) {
            return ResolvedLevel(AshLevel.NON_FAIL_DEFAULT, explicit = false)
        }

        val rawLevel = result.optString("level")
        AshLevel.describeUnrecognized(rawLevel)?.let { problems.addCapped("$where: $it") }
        // `explicit` is set from the PARSE succeeding, not from the field being
        // present. An unrecognized level string is a present field that yielded
        // nothing, and reporting it as explicit would let the annotator claim a
        // severity came off the wire when it came from the rule default.
        AshLevel.fromSarif(rawLevel)?.let { return ResolvedLevel(it, explicit = true) }

        ruleIndex.defaultLevelFor(result)?.let { return ResolvedLevel(it, explicit = false) }

        return ResolvedLevel(AshLevel.FAIL_DEFAULT, explicit = false)
    }

    private data class ResolvedLevel(val level: AshLevel, val explicit: Boolean)

    internal enum class Suppression { NOT_SUPPRESSED, SUPPRESSED }

    /**
     * Whether the report says this result is suppressed.
     *
     * SARIF 2.1.0 section 3.27.23: an absent or null `suppressions` means suppression information is
     * not available and the result is NOT suppressed; an empty array means the same; a non-empty
     * array means a consumer that needs the state "SHALL examine the status properties (section
     * 3.35.3)" of the suppression objects.
     *
     * TWO FIELD NAMES ARE READ, and that is not belt-and-braces. Section 3.35.3 names the property
     * `status`, with values `accepted`, `underReview` and `rejected`. ASH emits `state` instead --
     * its own model declares `state: Optional[State]` at `sarif_schema_model.py`, and all 92
     * suppression objects in the real report carry a `state` key and no `status` key. A consumer
     * that reads only the spec's name sees nothing on ASH output; one that reads only ASH's name
     * sees nothing on a spec-conformant producer's. Both are null in the real report, so this
     * changes no behaviour there -- it is the case not yet met that it is for.
     *
     * THE ABSENT-STATUS DECISION IS MINE, NOT THE SPEC'S. The spec defines no default for an absent
     * status; it only says to examine it. A non-empty suppressions array with no explicit status is
     * treated here as SUPPRESSED, because section 3.35.1 NOTE 2 says development environments
     * "typically do not expose suppressed results to the user... do not display them in error
     * lists", an editor is such an environment, and the producer writing a justification is an
     * affirmative act. ASH's own justifications say so plainly: "(ASH) Suppressing finding on uri
     * ... based on path match ... with global reason: This is test data".
     *
     * An explicit `rejected` means the team decided NOT to suppress, so the result is shown.
     * `underReview` is also shown: nothing has been decided, and for a security tool hiding a
     * finding whose suppression has not been agreed is the more dangerous direction.
     */
    internal fun suppressionOf(result: JsonObject): Suppression {
        val suppressions = result.optArray("suppressions") ?: return Suppression.NOT_SUPPRESSED
        if (suppressions.size() == 0) return Suppression.NOT_SUPPRESSED

        var anyEffective = false
        suppressions.forEach { element ->
            val suppression = element.asObjectOrNull() ?: return@forEach
            // Spec name first, producer name second; whichever is present decides.
            val status = (suppression.optString("status") ?: suppression.optString("state"))?.let(::token)
            when (status) {
                null, "", "accepted" -> anyEffective = true
                "rejected", "underreview" -> Unit
                // An unrecognized status is not evidence the suppression was withdrawn, so it is
                // treated as effective rather than silently re-displaying the finding.
                else -> anyEffective = true
            }
        }
        return if (anyEffective) Suppression.SUPPRESSED else Suppression.NOT_SUPPRESSED
    }

    /**
     * Strips a `file://` scheme and a Windows drive-letter leading slash.
     *
     * `file:///C:/code/a.cs` -- the form the spec's own example in section 3.27.10
     * uses -- becomes `C:/code/a.cs` rather than `/C:/code/a.cs`, which no filesystem
     * would resolve. Percent-decoding is applied only to `%20`-style escapes that
     * SARIF producers actually emit for spaces; a full URL-decode would corrupt a path
     * containing a literal `%`.
     */
    internal fun stripUriScheme(uri: String): String? {
        val trimmed = uri.trim()
        if (trimmed.isEmpty()) return null

        val scheme = SCHEME.find(trimmed)?.groupValues?.get(1)

        // A ONE-LETTER "SCHEME" IS A WINDOWS DRIVE, NOT A SCHEME. `C:/code/a.cs` matches the RFC
        // 3986 scheme production, so a naive scheme check rejects every Windows path. Checked before
        // anything else for that reason.
        if (scheme != null && scheme.length > 1) {
            if (!scheme.equals("file", ignoreCase = true)) {
                // REFUSED, not joined onto the project root. `https://example.com/app.py` is not
                // absolute and carries no drive letter, so the previous version handed it to
                // AshPathResolver, which joined it to the project base and produced a finding at
                // <project>/https:/example.com/app.py -- a path no file has. The finding was then
                // counted as SURFACED, so the notification said "1 finding" while the editor showed
                // none, with nothing reconciling the two.
                return null
            }

            var rest = trimmed.substring(scheme.length + 1)
            if (rest.startsWith("//")) {
                // Split the authority from the path. `file:///x` has an empty authority and means
                // local `/x`. `file://server/share/x` names a REMOTE host, and discarding it yields
                // `server/share/x`, which resolves to a different file on this machine -- so it is
                // refused rather than silently relocated. RFC 8089 makes `localhost` equivalent to
                // an empty authority, so that one is accepted.
                val afterSlashes = rest.substring(2)
                val slash = afterSlashes.indexOf('/')
                val authority = if (slash >= 0) afterSlashes.substring(0, slash) else afterSlashes
                if (authority.isNotEmpty() && !authority.equals("localhost", ignoreCase = true)) {
                    return null
                }
                rest = if (slash >= 0) afterSlashes.substring(slash) else ""
            }
            // The authority-less `file:/x` form keeps its leading slash: removing `file:/` would
            // leave `x`, turning an absolute path into a relative one.
            var path = rest
            // A leading slash before a drive letter is a URI artifact, not a path.
            if (path.length >= 3 && path[0] == '/' && path[2] == ':') {
                path = path.substring(1)
            }
            return path.replace("%20", " ").takeIf { it.isNotBlank() }
        }

        // No scheme, or a drive letter: a plain path.
        return trimmed.replace("%20", " ").takeIf { it.isNotBlank() }
    }

    /**
     * An enum-valued SARIF string, normalized: trimmed, lowercased, and stripped of a Python enum
     * repr's class prefix, so `Kind.FAIL` and `fail` compare equal. AshLevel applies the same rule
     * to `level`, for the defect AshLevelTest describes.
     */
    private fun token(raw: String): String = raw.trim().substringAfterLast('.').lowercase()

    /** RFC 3986 scheme production. One-letter matches are Windows drives; see [stripUriScheme]. */
    private val SCHEME = Regex("^([A-Za-z][A-Za-z0-9+.\\-]*):")

    /**
     * The rules a run declares, indexed so a result can find its own.
     *
     * Both lookup keys are supported because SARIF offers both and producers differ:
     * `result.ruleIndex` / `result.rule.index` point into `tool.driver.rules` by
     * position, and `result.ruleId` matches a rule's `id`. Supporting only the id
     * would lose the default level for any producer that omits it and relies on the
     * index.
     */
    private class RuleIndex(
        private val byId: Map<String, AshLevel>,
        private val byPosition: List<AshLevel?>,
    ) {
        fun defaultLevelFor(result: JsonObject): AshLevel? {
            val index = result.optInt("ruleIndex")
                ?: result.optObject("rule")?.optInt("index")
            if (index != null && index >= 0 && index < byPosition.size) {
                byPosition[index]?.let { return it }
            }
            val id = result.optString("ruleId") ?: result.optObject("rule")?.optString("id")
            return id?.let { byId[it] }
        }

        companion object {
            /**
             * Indexes `tool.driver.rules` AND every `tool.extensions[].rules`.
             *
             * READING ONLY THE DRIVER'S RULES FINDS NOTHING IN A REAL ASH REPORT. Measured on
             * tests/test_data/outputs/ash_aggregated_results.json: `driver.rules` is EMPTY and
             * all 1,264 rules live across seven extensions, so of the 41 fail-kind results, 0
             * ruleIds resolved against the driver and 38 resolve against the extensions. The
             * lookup was not merely incomplete, it was dead -- and a dead lookup looks identical
             * to "this rule has no default level", which is why it survived every test.
             *
             * ID-KEYED ACROSS ALL COMPONENTS IS SAFE HERE, and that was checked rather than
             * assumed: no rule id appears in more than one extension in that report. If that ever
             * stops holding, the last component wins, which is why the positional map below is
             * kept driver-only.
             *
             * POSITIONAL LOOKUP STAYS DRIVER-ONLY. SARIF section 3.27.6 defines `ruleIndex`
             * relative to the tool component the result's rule belongs to, so indexing into a
             * concatenation of driver and extension rules would silently resolve the wrong rule.
             * Real ASH writes `ruleIndex: -1` on every result, so this path is unused there, but
             * "unused" is not a reason to leave it wrong.
             */
            fun of(run: JsonObject): RuleIndex {
                val byId = mutableMapOf<String, AshLevel>()
                val byPosition = mutableListOf<AshLevel?>()
                val tool = run.optObject("tool")

                fun levelOf(rule: JsonObject?): AshLevel? = rule
                    ?.optObject("defaultConfiguration")
                    ?.optString("level")
                    ?.let { AshLevel.fromSarif(it) }

                tool?.optObject("driver")?.optArray("rules")?.forEach { element ->
                    val rule = element.asObjectOrNull()
                    val level = levelOf(rule)
                    byPosition.add(level)
                    val id = rule?.optString("id")
                    if (id != null && level != null) byId[id] = level
                }

                tool?.optArray("extensions")?.forEach { extensionElement ->
                    extensionElement.asObjectOrNull()?.optArray("rules")?.forEach { element ->
                        val rule = element.asObjectOrNull()
                        val level = levelOf(rule)
                        val id = rule?.optString("id")
                        if (id != null && level != null) byId[id] = level
                    }
                }

                return RuleIndex(byId, byPosition)
            }
        }
    }

    private fun MutableList<String>.addCapped(problem: String) {
        if (size < MAX_PROBLEMS) {
            add(problem)
        } else if (size == MAX_PROBLEMS) {
            add("... further SARIF problems suppressed after $MAX_PROBLEMS.")
        }
    }

    // ------------------------------------------------------------------
    // Gson accessors that return null instead of throwing.
    //
    // Gson's own getAsString on a JsonNull throws, and on a JsonObject returns a
    // rendering of the object rather than failing. Each helper below checks the type
    // before reading, so a SARIF with a field of the wrong shape produces a skipped
    // field rather than an exception that loses the whole file.
    // ------------------------------------------------------------------

    private fun JsonElement.asObjectOrNull(): JsonObject? = if (isJsonObject) asJsonObject else null

    private fun JsonObject.optObject(name: String): JsonObject? =
        get(name)?.takeIf { it.isJsonObject }?.asJsonObject

    private fun JsonObject.optArray(name: String): JsonArray? =
        get(name)?.takeIf { it.isJsonArray }?.asJsonArray

    private fun JsonObject.optString(name: String): String? =
        get(name)?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }?.asString

    private fun JsonObject.optInt(name: String): Int? {
        val primitive = get(name)?.takeIf { it.isJsonPrimitive }?.asJsonPrimitive ?: return null
        return when {
            primitive.isNumber -> primitive.asInt
            // A line number arriving as "12" rather than 12 is out of spec but
            // harmless to accept, and rejecting it would drop a locatable finding.
            primitive.isString -> primitive.asString.trim().toIntOrNull()
            else -> null
        }
    }
}
