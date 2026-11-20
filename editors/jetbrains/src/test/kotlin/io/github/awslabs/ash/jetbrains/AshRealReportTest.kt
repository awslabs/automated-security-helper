// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * Parses a REAL ASH report, not a hand-written fixture.
 *
 * WHY THIS EXISTS. Every other test in this package runs against SARIF authored alongside the
 * parser, and that is exactly why three defects survived them. The hand-written fixture had one
 * scanner, put that scanner's name in `tool.driver.name`, and put its rules in
 * `tool.driver.rules` -- which is the single SARIF shape in which a run-level driver-name read is
 * correct and a driver-rules lookup resolves. The fixture encoded the same assumption as the
 * code, so it could only ever confirm it. All of it passed while the feature was wrong against
 * every report ASH actually writes.
 *
 * What a real ASH report looks like, measured on the file below:
 *
 *   tool.driver.name  = "AWS Labs - Automated Security Helper"   (ASH, not the scanner)
 *   tool.driver.rules = 0 entries
 *   tool.extensions   = 7 (cfn-nag 170, detect-secrets 0, bandit 5, cdk-nag 4,
 *                          checkov 13, grype 10, semgrep 1062 rules)
 *   runs              = 1, results = 126
 *   result.properties.scanner_name = the per-result scanner, present on all 126
 *   result.ruleIndex  = -1 on all 126;  result.rule = null on all 126
 *
 * THE FILE IS THE REPOSITORY'S OWN TEST DATA, referenced rather than copied. Copying a 15 MB
 * artifact into this module would duplicate it and let the copy go stale against the real one.
 * The path is resolved relative to this Gradle project, and a missing file FAILS rather than
 * skipping -- a skipped test is indistinguishable from a passing one in a CI summary, and this
 * is the only test here that sees real data.
 */
class AshRealReportTest {

    /**
     * `reports/ash.sarif` is the `sarif` block of this file verbatim: the SARIF reporter's
     * `report()` returns `model.sarif.model_dump_json(...)`. So parsing that block is parsing
     * exactly what the plugin reads from disk after a real scan.
     */
    private val reportFile: File by lazy {
        val candidates = listOf(
            File("../../tests/test_data/outputs/ash_aggregated_results.json"),
            File("tests/test_data/outputs/ash_aggregated_results.json"),
        )
        candidates.firstOrNull { it.isFile }
            ?: throw AssertionError(
                "cannot find the real ASH report. Looked for " +
                    candidates.joinToString(", ") { it.absolutePath } +
                    ". This test must not be skipped: it is the only coverage against SARIF this " +
                    "plugin did not author, and three defects survived the hand-written fixtures.",
            )
    }

    /**
     * The TOP-LEVEL `sarif` member.
     *
     * Taken by parsing the container and asking for the member by name, which is not a stylistic
     * choice. The first version scanned for the literal `"sarif":` and brace-matched from there,
     * and it matched the WRONG ONE: this report contains two such keys, and the first at offset
     * 7,381 is a reporter-configuration entry inside `ash_config`
     * (`{"enabled": true, "extension": "sarif", "name": "sarif", ...}`), while the real document is
     * at 7,593,078. The test then reported zero findings and every assertion failed -- which read
     * as three parser defects and was in fact one harness defect measuring an adjacent object.
     *
     * Using Gson here does not weaken the test: the container is not the code under test, and
     * [AshSarifParser] still receives a SARIF string and does its own parsing.
     */
    private val sarifText: String by lazy {
        val root = com.google.gson.JsonParser.parseString(reportFile.readText())
        assertTrue("report root is not a JSON object", root.isJsonObject)
        val sarif = root.asJsonObject.get("sarif")
        assertNotNull("report has no top-level \"sarif\" member", sarif)
        assertTrue("top-level \"sarif\" is not an object", sarif.isJsonObject)
        // A quick shape check, so a future report that moves the runs elsewhere fails here with a
        // clear reason rather than as a mysterious zero-findings result.
        assertTrue(
            "the top-level \"sarif\" member has no \"runs\" array -- this is probably not the " +
                "SARIF document (the reporter-config entry of the same name has no runs)",
            sarif.asJsonObject.get("runs")?.isJsonArray == true,
        )
        sarif.toString()
    }

    private val parsed: AshScanResults by lazy { AshSarifParser.parse(sarifText) }

    @Test
    fun parsesTheRealReportWithoutLosingResults() {
        // 41 of 126 results are kind=fail; the other 85 are kind=informational with level=none,
        // which SARIF 3.27.10 says carry no severity and which this parser drops by design. Every
        // one of the 126 is locatable, so nothing is lost to a missing region.
        assertEquals(34, parsed.findings.size)
        assertEquals(
            "a real report must parse with no complaints; any problem here is a shape this " +
                "parser does not understand",
            emptyList<String>(),
            parsed.problems,
        )

        // THE CLOSURE INVARIANT. Every one of the 126 results lands in exactly one bucket, so a
        // result that falls out of the parser uncounted -- a new early return, a missed increment --
        // fails here even when each separate count still looks plausible.
        //
        // IT IS NOT EVIDENCE ABOUT THE GRYPE PATH DEFECT, and an earlier version of this comment
        // said it was. That finding was produced and counted as surfaced; it then failed to match an
        // open file downstream in AshPathResolver, which runs after this tally. The invariant holds
        // identically before and after that fix. See grypeRootAbsolutePathsResolveIntoTheProject...
        // below, which says plainly that a count cannot catch it.
        //
        // Paired with an expected totalResults deliberately: all-zero counts satisfy the invariant,
        // so asserting it alone would pass on every parse-failure path.
        assertEquals(126, parsed.totalResults)
        assertEquals(92, parsed.suppressedResults)
        assertEquals(34, parsed.surfacedResults)
        assertEquals(0, parsed.noSeverityResults)
        assertEquals(0, parsed.unlocatableResults)
        assertTrue(
            "every result must land in exactly one bucket: ${parsed.suppressedResults} " +
                "suppressed + ${parsed.noSeverityResults} non-failure + " +
                "${parsed.unlocatableResults} unlocatable + ${parsed.surfacedResults} surfaced " +
                "!= ${parsed.totalResults}",
            parsed.accountsForEveryResult,
        )
    }

    @Test
    fun inSourceSuppressedFailuresAreNotResurfaced() {
        // The 7 results a level-based filter re-displays: 5 checkov warnings and 2 semgrep errors,
        // every one `kind=fail` with a real level and `suppression.kind: "inSource"`. An in-source
        // suppression is the most deliberate kind -- someone wrote it next to the code -- so
        // showing it again is the worst version of this defect.
        //
        // 92 results are suppressed but only 85 are informational/none, so filtering on level
        // rather than on suppression state misses exactly these 7.
        assertEquals(92, parsed.suppressedResults)
        assertEquals(
            "no suppressed checkov warning may reappear",
            0,
            parsed.findings.count { it.scannerName == "checkov" && it.level == AshLevel.WARNING },
        )
        // And nothing at all is surfaced at warning level on this report, because all 5 warnings
        // were the suppressed checkov ones.
        assertEquals(0, parsed.findings.count { it.level == AshLevel.WARNING })
    }

    @Test
    fun anUnsuppressedInformationalResultIsStillDroppedAsANonFailure() {
        // The two filters answer different questions, so each needs its own arm. This report
        // happens to have no unsuppressed informational result -- noSeverityResults is 0 -- which
        // is why the kind check cannot be tested against it directly and is synthesised here.
        val oneInformational = """
            {"version":"2.1.0","runs":[{"tool":{"driver":{"name":"ash"}},"results":[
              {"ruleId":"R1","kind":"informational","level":"none",
               "message":{"text":"not a failure"},
               "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},
                 "region":{"startLine":1}}}]}
            ]}]}
        """.trimIndent()
        val r = AshSarifParser.parse(oneInformational)
        assertEquals(emptyList<AshFinding>(), r.findings)
        assertEquals(1, r.totalResults)
        assertEquals(0, r.suppressedResults)
        assertEquals(1, r.noSeverityResults)
        assertTrue(r.accountsForEveryResult)
    }

    @Test
    fun aRejectedSuppressionIsShown() {
        // An explicit `rejected` status means the team decided NOT to suppress, so the finding must
        // still appear. Synthesised because the real report's suppressions carry no status at all.
        // Both field names are exercised: the spec calls it `status` (section 3.35.3) and ASH emits
        // `state`.
        for (field in listOf("status", "state")) {
            val rejected = """
                {"version":"2.1.0","runs":[{"tool":{"driver":{"name":"ash"}},"results":[
                  {"ruleId":"R1","kind":"fail","level":"error","message":{"text":"still live"},
                   "suppressions":[{"kind":"inSource","$field":"rejected"}],
                   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},
                     "region":{"startLine":1}}}]}
                ]}]}
            """.trimIndent()
            val r = AshSarifParser.parse(rejected)
            assertEquals("a rejected suppression must not hide the finding ($field)", 1, r.findings.size)
            assertEquals(0, r.suppressedResults)
            assertEquals(1, r.surfacedResults)
        }
    }

    @Test
    fun anAcceptedOrUnspecifiedSuppressionHidesTheFinding() {
        for (suppression in listOf(
            """{"kind":"external"}""",
            """{"kind":"external","state":null}""",
            """{"kind":"inSource","status":"accepted"}""",
            """{"kind":"inSource","state":"accepted"}""",
        )) {
            val text = """
                {"version":"2.1.0","runs":[{"tool":{"driver":{"name":"ash"}},"results":[
                  {"ruleId":"R1","kind":"fail","level":"error","message":{"text":"hidden"},
                   "suppressions":[$suppression],
                   "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},
                     "region":{"startLine":1}}}]}
                ]}]}
            """.trimIndent()
            val r = AshSarifParser.parse(text)
            assertEquals("suppression $suppression must hide it", 0, r.findings.size)
            assertEquals(1, r.suppressedResults)
            assertTrue(r.accountsForEveryResult)
        }
        // An EMPTY suppressions array explicitly means not suppressed (section 3.27.23).
        val empty = """
            {"version":"2.1.0","runs":[{"tool":{"driver":{"name":"ash"}},"results":[
              {"ruleId":"R1","kind":"fail","level":"error","message":{"text":"shown"},
               "suppressions":[],
               "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},
                 "region":{"startLine":1}}}]}
            ]}]}
        """.trimIndent()
        assertEquals(1, AshSarifParser.parse(empty).findings.size)
    }

    @Test
    fun attributesEachFindingToItsOwnScannerNotToAsh() {
        // DEFECT 1 and 2. Before the fix every finding was attributed to the driver name, so this
        // asserted set would have been the single string "AWS Labs - Automated Security Helper".
        val scanners = parsed.findings.mapNotNull { it.scannerName }.toSortedSet()
        assertEquals(
            setOf("bandit", "checkov", "detect-secrets", "grype", "semgrep"),
            scanners.toSet(),
        )
        assertFalse(
            "no finding may be attributed to ASH itself; that is the aggregator, not the scanner",
            parsed.findings.any { it.scannerName?.contains("Automated Security Helper") == true },
        )
        // Cardinality: one run, many scanners. A run-level read cannot produce more than one.
        assertTrue("expected several distinct scanners in ONE run", scanners.size >= 5)
    }

    @Test
    fun perScannerCountsMatchTheReport() {
        val counts = parsed.findings.groupingBy { it.scannerName }.eachCount()
        // checkov 4 not 9, semgrep 7 not 9: 5 checkov and 2 semgrep results are inSource-suppressed.
        // cdk-nag and cfn-nag are absent entirely -- every one of their findings is suppressed -- so
        // the surfaced set has 5 scanners while extensions[] advertises 7. An assertion of "one
        // scanner per extension entry" would be wrong.
        assertEquals(
            mapOf(
                "detect-secrets" to 11,
                "bandit" to 11,
                "semgrep" to 7,
                "checkov" to 4,
                "grype" to 1,
            ),
            counts,
        )
    }

    @Test
    fun ruleIndexOfMinusOneIsIgnoredRatherThanIndexing() {
        // Every real result carries ruleIndex -1 and rule null. -1 must not index anything: on a
        // list accessor it would throw, and this parser's guard is the reason it does not.
        // Asserted through the public parse rather than by calling the guard, so the assertion is
        // about behaviour and not about an internal.
        assertEquals(34, parsed.findings.size)
        assertTrue(
            "every finding's level came off the result itself, because real ASH writes an " +
                "explicit level on all 126 results",
            parsed.findings.all { it.levelExplicit },
        )
    }

    @Test
    fun severitiesMatchTheReportsOwnLevels() {
        val byLevel = parsed.findings.groupingBy { it.level }.eachCount()
        // NO WARNINGS AT ALL, which looks like a bug and is not: all 5 warning-level results are
        // checkov findings suppressed in source, so a correct surfaced set has only errors and notes.
        assertEquals(
            mapOf(AshLevel.ERROR to 32, AshLevel.NOTE to 2),
            byLevel,
        )
        assertFalse(
            "a `none` level carries no severity and must not be surfaced",
            parsed.findings.any { it.level == AshLevel.NONE },
        )
    }

    @Test
    fun ruleMetadataResolvesThroughExtensionsWhenItIsConsulted() {
        // DEFECT 3, tested on the real rule tables rather than on the results.
        //
        // It cannot be tested through the results of this report, because all 126 carry an
        // explicit `level` and so never consult rule metadata -- which is precisely why the dead
        // lookup was invisible. So the report's own extension rules are fed to the parser with
        // the levels stripped from the results, and the levels must then come from the rules.
        // Stripped STRUCTURALLY, not by string replacement. A previous version replaced
        // `"level": "error"` with a space after the colon; sarifText comes from Gson's toString(),
        // which is compact (`"level":"error"`), so the replacement matched nothing, no level was
        // removed, and the test reported 0 inherited of 41 -- reading as a dead rule lookup when
        // it was a dead find-and-replace.
        val root = com.google.gson.JsonParser.parseString(sarifText).asJsonObject
        for (runElement in root.getAsJsonArray("runs")) {
            val results = runElement.asJsonObject.getAsJsonArray("results") ?: continue
            for (resultElement in results) {
                resultElement.asJsonObject.remove("level")
            }
        }
        val reparsed = AshSarifParser.parse(root.toString())

        assertEquals("stripping result levels must not lose findings", 34, reparsed.findings.size)
        val inherited = reparsed.findings.filter { !it.levelExplicit }
        assertEquals(
            "every finding must now take its level from rule metadata or the spec default",
            34,
            inherited.size,
        )
        // Of the 34 surfaced findings, 4 have a ruleId whose extension rule declares a level other
        // than `warning` (all four `error`); the remaining 30 either have no rule-declared level or
        // a rule that says `warning`, so they land on `warning` either way. If the extension tables
        // were not being read, ALL 34 would fall through to the spec default and this would be 0 --
        // which is exactly what the dead driver-only lookup produced.
        //
        // Derived from the report rather than copied from a failure message: the earlier 9 was
        // measured over the pre-suppression 41-finding set.
        // ASSERTED AS A DISTRIBUTION, NOT AS A `!= DEFAULT` COUNT, and that distinction is the point.
        //
        // The obvious form is `count { it.level != AshLevel.WARNING }`, and it is coupled to
        // FAIL_DEFAULT: the 30 findings that land on `warning` do so either because their rule says
        // `warning` or because no rule level exists and the spec default applies. If FAIL_DEFAULT ever
        // changed to `error`, `!= WARNING` would stop separating "inherited from a rule" from "fell to
        // the default" -- the two would collapse, and the assertion would be measuring nothing even
        // though it still has a number in it.
        //
        // A full distribution changes visibly instead. It is also the count-is-not-a-set lesson: the
        // two buckets are named, so a shift between them cannot cancel out in a total.
        assertEquals(
            "inherited severities, by level",
            mapOf(AshLevel.WARNING to 30, AshLevel.ERROR to 4),
            inherited.groupingBy { it.level }.eachCount(),
        )
    }

    @Test
    fun everyFindingHasAUsableFileAndLine() {
        for (f in parsed.findings) {
            assertNotNull("finding without a path: $f", f.filePath)
            assertTrue("path must not be blank: $f", f.filePath.isNotBlank())
            assertTrue("startLine must be 1-based and positive: $f", f.startLine >= 1)
            assertTrue("endLine must not precede startLine: $f", f.endLine >= f.startLine)
            assertTrue("startColumn must be 1-based: $f", f.startColumn >= 1)
        }
        // BOTH region shapes occur in one real report, which is what makes this worth asserting:
        // 19 of the 34 surfaced findings carry startColumn/endColumn and 15 omit them. So the
        // explicit-column path and the spec's end-of-line default are both exercised by real data,
        // rather than one of them being reachable only from a hand-written fixture.
        //
        // These numbers have been wrong twice, both times from measuring the wrong population. The
        // first version asserted "most omit endColumn", true of all 126 (dominated by the 85
        // informational results) and false of the surfaced set. The second said 21/20, measured
        // before suppressions were honoured; two of those were suppressed semgrep results.
        val withExplicitEnd = parsed.findings.count { it.endColumn != null }
        val withDefaultedEnd = parsed.findings.count { it.endColumn == null }
        assertEquals(19, withExplicitEnd)
        assertEquals(15, withDefaultedEnd)
        assertEquals(34, withExplicitEnd + withDefaultedEnd)
    }

    @Test
    fun grypeRootAbsolutePathsResolveIntoTheProjectRatherThanVanishing() {
        // The 4th defect, against the real report's own URIs.
        //
        // 14 of the 126 results carry a URI beginning with '/', every one of them grype, and none
        // of them exists at that absolute location -- grype reports scan-root-relative paths with
        // a leading slash. A COUNT CANNOT CATCH THIS: all 126 still parse and the findings are
        // still produced; they simply key to a path no open file has, so they disappear from the
        // editor with no error. Count is not a set.
        //
        // The existence oracle describes a checkout where those files are present, because they
        // are not present on whatever machine runs this test -- which is exactly why an
        // unparameterised existence check could not be asserted here.
        val base = "/home/u/proj"

        // Taken from the report's own URIs rather than from parsed findings, because 13 of the 14
        // are kind=informational and this parser drops those before path resolution ever runs. The
        // resolver still has to handle them: a project where grype reports real vulnerabilities
        // would have every one of them in this shape.
        val root = com.google.gson.JsonParser.parseString(sarifText).asJsonObject
        val leadingSlashUris = mutableListOf<String>()
        for (runElement in root.getAsJsonArray("runs")) {
            for (resultElement in runElement.asJsonObject.getAsJsonArray("results")) {
                val uri = resultElement.asJsonObject
                    .getAsJsonArray("locations")?.firstOrNull()
                    ?.asJsonObject?.getAsJsonObject("physicalLocation")
                    ?.getAsJsonObject("artifactLocation")
                    ?.get("uri")?.takeIf { !it.isJsonNull }?.asString
                if (uri != null && uri.startsWith("/")) leadingSlashUris.add(uri)
            }
        }
        assertEquals("expected the real report's 14 grype root-absolute URIs", 14, leadingSlashUris.size)

        for (uri in leadingSlashUris) {
            val key = AshPathResolver.toAbsoluteKey(uri, base, exists = { it.startsWith("$base/") })
            assertTrue(
                "grype path $uri must resolve under the project root, was $key",
                key.startsWith("$base/"),
            )
            assertFalse("must not key on a bare scan-root path: $key", key == uri)
        }

        // And the one that is kind=fail, so the one a user would actually lose from the editor.
        val poetry = parsed.findings.firstOrNull { it.filePath == "/poetry.lock" }
        assertNotNull("expected the real report's /poetry.lock grype finding to be surfaced", poetry)
        assertEquals(
            "$base/poetry.lock",
            AshPathResolver.toAbsoluteKey(
                poetry!!.filePath,
                base,
                exists = { it == "$base/poetry.lock" },
            ),
        )
    }

    @Test
    fun ruleIdsSurviveParsing() {
        // The rule id is half the attribution the Problems view shows, so losing it would degrade
        // every row to a bare "ASH [scanner]".
        val withRuleId = parsed.findings.count { !it.ruleId.isNullOrBlank() }
        assertEquals("every real finding carries a ruleId", parsed.findings.size, withRuleId)
    }
}
