// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The parser against SARIF of the wrong SHAPE: a field that is an array where an object was
 * expected, a number where a string was, an entry missing its parent.
 *
 * Every one of these is a place the parser could throw and lose the whole file, or skip a
 * result without counting it. So each test asserts two things: what was kept, and that the
 * result tally still accounts for every result (AshScanResults.accountsForEveryResult, always
 * paired with an expected total, because it is vacuously true on zeroes).
 */
class AshSarifParserShapeTest {

    private fun run(body: String) = """{"version":"2.1.0","runs":[$body]}"""

    private fun loc(uri: String = "a.py", region: String = """"startLine": 1""") =
        """{"physicalLocation":{"artifactLocation":{"uri":"$uri"},"region":{$region}}}"""

    private fun parseResults(vararg results: String, tool: String = """"tool":{"driver":{"name":"drv"}}""") =
        AshSarifParser.parse(run("""{$tool,"results":[${results.joinToString(",")}]}"""))

    private fun assertAccounted(parsed: AshScanResults, total: Int) {
        assertEquals(total, parsed.totalResults)
        assertTrue("every result must land in one bucket", parsed.accountsForEveryResult)
    }

    @Test
    fun nonObjectRunsAndResultsAreReportedAndSkipped() {
        val parsed = AshSarifParser.parse(run("""7, {"results":[ "x", {"level":"error","locations":[${loc()}]} ]}, {}"""))
        assertEquals(1, parsed.findings.size)
        assertTrue(parsed.problems.toString(), parsed.problems.any { it == "runs[0] is not an object; skipped." })
        assertTrue(parsed.problems.toString(), parsed.problems.any { it == "runs[1].results[0] is not an object; skipped." })
        // The run with no results array contributes nothing and is not an error.
        assertAccounted(parsed, 1)
    }

    @Test
    fun aRootThatIsNotAnObjectIsReported() {
        for (text in listOf("null", "[]", "3")) {
            val parsed = AshSarifParser.parse(text)
            assertEquals(listOf("SARIF root is not a JSON object."), parsed.problems)
        }
    }

    @Test
    fun aDocumentOfWhichNothingCanBeReadIsMarkedUnreadable() {
        // Truncated mid-write, empty, a bare value, and an object that is not SARIF.
        for (text in listOf("""{"version":"2.1.0","runs":[{"results":[""", "", "[]", "null", """{"version":"2.1.0"}""")) {
            val parsed = AshSarifParser.parse(text)
            assertTrue("must be unreadable: '$text'", parsed.unreadableReason != null)
            assertEquals(listOf(parsed.unreadableReason), parsed.problems)
        }
        // A report with no runs in it is readable SARIF that found nothing, not an unreadable one,
        // and neither is a report with one malformed part.
        for (text in listOf("""{"runs":[]}""", run("7"))) {
            assertNull(text, AshSarifParser.parse(text).unreadableReason)
        }
    }

    @Test
    fun scannerNameFallsBackToTheDriverAndToNothing() {
        val withProperty = """{"level":"error","properties":{"scanner_name":"bandit"},"locations":[${loc()}]}"""
        val blankProperty = """{"level":"error","properties":{"scanner_name":"  "},"locations":[${loc()}]}"""
        val noProperties = """{"level":"error","locations":[${loc()}]}"""
        assertEquals(
            listOf("bandit", "drv", "drv"),
            parseResults(withProperty, blankProperty, noProperties).findings.map { it.scannerName },
        )
        for (tool in listOf(""""tool":{}""", """"tool":{"driver":{}}""", """"other":1""")) {
            assertNull(tool, parseResults(noProperties, tool = tool).findings.single().scannerName)
        }
    }

    @Test
    fun aMissingOrBlankMessageGetsAPlaceholderRatherThanAnEmptyTooltip() {
        val parsed = parseResults(
            """{"level":"error","locations":[${loc()}]}""",
            """{"level":"error","message":{},"locations":[${loc()}]}""",
            """{"level":"error","message":{"text":"   "},"locations":[${loc()}]}""",
        )
        assertEquals(List(3) { "ASH reported a finding with no message text." }, parsed.findings.map { it.message })
    }

    @Test
    fun unlocatableResultsAreCountedAndNamedEvenWithoutARuleId() {
        val parsed = parseResults(
            """{"level":"error","locations":[]}""",
            """{"level":"error","locations":[ 5, {}, {"physicalLocation":{}}, {"physicalLocation":{"artifactLocation":{}}} ]}""",
        )
        assertEquals(0, parsed.findings.size)
        assertEquals(2, parsed.unlocatableResults)
        assertTrue(parsed.problems.toString(), parsed.problems[0].contains("(no ruleId) has no locations"))
        assertTrue(parsed.problems.toString(), parsed.problems[1].contains("(no ruleId) has 4 location(s) but none"))
        assertAccounted(parsed, 2)
    }

    @Test
    fun regionValuesOutsideTheSpecFallBackToItsDefaults() {
        val findings = parseResults(
            // startLine 0 is not a line.
            """{"level":"error","locations":[${loc(region = """"startLine": 0""")}]}""",
            // Column 0, an endLine before the start and endColumn 0 all fall back to the defaults.
            """{"level":"error","locations":[${loc(region = """"startLine": 5, "startColumn": 0, "endLine": 2, "endColumn": 0""")}]}""",
            // Numbers as strings are read; a string that is not a number is absent; a boolean is absent.
            """{"level":"error","locations":[${loc(region = """"startLine": "7", "startColumn": "x", "endColumn": true""")}]}""",
            // A region that is an object with no startLine at all.
            """{"level":"error","locations":[${loc(region = """"charOffset": 3""")}]}""",
        ).findings
        assertEquals(listOf(5, 7), findings.map { it.startLine })
        assertEquals(listOf(1, 1), findings.map { it.startColumn })
        assertEquals(listOf(5, 7), findings.map { it.endLine })
        assertEquals(listOf<Int?>(null, null), findings.map { it.endColumn })
    }

    @Test
    fun fieldsOfTheWrongTypeAreAbsentRatherThanRenderedAsText() {
        // Gson renders an object's getAsString as its JSON text; the accessors refuse it.
        val parsed = parseResults(
            """{"ruleId":{"x":1},"level":["error"],"kind":3,"message":{"text":4},"locations":[${loc()}]}""",
        )
        val finding = parsed.findings.single()
        assertNull(finding.ruleId)
        assertEquals("non-string level falls through to the default", AshLevel.WARNING, finding.level)
        assertEquals("ASH reported a finding with no message text.", finding.message)
    }

    @Test
    fun suppressionStatusesAreReadUnderBothNames() {
        fun suppressed(status: String) =
            """{"level":"error","suppressions":[$status],"locations":[${loc()}]}"""
        val parsed = parseResults(
            suppressed("""{"status":"underReview"}"""),
            suppressed("""{"state":"Status.REJECTED"}"""),
            suppressed("""{"status":"somethingNew"}"""),
            suppressed("""{}"""),
            suppressed("""7"""),
            """{"level":"error","suppressions":[],"locations":[${loc()}]}""",
        )
        // underReview, rejected, the non-object entry and the empty array are shown; the
        // unrecognized status and the status-less suppression are effective.
        assertEquals(4, parsed.findings.size)
        assertEquals(2, parsed.suppressedResults)
        assertAccounted(parsed, 6)
    }

    @Test
    fun uriShapesThatNameNoFileAreRefused() {
        assertNull(AshSarifParser.stripUriScheme("   "))
        assertNull(AshSarifParser.stripUriScheme("%20"))
        // An authority with no path names the host's root, which is nothing a file can be.
        assertNull(AshSarifParser.stripUriScheme("file://localhost"))
        assertEquals("/x", AshSarifParser.stripUriScheme("file://localhost/x"))
        // A slash, then something that is not a drive letter, keeps its slash.
        assertEquals("/ab/c", AshSarifParser.stripUriScheme("file:///ab/c"))
        // And a slash before a drive letter is a URI artifact, so it goes.
        assertEquals("a:", AshSarifParser.stripUriScheme("file:///a:"))
    }

    @Test
    fun ruleDefaultsAreFoundByEveryKeyAndIgnoreMalformedRules() {
        val tool = """"tool":{"driver":{"name":"drv","rules":[
            {"id":"D0","defaultConfiguration":{"level":"error"}},
            {"id":"D1"},
            7,
            {"defaultConfiguration":{"level":"note"}}
        ]},"extensions":[
            3,
            {"name":"no-rules"},
            {"rules":[ 1, {"id":"X1","defaultConfiguration":{"level":"note"}}, {"defaultConfiguration":{"level":"error"}}, {"id":"X2"} ]}
        ]}"""
        val parsed = parseResults(
            // By rule.index into the driver.
            """{"rule":{"index":0},"locations":[${loc()}]}""",
            // An index past the end, and an index whose rule has no level, fall through to the id.
            """{"ruleIndex":99,"ruleId":"X1","locations":[${loc()}]}""",
            """{"ruleIndex":1,"rule":{"id":"X1"},"locations":[${loc()}]}""",
            // An id nobody declared, and a negative index, end at the spec default.
            """{"ruleIndex":-1,"ruleId":"nobody","locations":[${loc()}]}""",
            """{"locations":[${loc()}]}""",
            tool = tool,
        )
        assertEquals(
            listOf(AshLevel.ERROR, AshLevel.NOTE, AshLevel.NOTE, AshLevel.WARNING, AshLevel.WARNING),
            parsed.findings.map { it.level },
        )
        assertEquals(listOf(false, false, false, false, false), parsed.findings.map { it.levelExplicit })
    }

    @Test
    fun problemsAreCappedSoABrokenReportCannotFloodTheNotification() {
        val parsed = parseResults(*Array(60) { """{"level":"error","locations":[]}""" })
        assertEquals(51, parsed.problems.size)
        assertEquals("... further SARIF problems suppressed after 50.", parsed.problems.last())
        assertAccounted(parsed, 60)
    }
}
