// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Tests for reading an ASH SARIF report.
 *
 * Runs on the JVM with no IDE booted. The IntelliJ Platform jars are on the test
 * classpath (that is where Gson comes from), but nothing here starts an Application --
 * so these are fast, and a failure points at the parser rather than at the platform.
 */
class AshSarifParserTest {

    private fun sarif(results: String, rules: String = "", driverName: String = "ash"): String = """
        {
          "version": "2.1.0",
          "runs": [
            {
              "tool": { "driver": { "name": "$driverName"${if (rules.isBlank()) "" else ", \"rules\": [$rules]"} } },
              "results": [$results]
            }
          ]
        }
    """.trimIndent()

    private fun result(
        ruleId: String = "R1",
        level: String? = "error",
        kind: String? = null,
        uri: String = "src/app.py",
        region: String = """"startLine": 3""",
        ruleIndex: Int? = null,
    ): String = buildString {
        append("{")
        append(""""ruleId": "$ruleId",""")
        if (level != null) append(""""level": "$level",""")
        if (kind != null) append(""""kind": "$kind",""")
        if (ruleIndex != null) append(""""ruleIndex": $ruleIndex,""")
        append(""""message": { "text": "problem here" },""")
        append(""""locations": [ { "physicalLocation": {""")
        append(""""artifactLocation": { "uri": "$uri" },""")
        append(""""region": { $region }""")
        append("} } ]")
        append("}")
    }

    @Test
    fun mapsEachSarifLevelToItsOwnSeverity() {
        val results = listOf("error", "warning", "note")
            .mapIndexed { i, lvl -> result(ruleId = "R$i", level = lvl, region = """"startLine": ${i + 1}""") }
            .joinToString(",")
        val parsed = AshSarifParser.parse(sarif(results))

        assertEquals(emptyList<String>(), parsed.problems)
        assertEquals(
            listOf(AshLevel.ERROR, AshLevel.WARNING, AshLevel.NOTE),
            parsed.findings.map { it.level },
        )
        assertTrue("all three levels were explicit in the SARIF", parsed.findings.all { it.levelExplicit })
    }

    @Test
    fun readsAnEnumReprLevelAsItsValue() {
        // The severity-downgrade defect, end to end: a producer that wrote str(Level.error)
        // must still be read as an error, not defaulted to a warning.
        val parsed = AshSarifParser.parse(sarif(result(level = "Level.error")))
        assertEquals(1, parsed.findings.size)
        assertEquals(AshLevel.ERROR, parsed.findings[0].level)
        assertTrue(parsed.findings[0].levelExplicit)
        assertEquals(emptyList<String>(), parsed.problems)
    }

    @Test
    fun absentLevelInheritsTheRuleDefaultConfiguration() {
        val rules = """{ "id": "R1", "defaultConfiguration": { "level": "error" } }"""
        val parsed = AshSarifParser.parse(sarif(result(level = null), rules = rules))

        assertEquals(1, parsed.findings.size)
        assertEquals(AshLevel.ERROR, parsed.findings[0].level)
        // Inherited, not read off the result -- the tooltip says so, and this is the
        // assertion that keeps that claim true.
        assertFalse(parsed.findings[0].levelExplicit)
    }

    @Test
    fun absentLevelFindsTheRuleByIndexWhenThereIsNoMatchingId() {
        // A producer that emits ruleIndex and a rules array whose ids do not match the
        // result's ruleId. Supporting only id lookup would lose this rule's severity.
        val rules = """{ "id": "different-id", "defaultConfiguration": { "level": "note" } }"""
        val parsed = AshSarifParser.parse(
            sarif(result(ruleId = "R1", level = null, ruleIndex = 0), rules = rules),
        )
        assertEquals(1, parsed.findings.size)
        assertEquals(AshLevel.NOTE, parsed.findings[0].level)
    }

    @Test
    fun absentLevelAndNoRuleMetadataDefaultsToWarning() {
        // SARIF 2.1.0 section 3.27.10: "IF level has not yet been set THEN SET level to
        // warning".
        val parsed = AshSarifParser.parse(sarif(result(level = null)))
        assertEquals(1, parsed.findings.size)
        assertEquals(AshLevel.WARNING, parsed.findings[0].level)
        assertFalse(parsed.findings[0].levelExplicit)
    }

    @Test
    fun absentKindIsReadAsFail() {
        // Section 3.27.9: kind defaults to "fail". Reading an absent kind as anything else
        // would discard findings from every scanner that omits the field.
        val parsed = AshSarifParser.parse(sarif(result(level = "error", kind = null)))
        assertEquals(1, parsed.findings.size)
        assertEquals(AshLevel.ERROR, parsed.findings[0].level)
    }

    @Test
    fun nonFailKindsAreDroppedEvenWhenTheyCarryASeverity() {
        // Section 3.27.10: for a non-fail kind, level "SHALL have the value none". A
        // producer that contradicts that must not get a notApplicable result rendered as
        // an error.
        for (kind in listOf("pass", "notApplicable", "informational", "open")) {
            val parsed = AshSarifParser.parse(sarif(result(level = "error", kind = kind)))
            assertEquals("kind=$kind must not surface", emptyList<AshFinding>(), parsed.findings)
        }
    }

    @Test
    fun unrecognizedLevelIsReportedAndFallsThroughToTheRuleDefault() {
        val rules = """{ "id": "R1", "defaultConfiguration": { "level": "note" } }"""
        val parsed = AshSarifParser.parse(sarif(result(level = "critical"), rules = rules))

        assertEquals(1, parsed.findings.size)
        assertEquals(AshLevel.NOTE, parsed.findings[0].level)
        // A present-but-unreadable level is not explicit: the severity came from the rule.
        assertFalse(parsed.findings[0].levelExplicit)
        assertEquals(1, parsed.problems.size)
        assertTrue(parsed.problems[0].contains("critical"))
    }

    @Test
    fun appliesTheSpecRegionDefaults() {
        val parsed = AshSarifParser.parse(sarif(result(region = """"startLine": 7""")))
        val f = parsed.findings.single()
        assertEquals(7, f.startLine)
        // Section 3.30.6: absent startColumn defaults to 1.
        assertEquals(1, f.startColumn)
        // Section 3.30.7: absent endLine defaults to startLine.
        assertEquals(7, f.endLine)
        // Section 3.30.8: absent endColumn means end-of-line, which depends on the file,
        // so the parser must NOT invent a number here.
        assertNull(f.endColumn)
    }

    @Test
    fun keepsExplicitRegionBounds() {
        val parsed = AshSarifParser.parse(
            sarif(result(region = """"startLine": 2, "startColumn": 5, "endLine": 3, "endColumn": 9""")),
        )
        val f = parsed.findings.single()
        assertEquals(2, f.startLine)
        assertEquals(5, f.startColumn)
        assertEquals(3, f.endLine)
        assertEquals(9, f.endColumn)
    }

    @Test
    fun resultWithNoLocationIsReportedNotSilentlyDropped() {
        val noLocation = """
            { "ruleId": "R9", "level": "error", "message": { "text": "no location" } }
        """.trimIndent()
        val parsed = AshSarifParser.parse(sarif("$noLocation,${result()}"))

        // The locatable one still lands...
        assertEquals(1, parsed.findings.size)
        // ...and the other is accounted for, because "1 finding" over a report with two
        // results is a count that understates the scan.
        assertEquals(1, parsed.problems.size)
        assertTrue(parsed.problems[0].contains("R9"))
    }

    @Test
    fun regionWithoutStartLineIsReportedNotSilentlyDropped() {
        // A binary region (section 3.30.3) has byteOffset rather than startLine. There is
        // no line to annotate, but the finding must not vanish without a word.
        val binary = """
            { "ruleId": "RB", "level": "error", "message": { "text": "binary" },
              "locations": [ { "physicalLocation": {
                "artifactLocation": { "uri": "a.bin" },
                "region": { "byteOffset": 16, "byteLength": 4 } } } ] }
        """.trimIndent()
        val parsed = AshSarifParser.parse(sarif(binary))
        assertEquals(emptyList<AshFinding>(), parsed.findings)
        assertEquals(1, parsed.problems.size)
        assertTrue(parsed.problems[0].contains("RB"))
    }

    @Test
    fun carriesRuleIdMessageAndScannerName() {
        val parsed = AshSarifParser.parse(sarif(result(ruleId = "B105"), driverName = "bandit"))
        val f = parsed.findings.single()
        assertEquals("B105", f.ruleId)
        assertEquals("bandit", f.scannerName)
        assertEquals("problem here", f.message)
        assertEquals("src/app.py", f.filePath)
    }

    @Test
    fun aNonFileSchemeIsRefusedRatherThanJoinedOntoTheProject() {
        // An https URI is not absolute and has no drive letter, so before the scheme guard it was
        // handed to AshPathResolver, joined to the project base, and produced a finding at
        // <project>/https:/example.com/app.py -- a path no file has. The finding was then counted as
        // SURFACED, so the notification said "1 finding" while the editor showed none.
        for (scheme in listOf("https", "http", "ftp", "s3", "git+ssh")) {
            val uri = "$scheme://example.com/app.py"
            assertNull("$uri must be refused", AshSarifParser.stripUriScheme(uri))

            val parsed = AshSarifParser.parse(sarif(result(uri = uri)))
            assertEquals("$uri must produce no finding", emptyList<AshFinding>(), parsed.findings)
            // And it must be ACCOUNTED FOR, not vanish: unlocatable, never surfaced.
            assertEquals(1, parsed.totalResults)
            assertEquals(0, parsed.surfacedResults)
            assertEquals(1, parsed.unlocatableResults)
            assertTrue(parsed.accountsForEveryResult)
            assertTrue("and reported: ${parsed.problems}", parsed.problems.isNotEmpty())
        }
    }

    @Test
    fun aUncFileUriIsRefusedRatherThanRelocatedIntoTheProject() {
        // `file://server/share/app.py` names a remote host. Stripping `file://` leaves
        // `server/share/app.py`, which is relative, so it joined onto the project base and pointed at
        // a DIFFERENT file on this machine -- a misplacement, not an absence, which is the harder
        // kind to notice.
        assertNull(AshSarifParser.stripUriScheme("file://server/share/app.py"))
        assertNull(AshSarifParser.stripUriScheme("file://192.168.0.5/vol/app.py"))

        val parsed = AshSarifParser.parse(sarif(result(uri = "file://server/share/app.py")))
        assertEquals(emptyList<AshFinding>(), parsed.findings)
        assertEquals(1, parsed.unlocatableResults)
        assertTrue(parsed.accountsForEveryResult)
    }

    @Test
    fun localhostAuthorityIsAcceptedAsLocal() {
        // RFC 8089 makes `file://localhost/x` equivalent to `file:///x`. Refusing it would reject a
        // legitimate producer, so the authority check has to exempt it rather than reject any
        // authority at all.
        assertEquals("/home/u/a.py", AshSarifParser.stripUriScheme("file://localhost/home/u/a.py"))
        assertEquals("/home/u/a.py", AshSarifParser.stripUriScheme("file://LOCALHOST/home/u/a.py"))
    }

    @Test
    fun aWindowsDriveIsNotMistakenForAUriScheme() {
        // `C:` matches the RFC 3986 scheme production, so a naive scheme guard rejects every Windows
        // path. One-letter schemes are treated as drive letters for exactly this reason -- and this is
        // the positive control for the two refusal tests above, which would otherwise be satisfied by
        // a guard that rejected everything.
        assertEquals("C:/code/a.cs", AshSarifParser.stripUriScheme("C:/code/a.cs"))
        assertEquals("d:/x/y.tf", AshSarifParser.stripUriScheme("d:/x/y.tf"))
        assertEquals("C:/code/a.cs", AshSarifParser.stripUriScheme("file:///C:/code/a.cs"))

        val parsed = AshSarifParser.parse(sarif(result(uri = "C:/code/a.cs")))
        assertEquals(1, parsed.findings.size)
        assertEquals(1, parsed.surfacedResults)
    }

    @Test
    fun stripsUriSchemesWithoutLosingAbsolutePaths() {
        // file:// has an empty authority, so removing it leaves the absolute path.
        assertEquals("/home/u/a.py", AshSarifParser.stripUriScheme("file:///home/u/a.py"))
        // The authority-less form must keep its leading slash. Removing "file:/" would
        // leave "home/u/a.py", which then resolves against the project root and points at
        // a file that does not exist.
        assertEquals("/home/u/a.py", AshSarifParser.stripUriScheme("file:/home/u/a.py"))
        // The spec's own example in section 3.27.10 uses this form; the slash before the
        // drive letter is a URI artifact, not part of the path.
        assertEquals("C:/code/a.cs", AshSarifParser.stripUriScheme("file:///C:/code/a.cs"))
        assertEquals("src/app.py", AshSarifParser.stripUriScheme("src/app.py"))
        assertEquals("a b/c.py", AshSarifParser.stripUriScheme("a%20b/c.py"))
    }

    @Test
    fun malformedInputIsReportedRatherThanReadAsEmpty() {
        // Each of these must produce a problem. An empty findings list with an empty
        // problems list is how a parser says "clean scan", and none of these is one.
        for (bad in listOf("", "{", "not json", "[]", """{"version":"2.1.0"}""")) {
            val parsed = AshSarifParser.parse(bad)
            assertEquals("input: <$bad>", emptyList<AshFinding>(), parsed.findings)
            assertTrue("input <$bad> must be reported, not read as clean", parsed.problems.isNotEmpty())
        }
    }

    @Test
    fun anEmptyResultsArrayIsACleanScan() {
        // The positive control for the test above: a well-formed SARIF with no results
        // genuinely IS a clean scan, and must not be reported as a problem.
        val parsed = AshSarifParser.parse(sarif(""))
        assertEquals(emptyList<AshFinding>(), parsed.findings)
        assertEquals(emptyList<String>(), parsed.problems)
    }

    @Test
    fun readsFindingsFromEveryRun() {
        // ASH aggregates one run per scanner, so reading only runs[0] would show the
        // findings of whichever scanner happened to be first.
        val twoRuns = """
            {
              "version": "2.1.0",
              "runs": [
                { "tool": { "driver": { "name": "bandit" } },
                  "results": [ ${result(ruleId = "B1", uri = "a.py")} ] },
                { "tool": { "driver": { "name": "checkov" } },
                  "results": [ ${result(ruleId = "CKV1", uri = "b.tf")} ] }
              ]
            }
        """.trimIndent()
        val parsed = AshSarifParser.parse(twoRuns)
        assertEquals(listOf("bandit", "checkov"), parsed.findings.map { it.scannerName })
        assertEquals(listOf("B1", "CKV1"), parsed.findings.map { it.ruleId })
    }
}
