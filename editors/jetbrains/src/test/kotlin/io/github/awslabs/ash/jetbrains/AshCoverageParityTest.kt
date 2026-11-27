// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains

import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The plugin reaches the coverage verdict ASH's own `assess_coverage` reaches, on the same cases.
 *
 * WHY THIS EXISTS. `coverage_complete` is not a field of `ash_aggregated_results.json`; ASH
 * computes it on demand (scan_tracking.assess_coverage and coverage_has_gap), and the plugin
 * cannot import Python. So the plugin asks the same questions of the results file in Kotlin, which
 * makes it a third reader of one rule. With `fail_on_incomplete_scanners: false` ASH exits 0 over
 * a scan with a stale content database or an unevaluated rule, and the results file is then the
 * only place the gap is recorded. Before this test the plugin read only the scanner roster, so it
 * reported those scans as complete.
 *
 * THE CASES ARE SHARED, NOT COPIED. editors/vscode/test/fixtures/coverage-cases/cases.json is the
 * file the VS Code extension's jest suite and tests/unit/test_vscode_coverage_parity.py already
 * read: each case is a results file captured from a real scan plus a few edits, and the verdict
 * ASH reaches on it. The Python test proves ASH reaches that verdict, so agreeing with the file
 * here is agreeing with ASH. A change to ASH's rule that moves a verdict fails the Python test,
 * and the fix is to update cases.json, coverage.ts and AshScannerStatus.kt together; a change to
 * AshScannerStatus.kt alone fails this test. A missing file FAILS rather than skipping, for the
 * reason AshRealReportTest gives.
 *
 * Every case is evaluated before anything is asserted, so a failure lists every case that
 * disagrees rather than the first.
 */
class AshCoverageParityTest {

    private val fixtures: File by lazy {
        val candidates = listOf(
            File("../vscode/test/fixtures"),
            File("editors/vscode/test/fixtures"),
        )
        candidates.firstOrNull { File(it, "coverage-cases/cases.json").isFile }
            ?: throw AssertionError(
                "cannot find the shared coverage cases. Looked for coverage-cases/cases.json under " +
                    candidates.joinToString(", ") { it.absolutePath } + ". This test must not be skipped.",
            )
    }

    private data class Case(val name: String, val document: String, val expect: JsonObject)

    private val cases: List<Case> by lazy {
        val root = JsonParser.parseString(File(fixtures, "coverage-cases/cases.json").readText()).asJsonObject
        root.getAsJsonArray("cases").map { element ->
            val case = element.asJsonObject
            val base = JsonParser.parseString(File(fixtures, case.get("base").asString).readText())
            for (edit in case.getAsJsonArray("set")) {
                val pair = edit.asJsonArray
                apply(base, pair[0].asJsonArray, pair[1])
            }
            Case(case.get("name").asString, base.toString(), case.getAsJsonObject("expect"))
        }
    }

    /** Sets `path` to a copy of `value`, the `_apply` of test_vscode_coverage_parity.py. */
    private fun apply(document: JsonElement, path: JsonArray, value: JsonElement) {
        var target = document
        for (i in 0 until path.size() - 1) {
            target = step(target, path[i])
        }
        val last = path[path.size() - 1]
        when {
            target.isJsonObject -> target.asJsonObject.add(last.asString, value.deepCopy())
            target.isJsonArray -> target.asJsonArray.set(last.asInt, value.deepCopy())
            else -> throw AssertionError("cannot set $path: the parent is $target")
        }
    }

    private fun step(node: JsonElement, key: JsonElement): JsonElement = when {
        node.isJsonObject -> node.asJsonObject.get(key.asString)
            ?: throw AssertionError("no member $key in the fixture")
        node.isJsonArray -> node.asJsonArray.get(key.asInt)
        else -> throw AssertionError("cannot index $node with $key")
    }

    /**
     * An exit-0 outcome over the case's results file: the gate-off scan, where the file is the
     * only evidence of a gap. Exit 1 would be incomplete whatever the file said, so it could not
     * tell a reader that sees the gap from one that does not.
     */
    private fun exitZeroOver(document: String) = AshScanRunner.Outcome.Completed(
        exitCode = AshScanRunner.EXIT_CLEAN,
        results = AshScanResults(emptyList(), emptyList()),
        sarifPath = "/p/reports/ash.sarif",
        scanners = AshScannerStatus.parse(document),
        versionLine = "awslabs/automated-security-helper v4.0.0",
        outputTail = "",
    )

    @Test
    fun theCaseListIsTheSharedOne() {
        // A loop over an empty list asserts nothing and passes. 18 cases at the time of writing;
        // the floor matches test_vscode_coverage_parity.py's.
        assertTrue("only ${cases.size} case(s) read", cases.size >= 10)
    }

    @Test
    fun anExitZeroScanIsCompleteExactlyWhenAshSaysSo() {
        val disagreements = cases.mapNotNull { case ->
            val want = case.expect.get("coverage_complete").asBoolean
            val got = exitZeroOver(case.document).coverageComplete
            if (got == want) null else "${case.name}: ASH says coverage_complete=$want, the plugin $got"
        }
        assertEquals(
            "the plugin's verdict differs from ASH's on ${disagreements.size} of ${cases.size} case(s)",
            emptyList<String>(),
            disagreements,
        )
    }

    @Test
    fun everyCaseNamesTheGapsAshNames() {
        val disagreements = cases.mapNotNull { case ->
            val report = AshScannerStatus.parse(case.document)
            val got = mapOf(
                "incomplete_scanners" to report.incomplete.map { it.name }.sorted(),
                "no_scanner_ran" to report.nothingMeasured,
                "incomplete_converters" to report.incompleteConverters.map { it.name },
                "unevaluated_rules" to report.unevaluatedRules,
                "stale_content_databases" to report.staleContentDatabases,
            )
            val want = mapOf(
                "incomplete_scanners" to names(case.expect, "incomplete_scanners").sorted(),
                "no_scanner_ran" to case.expect.get("no_scanner_ran").asBoolean,
                "incomplete_converters" to names(case.expect, "incomplete_converters"),
                "unevaluated_rules" to names(case.expect, "unevaluated_rules"),
                "stale_content_databases" to names(case.expect, "stale_content_databases"),
            )
            if (got == want) null else "${case.name}:\n  ASH    $want\n  plugin $got"
        }
        assertEquals(
            "the plugin names different gaps from ASH on ${disagreements.size} of ${cases.size} case(s)",
            emptyList<String>(),
            disagreements,
        )
    }

    private fun names(expect: JsonObject, field: String): List<String> =
        expect.getAsJsonArray(field).map { it.asString }
}
