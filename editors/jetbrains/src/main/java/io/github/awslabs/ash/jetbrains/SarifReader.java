// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package io.github.awslabs.ash.jetbrains;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Reads ASH's SARIF into {@link AshFinding}s.
 *
 * <p>WHAT THIS WAS WRITTEN AGAINST
 *
 * <p>A real {@code ash scan --scanners detect-secrets} over a file carrying AWS's published
 * example secret access key, not against the SARIF 2.1.0 schema. That matters, because the
 * schema permits far more than ASH emits and omits nothing ASH relies on, so writing to the
 * schema would have produced a reader that handles cases that never occur and mishandles
 * the ones that do. Three differences from a schema reading, each measured:
 *
 * <ul>
 *   <li>{@code runs[0].tool.driver.rules} is EMPTY. There is no rule metadata to fall back
 *       to for a result's severity, so {@code result.level} is the only source, and a
 *       reader that resolved severity through {@code ruleIndex} would resolve nothing.
 *   <li>A {@code region} has {@code startLine} and {@code endLine} and no column members,
 *       plus {@code charOffset: -1} and {@code byteOffset: -1}. The -1 is "unknown", so
 *       treating those as offsets puts every annotation one character before the file.
 *   <li>{@code artifactLocation.index} is also -1, so the {@code run.artifacts} table
 *       cannot be used to resolve a uri and the uri itself is the only locator.
 * </ul>
 *
 * <p>WHY A RESULT WITH NO LINE IS DROPPED RATHER THAN PLACED AT LINE 1
 *
 * <p>Some ASH scanners report findings about a whole repository or a dependency graph rather
 * than about a place in a file. Those have no physical location, and an annotation is a
 * range in a document. Defaulting them to line 1 would attach an unrelated warning to
 * whatever happens to be at the top of a file, which is worse than not showing it -- the
 * user cannot tell a real line-1 finding from a placed one. {@link #skippedWithoutLocation}
 * counts them so the number is reportable rather than invisible.
 */
public final class SarifReader {

    /** Used when SARIF omits {@code ruleId}; an annotation with no rule name is unsearchable. */
    static final String UNKNOWN_RULE_ID = "ASH-UNKNOWN-RULE";

    /** Used when SARIF omits {@code message.text}. */
    static final String NO_MESSAGE = "(no message in the SARIF result)";

    private final List<AshFinding> findings;
    private final int skippedWithoutLocation;

    private SarifReader(List<AshFinding> findings, int skippedWithoutLocation) {
        this.findings = List.copyOf(findings);
        this.skippedWithoutLocation = skippedWithoutLocation;
    }

    /**
     * Parses a SARIF document.
     *
     * @throws Json.SyntaxException if the text is not valid JSON. Deliberately not caught:
     *     a SARIF file this plugin cannot read is a condition the user has to be told
     *     about, and returning an empty list would report it as a clean scan.
     */
    public static SarifReader read(String sarifText) {
        Object document = Json.parse(sarifText);
        List<AshFinding> collected = new ArrayList<>();
        int skipped = 0;
        for (Object runValue : Json.asArray(Json.get(Json.asObject(document), "runs"))) {
            Map<String, Object> run = Json.asObject(runValue);
            for (Object resultValue : Json.asArray(Json.get(run, "results"))) {
                AshFinding finding = toFinding(Json.asObject(resultValue));
                if (finding == null) {
                    skipped++;
                } else {
                    collected.add(finding);
                }
            }
        }
        return new SarifReader(collected, skipped);
    }

    /** Every result that carried a file location, in document order. */
    public List<AshFinding> findings() {
        return findings;
    }

    /**
     * How many results were dropped for having no line-bearing physical location.
     *
     * <p>Reported rather than silent: "0 annotations" with a non-zero count here means the
     * scan found things this plugin cannot place, which is a different situation from a
     * clean file and the user should be able to tell them apart.
     */
    public int skippedWithoutLocation() {
        return skippedWithoutLocation;
    }

    /** Null when the result has no usable location. */
    private static AshFinding toFinding(Map<String, Object> result) {
        List<Object> locations = Json.asArray(Json.get(result, "locations"));
        if (locations.isEmpty()) {
            return null;
        }
        Map<String, Object> physical =
                Json.asObject(Json.get(Json.asObject(locations.get(0)), "physicalLocation"));
        String uri =
                Json.asString(
                        Json.get(Json.asObject(Json.get(physical, "artifactLocation")), "uri"), "");
        if (uri.isEmpty()) {
            return null;
        }

        Map<String, Object> region = Json.asObject(Json.get(physical, "region"));
        int startLine = Json.asInt(Json.get(region, "startLine"), 0);
        if (startLine < 1) {
            return null;
        }
        // A region may omit endLine for a single-line finding. Falling back to startLine is
        // what SARIF says that means, and it is also what keeps the range non-empty.
        int endLine = Json.asInt(Json.get(region, "endLine"), startLine);
        if (endLine < startLine) {
            endLine = startLine;
        }

        int startColumn = positiveOrAbsent(Json.asInt(Json.get(region, "startColumn"), 0));
        int endColumn = positiveOrAbsent(Json.asInt(Json.get(region, "endColumn"), 0));

        String message =
                Json.asString(Json.get(Json.asObject(Json.get(result, "message")), "text"), "");
        String scannerName =
                Json.asString(
                        Json.get(Json.asObject(Json.get(result, "properties")), "scanner_name"), "");

        return new AshFinding(
                orDefault(Json.asString(Json.get(result, "ruleId"), ""), UNKNOWN_RULE_ID),
                Json.asString(Json.get(result, "level"), ""),
                orDefault(message, NO_MESSAGE),
                uri,
                startLine,
                endLine,
                startColumn,
                endColumn,
                scannerName);
    }

    /**
     * Collapses every non-positive column, including ASH's own -1 sentinel, to
     * {@link AshFinding#ABSENT}.
     */
    private static int positiveOrAbsent(int column) {
        return column > 0 ? column : AshFinding.ABSENT;
    }

    private static String orDefault(String value, String fallback) {
        return value.isBlank() ? fallback : value;
    }
}
