# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""flat.json and SARIF must report the same line for the same finding.

Why this exists: the flattening path used to read line numbers off
``physicalLocation.contextRegion`` in preference to ``physicalLocation.region``.
The SARIF schema defines ``region`` as the portion of the artifact the result is
about and ``contextRegion`` as "a portion of the artifact that encloses the
region", there so "a viewer [can] display additional context around the region".
Reading lines off the context window made flat.json disagree with ASH's own
SARIF about where a finding is -- a bandit B102 at line 231 came out as 230 --
and every other consumer of the field (the CSV reporter, the HTML/Markdown/Text
summaries, the MCP ``suggest_suppression`` tool) inherited the same wrong line.

The assertion deliberately compares the two rendered outputs against each other
rather than against a literal. A test that checked flat.json against a hardcoded
number would pass under either convention, so it could not tell a correct
reporter from one that had simply been re-baselined; and it would not notice the
two outputs drifting apart again for some new reason.

The fixture shapes are measured from real ``bandit -f sarif`` output, not
invented, because the interesting part is that the drift is not a uniform
off-by-one: bandit widens the window by however much context it wants, the
widening hits ``endLine`` in the opposite direction from ``startLine``, it is
zero when the finding is already at line 1, and for B602 ``contextRegion``
starts *below* the region rather than above it.
"""

import json

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.flatjson_reporter import (
    FlatJSONReporter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.sarif_reporter import (
    SarifReporter,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactContent,
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation2,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)

# (rule_id, region start/end, contextRegion start/end) as emitted by
# `bandit -f sarif`. See the module docstring for how these were obtained.
BANDIT_SHAPES = [
    # B102 exec() on line 231, one line of lead-in context.
    ("B102", 231, 231, 230, 231),
    # Same rule at line 1: contextRegion cannot start earlier, so no drift.
    ("B102", 1, 1, 1, 1),
    # B404 import on line 1: only endLine is widened.
    ("B404", 1, 1, 1, 3),
    # B607 over a two-line call: both ends widened.
    ("B607", 4, 5, 3, 7),
    # B602 on the same call: contextRegion starts BELOW the region.
    ("B602", 4, 5, 5, 7),
]


def _model_with_context_region(
    rule_id: str,
    region_start: int,
    region_end: int,
    context_start: int,
    context_end: int,
) -> AshAggregatedResults:
    """An AshAggregatedResults holding one bandit-shaped result."""
    model = AshAggregatedResults()
    model.sarif = SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="bandit", version="1.8.0")),
                results=[
                    Result(
                        ruleId=rule_id,
                        level="error",
                        message=Message(text=f"{rule_id} finding"),
                        locations=[
                            Location(
                                physicalLocation=PhysicalLocation2(
                                    artifactLocation=ArtifactLocation(
                                        uri="src/target.py"
                                    ),
                                    region=Region(
                                        startLine=region_start,
                                        endLine=region_end,
                                        snippet=ArtifactContent(
                                            text='exec("print(1)")\n'
                                        ),
                                    ),
                                    contextRegion=Region(
                                        startLine=context_start,
                                        endLine=context_end,
                                        snippet=ArtifactContent(
                                            text='# lead-in\nexec("print(1)")\n'
                                        ),
                                    ),
                                )
                            )
                        ],
                    )
                ],
            )
        ],
    )
    return model


def _sarif_regions(rendered: str) -> list[dict]:
    """The region of every result in a rendered SARIF document."""
    doc = json.loads(rendered)
    regions = []
    for run in doc["runs"]:
        for result in run.get("results") or []:
            for location in result.get("locations") or []:
                regions.append(location["physicalLocation"]["region"])
    return regions


@pytest.mark.parametrize(
    "rule_id,region_start,region_end,context_start,context_end", BANDIT_SHAPES
)
def test_flatjson_line_matches_sarif_region(
    rule_id,
    region_start,
    region_end,
    context_start,
    context_end,
    test_plugin_context,
):
    """The two rendered outputs must name the same line for the same finding."""
    model = _model_with_context_region(
        rule_id, region_start, region_end, context_start, context_end
    )

    flat = json.loads(FlatJSONReporter(context=test_plugin_context).report(model))
    sarif_regions = _sarif_regions(
        SarifReporter(context=test_plugin_context).report(model)
    )

    assert len(flat["findings"]) == 1, (
        "fixture should yield exactly one finding in flat.json"
    )
    assert len(sarif_regions) == 1, (
        "fixture should yield exactly one region in the SARIF output"
    )

    finding = flat["findings"][0]
    region = sarif_regions[0]

    assert finding["line_start"] == region["startLine"], (
        f"{rule_id}: flat.json line_start={finding['line_start']} but SARIF "
        f"region.startLine={region['startLine']} for the same finding. The two "
        f"outputs disagree about where this finding is."
    )
    assert finding["line_end"] == region["endLine"], (
        f"{rule_id}: flat.json line_end={finding['line_end']} but SARIF "
        f"region.endLine={region['endLine']} for the same finding. Fixing "
        f"line_start alone would leave the range incoherent."
    )


def test_context_region_is_still_the_fallback_when_there_is_no_region(
    test_plugin_context,
):
    """A tool that supplies only a contextRegion must not lose its lines.

    Guards the fix against over-correction: the point was to stop preferring
    the context window over the region, not to stop reading contextRegion at
    all. Without this, a narrowing to `region`-only would silently drop
    locations for any tool that emits contextRegion alone.
    """
    model = AshAggregatedResults()
    model.sarif = SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="bandit", version="1.8.0")),
                results=[
                    Result(
                        ruleId="B102",
                        level="error",
                        message=Message(text="B102 finding"),
                        locations=[
                            Location(
                                physicalLocation=PhysicalLocation2(
                                    artifactLocation=ArtifactLocation(
                                        uri="src/target.py"
                                    ),
                                    contextRegion=Region(startLine=42, endLine=44),
                                )
                            )
                        ],
                    )
                ],
            )
        ],
    )

    flat = json.loads(FlatJSONReporter(context=test_plugin_context).report(model))
    finding = flat["findings"][0]

    assert finding["line_start"] == 42
    assert finding["line_end"] == 44


def test_snippet_still_prefers_the_context_region(test_plugin_context):
    """contextRegion keeps supplying the snippet -- that is what it is for.

    The schema's own words: contextRegion exists so "a viewer [can] display
    additional context around the region". Only the *location* moved to
    ``region``; taking the wider snippet away would strip context out of the
    HTML, Markdown and Text summaries for no stated reason.
    """
    model = _model_with_context_region("B102", 231, 231, 230, 231)

    flat = json.loads(FlatJSONReporter(context=test_plugin_context).report(model))
    finding = flat["findings"][0]

    assert finding["code_snippet"] == '# lead-in\nexec("print(1)")'
