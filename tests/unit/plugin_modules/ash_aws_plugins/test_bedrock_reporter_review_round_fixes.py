# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Six defects a review of the AWS plugin fixes found, each pinned here.

Each test failed before its fix: a code span holding a pipe had every "<"
written as "&lt;" on every line, which a viewer shows literally inside code
(CommonMark decodes no entity in a span); a summarized finding's prompt listed
every one of its locations unbounded; ``recommendations()`` built a prompt from
no findings; the CloudWatch Logs reporter kept an older region pattern than the
S3 and Bedrock reporters; "The secret findings are reported in their own
section" was written where no such section was; and the dependency check asked
the control plane for its listings twice.

No test here calls AWS: boto3's session is a double, the model runtime answers
by plan, and the control plane is a MagicMock.
"""

import logging

import botocore.exceptions
import pytest
from pydantic import ValidationError

from automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils import (
    AWS_REGION_PATTERN,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_pipeline import (
    MAX_LOCATIONS_LISTED,
    BedrockPromptBuilder,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporterConfigOptions,
    _inline_as_written,
    _markdown_as_written,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.cloudwatch_logs_reporter import (
    CloudWatchLogsReporterConfigOptions,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
    S3ReporterConfigOptions,
)
from tests.unit.plugin_modules.ash_aws_plugins.test_bedrock_summary_reporter_fixes import (
    Runtime,
    Session,
    _control_plane,
    _run,
    _sts,
)
from tests.unit.plugin_modules.ash_aws_plugins.test_bedrock_summary_reporter_paths import (
    FALLBACK_ONE,
    FALLBACK_TWO,
    MODULE,
    PRIMARY_MODEL,
    context,  # noqa: F401  (fixture)
    finding,
    make_reporter,
)

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# 1. A code span holding a pipe is rewritten on table rows only
# ---------------------------------------------------------------------------


def test_a_pipe_span_off_a_table_row_is_written_as_the_model_wrote_it():
    """`List<T> | None` in a sentence is code to every viewer; an entity written
    there would show as the entity, since none is decoded inside a span."""
    answer = "The field is `List<T> | None` on every record."

    written = _markdown_as_written(answer)

    assert written == answer, written


def test_a_pipe_span_on_a_table_row_keeps_its_pipe_in_its_column_and_its_html_inert():
    """On a table row the span's pipe is written as "\\|", which GFM keeps inside
    its column and the span, and its "<" as text, so a viewer that does not read
    the escape still renders no HTML."""
    table = "| rule | note |\n|---|---|\n| rule | `x | <img src=x onerror=alert(1)>` |"

    written = _markdown_as_written(table)

    assert "`x \\| &lt;img src=x onerror=alert(1)>`" in written, written
    assert "<img" not in written, written
    # The header, the delimiter and the column delimiters are untouched.
    assert written.startswith("| rule | note |\n|---|---|\n| rule | "), written
    assert written.endswith(" |"), written


def test_a_pipe_already_escaped_in_a_table_row_span_is_not_escaped_again():
    table = "| a |\n|---|\n| `x \\| y` |"

    written = _markdown_as_written(table)

    assert written == table, written


def test_a_lone_line_with_pipes_is_prose_and_its_span_stays_as_written():
    """GFM makes a table only of a header row followed by a delimiter row; a
    line that merely holds pipes is a paragraph, which the viewer never splits,
    so its span is whole and nothing in it is rewritten."""
    for line in (
        "| rule | `x | <b>bold</b>` |",
        "Use `a<b | c` or x | y on the same line.",
    ):
        assert _markdown_as_written(line) == line, line


def test_a_table_row_whose_only_pipe_is_inside_a_span_is_still_split():
    """Inside a table the viewer splits every row at every pipe, a span's pipe
    included, so a row whose only pipe sits in a span is rewritten too."""
    table = "| a |\n|---|\n`x | <b>y</b>`"

    written = _markdown_as_written(table)

    assert written.endswith("`x \\| &lt;b>y&lt;/b>`"), written


def test_a_table_whose_header_and_delimiter_disagree_is_not_a_table():
    """The control: a delimiter row with a different column count makes no
    table, so the lines are prose and a span holding a pipe is left as written."""
    block = "| a | b |\n|---|\n| `x | <b>y</b>` |"

    assert _markdown_as_written(block) == block


def test_a_table_inside_a_block_quote_is_a_table_and_its_pipe_span_is_rewritten():
    """A viewer finds a table inside a block quote, reading its rows with the
    "> " markers stripped; the rule reads the same lines, so a raw "> |---|" is
    still the delimiter row it is to the viewer and the row's span is rewritten."""
    table = "> | a |\n> |---|\n> | `x | <b>y</b>` |"

    written = _markdown_as_written(table)

    assert written == "> | a |\n> |---|\n> | `x \\| &lt;b>y&lt;/b>` |", written


def test_a_table_inside_a_list_item_is_a_table_and_its_pipe_span_is_rewritten():
    """The same inside a list item: the item's "- " marker and the indent of its
    continuation lines are not part of the rows the viewer counts columns on."""
    table = "- | a |\n  |---|\n  | `x | <b>y</b>` |"

    written = _markdown_as_written(table)

    assert written == "- | a |\n  |---|\n  | `x \\| &lt;b>y&lt;/b>` |", written


def test_a_quoted_prose_line_with_pipes_is_prose_and_its_span_stays_as_written():
    """The control: a quoted line that merely holds pipes is a paragraph to the
    viewer, so nothing in its span is rewritten."""
    quote = "> Use `a<b | c` or x | y on the same line."

    assert _markdown_as_written(quote) == quote


def test_a_content_whose_line_count_disagrees_treats_every_piped_line_as_a_row():
    """The guard's fallback: when the parser's content does not line up with the
    raw lines (or no content is given), the rule cannot be read, and the block
    takes the side that rewrites a span it could have left alone. The lone
    piped line is prose under the rule (the control), a row under the fallback."""
    source = "Use `x | <b>y</b>` or x | y here."
    rewritten = "Use `x \\| &lt;b>y&lt;/b>` or x | y here."

    assert _inline_as_written(source, content=source) == source
    assert _inline_as_written(source) == rewritten
    assert _inline_as_written(source, content=f"{source}\nextra") == rewritten


def test_the_fallback_leaves_a_line_without_a_pipe_alone():
    """The fallback is keyed on the pipe: a span without one is written as the
    model wrote it even when the content cannot be read."""
    source = "Use `List<T>` here."

    assert _inline_as_written(source) == source


# ---------------------------------------------------------------------------
# 2. A prompt lists at most MAX_LOCATIONS_LISTED locations per finding
# ---------------------------------------------------------------------------


def _finding_with_locations(count):
    return {
        "ruleId": "R1",
        "level": "error",
        "message": {"text": "one rule, many files"},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": f"src/file_{i}.py"}}}
            for i in range(count)
        ],
    }


def test_a_findings_locations_are_capped_with_a_count_of_the_rest():
    builder = BedrockPromptBuilder()
    total = MAX_LOCATIONS_LISTED + 15

    locations = builder._extract_locations(_finding_with_locations(total))

    assert len(locations) == MAX_LOCATIONS_LISTED + 1, locations
    assert locations[-1] == "and 15 more", locations
    assert f"src/file_{MAX_LOCATIONS_LISTED}.py" not in locations, locations


def test_a_finding_within_the_cap_lists_every_location():
    builder = BedrockPromptBuilder()

    locations = builder._extract_locations(
        _finding_with_locations(MAX_LOCATIONS_LISTED)
    )

    assert len(locations) == MAX_LOCATIONS_LISTED, locations
    assert not any(uri.startswith("and ") for uri in locations), locations


@pytest.mark.parametrize(
    "build",
    [
        lambda b, f: b.findings_summary([f]),
        lambda b, f: b.recommendations([f], 10),
        lambda b, f: b.severity_analysis([f], "critical"),
        lambda b, f: b.technical_analysis([f], 10, False),
        lambda b, f: b.legacy_summary([f], [], [], 10),
    ],
)
def test_every_prompt_builder_lists_the_capped_locations(build):
    builder = BedrockPromptBuilder()
    prompt = build(builder, _finding_with_locations(MAX_LOCATIONS_LISTED + 500))

    assert "and 500 more" in prompt, prompt
    assert f"src/file_{MAX_LOCATIONS_LISTED + 1}.py" not in prompt, prompt


# ---------------------------------------------------------------------------
# 3. recommendations() builds no prompt from nothing
# ---------------------------------------------------------------------------


def test_recommendations_given_no_findings_answers_nothing():
    builder = BedrockPromptBuilder()

    assert builder.recommendations([], max_findings=10) == ""


def test_a_secrets_only_scan_sends_no_recommendations_placeholder(context, monkeypatch):  # noqa: F811
    """With only secret findings the Recommendations section is report text,
    never the model's reply to "FINDINGS BY SEVERITY:" over nothing."""
    reporter = make_reporter(
        context,
        output_markdown=False,
        group_by_severity=False,
        include_sections=["remediation_guide", "secret_findings"],
    )
    runtime = Runtime()

    report = _run(
        reporter, monkeypatch, runtime, finding("S1", scanner="detect-secrets")
    )

    assert not any("FINDINGS BY SEVERITY" in prompt for prompt in runtime.prompts()), (
        runtime.prompts()
    )
    assert "## Recommendations" in report, report
    assert "No actionable findings to analyze for this section." in report, report


# ---------------------------------------------------------------------------
# 4. One region pattern for the three AWS reporters
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "region",
    [
        "mx-central-1",
        "us-isof-south-1",
        "eu-isoe-west-1",
        "eusc-de-east-1",
        "us-east-1",
    ],
)
def test_cloudwatch_logs_accepts_every_region_the_other_reporters_accept(region):
    options = CloudWatchLogsReporterConfigOptions(aws_region=region)

    assert options.aws_region == region


def test_a_name_that_is_no_region_is_refused_by_cloudwatch_logs_too():
    with pytest.raises(ValidationError):
        CloudWatchLogsReporterConfigOptions(aws_region="nowhere-1")


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(
            lambda region: S3ReporterConfigOptions(
                aws_region=region, bucket_name="a-bucket"
            ),
            id="s3",
        ),
        pytest.param(
            lambda region: BedrockSummaryReporterConfigOptions(aws_region=region),
            id="bedrock",
        ),
        pytest.param(
            lambda region: CloudWatchLogsReporterConfigOptions(aws_region=region),
            id="cloudwatch-logs",
        ),
    ],
)
@pytest.mark.parametrize(
    "value",
    [
        pytest.param("us-east-1.attacker.example", id="host-suffix"),
        pytest.param("us-east-1/x", id="path-suffix"),
        pytest.param("US-EAST-1", id="upper-case"),
        pytest.param("us-east-1\n", id="trailing-newline"),
        pytest.param("xus-east-1", id="prefix"),
    ],
)
def test_a_value_that_only_holds_a_region_name_is_refused(build, value):
    """The pattern is a whole-value match: a value that merely contains a region
    name is refused, since the region ends up in an endpoint hostname. (The
    upper-case value is the control that the old pattern refused too.)"""
    with pytest.raises(ValidationError):
        build(value)


def test_the_three_reporters_share_the_one_region_pattern():
    patterns = {
        name: options.model_fields["aws_region"].metadata
        for name, options in (
            ("s3", S3ReporterConfigOptions),
            ("bedrock", BedrockSummaryReporterConfigOptions),
            ("cloudwatch-logs", CloudWatchLogsReporterConfigOptions),
        )
    }
    for name, metadata in patterns.items():
        found = [
            getattr(item, "pattern", None)
            for item in metadata
            if getattr(item, "pattern", None)
        ]
        assert found == [AWS_REGION_PATTERN], (name, found)


# ---------------------------------------------------------------------------
# 5. The secrets-section sentence names a section the report has
# ---------------------------------------------------------------------------


def test_the_sentence_is_not_written_when_the_secrets_section_is_excluded(
    context,  # noqa: F811
    monkeypatch,
):
    reporter = make_reporter(
        context,
        output_markdown=False,
        group_by_severity=False,
        include_sections=["risk_assessment"],
    )

    report = _run(
        reporter, monkeypatch, Runtime(), finding("S1", scanner="detect-secrets")
    )

    assert "No actionable findings to analyze for this section." in report, report
    assert "reported in their own section" not in report, report


def test_the_sentence_is_written_when_the_secrets_section_is_included(
    context,  # noqa: F811
    monkeypatch,
):
    """The control: the sentence as before where the section exists."""
    reporter = make_reporter(
        context,
        output_markdown=False,
        group_by_severity=False,
        include_sections=["risk_assessment", "secret_findings"],
    )

    report = _run(
        reporter, monkeypatch, Runtime(), finding("S1", scanner="detect-secrets")
    )

    assert "The secret findings are reported in their own section." in report, report


def test_without_the_main_reports_section_set_no_section_is_named(context):  # noqa: F811
    """The separate technical-analysis file calls with no section set: it has
    no secrets section to point at, whatever the main report includes."""
    reporter = make_reporter(context, include_sections=["technical_analysis"])
    reporter._secret_findings_exist = True

    text = reporter._nothing_to_analyze()

    assert text == "No actionable findings to analyze for this section."


# ---------------------------------------------------------------------------
# 6. The dependency check asks each listing once
# ---------------------------------------------------------------------------


def test_the_dependency_check_asks_the_control_plane_once_for_the_whole_chain(
    context,  # noqa: F811
    monkeypatch,
):
    """The configured model and two fallbacks are checked against ONE pair of
    listings; before, the configured model's check listed once and the walk a
    second time."""
    control = _control_plane(FALLBACK_TWO)
    monkeypatch.setattr(f"{MODULE}.boto3.Session", Session(sts=_sts(), bedrock=control))
    monkeypatch.setattr(
        f"{MODULE}.get_fallback_model",
        {PRIMARY_MODEL: FALLBACK_ONE, FALLBACK_ONE: FALLBACK_TWO}.get,
    )
    reporter = make_reporter(context, enable_fallback_models=True)

    assert reporter.validate_plugin_dependencies() is True, reporter.errors
    assert control.list_inference_profiles.call_count == 1
    # The reachability probe (byOutputModality) and the validator's listing are
    # two calls with different arguments; neither is repeated.
    assert control.list_foundation_models.call_count == 2


def test_a_failed_profile_listing_is_warned_once_across_the_chain(
    context,  # noqa: F811
    monkeypatch,
    caplog,
):
    """The listing fails; the configured model and both fallbacks are checked
    against the kept failure, and the listing's own WARNING is logged once, the
    two later checks logging the kept failure at DEBUG. Before, the walk's fresh
    wrapper raised the original error again and warned twice. The reporter's
    "Configured model ... is not valid" WARNING quotes the reason and is a
    different line, so the count is of the listing's line, not of the phrase."""
    control = _control_plane(FALLBACK_TWO)
    control.list_inference_profiles.side_effect = botocore.exceptions.ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "Access denied"}},
        "ListInferenceProfiles",
    )
    monkeypatch.setattr(f"{MODULE}.boto3.Session", Session(sts=_sts(), bedrock=control))
    monkeypatch.setattr(
        f"{MODULE}.get_fallback_model",
        {PRIMARY_MODEL: FALLBACK_ONE, FALLBACK_ONE: FALLBACK_TWO}.get,
    )
    reporter = make_reporter(context, enable_fallback_models=True)

    with caplog.at_level(logging.DEBUG):
        reporter.validate_plugin_dependencies()

    warned = [
        record
        for record in caplog.records
        if record.levelno == logging.WARNING
        and record.getMessage().startswith(
            "Bedrock API error when getting available models"
        )
    ]
    assert len(warned) == 1, [record.getMessage() for record in warned]
    assert "inference profile listing failed" in warned[0].getMessage()
    replayed = [
        record
        for record in caplog.records
        if record.levelno == logging.DEBUG
        and "the listing failed earlier in this walk" in record.getMessage()
    ]
    assert len(replayed) == 2, [record.getMessage() for record in replayed]
    assert control.list_inference_profiles.call_count == 1
