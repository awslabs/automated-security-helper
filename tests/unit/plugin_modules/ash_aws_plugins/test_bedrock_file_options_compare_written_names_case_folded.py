# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""The Bedrock file options clash only when their files are written, and by folded name.

``test_bedrock_summary_reporter_file_names.py`` covers two options naming the
same file. Two gaps remained in that rule:

* names were compared as written, so ``Report.md`` and ``report.md`` were two
  files to the check and one file on a case-insensitive file system (the
  default on macOS and Windows), where the later report overwrote the earlier;
* an option whose file is never written (its section excluded, or markdown
  output off) was still compared, so a harmless repeat was refused or rewrote
  an operator's name for no reason.

No test here calls AWS: only the options model is built.
"""

import logging

import pytest
from pydantic import ValidationError

from automated_security_helper.base.options import (
    reset_refused_tool_version_warnings,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporterConfigOptions,
)
from tests.unit.plugin_modules.ash_aws_plugins.bedrock_reporter_doubles import (
    make_reporter,
    plugin_context_in,
)

pytestmark = pytest.mark.unit

PREFIX = "reporters.bedrock-summary-reporter.options."


@pytest.fixture(autouse=True)
def _fresh_warnings():
    reset_refused_tool_version_warnings()
    yield
    reset_refused_tool_version_warnings()


def _names(options):
    return (
        options.output_file,
        options.output_executive_file,
        options.output_technical_file,
    )


def _warnings(caplog):
    return [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]


def test_names_that_differ_only_by_case_are_one_file(caplog):
    with caplog.at_level(logging.WARNING):
        options = BedrockSummaryReporterConfigOptions(
            output_file="Report.md", output_executive_file="report.md"
        )

    assert _names(options) == (
        "Report.md",
        "bedrock-executive.md",
        "bedrock-technical.md",
    )
    warnings = _warnings(caplog)
    assert len(warnings) == 1, warnings
    assert f"{PREFIX}output_executive_file" in warnings[0], warnings
    assert f"{PREFIX}output_file" in warnings[0], warnings


def test_a_default_that_differs_only_by_case_from_a_taken_name_is_refused():
    with pytest.raises(ValidationError) as raised:
        BedrockSummaryReporterConfigOptions(output_file="Bedrock-Executive.MD")

    text = str(raised.value)
    assert f"{PREFIX}output_executive_file" in text, text
    assert f"{PREFIX}output_file" in text, text


def test_distinct_names_that_share_letters_are_kept(caplog):
    """The control: only a folded equal name is a clash."""
    with caplog.at_level(logging.WARNING):
        options = BedrockSummaryReporterConfigOptions(
            output_file="report.md",
            output_executive_file="report-2.md",
            output_technical_file="Report.markdown",
        )

    assert _names(options) == ("report.md", "report-2.md", "Report.markdown")
    assert _warnings(caplog) == []


def test_an_excluded_section_writes_no_file_and_clashes_with_nothing(caplog):
    with caplog.at_level(logging.WARNING):
        options = BedrockSummaryReporterConfigOptions(
            output_file="shared.md",
            output_executive_file="shared.md",
            exclude_sections=["executive_summary"],
        )

    assert _names(options)[:2] == ("shared.md", "shared.md")
    assert _warnings(caplog) == []


def test_a_section_left_out_of_the_included_list_writes_no_file(caplog):
    with caplog.at_level(logging.WARNING):
        options = BedrockSummaryReporterConfigOptions(
            output_file="shared.md",
            output_technical_file="shared.md",
            include_sections=["executive_summary"],
        )

    assert options.output_technical_file == "shared.md"
    assert _warnings(caplog) == []


def test_with_markdown_output_off_no_file_is_written_and_nothing_clashes(caplog):
    with caplog.at_level(logging.WARNING):
        options = BedrockSummaryReporterConfigOptions(
            output_markdown=False,
            output_file="shared.md",
            output_executive_file="shared.md",
        )

    assert _names(options)[:2] == ("shared.md", "shared.md")
    assert _warnings(caplog) == []


def test_a_clash_between_written_files_is_still_resolved_when_another_is_excluded(
    caplog,
):
    """The exclusion of one section does not switch the check off for the rest."""
    with caplog.at_level(logging.WARNING):
        options = BedrockSummaryReporterConfigOptions(
            output_file="shared.md",
            output_technical_file="SHARED.md",
            exclude_sections=["executive_summary"],
        )

    assert options.output_technical_file == "bedrock-technical.md"
    assert len(_warnings(caplog)) == 1, _warnings(caplog)


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({}, ("output_file", "output_executive_file", "output_technical_file")),
        ({"output_markdown": False}, ()),
        (
            {"exclude_sections": ["executive_summary"]},
            ("output_file", "output_technical_file"),
        ),
        (
            {"include_sections": ["executive_summary"]},
            ("output_file", "output_executive_file"),
        ),
        ({"include_sections": []}, ("output_file",)),
    ],
    ids=["default", "markdown-off", "no-executive", "executive-only", "no-sections"],
)
def test_the_options_name_the_files_that_are_written(kwargs, expected):
    options = BedrockSummaryReporterConfigOptions(**kwargs)

    assert options.written_file_options() == expected


def test_the_reporter_lists_exactly_the_files_the_options_say_are_written(tmp_path):
    reporter = make_reporter(
        plugin_context_in(tmp_path),
        output_file="a.md",
        output_executive_file="b.md",
        output_technical_file="c.md",
        exclude_sections=["technical_analysis"],
    )

    assert reporter.companion_file_names() == ("a.md", "b.md")
