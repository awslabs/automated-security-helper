# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two of the Bedrock summary reporter's file options cannot name one file.

``output_file``, ``output_executive_file`` and ``output_technical_file`` each
name a file the reporter writes in the reports directory. At the base two of
them could be set to the same name: the later report overwrote the earlier one
and nothing said so. The options model now keeps the earlier option's name and
replaces the later option by its default, with one warning naming both keys; a
default that is itself taken is refused.

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

pytestmark = pytest.mark.unit

PREFIX = "reporters.bedrock-summary-reporter.options."


@pytest.fixture(autouse=True)
def _fresh_warnings():
    reset_refused_tool_version_warnings()
    yield
    reset_refused_tool_version_warnings()


def test_a_later_option_naming_an_earlier_options_file_takes_its_default(caplog):
    """output_file keeps the shared name; output_executive_file goes back to its
    default; one warning names both keys and neither value."""
    with caplog.at_level(logging.WARNING):
        options = BedrockSummaryReporterConfigOptions(
            output_file="one-report.md",
            output_executive_file="one-report.md",
        )

    assert options.output_file == "one-report.md"
    assert options.output_executive_file == "bedrock-executive.md"
    assert options.output_technical_file == "bedrock-technical.md"
    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(warnings) == 1, warnings
    assert f"{PREFIX}output_executive_file" in warnings[0], warnings
    assert f"{PREFIX}output_file" in warnings[0], warnings
    assert "one-report.md" not in warnings[0], warnings


def test_the_same_pair_is_warned_about_once_over_repeated_validation(caplog):
    """A plugin's options are validated several times per scan (the config, its
    dump, each instance); one collision is one warning."""
    with caplog.at_level(logging.WARNING):
        for _ in range(3):
            BedrockSummaryReporterConfigOptions(
                output_technical_file="shared.md", output_file="shared.md"
            )

    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(warnings) == 1, warnings


def test_a_collision_with_a_replaced_options_default_is_resolved_in_order():
    """Executive collides with output_file and takes its default; technical was
    set to that default and so collides next, and takes its own default."""
    options = BedrockSummaryReporterConfigOptions(
        output_file="shared.md",
        output_executive_file="shared.md",
        output_technical_file="bedrock-executive.md",
    )

    assert (
        options.output_file,
        options.output_executive_file,
        options.output_technical_file,
    ) == ("shared.md", "bedrock-executive.md", "bedrock-technical.md")


def test_a_default_that_is_already_taken_is_refused():
    """output_file set to the executive report's default name: the executive
    option is at its default and has no other name to take, so the config is refused
    rather than one report silently overwriting the other."""
    with pytest.raises(ValidationError) as raised:
        BedrockSummaryReporterConfigOptions(output_file="bedrock-executive.md")

    text = str(raised.value)
    assert f"{PREFIX}output_executive_file" in text, text
    assert f"{PREFIX}output_file" in text, text


def test_three_distinct_names_are_kept_as_given(caplog):
    """The control: distinct names pass through with no warning."""
    with caplog.at_level(logging.WARNING):
        options = BedrockSummaryReporterConfigOptions(
            output_file="a.md",
            output_executive_file="b.md",
            output_technical_file="c.md",
        )

    assert (
        options.output_file,
        options.output_executive_file,
        options.output_technical_file,
    ) == ("a.md", "b.md", "c.md")
    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []
