# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Two readings of a refused input's name in the reports.

``inert_text`` escaped the C0 and C1 controls and the bidirectional-formatting
characters, and left the line and paragraph separators (U+2028, U+2029) and the
other format characters (a zero-width space, say) as they were, so a tree-chosen
name holding one still broke a summary line in the text and markdown reports.

The SARIF notification for a refused input wrote the input's path verbatim as its
``artifactLocation.uri``, which is a URI reference: a ``#``, ``?``, ``%`` or space
in the name made the reference name another file, or no valid one.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ConverterStatusInfo,
    RefusedInputInfo,
)
from automated_security_helper.utils.converter_refusals import (
    inert_text,
    refusal_invocations,
)

pytestmark = pytest.mark.unit

# Built with chr() so the source holds no invisible character: the line and
# paragraph separators, a zero-width space, a soft hyphen, a tag character
# (outside the BMP) and a right-to-left override.
LINE_SEPARATOR = chr(0x2028)
PARAGRAPH_SEPARATOR = chr(0x2029)
ZERO_WIDTH_SPACE = chr(0x200B)
SOFT_HYPHEN = chr(0x00AD)
TAG_A = chr(0xE0041)
RIGHT_TO_LEFT_OVERRIDE = chr(0x202E)
BACKSLASH = chr(0x5C)


def test_line_and_paragraph_separators_are_escaped():
    assert inert_text(f"a{LINE_SEPARATOR}b{PARAGRAPH_SEPARATOR}c") == (
        f"a{BACKSLASH}u2028b{BACKSLASH}u2029c"
    )


def test_other_format_characters_are_escaped():
    # A zero-width space and a soft hyphen show as nothing; a tag character is
    # outside the BMP and is written with its whole code point.
    assert inert_text(f"a{ZERO_WIDTH_SPACE}b{SOFT_HYPHEN}c") == (
        f"a{BACKSLASH}u200bb{BACKSLASH}u00adc"
    )
    assert inert_text(f"x{TAG_A}y") == f"x{BACKSLASH}U000e0041y"


def test_ordinary_text_passes_through_and_controls_still_escape():
    """The control: letters, marks and spaces are kept; a tab still escapes as before."""
    assert inert_text("café résumé.ipynb") == "café résumé.ipynb"
    assert inert_text("a\tb") == f"a{BACKSLASH}x09b"
    assert inert_text(f"a{RIGHT_TO_LEFT_OVERRIDE}b") == f"a{BACKSLASH}u202eb"


def _model_refusing(path: str) -> AshAggregatedResults:
    model = AshAggregatedResults(ash_config=get_default_config())
    model.converter_results["archive"] = ConverterStatusInfo(
        converted_paths=[],
        refused_inputs=[RefusedInputInfo(path=path, reason="it is a symbolic link")],
    )
    return model


def test_the_notification_uri_is_a_percent_encoded_reference():
    (invocation,) = refusal_invocations(_model_refusing("dir/a b#c?100%.zip"))

    (note,) = invocation.toolExecutionNotifications
    (location,) = note.locations
    assert location.physicalLocation.root.artifactLocation.uri == (
        "dir/a%20b%23c%3F100%25.zip"
    )
    # The record itself keeps the path as written.
    assert note.properties.model_dump()["refused_input"]["path"] == "dir/a b#c?100%.zip"


def test_a_plain_path_is_its_own_uri():
    """The control: a path with nothing to encode is written as it is."""
    (invocation,) = refusal_invocations(_model_refusing("vendor/declared.zip"))

    (note,) = invocation.toolExecutionNotifications
    (location,) = note.locations
    assert location.physicalLocation.root.artifactLocation.uri == "vendor/declared.zip"
