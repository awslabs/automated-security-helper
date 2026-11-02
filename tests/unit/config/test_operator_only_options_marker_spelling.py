# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The ignored marker finds a reporter section under any spelling of its name.

``mark_operator_only_options`` shows an operator-only option as ignored where
the chain's files wrote it. The record of what the files wrote keys a reporter
section by the spelling of the file that wrote it, and the merged dump by the
spelling the chain kept, which another file of the chain may have written the
other way. The two are one section.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.operator_only_options import (
    RepositorySettings,
    mark_operator_only_options,
)

pytestmark = pytest.mark.unit

SH = "aws-security-hub"
MARKER = '<operator only; ignored from this file: "a-scope">'


def _marked(wrote_as: str, dumped_as: str):
    repository = RepositorySettings(trees=[])
    repository.found.append(("reporters", SH, wrote_as, "findings_scope", "a-scope"))
    return mark_operator_only_options(
        {"reporters": {dumped_as: {"options": {"aws_region": "us-west-2"}}}},
        written=repository,
    )["reporters"][dumped_as]["options"]


@pytest.mark.parametrize(
    "wrote_as, dumped_as",
    [
        (SH, SH),
        ("aws_security_hub", SH),
        (SH, "aws_security_hub"),
    ],
    ids=["same-spelling", "base-underscored", "base-dashed"],
)
def test_an_option_a_file_wrote_is_marked_under_any_spelling_of_the_section(
    wrote_as, dumped_as
):
    options = _marked(wrote_as, dumped_as)

    assert options["findings_scope"] == MARKER
    assert options["aws_region"] == "us-west-2"


def test_an_option_no_file_wrote_is_not_marked():
    """The control: the record names only the scope."""
    options = _marked("aws_security_hub", SH)

    assert "archive_resolved_findings" not in options
