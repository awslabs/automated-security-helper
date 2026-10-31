# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A string given as the requested output formats names one format.

A ``str`` is a collection of its characters, so ``"markdown"`` was read as the
formats ``m``, ``a``, ``r``, ``k``, ``d``, ``o``, ``w`` and ``n``, and every
reporter was quietly dropped.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from automated_security_helper.base.reporter_plugin import (
    reporter_matches_requested_formats,
)
from automated_security_helper.core.enums import ExportFormat

pytestmark = pytest.mark.unit


def _reporter(name: str) -> SimpleNamespace:
    return SimpleNamespace(config=SimpleNamespace(name=name))


def test_a_string_names_the_one_format_it_spells():
    assert reporter_matches_requested_formats(_reporter("markdown"), "markdown")
    assert not reporter_matches_requested_formats(_reporter("sarif"), "markdown")


def test_a_string_is_read_the_way_a_one_item_list_is():
    for name in ("markdown", "sarif", "flat-json"):
        reporter = _reporter(name)
        assert reporter_matches_requested_formats(
            reporter, "markdown"
        ) == reporter_matches_requested_formats(reporter, ["markdown"])


def test_a_reporter_named_by_one_letter_is_not_matched_by_a_longer_string():
    assert not reporter_matches_requested_formats(_reporter("m"), "markdown")


def test_an_export_format_member_given_alone_names_its_format():
    member = next(iter(ExportFormat))
    assert reporter_matches_requested_formats(_reporter(str(member.value)), member)


def test_an_empty_string_is_an_empty_request():
    assert reporter_matches_requested_formats(_reporter("markdown"), "")


def test_bytes_are_refused():
    with pytest.raises(TypeError, match="not bytes"):
        reporter_matches_requested_formats(_reporter("markdown"), b"markdown")


def test_an_iterator_is_still_refused():
    with pytest.raises(TypeError, match="iterator"):
        reporter_matches_requested_formats(_reporter("markdown"), iter(["markdown"]))
