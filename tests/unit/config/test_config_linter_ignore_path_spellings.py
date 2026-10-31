# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""One expired ignore path draws one message when a section is spelled twice.

Why this file exists
--------------------
A scanner's section is found under any spelling the file gives it, and a scan
merges two spellings key by key with the canonical spelling winning. The expiry
check reported every spelling's list, so an entry written under both
``bandit:`` and ``Bandit:`` drew two near-identical messages at one path, one of
them about a list the scan never reads. When both spellings hold the list, only
the canonical one is reported.
"""

import pytest

from automated_security_helper.config.config_linter import (
    ConfigLinter,
    LintCategory,
    LintResult,
)

pytestmark = pytest.mark.unit

EXPIRED = {"path": "old", "reason": "r", "expiration": "2020-01-01"}


def _expired_messages(config_data) -> list:
    result = LintResult()
    ConfigLinter._check_ignore_path_expirations(config_data, result)
    return [
        issue
        for issue in result.issues
        if issue.category == LintCategory.IGNORE_PATH_ISSUE
    ]


def _section(**options) -> dict:
    return {"options": options}


def test_a_list_under_both_spellings_is_reported_once():
    """Red at the base: each spelling's list drew its own message."""
    config = {
        "scanners": {
            "bandit": _section(excluded_paths=[dict(EXPIRED)]),
            "Bandit": _section(excluded_paths=[dict(EXPIRED)]),
        }
    }

    found = _expired_messages(config)

    assert [issue.path for issue in found] == [
        "scanners.bandit.options.excluded_paths[0]"
    ]


def test_the_canonical_list_is_the_one_reported_when_the_other_differs():
    """The non-canonical list is shadowed: the scan reads the canonical one."""
    config = {
        "scanners": {
            "Bandit": _section(excluded_paths=[dict(EXPIRED), dict(EXPIRED)]),
            "bandit": _section(excluded_paths=[dict(EXPIRED)]),
        }
    }

    assert len(_expired_messages(config)) == 1


@pytest.mark.parametrize("spelling", ["bandit", "Bandit"])
def test_a_list_under_one_spelling_is_still_reported(spelling):
    """The positive control, for the canonical spelling and for another."""
    config = {"scanners": {spelling: _section(excluded_paths=[dict(EXPIRED)])}}

    assert len(_expired_messages(config)) == 1


def test_a_non_canonical_list_is_reported_when_the_canonical_one_sets_none():
    config = {
        "scanners": {
            "bandit": _section(),
            "Bandit": _section(excluded_paths=[dict(EXPIRED)]),
        }
    }

    assert len(_expired_messages(config)) == 1
