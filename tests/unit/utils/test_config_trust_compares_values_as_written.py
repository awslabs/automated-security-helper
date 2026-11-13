# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""set_by_operator compares a value with the operator's as written.

``operator_path`` resolves the value a scanner is about to use as given, so a
value that differs from the operator's only by a leading or trailing character
names a different file. ``set_by_operator`` used to compare the two after
``str.strip``, which also removes the separators U+001C to U+001F that the
config model keeps, so a repository's value differing from the operator's by such
a character alone was judged the operator's and then resolved, relative to the
source directory, to a path inside the scanned tree.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.utils.config_trust import (
    record_provenance,
    set_by_operator,
)

pytestmark = pytest.mark.unit

KEY = "scanners.gitleaks.options.baseline_path"
OPERATORS = "/ops/gitleaks-baseline.json"


def _config_with_an_in_tree_file() -> SimpleNamespace:
    config = SimpleNamespace()
    record_provenance(
        config,
        in_tree=[Path("repo/.ash/.ash.yaml")],
        trusted={"scanners": {"gitleaks": {"options": {"baseline_path": OPERATORS}}}},
    )
    return config


def test_the_operators_value_as_written_is_the_operators():
    config = _config_with_an_in_tree_file()

    assert set_by_operator(config, KEY, OPERATORS)
    assert set_by_operator(config, KEY, Path(OPERATORS))


@pytest.mark.parametrize(
    "edge",
    [
        pytest.param(" ", id="a-space"),
        pytest.param("\t", id="a-tab"),
        pytest.param("\n", id="a-newline"),
        pytest.param(chr(0x1C), id="file-separator"),
        pytest.param(chr(0x1F), id="unit-separator"),
    ],
)
def test_a_value_differing_by_a_leading_or_trailing_character_is_not(edge):
    config = _config_with_an_in_tree_file()

    assert not set_by_operator(config, KEY, edge + OPERATORS)
    assert not set_by_operator(config, KEY, OPERATORS + edge)
    assert not set_by_operator(config, KEY, Path(edge + OPERATORS))
