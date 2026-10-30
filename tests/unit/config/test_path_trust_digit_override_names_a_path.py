# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``--config-overrides`` value of digits is recorded as the text the operator wrote.

``resolve_config`` parses ``2024`` as a number, and a string option keeps the text
(``_validated_with_overrides``). ``OperatorPaths`` compares a path with the value an
override set, and only a string can be a path, so an override naming a file called
``2024`` has to be recorded as the text to be credited to the operator.
"""

import pytest

from automated_security_helper.config.path_trust import OperatorPaths, parse_overrides

pytestmark = pytest.mark.unit

KEY = "scanners.bandit.options.config_file"


@pytest.mark.parametrize("raw", ["2024", "007", "1.10"])
def test_digit_text_is_recorded_as_written(raw):
    assert parse_overrides([f"{KEY}={raw}"]) == [(KEY, raw)]


def test_an_override_naming_a_digit_only_path_is_the_operators():
    paths = OperatorPaths(overrides=parse_overrides([f"{KEY}=2024"]))

    assert paths.named(KEY, "2024")
    assert not paths.named(KEY, "2025")


def test_values_that_are_not_digit_text_keep_their_type():
    assert parse_overrides([f"{KEY}=true", f"{KEY}=null", f"{KEY}=[a, b]"]) == [
        (KEY, True),
        (KEY, None),
        (KEY, ["a", "b"]),
    ]
