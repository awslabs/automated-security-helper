# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A section's repr shows an opted typed field by placeholder, never by number.

scan_timeout is opted into environment references
(``ScannerOptionsBase._env_scalar_typed_fields``): a lax plugin model types the
resolved text, so the section holds a number, not the text the redaction
needle matches. The needle cannot catch it -- a number under
MIN_REDACTED_LENGTH is below the band ("67"), and a respelled read ("0067"
typed to 67) prints a spelling the needle never saw. The section's repr is a
shown surface (tracebacks with locals, DEBUG logs), so the repr itself shows
such a field as ``<value>`` whenever a carried environment value types to it
(``config_validator.typed_from``), and keeps a literal number readable.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.utils.redacted_model import carry_environment_values

pytestmark = pytest.mark.unit


def _options(timeout: int, carried: str) -> ScannerOptionsBase:
    options = ScannerOptionsBase(scan_timeout=timeout)
    carry_environment_values(options, (carried,))
    return options


@pytest.mark.parametrize(
    ("written", "typed"),
    [("67", 67), ("0067", 67)],
    ids=["short", "respelled"],
)
def test_a_timeout_typed_from_the_environment_shows_as_value(written, typed):
    text = repr(_options(typed, written))

    assert f"scan_timeout={typed}" not in text, text
    assert "scan_timeout=<value>" in text, text


def test_a_long_environment_number_shows_no_digits_either():
    """A value long enough for the text needle: whichever layer catches it,
    no spelling of it is shown."""
    text = repr(_options(987654, "987654"))

    assert "987654" not in text, text


def test_a_literal_timeout_still_shows_its_number():
    """The must-not-flag control: a carried value that does not type to the
    limit leaves the written number readable."""
    text = repr(_options(300, "zz-not-a-number-canary"))

    assert "scan_timeout=300" in text, text
