# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A severity restriction that names no threshold is refused like a bad config.

Why these tests exist
---------------------
``ASHScanOrchestrator._restrict_severity_threshold`` refuses a restriction that is
not one of ALL, LOW, MEDIUM, HIGH or CRITICAL. It raised ``ASHValidationError``,
which the CLI's handlers do not read as a refused input: the scan ended in the
generic "Exiting due to exception" arm with exit code 1, where an invalid
configuration exits 3 with its message. ``ASHConfigValidationError`` is an
``ASHValidationError`` and a ``ValueError``, so every caller that caught the
first still does.

Each test states the assertion that fails at the base.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import (
    ASHConfigValidationError,
    ASHValidationError,
)
from automated_security_helper.core.orchestrator import ASHScanOrchestrator

pytestmark = pytest.mark.unit


def _orchestrator(tmp_path) -> ASHScanOrchestrator:
    source = tmp_path / "proj"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    return ASHScanOrchestrator(source_dir=source, output_dir=output)


def test_an_unknown_threshold_is_a_config_validation_error(tmp_path):
    orchestrator = _orchestrator(tmp_path)

    with pytest.raises(ASHConfigValidationError) as raised:
        orchestrator._restrict_severity_threshold(AshConfig(), "BOGUS")

    # Red at the base: a plain ASHValidationError.
    assert "'BOGUS' is not one of ALL, LOW, MEDIUM, HIGH or CRITICAL" in str(
        raised.value
    )
    assert isinstance(raised.value, ASHValidationError)


def test_a_ladder_word_is_accepted(tmp_path):
    """The control: a valid restriction raises nothing."""
    orchestrator = _orchestrator(tmp_path)

    orchestrator._restrict_severity_threshold(AshConfig(), "HIGH")
