# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""TDD tests for issue #171: expiration validator format-only + exit code 3.

These tests were written before the fix and must FAIL on the old code, then
pass after the implementation is applied.
"""
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from automated_security_helper.models.core import AshSuppression


# ---------------------------------------------------------------------------
# AshSuppression.validate_expiration_date — format-only validation
# ---------------------------------------------------------------------------


def test_past_expiration_accepted_by_validator():
    """Past expiration date must not raise; validator checks format only."""
    s = AshSuppression(
        rule_id="RULE-001",
        path="src/main.py",
        reason="known false positive",
        expiration="2020-01-01",
    )
    assert s.expiration == "2020-01-01"


def test_past_expiration_is_expired():
    """A past expiration date must result in is_expired == True."""
    s = AshSuppression(
        rule_id="RULE-001",
        path="src/main.py",
        reason="known false positive",
        expiration="2020-01-01",
    )
    assert s.is_expired is True


def test_malformed_expiration_rejected():
    """A non-YYYY-MM-DD string must still raise ValidationError."""
    with pytest.raises(ValidationError) as exc_info:
        AshSuppression(
            rule_id="RULE-001",
            path="src/main.py",
            reason="test",
            expiration="not-a-date",
        )
    assert "YYYY-MM-DD" in str(exc_info.value)


def test_future_expiration_not_expired():
    """A future expiration date is accepted and is_expired == False."""
    s = AshSuppression(
        rule_id="RULE-001",
        path="src/main.py",
        reason="suppressed until next audit",
        expiration="2099-12-31",
    )
    assert s.expiration == "2099-12-31"
    assert s.is_expired is False


# ---------------------------------------------------------------------------
# Exit code 3 on invalid config
# ---------------------------------------------------------------------------


def test_invalid_config_triggers_exit_code_3(tmp_path):
    """An invalid config file must cause run_ash_scan to exit with code 3.

    Uses build set to a scalar string, which pydantic cannot coerce to the
    expected BuildConfig model and raises ValidationError.
    """
    bad_config = tmp_path / ".ash.yaml"
    # build expects a BuildConfig object; a plain string triggers ValidationError
    bad_config.write_text("build: not_an_object\n")

    from automated_security_helper.interactions.run_ash_scan import run_ash_scan
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    with pytest.raises(SystemExit) as exc_info:
        run_ash_scan(
            source_dir=str(tmp_path),
            output_dir=str(tmp_path / "output"),
            config=str(bad_config),
        )

    assert exc_info.value.code == 3
