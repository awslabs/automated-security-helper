# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The expiry warnings quote an environment-read date by its reference.

Why this file exists
--------------------
``recorded_suppressions`` keys its environment record by the SHOWN field names,
and ``record_environment_references`` finds a reference by the key the FILE
wrote the value at. After the field's rename the shown key was still
``expiration`` while the documented config spelling is ``expires``, so an entry
written ``expires: ${VAR}`` found no position in the record and the 30-day and
expired-entries warnings printed the RESOLVED environment value, which this
record exists to prevent. The shown key is now ``expires``, and the record
covers the deprecated ``expiration`` alias spelling too, so either spelling in
the file keeps the reference in the warning.
"""

from __future__ import annotations

import warnings as _warnings
from datetime import date, timedelta
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.plugin_modules.ash_builtin.event_handlers import (
    suppression_expiration_checker,
)

pytestmark = pytest.mark.unit

_LOGGER = (
    "automated_security_helper.plugin_modules.ash_builtin.event_handlers."
    "suppression_expiration_checker.ASH_LOGGER"
)


def _in_days(days: int) -> str:
    return (date.today() + timedelta(days=days)).strftime("%Y-%m-%d")


def _config_from(tmp_path, spelling: str, reference: str):
    source = tmp_path / "src"
    source.mkdir()
    (source / ".ash.yaml").write_text(
        "project_name: expiry-ref\n"
        "global_settings:\n"
        "  suppressions:\n"
        "    - path: 'src/app.py'\n"
        "      rule_id: B101\n"
        "      reason: accepted\n"
        f"      {spelling}: {reference}\n",
        encoding="utf-8",
    )
    with _warnings.catch_warnings():
        # The deprecated spelling case warns by design; the test reads the log.
        _warnings.simplefilter("ignore", DeprecationWarning)
        return resolve_config(source_dir=source)


def _warnings_logged(config) -> str:
    context = SimpleNamespace(config=config, ignore_suppressions=False)
    with patch(_LOGGER) as logger:
        suppression_expiration_checker.handle_suppression_expiration_check(
            plugin_context=context
        )
    return " ".join(str(call.args[0]) for call in logger.warning.call_args_list)


@pytest.mark.parametrize("spelling", ["expires", "expiration"])
def test_an_expiring_env_read_date_is_shown_as_its_reference(
    tmp_path, monkeypatch, spelling
):
    """Red before the fix for ``expires``: the warning held the resolved date."""
    resolved = _in_days(5)
    monkeypatch.setenv("ASH_TEST_Q2_EXPIRY", resolved)
    config = _config_from(tmp_path, spelling, "${ASH_TEST_Q2_EXPIRY}")

    logged = _warnings_logged(config)

    assert "expire within 30 days" in logged, logged
    assert "${ASH_TEST_Q2_EXPIRY}" in logged, logged
    assert resolved not in logged, logged


@pytest.mark.parametrize("spelling", ["expires", "expiration"])
def test_an_expired_env_read_date_is_shown_as_its_reference(
    tmp_path, monkeypatch, spelling
):
    resolved = _in_days(-5)
    monkeypatch.setenv("ASH_TEST_Q2_EXPIRY", resolved)
    config = _config_from(tmp_path, spelling, "${ASH_TEST_Q2_EXPIRY}")

    logged = _warnings_logged(config)

    assert "have expired" in logged, logged
    assert "${ASH_TEST_Q2_EXPIRY}" in logged, logged
    assert resolved not in logged, logged


def test_a_literal_date_is_still_shown_as_itself(tmp_path):
    """The positive control: a date the file wrote itself is quoted as it is."""
    written = _in_days(5)
    config = _config_from(tmp_path, "expires", f'"{written}"')

    logged = _warnings_logged(config)

    assert "expire within 30 days" in logged, logged
    assert written in logged, logged
