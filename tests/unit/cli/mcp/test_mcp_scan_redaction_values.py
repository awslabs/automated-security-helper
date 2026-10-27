# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The MCP scan runner's redaction set is read tolerantly and completely.

The runner redacts failure texts with the values configurations read from the
environment. Two helpers feed that set beside the scan's own config's values:
``_operator_environment_values`` reads the operator chain's values off the
limits section through the section's public accessor, and
``_profile_environment_values`` reads the session-bound trusted profile's
chain, whose values the scan resolves but the pre-check never saw. Both read
tolerantly: a stand-in with no record adds none, and a reading that fails
removes none of the scan's own values and is logged by its type only --
the values the read failed to produce are exactly the ones no log line may
hold.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Tuple

import pytest

from automated_security_helper.cli.mcp_tools import (
    _operator_environment_values,
    _profile_environment_values,
)

SECRET = "value-the-log-must-not-hold"


def test_the_runners_operator_read_is_the_sections_public_accessor():
    """The limits section's carried values come back through the public
    ``redaction_values`` accessor, which answers the same values as the
    model machinery's own internal read."""
    from automated_security_helper.config.ash_config import (
        MCPResourceManagementConfig,
    )
    from automated_security_helper.utils.redacted_model import (
        carry_environment_values,
    )

    limits = MCPResourceManagementConfig()
    carry_environment_values(limits, ("held-value",))

    assert limits.redaction_values() == ("held-value",)
    assert limits.redaction_values() == limits._redaction_values()
    assert _operator_environment_values(limits) == ("held-value",)


def test_a_limits_stand_in_with_no_record_adds_none(
    caplog: pytest.LogCaptureFixture,
):
    with caplog.at_level(logging.WARNING):
        assert _operator_environment_values(object()) == ()
    assert "could not be read" not in caplog.text


def test_a_raising_limits_record_is_logged_by_type_only(
    caplog: pytest.LogCaptureFixture,
):
    class Raising:
        def redaction_values(self) -> Tuple[str, ...]:
            raise RuntimeError(SECRET)

    with caplog.at_level(logging.WARNING):
        assert _operator_environment_values(Raising()) == ()
    assert "RuntimeError" in caplog.text
    assert SECRET not in caplog.text


class _RecordingRegistry:
    """finish_scan's record, for cells that read the reason a scan closes with."""

    def __init__(self) -> None:
        self.recorded: dict = {}

    def finish_scan(self, scan_id, status, reason, exit_code=None) -> None:
        self.recorded["reason"] = reason
        self.recorded["exit_code"] = exit_code


def test_a_short_exit_code_survives_the_widened_redaction_set():
    """``_scan_failed`` redacts the whole reason -- ``_exit_message``'s
    "ASH exited with code N" included -- with every value the operator's
    chain read. Shell exit codes are 0-255, at most three characters, and an
    unquoted value below the redaction floor matches only in quotes, so a
    code that happens to equal a short env-read value is still shown as the
    code; nothing needs to sit outside the redacted span."""
    from automated_security_helper.cli.mcp_tools import _exit_message, _scan_failed

    registry = _RecordingRegistry()

    _scan_failed(
        registry,
        "scan-1",
        _exit_message(SystemExit(2)),
        exit_code=2,
        environment_values=("2",),
    )

    assert registry.recorded["reason"] == "ASH exited with code 2", registry.recorded


def test_a_quoted_value_in_the_exit_reason_is_redacted():
    """Control: the redaction does reach the exit message's span. A short
    value matches in quotes (a quoted occurrence is a deliberate echo of the
    value), so a reason quoting it shows the marker, never the value."""
    from automated_security_helper.cli.mcp_tools import _scan_failed

    registry = _RecordingRegistry()

    _scan_failed(
        registry,
        "scan-1",
        "ASH exited with code 2: refused '2'",
        exit_code=2,
        environment_values=("2",),
    )

    assert "'2'" not in registry.recorded["reason"], registry.recorded
    assert registry.recorded["reason"].startswith("ASH exited with code 2"), (
        registry.recorded
    )


def test_the_profiles_chain_values_join_the_redaction_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("ASH_PROFILE_HELD", "profile-held-value")
    profile = tmp_path / "profile.yaml"
    profile.write_text("project_name: ${ASH_PROFILE_HELD}\n", encoding="utf-8")

    values = _profile_environment_values(profile)

    assert "profile-held-value" in values, values


def test_a_profile_under_dot_ash_extending_past_it_adds_its_chain_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The helper resolves the chain as the scan's own loader does: for a
    profile in a ``.ash`` directory the confinement root is that directory's
    parent, so a base beside ``.ash`` is read and its values join the set.
    A reader whose root were the ``.ash`` directory itself would refuse the
    base the scan loads, and the values in use would silently drop out."""
    monkeypatch.setenv("ASH_DOT_ASH_BASE", "dot-ash-base-held-value")
    base = tmp_path / "base.yaml"
    base.write_text("project_name: ${ASH_DOT_ASH_BASE}\n", encoding="utf-8")
    dot_ash = tmp_path / ".ash"
    dot_ash.mkdir()
    profile = dot_ash / "profile.yaml"
    profile.write_text("extends: ../base.yaml\n", encoding="utf-8")

    values = _profile_environment_values(profile)

    assert "dot-ash-base-held-value" in values, values


def test_no_profile_reads_nothing():
    assert _profile_environment_values(None) == ()


def test_a_failing_profile_read_is_logged_by_type_only(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
):
    """The fault is in the file itself, not patched into a named callee: a
    profile extending a base that does not exist fails whatever loader the
    helper reads through, and the loader's own error names the missing path.
    The path here is the secret, so the cell measures the property -- the
    failure reaches the log as its type alone -- and not the helper's choice
    of callee."""
    profile = tmp_path / "profile.yaml"
    profile.write_text(f"extends: {SECRET}.yaml\n", encoding="utf-8")
    # Control: the real read of this file raises, and its text carries the
    # secret-named path the warning below must not.
    with pytest.raises(Exception, match=SECRET):
        from automated_security_helper.config.resolve_config import (
            load_config_file_for_run,
        )

        load_config_file_for_run(profile)

    with caplog.at_level(logging.WARNING):
        assert _profile_environment_values(profile) == ()
    assert "could not be read for redaction" in caplog.text
    assert "ASHConfigSourceError" in caplog.text
    assert SECRET not in caplog.text
