# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ferret-scan's dependency check refuses what its options and probes say it should.

Three gates that used to let the scanner run and be graded anyway:

- ``skip_version_check`` had no effect: an out-of-range ferret-scan ran whether the
  option was true or false, and the warning told the operator to set an option
  that changed nothing. Now an out-of-range version is MISSING with a reason that
  names the option, and ``skip_version_check: true`` lets it run.
- ``validate_plugin_dependencies`` never read ``dependency_unavailable_reason`` and
  read a version probe that a refusing sandbox scope turned down (a
  ``SandboxUnavailable``, an ``OSError``) as "no version, assume compatible", so a
  scanner that asked for a sandbox it cannot have answered True. Now a recorded
  reason, and a refused probe, answer False.
- The bundled ``redaction`` and ``secure-redaction`` profiles turn on ferret-scan's
  redaction, which the plugin declares unsupported, and name their output paths
  relative to the working directory ferret-scan runs from. Selecting one now
  records a reason at construction, and the dependency check refuses.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from automated_security_helper.plugin_modules.ash_ferret_plugins import ferret_scanner
from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
    FerretScannerConfig,
    FerretScannerConfigOptions,
    FerretScanScanner,
    bundled_redaction_profiles,
)
from automated_security_helper.utils.sandbox.policy import SandboxUnavailable

pytestmark = pytest.mark.unit

BINARY = "/opt/ferret/bin/ferret-scan"


def _scanner(context, **options) -> FerretScanScanner:
    return FerretScanScanner(
        context=context,
        config=FerretScannerConfig(options=FerretScannerConfigOptions(**options)),
    )


@pytest.fixture
def binary_present(monkeypatch):
    monkeypatch.setattr(ferret_scanner, "find_executable", lambda name: BINARY)


def test_an_out_of_range_version_is_refused_unless_the_check_is_skipped(
    mock_plugin_context, binary_present
):
    scanner = _scanner(mock_plugin_context)

    with (
        patch.object(
            scanner,
            "_check_version_compatibility",
            return_value=(False, "99.0.0", "Version too new."),
        ),
        patch.object(scanner, "_plugin_log"),
    ):
        assert scanner.validate_plugin_dependencies() is False

    assert scanner.dependencies_satisfied is False
    reason = scanner.dependency_unavailable_reason
    assert reason is not None
    assert "Version too new." in reason
    assert "skip_version_check=true" in reason


def test_control_skip_version_check_lets_an_out_of_range_version_run(
    mock_plugin_context, binary_present
):
    scanner = _scanner(mock_plugin_context, skip_version_check=True)

    with (
        patch.object(
            scanner,
            "_check_version_compatibility",
            return_value=(False, "99.0.0", "Version too new."),
        ),
        patch.object(scanner, "_plugin_log"),
    ):
        assert scanner.validate_plugin_dependencies() is True

    assert scanner.dependency_unavailable_reason is None


def test_a_recorded_reason_is_read_before_the_binary_is_probed(
    mock_plugin_context, binary_present
):
    scanner = _scanner(mock_plugin_context)
    scanner.dependency_unavailable_reason = "recorded at construction"

    with (
        patch.object(scanner, "_check_version_compatibility") as probe,
        patch.object(scanner, "_plugin_log"),
    ):
        assert scanner.validate_plugin_dependencies() is False

    probe.assert_not_called()


def test_a_refused_version_probe_is_not_read_as_compatible(
    mock_plugin_context, binary_present, monkeypatch
):
    """Under a refusing sandbox scope the probe raises SandboxUnavailable, an
    OSError; swallowing it read as "no version, assume compatible"."""

    def _refuse(*args, **kwargs):
        raise SandboxUnavailable("ferret-scan cannot be sandboxed as requested")

    monkeypatch.setattr(ferret_scanner, "spawn_run", _refuse)
    scanner = _scanner(mock_plugin_context)

    with patch.object(scanner, "_plugin_log"):
        assert scanner.validate_plugin_dependencies() is False

    reason = scanner.dependency_unavailable_reason
    assert reason is not None
    assert "cannot be sandboxed as requested" in reason


def test_the_bundled_config_names_its_redaction_profiles():
    assert {"redaction", "secure-redaction"} <= bundled_redaction_profiles()
    assert "ci" not in bundled_redaction_profiles()


@pytest.fixture
def fresh_profile_read():
    """The bundled file's cached read, cleared before and after the test."""
    ferret_scanner._bundled_redaction_profiles_read.cache_clear()
    yield
    ferret_scanner._bundled_redaction_profiles_read.cache_clear()


def test_a_failed_read_of_the_bundled_config_is_not_cached(
    tmp_path, fresh_profile_read
):
    """One transient read error must not turn the redaction refusal off for the
    rest of the process: the known names stay, and the next call reads the file
    again (here one that adds a profile, which proves the read happened)."""
    extra = tmp_path / "ferret-config.yaml"
    extra.write_text(
        "profiles:\n  extra-redaction:\n    redaction:\n      enabled: true\n",
        encoding="utf-8",
    )

    with patch.object(ferret_scanner, "DEFAULT_FERRET_CONFIG", tmp_path / "missing"):
        assert bundled_redaction_profiles() == {"redaction", "secure-redaction"}
    with patch.object(ferret_scanner, "DEFAULT_FERRET_CONFIG", extra):
        assert "extra-redaction" in bundled_redaction_profiles()
        assert {"redaction", "secure-redaction"} <= bundled_redaction_profiles()


@pytest.mark.parametrize("profile", ["redaction", "secure-redaction"])
def test_a_bundled_redaction_profile_is_refused(
    mock_plugin_context, binary_present, profile
):
    scanner = _scanner(mock_plugin_context, profile=profile)

    reason = scanner.dependency_unavailable_reason
    assert reason is not None
    assert profile in reason
    assert "redaction" in reason
    with (
        patch.object(
            scanner, "_check_version_compatibility", return_value=(True, "2.5.3", None)
        ),
        patch.object(scanner, "_plugin_log"),
    ):
        assert scanner.validate_plugin_dependencies() is False


def test_control_another_bundled_profile_is_accepted(
    mock_plugin_context, binary_present
):
    scanner = _scanner(mock_plugin_context, profile="ci")

    assert scanner.dependency_unavailable_reason is None
    with (
        patch.object(
            scanner, "_check_version_compatibility", return_value=(True, "2.5.3", None)
        ),
        patch.object(scanner, "_plugin_log"),
    ):
        assert scanner.validate_plugin_dependencies() is True
