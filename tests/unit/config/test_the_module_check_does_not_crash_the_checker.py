# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A defect in the module check's own resolution does not crash the checker.

``check_config_file`` runs a second ``resolve_config`` to judge
``ash_plugin_modules`` the way a scan would. That resolution's failure
surface is wider than the source refusals its arm names: with
``fallback_to_default=False`` anything else re-raises raw, and the trust
confinement ran on no checker path before this call existed. A defect there
is the check's own, not the file's: ``ash config validate``, ``lint``,
``get``'s error printer and the MCP ``validate_config`` tool all call the
check and must keep answering about the file.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit


def test_the_module_checks_own_resolution_failure_does_not_crash_the_check(
    tmp_path, monkeypatch
):
    from automated_security_helper.config import resolve_config as resolve_module
    from automated_security_helper.config.config_validator import ConfigValidator

    config = tmp_path / ".ash.yaml"
    # The module check only runs for a config that names modules (its call
    # site is gated on ash_plugin_modules); without one the arm under test is
    # never reached and this cell would pass over an empty check.
    config.write_text(
        "project_name: checked\n"
        "ash_plugin_modules:\n"
        "  - automated_security_helper.plugin_modules.ash_builtin\n",
        encoding="utf-8",
    )

    def raises(*args, **kwargs):
        raise TypeError("a defect in the resolution, not in the file")

    # The checker's only use of resolve_config is the module check's second
    # resolution (one call site), so this reaches exactly that call.
    monkeypatch.setattr(resolve_module, "resolve_config", raises)

    check = ConfigValidator.check_config_file(config)

    # The file is valid: a failure of the check's own machinery is never shown
    # as the file's. (This cell previously asserted ONLY that, which locked in
    # a silent fail-open; the re-pin below is declared.)
    assert check.errors == [], check.errors
    # Not silent either: the check says it could not judge the modules, naming
    # the failure's type and nothing of its text.
    failures = [w for w in check.warnings if "could not run" in w]
    assert failures, check.warnings
    assert any("TypeError" in w for w in failures), failures
    assert "a defect in the resolution" not in " ".join(check.warnings)
