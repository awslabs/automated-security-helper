# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A selection that names the retired ``semgrep`` is served by opengrep.

``--scanners semgrep`` is documented as working. The engine's construction-time
check compared the requested names against the registered names with no alias
resolution, so a selection of only ``semgrep`` matched nothing and was refused
before ScanPhase could resolve it. The selection helpers now compare through the
alias table, so the three checks agree with ScanPhase.
"""

import pytest

from automated_security_helper.core.scanner_selection import (
    community_scanner_refusal,
    exclusions_matching_no_scanner,
    refuse_selection_matching_no_scanner,
)

pytestmark = pytest.mark.unit

REGISTERED = ["bandit", "opengrep", "gitleaks"]


def test_a_selection_naming_only_the_retired_name_is_not_refused():
    refuse_selection_matching_no_scanner(["semgrep"], REGISTERED, "cli")


def test_the_retired_name_is_matched_whatever_its_case_and_spacing():
    refuse_selection_matching_no_scanner([" SemGrep "], REGISTERED, "cli")


def test_the_control_a_name_that_matches_nothing_is_still_refused():
    from automated_security_helper.core.exceptions import ScannerSelectionError

    with pytest.raises(ScannerSelectionError):
        refuse_selection_matching_no_scanner(["no-such-scanner"], REGISTERED, "cli")


def test_an_exclusion_by_the_retired_name_is_not_reported_as_unmatched():
    assert exclusions_matching_no_scanner(["semgrep"], REGISTERED) == []
    assert exclusions_matching_no_scanner(["no-such-scanner"], REGISTERED) == [
        "no-such-scanner"
    ]


def test_the_community_refusal_does_not_apply_to_the_retired_name():
    class _Scanner:
        pass

    assert community_scanner_refusal(["semgrep"], REGISTERED, [_Scanner]) == ""


def test_the_engine_accepts_a_selection_of_only_the_retired_name(tmp_path):
    from unittest.mock import MagicMock

    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.core.execution_engine import ScanExecutionEngine

    context = MagicMock()
    context.config = AshConfig(project_name="selection-test")
    context.source_dir = tmp_path
    context.output_dir = tmp_path / "out"
    context.work_dir = tmp_path / "work"
    engine = ScanExecutionEngine(
        context=context,
        enabled_scanners=["semgrep"],
        excluded_scanners=[],
        asharp_model=MagicMock(),
    )

    assert engine._init_enabled_scanners == ["semgrep"]
    names = [
        engine._selectable_scanner_name(cls)
        for cls in engine.plugins.get("scanner", [])
    ]
    assert "opengrep" in names, names


def test_a_registry_that_lists_the_old_name_matches_the_old_name():
    refuse_selection_matching_no_scanner(["semgrep"], ["bandit", "Semgrep"], "cli")
    assert exclusions_matching_no_scanner(["opengrep"], ["Semgrep"]) == []
