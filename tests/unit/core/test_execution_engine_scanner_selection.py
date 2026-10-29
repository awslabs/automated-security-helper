# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An allowlist cancelled by its own exclusions must not silently mean "all scanners".

The defect
----------
``ensure_initialized`` subtracts ``--exclude-scanners`` from ``--scanners``, and the
scan phase reads an *empty* allowlist as "no narrowing, run everything". So an operator
who excludes every scanner they also selected gets the opposite of what they asked for.

Measured on this tree, on a host with five of the ten scanner tools installed::

    ash scan --scanners detect-secrets --exclude-scanners detect-secrets
    -> PASSED 5, FAILED 1, MISSING 3, SKIPPED 1

detect-secrets -- the only scanner named -- is the one SKIPPED, and the nine that were
never asked for ran. On a runner with every tool present that reports a verdict on nine
scanners the operator excluded, and says nothing about the one they selected.

Why refusing is right, and why here
-----------------------------------
Two readings of ``--scanners X --exclude-scanners X`` are available and both are worse
than refusing. "Run everything" is what happens today and is the opposite of either
flag's intent. "Run nothing" would put every scanner in SKIPPED, which the completeness
gate has to tolerate one entry at a time, so it would be the silent-zero shape that
``ScannerSelectionError`` exists to prevent -- reached by a route the phase-level check
cannot see, because by the time it looks the allowlist is already empty and empty is
indistinguishable from "not given".

Refused here because this is the only layer that still holds both lists as the operator
wrote them. After the subtraction the information is gone. It is also the same shape as
``validate_shard_selection``: a contradictory selection is refused rather than resolved
to one of its readings.
"""

from unittest.mock import MagicMock

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ScannerSelectionError
from automated_security_helper.core.execution_engine import ScanExecutionEngine


def _engine(enabled, excluded, tmp_path, **kwargs):
    context = MagicMock()
    context.config = AshConfig(project_name="selection-test")
    context.source_dir = tmp_path
    context.output_dir = tmp_path / "out"
    context.work_dir = tmp_path / "work"
    return ScanExecutionEngine(
        context=context,
        enabled_scanners=enabled,
        excluded_scanners=excluded,
        asharp_model=MagicMock(),
        **kwargs,
    )


class TestAnAllowlistCancelledByExclusionsIsRefused:
    """Refused during construction, because ``__init__`` calls ``ensure_initialized``.

    Worth knowing rather than incidental: nothing has been discovered, instantiated or
    scanned by then, so the operator gets a refusal and no output directory rather than
    a report about the wrong nine scanners.
    """

    def test_the_single_name_case_is_refused(self, tmp_path):
        with pytest.raises(ScannerSelectionError) as excinfo:
            _engine(["detect-secrets"], ["detect-secrets"], tmp_path)

        message = str(excinfo.value)
        assert "detect-secrets" in message, (
            f"the name that was both selected and excluded has to be named: {message!r}"
        )
        assert "--exclude-scanners" in message, (
            "and the message has to say which two flags disagree, or the operator has "
            f"to guess which one to drop: {message!r}"
        )

    def test_every_selected_name_excluded_is_refused(self, tmp_path):
        with pytest.raises(ScannerSelectionError):
            _engine(["bandit", "semgrep"], ["semgrep", "bandit", "grype"], tmp_path)

    def test_case_and_space_do_not_evade_the_check(self, tmp_path):
        """The subtraction is case-insensitive, so the refusal has to be too.

        Otherwise ``--scanners BANDIT --exclude-scanners bandit`` empties the allowlist
        without tripping the check, and lands back in the defect through a spelling.
        """
        with pytest.raises(ScannerSelectionError):
            _engine([" BANDIT "], ["bandit"], tmp_path)

    def test_comma_separated_forms_are_refused_too(self, tmp_path):
        """Both lists are split on commas before comparison, so both forms must agree."""
        with pytest.raises(ScannerSelectionError):
            _engine(["bandit,semgrep"], ["bandit,semgrep"], tmp_path)


class TestSelectionsThatStillMeanSomething:
    """Controls. A check that refused any overlap at all would pass everything above."""

    def test_a_partial_exclusion_leaves_the_rest_selected(self, tmp_path):
        engine = _engine(["bandit", "semgrep"], ["semgrep"], tmp_path)
        assert engine._init_enabled_scanners == ["bandit"], (
            "excluding one of two selected scanners must leave the other selected"
        )

    def test_exclusions_with_no_allowlist_are_untouched(self, tmp_path):
        """The common shape: exclude a few, run the rest. Must not be refused.

        An empty allowlist here genuinely means "no narrowing", because the operator
        never gave one. That is the case the refusal has to be able to tell apart from
        an allowlist that was emptied.
        """
        engine = _engine([], ["grype", "syft"], tmp_path)
        assert engine._init_enabled_scanners == []
        assert engine._init_excluded_scanners == ["grype", "syft"]

    def test_an_allowlist_with_no_exclusions_is_untouched(self, tmp_path):
        engine = _engine(["bandit"], [], tmp_path)
        assert engine._init_enabled_scanners == ["bandit"]

    def test_excluding_something_that_was_never_selected_is_harmless(self, tmp_path):
        """A CI matrix may pass a blanket exclusion list to differently-narrowed jobs."""
        engine = _engine(["bandit"], ["grype", "syft"], tmp_path)
        assert engine._init_enabled_scanners == ["bandit"]


class TestTheRefusalNamesTheSelectionsOwnInputs:
    """The refusal names what the caller used, and says it as the workspace does.

    ``selection_origin`` is a public orchestrator field, so an engine built for an
    MCP caller outside a workspace scan reaches this refusal directly. The workspace
    pre-flight makes the same refusal for a workspace scan; the two share one
    implementation (``core.scanner_selection``), so their texts cannot drift.
    """

    def test_an_mcp_selection_names_the_parameters(self, tmp_path):
        with pytest.raises(ScannerSelectionError) as excinfo:
            _engine(["bandit"], ["bandit"], tmp_path, selection_origin="mcp")

        message = str(excinfo.value)
        assert (
            "Every scanner named by the scanners parameter is also named by the "
            "excluded_scanners parameter, so the selection cancels itself" in message
        ), message
        assert message.endswith("Drop one of the two."), message
        for flag in ("--scanners", "--exclude-scanners"):
            assert flag not in message, message

    @pytest.mark.parametrize("origin", ["cli", "mcp"])
    def test_the_engine_and_the_workspace_refuse_in_the_same_words(
        self, tmp_path, origin
    ):
        from automated_security_helper.workspace.execution import (
            ProjectScanSettings,
            refuse_unresolvable_scanner_selection,
        )
        from automated_security_helper.workspace.resolver import resolve_workspace

        with pytest.raises(ScannerSelectionError) as engine_refusal:
            _engine(["bandit"], ["bandit"], tmp_path, selection_origin=origin)
        (tmp_path / "api").mkdir()
        workspace_file = tmp_path / "dev.code-workspace"
        workspace_file.write_text('{"folders": [{"path": "api"}]}', encoding="utf-8")
        settings = ProjectScanSettings(
            output_dir=tmp_path / "workspace-out",
            enabled_scanners=("bandit",),
            excluded_scanners=("bandit",),
            selection_origin=origin,
        )
        with pytest.raises(ScannerSelectionError) as workspace_refusal:
            refuse_unresolvable_scanner_selection(
                resolve_workspace(workspace_file), settings
            )

        assert str(engine_refusal.value) == str(workspace_refusal.value)
