# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""--only-scanners, --add-scanners, the precommit config keys, and what wins.

Why this file exists
--------------------
``--scanners`` is additive in ``--mode precommit`` (the five-scanner default set
stays whatever it names), which operators found surprising: there was no way to
shrink the set except ``--exclude-scanners``. The replacement surface is three
things that say what they do: ``--only-scanners`` (the whole selection),
``--add-scanners`` (explicitly additive), and the config file's
``precommit.only_scanners`` / ``precommit.add_scanners`` keys. ``--scanners``
keeps its behavior and gains a deprecation line.

The precedence under test, lowest to highest
(``SelectionLayers.fold`` in ``core/scanner_selection.py`` is the one place it is
implemented):

1. mode default (``PRECOMMIT_MODE_SCANNERS`` in precommit mode, empty elsewhere)
2. the operator's ``default_scanners`` (every mode), folded by the orchestrator
   against its settled config
3. config: ``precommit.only_scanners`` replaces the lower layers,
   ``precommit.add_scanners`` adds (both at once is refused by the model)
4. CLI: ``--only-scanners`` replaces everything above; ``--add-scanners`` and
   the deprecated ``--scanners`` add
5. ``--exclude-scanners`` applies after selection, in the engine, so exclusion
   wins over inclusion -- these tests assert it is handed through untouched

No scanner runs here: the orchestrator's ``create`` is replaced and recorded,
exactly as ``test_run_ash_scan_helpers_coverage`` does for the existing
precommit test, and the CLI-level tests stop at the usage refusal or replace
``run_ash_scan`` itself.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest
from typer.testing import CliRunner

from automated_security_helper.core.enums import RunMode
from automated_security_helper.interactions.run_ash_scan import (
    PRECOMMIT_MODE_SCANNERS,
    ScanOptions,
    _folded_scanner_allowlist,
    _run_local_mode,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults

pytestmark = pytest.mark.unit


class _RecordingLogger:
    """Only the members the selection code calls; a Mock would fabricate more."""

    def __init__(self) -> None:
        self.records: Dict[str, List[str]] = {
            "verbose": [],
            "debug": [],
            "info": [],
            "warning": [],
            "error": [],
        }

    def verbose(self, message, **kwargs):
        self.records["verbose"].append(str(message))

    def debug(self, message, **kwargs):
        self.records["debug"].append(str(message))

    def info(self, message, **kwargs):
        self.records["info"].append(str(message))

    def warning(self, message, **kwargs):
        self.records["warning"].append(str(message))

    def error(self, message, **kwargs):
        self.records["error"].append(str(message))


class _StubOrchestrator:
    def __init__(self, results):
        self.config = None
        self._results = results
        self.added_metadata: Dict[str, Any] = {}

    def add_metadata(self, **values):
        self.added_metadata.update(values)

    def restrict_to_changed_files(self, changed_files):
        pass

    def execute_scan(self, phases):
        return self._results


def _selected(opts: ScanOptions, logger: _RecordingLogger) -> List[str]:
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    recorded: List[Dict[str, Any]] = []

    def fake_create(**kwargs):
        recorded.append(kwargs)
        return _StubOrchestrator(AshAggregatedResults())

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(ASHScanOrchestrator, "create", staticmethod(fake_create))
        _run_local_mode(opts, logger)
    return list(recorded[0]["enabled_scanners"])


@pytest.fixture
def logger() -> _RecordingLogger:
    return _RecordingLogger()


@pytest.fixture
def local_orchestrator(monkeypatch):
    """Replace ASHScanOrchestrator.create and record the kwargs it was handed."""
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    recorded: Dict[str, Any] = {"create_kwargs": []}

    def fake_create(**kwargs):
        recorded["create_kwargs"].append(kwargs)
        return _StubOrchestrator(AshAggregatedResults())

    monkeypatch.setattr(ASHScanOrchestrator, "create", staticmethod(fake_create))
    return recorded


def _opts(source_dir: Path, output_dir: Path, **overrides: Any) -> ScanOptions:
    output_dir.mkdir(exist_ok=True)
    return ScanOptions(source_dir=source_dir, output_dir=output_dir, **overrides)


def _config_file(tmp_path: Path, body: str) -> str:
    path = tmp_path / "selection.ash.yaml"
    path.write_text(body, encoding="utf-8")
    return str(path)


# --------------------------------------------------------------------------- #
# The precedence matrix, at the selection resolver
# --------------------------------------------------------------------------- #


class TestSelectionPrecedence:
    def test_precommit_default_is_the_mode_set(self, tmp_path, logger):
        opts = _opts(tmp_path, tmp_path / "out", mode=RunMode.precommit)

        selected = _selected(opts, logger)

        assert sorted(selected) == sorted(PRECOMMIT_MODE_SCANNERS)

    def test_config_only_scanners_replaces_the_mode_default(self, tmp_path, logger):
        config = _config_file(
            tmp_path,
            "project_name: t\nprecommit:\n  only_scanners:\n    - bandit\n",
        )
        opts = _opts(tmp_path, tmp_path / "out", mode=RunMode.precommit, config=config)

        assert _selected(opts, logger) == ["bandit"]

    def test_config_add_scanners_adds_to_the_mode_default(self, tmp_path, logger):
        config = _config_file(
            tmp_path,
            "project_name: t\nprecommit:\n  add_scanners:\n    - grype\n",
        )
        opts = _opts(tmp_path, tmp_path / "out", mode=RunMode.precommit, config=config)

        selected = _selected(opts, logger)

        assert sorted(selected) == sorted(list(PRECOMMIT_MODE_SCANNERS) + ["grype"])

    def test_config_keys_apply_through_config_overrides_alone(self, tmp_path, logger):
        """No config file: a --config-overrides entry naming the section counts."""
        opts = _opts(
            tmp_path,
            tmp_path / "out",
            mode=RunMode.precommit,
            config_overrides=["precommit.only_scanners=[bandit]"],
        )

        assert _selected(opts, logger) == ["bandit"]

    def test_cli_only_scanners_replaces_mode_default_and_config(self, tmp_path, logger):
        config = _config_file(
            tmp_path,
            "project_name: t\nprecommit:\n  add_scanners:\n    - grype\n",
        )
        opts = _opts(
            tmp_path,
            tmp_path / "out",
            mode=RunMode.precommit,
            config=config,
            only_scanners=["checkov"],
        )

        assert _selected(opts, logger) == ["checkov"]

    def test_cli_add_scanners_adds_to_the_mode_default(self, tmp_path, logger):
        opts = _opts(
            tmp_path,
            tmp_path / "out",
            mode=RunMode.precommit,
            add_scanners=["grype"],
        )

        selected = _selected(opts, logger)

        assert sorted(selected) == sorted(list(PRECOMMIT_MODE_SCANNERS) + ["grype"])

    def test_cli_add_scanners_adds_on_top_of_the_config_keys(self, tmp_path, logger):
        config = _config_file(
            tmp_path,
            "project_name: t\nprecommit:\n  only_scanners:\n    - bandit\n",
        )
        opts = _opts(
            tmp_path,
            tmp_path / "out",
            mode=RunMode.precommit,
            config=config,
            add_scanners=["grype"],
        )

        assert sorted(_selected(opts, logger)) == ["bandit", "grype"]

    def test_legacy_scanners_stays_additive_in_precommit(self, tmp_path, logger):
        """--scanners behavior is unchanged: additive to the mode default."""
        opts = _opts(
            tmp_path,
            tmp_path / "out",
            mode=RunMode.precommit,
            scanners=["grype"],
        )

        selected = _selected(opts, logger)

        assert sorted(selected) == sorted(list(PRECOMMIT_MODE_SCANNERS) + ["grype"])

    def test_local_mode_ignores_the_precommit_config_keys(self, tmp_path, logger):
        config = _config_file(
            tmp_path,
            "project_name: t\nprecommit:\n  only_scanners:\n    - bandit\n",
        )
        opts = _opts(
            tmp_path,
            tmp_path / "out",
            mode=RunMode.local,
            config=config,
            scanners=["grype"],
        )

        assert _selected(opts, logger) == ["grype"]

    def test_local_mode_only_scanners_is_the_allowlist(self, tmp_path, logger):
        opts = _opts(
            tmp_path, tmp_path / "out", mode=RunMode.local, only_scanners=["bandit"]
        )

        assert _selected(opts, logger) == ["bandit"]

    def test_the_selection_is_deduplicated_in_first_appearance_order(
        self, tmp_path, logger
    ):
        opts = _opts(
            tmp_path,
            tmp_path / "out",
            mode=RunMode.precommit,
            scanners=["bandit"],
            add_scanners=["bandit", "grype"],
        )

        selected = _selected(opts, logger)

        assert selected.count("bandit") == 1
        assert set(selected) == set(PRECOMMIT_MODE_SCANNERS) | {"grype"}


class TestFoldedAllowlist:
    """The no-mode-default paths (workspace, the container's forwarded list)."""

    def test_only_scanners_is_the_whole_list(self, tmp_path):
        opts = _opts(
            tmp_path,
            tmp_path / "out",
            only_scanners=["bandit"],
            # A library caller may set these beside only_scanners; only_scanners
            # wins by the documented precedence (the CLI refuses the combination).
            scanners=["grype"],
            add_scanners=["checkov"],
        )

        assert _folded_scanner_allowlist(opts) == ["bandit"]

    def test_additive_flags_concatenate(self, tmp_path):
        opts = _opts(
            tmp_path, tmp_path / "out", scanners=["grype"], add_scanners=["checkov"]
        )

        assert _folded_scanner_allowlist(opts) == ["grype", "checkov"]


class TestLocalModeHandsTheSelectionToTheOrchestrator:
    def test_precommit_with_cli_only_scanners(
        self, tmp_path, logger, local_orchestrator
    ):
        opts = _opts(
            tmp_path,
            tmp_path / "out",
            mode=RunMode.precommit,
            only_scanners=["bandit", "checkov"],
        )

        _run_local_mode(opts, logger)

        created = local_orchestrator["create_kwargs"][0]
        assert sorted(created["enabled_scanners"]) == ["bandit", "checkov"]

    def test_exclusions_are_handed_through_beside_the_selection(
        self, tmp_path, logger, local_orchestrator
    ):
        """Exclusion-wins is the engine's rule (selection_after_exclusions);
        what this layer owes it is the untouched excluded list beside the
        resolved allowlist, so an excluded name still wins over any inclusion
        source."""
        opts = _opts(
            tmp_path,
            tmp_path / "out",
            mode=RunMode.precommit,
            only_scanners=["bandit", "checkov"],
            excluded_scanners=["checkov"],
        )

        _run_local_mode(opts, logger)

        created = local_orchestrator["create_kwargs"][0]
        assert sorted(created["enabled_scanners"]) == ["bandit", "checkov"]
        assert created["excluded_scanners"] == ["checkov"]


# --------------------------------------------------------------------------- #
# The config model's own refusal
# --------------------------------------------------------------------------- #


class TestPrecommitConfigModel:
    def test_both_keys_at_once_are_refused(self):
        from pydantic import ValidationError

        from automated_security_helper.config.ash_config import PrecommitModeConfig

        with pytest.raises(ValidationError) as refusal:
            PrecommitModeConfig(only_scanners=["bandit"], add_scanners=["grype"])

        assert "cannot be set together" in str(refusal.value)

    def test_each_key_alone_is_accepted(self):
        from automated_security_helper.config.ash_config import PrecommitModeConfig

        assert PrecommitModeConfig(only_scanners=["bandit"]).only_scanners == ["bandit"]
        assert PrecommitModeConfig(add_scanners=["grype"]).add_scanners == ["grype"]

    def test_the_section_loads_from_a_config_file(self, tmp_path, logger):
        """A file setting both keys is refused as the model refuses them: the
        selection then falls back to the mode default here, and the scan itself
        refuses the config with exit 3 before any scanner runs."""
        from automated_security_helper.interactions.run_ash_scan import (
            _resolved_precommit_config,
        )

        config = _config_file(
            tmp_path,
            "project_name: t\n"
            "precommit:\n"
            "  only_scanners: [bandit]\n"
            "  add_scanners: [grype]\n",
        )
        opts = _opts(tmp_path, tmp_path / "out", mode=RunMode.precommit, config=config)

        assert _resolved_precommit_config(opts) is None
        assert sorted(_selected(opts, logger)) == sorted(PRECOMMIT_MODE_SCANNERS)


# --------------------------------------------------------------------------- #
# The CLI surface: conflicts and the deprecation line
# --------------------------------------------------------------------------- #


@pytest.fixture
def clean_cli_env(monkeypatch, tmp_path):
    for name in (
        "ASH_CONFIG",
        "ASH_SOURCE_DIR",
        "ASH_OUTPUT_DIR",
        "ASH_WORKSPACE",
        "ASH_SCANNERS",
        "ASH_EXCLUDED_SCANNERS",
        "ASH_MODE",
        "ASH_IN_CONTAINER",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "src"
    source.mkdir()
    return source


class TestCliConflictsAndDeprecation:
    def _invoke(self, source: Path, *args: str):
        from automated_security_helper.cli.main import app

        return CliRunner().invoke(
            app,
            [
                "scan",
                "fs",
                str(source),
                "--output-dir",
                str(source.parent / "out"),
                "--no-progress",
                *args,
            ],
        )

    def test_only_with_add_is_refused(self, clean_cli_env):
        from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR

        result = self._invoke(
            clean_cli_env, "--only-scanners", "bandit", "--add-scanners", "grype"
        )

        assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
        assert "--only-scanners cannot be combined with --add-scanners" in str(
            result.output
        )

    def test_only_with_legacy_scanners_is_refused_naming_the_deprecation(
        self, clean_cli_env
    ):
        from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR

        result = self._invoke(
            clean_cli_env, "--only-scanners", "bandit", "--scanners", "grype"
        )

        assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
        assert "--only-scanners cannot be combined with --scanners" in result.output
        assert "deprecated" in result.output

    def test_the_refusal_names_the_environment_when_that_is_where_scanners_came_from(
        self, clean_cli_env, monkeypatch
    ):
        """A CI job that exports ASH_SCANNERS and passes only --only-scanners
        has no --scanners on its command line: the refusal says where the
        value came from instead of blaming a flag nobody typed."""
        from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR

        monkeypatch.setenv("ASH_SCANNERS", "grype")
        result = self._invoke(clean_cli_env, "--only-scanners", "bandit")

        assert result.exit_code == ASH_EXIT_USAGE_ERROR, result.output
        assert "ASH_SCANNERS" in result.output
        assert "cannot be combined with --scanners" not in result.output

    def test_legacy_scanners_emits_the_deprecation_line_and_still_runs(
        self, clean_cli_env, monkeypatch
    ):
        from automated_security_helper.cli import scan as scan_module

        forwarded: Dict[str, Any] = {}

        def fake_run_ash_scan(**kwargs):
            forwarded.update(kwargs)
            return AshAggregatedResults()

        monkeypatch.setattr(scan_module, "run_ash_scan", fake_run_ash_scan)

        result = self._invoke(clean_cli_env, "--scanners", "bandit")

        assert "DeprecationWarning: --scanners" in result.output, result.output
        assert "--only-scanners" in result.output
        assert "--add-scanners" in result.output
        assert forwarded["scanners"] == ["bandit"]
        assert forwarded["only_scanners"] is None
        assert forwarded["add_scanners"] == []

    def test_the_new_flags_do_not_emit_the_deprecation_line(
        self, clean_cli_env, monkeypatch
    ):
        from automated_security_helper.cli import scan as scan_module

        forwarded: Dict[str, Any] = {}

        def fake_run_ash_scan(**kwargs):
            forwarded.update(kwargs)
            return AshAggregatedResults()

        monkeypatch.setattr(scan_module, "run_ash_scan", fake_run_ash_scan)

        result = self._invoke(clean_cli_env, "--only-scanners", "bandit,detect-secrets")

        assert "DeprecationWarning" not in result.output, result.output
        assert forwarded["only_scanners"] == ["bandit,detect-secrets"]
        assert forwarded["scanners"] == []

    def test_the_deprecation_line_is_skipped_inside_the_container(
        self, clean_cli_env, monkeypatch
    ):
        from automated_security_helper.cli import scan as scan_module

        monkeypatch.setenv("ASH_IN_CONTAINER", "YES")
        monkeypatch.setattr(
            scan_module, "run_ash_scan", lambda **kwargs: AshAggregatedResults()
        )

        result = self._invoke(clean_cli_env, "--scanners", "bandit")

        assert "DeprecationWarning" not in result.output, result.output

    def test_add_scanners_is_forwarded(self, clean_cli_env, monkeypatch):
        from automated_security_helper.cli import scan as scan_module

        forwarded: Dict[str, Any] = {}

        def fake_run_ash_scan(**kwargs):
            forwarded.update(kwargs)
            return AshAggregatedResults()

        monkeypatch.setattr(scan_module, "run_ash_scan", fake_run_ash_scan)

        result = self._invoke(
            clean_cli_env, "--mode", "precommit", "--add-scanners", "grype"
        )

        assert result.exit_code == 0, result.output
        assert forwarded["add_scanners"] == ["grype"]
        assert forwarded["mode"].value == "precommit"


# --------------------------------------------------------------------------- #
# The operator's default_scanners, folded against the orchestrator's config
# --------------------------------------------------------------------------- #


def _fold(**layers: Any):
    from automated_security_helper.core.scanner_selection import SelectionLayers

    operator_only = layers.pop("operator_only", ())
    operator_add = layers.pop("operator_add", ())
    return SelectionLayers(**layers).fold(operator_only, operator_add)


class TestTheFold:
    def test_nothing_selected_is_unrestricted(self):
        folded = _fold()

        assert folded.names == []
        assert folded.origin is None

    def test_operator_only_replaces_the_unrestricted_default(self):
        folded = _fold(operator_only=["bandit"])

        assert folded.names == ["bandit"]
        assert folded.origin == "operator"

    def test_operator_add_alone_leaves_the_default_unrestricted(self):
        folded = _fold(operator_add=["trivy"])

        assert folded.names == []
        assert folded.origin is None

    def test_operator_add_extends_a_bounded_default(self):
        folded = _fold(mode_default=["bandit", "checkov"], operator_add=["trivy"])

        assert folded.names == ["bandit", "checkov", "trivy"]
        assert folded.origin == "operator"

    def test_operator_only_replaces_a_bounded_default(self):
        folded = _fold(mode_default=["bandit", "checkov"], operator_only=["trivy"])

        assert folded.names == ["trivy"]

    def test_precommit_only_replaces_the_operators_list(self):
        folded = _fold(
            mode_default=["bandit", "checkov"],
            operator_add=["trivy"],
            precommit_only=["grype"],
        )

        assert folded.names == ["grype"]
        assert folded.origin == "precommit"

    def test_precommit_add_extends_the_operators_result(self):
        folded = _fold(
            mode_default=["bandit"], operator_add=["trivy"], precommit_add=["grype"]
        )

        assert folded.names == ["bandit", "trivy", "grype"]

    def test_cli_only_replaces_every_lower_layer(self):
        folded = _fold(
            mode_default=["bandit"],
            operator_only=["trivy"],
            precommit_add=["grype"],
            cli_only=["checkov"],
            workspace_required=["semgrep"],
        )

        assert folded.names == ["checkov"]
        assert folded.origin == "cli"

    def test_cli_additions_extend_an_explicit_base_listed_first(self):
        folded = _fold(operator_only=["bandit"], cli_additive=["checkov"])

        assert folded.names == ["checkov", "bandit"]
        assert folded.origin == "cli+operator"

    def test_cli_additions_alone_are_the_allowlist(self):
        assert _fold(cli_additive=["checkov"]).names == ["checkov"]

    def test_cli_additions_do_not_turn_an_add_only_operator_list_into_a_base(self):
        assert _fold(operator_add=["trivy"], cli_additive=["checkov"]).names == [
            "checkov"
        ]

    def test_workspace_required_names_follow_a_bounded_config_selection(self):
        folded = _fold(operator_only=["bandit"], workspace_required=["trivy"])

        assert folded.names == ["bandit", "trivy"]

    def test_workspace_required_names_do_not_narrow_an_unrestricted_selection(self):
        assert _fold(workspace_required=["trivy"]).names == []

    def test_names_keep_first_appearance_without_repeats(self):
        folded = _fold(operator_only=["bandit", "trivy"], cli_additive=["trivy", "x"])

        assert folded.names == ["trivy", "x", "bandit"]

    def test_the_core_helper_imports_no_config_model(self):
        import subprocess  # nosec B404 - a fresh interpreter is the property under test
        import sys

        from tests.utils.helpers import importing_this_checkout

        probe = (
            "import sys; "
            "import automated_security_helper.core.scanner_selection; "
            "sys.exit(int('automated_security_helper.config.ash_config' in sys.modules))"
        )
        completed = subprocess.run(  # nosec B603 - fixed argv, the test's own interpreter
            [sys.executable, "-I", "-c", importing_this_checkout(probe)]
        )
        assert completed.returncode == 0


@pytest.fixture
def operator_home(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    source = tmp_path / "src"
    source.mkdir()
    return source


def _operator_config(tmp_path: Path, selection: str = "") -> str:
    path = tmp_path / "operator" / "ash.yaml"
    path.parent.mkdir(exist_ok=True)
    path.write_text(f"project_name: t\n{selection}", encoding="utf-8")
    return str(path)


def _created(
    tmp_path: Path,
    source: Path,
    config: str | None,
    *,
    mode: RunMode = RunMode.local,
    excluded: List[str] | None = None,
    **options: Any,
):
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator
    from automated_security_helper.interactions.run_ash_scan import _selection_layers

    output = tmp_path / "out"
    opts = _opts(
        source, output, mode=mode, config=config, excluded_scanners=excluded, **options
    )
    layers = _selection_layers(opts, _RecordingLogger())
    return ASHScanOrchestrator.create(
        source_dir=source,
        output_dir=output,
        work_dir=output / ".ash-work",
        enabled_scanners=layers.fold().names,
        selection_layers=layers,
        excluded_scanners=list(excluded or []),
        config_path=config,
        config_overrides=opts.config_overrides or [],
        no_cleanup=True,
    )


def _engine_allowlist(*args: Any, **kwargs: Any) -> List[str]:
    return list(_created(*args, **kwargs).execution_engine._init_enabled_scanners)


class TestTheOperatorSelectionReachesTheEngine:
    def test_local_only_selects_exactly_those_scanners(self, tmp_path, operator_home):
        config = _operator_config(tmp_path, "default_scanners:\n  only: [bandit]\n")

        assert _engine_allowlist(tmp_path, operator_home, config) == ["bandit"]

    def test_local_add_alone_stays_unrestricted(self, tmp_path, operator_home):
        config = _operator_config(tmp_path, "default_scanners:\n  add: [trivy]\n")

        assert _engine_allowlist(tmp_path, operator_home, config) == []

    def test_precommit_defaults_take_the_global_add(self, tmp_path, operator_home):
        config = _operator_config(tmp_path, "default_scanners:\n  add: [grype]\n")

        selected = _engine_allowlist(
            tmp_path, operator_home, config, mode=RunMode.precommit
        )

        assert selected == [*PRECOMMIT_MODE_SCANNERS, "grype"]

    def test_the_precommit_only_key_replaces_the_global_selection(
        self, tmp_path, operator_home
    ):
        config = _operator_config(
            tmp_path,
            "default_scanners:\n  add: [grype]\n"
            "precommit:\n  only_scanners: [checkov]\n",
        )

        selected = _engine_allowlist(
            tmp_path, operator_home, config, mode=RunMode.precommit
        )

        assert selected == ["checkov"]

    def test_the_cli_only_flag_replaces_both(self, tmp_path, operator_home):
        config = _operator_config(
            tmp_path,
            "default_scanners:\n  only: [bandit]\n"
            "precommit:\n  add_scanners: [grype]\n",
        )

        selected = _engine_allowlist(
            tmp_path,
            operator_home,
            config,
            mode=RunMode.precommit,
            only_scanners=["checkov"],
        )

        assert selected == ["checkov"]

    @pytest.mark.parametrize("flag", ["add_scanners", "scanners"])
    def test_the_additive_cli_flags_extend_the_configured_base(
        self, tmp_path, operator_home, flag
    ):
        config = _operator_config(tmp_path, "default_scanners:\n  only: [bandit]\n")

        selected = _engine_allowlist(
            tmp_path, operator_home, config, **{flag: ["checkov"]}
        )

        assert selected == ["checkov", "bandit"]

    def test_an_operator_override_selects_with_no_file(self, tmp_path, operator_home):
        selected = _engine_allowlist(
            tmp_path,
            operator_home,
            None,
            config_overrides=["default_scanners.only=[bandit]"],
        )

        assert selected == ["bandit"]

    def test_exclusions_that_remove_the_whole_list_are_refused_in_config_words(
        self, tmp_path, operator_home
    ):
        from automated_security_helper.core.exceptions import ScannerSelectionError

        config = _operator_config(tmp_path, "default_scanners:\n  only: [bandit]\n")

        with pytest.raises(ScannerSelectionError) as refusal:
            _engine_allowlist(tmp_path, operator_home, config, excluded=["bandit"])

        text = str(refusal.value)
        assert "default_scanners in the ASH config" in text
        assert "--exclude-scanners" in text
        assert "--scanners" not in text.replace("--exclude-scanners", "")

    def test_a_list_naming_no_registered_scanner_is_refused(
        self, tmp_path, operator_home
    ):
        from automated_security_helper.core.exceptions import ScannerSelectionError

        config = _operator_config(
            tmp_path, "default_scanners:\n  only: [no-such-scanner]\n"
        )

        with pytest.raises(ScannerSelectionError) as refusal:
            _engine_allowlist(tmp_path, operator_home, config)

        assert "None of the requested scanners exist: no-such-scanner" in str(
            refusal.value
        )
        assert "default_scanners in the ASH config" in str(refusal.value)

    def test_a_flag_cancelled_by_exclusions_keeps_the_flag_wording(
        self, tmp_path, operator_home
    ):
        from automated_security_helper.core.exceptions import ScannerSelectionError

        config = _operator_config(tmp_path, "default_scanners:\n  only: [bandit]\n")

        with pytest.raises(ScannerSelectionError) as refusal:
            _engine_allowlist(
                tmp_path,
                operator_home,
                config,
                only_scanners=["checkov"],
                excluded=["checkov"],
            )

        assert "named by --scanners" in str(refusal.value)

    def test_a_selection_does_not_enable_a_disabled_scanner(
        self, tmp_path, operator_home
    ):
        config = _operator_config(
            tmp_path,
            "default_scanners:\n  only: [bandit]\n"
            "scanners:\n  bandit:\n    enabled: false\n",
        )

        orchestrator = _created(tmp_path, operator_home, config)

        assert orchestrator.config.scanners.bandit.enabled is False
        assert list(orchestrator.execution_engine._init_enabled_scanners) == ["bandit"]


class TestWithoutTheNewSection:
    @pytest.mark.parametrize(
        "mode,kwargs,expected",
        [
            (RunMode.local, {}, []),
            (RunMode.local, {"scanners": ["grype", "bandit"]}, ["grype", "bandit"]),
            (
                RunMode.local,
                {"scanners": ["grype"], "add_scanners": ["checkov"]},
                ["grype", "checkov"],
            ),
            (RunMode.local, {"only_scanners": ["bandit"]}, ["bandit"]),
            (RunMode.precommit, {}, list(PRECOMMIT_MODE_SCANNERS)),
            (
                RunMode.precommit,
                {"add_scanners": ["grype"], "scanners": ["checkov"]},
                [
                    "checkov",
                    "grype",
                    *(n for n in PRECOMMIT_MODE_SCANNERS if n != "checkov"),
                ],
            ),
        ],
    )
    def test_the_result_and_order_are_unchanged(
        self, tmp_path, operator_home, mode, kwargs, expected
    ):
        config = _operator_config(tmp_path)

        selected = _engine_allowlist(
            tmp_path, operator_home, config, mode=mode, **kwargs
        )

        assert selected == expected

    def test_the_precommit_keys_keep_their_existing_refusal_wording(
        self, tmp_path, operator_home
    ):
        from automated_security_helper.core.exceptions import ScannerSelectionError

        config = _operator_config(tmp_path, "precommit:\n  only_scanners: [bandit]\n")

        with pytest.raises(ScannerSelectionError) as refusal:
            _engine_allowlist(
                tmp_path,
                operator_home,
                config,
                mode=RunMode.precommit,
                excluded=["bandit"],
            )

        assert "named by --scanners" in str(refusal.value)

    def test_the_orchestrator_handed_no_layers_uses_its_own_allowlist(
        self, tmp_path, operator_home
    ):
        from automated_security_helper.core.orchestrator import ASHScanOrchestrator

        config = _operator_config(tmp_path, "default_scanners:\n  only: [checkov]\n")
        output = tmp_path / "out"

        orchestrator = ASHScanOrchestrator.create(
            source_dir=operator_home,
            output_dir=output,
            work_dir=output / ".ash-work",
            config_path=config,
            enabled_scanners=["bandit"],
            no_cleanup=True,
        )

        assert list(orchestrator.execution_engine._init_enabled_scanners) == ["bandit"]


class TestLocalModeHandsTheLayersToTheOrchestrator:
    def test_the_layers_travel_beside_the_unfolded_list(
        self, tmp_path, logger, local_orchestrator
    ):
        opts = _opts(
            tmp_path,
            tmp_path / "out",
            mode=RunMode.precommit,
            add_scanners=["grype"],
        )

        _run_local_mode(opts, logger)

        created = local_orchestrator["create_kwargs"][0]
        layers = created["selection_layers"]
        assert list(layers.mode_default) == list(PRECOMMIT_MODE_SCANNERS)
        assert list(layers.cli_additive) == ["grype"]
        assert layers.cli_only is None
        assert created["enabled_scanners"] == layers.fold().names


class TestTheExistingCliPathKeepsItsDuplicates:
    def test_only_scanners_is_handed_over_as_given(self, tmp_path, logger):
        opts = _opts(
            tmp_path,
            tmp_path / "out",
            mode=RunMode.local,
            only_scanners=["bandit", "bandit"],
        )

        assert _selected(opts, logger) == ["bandit", "bandit"]

    def test_the_local_additive_flags_are_handed_over_as_given(self, tmp_path, logger):
        opts = _opts(
            tmp_path,
            tmp_path / "out",
            mode=RunMode.local,
            scanners=["grype", "grype"],
            add_scanners=["grype"],
        )

        assert _selected(opts, logger) == ["grype", "grype", "grype"]

    def test_the_precommit_union_stays_deduplicated(self, tmp_path, logger):
        opts = _opts(
            tmp_path,
            tmp_path / "out",
            mode=RunMode.precommit,
            scanners=["bandit", "bandit"],
        )

        assert _selected(opts, logger).count("bandit") == 1


class TestAMixedSelectionIsNotAttributedToTheFlagsAlone:
    def test_the_refusal_names_the_flags_and_the_config(self, tmp_path, operator_home):
        from automated_security_helper.core.exceptions import ScannerSelectionError

        config = _operator_config(tmp_path, "default_scanners:\n  only: [bandit]\n")

        with pytest.raises(ScannerSelectionError) as refusal:
            _engine_allowlist(
                tmp_path,
                operator_home,
                config,
                add_scanners=["checkov"],
                excluded=["checkov", "bandit"],
            )

        text = str(refusal.value)
        assert "--scanners" in text
        assert "default_scanners in the ASH config" in text
        assert "bandit" in text and "checkov" in text

    def test_flags_alone_keep_the_flag_wording(self, tmp_path, operator_home):
        from automated_security_helper.core.exceptions import ScannerSelectionError

        config = _operator_config(tmp_path)

        with pytest.raises(ScannerSelectionError) as refusal:
            _engine_allowlist(
                tmp_path,
                operator_home,
                config,
                scanners=["checkov"],
                excluded=["checkov"],
            )

        assert "default_scanners" not in str(refusal.value)
        assert "named by --scanners" in str(refusal.value)


class TestTheInnerScanChecksTheMarkerBeforeAnyScanner:
    @pytest.fixture
    def executed(self, monkeypatch):
        from automated_security_helper.core.orchestrator import ASHScanOrchestrator

        calls: List[Any] = []

        def fake_execute(self, phases=None):
            calls.append(self)
            return AshAggregatedResults()

        monkeypatch.setattr(ASHScanOrchestrator, "execute_scan", fake_execute)
        return calls

    def _run(self, tmp_path, source, config, marker, logger):
        opts = _opts(
            source,
            tmp_path / "out",
            mode=RunMode.local,
            config=config,
            required_scanner_selection=marker,
        )
        return _run_local_mode(opts, logger)

    def test_a_matching_section_runs_the_scan(
        self, tmp_path, operator_home, logger, executed
    ):
        config = _operator_config(tmp_path, "default_scanners:\n  only: [bandit]\n")

        self._run(
            tmp_path,
            operator_home,
            config,
            '{"add": [], "only": ["bandit"]}',
            logger,
        )

        assert len(executed) == 1

    @pytest.mark.parametrize(
        "body",
        [
            "project_name: t\n",
            "default_scanners:\n  only: [checkov]\n",
            "default_scanners:\n  add: [bandit]\n",
            "default_scanners:\n  only: [bandit, checkov]\n",
        ],
    )
    def test_a_different_or_missing_section_refuses_before_any_scanner(
        self, tmp_path, operator_home, logger, executed, body
    ):
        from automated_security_helper.interactions.run_ash_scan import (
            ScanRefusedExit,
        )

        config = _operator_config(tmp_path, body)

        with pytest.raises(ScanRefusedExit) as refusal:
            self._run(
                tmp_path,
                operator_home,
                config,
                '{"add": [], "only": ["bandit"]}',
                logger,
            )

        assert refusal.value.code == 3
        assert executed == []

    @pytest.mark.parametrize("marker", ["not json", "[]", '{"only": "bandit"}'])
    def test_a_marker_that_cannot_be_read_refuses(
        self, tmp_path, operator_home, logger, executed, marker
    ):
        from automated_security_helper.interactions.run_ash_scan import (
            ScanRefusedExit,
        )

        config = _operator_config(tmp_path, "default_scanners:\n  only: [bandit]\n")

        with pytest.raises(ScanRefusedExit) as refusal:
            self._run(tmp_path, operator_home, config, marker, logger)

        assert refusal.value.code == 3
        assert executed == []

    def test_a_replacement_flag_still_applies_after_the_marker_matched(
        self, tmp_path, operator_home, logger, executed
    ):
        config = _operator_config(tmp_path, "default_scanners:\n  only: [bandit]\n")
        opts = _opts(
            operator_home,
            tmp_path / "out",
            mode=RunMode.local,
            config=config,
            only_scanners=["checkov"],
            required_scanner_selection='{"add": [], "only": ["bandit"]}',
        )

        _run_local_mode(opts, logger)

        engine = executed[0].execution_engine
        assert list(engine._init_enabled_scanners) == ["checkov"]

    def test_without_a_marker_nothing_is_checked(
        self, tmp_path, operator_home, logger, executed
    ):
        config = _operator_config(tmp_path)

        self._run(tmp_path, operator_home, config, None, logger)

        assert len(executed) == 1


class TestTheHiddenMarkerOnTheCommandLine:
    def _invoke(self, clean_cli_env, tmp_path, config, marker):
        from automated_security_helper.cli.main import app

        return CliRunner().invoke(
            app,
            [
                "scan",
                "fs",
                str(clean_cli_env),
                "--no-progress",
                "--output-dir",
                str(tmp_path / "out"),
                "--config",
                config,
                "--require-scanner-selection",
                marker,
            ],
        )

    def test_a_mismatch_exits_3_and_names_the_selection(self, clean_cli_env, tmp_path):
        config = _operator_config(tmp_path, "project_name: t\n")

        result = self._invoke(
            clean_cli_env, tmp_path, config, '{"add": [], "only": ["bandit"]}'
        )

        assert result.exit_code == 3, result.output
        assert "default_scanners" in " ".join(result.output.split())

    def test_the_option_is_not_in_the_help(self, clean_cli_env):
        from automated_security_helper.cli.main import app

        result = CliRunner().invoke(app, ["scan", "--help"])

        assert "--require-scanner-selection" not in result.output


class TestTheHostMarkerIsTheSelectionTheInnerScanUses:
    @pytest.fixture
    def executed(self, monkeypatch):
        from automated_security_helper.core.orchestrator import ASHScanOrchestrator

        calls: List[Any] = []

        def fake_execute(self, phases=None):
            calls.append(self)
            return AshAggregatedResults()

        monkeypatch.setattr(ASHScanOrchestrator, "execute_scan", fake_execute)
        return calls

    @staticmethod
    def _checkout(tmp_path: Path, body: str) -> Path:
        from tests.utils.helpers import mark_git_checkout

        checkout = tmp_path / "repo"
        mark_git_checkout(checkout)
        base = checkout / "ci" / "base.yaml"
        base.parent.mkdir(parents=True)
        base.write_text(body, encoding="utf-8")
        return checkout

    def _marker_then_inner_scan(self, tmp_path, checkout, config, logger, executed):
        import json

        from automated_security_helper.interactions.run_ash_scan import (
            _container_selection,
        )

        host = _container_selection(
            _opts(checkout, tmp_path / "out", mode=RunMode.container, config=config)
        )
        assert host.marker is not None
        _run_local_mode(
            _opts(
                checkout,
                tmp_path / "out",
                mode=RunMode.local,
                config=config,
                required_scanner_selection=host.marker,
            ),
            logger,
        )
        [orchestrator] = executed
        return json.loads(host.marker), list(
            orchestrator.execution_engine._init_enabled_scanners
        )

    @pytest.mark.parametrize(
        "body",
        ["project_name: repo\n", "default_scanners:\n  only: [trivy]\n"],
        ids=["no-section", "asks-for-trivy"],
    )
    def test_ash_config_under_a_named_checkout_config(
        self, tmp_path, monkeypatch, logger, executed, body
    ):
        operator = tmp_path / "operator" / "ash.yaml"
        operator.parent.mkdir()
        operator.write_text("default_scanners:\n  only: [bandit]\n", encoding="utf-8")
        monkeypatch.setenv("ASH_CONFIG", str(operator))
        checkout = self._checkout(tmp_path, body)

        marker, allowlist = self._marker_then_inner_scan(
            tmp_path, checkout, str(checkout / "ci" / "base.yaml"), logger, executed
        )

        assert marker == {"add": [], "only": ["bandit"]}
        assert allowlist == ["bandit"]

    def test_an_operator_file_extending_a_checkout_file(
        self, tmp_path, monkeypatch, logger, executed
    ):
        monkeypatch.delenv("ASH_CONFIG", raising=False)
        checkout = self._checkout(tmp_path, "default_scanners:\n  only: [trivy]\n")
        operator = tmp_path / "operator.yaml"
        operator.write_text(
            f"extends: [{(checkout / 'ci' / 'base.yaml').as_posix()}]\n"
            "default_scanners:\n  only: [bandit]\n",
            encoding="utf-8",
        )

        marker, allowlist = self._marker_then_inner_scan(
            tmp_path, checkout, str(operator), logger, executed
        )

        assert marker == {"add": [], "only": ["bandit"]}
        assert allowlist == ["bandit"]
