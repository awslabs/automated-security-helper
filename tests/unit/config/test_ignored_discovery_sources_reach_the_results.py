# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config source discovery found but did not use is reported with the results.

Config sources are selected by precedence, never merged, so the settings in an
ignored source are not applied. ``resolve_config`` collects discovery's
ignored-source warnings as ``LoggedResolutionWarning`` entries on the resolved
config's ``_resolution_warnings``: the scan's results then carry them, and the
orchestrator, which logs every other resolution warning, skips these because
discovery already logged them (``orchestrator.py`` filters on the class).

The second route to the same landing: a caller that ran discovery itself and
passed the file it selected as a NAMED ``config_path`` (workspace mode's
resolver and execution, the sandbox-mode probe) skips resolution's own
discovery branch, so ``_warnings_when_discovered`` re-derives the ignored
sources for a named file that is exactly what discovery selects in the
caller's source directory. Those entries are plain strings, not
``LoggedResolutionWarning``: nothing logged them (``run_ash_scan.
_discovered_config_path`` logs nothing), so the orchestrator logs each once.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest
import yaml

from automated_security_helper.config.resolve_config import (
    LoggedResolutionWarning,
    resolve_config,
)


@pytest.fixture(autouse=True)
def _no_operator_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)


def _repo(tmp_path: Path, with_pyproject: bool) -> Path:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    document: Dict[str, Any] = {"scanners": {"bandit": {"enabled": False}}}
    config = repo / ".ash" / ".ash.yaml"
    config.parent.mkdir(parents=True)
    config.write_text(yaml.safe_dump(document), encoding="utf-8")
    if with_pyproject:
        (repo / "pyproject.toml").write_text(
            '[tool.ash]\nproject_name = "ignored"\n', encoding="utf-8"
        )
    return repo


def test_an_ignored_source_appears_in_the_results_resolution_warnings(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path, with_pyproject=True)

    config = resolve_config(source_dir=repo)

    ignored = [
        warning
        for warning in config._resolution_warnings
        if "pyproject.toml" in str(warning)
    ]
    assert ignored, config._resolution_warnings
    # Already logged by discovery, so the orchestrator must not log them again:
    # its filter reads the class (orchestrator.py).
    assert all(isinstance(warning, LoggedResolutionWarning) for warning in ignored)


def test_a_single_source_repo_reports_no_ignored_source(tmp_path: Path) -> None:
    """The control: with one source there is nothing to ignore."""
    repo = _repo(tmp_path, with_pyproject=False)

    config = resolve_config(source_dir=repo)

    assert not [
        warning
        for warning in config._resolution_warnings
        if "Ignoring ASH configuration" in str(warning)
    ]


def test_a_named_but_discovered_config_reports_the_ignored_sources(
    tmp_path: Path,
) -> None:
    """The second route: the caller discovered the file and named it.

    Workspace mode passes discovery's find as ``config_path``
    (``workspace/resolver.py``, ``workspace/execution.py``), so resolution's
    own discovery branch never runs; the ignored sources must still land in
    ``_resolution_warnings``, as plain strings the orchestrator logs once
    (nothing has logged them yet).
    """
    repo = _repo(tmp_path, with_pyproject=True)

    config = resolve_config(config_path=repo / ".ash" / ".ash.yaml", source_dir=repo)

    ignored = [
        warning
        for warning in config._resolution_warnings
        if "pyproject.toml" in str(warning)
    ]
    assert ignored, config._resolution_warnings
    # Not logged by resolution on this route, so the orchestrator must log
    # them: its filter skips only LoggedResolutionWarning (orchestrator.py).
    assert not any(isinstance(warning, LoggedResolutionWarning) for warning in ignored)


def test_a_named_config_outside_the_discovery_locations_reports_nothing(
    tmp_path: Path,
) -> None:
    """The control: a --config at no discovery location re-runs no discovery.

    The named file is the operator's explicit choice, not discovery's, so the
    neighboring sources are not "ignored by precedence" and no warning names
    them.
    """
    repo = _repo(tmp_path, with_pyproject=True)
    named = repo / "elsewhere.yaml"
    named.write_text(
        yaml.safe_dump({"scanners": {"bandit": {"enabled": False}}}),
        encoding="utf-8",
    )

    config = resolve_config(config_path=named, source_dir=repo)

    assert not [
        warning
        for warning in config._resolution_warnings
        if "Ignoring ASH configuration" in str(warning)
    ]
