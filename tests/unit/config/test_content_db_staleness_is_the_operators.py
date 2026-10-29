# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Relaxing the stale-database gate is the operator's choice.

``content_db_staleness: warn`` lets a scan pass against a content database past its
bound, and a ``content_db_staleness_overrides`` entry with ``policy: warn`` does the
same for one database. A config file inside the scanned tree, or one an MCP client
delivered, does not relax the gate: the values come from the defaults, a config
file outside the tree, ``--config-overrides`` or ``--allow-stale-content-db``
(``config/staleness_trust.py``). A repository config that repeats the operator's
value is kept, and one that only makes the gate stricter (``fail``) applies.

Both routes a repository config reaches a scan by are checked: a scan of the
repository (``resolve_config`` with the source directory), and a workspace project
(the operator's ``--config`` layered over the project's own config).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.utils.content_databases import (
    content_db_staleness_flag_overrides,
)
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.live_tool_probes

_WARN_TRIVY = {
    "database": "trivy-db",
    "policy": "warn",
    "expiration": "2099-01-01",
    "reason": "upstream publishing is paused",
}
_FAIL_GRYPE = {
    "database": "grype-db",
    "policy": "fail",
    "expiration": "2099-01-01",
    "reason": "held to fail while the scan-wide policy is warn",
}


@pytest.fixture(autouse=True)
def _no_operator_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)


@pytest.fixture
def ash_log():
    """ASH_LOGGER's records; it does not propagate, so caplog would see nothing."""
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Collect(level=logging.DEBUG)
    previous_level = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous_level)


def _warnings_naming(records: List[logging.LogRecord], key: str) -> List[str]:
    return [
        r.getMessage()
        for r in records
        if r.levelno == logging.WARNING
        and key in r.getMessage()
        and r.getMessage().startswith("Ignoring")
    ]


def _write(path: Path, document: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def _repo(tmp_path: Path, document: Dict[str, Any]) -> Path:
    """A checkout whose own .ash/.ash.yaml holds ``document``."""
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    _write(repo / ".ash" / ".ash.yaml", document)
    return repo


def _operator(tmp_path: Path, document: Dict[str, Any]) -> Path:
    return _write(tmp_path / "operator" / "ash.yaml", document)


def _workspace_project(repo: Path, operator: Path, **kwargs: Any):
    return resolve_config(
        config_path=repo / ".ash" / ".ash.yaml",
        source_dir=repo,
        trusted_config_path=operator,
        overlay_config_path=operator,
        **kwargs,
    )


def _entries(config) -> List[Dict[str, Any]]:
    return [
        entry.model_dump(mode="json") for entry in config.content_db_staleness_overrides
    ]


# ---------------------------------------------------------------------------
# content_db_staleness
# ---------------------------------------------------------------------------


def test_a_repository_config_does_not_set_warn(tmp_path: Path, ash_log) -> None:
    repo = _repo(tmp_path, {"content_db_staleness": "warn"})

    config = resolve_config(source_dir=repo)

    assert config.content_db_staleness == "fail"
    assert _warnings_naming(ash_log, "content_db_staleness")


def test_a_repository_config_repeating_the_operators_override_is_kept(
    tmp_path: Path, ash_log
) -> None:
    repo = _repo(tmp_path, {"content_db_staleness": "warn"})

    config = resolve_config(
        source_dir=repo, config_overrides=["content_db_staleness=warn"]
    )

    assert config.content_db_staleness == "warn"
    assert not _warnings_naming(ash_log, "content_db_staleness")


def test_the_allow_stale_flag_still_sets_warn(tmp_path: Path, ash_log) -> None:
    repo = _repo(tmp_path, {"content_db_staleness": "fail"})

    config = resolve_config(
        source_dir=repo,
        config_overrides=content_db_staleness_flag_overrides(allow_stale=True),
    )

    assert config.content_db_staleness == "warn"
    assert not _warnings_naming(ash_log, "content_db_staleness")


def test_an_operator_config_outside_the_tree_sets_warn(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {})
    operator = _operator(tmp_path, {"content_db_staleness": "warn"})

    config = resolve_config(config_path=operator, source_dir=repo)

    assert config.content_db_staleness == "warn"


def test_a_repository_config_may_make_the_gate_stricter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ash_log
) -> None:
    """fail only tightens, so it applies over an operator's warn from ASH_CONFIG."""
    repo = _repo(tmp_path, {"content_db_staleness": "fail"})
    monkeypatch.setenv(
        "ASH_CONFIG", str(_operator(tmp_path, {"content_db_staleness": "warn"}))
    )

    config = resolve_config(source_dir=repo)

    assert config.content_db_staleness == "fail"
    assert not _warnings_naming(ash_log, "content_db_staleness")


def test_a_workspace_project_does_not_set_warn(tmp_path: Path, ash_log) -> None:
    repo = _repo(tmp_path, {"content_db_staleness": "warn"})
    operator = _operator(tmp_path, {"project_name": "operator"})

    config = _workspace_project(repo, operator)

    assert config.content_db_staleness == "fail"
    assert _warnings_naming(ash_log, "content_db_staleness")


def test_a_workspace_project_repeating_the_operators_value_is_kept(
    tmp_path: Path, ash_log
) -> None:
    repo = _repo(tmp_path, {"content_db_staleness": "warn"})
    operator = _operator(tmp_path, {"content_db_staleness": "warn"})

    config = _workspace_project(repo, operator)

    assert config.content_db_staleness == "warn"
    assert not _warnings_naming(ash_log, "content_db_staleness")


# ---------------------------------------------------------------------------
# content_db_staleness_overrides
# ---------------------------------------------------------------------------


def test_a_repository_config_does_not_relax_one_database(
    tmp_path: Path, ash_log
) -> None:
    repo = _repo(tmp_path, {"content_db_staleness_overrides": [_WARN_TRIVY]})

    config = resolve_config(source_dir=repo)

    assert _entries(config) == []
    assert _warnings_naming(ash_log, "content_db_staleness_overrides")


def test_a_repository_entry_repeating_the_operators_override_is_kept(
    tmp_path: Path, ash_log
) -> None:
    repo = _repo(tmp_path, {"content_db_staleness_overrides": [_WARN_TRIVY]})

    config = resolve_config(
        source_dir=repo,
        config_overrides=[
            f"content_db_staleness_overrides={json.dumps([_WARN_TRIVY])}"
        ],
    )

    assert _entries(config) == [_WARN_TRIVY]
    assert not _warnings_naming(ash_log, "content_db_staleness_overrides")


def test_a_repository_entry_that_only_tightens_applies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ash_log
) -> None:
    repo = _repo(tmp_path, {"content_db_staleness_overrides": [_FAIL_GRYPE]})
    monkeypatch.setenv(
        "ASH_CONFIG", str(_operator(tmp_path, {"content_db_staleness": "warn"}))
    )

    config = resolve_config(source_dir=repo)

    assert _entries(config) == [_FAIL_GRYPE]
    assert not _warnings_naming(ash_log, "content_db_staleness_overrides")


def test_a_workspace_project_does_not_relax_one_database(
    tmp_path: Path, ash_log
) -> None:
    repo = _repo(tmp_path, {"content_db_staleness_overrides": [_WARN_TRIVY]})
    operator = _operator(tmp_path, {"project_name": "operator"})

    config = _workspace_project(repo, operator)

    assert _entries(config) == []
    assert _warnings_naming(ash_log, "content_db_staleness_overrides")


def test_a_workspace_project_repeating_the_operators_entry_is_kept(
    tmp_path: Path, ash_log
) -> None:
    repo = _repo(tmp_path, {"content_db_staleness_overrides": [_WARN_TRIVY]})
    operator = _operator(tmp_path, {"content_db_staleness_overrides": [_WARN_TRIVY]})

    config = _workspace_project(repo, operator)

    assert _entries(config) == [_WARN_TRIVY]
    assert not _warnings_naming(ash_log, "content_db_staleness_overrides")


# ---------------------------------------------------------------------------
# content_db_staleness_offline_image_default
#
# true holds trivy-db to warn in an image built with OFFLINE=YES, so it relaxes the
# gate the way warn does; false only makes it stricter.
# ---------------------------------------------------------------------------

_OFFLINE_IMAGE = "content_db_staleness_offline_image_default"


def test_a_repository_config_does_not_turn_the_offline_image_default_back_on(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ash_log
) -> None:
    repo = _repo(tmp_path, {_OFFLINE_IMAGE: True})
    monkeypatch.setenv("ASH_CONFIG", str(_operator(tmp_path, {_OFFLINE_IMAGE: False})))

    config = resolve_config(source_dir=repo)

    assert config.content_db_staleness_offline_image_default is False
    assert _warnings_naming(ash_log, _OFFLINE_IMAGE)


def test_a_repository_config_may_turn_the_offline_image_default_off(
    tmp_path: Path, ash_log
) -> None:
    repo = _repo(tmp_path, {_OFFLINE_IMAGE: False})

    config = resolve_config(source_dir=repo)

    assert config.content_db_staleness_offline_image_default is False
    assert not _warnings_naming(ash_log, _OFFLINE_IMAGE)


def test_the_operators_override_of_the_offline_image_default_is_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ash_log
) -> None:
    repo = _repo(tmp_path, {_OFFLINE_IMAGE: True})
    monkeypatch.setenv("ASH_CONFIG", str(_operator(tmp_path, {_OFFLINE_IMAGE: False})))

    config = resolve_config(
        source_dir=repo, config_overrides=[f"{_OFFLINE_IMAGE}=true"]
    )

    assert config.content_db_staleness_offline_image_default is True
    assert not _warnings_naming(ash_log, _OFFLINE_IMAGE)


def test_a_workspace_project_does_not_turn_the_offline_image_default_back_on(
    tmp_path: Path,
) -> None:
    """The operator's --config is merged over the project's config, so its false wins."""
    repo = _repo(tmp_path, {_OFFLINE_IMAGE: True})
    operator = _operator(tmp_path, {_OFFLINE_IMAGE: False})

    config = _workspace_project(repo, operator)

    assert config.content_db_staleness_offline_image_default is False
