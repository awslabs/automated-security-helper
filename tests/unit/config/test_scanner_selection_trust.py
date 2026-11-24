# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The default scanner selection is the operator's, never the scanned repository's.

``scanner_selection.only_scanners`` and ``scanner_selection.add_scanners`` are
read from the defaults, a config file outside every checkout, or
``--config-overrides``. A file inside the scanned tree, an ``extends`` link in a
checkout, or a client's patched session copy cannot replace or erase them
(``config/scanner_selection_trust.py``), and a client patch to the section is
refused whatever the profile allows.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Iterator, List

import pytest
import yaml
from pydantic import ValidationError

from automated_security_helper.config.ash_config import (
    ALWAYS_DENIED_PATHS,
    AshConfig,
    ScannerSelectionConfig,
)
from automated_security_helper.config.config_validator import ConfigValidator
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import (
    ASHConfigFieldDeniedError,
    ASHConfigValidationError,
)
from automated_security_helper.utils.log import ASH_LOGGER
from tests.utils.helpers import mark_git_checkout

pytestmark = [pytest.mark.unit, pytest.mark.live_tool_probes]


@pytest.fixture(autouse=True)
def _no_operator_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)


@pytest.fixture
def ash_log() -> Iterator[List[logging.LogRecord]]:
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


def _selecting(*names: str) -> Dict[str, Any]:
    return {"scanner_selection": {"only_scanners": list(names)}}


def _repo(tmp_path: Path, document: Dict[str, Any]) -> Path:
    repo = tmp_path / "repo"
    mark_git_checkout(repo)
    _write(repo / ".ash" / ".ash.yaml", document)
    return repo


def _operator(tmp_path: Path, document: Dict[str, Any]) -> Path:
    return _write(tmp_path / "operator" / "ash.yaml", document)


def _only(config: AshConfig) -> List[str]:
    return list(config.scanner_selection.only_scanners)


def _add(config: AshConfig) -> List[str]:
    return list(config.scanner_selection.add_scanners)


class TestModel:
    def test_the_defaults_select_nothing(self) -> None:
        config = AshConfig()

        assert _only(config) == []
        assert _add(config) == []

    def test_each_list_alone_is_accepted(self) -> None:
        assert ScannerSelectionConfig(only_scanners=["bandit"]).only_scanners == [
            "bandit"
        ]
        assert ScannerSelectionConfig(add_scanners=["trivy"]).add_scanners == ["trivy"]

    def test_both_lists_at_once_are_refused(self) -> None:
        with pytest.raises(ValidationError, match="cannot be set together"):
            ScannerSelectionConfig(only_scanners=["bandit"], add_scanners=["trivy"])

    def test_an_unknown_key_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            ScannerSelectionConfig(only_scanner=["bandit"])  # type: ignore[call-arg]

    def test_the_section_is_a_known_top_level_key(self) -> None:
        assert "scanner_selection" in ConfigValidator.VALID_TOP_LEVEL_FIELDS

    def test_a_client_may_not_patch_the_section_or_its_children(self) -> None:
        assert "/scanner_selection" in ALWAYS_DENIED_PATHS
        assert "/scanner_selection/**" in ALWAYS_DENIED_PATHS


class TestResolution:
    def test_an_operator_file_selects_bandit(self, tmp_path: Path) -> None:
        repo = _repo(tmp_path, {})
        operator = _operator(tmp_path, _selecting("bandit"))

        config = resolve_config(config_path=operator, source_dir=repo)

        assert _only(config) == ["bandit"]

    def test_no_section_selects_nothing(self, tmp_path: Path) -> None:
        repo = _repo(tmp_path, {})

        assert _only(resolve_config(source_dir=repo)) == []

    def test_both_lists_in_an_operator_file_are_a_config_error(
        self, tmp_path: Path
    ) -> None:
        repo = _repo(tmp_path, {})
        operator = _operator(
            tmp_path,
            {"scanner_selection": {"only_scanners": ["bandit"], "add_scanners": ["x"]}},
        )

        with pytest.raises(ASHConfigValidationError):
            resolve_config(config_path=operator, source_dir=repo)

    def test_an_operator_override_selects(self, tmp_path: Path) -> None:
        repo = _repo(tmp_path, {})

        config = resolve_config(
            source_dir=repo,
            config_overrides=['scanner_selection.only_scanners=["bandit"]'],
        )

        assert _only(config) == ["bandit"]

    def test_an_operator_override_wins_over_the_operators_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = _repo(tmp_path, {})
        monkeypatch.setenv("ASH_CONFIG", str(_operator(tmp_path, _selecting("bandit"))))

        config = resolve_config(
            source_dir=repo,
            config_overrides=['scanner_selection.only_scanners=["checkov"]'],
        )

        assert _only(config) == ["checkov"]

    def test_an_operator_add_list_resolves(self, tmp_path: Path) -> None:
        repo = _repo(tmp_path, {})
        operator = _operator(
            tmp_path, {"scanner_selection": {"add_scanners": ["trivy"]}}
        )

        config = resolve_config(config_path=operator, source_dir=repo)

        assert _add(config) == ["trivy"]
        assert _only(config) == []


class TestARepositoryCannotChangeTheOperatorsSelection:
    @pytest.fixture
    def operator_base(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        path = _operator(tmp_path, _selecting("bandit"))
        monkeypatch.setenv("ASH_CONFIG", str(path))
        return path

    def test_a_discovered_checkout_file_cannot_replace_it(
        self, tmp_path: Path, operator_base: Path, ash_log
    ) -> None:
        repo = _repo(tmp_path, _selecting("trivy"))

        config = resolve_config(source_dir=repo)

        assert _only(config) == ["bandit"]
        assert _warnings_naming(ash_log, "scanner_selection")

    def test_a_named_checkout_file_cannot_replace_it(
        self, tmp_path: Path, operator_base: Path, ash_log
    ) -> None:
        repo = _repo(tmp_path, _selecting("trivy"))

        config = resolve_config(
            config_path=repo / ".ash" / ".ash.yaml", source_dir=repo
        )

        assert _only(config) == ["bandit"]
        assert _warnings_naming(ash_log, "scanner_selection")

    def test_a_checkout_file_cannot_erase_it(
        self, tmp_path: Path, operator_base: Path
    ) -> None:
        repo = _repo(tmp_path, {"scanner_selection": {}})

        assert _only(resolve_config(source_dir=repo)) == ["bandit"]

    def test_a_checkout_file_cannot_swap_it_for_an_add_list(
        self, tmp_path: Path, operator_base: Path
    ) -> None:
        repo = _repo(tmp_path, {"scanner_selection": {"add_scanners": ["trivy"]}})

        config = resolve_config(source_dir=repo)

        assert _only(config) == ["bandit"]
        assert _add(config) == []

    def test_a_checkout_file_repeating_the_operators_value_is_quiet(
        self, tmp_path: Path, operator_base: Path, ash_log
    ) -> None:
        repo = _repo(tmp_path, _selecting("bandit"))

        config = resolve_config(source_dir=repo)

        assert _only(config) == ["bandit"]
        assert not _warnings_naming(ash_log, "scanner_selection")

    def test_an_untrusted_extends_link_cannot_replace_it(
        self, tmp_path: Path, operator_base: Path
    ) -> None:
        repo = _repo(tmp_path, {})
        _write(repo / ".ash" / "base.yaml", _selecting("trivy"))
        _write(repo / ".ash" / ".ash.yaml", {"extends": "base.yaml"})

        config = resolve_config(source_dir=repo)

        assert _only(config) == ["bandit"]

    def test_a_workspace_project_cannot_replace_it(
        self, tmp_path: Path, ash_log
    ) -> None:
        repo = _repo(tmp_path, _selecting("trivy"))
        operator = _operator(tmp_path, _selecting("bandit"))

        config = resolve_config(
            config_path=repo / ".ash" / ".ash.yaml",
            source_dir=repo,
            trusted_config_path=operator,
            overlay_config_path=operator,
        )

        assert _only(config) == ["bandit"]

    def test_an_operator_override_still_replaces_it(
        self, tmp_path: Path, operator_base: Path
    ) -> None:
        repo = _repo(tmp_path, _selecting("trivy"))

        config = resolve_config(
            source_dir=repo,
            config_overrides=['scanner_selection.only_scanners=["checkov"]'],
        )

        assert _only(config) == ["checkov"]

    def test_with_no_operator_selection_a_checkout_file_selects_nothing(
        self, tmp_path: Path, ash_log
    ) -> None:
        repo = _repo(tmp_path, _selecting("trivy"))

        config = resolve_config(source_dir=repo)

        assert _only(config) == []
        assert _warnings_naming(ash_log, "scanner_selection")


class TestAClientPatchIsRefused:
    @pytest.fixture
    def session(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        from automated_security_helper.cli.mcp import profile_registry

        monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
        monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
        monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
        monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
        profile = _operator(
            tmp_path,
            {
                **_selecting("bandit"),
                "global_settings": {
                    "mcp": {
                        "runtime_overrides": {
                            "enabled": True,
                            "allowed_paths": [
                                "/scanner_selection",
                                "/scanner_selection/**",
                            ],
                            "denied_paths": [],
                        }
                    }
                },
            },
        )
        profile_registry.clear_profile_registry()
        profile_registry.clear_all_session_state()
        profile_registry.set_profile_registry(
            profile_registry.register_profiles([f"op={profile}"])
        )
        yield profile_registry
        profile_registry.clear_profile_registry()
        profile_registry.clear_all_session_state()

    @pytest.mark.parametrize(
        "op",
        [
            {
                "op": "replace",
                "path": "/scanner_selection/only_scanners",
                "value": ["trivy"],
            },
            {
                "op": "add",
                "path": "/scanner_selection/add_scanners",
                "value": ["trivy"],
            },
            {"op": "remove", "path": "/scanner_selection/only_scanners"},
            {"op": "replace", "path": "/scanner_selection", "value": {}},
        ],
    )
    def test_a_patch_is_refused_even_when_the_profile_allows_the_path(
        self, session, op: Dict[str, Any]
    ) -> None:
        from automated_security_helper.cli.mcp_tools import mcp_select_profile

        result = mcp_select_profile("op", patch_ops=[op], session_id="session-a")

        assert result["success"] is False
        assert "scanner_selection" in str(result.get("error"))

    def test_the_operators_selection_still_reads_through_the_session(
        self, session
    ) -> None:
        from automated_security_helper.cli.mcp_tools import mcp_select_profile

        result = mcp_select_profile("op", session_id="session-a")
        assert result["success"] is True, result.get("error")
        client = Path(session.resolve_session_config_path("session-a") or "")
        operator = Path(session.resolve_session_trusted_config_path("session-a") or "")

        config = resolve_config(client, trusted_config_path=operator)

        assert _only(config) == ["bandit"]

    def test_a_session_copy_asking_for_trivy_is_refused_not_substituted(
        self, session
    ) -> None:
        from automated_security_helper.cli.mcp_tools import mcp_select_profile

        result = mcp_select_profile("op", session_id="session-a")
        assert result["success"] is True, result.get("error")
        operator = Path(session.resolve_session_trusted_config_path("session-a") or "")
        client = operator.parent.parent / "client-config" / "ash.yaml"
        document = yaml.safe_load(operator.read_text(encoding="utf-8"))
        document["scanner_selection"] = {"only_scanners": ["trivy"]}
        _write(client, document)

        with pytest.raises(ASHConfigFieldDeniedError):
            resolve_config(
                client,
                trusted_config_path=operator,
                untrusted_config=True,
                remote_client=True,
            )
