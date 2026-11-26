# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The default scanner selection is the operator's, never the scanned repository's.

``default_scanners.only`` and ``default_scanners.add`` are
read from the defaults, a config file outside every checkout, or
``--config-overrides``. A file inside the scanned tree, an ``extends`` link in a
checkout, or a client's patched session copy cannot replace or erase them
(``config/default_scanners_trust.py``), and a client patch to the section is
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
    DefaultScannersConfig,
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
    return {"default_scanners": {"only": list(names)}}


def _repo(tmp_path: Path, document: Dict[str, Any]) -> Path:
    repo = tmp_path / "repo"
    mark_git_checkout(repo)
    _write(repo / ".ash.yaml", document)
    return repo


def _operator(tmp_path: Path, document: Dict[str, Any]) -> Path:
    return _write(tmp_path / "operator" / "ash.yaml", document)


def _only(config: AshConfig) -> List[str]:
    return list(config.default_scanners.only)


def _add(config: AshConfig) -> List[str]:
    return list(config.default_scanners.add)


class TestModel:
    def test_the_defaults_select_nothing(self) -> None:
        config = AshConfig()

        assert _only(config) == []
        assert _add(config) == []

    def test_each_list_alone_is_accepted(self) -> None:
        assert DefaultScannersConfig(only=["bandit"]).only == ["bandit"]
        assert DefaultScannersConfig(add=["trivy"]).add == ["trivy"]

    def test_both_lists_at_once_are_refused(self) -> None:
        with pytest.raises(ValidationError, match="cannot be set together"):
            DefaultScannersConfig(only=["bandit"], add=["trivy"])

    def test_an_unknown_key_is_refused(self) -> None:
        with pytest.raises(ValidationError):
            DefaultScannersConfig(only_scanner=["bandit"])  # type: ignore[call-arg]

    def test_the_section_is_a_known_top_level_key(self) -> None:
        assert "default_scanners" in ConfigValidator.VALID_TOP_LEVEL_FIELDS

    def test_a_client_may_not_patch_the_section_or_its_children(self) -> None:
        assert "/default_scanners" in ALWAYS_DENIED_PATHS
        assert "/default_scanners/**" in ALWAYS_DENIED_PATHS


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
            {"default_scanners": {"only": ["bandit"], "add": ["x"]}},
        )

        with pytest.raises(ASHConfigValidationError):
            resolve_config(config_path=operator, source_dir=repo)

    def test_an_operator_override_selects(self, tmp_path: Path) -> None:
        repo = _repo(tmp_path, {})

        config = resolve_config(
            source_dir=repo,
            config_overrides=['default_scanners.only=["bandit"]'],
        )

        assert _only(config) == ["bandit"]

    def test_an_operator_override_wins_over_the_operators_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = _repo(tmp_path, {})
        monkeypatch.setenv("ASH_CONFIG", str(_operator(tmp_path, _selecting("bandit"))))

        config = resolve_config(
            source_dir=repo,
            config_overrides=['default_scanners.only=["checkov"]'],
        )

        assert _only(config) == ["checkov"]

    def test_an_operator_add_list_resolves(self, tmp_path: Path) -> None:
        repo = _repo(tmp_path, {})
        operator = _operator(tmp_path, {"default_scanners": {"add": ["trivy"]}})

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
        assert _warnings_naming(ash_log, "default_scanners")

    def test_a_named_checkout_file_cannot_replace_it(
        self, tmp_path: Path, operator_base: Path, ash_log
    ) -> None:
        repo = _repo(tmp_path, _selecting("trivy"))

        config = resolve_config(config_path=repo / ".ash.yaml", source_dir=repo)

        assert _only(config) == ["bandit"]
        assert _warnings_naming(ash_log, "default_scanners")

    def test_a_checkout_file_cannot_erase_it(
        self, tmp_path: Path, operator_base: Path
    ) -> None:
        repo = _repo(tmp_path, {"default_scanners": {}})

        assert _only(resolve_config(source_dir=repo)) == ["bandit"]

    def test_a_checkout_file_cannot_swap_it_for_an_add_list(
        self, tmp_path: Path, operator_base: Path
    ) -> None:
        repo = _repo(tmp_path, {"default_scanners": {"add": ["trivy"]}})

        config = resolve_config(source_dir=repo)

        assert _only(config) == ["bandit"]
        assert _add(config) == []

    def test_a_checkout_file_repeating_the_operators_value_is_quiet(
        self, tmp_path: Path, operator_base: Path, ash_log
    ) -> None:
        repo = _repo(tmp_path, _selecting("bandit"))

        config = resolve_config(source_dir=repo)

        assert _only(config) == ["bandit"]
        assert not _warnings_naming(ash_log, "default_scanners")

    def test_an_untrusted_extends_link_cannot_replace_it(
        self, tmp_path: Path, operator_base: Path
    ) -> None:
        repo = _repo(tmp_path, {})
        _write(repo / "base.yaml", _selecting("trivy"))
        _write(repo / ".ash.yaml", {"extends": "base.yaml"})

        config = resolve_config(source_dir=repo)

        assert _only(config) == ["bandit"]

    def test_a_workspace_project_cannot_replace_it(
        self, tmp_path: Path, ash_log
    ) -> None:
        repo = _repo(tmp_path, _selecting("trivy"))
        operator = _operator(tmp_path, _selecting("bandit"))

        config = resolve_config(
            config_path=repo / ".ash.yaml",
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
            config_overrides=['default_scanners.only=["checkov"]'],
        )

        assert _only(config) == ["checkov"]

    def test_with_no_operator_selection_a_checkout_file_selects_nothing(
        self, tmp_path: Path, ash_log
    ) -> None:
        repo = _repo(tmp_path, _selecting("trivy"))

        config = resolve_config(source_dir=repo)

        assert _only(config) == []
        assert _warnings_naming(ash_log, "default_scanners")


class TestTheWarningNamesOnlyWhatARepositoryWrote:
    @pytest.fixture
    def operator_base(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        path = _operator(tmp_path, _selecting("bandit"))
        monkeypatch.setenv("ASH_CONFIG", str(path))
        return path

    def test_a_checkout_file_without_the_section_draws_no_warning(
        self, tmp_path: Path, operator_base: Path, ash_log
    ) -> None:
        repo = _repo(tmp_path, {"project_name": "repo"})

        config = resolve_config(source_dir=repo)

        assert _only(config) == ["bandit"]
        assert not _warnings_naming(ash_log, "default_scanners")

    def test_a_named_checkout_file_without_the_section_draws_no_warning(
        self, tmp_path: Path, operator_base: Path, ash_log
    ) -> None:
        repo = _repo(tmp_path, {"project_name": "repo"})

        config = resolve_config(config_path=repo / ".ash.yaml", source_dir=repo)

        assert _only(config) == ["bandit"]
        assert not _warnings_naming(ash_log, "default_scanners")

    def test_the_warning_names_the_one_key_the_file_wrote_once(
        self, tmp_path: Path, operator_base: Path, ash_log
    ) -> None:
        repo = _repo(tmp_path, _selecting("trivy"))

        resolve_config(source_dir=repo)

        said = _warnings_naming(ash_log, "default_scanners")
        assert len(said) == 1
        assert said[0].count("default_scanners.only") == 1
        assert "default_scanners.add" not in said[0]

    def test_a_file_that_wrote_an_add_list_is_named_by_that_key_only(
        self, tmp_path: Path, operator_base: Path, ash_log
    ) -> None:
        repo = _repo(tmp_path, {"default_scanners": {"add": ["trivy"]}})

        resolve_config(source_dir=repo)

        said = _warnings_naming(ash_log, "default_scanners")
        assert len(said) == 1
        assert said[0].count("default_scanners.add") == 1
        assert "default_scanners.only" not in said[0]

    def test_an_extends_chain_naming_the_key_in_two_files_names_it_once(
        self, tmp_path: Path, operator_base: Path, ash_log
    ) -> None:
        repo = _repo(tmp_path, {})
        _write(repo / "base.yaml", _selecting("trivy"))
        _write(
            repo / ".ash.yaml",
            {"extends": "base.yaml", **_selecting("checkov")},
        )

        resolve_config(source_dir=repo)

        said = _warnings_naming(ash_log, "default_scanners")
        assert len(said) == 1
        assert said[0].count("default_scanners.only") == 1


class TestAnOperatorOverrideIsNotBlockedByAnIgnoredFile:
    def test_an_only_override_over_a_checkout_add_list(self, tmp_path: Path) -> None:
        repo = _repo(tmp_path, {"default_scanners": {"add": ["trivy"]}})

        config = resolve_config(
            source_dir=repo,
            config_overrides=['default_scanners.only=["bandit"]'],
        )

        assert _only(config) == ["bandit"]
        assert _add(config) == []

    def test_an_add_override_over_a_checkout_only_list(self, tmp_path: Path) -> None:
        repo = _repo(tmp_path, _selecting("trivy"))

        config = resolve_config(
            source_dir=repo,
            config_overrides=['default_scanners.add=["checkov"]'],
        )

        assert _add(config) == ["checkov"]
        assert _only(config) == []

    def test_a_checkout_file_writing_both_lists_does_not_make_the_config_unloadable(
        self, tmp_path: Path
    ) -> None:
        repo = _repo(
            tmp_path,
            {"default_scanners": {"only": ["a"], "add": ["b"]}},
        )

        config = resolve_config(source_dir=repo)

        assert _only(config) == []
        assert _add(config) == []

    def test_the_override_still_conflicts_with_the_operators_own_file(
        self, tmp_path: Path
    ) -> None:
        repo = _repo(tmp_path, {})
        operator = _operator(tmp_path, _selecting("bandit"))

        with pytest.raises(ASHConfigValidationError, match="cannot be set together"):
            resolve_config(
                config_path=operator,
                source_dir=repo,
                config_overrides=['default_scanners.add=["checkov"]'],
            )

    def test_the_override_still_conflicts_with_the_operators_ash_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo = _repo(tmp_path, {})
        monkeypatch.setenv("ASH_CONFIG", str(_operator(tmp_path, _selecting("bandit"))))

        with pytest.raises(ASHConfigValidationError, match="cannot be set together"):
            resolve_config(
                source_dir=repo,
                config_overrides=['default_scanners.add=["checkov"]'],
            )


def _mixed(
    tmp_path: Path,
    checkout_document: Dict[str, Any],
    operator_document: Dict[str, Any],
    *own_bases: Path,
) -> tuple[Path, Path]:
    repo = tmp_path / "repo"
    mark_git_checkout(repo)
    base = _write(repo / "ci" / "base.yaml", checkout_document)
    operator = _write(
        tmp_path / "operator.yaml",
        {
            "extends": [p.as_posix() for p in (*own_bases, base)],
            **operator_document,
        },
    )
    return repo, operator


def _resolved_by(
    source: str,
    operator: Path,
    repo: Path,
    monkeypatch: pytest.MonkeyPatch,
    **options: Any,
) -> AshConfig:
    if source == "ASH_CONFIG":
        monkeypatch.setenv("ASH_CONFIG", str(operator))
        return resolve_config(source_dir=repo, **options)
    return resolve_config(config_path=operator, source_dir=repo, **options)


_CHECKOUTS = {
    "checkout-without-section": {"project_name": "repo"},
    "checkout-asking-for-trivy": _selecting("trivy"),
}


class TestAnOperatorFileExtendingACheckoutFileKeepsItsSelection:
    @pytest.mark.parametrize("source", ["--config", "ASH_CONFIG"])
    @pytest.mark.parametrize("checkout", list(_CHECKOUTS))
    def test_the_operators_only_list_stands(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        ash_log,
        source: str,
        checkout: str,
    ) -> None:
        repo, operator = _mixed(tmp_path, _CHECKOUTS[checkout], _selecting("bandit"))

        config = _resolved_by(source, operator, repo, monkeypatch)

        assert _only(config) == ["bandit"]
        assert _add(config) == []
        said = _warnings_naming(ash_log, "default_scanners")
        if checkout == "checkout-asking-for-trivy":
            assert len(said) == 1
            assert "base.yaml" in said[0]
            assert "operator.yaml" not in said[0]
        else:
            assert said == []

    @pytest.mark.parametrize("source", ["--config", "ASH_CONFIG"])
    def test_an_operator_add_list_stands(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source: str
    ) -> None:
        repo, operator = _mixed(
            tmp_path,
            _selecting("trivy"),
            {"default_scanners": {"add": ["checkov"]}},
        )

        config = _resolved_by(source, operator, repo, monkeypatch)

        assert _add(config) == ["checkov"]
        assert _only(config) == []

    def test_a_later_operator_file_replaces_an_earlier_ones_list(
        self, tmp_path: Path
    ) -> None:
        own = _write(tmp_path / "own.yaml", _selecting("checkov"))
        repo, operator = _mixed(
            tmp_path, _selecting("trivy"), _selecting("bandit"), own
        )

        assert _only(resolve_config(config_path=operator, source_dir=repo)) == [
            "bandit"
        ]

    def test_an_operator_base_s_list_stands_when_the_root_writes_none(
        self, tmp_path: Path
    ) -> None:
        own = _write(tmp_path / "own.yaml", _selecting("checkov"))
        repo, operator = _mixed(tmp_path, _selecting("trivy"), {}, own)

        assert _only(resolve_config(config_path=operator, source_dir=repo)) == [
            "checkov"
        ]

    def test_an_operator_patch_adds_to_its_own_list(self, tmp_path: Path) -> None:
        own = _write(tmp_path / "own.yaml", _selecting("checkov"))
        repo, operator = _mixed(
            tmp_path,
            {"project_name": "repo"},
            {
                "patch": [
                    {
                        "op": "add",
                        "path": "/default_scanners/only/-",
                        "value": "bandit",
                    }
                ]
            },
            own,
        )

        assert _only(resolve_config(config_path=operator, source_dir=repo)) == [
            "checkov",
            "bandit",
        ]

    def test_an_operator_override_still_wins(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo, operator = _mixed(tmp_path, _selecting("trivy"), _selecting("bandit"))

        config = resolve_config(
            config_path=operator,
            source_dir=repo,
            config_overrides=['default_scanners.only=["checkov"]'],
        )

        assert _only(config) == ["checkov"]

    @pytest.mark.parametrize("source", ["--config", "ASH_CONFIG"])
    def test_a_chain_with_no_operator_write_does_not_adopt_the_checkout_s(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        ash_log,
        source: str,
    ) -> None:
        repo, operator = _mixed(tmp_path, _selecting("trivy"), {"project_name": "op"})

        config = _resolved_by(source, operator, repo, monkeypatch)

        assert _only(config) == []
        assert _add(config) == []
        assert len(_warnings_naming(ash_log, "default_scanners")) == 1

    def test_ash_config_s_list_stands_beside_a_discovered_checkout_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ash_log
    ) -> None:
        repo, operator = _mixed(
            tmp_path, {"project_name": "repo"}, _selecting("bandit")
        )
        _write(repo / ".ash.yaml", {"project_name": "repo"})
        monkeypatch.setenv("ASH_CONFIG", str(operator))

        config = resolve_config(source_dir=repo)

        assert _only(config) == ["bandit"]
        assert _warnings_naming(ash_log, "default_scanners") == []

    def test_ash_config_s_list_stands_under_a_named_checkout_config_asking_for_trivy(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ash_log
    ) -> None:
        repo, operator = _mixed(
            tmp_path, {"project_name": "repo"}, _selecting("bandit")
        )
        named = _write(repo / ".ash.yaml", _selecting("trivy"))
        monkeypatch.setenv("ASH_CONFIG", str(operator))

        config = resolve_config(config_path=named, source_dir=repo)

        assert _only(config) == ["bandit"]
        assert len(_warnings_naming(ash_log, "default_scanners")) == 1

    def test_a_named_operator_file_over_a_mixed_ash_config_replaces_its_list(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        repo, operator = _mixed(
            tmp_path, {"project_name": "repo"}, _selecting("bandit")
        )
        named = _write(
            tmp_path / "named" / "ash.yaml",
            {"default_scanners": {"add": ["checkov"]}},
        )
        monkeypatch.setenv("ASH_CONFIG", str(operator))

        config = resolve_config(config_path=named, source_dir=repo)

        assert _add(config) == ["checkov"]
        assert _only(config) == []


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
                                "/default_scanners",
                                "/default_scanners/**",
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
                "path": "/default_scanners/only",
                "value": ["trivy"],
            },
            {
                "op": "add",
                "path": "/default_scanners/add",
                "value": ["trivy"],
            },
            {"op": "remove", "path": "/default_scanners/only"},
            {"op": "replace", "path": "/default_scanners", "value": {}},
        ],
    )
    def test_a_patch_is_refused_even_when_the_profile_allows_the_path(
        self, session, op: Dict[str, Any]
    ) -> None:
        from automated_security_helper.cli.mcp_tools import mcp_select_profile

        result = mcp_select_profile("op", patch_ops=[op], session_id="session-a")

        assert result["success"] is False
        assert "default_scanners" in str(result.get("error"))

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
        document["default_scanners"] = {"only": ["trivy"]}
        _write(client, document)

        with pytest.raises(ASHConfigFieldDeniedError):
            resolve_config(
                client,
                trusted_config_path=operator,
                untrusted_config=True,
                remote_client=True,
            )


class TestTheLinterAgreesWithTheScan:
    def _lint(self, *args: str):
        from typer.testing import CliRunner

        from automated_security_helper.cli.main import app

        return CliRunner().invoke(app, ["config", "lint", *args])

    @pytest.mark.parametrize(
        "section",
        [
            {"only_scanner": ["bandit"]},
            {"only": ["a"], "add": ["b"]},
        ],
        ids=["unknown-subkey", "both-lists"],
    )
    def test_an_operator_file_with_a_bad_section_is_reported_as_blocking(
        self, tmp_path: Path, section: Dict[str, Any]
    ) -> None:
        operator = _operator(tmp_path, {"default_scanners": section})
        source = tmp_path / "src"
        source.mkdir()

        result = self._lint("--config", str(operator), "--source-dir", str(source))

        assert "default_scanners" in result.output
        assert "blocks the scan" in result.output

    @pytest.mark.parametrize(
        "section",
        [
            {"only_scanner": ["bandit"]},
            {"only": ["a"], "add": ["b"]},
        ],
        ids=["unknown-subkey", "both-lists"],
    )
    def test_a_repository_file_with_a_bad_section_is_ignored_not_a_veto(
        self, tmp_path: Path, section: Dict[str, Any]
    ) -> None:
        repo = _repo(tmp_path, {"default_scanners": section})

        scanned = resolve_config(source_dir=repo)
        result = self._lint("--source-dir", str(repo))

        assert list(scanned.default_scanners.only) == []
        assert "blocks the scan" not in result.output, result.output

    @staticmethod
    def _words(output: str) -> str:
        return " ".join(output.split())

    def test_an_unknown_subkey_in_a_repository_file_is_a_warning_not_a_veto(
        self, tmp_path: Path
    ) -> None:
        repo = _repo(
            tmp_path, {"default_scanners": {"only_scanner": ["zz-secret-value"]}}
        )

        result = self._lint("--source-dir", str(repo))
        said = self._words(result.output)

        assert result.exit_code == 0, result.output
        assert "blocks the scan" not in said
        assert "default_scanners.only_scanner is not a default_scanners key" in said
        assert "a scan ignores the default_scanners section" in said
        assert "zz-secret-value" not in said

    def test_a_repository_list_a_scan_ignores_is_a_warning(
        self, tmp_path: Path
    ) -> None:
        repo = _repo(tmp_path, _selecting("trivy"))

        result = self._lint("--source-dir", str(repo))
        said = self._words(result.output)

        assert result.exit_code == 0, result.output
        assert (
            "default_scanners.only is set in a config file inside the "
            "scanned tree, and a scan ignores that value"
        ) in said
        assert "trivy" not in said

    def test_a_repository_list_repeating_the_operators_is_quiet(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ASH_CONFIG", str(_operator(tmp_path, _selecting("bandit"))))
        repo = _repo(tmp_path, _selecting("bandit"))

        result = self._lint("--source-dir", str(repo))

        assert result.exit_code == 0, result.output
        assert "default_scanners" not in result.output

    def test_a_repository_file_without_the_section_is_quiet(
        self, tmp_path: Path
    ) -> None:
        repo = _repo(tmp_path, {"project_name": "repo"})

        result = self._lint("--source-dir", str(repo))

        assert result.exit_code == 0, result.output
        assert "default_scanners" not in result.output


class TestTheReferenceQualifiesUnknownKeys:
    def test_the_section_s_unknown_key_sentence_names_the_repository_case(
        self,
    ) -> None:
        text = (
            Path(__file__).resolve().parents[3]
            / "docs"
            / "content"
            / "reference"
            / "configuration.md"
        ).read_text(encoding="utf-8")
        section = text[text.index('<a id="section-default_scanners">') :]
        section = section[: section.index("<!-- doctest: options of=default_scanners")]
        said = " ".join(section.split())

        # The page is generated, and its generator spells every `ash <subcommand>`
        # with the v4 entry point (scripts/_reference_docs.py, canonical_cli).
        assert (
            "A key not listed here is an error when the configuration is loaded. "
            "In a config file inside a git checkout or the scanned tree, or one an "
            "MCP client delivered, the whole section is ignored instead, an "
            "unknown key included, and `ashx config lint` warns about it."
        ) in said
