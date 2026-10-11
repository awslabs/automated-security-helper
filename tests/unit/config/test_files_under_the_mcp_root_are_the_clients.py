# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config file under the MCP workspace root is a client's, whoever names it.

The MCP server writes everything a client delivers under its workspace root
(``ASH_MCP_WORKSPACE_ROOT``), except each session's ``config/`` directory. A
``--config`` or ``ASH_CONFIG`` naming a file there, on the CLI and while
scanning another directory, gets the same tier as a config inside the scanned
tree: sandbox grants, plugin modules, reporter destinations and tool config
files come from the trusted base, and the runtime-override policy is never read
from it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from automated_security_helper.config.resolve_config import resolve_config


@pytest.fixture
def mcp_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "mcp-workspaces"
    (root / "session-1" / "source").mkdir(parents=True)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(root))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    return root


def _repo(tmp_path: Path, document: dict | None = None) -> Path:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    if document is not None:
        (repo / ".ash").mkdir()
        (repo / ".ash" / ".ash.yaml").write_text(
            yaml.safe_dump(document), encoding="utf-8"
        )
    return repo


def test_an_ash_config_under_the_mcp_root_grants_nothing(
    tmp_path: Path, mcp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Its sandbox grants are not the trusted base a repository's config is held to."""
    delivered = mcp_root / "session-1" / "source" / "ash.yaml"
    delivered.write_text(
        yaml.safe_dump({"sandbox": {"extra_read_paths": ["/data"]}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(delivered))
    repo = _repo(tmp_path, {"sandbox": {"extra_read_paths": ["/data"]}})

    config = resolve_config(source_dir=repo)

    assert config.sandbox.extra_read_paths == []


def test_an_ash_config_under_the_mcp_root_is_not_the_policy(
    tmp_path: Path, mcp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The runtime-override policy for an unbound session is not read from it."""
    from automated_security_helper.cli.mcp.profile_registry import (
        session_client_rules,
    )

    delivered = mcp_root / "session-1" / "source" / "ash.yaml"
    delivered.write_text(
        yaml.safe_dump(
            {
                "global_settings": {
                    "mcp": {
                        "runtime_overrides": {
                            "denied_paths": [],
                            "replace_default_denied_paths": True,
                        }
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(delivered))

    rules = session_client_rules("session-1")

    assert "/fail_on_findings" in rules.policy.denied_paths


def test_a_config_under_the_mcp_root_named_on_the_cli_is_not_the_operators(
    tmp_path: Path, mcp_root: Path
) -> None:
    """Confined like an in-tree config even though it is outside the scanned tree."""
    from automated_security_helper.config import resolve_config as rc

    delivered = mcp_root / "session-1" / "source" / "ash.yaml"
    delivered.write_text(yaml.safe_dump({"project_name": "delivered"}), "utf-8")
    repo = _repo(tmp_path)
    seen = {}
    real = rc.confine_sandbox_grants

    def recording(sandbox, trusted, in_tree, **kwargs):
        seen["in_tree"] = list(in_tree)
        return real(sandbox, trusted, in_tree, **kwargs)

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(rc, "confine_sandbox_grants", recording)
    try:
        config = resolve_config(config_path=delivered, source_dir=repo)
    finally:
        monkeypatch.undo()

    assert config.project_name == "delivered"
    assert [Path(p).name for p in seen.get("in_tree", [])] == ["ash.yaml"]


def test_positive_control_an_operator_ash_config_still_grants(
    tmp_path: Path, mcp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    operator = tmp_path / "operator" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text(
        yaml.safe_dump({"sandbox": {"extra_read_paths": ["/data"]}}), "utf-8"
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    repo = _repo(tmp_path, {"sandbox": {"extra_read_paths": ["/data"]}})

    config = resolve_config(source_dir=repo)

    assert config.sandbox.extra_read_paths == ["/data"]


@pytest.mark.parametrize("named_as", ["ASH_CONFIG", "--config"])
def test_a_config_under_the_mcp_root_setting_a_denied_field_is_refused(
    tmp_path: Path,
    mcp_root: Path,
    monkeypatch: pytest.MonkeyPatch,
    named_as: str,
) -> None:
    """Checked against the policy as a delivered file is, however it is named."""
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    delivered = mcp_root / "session-1" / "source" / "ash.yaml"
    delivered.write_text(
        yaml.safe_dump(
            {
                "fail_on_findings": False,
                "global_settings": {
                    "ignore_paths": [{"path": "src/**", "reason": "delivered"}]
                },
            }
        ),
        encoding="utf-8",
    )
    repo = _repo(tmp_path)
    if named_as == "ASH_CONFIG":
        monkeypatch.setenv("ASH_CONFIG", str(delivered))
        call = {"source_dir": repo}
    else:
        call = {"config_path": delivered, "source_dir": repo}

    with pytest.raises(ASHConfigFieldDeniedError) as excinfo:
        resolve_config(**call)
    assert "fail_on_findings" in str(excinfo.value)


def test_positive_control_an_operator_ash_config_is_not_checked(
    tmp_path: Path, mcp_root: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With nothing the client named read, the operator's own file is the config."""
    operator = tmp_path / "operator" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text(yaml.safe_dump({"fail_on_findings": False}), "utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    missing = mcp_root / "session-1" / "source" / "missing.yaml"

    config = resolve_config(
        config_path=missing, source_dir=_repo(tmp_path), untrusted_config=True
    )

    assert config.fail_on_findings is False
