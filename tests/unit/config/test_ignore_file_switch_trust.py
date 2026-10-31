# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Only the operator decides whether a scan honors the repository's ignore files.

The switch that turns ``.gitignore`` / ``.ignore`` handling off is an operator setting.
Operator tier, here as everywhere else the config trust checks apply: the defaults, a
config file outside the scanned tree, ``ASH_CONFIG`` naming a file outside it, and
``--config-overrides``. A config file the scanned repository wrote (found in the tree,
named with ``--config`` inside it, or named by ``ASH_CONFIG`` inside it) and a config an
MCP client supplied cannot set it in either direction. Their value is replaced by the
trusted one with one warning naming the key and the file, which is what
``ash_plugin_modules`` (config/plugin_module_trust.py) and the sandbox grants
(config/sandbox_grants.py) do. MCP runtime overrides and an MCP client's
``config_overrides`` are refused by the default ``denied_paths``, like
``fail_on_findings``.

The config key is ``honor_ignore_files`` (a proposed name, spelled only in
``CONFIG_KEY``), default true. On a build that has no such key every resolved config
reads as honoring, which is what :func:`honors_ignore_files` returns then.
"""

from __future__ import annotations

from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.config.ash_config import RuntimeOverridesConfig
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.config.runtime_patch import (
    RuntimePatchDeniedError,
    check_runtime_ops,
)
from automated_security_helper.utils.log import ASH_LOGGER
from tests.unit.config._client_policy_helpers import narrow_client_rules

pytestmark = pytest.mark.unit

CONFIG_KEY = "honor_ignore_files"


def honors_ignore_files(config) -> bool:
    return getattr(config, CONFIG_KEY, True)


def _yaml(honor: bool, **extra: str) -> str:
    lines = ["project_name: test", f"{CONFIG_KEY}: {'true' if honor else 'false'}"]
    lines += [f"{key}: {value}" for key, value in extra.items()]
    return "\n".join(lines) + "\n"


def _repo(tmp_path: Path, config: str | None = None) -> Path:
    """A checkout, with its own config at .ash/.ash.yaml when ``config`` is given."""
    source = tmp_path / "repo"
    (source / ".git").mkdir(parents=True)
    if config is not None:
        (source / ".ash").mkdir()
        (source / ".ash" / ".ash.yaml").write_text(config)
    return source


def _outside(tmp_path: Path, config: str, name: str = "operator.yaml") -> Path:
    path = tmp_path / "outside" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(config)
    return path


def _warnings_while(func, *args, **kwargs):
    """Run ``func`` and return (its result, every ASH_LOGGER warning text)."""
    mock_warning = MagicMock()
    with patch.object(ASH_LOGGER, "warning", mock_warning):
        result = func(*args, **kwargs)
    messages: List[str] = []
    for call in mock_warning.call_args_list:
        if not call.args:
            continue
        template = str(call.args[0])
        try:
            messages.append(
                template % call.args[1:] if len(call.args) > 1 else template
            )
        except (TypeError, ValueError):
            messages.append(" ".join(str(a) for a in call.args))
    return result, messages


@pytest.fixture(autouse=True)
def _no_operator_env(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)


# --------------------------------------------------------------------------- operator tier


class TestOperatorSourcesSetTheSwitch:
    def test_a_config_file_outside_the_tree(self, tmp_path):
        source = _repo(tmp_path)
        config = resolve_config(
            config_path=_outside(tmp_path, _yaml(False)), source_dir=source
        )
        assert honors_ignore_files(config) is False

    def test_ash_config_outside_the_tree(self, tmp_path, monkeypatch):
        source = _repo(tmp_path)
        monkeypatch.setenv("ASH_CONFIG", str(_outside(tmp_path, _yaml(False))))
        assert honors_ignore_files(resolve_config(source_dir=source)) is False

    def test_ash_config_outside_the_tree_wins_over_the_repository_config(
        self, tmp_path, monkeypatch
    ):
        """The direction that would shrink the scan: the repository asks to honor."""
        source = _repo(tmp_path, _yaml(True))
        monkeypatch.setenv("ASH_CONFIG", str(_outside(tmp_path, _yaml(False))))
        config, warnings = _warnings_while(resolve_config, source_dir=source)
        assert honors_ignore_files(config) is False
        assert any(CONFIG_KEY in w and ".ash.yaml" in w for w in warnings), warnings

    @pytest.mark.parametrize("spelling", [CONFIG_KEY, CONFIG_KEY.replace("_", "-")])
    def test_a_config_override_wins_over_the_repository_config(
        self, tmp_path, spelling
    ):
        source = _repo(tmp_path, _yaml(True))
        config = resolve_config(
            source_dir=source, config_overrides=[f"{spelling}=false"]
        )
        assert honors_ignore_files(config) is False


# --------------------------------------------------------------------------- refused tiers


class TestARepositoryOrClientConfigCannotSetTheSwitch:
    def test_a_discovered_config_in_the_tree(self, tmp_path):
        source = _repo(tmp_path, _yaml(False))
        config, warnings = _warnings_while(resolve_config, source_dir=source)
        assert honors_ignore_files(config) is True
        assert any(CONFIG_KEY in w and ".ash.yaml" in w for w in warnings), warnings

    def test_an_explicit_config_inside_the_tree(self, tmp_path):
        source = _repo(tmp_path)
        path = source / "ash.yaml"
        path.write_text(_yaml(False))
        config, warnings = _warnings_while(
            resolve_config, config_path=path, source_dir=source
        )
        assert honors_ignore_files(config) is True
        assert any(CONFIG_KEY in w and "ash.yaml" in w for w in warnings), warnings

    def test_ash_config_inside_the_tree(self, tmp_path, monkeypatch):
        source = _repo(tmp_path)
        inside = source / "ci" / "ash.yaml"
        inside.parent.mkdir()
        inside.write_text(_yaml(False))
        monkeypatch.setenv("ASH_CONFIG", str(inside))
        config, warnings = _warnings_while(resolve_config, source_dir=source)
        assert honors_ignore_files(config) is True
        assert any(CONFIG_KEY in w and "ash.yaml" in w for w in warnings), warnings

    def test_a_config_an_mcp_client_supplied(self, tmp_path):
        """Outside the tree, but written by the client: ``untrusted_config``.

        Refused rather than confined: the switch is in the default denied_paths,
        and a config an MCP client supplied that sets a denied field is refused
        (``client_config_policy``, exit 3), naming the field.
        """
        from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

        source = _repo(tmp_path)
        uploaded = _outside(tmp_path, _yaml(False), name="uploaded.yaml")
        with pytest.raises(ASHConfigFieldDeniedError) as refused:
            resolve_config(
                config_path=uploaded, source_dir=source, untrusted_config=True
            )
        assert CONFIG_KEY in str(refused.value)
        assert "uploaded.yaml" in str(refused.value)

    def test_a_config_an_mcp_client_supplied_under_a_policy_without_the_key(
        self, tmp_path
    ):
        """The switch is in the default denied_paths only, so an operator profile
        with ``replace_default_denied_paths: true`` and a list that leaves it out
        lets the upload past the refusal. The fallback then stands alone: the
        upload's value is replaced by the trusted one, with the warning naming
        the key and the file."""
        source = _repo(tmp_path)
        uploaded = _outside(tmp_path, _yaml(False), name="uploaded.yaml")

        config, warnings = _warnings_while(
            resolve_config,
            config_path=uploaded,
            source_dir=source,
            untrusted_config=True,
            client_config_policy=narrow_client_rules(),
        )

        assert honors_ignore_files(config) is True
        (warning,) = [w for w in warnings if CONFIG_KEY in w]
        assert "uploaded.yaml" in warning, warning


class TestTheWarningSaysWhoWroteTheFile:
    """An MCP client's upload is not in the scanned tree; neither the refusal
    nor the fallback's warning may say it is."""

    def test_an_upload_is_named_as_the_clients(self, tmp_path):
        """The refusal under the default denied_paths."""
        from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

        source = _repo(tmp_path)
        uploaded = _outside(tmp_path, _yaml(False), name="uploaded.yaml")
        with pytest.raises(ASHConfigFieldDeniedError) as refused:
            resolve_config(
                config_path=uploaded, source_dir=source, untrusted_config=True
            )
        assert "MCP client" in str(refused.value), refused.value
        assert "inside a git checkout" not in str(refused.value), refused.value

    def test_an_uploads_fallback_warning_names_the_client(self, tmp_path):
        """The fallback's warning, reached under a policy whose list leaves the
        key out: it gives the client's reason, not the in-tree one."""
        source = _repo(tmp_path)
        uploaded = _outside(tmp_path, _yaml(False), name="uploaded.yaml")

        _config, warnings = _warnings_while(
            resolve_config,
            config_path=uploaded,
            source_dir=source,
            untrusted_config=True,
            client_config_policy=narrow_client_rules(),
        )

        (warning,) = [w for w in warnings if CONFIG_KEY in w]
        assert "MCP client" in warning, warning
        assert "inside a git checkout or the scanned directory" not in warning, warning

    def test_an_in_tree_file_is_named_as_the_repositorys(self, tmp_path):
        source = _repo(tmp_path, _yaml(False))
        _config, warnings = _warnings_while(resolve_config, source_dir=source)
        (warning,) = [w for w in warnings if CONFIG_KEY in w]
        assert "inside a git checkout or the scanned directory" in warning, warning
        assert "MCP client" not in warning, warning


class TestControls:
    """Pass today: the harness reaches the trust checks and sees their warnings."""

    def test_a_repository_config_without_the_key_warns_about_nothing(self, tmp_path):
        source = _repo(tmp_path, "project_name: scanned\n")
        config, warnings = _warnings_while(resolve_config, source_dir=source)
        assert honors_ignore_files(config) is True
        assert not any(CONFIG_KEY in w for w in warnings), warnings

    def test_an_in_tree_sandbox_grant_is_ignored_with_a_warning(self, tmp_path):
        source = _repo(
            tmp_path, 'project_name: scanned\nsandbox:\n  extra_read_paths: ["~"]\n'
        )
        config, warnings = _warnings_while(resolve_config, source_dir=source)
        assert config.sandbox.extra_read_paths == []
        assert any(
            "sandbox.extra_read_paths" in w and ".ash.yaml" in w for w in warnings
        ), warnings


# --------------------------------------------------------------------------- MCP


_OPEN_ALLOWLIST = RuntimeOverridesConfig(enabled=True, allowed_paths=["/**"])


class TestMcpRuntimeOverrides:
    """``select_profile``'s patch ops and an MCP client's config_overrides."""

    @pytest.mark.parametrize("op", ["add", "replace"])
    @pytest.mark.parametrize(
        "path", [f"/{CONFIG_KEY}", "/" + CONFIG_KEY.replace("_", "-")]
    )
    def test_a_runtime_patch_cannot_set_the_switch(self, op, path):
        with pytest.raises(RuntimePatchDeniedError):
            check_runtime_ops(
                [{"op": op, "path": path, "value": False}],
                allowlist=_OPEN_ALLOWLIST,
                config=None,
            )

    def test_a_client_config_override_cannot_set_the_switch(self, tmp_path):
        with pytest.raises(RuntimePatchDeniedError, match="denied_paths"):
            _gate([f"{CONFIG_KEY}=false"], tmp_path)

    # Controls: the same gate, safe inputs.

    def test_control_a_denied_key_is_refused(self):
        with pytest.raises(RuntimePatchDeniedError):
            check_runtime_ops(
                [{"op": "replace", "path": "/fail_on_findings", "value": False}],
                allowlist=_OPEN_ALLOWLIST,
                config=None,
            )

    def test_control_an_allowed_key_is_accepted(self, tmp_path):
        check_runtime_ops(
            [{"op": "replace", "path": "/project_name", "value": "renamed"}],
            allowlist=_OPEN_ALLOWLIST,
            config=None,
        )
        _gate(["project_name=renamed"], tmp_path)


def _profile_with_open_overrides(tmp_path: Path) -> Path:
    path = tmp_path / "profile.yaml"
    path.write_text(
        "project_name: profile\n"
        "global_settings:\n"
        "  mcp:\n"
        "    runtime_overrides:\n"
        "      enabled: true\n"
        '      allowed_paths: ["/**"]\n'
    )
    return path


def _gate(overrides: List[str], tmp_path: Path) -> None:
    """The workspace tools' gate, under the open profile registered as ``open``.

    The policy is the registered profile's (``session_profile_entry``); the
    session config is the config the overrides apply to.
    """
    from automated_security_helper.cli.mcp.profile_registry import (
        clear_profile_registry,
        register_profiles,
        set_profile_registry,
    )
    from automated_security_helper.cli.mcp.workspace import _gate_client_overrides

    profile = _profile_with_open_overrides(tmp_path)
    set_profile_registry(register_profiles([f"open={profile}"]))
    try:
        _gate_client_overrides(overrides, str(profile), profile="open")
    finally:
        clear_profile_registry()
