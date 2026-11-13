# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every production loader accepts what a scan accepts (warn-then-refuse rollout).

``build_config`` warns about an unknown suppression or ignore-path key and
disables the entry (test_fail_on_unknown_keys_warn_mode.py). The other loaders
that validate a config "as a scan validates it" went on refusing the same file
with exit 3: ``validate_config_document`` ran a strict validation with no
context, which its callers inherit -- the ASH_CONFIG pre-run load
(``run_ash_scan._host_resolved_config`` via ``_load_single_config_file``), the
MCP config-input check (``sandbox.check_config_input``) and the operator
overlay's own validation (``_load_overlay``) -- and the overlay-alone fallback
validated with its own bare ``model_validate``. Each loader now builds the same
context (``_entry_warn_context``): the file loads with the warning under the
default, and still refuses under ``fail_on_unknown_keys: true``.
"""

from pathlib import Path

import pytest
import yaml

from automated_security_helper.config.resolve_config import (
    _load_single_config_file,
    resolve_config,
)
from automated_security_helper.core.exceptions import ASHConfigValidationError

pytestmark = pytest.mark.unit

#: A suppression entry with one unknown key (a typo of ``expiration``).
_TYPO_SUPPRESSION = {
    "rule_id": "RULE-1",
    "path": "src/app.py",
    "reason": "test",
    "expiraton": "2099-12-31",
}


def _config_data(**top_level) -> dict:
    data = {
        "project_name": "warn-mode-loaders",
        "global_settings": {"suppressions": [dict(_TYPO_SUPPRESSION)]},
    }
    data.update(top_level)
    return data


def _write(path: Path, document) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def _the_warning(config) -> list:
    return [
        w for w in config._resolution_warnings if "Unknown key 'expiraton'" in str(w)
    ]


class TestSingleFileLoad:
    """``_load_single_config_file``: the loader behind the ASH_CONFIG pre-run
    read (``run_ash_scan._host_resolved_config``) and ``AshConfig.from_file``."""

    def test_an_unknown_entry_key_warns_and_loads(self, tmp_path):
        path = _write(tmp_path / "ash.yaml", _config_data())

        loaded = _load_single_config_file(path)

        assert len(_the_warning(loaded)) == 1
        assert loaded.global_settings.suppressions[0].has_unknown_keys

    def test_fail_on_unknown_keys_still_refuses(self, tmp_path):
        path = _write(tmp_path / "ash.yaml", _config_data(fail_on_unknown_keys=True))

        with pytest.raises(ASHConfigValidationError) as raised:
            _load_single_config_file(path)

        assert "Unknown key 'expiraton'" in str(raised.value)


class TestMcpConfigInputCheck:
    """``sandbox.check_config_input``: the MCP pre-scan check of a named config."""

    @pytest.fixture
    def scan_root(self, tmp_path, monkeypatch) -> Path:
        from automated_security_helper.cli.mcp.sandbox import (
            ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV,
            ASH_MCP_ALLOWED_ROOTS_ENV,
            ASH_MCP_TRANSPORT_ENV,
        )

        monkeypatch.delenv(ASH_MCP_ALLOWED_ROOTS_ENV, raising=False)
        monkeypatch.setenv(ASH_MCP_TRANSPORT_ENV, "stdio")
        monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
        ops = tmp_path / "ops"
        ops.mkdir()
        monkeypatch.setenv(ASH_MCP_ALLOWED_CONFIG_ROOTS_ENV, str(ops))
        scan = tmp_path / "scan"
        scan.mkdir()
        (scan / "app.py").write_text("x = 1\n", encoding="utf-8")
        return scan

    def test_an_unknown_entry_key_passes_the_check(self, scan_root, tmp_path):
        from automated_security_helper.cli.mcp.sandbox import check_config_input

        config = _write(tmp_path / "ops" / "ash.yaml", _config_data())

        checked = check_config_input(str(config), source_dir=scan_root)

        assert checked.refusal is None
        assert checked.load_error is None, str(checked.load_error)
        assert checked.document is not None

    def test_fail_on_unknown_keys_still_refuses(self, scan_root, tmp_path):
        from automated_security_helper.cli.mcp.sandbox import check_config_input

        config = _write(
            tmp_path / "ops" / "ash.yaml", _config_data(fail_on_unknown_keys=True)
        )

        checked = check_config_input(str(config), source_dir=scan_root)

        assert checked.load_error is not None
        assert "Unknown key 'expiraton'" in str(checked.load_error)


class TestOperatorOverlay:
    """``resolve_config(overlay_config_path=...)``: the overlay's own validation
    (``_load_overlay``) and the overlay-alone fallback."""

    @pytest.fixture(autouse=True)
    def _no_ash_config(self, monkeypatch):
        monkeypatch.delenv("ASH_CONFIG", raising=False)
        monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)

    def test_an_unknown_entry_key_in_the_overlay_warns_and_loads(self, tmp_path):
        project = _write(tmp_path / "repo" / ".ash" / ".ash.yaml", {})
        operator = _write(tmp_path / "operator" / "ash.yaml", _config_data())

        config = resolve_config(
            config_path=project,
            source_dir=tmp_path / "repo",
            overlay_config_path=operator,
        )

        assert len(_the_warning(config)) == 1
        assert config.global_settings.suppressions[0].has_unknown_keys

    def test_fail_on_unknown_keys_in_the_overlay_still_refuses(self, tmp_path):
        project = _write(tmp_path / "repo" / ".ash" / ".ash.yaml", {})
        operator = _write(
            tmp_path / "operator" / "ash.yaml", _config_data(fail_on_unknown_keys=True)
        )

        with pytest.raises(ASHConfigValidationError) as raised:
            resolve_config(
                config_path=project,
                source_dir=tmp_path / "repo",
                overlay_config_path=operator,
            )

        assert "Unknown key 'expiraton'" in str(raised.value)

    def test_the_overlay_used_alone_warns_and_loads(self, tmp_path, monkeypatch):
        """The fallback arm: no source, no config, the overlay stands alone."""
        (tmp_path / "cwd").mkdir()
        monkeypatch.chdir(tmp_path / "cwd")
        operator = _write(tmp_path / "operator" / "ash.yaml", _config_data())

        config = resolve_config(overlay_config_path=operator)

        assert len(_the_warning(config)) == 1
        assert config.global_settings.suppressions[0].has_unknown_keys

    def test_the_overlay_used_alone_still_refuses_under_the_flag(
        self, tmp_path, monkeypatch
    ):
        (tmp_path / "cwd").mkdir()
        monkeypatch.chdir(tmp_path / "cwd")
        operator = _write(
            tmp_path / "operator" / "ash.yaml", _config_data(fail_on_unknown_keys=True)
        )

        with pytest.raises(ASHConfigValidationError) as raised:
            resolve_config(overlay_config_path=operator)

        assert "Unknown key 'expiraton'" in str(raised.value)
