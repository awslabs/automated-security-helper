# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The ambiguity refusal names no value read from the environment.

Two non-declared spellings of one known plugin's section are refused as
ambiguous. A section key can itself be read from the environment, and the
refusal printed that key's value on every surface (validate, get, lint, scan,
and the MCP get_config answer). The refusal keeps saying which keys collide,
naming an env-read key by its written form.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.cli.mcp_tools import mcp_get_config
from automated_security_helper.config.resolve_config import load_config_file_for_run

VAR_SECT = "ASH_TEST_AMBIG_SECT"
SECT_VALUE = "dEtEcT-sEcReTs"
VAR_EXT = "ASH_TEST_AMBIG_EXT"
EXT_VALUE = "ambig-needle-7c.json"

#: Two non-declared spellings of detect-secrets in one file.
CASES = {
    # the second spelling's section reads its content from the environment
    "env-content": (
        "  DetectSecrets:\n    enabled: false\n"
        f"  DETECT_SECRETS:\n    options:\n      baseline_file: ${{{VAR_EXT}}}\n"
    ),
    # the second spelling is itself read from the environment
    "env-key": (
        "  DetectSecrets:\n    enabled: false\n"
        f"  ${{{VAR_SECT}}}:\n    options:\n      baseline_file: lit.json\n"
    ),
}
SURFACES = ("validate", "get", "lint", "scan", "mcp")


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv(VAR_SECT, SECT_VALUE)
    monkeypatch.setenv(VAR_EXT, EXT_VALUE)


def _write(folder, scanners_body, name="ash.yaml"):
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    path.write_text("project_name: t\nscanners:\n" + scanners_body, encoding="utf-8")
    return path


def _surface(tmp_path, monkeypatch, surface, body):
    if surface == "mcp":
        path = _write(tmp_path / "operator", body, ".ash.yaml")
        monkeypatch.setenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", str(tmp_path))
        result = mcp_get_config(config_path=str(path))
        code = 0 if result.get("success") is not False else 1
        return code, json.dumps(result, default=str)
    path = _write(tmp_path / "cfg", body)
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    monkeypatch.chdir(source)
    if surface == "scan":
        argv = [
            "scan",
            "--source-dir",
            str(source),
            "--output-dir",
            str(tmp_path / "out"),
            "--config",
            str(path),
        ]
    else:
        argv = ["config", surface, "--config", str(path)]
    result = CliRunner().invoke(app, argv)
    return result.exit_code, result.output


@pytest.mark.parametrize("surface", SURFACES)
@pytest.mark.parametrize("case", sorted(CASES))
def test_the_ambiguity_refusal_names_no_value(tmp_path, monkeypatch, case, surface):
    code, text = _surface(tmp_path, monkeypatch, surface, CASES[case])
    bare = "".join(text.split())
    assert code != 0, bare[-2000:]
    assert "ambiguous" in bare, bare[-2000:]
    assert EXT_VALUE not in bare, bare[-2000:]
    assert SECT_VALUE not in bare, bare[-2000:]


def test_control_an_env_read_section_key_is_folded(tmp_path):
    """The env-key case tests the refusal only if a key read from the
    environment reaches the fold: one such key alone configures the plugin."""
    path = _write(tmp_path, f"  ${{{VAR_SECT}}}:\n    enabled: false\n")
    _, config = load_config_file_for_run(path)
    assert config.scanners.detect_secrets.enabled is False
    assert SECT_VALUE not in (config.scanners.model_extra or {})


def test_control_an_unknown_plugin_with_two_spellings_is_not_refused(
    tmp_path, monkeypatch
):
    path = _write(
        tmp_path,
        "  my-scanner:\n    enabled: false\n  MyScanner:\n    enabled: false\n",
    )
    _, config = load_config_file_for_run(path)
    extras = config.scanners.model_extra or {}
    assert {"my-scanner", "MyScanner"} <= set(extras), extras
    monkeypatch.chdir(tmp_path)
    validate = CliRunner().invoke(app, ["config", "validate", "--config", str(path)])
    assert validate.exit_code == 0, validate.output
