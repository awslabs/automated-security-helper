# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A respelled known-plugin override names its plugin.

A config file may spell a known plugin's section under any spelling (case and
the ``-``/``_`` separators dropped), so an override may too:
``--config-overrides scanners.CdkNag.enabled=false`` applies to cdk-nag
instead of being silently dropped while the run reports success. The fold
covers DECLARED plugin sections only, directly under converters, scanners and
reporters: an unknown section's override stays exact, and an off-host
reporter (an extra section, not a declared field) is never folded into, so a
respelled override cannot reach it past the gates that match its real name.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.config.resolve_config import (
    apply_config_overrides,
    load_config_file_for_run,
)

pytestmark = pytest.mark.unit

OVERRIDE_SPELLINGS = ["cdk-nag", "cdk_nag", "CdkNag", "CDK_NAG", "cdknag"]


@pytest.fixture
def enabled_config(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / "ash.yaml"
    path.write_text(
        "project_name: t\nscanners:\n  cdk-nag:\n    enabled: true\n",
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize("spelling", OVERRIDE_SPELLINGS)
def test_a_respelled_override_is_applied(enabled_config, spelling):
    _, config = load_config_file_for_run(enabled_config)
    assert config.scanners.cdk_nag.enabled is True

    updated = apply_config_overrides(config, [f"scanners.{spelling}.enabled=false"])

    assert updated.scanners.cdk_nag.enabled is False


def test_config_get_shows_a_respelled_override(enabled_config, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        app,
        [
            "config",
            "get",
            "--config",
            str(enabled_config),
            "--config-overrides",
            "scanners.CdkNag.enabled=false",
        ],
    )
    flat = " ".join(result.output.split())
    assert result.exit_code == 0, result.output
    assert "cdk-nag: name: cdk-nag enabled: false" in flat, flat[:3000]


def test_the_operator_only_gate_reads_a_respelled_override():
    """The gate resolves segments the way the apply does, fold included, so a
    respelled override of a declared reporter counts as writing its option."""
    from automated_security_helper.config.operator_only_options import _set_by_override

    reporters = {"gitlab-sast": {"options": {"output_dir": "a"}}}

    assert _set_by_override(
        reporters,
        "gitlab-sast",
        "output_dir",
        ["reporters.GitlabSast.options.output_dir=b"],
    )


def test_the_workspace_gate_reads_a_respelled_override():
    """The MCP workspace gate resolves the same keys the apply writes."""
    from automated_security_helper.cli.mcp.workspace import _resolve_override_key

    base = {"reporters": {"gitlab-sast": {"options": {"output_dir": "a"}}}}

    resolved = _resolve_override_key(
        base, ["reporters", "GitlabSast", "options", "output_dir"]
    )

    assert resolved == ["reporters", "gitlab-sast", "options", "output_dir"]


def test_the_cli_and_mcp_walks_resolve_one_key_to_one_place():
    """One override key lands in the SAME place on the CLI and MCP paths.

    The CLI side is the real apply walk (_apply_config_override on a copy,
    located by where its marker value landed), not a replay of the resolver;
    the MCP side is the workspace gate's walk. A walk that kept its own
    resolver, or dropped the shared one, would land one override in different
    sections per surface or refuse on one surface only; both turn this red.
    """
    import copy

    from automated_security_helper.cli.mcp.workspace import _resolve_override_key
    from automated_security_helper.config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    marker = "zq-f7-landed-marker"
    base = {
        "scanners": {"cdk_nag": {"enabled": True}, "my-scanner": {"enabled": True}},
        "reporters": {"gitlab-sast": {"options": {"output_dir": "a"}}},
    }

    def landed_at(node, trail=()):
        if node == marker:
            return trail
        if isinstance(node, dict):
            for key, value in node.items():
                found = landed_at(value, (*trail, key))
                if found is not None:
                    return found
        return None

    def cli_walk(parts):
        data = copy.deepcopy(base)
        try:
            resolve_config._apply_config_override(data, ".".join(parts), marker)
        except ASHConfigValidationError as refused:
            return ("refused", str(refused))
        return ("landed", landed_at(data))

    def mcp_walk(parts):
        try:
            resolved = _resolve_override_key(copy.deepcopy(base), parts)
        except ASHConfigValidationError as refused:
            return ("refused", str(refused))
        return ("landed", tuple(resolved))

    for parts, expected in (
        (
            ["scanners", "CdkNag", "enabled"],
            ("landed", ("scanners", "cdk_nag", "enabled")),
        ),
        (
            ["reporters", "GitlabSast", "options", "output_dir"],
            ("landed", ("reporters", "gitlab-sast", "options", "output_dir")),
        ),
        (
            ["reporters", "brand-new", "enabled"],
            ("landed", ("reporters", "brand-new", "enabled")),
        ),
        (["scanners", "MyScanner", "enabled"], None),
    ):
        cli = cli_walk(parts)
        mcp = mcp_walk(parts)
        assert cli == mcp, (parts, cli, mcp)
        if expected is None:
            assert cli[0] == "refused", (parts, cli)
            assert "'scanners.my-scanner'" in cli[1], cli
        else:
            assert cli == expected, (parts, cli)


def test_control_an_unknown_section_override_stays_exact(tmp_path, monkeypatch):
    """An unknown plugin's spellings are distinct sections (extras), so an
    override of one spelling never writes another: one that matches no
    existing section lands as written, and one respelling an existing section
    is refused with the real key (never silently landed beside it)."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / "ash.yaml"
    path.write_text(
        "project_name: t\nscanners:\n  my-scanner:\n    enabled: true\n",
        encoding="utf-8",
    )
    _, config = load_config_file_for_run(path)

    updated = apply_config_overrides(config, ["scanners.other-tool.enabled=false"])

    extras = updated.scanners.model_extra or {}
    assert extras["my-scanner"]["enabled"] is True, extras
    assert extras["other-tool"]["enabled"] is False, extras

    with pytest.raises(Exception) as refused:
        apply_config_overrides(config, ["scanners.MyScanner.enabled=false"])
    assert "scanners.my-scanner" in str(refused.value), str(refused.value)


def test_control_an_off_host_section_is_not_a_fold_target(tmp_path, monkeypatch):
    """Must-not-bypass: the off-host reporters are extra sections, not
    declared fields, so a respelled override is never folded into them -- and
    never silently landed beside them either: it is refused with the real
    key, so a disable the operator wrote cannot read as success while the
    reporter's own section keeps sending findings off the host."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / "ash.yaml"
    path.write_text(
        "project_name: t\nreporters:\n  aws-security-hub:\n    enabled: true\n",
        encoding="utf-8",
    )
    _, config = load_config_file_for_run(path)
    extras = config.reporters.model_extra or {}
    assert extras.get("aws-security-hub", {}).get("enabled") is True

    with pytest.raises(Exception) as refused:
        apply_config_overrides(config, ["reporters.AwsSecurityHub.enabled=false"])

    assert "reporters.aws-security-hub" in str(refused.value), str(refused.value)
    after = config.reporters.model_extra or {}
    assert after["aws-security-hub"]["enabled"] is True, after
