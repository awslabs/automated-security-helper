# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Each warning that drops a setting from a config file the operator did not write
says how to keep it.

A config file inside a git checkout, the scanned one or any other, or inside the
scanned directory may not choose what ``resolve_config`` confines: the sandbox
grants, ``ash_plugin_modules``, the reporters' destinations, the scanners' own
config files, ``tool_version``, the content database staleness policy,
detect-secrets' scan settings, ``honor_ignore_files`` and the archive extraction
limits. Each step warns when it drops or caps a setting, naming the file and the
setting. Every one of those warnings also says how to keep it, in the same words
(``config/confinement_remedy.KEEP_A_SETTING``, which ``IN_TREE_OR_DELIVERED`` carries
as its remedy): move the file outside every git checkout, or pass the setting with
``--config-overrides``.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.utils.log import ASH_LOGGER
from tests.utils.helpers import mark_git_checkout

REMEDY = (
    "move the file outside every git checkout, or pass the setting with "
    "--config-overrides"
)
VERIFICATION_FILTER = (
    "detect_secrets.filters.common.is_ignored_due_to_verification_policies"
)
#: A module no environment has: a config the operator did not write may not add it.
UNINSTALLED = "not_installed_ash_plugins"


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    for directory in (tmp_path, *tmp_path.parents):
        assert not os.path.lexists(directory / ".git"), (
            f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
        )


@pytest.fixture
def warnings():
    """The text of every warning ASH logs while a test resolves a config."""
    messages: List[str] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            messages.append(" ".join(record.getMessage().split()))

    handler = _Collect(level=logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    try:
        yield messages
    finally:
        ASH_LOGGER.removeHandler(handler)


def _config(tmp_path: Path, where: str, settings: dict) -> tuple:
    """(config file, scanned directory): the file in the scanned checkout, or in
    a checkout of its own beside it."""
    repo = tmp_path / "repo"
    mark_git_checkout(repo)
    if where == "the-scanned-checkout":
        path = repo / "ci" / "ash.yaml"
    else:
        mark_git_checkout(tmp_path / "ops")
        path = tmp_path / "ops" / "ash.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"project_name": "p", **settings}), encoding="utf-8")
    return path, repo


def _naming(messages: List[str], setting: str) -> List[str]:
    return [message for message in messages if setting in message]


WHERE = ["the-scanned-checkout", "another-checkout"]


@pytest.mark.parametrize("where", WHERE)
def test_the_sandbox_grant_warning(where, tmp_path, warnings):
    path, repo = _config(
        tmp_path, where, {"sandbox": {"extra_read_paths": ["/opt/grant"]}}
    )

    sandbox = resolve_config(config_path=path, source_dir=repo).sandbox

    assert sandbox.extra_read_paths == []
    (message,) = _naming(warnings, "sandbox.extra_read_paths")
    assert REMEDY in message, message
    assert path.name in message, message


@pytest.mark.parametrize("where", WHERE)
def test_the_plugin_modules_warning(where, tmp_path, warnings):
    path, repo = _config(tmp_path, where, {"ash_plugin_modules": [UNINSTALLED]})

    config = resolve_config(config_path=path, source_dir=repo)

    assert UNINSTALLED not in config.ash_plugin_modules
    (message,) = _naming(warnings, "ash_plugin_modules")
    assert REMEDY in message, message
    assert "--ash-plugin-modules" in message, message


@pytest.mark.parametrize("where", WHERE)
def test_the_detect_secrets_settings_warning(where, tmp_path, warnings):
    path, repo = _config(
        tmp_path,
        where,
        {
            "scanners": {
                "detect-secrets": {
                    "enabled": True,
                    "options": {
                        "scan_settings": {
                            "version": "1.5.0",
                            "plugins_used": [{"name": "AWSKeyDetector"}],
                            "filters_used": [
                                {"path": VERIFICATION_FILTER, "min_level": 2}
                            ],
                        }
                    },
                }
            }
        },
    )

    resolve_config(config_path=path, source_dir=repo)

    (message,) = _naming(warnings, "scanners.detect-secrets.options.scan_settings")
    assert REMEDY in message, message
    assert path.name in message, message


@pytest.mark.parametrize("where", WHERE)
def test_the_honor_ignore_files_warning(where, tmp_path, warnings):
    path, repo = _config(tmp_path, where, {"honor_ignore_files": False})

    config = resolve_config(config_path=path, source_dir=repo)

    assert config.honor_ignore_files is True
    (message,) = _naming(warnings, "honor_ignore_files")
    assert REMEDY in message, message
    assert "--no-honor-ignore-files" in message, message


@pytest.mark.parametrize("where", WHERE)
def test_the_archive_limit_warning_for_a_limit_the_file_raises(
    where, tmp_path, warnings
):
    path, repo = _config(
        tmp_path,
        where,
        {"converters": {"archive": {"options": {"max_members": 10_000_000}}}},
    )

    resolve_config(config_path=path, source_dir=repo)

    (message,) = _naming(warnings, "converters.archive.options.max_members")
    assert "set by" in message, message
    assert REMEDY in message, message


def test_the_archive_limit_warning_for_a_default_it_caps(
    tmp_path, monkeypatch, warnings
):
    path, repo = _config(tmp_path, "the-scanned-checkout", {})
    operator = tmp_path / "operator" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text(
        json.dumps(
            {
                "project_name": "operator",
                "converters": {"archive": {"options": {"max_members": 2}}},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))

    resolve_config(config_path=path, source_dir=repo)

    (message,) = _naming(warnings, "converters.archive.options.max_members")
    assert "the default" in message, message
    assert REMEDY in message, message


@pytest.mark.parametrize(
    "setting, settings",
    [
        (
            "aws_region",
            {
                "reporters": {
                    "bedrock-summary-reporter": {
                        "options": {"aws_region": "repo-region-1"}
                    }
                }
            },
        ),
        (
            "scanners.bandit.options.config_file",
            {"scanners": {"bandit": {"options": {"config_file": ".ash/tool.yaml"}}}},
        ),
        (
            "tool_version",
            {"scanners": {"semgrep": {"options": {"tool_version": "==1.7.9"}}}},
        ),
        ("content_db_staleness", {"content_db_staleness": "warn"}),
    ],
    ids=["reporter-destination", "scanner-config-file", "tool-version", "staleness"],
)
@pytest.mark.parametrize("where", WHERE)
def test_the_other_confinement_warnings(where, setting, settings, tmp_path, warnings):
    path, repo = _config(tmp_path, where, settings)

    resolve_config(config_path=path, source_dir=repo)

    named = _naming(warnings, setting)
    assert named, warnings
    for message in named:
        assert REMEDY in message, message
        assert path.name in message, message


@pytest.mark.parametrize("where", ["the-workspace", "its-checkout"])
def test_a_refused_workspace_operator_config_of_the_repository_says_how(
    where, tmp_path
):
    """A workspace's operator config may not be one of the workspace's files
    (resolve_config.check_operator_config). Where the cause is the repository's
    tier, the refusal ends with the same remedy as the confinement warnings."""
    from automated_security_helper.config.confinement_remedy import KEEP_A_SETTING
    from automated_security_helper.config.resolve_config import check_operator_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    repo = tmp_path / "repo"
    mark_git_checkout(repo)
    workspace = repo / "ws"
    workspace.mkdir()
    place = workspace if where == "the-workspace" else repo / "ops"
    place.mkdir(exist_ok=True)
    config = place / "ash.yaml"
    config.write_text("project_name: p\n", encoding="utf-8")

    with pytest.raises(ASHConfigValidationError) as raised:
        check_operator_config(config, workspace)

    message = " ".join(str(raised.value).split())
    assert "Move the config, and every base it extends, outside" in message, message
    assert message.endswith(KEEP_A_SETTING), message


def test_a_refused_workspace_operator_config_an_mcp_client_delivered_does_not(
    tmp_path, monkeypatch
):
    """Control: an MCP client's file is refused for its tier, not the repository's,
    so the refusal names only the place to move it out of."""
    from automated_security_helper.config.resolve_config import check_operator_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    workspace = tmp_path / "work"
    workspace.mkdir()
    delivered = tmp_path / "mcp-workspaces" / "sess" / "upload" / "ash.yaml"
    delivered.parent.mkdir(parents=True)
    delivered.write_text("project_name: p\n", encoding="utf-8")

    with pytest.raises(ASHConfigValidationError) as raised:
        check_operator_config(delivered, workspace)

    message = str(raised.value)
    assert "delivered by an MCP client" in message, message
    assert "To keep a setting" not in message, message


def test_a_merged_shards_config_says_how_to_keep_a_setting_there():
    """``ash merge``'s own source: the same form, with the merge's options."""
    from automated_security_helper.config.untrusted_source import SHARD_RECORDED

    assert SHARD_RECORDED.remedy.startswith("To keep a setting, ")
    assert "ash merge's --config-overrides or --config" in SHARD_RECORDED.remedy
