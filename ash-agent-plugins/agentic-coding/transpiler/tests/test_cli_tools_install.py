"""Install commands check a pinned digest before they unpack what they download.

goose's and cursor's commands used to pipe a vendor install script into bash,
which ran a remote script with nothing checked. goose's script also falls back to
the latest release when the pinned download fails. q's and kiro-cli's commands
fetched a `latest/` zip and ran its install.sh, also unchecked, at whatever
version `latest/` held that day.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from transpiler.cli_tools import (
    ALL_CLI_TOOLS,
    CLI_CURSOR,
    CLI_GOOSE,
    CLI_KIRO_CLI,
    CLI_Q,
)

_VERIFY = re.compile(r"echo '([0-9a-f]{64})  (\S+)' \| sha256sum -c -")
_DOWNLOADING = (CLI_GOOSE, CLI_CURSOR, CLI_Q, CLI_KIRO_CLI)
_CLI_VERSIONS = Path(__file__).resolve().parents[1] / "_base" / "cli_versions.json"


@pytest.mark.parametrize("tool", ALL_CLI_TOOLS, ids=lambda t: t.name)
def test_no_install_command_pipes_a_download_into_a_shell(tool):
    assert not re.search(r"\|\s*(ba)?sh\b", tool.install_cmd), tool.install_cmd


@pytest.mark.parametrize("tool", ALL_CLI_TOOLS, ids=lambda t: t.name)
def test_no_install_command_fetches_a_moving_latest_url(tool):
    assert "/latest/" not in tool.install_cmd, tool.install_cmd


@pytest.mark.parametrize("tool", _DOWNLOADING, ids=lambda t: t.name)
def test_install_verifies_a_pinned_digest_before_extracting(tool):
    cmd = tool.install_cmd
    match = _VERIFY.search(cmd)
    assert match, cmd
    archive = match.group(2)
    extract = re.search(rf"(tar [^&]*-xzf |unzip [^&]*?){re.escape(archive)}( |$)", cmd)
    assert extract, cmd
    # The checked file is the one curl wrote and the one that gets unpacked, the
    # check comes between them, and && joins it so a mismatch stops the install.
    assert f"-o {archive} " in cmd
    assert cmd.index("curl ") < match.start() < extract.start()
    assert cmd[match.end() :].lstrip().startswith("&&")


def test_goose_install_names_the_pinned_release():
    assert "/releases/download/v1.33.1/" in CLI_GOOSE.install_cmd
    assert "download_cli.sh" not in CLI_GOOSE.install_cmd


def test_q_and_kiro_cli_share_one_pin_that_matches_the_archive_they_fetch():
    pins = json.loads(_CLI_VERSIONS.read_text())
    # q was renamed kiro-cli: one entry is the source of truth for both.
    assert "q" not in pins
    assert CLI_Q.resolved_pin_key() == CLI_KIRO_CLI.resolved_pin_key() == "kiro-cli"
    version = re.search(r"/(\d+\.\d+)\.\d+/kirocli-", CLI_KIRO_CLI.install_cmd)
    assert version, CLI_KIRO_CLI.install_cmd
    assert pins["kiro-cli"] == version.group(1)
    assert CLI_Q.install_cmd.startswith(CLI_KIRO_CLI.install_cmd)
