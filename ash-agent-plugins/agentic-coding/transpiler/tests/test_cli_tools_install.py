"""Install commands check a pinned digest before they unpack what they download.

goose's and cursor's commands used to pipe a vendor install script into bash.
That ran a remote script with nothing checked. goose's script also falls back to
the latest release when the pinned download fails, so CI could validate against a
version cli_versions.json does not name.
"""

from __future__ import annotations

import re

import pytest

from transpiler.cli_tools import ALL_CLI_TOOLS, CLI_CURSOR, CLI_GOOSE

_VERIFY = re.compile(r"echo '([0-9a-f]{64})  (\S+)' \| sha256sum -c -")


@pytest.mark.parametrize("tool", ALL_CLI_TOOLS, ids=lambda t: t.name)
def test_no_install_command_pipes_a_download_into_a_shell(tool):
    assert not re.search(r"\|\s*(ba)?sh\b", tool.install_cmd), tool.install_cmd


@pytest.mark.parametrize("tool", (CLI_GOOSE, CLI_CURSOR), ids=lambda t: t.name)
def test_install_verifies_a_pinned_digest_before_extracting(tool):
    cmd = tool.install_cmd
    match = _VERIFY.search(cmd)
    assert match, cmd
    archive = match.group(2)
    # The checked file is the one curl wrote and the one tar reads, the check
    # comes between them, and && joins it so a mismatch stops the install.
    assert f"-o {archive} " in cmd
    assert re.search(rf"tar [^&]*-xzf {re.escape(archive)} ", cmd)
    assert cmd.index("curl ") < match.start() < cmd.index("tar ")
    assert cmd[match.end() :].lstrip().startswith("&&")


def test_goose_install_names_the_pinned_release():
    assert "/releases/download/v1.33.1/" in CLI_GOOSE.install_cmd
    assert "download_cli.sh" not in CLI_GOOSE.install_cmd
