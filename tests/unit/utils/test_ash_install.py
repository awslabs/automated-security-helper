# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The requirement every install hint names resolves to the running ASH from git.

ASH is not published to PyPI, and the PyPI project with ASH's distribution name
is unrelated, so a hint that asks an index for that name installs the wrong
project. ``ash_git_requirement`` is the one place the hints get their
requirement from; these tests pin its shape, its version pin, and that each
hint built on it passes the same bare-name matcher the repository gate uses.
"""

from __future__ import annotations

import re

import pytest

from automated_security_helper.core.constants import ASH_REPO_URL
from automated_security_helper.utils import ash_install
from automated_security_helper.utils.ash_install import ash_git_requirement
from automated_security_helper.utils.get_ash_version import get_ash_version
from tests.utils.bare_install_names import find_bare_installs


def test_without_an_extra_it_is_the_git_url_pinned_to_the_running_version():
    assert ash_git_requirement() == f"git+{ASH_REPO_URL}.git@v{get_ash_version()}"


def test_with_an_extra_it_is_a_direct_reference_to_the_same_url():
    assert ash_git_requirement("symbols") == (
        f"automated-security-helper[symbols] @ git+{ASH_REPO_URL}.git"
        f"@v{get_ash_version()}"
    )


def test_the_pin_follows_the_running_version(monkeypatch):
    """The ref comes from the package version, not from ASH_REPO_LATEST_REVISION.

    In a local checkout that constant holds the checked-out branch name, which
    is not a ref a user's installer can fetch.
    """
    monkeypatch.setattr(ash_install, "get_ash_version", lambda: "3.9.1")
    assert ash_git_requirement().endswith(".git@v3.9.1")
    assert ash_git_requirement("cdk").endswith(".git@v3.9.1")


def test_an_unknown_version_gives_the_url_without_a_ref(monkeypatch):
    """get_version() returns "unknown" when it cannot read a version.

    There is no tag ``vunknown``, so pinning to it would make every hint an
    install that fails; the unpinned URL installs the default branch instead.
    """
    monkeypatch.setattr(ash_install, "get_ash_version", lambda: "unknown")
    assert ash_git_requirement() == f"git+{ASH_REPO_URL}.git"
    assert ash_git_requirement("symbols") == (
        f"automated-security-helper[symbols] @ git+{ASH_REPO_URL}.git"
    )


@pytest.mark.parametrize("extra", [None, "symbols", "cdk"])
@pytest.mark.parametrize(
    "template",
    [
        "pip install '{}'",
        "pip install --force-reinstall '{}'",
        "pipx install '{}'",
        "uv tool install '{}'",
        "uvx --from '{}' ash --help",
    ],
)
def test_every_installer_form_resolves_to_ash(template, extra):
    command = template.format(ash_git_requirement(extra))
    assert find_bare_installs(command) == [], command


def test_the_symbols_hints_share_one_install_command():
    """The scan warning and the config lint take their command from one function."""
    from automated_security_helper.utils.symbol_spans import (
        SYMBOLS_EXTRA,
        symbols_extra_install_command,
    )

    command = symbols_extra_install_command()
    assert command == f"pip install '{ash_git_requirement(SYMBOLS_EXTRA)}'"
    assert find_bare_installs(command) == []


def test_the_mcp_reinstall_hint_is_pinned_and_on_one_line(capsys, monkeypatch):
    """``ash mcp`` without its dependencies prints a reinstall that resolves to ASH.

    stderr is usually not a terminal when an MCP client runs the server, and
    rich wraps non-terminal output at 80 columns. A wrap between
    ``--force-reinstall`` and the URL leaves a pip command with no requirement
    on the first line, so the whole command has to stay on one line.
    """
    import typer
    from unittest.mock import patch

    from automated_security_helper.cli.mcp import mcp_command

    # The width rich uses when stderr is not a terminal, set explicitly so the
    # result does not depend on the terminal the tests run in.
    monkeypatch.setenv("COLUMNS", "80")
    with patch(
        "automated_security_helper.cli.mcp.validate_mcp_dependencies",
        return_value=False,
    ):
        with pytest.raises(typer.Exit):
            mcp_command(_Context())

    # FORCE_COLOR in the environment makes rich emit color codes, which sit
    # between the words of the command; the text a user reads is what is checked.
    err = re.sub(r"\x1b\[[0-9;]*m", "", capsys.readouterr().err)
    reinstall = [line for line in err.splitlines() if "force-reinstall" in line]
    assert len(reinstall) == 1, err
    assert find_bare_installs(reinstall[0]) == [], reinstall[0]
    pinned = re.escape(f"git+{ASH_REPO_URL}.git@v{get_ash_version()}")
    assert re.search(rf"--force-reinstall '{pinned}'", reinstall[0]), reinstall[0]


class _Context:
    """The one attribute of typer's context that ``mcp_command`` reads first."""

    resilient_parsing = False
