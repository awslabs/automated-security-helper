# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every install hint names an install that resolves to the ASH that is running.

Why this file exists
--------------------
ASH is not published to PyPI, and the PyPI project with ASH's distribution name
is unrelated, so a hint that asks an index for that name installs the wrong
project. The first fix pinned every hint to the git tag ``v<version>``. That is
wrong on every build between releases: main reports 3.7.0 while its tree has
moved on, and ``v3.7.0`` has no ``symbols`` extra at all, so the symbols hint
asked for an extra the tag does not define and the reinstall hints downgraded
a main install to the release.

What the hints name now
-----------------------
* The symbols hint names the extra's packages, read from the running
  distribution's own metadata, so it cannot disagree with the installed ASH.
* The reinstall hints name where the running ASH was installed from, as the
  installer recorded it in the PEP 610 ``direct_url.json``: the commit of a git
  install, the directory of an editable or local install, the archive of an
  archive install. Only an install with no record falls back to the release tag
  of its version, and an unknown version to the repository without a ref.

``ash_install._direct_url`` is the one seam the shape tests replace; every
other step, including the quoting and the extra, runs for real.
"""

from __future__ import annotations

import json
import re
import shlex
from importlib.metadata import distribution
from pathlib import Path
from unittest.mock import patch
from urllib.request import url2pathname

import pytest
import typer

from automated_security_helper.core.constants import ASH_DOCS_URL, ASH_REPO_URL
from automated_security_helper.utils import ash_install
from automated_security_helper.utils.get_ash_version import get_ash_version
from tests.utils.bare_install_names import find_bare_installs, normalize

REPO_ROOT = Path(__file__).resolve().parents[3]
COMMIT = "0123456789abcdef0123456789abcdef01234567"
GIT_INSTALL = {
    "url": "https://github.com/awslabs/automated-security-helper.git",
    "vcs_info": {"vcs": "git", "commit_id": COMMIT, "requested_revision": "main"},
}
EDITABLE_INSTALL = {
    "url": Path("/work/automated-security-helper").as_uri(),
    "dir_info": {"editable": True},
}
LOCAL_DIRECTORY_INSTALL = {"url": Path("/src").as_uri(), "dir_info": {}}
LOCAL_WHEEL_INSTALL = {
    "url": Path("/ash/automated_security_helper-3.7.0-py3-none-any.whl").as_uri(),
    "archive_info": {},
}
REMOTE_WHEEL_INSTALL = {
    "url": "https://example.invalid/automated_security_helper-3.7.0-py3-none-any.whl",
    "archive_info": {},
}


def _origin(monkeypatch, direct_url, version=None):
    monkeypatch.setattr(ash_install, "_direct_url", lambda: direct_url)
    if version is not None:
        monkeypatch.setattr(ash_install, "get_ash_version", lambda: version)


def _words(command: str) -> list[str]:
    return shlex.split(command)


class TestReinstallNamesWhereThisAshCameFrom:
    def test_a_git_install_is_pinned_to_its_commit(self, monkeypatch):
        _origin(monkeypatch, GIT_INSTALL, version="3.7.0")
        command = ash_install.ash_reinstall_command()
        assert _words(command) == [
            "pip",
            "install",
            "--force-reinstall",
            f"git+{GIT_INSTALL['url']}@{COMMIT}",
        ]
        assert "@v3.7.0" not in command

    def test_a_git_install_keeps_its_subdirectory(self, monkeypatch):
        _origin(monkeypatch, {**GIT_INSTALL, "subdirectory": "pkg"})
        assert _words(ash_install.ash_install_arguments())[-1].endswith(
            f"@{COMMIT}#subdirectory=pkg"
        )

    def test_credentials_in_a_recorded_url_are_not_repeated(self, monkeypatch):
        """PEP 610 tells installers to strip them; a hint must not depend on that."""
        _origin(
            monkeypatch,
            {**GIT_INSTALL, "url": "https://user:token@github.example/ash.git"},
        )
        command = ash_install.ash_reinstall_command()
        assert "token" not in command and "user" not in command, command
        assert f"git+https://github.example/ash.git@{COMMIT}" in command

    def test_an_editable_install_names_its_directory(self, monkeypatch):
        _origin(monkeypatch, EDITABLE_INSTALL, version="3.7.0")
        assert _words(ash_install.ash_reinstall_command()) == [
            "pip",
            "install",
            "--force-reinstall",
            "-e",
            str(Path("/work/automated-security-helper")),
        ]

    def test_a_local_directory_install_names_its_directory(self, monkeypatch):
        _origin(monkeypatch, LOCAL_DIRECTORY_INSTALL, version="3.7.0")
        assert _words(ash_install.ash_install_arguments()) == [str(Path("/src"))]

    def test_a_local_archive_install_names_its_archive(self, monkeypatch):
        _origin(monkeypatch, LOCAL_WHEEL_INSTALL, version="3.7.0")
        assert _words(ash_install.ash_install_arguments()) == [
            str(Path("/ash/automated_security_helper-3.7.0-py3-none-any.whl"))
        ]

    def test_a_remote_archive_install_names_its_url(self, monkeypatch):
        _origin(monkeypatch, REMOTE_WHEEL_INSTALL, version="3.7.0")
        assert _words(ash_install.ash_install_arguments()) == [
            REMOTE_WHEEL_INSTALL["url"]
        ]

    def test_an_install_with_no_record_falls_back_to_the_release_tag(self, monkeypatch):
        _origin(monkeypatch, None, version="3.9.1")
        assert _words(ash_install.ash_install_arguments()) == [
            f"git+{ASH_REPO_URL}.git@v3.9.1"
        ]

    def test_an_unknown_version_with_no_record_names_no_ref(self, monkeypatch):
        """get_version() returns "unknown" when it cannot read a version.

        There is no tag ``vunknown``; the URL without a ref installs the default
        branch, which is the closest working install there is.
        """
        _origin(monkeypatch, None, version="unknown")
        assert _words(ash_install.ash_install_arguments()) == [
            f"git+{ASH_REPO_URL}.git"
        ]

    @pytest.mark.parametrize(
        "record",
        [
            {"url": "https://example.invalid/x", "vcs_info": {"vcs": "git"}},
            {"url": 7, "dir_info": {}},
            {"dir_info": {"editable": True}},
            {"url": "https://example.invalid/dir", "dir_info": {}},
            ["not", "a", "mapping"],
        ],
        ids=["vcs-without-commit", "url-not-a-string", "no-url", "remote-dir", "list"],
    )
    def test_an_unusable_record_falls_back_to_the_release_tag(
        self, monkeypatch, record
    ):
        _origin(monkeypatch, record, version="3.9.1")
        assert _words(ash_install.ash_install_arguments()) == [
            f"git+{ASH_REPO_URL}.git@v3.9.1"
        ]


class TestAnExtraGoesOnTheSameSource:
    @pytest.mark.parametrize(
        "record, expected",
        [
            (
                GIT_INSTALL,
                [f"automated-security-helper[cdk] @ git+{GIT_INSTALL['url']}@{COMMIT}"],
            ),
            (
                EDITABLE_INSTALL,
                ["-e", f"{Path('/work/automated-security-helper')}[cdk]"],
            ),
            (LOCAL_DIRECTORY_INSTALL, [f"{Path('/src')}[cdk]"]),
            (
                REMOTE_WHEEL_INSTALL,
                [f"automated-security-helper[cdk] @ {REMOTE_WHEEL_INSTALL['url']}"],
            ),
            (
                None,
                [f"automated-security-helper[cdk] @ git+{ASH_REPO_URL}.git@v3.9.1"],
            ),
        ],
        ids=["git", "editable", "local-directory", "remote-archive", "no-record"],
    )
    def test_each_source_takes_the_extra(self, monkeypatch, record, expected):
        _origin(monkeypatch, record, version="3.9.1")
        arguments = ash_install.ash_install_arguments("cdk")
        assert _words(arguments) == expected
        assert find_bare_installs(f"pip install {arguments}") == []


@pytest.mark.parametrize(
    "record",
    [
        GIT_INSTALL,
        EDITABLE_INSTALL,
        LOCAL_DIRECTORY_INSTALL,
        REMOTE_WHEEL_INSTALL,
        None,
    ],
    ids=["git", "editable", "local-directory", "remote-archive", "no-record"],
)
@pytest.mark.parametrize(
    "template",
    [
        "pip install {}",
        "pip install --force-reinstall {}",
        "pipx install {}",
        "uv tool install {}",
    ],
)
def test_every_installer_form_resolves_to_ash(monkeypatch, record, template):
    _origin(monkeypatch, record, version="3.7.0")
    for extra in (None, "symbols"):
        command = template.format(ash_install.ash_install_arguments(extra))
        assert find_bare_installs(command) == [], command


def test_this_installation_is_reinstalled_from_its_own_record():
    """The real environment, read without the seam.

    The test suite runs from an installed checkout, so the distribution carries a
    direct_url.json. Whatever it records, the hint must name it and must not
    fall back to the release tag, which on main names an older tree.
    """
    raw = distribution("automated-security-helper").read_text("direct_url.json")
    assert raw, "the suite is expected to run from an installed checkout"
    record = json.loads(raw)
    command = ash_install.ash_reinstall_command()
    assert f"@v{get_ash_version()}" not in command, command
    if "vcs_info" in record:
        expected = record["vcs_info"]["commit_id"]
    else:
        expected = str(Path(url2pathname(record["url"].removeprefix("file://"))))
    assert any(expected in word for word in _words(command)), (expected, command)


class TestExtraRequirementsFromMetadata:
    def test_the_symbols_extra_is_read_from_this_distribution(self):
        declared = ash_install.extra_requirements_from_metadata("symbols")
        assert declared, "the symbols extra could not be read from metadata"
        names = {normalize(re.match(r"[A-Za-z0-9._-]+", r).group(0)) for r in declared}
        assert "tree-sitter" in names and "tree-sitter-python" in names, declared
        assert all(";" not in r for r in declared), declared

    def test_the_cdk_scanner_reads_its_extra_through_the_same_function(self):
        from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
            _cdk_extra_requirements_from_metadata,
        )

        assert _cdk_extra_requirements_from_metadata() == (
            ash_install.extra_requirements_from_metadata("cdk")
        )

    def test_an_extra_no_distribution_declares_reads_as_none(self):
        assert ash_install.extra_requirements_from_metadata("no-such-extra") is None

    def test_an_extra_name_is_matched_whole(self):
        """``extra == 'cdk'`` must not be read as part of ``extra == 'cdk2'``."""
        with patch.object(
            ash_install,
            "requires",
            return_value=[
                "a>=1; extra == 'cdk2'",
                'b>=1; extra == "cdk"',
                "c>=1; extra=='cdk'",
            ],
        ):
            assert ash_install.extra_requirements_from_metadata("cdk") == [
                "b>=1",
                "c>=1",
            ]


class TestTheSymbolsHint:
    def test_it_names_the_packages_of_the_installed_extra(self, monkeypatch):
        """No tag, no ASH name: v3.7.0 has no symbols extra, main reports 3.7.0."""
        from automated_security_helper.utils.symbol_spans import (
            SYMBOLS_EXTRA,
            symbols_extra_install_command,
        )

        _origin(monkeypatch, None, version="3.7.0")
        command = symbols_extra_install_command()
        declared = ash_install.extra_requirements_from_metadata(SYMBOLS_EXTRA)
        assert _words(command)[:2] == ["pip", "install"]
        assert _words(command)[2:] == declared, command
        assert "automated-security-helper" not in command
        assert "@v" not in command
        assert find_bare_installs(command) == []

    def test_without_readable_metadata_it_falls_back_to_this_install(self, monkeypatch):
        from automated_security_helper.utils.symbol_spans import (
            symbols_extra_install_command,
        )

        _origin(monkeypatch, GIT_INSTALL)
        monkeypatch.setattr(
            ash_install, "extra_requirements_from_metadata", lambda extra: None
        )
        assert _words(symbols_extra_install_command()) == [
            "pip",
            "install",
            f"automated-security-helper[symbols] @ git+{GIT_INSTALL['url']}@{COMMIT}",
        ]

    def test_it_points_at_the_docs_for_other_installers(self, monkeypatch):
        """pip is one installer; uv tool, pipx and uvx users need the docs page."""
        from automated_security_helper.utils.symbol_spans import (
            symbols_extra_install_command,
            symbols_extra_install_hint,
        )

        url = f"{ASH_DOCS_URL}/docs/suppressions/#installing-the-extra"
        hint = symbols_extra_install_hint()
        assert url in hint, hint
        assert f"`{symbols_extra_install_command()}`" in hint, hint
        assert find_bare_installs(hint) == []
        page = REPO_ROOT / "docs" / "content" / "docs" / "suppressions.md"
        assert "\n### Installing the extra\n" in page.read_text(encoding="utf-8")


def _name_and_clauses(requirement: str) -> tuple[str, frozenset[str]]:
    """A requirement as its normalized name and its unordered specifier clauses.

    importlib.metadata reorders clauses: ``>=0.26,<0.27`` comes back as
    ``<0.27,>=0.26``.
    """
    name = re.match(r"[A-Za-z0-9._-]+", requirement).group(0)
    clauses = requirement[len(name) :].split(",")
    return normalize(name), frozenset(c.strip() for c in clauses if c.strip())


def test_the_suppressions_page_lists_the_packages_of_the_extra():
    """The docs page's pip command installs what the metadata declares.

    It is a copy of the extra, so it is checked against the running
    distribution's metadata rather than trusted to stay current.
    """
    page = REPO_ROOT / "docs" / "content" / "docs" / "suppressions.md"
    text = page.read_text(encoding="utf-8")
    section = text.split("### Installing the extra", 1)[1].split("\n### ", 1)[0]
    pip_lines = [
        line for line in section.splitlines() if line.startswith("pip install ")
    ]
    assert len(pip_lines) == 1, pip_lines
    documented = {_name_and_clauses(r) for r in shlex.split(pip_lines[0])[2:]}
    declared = ash_install.extra_requirements_from_metadata("symbols")
    assert declared, "the symbols extra could not be read from metadata"
    assert documented == {_name_and_clauses(r) for r in declared}


def test_the_mcp_reinstall_hint_names_this_install_on_one_line(capsys, monkeypatch):
    """``ash mcp`` without its dependencies prints a reinstall that resolves to ASH.

    stderr is usually not a terminal when an MCP client runs the server, and
    rich wraps non-terminal output at 80 columns. A wrap between
    ``--force-reinstall`` and the source leaves a pip command with no
    requirement on the first line, so the whole command has to stay on one line.
    """
    from automated_security_helper.cli.mcp import mcp_command

    _origin(monkeypatch, GIT_INSTALL)
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
    assert _words(reinstall[0]) == [
        "pip",
        "install",
        "--force-reinstall",
        f"git+{GIT_INSTALL['url']}@{COMMIT}",
    ], reinstall[0]


class _Context:
    """The one attribute of typer's context that ``mcp_command`` reads first."""

    resilient_parsing = False
