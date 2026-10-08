# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The install hints ASH prints must reinstall the version that is running.

ASH is installed from git, and the PyPI name ``automated-security-helper`` belongs to
an unrelated third party, so every hint names the repository as a PEP 508 direct
reference. An untagged reference resolves to the default branch, which on a v4
install silently replaced ASH with an older release. These tests pin the tag to the
running ``__version__``, and patch the version to show the tag is read from it
rather than written as a literal that happens to match today.

Two more properties are pinned here. A version ASH cannot read ("unknown") must not
become a ``@vunknown`` tag; the hint falls back to the untagged URL and says so. And
the commands run pip through the interpreter that is running ASH, because inside the
MSIX, Chocolatey and Flatpak packages ASH lives in its own virtualenv and a bare
``pip`` reaches some other environment.
"""

from __future__ import annotations

import sys

import pytest
from packaging.requirements import Requirement

import automated_security_helper
from automated_security_helper.core import constants
from automated_security_helper.core.constants import (
    ASH_REPO_URL,
    UNPINNED_INSTALL_NOTE,
    ash_extra_install_command,
    ash_git_requirement,
    ash_reinstall_command,
)

_COMMANDS = [
    lambda: ash_git_requirement(),
    lambda: ash_git_requirement("symbols"),
    ash_reinstall_command,
    lambda: ash_extra_install_command("symbols"),
]
_IDS = ["requirement", "requirement-with-extra", "reinstall", "extra-install"]


def _expected_url(version: str) -> str:
    return f"git+{ASH_REPO_URL}.git@v{version}"


@pytest.fixture
def venv_python(monkeypatch):
    path = "/opt/ash/venv/bin/python3"
    monkeypatch.setattr(sys, "executable", path)
    return path


def test_the_requirement_is_a_direct_reference_at_the_running_tag():
    requirement = Requirement(ash_git_requirement("symbols"))
    assert requirement.name == "automated-security-helper"
    assert requirement.extras == {"symbols"}
    assert requirement.url == _expected_url(automated_security_helper.__version__)


def test_the_requirement_without_an_extra_names_no_extra():
    requirement = Requirement(ash_git_requirement())
    assert requirement.extras == set()
    assert requirement.url == _expected_url(automated_security_helper.__version__)


@pytest.mark.parametrize("build", _COMMANDS, ids=_IDS)
def test_every_helper_follows_the_running_version(build, monkeypatch):
    """A version that cannot be a literal anywhere in the tree must appear in the hint."""
    monkeypatch.setattr(automated_security_helper, "__version__", "97.98.99")
    text = build()
    assert ".git@v97.98.99" in text
    assert UNPINNED_INSTALL_NOTE not in text


@pytest.mark.parametrize("unreadable", ["unknown", "", None])
@pytest.mark.parametrize("build", _COMMANDS, ids=_IDS)
def test_an_unreadable_version_falls_back_to_the_untagged_url(
    build, unreadable, monkeypatch
):
    monkeypatch.setattr(automated_security_helper, "__version__", unreadable)
    text = build()
    assert "@vunknown" not in text
    assert "@v" not in text.split("git+", 1)[1].split('"', 1)[0]
    assert f"git+{ASH_REPO_URL}.git" in text


@pytest.mark.parametrize("build", _COMMANDS[2:], ids=_IDS[2:])
def test_an_unpinned_command_says_it_is_unpinned(build, monkeypatch):
    monkeypatch.setattr(automated_security_helper, "__version__", "unknown")
    assert build().endswith(UNPINNED_INSTALL_NOTE)


def test_the_unpinned_requirement_still_parses(monkeypatch):
    """The bare requirement carries no note, so it stays a valid PEP 508 string."""
    monkeypatch.setattr(automated_security_helper, "__version__", "unknown")
    requirement = Requirement(ash_git_requirement("symbols"))
    assert requirement.url == f"git+{ASH_REPO_URL}.git"


def test_the_commands_run_pip_through_the_running_interpreter(venv_python):
    """Quoted requirement, interpreter first: `<venv python> -m pip install "..."`."""
    version = automated_security_helper.__version__
    assert ash_extra_install_command("symbols") == (
        f"{venv_python} -m pip install "
        f'"automated-security-helper[symbols] @ {_expected_url(version)}"'
    )
    assert ash_reinstall_command() == (
        f"{venv_python} -m pip install --force-reinstall "
        f'"automated-security-helper @ {_expected_url(version)}"'
    )


@pytest.mark.parametrize(
    "executable, expected",
    [
        ("/opt/ash/venv/bin/python3", "/opt/ash/venv/bin/python3"),
        (
            r"C:\ProgramData\ash\venv\Scripts\python.exe",
            r"C:\ProgramData\ash\venv\Scripts\python.exe",
        ),
        (
            r"C:\Users\Jane Doe\AppData\Local\ash\venv\Scripts\python.exe",
            r'"C:\Users\Jane Doe\AppData\Local\ash\venv\Scripts\python.exe"',
        ),
        ("", "python"),
    ],
    ids=["posix", "windows", "windows-with-space", "no-executable"],
)
def test_the_interpreter_path_is_quoted_only_when_it_needs_to_be(
    executable, expected, monkeypatch
):
    monkeypatch.setattr(sys, "executable", executable)
    assert constants._running_python() == expected
    assert ash_reinstall_command().startswith(f"{expected} -m pip install ")


def test_no_command_calls_a_bare_pip(venv_python):
    for command in (ash_reinstall_command(), ash_extra_install_command("symbols")):
        assert not command.startswith("pip ")
        assert command.startswith(f"{venv_python} -m pip ")
