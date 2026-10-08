# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The install hints ASH prints must reinstall the version that is running.

ASH is installed from git, and the PyPI name ``automated-security-helper`` belongs to
an unrelated third party, so every hint names the repository as a PEP 508 direct
reference. An untagged reference resolves to the default branch, which on a v4
install silently replaced ASH with an older release. These tests pin the tag to the
running ``__version__``, and patch the version to show the tag is read from it
rather than written as a literal that happens to match today.
"""

from __future__ import annotations

import pytest
from packaging.requirements import Requirement

import automated_security_helper
from automated_security_helper.core.constants import (
    ASH_REPO_URL,
    ash_extra_install_command,
    ash_git_requirement,
    ash_reinstall_command,
)


def _expected_url(version: str) -> str:
    return f"git+{ASH_REPO_URL}.git@v{version}"


def test_the_requirement_is_a_direct_reference_at_the_running_tag():
    requirement = Requirement(ash_git_requirement("symbols"))
    assert requirement.name == "automated-security-helper"
    assert requirement.extras == {"symbols"}
    assert requirement.url == _expected_url(automated_security_helper.__version__)


def test_the_requirement_without_an_extra_names_no_extra():
    requirement = Requirement(ash_git_requirement())
    assert requirement.extras == set()
    assert requirement.url == _expected_url(automated_security_helper.__version__)


@pytest.mark.parametrize(
    "build",
    [
        lambda: ash_git_requirement(),
        lambda: ash_git_requirement("symbols"),
        ash_reinstall_command,
        lambda: ash_extra_install_command("symbols"),
    ],
    ids=["requirement", "requirement-with-extra", "reinstall", "extra-install"],
)
def test_every_helper_follows_the_running_version(build, monkeypatch):
    """A version that cannot be a literal anywhere in the tree must appear in the hint."""
    monkeypatch.setattr(automated_security_helper, "__version__", "97.98.99")
    text = build()
    assert ".git@v97.98.99" in text


def test_the_commands_quote_the_requirement_for_a_shell():
    """Unquoted, `[symbols]` is a shell glob and ` @ ` splits the argument."""
    version = automated_security_helper.__version__
    assert ash_extra_install_command("symbols") == (
        f'pip install "automated-security-helper[symbols] @ {_expected_url(version)}"'
    )
    assert ash_reinstall_command() == (
        f'pip install --force-reinstall "automated-security-helper @ '
        f'{_expected_url(version)}"'
    )
