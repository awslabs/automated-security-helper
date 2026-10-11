# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The requirement that installs this ASH, for the hints that tell users how.

ASH installs from git and is not published to PyPI. On PyPI the distribution
name ``automated-security-helper`` belongs to an unrelated placeholder project
whose version number outranks every ASH release, so any install that asks an
index for that name, with or without an extra, gets that project instead of
ASH. Every message that tells a user how to install, reinstall or extend ASH
builds its requirement with :func:`ash_git_requirement`, so all of them name
the same git source and the same version.
"""

from __future__ import annotations

from typing import Optional

from automated_security_helper.core.constants import ASH_REPO_URL
from automated_security_helper.utils.get_ash_version import get_ash_version

#: ASH's distribution name. Only meaningful with a git reference after it.
ASH_DISTRIBUTION_NAME = "automated-security-helper"


def ash_git_requirement(extra: Optional[str] = None) -> str:
    """A requirement that installs the running ASH version from its git repository.

    Returns ``git+<repo>.git@v<version>``. When ``extra`` is given it returns
    the PEP 508 direct reference
    ``automated-security-helper[<extra>] @ git+<repo>.git@v<version>``
    instead: an extra can only be requested on a named requirement, and the git
    URL after the ``@`` is what keeps an installer from looking the name up on
    an index. Either form works with ``pip install``, ``pipx install``,
    ``uv tool install`` and ``uvx --from``.

    The ref is the release tag of the running version (releases are tagged
    ``v<version>``), so the install matches what the user already runs. It is
    not ``ASH_REPO_LATEST_REVISION``, which in a local checkout holds the branch
    name. When the version cannot be determined the URL carries no ref and
    installs the repository's default branch, which is the closest working
    install there is.
    """
    version = get_ash_version()
    # get_version() falls back to the literal "unknown" when neither package
    # metadata nor pyproject.toml is readable, and there is no tag "vunknown".
    ref = "" if version == "unknown" else f"@v{version}"
    source = f"git+{ASH_REPO_URL}.git{ref}"
    if extra is None:
        return source
    return f"{ASH_DISTRIBUTION_NAME}[{extra}] @ {source}"
