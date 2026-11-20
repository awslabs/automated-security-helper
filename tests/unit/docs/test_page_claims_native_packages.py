# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Claims of three native-package pages that no claims test, runnable block or inventory held.

The pages are docs/native-packages/index.md, msix.md and winget.md. (chocolatey.md and
flatpak.md are pinned in test_page_claims.py.) Each test follows the pattern of
test_page_claims.py in two halves: ``assert_on_page`` checks that the sentence is still
on its page, and the test then reads the packaging sources or pyproject.toml that make
it true. A test goes red when either half moves.

What each page has pinned:

- index: the command every native package puts on PATH and the two other names that come
  with it, read from ``[project.scripts]``, and the four files a release attaches, read
  from ``packaging/release-assets.py``.
- msix: the three app execution aliases and the absence of an ``ash`` alias, read from
  ``packaging/msix/AppxManifest.xml``.
- winget: the package identifier and the moniker, read from the three manifests in
  ``packaging/winget``.

Not pinned: what a Windows machine does with the package, which the packaging workflow
runs on Windows.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.unit.docs.test_page_claims import _install_project, assert_on_page

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
INDEX_PAGE = "docs/native-packages/index.md"
MSIX_PAGE = "docs/native-packages/msix.md"
WINGET_PAGE = "docs/native-packages/winget.md"
PACKAGING = REPO_ROOT / "packaging"


def _scripts() -> dict[str, str]:
    return _install_project()["scripts"]


def test_every_native_package_puts_ashx_on_the_path_with_two_other_names() -> None:
    """index.md (The command is `ashx`)."""
    assert_on_page(
        INDEX_PAGE,
        "Every native package puts `ashx` on your `PATH` (the Flatpak runs it inside its "
        "sandbox; see that page). Two other names come with it:",
    )
    assert_on_page(INDEX_PAGE, "- `ashv3` is deprecated.")
    assert_on_page(
        INDEX_PAGE,
        "- `automated-security-helper` is kept indefinitely and is silent.",
    )
    scripts = _scripts()
    assert {"ashx", "ashv3", "automated-security-helper"} <= set(scripts), scripts
    # ashv3 is the one that warns; the other two run the app as it is.
    assert scripts["ashv3"].endswith(":main_ashv3"), scripts["ashv3"]
    assert scripts["ashx"] == scripts["automated-security-helper"], scripts


def test_the_release_attaches_the_four_native_package_files() -> None:
    """index.md (Publication status)."""
    assert_on_page(
        INDEX_PAGE,
        "A GitHub release attaches each of them as a file: the `.msix`, the `.nupkg`, "
        "the Flatpak bundle and a winget manifest set rendered for that `.msix`",
    )
    source = (PACKAGING / "release-assets.py").read_text(encoding="utf-8")
    keys = set(re.findall(r'key="([a-z0-9-]+)"', source))
    assert {"msix", "nupkg", "flatpak", "winget"} <= keys, sorted(keys)


def test_the_msix_registers_three_aliases_and_no_ash() -> None:
    """msix.md (Run it) and winget.md (Run it): the same alias claim, one source."""
    assert_on_page(
        MSIX_PAGE,
        "The package registers three app execution aliases: `ashx`, the deprecated "
        "`ashv3`, and `automated-security-helper`. It does not register `ash`.",
    )
    assert_on_page(
        WINGET_PAGE,
        "The installed commands are the MSIX's app execution aliases: `ashx`, the "
        "deprecated `ashv3`, and `automated-security-helper`. No `ash` command is "
        "installed",
    )
    manifest = (PACKAGING / "msix" / "AppxManifest.xml").read_text(encoding="utf-8")
    aliases = re.findall(r'<uap5:ExecutionAlias Alias="([^"]+)"', manifest)
    assert sorted(aliases) == [
        "ashv3.exe",
        "ashx.exe",
        "automated-security-helper.exe",
    ], aliases


def test_the_winget_page_names_the_identifier_and_moniker_the_manifests_carry() -> None:
    """winget.md (the opening paragraph)."""
    assert_on_page(
        WINGET_PAGE,
        "The winget package identifier is `Amazon.AutomatedSecurityHelper` and its "
        "moniker is `ash`.",
    )
    texts = [
        path.read_text(encoding="utf-8")
        for path in sorted(
            (PACKAGING / "winget").glob("Amazon.AutomatedSecurityHelper*.yaml")
        )
    ]
    assert len(texts) == 3, len(texts)
    for text in texts:
        assert re.search(
            r"^PackageIdentifier: Amazon\.AutomatedSecurityHelper$", text, re.MULTILINE
        ), text[:200]
    assert any(re.search(r"^Moniker: ash$", text, re.MULTILINE) for text in texts), (
        "no manifest carries Moniker: ash"
    )
