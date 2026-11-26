# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""cdxgen's pin, the license read behind its register row, and the install paths.

cdxgen is pinned in the scanner module (``CDXGEN_VERSION``) and installed from
npm, so no shared download table carries it. These tests hold the places that
restate the pin to the module's value, and hold the documentation's statement
about the container image to the Dockerfile, so a version bump or an image change
that forgets one of them fails here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_cdxgen_plugins.cdxgen_scanner import (
    CDXGEN_NPM_PACKAGE,
    CDXGEN_VERSION,
    LICENSE_CITATION,
    CdxgenScanner,
)
from automated_security_helper.utils.tool_downloads import THIRD_PARTY_LICENSES

from .test_cdxgen_scanner_behavior import _scanner

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[4]
DOCS_PAGE = (
    REPO_ROOT / "docs" / "content" / "docs" / "plugins" / "alpha" / "cdxgen-plugin.md"
)
PLUGIN_README = (
    REPO_ROOT
    / "automated_security_helper"
    / "plugin_modules"
    / "ash_cdxgen_plugins"
    / "README.md"
)
DOCKERFILE = REPO_ROOT / "Dockerfile"

INSTALL_LINE = f"npm install -g {CDXGEN_NPM_PACKAGE}@{CDXGEN_VERSION}"
CITATION_HEAD = (
    "Apache-2.0 (source: the LICENSE file and package.json of the "
    f"{CDXGEN_NPM_PACKAGE} {CDXGEN_VERSION} npm package"
)


def _prose(path: Path) -> str:
    """The file's text with every run of whitespace read as one space."""
    return " ".join(path.read_text(encoding="utf-8").split())


def test_the_register_cites_the_license_read_at_the_pinned_release():
    citation = CdxgenScanner.operational_facets.provenance.upstream_license
    assert citation == LICENSE_CITATION
    assert citation.startswith(CITATION_HEAD), citation
    # The LICENSE file's digest and the commit the release tag names.
    assert re.search(r"\b[0-9a-f]{64}\b", citation), citation
    assert re.search(r"\b[0-9a-f]{40}\b", citation), citation
    assert f"v{CDXGEN_VERSION} tag" in citation


def test_a_citation_of_another_release_fails_the_check():
    """Negative control for the check above."""
    other = LICENSE_CITATION.replace(CDXGEN_VERSION, "12.9.1")
    assert not other.startswith(CITATION_HEAD)


@pytest.mark.parametrize("path", [DOCS_PAGE, PLUGIN_README], ids=lambda p: p.name)
def test_the_documentation_names_the_pinned_install(path):
    assert INSTALL_LINE in _prose(path), (
        f"{path.name} does not name `{INSTALL_LINE}`, the install the module pins"
    )


@pytest.mark.parametrize(
    "platform,arch",
    [(p, a) for p in ("linux", "darwin", "windows") for a in ("amd64", "arm64")],
)
def test_the_installer_runs_the_documented_install(tmp_path, platform, arch):
    commands = [
        " ".join(str(part) for part in getattr(c, "args", c))
        for c in _scanner(tmp_path).get_installation_commands(platform, arch)
    ]
    assert INSTALL_LINE in commands, commands


def test_the_image_statement_in_the_docs_matches_the_dockerfile():
    """The docs say the image does not include cdxgen; the Dockerfile agrees.

    When the image starts installing it (its module in ASH_ALPHA_PLUGIN_MODULES),
    the docs, the README and the image's license table change with it.
    """
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    declared = re.findall(
        r'^ARG ASH_ALPHA_PLUGIN_MODULES="([^"]*)"$', dockerfile, re.MULTILINE
    )
    assert len(declared) == 2, "the Dockerfile's ASH_ALPHA_PLUGIN_MODULES lines moved"
    in_image = any("ash_cdxgen_plugins" in value for value in declared)
    docs_say_absent = "The ASH container image does not include cdxgen." in _prose(
        DOCS_PAGE
    )
    readme_says_absent = "The ASH container image does not include it." in _prose(
        PLUGIN_README
    )
    assert in_image is not docs_say_absent
    assert readme_says_absent is docs_say_absent
    assert ("cdxgen" in THIRD_PARTY_LICENSES) is in_image
