# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""retire, the alpha retire.js scanner's tool, is a pinned tool with all of its tree.

retire.js is pinned by its own module (``ash_retire_js_plugins/retire_js_install.py``):
a lockfile holding the six packages of the tree it runs on, each with the integrity the
registry publishes. The image installs that tree, so it bundles six packages, and each
needs a license entry that records the release the lockfile installs. These tests hold
the entries, the lockfile and the image's wiring to one another, which the shared
coverage test cannot: it only knows TOOL_VERSIONS tools. The version probes of the
five carried packages are node code, so they are tested with the real node in
test_retire_js_tree_version_probes.py, beside this module.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.plugin_modules.ash_retire_js_plugins.retire_js_install import (
    LOCKED_PACKAGES,
    RETIRE_VERSION,
)
from automated_security_helper.plugin_modules.ash_retire_js_plugins.retire_js_scanner import (
    RetireJsScanner,
)
from automated_security_helper.utils import tool_downloads
from automated_security_helper.utils.tool_downloads import THIRD_PARTY_LICENSES

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
DOCKERFILE = REPO_ROOT / "Dockerfile"

#: Every package of the tree, by the name its THIRD_PARTY_LICENSES entry is under.
TREE = {path.split("/", 1)[1]: entry for path, entry in LOCKED_PACKAGES.items()}
#: The packages the tree carries beside retire.
CARRIED = sorted(name for name in TREE if name != "retire")


def test_the_license_entry_names_the_installers_pin():
    entry = THIRD_PARTY_LICENSES["retire"]
    assert entry.version == RETIRE_VERSION == "6.1.1"
    assert entry.license == "Apache-2.0" == TREE["retire"]["license"]
    assert entry.repository == "https://github.com/RetireJS/retire.js"
    assert re.fullmatch(r"[0-9a-f]{40}", entry.commit)
    assert not entry.version_probe and not entry.bundled_in
    (license_file,) = entry.files
    assert license_file.name == "LICENSE.md"
    assert license_file.url == (
        f"https://raw.githubusercontent.com/RetireJS/retire.js/{entry.commit}/LICENSE.md"
    )
    assert re.fullmatch(r"[0-9a-f]{64}", license_file.sha256 or "")


@pytest.mark.parametrize("name", CARRIED)
def test_every_package_the_tree_carries_has_an_entry_at_its_locked_release(name):
    entry = THIRD_PARTY_LICENSES[name]
    assert entry.version.lstrip("v") == TREE[name]["version"]
    # The license the registry records for the release, which is what the lockfile
    # copies; the text behind it is the URL-pinned file.
    assert entry.license == TREE[name]["license"]
    assert entry.bundled_in == tool_downloads._RETIRE_TREE
    assert entry.registry == "the npm registry"
    assert entry.version_probe[:2] == ("node", "-e")
    assert f'"{name}"' in entry.version_probe[2]
    assert not entry.executables
    for license_file in entry.files:
        assert license_file.url is not None and entry.commit in license_file.url


def test_the_tree_entries_are_exactly_the_locked_packages():
    bundled = sorted(
        tool
        for tool, entry in THIRD_PARTY_LICENSES.items()
        if entry.bundled_in == tool_downloads._RETIRE_TREE
    )
    assert bundled == CARRIED
    assert RETIRE_VERSION in tool_downloads._RETIRE_TREE


@pytest.mark.parametrize("name", CARRIED)
def test_the_source_notice_says_published_not_built(name):
    notice = THIRD_PARTY_LICENSES[name].source_notice()
    assert "the release its project published to the npm registry" in notice
    assert "built for that wheel" not in notice
    assert THIRD_PARTY_LICENSES[name].commit in notice


def test_the_register_citation_names_the_pinned_commit_and_digest():
    citation = RetireJsScanner.operational_facets.provenance.upstream_license
    entry = THIRD_PARTY_LICENSES["retire"]
    assert citation.startswith("Apache-2.0 (source: the LICENSE.md file inside ")
    assert entry.commit in citation
    assert entry.files[0].sha256 in citation


def _licenses_line(dockerfile: str) -> "list[str]":
    lines = [
        line
        for line in dockerfile.splitlines()
        if "install-pinned-tool --licenses-only" in line and "retire" in line
    ]
    assert len(lines) == 1, lines
    return lines[0].split("--licenses-only", 1)[1].strip(" '").split()


def test_the_image_loads_the_module_in_both_stages():
    dockerfile = DOCKERFILE.read_text()
    declared = re.findall(
        r'^ARG ASH_ALPHA_PLUGIN_MODULES="([^"]+)"$', dockerfile, re.MULTILINE
    )
    assert len(declared) == 2
    for modules in declared:
        assert (
            "automated_security_helper.plugin_modules.ash_retire_js_plugins"
            in modules.split(",")
        )


def test_the_image_stages_the_license_of_every_package_of_the_tree():
    assert sorted(_licenses_line(DOCKERFILE.read_text())) == sorted(TREE)


def test_the_image_checks_the_version_it_installed_in_both_stages():
    dockerfile = DOCKERFILE.read_text()
    assert f'ARG RETIRE_VERSION="{RETIRE_VERSION}"' in dockerfile
    assert (
        'RUN reported="$(retire --version)" && echo "${reported}" && \\\n'
        '    test "${reported}" = "${RETIRE_VERSION}"'
    ) in dockerfile
    core, non_root = dockerfile.split("\nFROM core AS non-root\n")
    assert "RUN retire --version" in non_root
    # After the install that puts it there, and before the license verification.
    assert core.index('ash dependencies install --bin-path "${ASH_BIN_PATH}"') < (
        core.index('ARG RETIRE_VERSION="')
    )
    assert core.index('ARG RETIRE_VERSION="') < core.index(
        "RUN install-pinned-tool --verify-third-party"
    )


def _load_checker():
    script = REPO_ROOT / "scripts" / "check_pinned_tool_versions.py"
    spec = importlib.util.spec_from_file_location("_check_pins_for_retire", script)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_the_pin_checker_reads_retire_and_its_tree_without_refusing_them():
    """retire is held by the Dockerfile's ARG RETIRE_VERSION and compared with its
    upstream; the packages it carries are bundled, listed and never looked up."""
    checker = _load_checker()
    pins = SimpleNamespace(
        TOOL_VERSIONS={},
        THIRD_PARTY_LICENSES={name: THIRD_PARTY_LICENSES[name] for name in TREE},
        RULES_BUNDLES={},
        _RELEASE_BASE_URLS={},
        CFN_NAG_GEM_VERSION=tool_downloads.CFN_NAG_GEM_VERSION,
        BUNDLER_VERSION=tool_downloads.BUNDLER_VERSION,
    )
    by_tool = {pin.tool: pin for pin in checker.enumerate_pins(pins, DOCKERFILE)}
    assert by_tool["retire"].kind == checker.DOCKERFILE_ARG
    assert by_tool["retire"].project == "RetireJS/retire.js"
    for name in CARRIED:
        assert by_tool[name].kind == checker.BUNDLED_LIBRARY, name
    carried = checker._dockerfile_arg_steps(pins, by_tool["retire"], "6.2.0")[-1]
    assert carried.startswith(", ".join(CARRIED) + ": bundled_in names retire")
