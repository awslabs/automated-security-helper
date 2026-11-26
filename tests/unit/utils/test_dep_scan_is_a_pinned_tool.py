# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""dep-scan, the alpha dependency scanner's uv tool, is a pinned tool.

The uv-tool shape ggshield and credsweeper use: a ``ThirdPartyLicense`` entry with
``distribution`` set, the license file read from the installed wheel's dist-info, and
image wiring through ``--uv-tool-pins`` and ``--licenses-only``. Two names differ
here, which is what this module pins: the entry is keyed by the scanner's config name
``dep-scan`` (``--uv-tool-pins`` writes ``scanners.<tool>.options.tool_version``), the
PyPI distribution is ``owasp-depscan``, and the executable on PATH is ``depscan``.
The entry's version is the release the register's license citation was read at (the
6.3.2 wheel's ``licenses/LICENSE``, whose sha256 the citation records), which is also
the scanner's own default constraint ``==6.3.2``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_dep_scan_plugins.dep_scan_scanner import (
    DEP_SCAN_DEFAULT_VERSION_CONSTRAINT,
    DEP_SCAN_PACKAGE,
    LICENSE_CITATION,
    DepScanScanner,
    DepScanScannerConfig,
)
from automated_security_helper.utils.tool_downloads import (
    THIRD_PARTY_LICENSES,
    _THIRD_PARTY_HASHES,
)

pytestmark = pytest.mark.unit


def test_the_license_entry_is_the_uv_tool_shape():
    entry = THIRD_PARTY_LICENSES["dep-scan"]
    # The upstream release tag; without its leading v, the version installed.
    assert entry.version == "v6.3.2"
    assert entry.license == "MIT"
    assert entry.repository == "https://github.com/owasp-dep-scan/dep-scan"
    assert entry.commit == _THIRD_PARTY_HASHES["dep-scan commit"]
    assert len(entry.commit) == 40
    assert entry.distribution == DEP_SCAN_PACKAGE == "owasp-depscan"
    assert [(f.name, f.url) for f in entry.files] == [("LICENSE", None)]


def test_the_entry_is_keyed_by_the_scanners_config_name():
    """--uv-tool-pins writes scanners.<entry.tool>.options.tool_version, so the tool
    name must be the name the scanner's config carries, or the image pin is lost."""
    entry = THIRD_PARTY_LICENSES["dep-scan"]
    assert entry.tool == DepScanScannerConfig().name == "dep-scan"


def test_the_version_check_runs_the_executable_the_wheel_installs():
    entry = THIRD_PARTY_LICENSES["dep-scan"]
    assert entry.executable_names == ("depscan",)
    assert not entry.version_probe


def test_the_entry_version_is_the_registers_read_and_the_default_pin():
    entry = THIRD_PARTY_LICENSES["dep-scan"]
    installed = entry.version.lstrip("v")
    assert f"owasp-depscan {installed} distribution" in LICENSE_CITATION, (
        "the register's license read and the license entry name different "
        "releases; re-read the license at the entry's version"
    )
    assert f"at tag {entry.version}" in LICENSE_CITATION
    assert LICENSE_CITATION.startswith("MIT (source: ")
    assert DepScanScanner.operational_facets.provenance.upstream_license == (
        LICENSE_CITATION
    )
    assert DEP_SCAN_DEFAULT_VERSION_CONSTRAINT == f"=={installed}"


def test_the_image_installs_and_attributes_the_pinned_dep_scan():
    dockerfile = (Path(__file__).resolve().parents[3] / "Dockerfile").read_text()
    assert "ash_dep_scan_plugins" in dockerfile
    assert "dep-scan" in _licenses_only_line(dockerfile).split()
    assert "RUN depscan --version" in dockerfile


def _licenses_only_line(dockerfile: str) -> str:
    for line in dockerfile.splitlines():
        if "--licenses-only" in line and "bandit" in line:
            return line
    raise AssertionError("the Python tools' --licenses-only line is missing")
