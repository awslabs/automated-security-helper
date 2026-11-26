# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""pip-audit, the alpha dependency-audit scanner's uv tool, is a pinned tool.

Same uv-tool shape as ggshield (and bandit/checkov/guarddog before it): a
``ThirdPartyLicense`` entry with ``distribution`` set, license files from the
installed wheel's dist-info, and image wiring through ``--uv-tool-pins`` and
``--licenses-only``. The entry's version is the one the register's license read
cites (the 2.10.1 wheel's ``licenses/LICENSE``, whose sha256 the citation
records), which is also the scanner's own default constraint ``==2.10.1``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_pip_audit_plugins.pip_audit_scanner import (
    LICENSE_CITATION,
    PIP_AUDIT_DEFAULT_VERSION_CONSTRAINT,
    PipAuditScanner,
)
from automated_security_helper.utils.tool_downloads import THIRD_PARTY_LICENSES

pytestmark = pytest.mark.unit


def test_the_license_entry_is_the_uv_tool_shape():
    entry = THIRD_PARTY_LICENSES["pip-audit"]
    assert entry.tool == "pip-audit"
    assert entry.version == "v2.10.1"
    assert entry.license == "Apache-2.0"
    assert entry.repository == "https://github.com/pypa/pip-audit"
    assert len(entry.commit) == 40
    assert entry.distribution == "pip-audit"
    # Read from the installed wheel's dist-info (licenses/LICENSE), not fetched.
    assert [(f.name, f.url) for f in entry.files] == [("LICENSE", None)]
    assert not entry.copyleft


def test_the_entry_version_is_the_registers_read_and_the_default_pin():
    entry = THIRD_PARTY_LICENSES["pip-audit"]
    bare = entry.version.lstrip("v")
    assert bare in LICENSE_CITATION, (
        "the register's license read and the license entry name different "
        "releases; re-read the license at the entry's version"
    )
    assert PIP_AUDIT_DEFAULT_VERSION_CONSTRAINT == f"=={bare}"


def test_the_register_cites_the_license_it_read():
    citation = PipAuditScanner.operational_facets.provenance.upstream_license
    assert citation == LICENSE_CITATION
    assert citation.startswith("Apache-2.0 (source: ")


def test_the_image_installs_and_attributes_the_pinned_pip_audit():
    dockerfile = (Path(__file__).resolve().parents[3] / "Dockerfile").read_text()
    assert "ash_pip_audit_plugins" in dockerfile
    assert "pip-audit" in _licenses_only_line(dockerfile).split()
    # Once in the core stage, once for the non-root user's own uv tool install.
    assert dockerfile.count("RUN pip-audit --version") == 2


def _licenses_only_line(dockerfile: str) -> str:
    for line in dockerfile.splitlines():
        if "--licenses-only" in line and "bandit" in line:
            return line
    raise AssertionError("the Python tools' --licenses-only line is missing")
