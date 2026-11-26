# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``docs/plugins/alpha/pip_audit-plugin.md`` says what the pip-audit plugin does.

Each test pins one sentence of the page with ``assert_on_page`` and reads the code
that makes it true, the two halves ``test_page_claims.py`` uses, so a reworded page
or a changed plugin fails here instead of leaving the page describing a plugin that
no longer exists. Not pinned: the configuration and suppression examples, which
illustrate options the plugin's own tests cover, and the flags block, which the
behavior tests pin against the argv the scanner builds.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.core.enums import OfflineStrategy
from automated_security_helper.plugin_modules.ash_pip_audit_plugins.pip_audit_scanner import (
    ADVISORY_LEVEL,
    ADVISORY_SEVERITY,
    PIP_AUDIT_DEFAULT_VERSION_CONSTRAINT,
    PipAuditScanner,
    PipAuditScannerConfig,
    is_requirements_file,
)
from automated_security_helper.utils.tool_downloads import THIRD_PARTY_LICENSES
from tests.unit.docs.test_page_claims import assert_on_page

pytestmark = pytest.mark.unit

PIP_AUDIT_PAGE = "docs/plugins/alpha/pip_audit-plugin.md"
REPO_ROOT = Path(__file__).resolve().parents[3]


def test_the_page_names_the_pinned_release() -> None:
    assert_on_page(PIP_AUDIT_PAGE, "ASH pins pip-audit 2.10.1.")
    assert PIP_AUDIT_DEFAULT_VERSION_CONSTRAINT == "==2.10.1"
    assert THIRD_PARTY_LICENSES["pip-audit"].version.lstrip("v") == "2.10.1"


def test_the_scanner_runs_once_its_module_is_listed() -> None:
    assert_on_page(
        PIP_AUDIT_PAGE,
        "With the module listed, `pip-audit` runs by default, like every other "
        "scanner.",
    )
    config = PipAuditScannerConfig()
    assert config.name == "pip-audit"
    assert config.enabled is True


def test_the_requirements_files_it_audits() -> None:
    assert_on_page(
        PIP_AUDIT_PAGE,
        "any `.txt` file directly under a directory named `requirements`.",
    )
    for path in (
        "requirements.txt",
        "requirements-dev.txt",
        "dev-requirements.txt",
        "requirements_test.txt",
        "requirements/base.txt",
    ):
        assert is_requirements_file(path), path
    # Control: a text file that is not a requirements file is not audited.
    assert not is_requirements_file("notes.txt")


def test_every_advisory_is_error_in_sarif_and_high_in_ash() -> None:
    assert_on_page(PIP_AUDIT_PAGE, "Every result is `error` in SARIF and HIGH in ASH")
    assert (ADVISORY_LEVEL, ADVISORY_SEVERITY) == ("error", "HIGH")


def test_offline_the_scanner_is_reported_missing() -> None:
    assert_on_page(
        PIP_AUDIT_PAGE,
        "The scanner is reported `MISSING` with the reason, and "
        "`--exclude-scanners pip-audit` leaves it out.",
    )
    assert PipAuditScanner.offline_strategy is OfflineStrategy.SKIP_OFFLINE


def test_the_image_installs_it_for_root_and_for_the_non_root_user() -> None:
    assert_on_page(
        PIP_AUDIT_PAGE,
        "the ASH container image installs pip-audit 2.10.1 the same way when it "
        "is built, for root and again for the image's non-root user",
    )
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert dockerfile.count("RUN pip-audit --version") == 2
    assert "automated_security_helper.plugin_modules.ash_pip_audit_plugins" in (
        dockerfile
    )


def test_the_license_and_the_file_the_image_ships() -> None:
    assert_on_page(PIP_AUDIT_PAGE, "pip-audit is Apache-2.0-licensed.")
    entry = THIRD_PARTY_LICENSES["pip-audit"]
    assert entry.license == "Apache-2.0"
    assert [f.name for f in entry.files] == ["LICENSE"]
