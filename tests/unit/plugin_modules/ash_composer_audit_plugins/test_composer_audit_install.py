# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The module-local Composer pin, its install command, and where it is not shipped.

Composer is pinned by the plugin's own module (``composer_install.py``) rather than
``tool_downloads``' shared tables, so the agreement the shared tests give those tools
(a pinned version, a digest, a license read naming the same release) is asserted here.
Nothing here downloads: the install command is built, and the download helper is
replaced, so the tests run with no network and no PHP.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_composer_audit_plugins import (
    composer_install as ci,
)
from automated_security_helper.plugin_modules.ash_composer_audit_plugins.composer_audit_scanner import (
    ComposerAuditScanner,
)
from automated_security_helper.utils import download_utils as du
from automated_security_helper.utils.tool_downloads import THIRD_PARTY_LICENSES

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[4]
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX40 = re.compile(r"[0-9a-f]{40}")


def test_the_pin_names_one_release_and_full_digests():
    assert ci.COMPOSER_VERSION == "2.11.3"
    assert ci.PHAR_URL == "https://getcomposer.org/download/2.11.3/composer.phar"
    assert HEX64.fullmatch(ci.PHAR_SHA256), ci.PHAR_SHA256
    assert HEX64.fullmatch(ci.LICENSE_SHA256), ci.LICENSE_SHA256
    assert HEX40.fullmatch(ci.COMPOSER_COMMIT), ci.COMPOSER_COMMIT
    assert ci.PHAR_SHA256 != ci.LICENSE_SHA256


def test_the_install_table_covers_linux_and_macos_and_never_windows(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    table = ci.composer_install_commands()
    pairs = {(p, a) for p, arches in table.items() for a in arches}
    assert pairs == set(ci.PLATFORMS)
    assert pairs == {
        ("darwin", "amd64"),
        ("darwin", "arm64"),
        ("linux", "amd64"),
        ("linux", "arm64"),
    }
    assert "windows" not in table
    for arches in table.values():
        for commands in arches.values():
            (command,) = commands
            assert command.shell is False
            assert "install_composer" in " ".join(command.args)
            assert command.args[-1] == du._destination_text(
                (tmp_path / "bin").absolute()
            )


def test_the_install_table_never_raises_without_a_bin_directory(monkeypatch):
    monkeypatch.setattr(du, "current_bin_path", lambda: None)
    table = ci.composer_install_commands()
    (command,) = table["linux"]["amd64"]
    assert "install_composer" not in " ".join(command.args), "a refusing command"


def test_install_places_the_verified_phar_as_composer(tmp_path, monkeypatch):
    calls = []

    def fake_install(url, destination, rename_to=None, expected_sha256=None, **_):
        calls.append((url, destination, rename_to, expected_sha256))
        return destination / rename_to

    monkeypatch.setattr(du, "install_binary_from_url", fake_install)
    placed = ci.install_composer(tmp_path / "bin")
    assert calls == [(ci.PHAR_URL, tmp_path / "bin", "composer", ci.PHAR_SHA256)]
    assert placed == tmp_path / "bin" / "composer"
    assert (tmp_path / "bin").is_dir()


def test_install_refuses_with_no_bin_directory(monkeypatch):
    monkeypatch.setattr(du, "current_bin_path", lambda: None)
    with pytest.raises(RuntimeError):
        ci.install_composer()


def test_the_register_cites_the_pinned_license_read():
    citation = ComposerAuditScanner.operational_facets.provenance.upstream_license
    assert citation.startswith("MIT (source: the LICENSE file at the 2.11.3 tag")
    assert ci.COMPOSER_COMMIT[:8] in citation
    assert ci.LICENSE_SHA256[:8] in citation


def test_the_capture_readme_names_the_digest_the_module_pins():
    readme = (
        REPO_ROOT / "tests/test_data/scanners/composer_audit/captured/README.md"
    ).read_text(encoding="utf-8")
    assert ci.PHAR_SHA256 in readme


def test_the_image_does_not_carry_composer():
    """The image would need a PHP runtime to run Composer, and it carries none.

    THIRD_PARTY_LICENSES lists what the image redistributes, so the table has no
    entry and the image loads no module for this scanner; the license read lives
    in the register row instead. Adding Composer to the image means adding PHP,
    an entry and its version check together.
    """
    assert "composer" not in THIRD_PARTY_LICENSES
    assert "composer-audit" not in THIRD_PARTY_LICENSES
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "ash_composer_audit_plugins" not in dockerfile
