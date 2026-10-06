# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Rules bundle install and verification (utils/rules_bundles.py).

The archive here is built in the test with the same layout as the AWS Guard Rules
Registry's ``ruleset-build-v1.0.2.zip`` -- rule files under ``output/`` plus
``__MACOSX/`` resource-fork entries -- and with hostile entries added. Only the network
fetch is replaced; extraction, the manifest, the skip decision and verification are
the real code.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import zipfile
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.core.exceptions import ToolDownloadIntegrityError
from automated_security_helper.utils import rules_bundles
from automated_security_helper.utils.rules_bundles import (
    MANIFEST_NAME,
    RulesBundleUnavailable,
    extract_bundle,
    install_rules_bundle,
    verify_installed_bundle,
)
from automated_security_helper.utils.tool_downloads import RULES_BUNDLES

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "automated_security_helper" / "assets" / "install-pinned-tool.py"
REAL = RULES_BUNDLES["aws-guard-rules-registry"]


def _zip(path: Path, entries: dict) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return path


GOOD_ENTRIES = {
    "output/": "",
    "output/wa-Security-Pillar.guard": "rule A { }\n",
    "output/cis-aws-benchmark-level-1.guard": "rule B { }\n",
    "__MACOSX/output/._wa-Security-Pillar.guard": "\x00\x05\x16\x07",
    "output/README.md": "not a rule file\n",
    "output/nested/deeper.guard": "rule C { }\n",
}


@pytest.fixture
def bundle_zip(tmp_path) -> tuple:
    archive = _zip(tmp_path / "ruleset-build-v1.0.2.zip", GOOD_ENTRIES)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    return archive, replace(REAL, sha256=digest)


def _fake_download(archive: Path, calls: list):
    def download_file(url, destination, rename_to=None, expected_sha256=None):
        calls.append((url, expected_sha256))
        target = Path(destination) / (rename_to or url.rsplit("/", 1)[-1])
        target.write_bytes(archive.read_bytes())
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if expected_sha256 and actual != expected_sha256:
            raise ToolDownloadIntegrityError("mismatch")
        return target

    return download_file


def _install(tmp_path, bundle, archive, calls, **kwargs):
    with (
        patch(
            "automated_security_helper.utils.download_utils.download_file",
            side_effect=_fake_download(archive, calls),
        ),
        patch(
            "automated_security_helper.utils.tool_downloads.get_rules_bundle",
            return_value=bundle,
        ),
    ):
        return install_rules_bundle(bundle.name, root=tmp_path / "rules", **kwargs)


class TestExtraction:
    def test_only_rule_files_directly_under_the_member_dir_are_extracted(
        self, tmp_path, bundle_zip
    ):
        archive, bundle = bundle_zip
        staging = tmp_path / "staging"
        staging.mkdir()
        files = extract_bundle(archive, bundle, staging)
        assert sorted(files) == [
            "cis-aws-benchmark-level-1.guard",
            "wa-Security-Pillar.guard",
        ]
        assert sorted(p.name for p in staging.iterdir()) == sorted(files)
        assert (
            files["wa-Security-Pillar.guard"]
            == hashlib.sha256(b"rule A { }\n").hexdigest()
        )

    @pytest.mark.parametrize(
        "entry",
        ["../output/escape.guard", "/output/abs.guard", "output/../../escape.guard"],
    )
    def test_traversal_entries_never_leave_the_staging_directory(self, tmp_path, entry):
        archive = _zip(
            tmp_path / "b.zip",
            {"output/ok.guard": "rule A { }\n", entry: "rule X { }\n"},
        )
        staging = tmp_path / "staging"
        staging.mkdir()
        files = extract_bundle(archive, REAL, staging)
        assert list(files) == ["ok.guard"]
        assert not (tmp_path / "escape.guard").exists()
        assert not (tmp_path / "abs.guard").exists()

    def test_an_unsafe_member_name_refuses_the_archive(self, tmp_path):
        archive = _zip(tmp_path / "b.zip", {"output/bad name.guard": "x"})
        staging = tmp_path / "s"
        staging.mkdir()
        with pytest.raises(ToolDownloadIntegrityError, match="will not write"):
            extract_bundle(archive, REAL, staging)

    def test_two_members_with_one_name_refuse_the_archive(self, tmp_path):
        archive = tmp_path / "b.zip"
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr("output/a.guard", "1")
            z.writestr("output/a.guard", "2")
        staging = tmp_path / "s"
        staging.mkdir()
        with pytest.raises(ToolDownloadIntegrityError, match="two members"):
            extract_bundle(archive, REAL, staging)

    def test_an_archive_with_no_rule_files_is_refused(self, tmp_path):
        archive = _zip(tmp_path / "b.zip", {"other/a.guard": "x"})
        staging = tmp_path / "s"
        staging.mkdir()
        with pytest.raises(ToolDownloadIntegrityError, match="holds no"):
            extract_bundle(archive, REAL, staging)

    def test_a_member_over_the_size_cap_is_refused(self, tmp_path, monkeypatch):
        monkeypatch.setattr(rules_bundles, "_MAX_MEMBER_BYTES", 8)
        archive = _zip(tmp_path / "b.zip", {"output/a.guard": "x" * 64})
        staging = tmp_path / "s"
        staging.mkdir()
        with pytest.raises(ToolDownloadIntegrityError, match="cap"):
            extract_bundle(archive, REAL, staging)

    def test_not_a_zip_is_a_typed_error(self, tmp_path):
        archive = tmp_path / "b.zip"
        archive.write_bytes(b"not a zip")
        with pytest.raises(ToolDownloadIntegrityError, match="not a readable zip"):
            extract_bundle(archive, REAL, tmp_path)


class TestInstall:
    def test_install_writes_files_and_a_manifest_naming_the_pin(
        self, tmp_path, bundle_zip
    ):
        archive, bundle = bundle_zip
        calls = []
        final = _install(tmp_path, bundle, archive, calls)
        assert calls == [(bundle.url, bundle.sha256)]
        manifest = json.loads((final / MANIFEST_NAME).read_text())
        assert manifest["url"] == bundle.url and manifest["sha256"] == bundle.sha256
        assert sorted(manifest["files"]) == [
            "cis-aws-benchmark-level-1.guard",
            "wa-Security-Pillar.guard",
        ]
        assert not [
            p for p in (tmp_path / "rules").iterdir() if p.name.startswith(".ash-rules")
        ]

    def test_a_digest_mismatch_installs_nothing(self, tmp_path, bundle_zip):
        archive, bundle = bundle_zip
        wrong = replace(bundle, sha256="0" * 64)
        with pytest.raises(ToolDownloadIntegrityError):
            _install(tmp_path, wrong, archive, [])
        assert list((tmp_path / "rules").iterdir()) == []

    def test_a_second_install_does_not_download(self, tmp_path, bundle_zip):
        archive, bundle = bundle_zip
        calls = []
        _install(tmp_path, bundle, archive, calls)
        _install(tmp_path, bundle, archive, calls)
        assert len(calls) == 1

    def test_a_tampered_file_is_reinstalled(self, tmp_path, bundle_zip):
        archive, bundle = bundle_zip
        calls = []
        final = _install(tmp_path, bundle, archive, calls)
        (final / "wa-Security-Pillar.guard").write_text("rule weakened { }\n")
        _install(tmp_path, bundle, archive, calls)
        assert len(calls) == 2
        assert (final / "wa-Security-Pillar.guard").read_text() == "rule A { }\n"

    def test_force_reinstalls(self, tmp_path, bundle_zip):
        archive, bundle = bundle_zip
        calls = []
        _install(tmp_path, bundle, archive, calls)
        _install(tmp_path, bundle, archive, calls, force=True)
        assert len(calls) == 2


class TestVerify:
    def test_missing_install_names_the_remedy(self, tmp_path):
        with pytest.raises(RulesBundleUnavailable, match="ash dependencies install"):
            verify_installed_bundle(REAL, tmp_path)

    def test_unreadable_manifest(self, tmp_path):
        directory = tmp_path / rules_bundles.bundle_dir_name(REAL)
        directory.mkdir()
        (directory / MANIFEST_NAME).write_text("{")
        with pytest.raises(RulesBundleUnavailable, match="unreadable"):
            verify_installed_bundle(REAL, tmp_path)

    def test_a_listed_file_that_is_gone(self, tmp_path, bundle_zip):
        archive, bundle = bundle_zip
        final = _install(tmp_path, bundle, archive, [])
        (final / "wa-Security-Pillar.guard").unlink()
        with pytest.raises(RulesBundleUnavailable, match="missing"):
            verify_installed_bundle(
                bundle, tmp_path / "rules", files=["wa-Security-Pillar.guard"]
            )


class TestTheTwoInstallersAgree:
    """The image installs with install-pinned-tool; ash dependencies install skips on
    what it wrote. A drift between the two manifests would make every image
    re-download, or fail where the scan user cannot write the directory."""

    def test_both_write_the_same_manifest(self, tmp_path, bundle_zip):
        archive, bundle = bundle_zip
        python_dir = _install(tmp_path / "py", bundle, archive, [])

        spec = importlib.util.spec_from_file_location("_ipt", SCRIPT)
        script = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(script)

        class Pins:
            @staticmethod
            def get_rules_bundle(name):
                return bundle

        def download(url, target):
            target.write_bytes(archive.read_bytes())
            return hashlib.sha256(target.read_bytes()).hexdigest()

        with (
            patch.object(script, "load_pins", return_value=Pins),
            patch.object(script, "download", side_effect=download),
        ):
            script_dir = script.install_bundle(bundle.name, tmp_path / "sh", tmp_path)

        assert (script_dir / MANIFEST_NAME).read_text() == (
            python_dir / MANIFEST_NAME
        ).read_text()
        assert sorted(p.name for p in script_dir.iterdir()) == sorted(
            p.name for p in python_dir.iterdir()
        )
        verify_installed_bundle(bundle, tmp_path / "sh")

    def test_the_script_refuses_a_digest_mismatch(self, tmp_path, bundle_zip):
        archive, bundle = bundle_zip
        spec = importlib.util.spec_from_file_location("_ipt2", SCRIPT)
        script = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(script)
        wrong = replace(bundle, sha256="0" * 64)

        class Pins:
            @staticmethod
            def get_rules_bundle(name):
                return wrong

        def download(url, target):
            target.write_bytes(archive.read_bytes())
            return hashlib.sha256(target.read_bytes()).hexdigest()

        with (
            patch.object(script, "load_pins", return_value=Pins),
            patch.object(script, "download", side_effect=download),
            pytest.raises(SystemExit) as exited,
        ):
            script.install_bundle(bundle.name, tmp_path / "sh", tmp_path)
        assert exited.value.code == 3
        assert list((tmp_path / "sh").iterdir()) == []


def test_the_real_pin_is_well_formed():
    assert REAL.url.startswith(
        "https://github.com/aws-cloudformation/aws-guard-rules-registry/"
    )
    assert len(REAL.sha256) == 64 and REAL.sha256 == REAL.sha256.lower()
    assert REAL.member_dir == "output" and REAL.member_suffix == ".guard"
