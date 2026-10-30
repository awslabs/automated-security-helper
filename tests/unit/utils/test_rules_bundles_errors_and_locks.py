# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The rules bundle installer answers every failure in its own terms.

Each test pins one change in ``utils/rules_bundles.py``:

* a rules root under a directory this process may not search is reported as a
  reason the bundle cannot be used, not raised as PermissionError past the
  RulesBundleUnavailable contract;
* a member that cannot be opened or read, and two members whose names differ
  only in case, are integrity errors, and no staging descriptor is left open;
* a rules root that cannot be created or written is the documented refusal;
* a local failure of the download is worded as local, and only a network failure
  says the install needs network access;
* a failed move of the old bundle aside leaves no empty directory behind;
* concurrent installs are serialized on a lock in the rules root, and an install
  that finds the bundle in place once it holds the lock downloads nothing.
"""

from __future__ import annotations

import hashlib
import os
import sys
import urllib.error
import zipfile
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.core.exceptions import ToolDownloadIntegrityError
from automated_security_helper.utils.rules_bundles import (
    RulesBundleUnavailable,
    extract_bundle,
    install_rules_bundle,
    verify_installed_bundle,
)
from automated_security_helper.utils.tool_downloads import RULES_BUNDLES

pytestmark = pytest.mark.unit

REAL = RULES_BUNDLES["aws-guard-rules-registry"]

GOOD_ENTRIES = {
    "output/": "",
    "output/wa-Security-Pillar.guard": "rule A { }\n",
    "output/cis-aws-benchmark-level-1.guard": "rule B { }\n",
}

GOOD_MEMBERS = {
    "wa-Security-Pillar.guard": b"rule A { }\n",
    "cis-aws-benchmark-level-1.guard": b"rule B { }\n",
}


def _zip(path: Path, entries: dict) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return path


def _pinned_contents(members: dict) -> str:
    lines = "".join(
        f"{name}\t{hashlib.sha256(data).hexdigest()}\n"
        for name, data in sorted(members.items())
    )
    return hashlib.sha256(lines.encode("ascii")).hexdigest()


def _pinned(archive: Path, members: dict = GOOD_MEMBERS):
    return replace(
        REAL,
        sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
        contents_sha256=_pinned_contents(members),
    )


@pytest.fixture
def bundle_zip(tmp_path) -> tuple:
    archive = _zip(tmp_path / "ruleset-build-v1.0.2.zip", GOOD_ENTRIES)
    return archive, _pinned(archive)


def _fake_download(archive: Path, calls: list):
    # ``mode`` as the real helper takes it: the bundle is data, and the caller
    # says so; the stand-in lands bytes and reads nothing from it.
    def download_file(
        url, destination, rename_to=None, expected_sha256=None, *, mode=None
    ):
        calls.append((url, expected_sha256))
        target = Path(destination) / (rename_to or url.rsplit("/", 1)[-1])
        target.write_bytes(archive.read_bytes())
        return target

    return download_file


def _failing_download(error: BaseException, calls: list):
    def download_file(
        url, destination, rename_to=None, expected_sha256=None, *, mode=None
    ):
        calls.append((url, expected_sha256))
        raise error

    return download_file


def _install(root: Path, bundle, archive: Path, calls: list, download=None, **kwargs):
    with (
        patch(
            "automated_security_helper.utils.download_utils.download_file",
            side_effect=download or _fake_download(archive, calls),
        ),
        patch(
            "automated_security_helper.utils.tool_downloads.get_rules_bundle",
            return_value=bundle,
        ),
    ):
        return install_rules_bundle(bundle.name, root=root, **kwargs)


def _leftovers(rules: Path) -> list:
    return sorted(
        p.name
        for p in rules.iterdir()
        if p.name.startswith(".ash-rules") and p.name != ".ash-rules-install.lock"
    )


class TestAnUnsearchableRulesRoot:
    def test_a_permission_error_on_the_probe_is_a_reason_not_an_exception(
        self, tmp_path, monkeypatch
    ):
        real_is_dir = Path.is_dir

        def _is_dir(self, *args, **kwargs):
            if self.name.startswith(REAL.name):
                raise PermissionError(13, "Permission denied", str(self))
            return real_is_dir(self, *args, **kwargs)

        monkeypatch.setattr(Path, "is_dir", _is_dir)
        with pytest.raises(RulesBundleUnavailable) as refused:
            verify_installed_bundle(REAL, tmp_path)
        assert "could not be read" in str(refused.value)
        assert "Permission denied" in str(refused.value)


class TestExtractionErrorsAreIntegrityErrors:
    def test_a_member_that_cannot_be_opened(self, tmp_path, bundle_zip, monkeypatch):
        archive, bundle = bundle_zip
        real_open = zipfile.ZipFile.open

        def _open(self, info, *args, **kwargs):
            name = info.filename if isinstance(info, zipfile.ZipInfo) else info
            if name.endswith("wa-Security-Pillar.guard"):
                raise zipfile.BadZipFile("Bad magic number for file header")
            return real_open(self, info, *args, **kwargs)

        monkeypatch.setattr(zipfile.ZipFile, "open", _open)
        staging = tmp_path / "staging"
        staging.mkdir()
        with pytest.raises(ToolDownloadIntegrityError, match="cannot be read"):
            extract_bundle(archive, bundle, staging)
        assert sorted(p.name for p in staging.iterdir()) == []

    def test_two_names_that_differ_only_in_case(self, tmp_path):
        archive = _zip(
            tmp_path / "case.zip",
            {
                "output/": "",
                "output/Rule.guard": "rule A { }\n",
                "output/rule.guard": "rule B { }\n",
            },
        )
        staging = tmp_path / "staging"
        staging.mkdir()
        with pytest.raises(ToolDownloadIntegrityError, match="two members named"):
            extract_bundle(archive, _pinned(archive), staging)

    def test_a_good_archive_still_extracts(self, tmp_path, bundle_zip):
        """The control."""
        archive, bundle = bundle_zip
        staging = tmp_path / "staging"
        staging.mkdir()
        written = extract_bundle(archive, bundle, staging)
        assert sorted(written) == sorted(GOOD_MEMBERS)


@pytest.mark.skipif(
    sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="a read-only directory refuses writes only to an unprivileged POSIX user",
)
class TestAnUnwritableRulesRoot:
    def test_the_refusal_is_the_documented_one(self, tmp_path, bundle_zip):
        archive, bundle = bundle_zip
        parent = tmp_path / "locked"
        parent.mkdir()
        parent.chmod(0o555)
        try:
            with pytest.raises(RulesBundleUnavailable) as refused:
                _install(parent / "rules", bundle, archive, [])
        finally:
            parent.chmod(0o755)
        message = str(refused.value)
        assert "could not be created" in message or "cannot be written" in message
        assert "are not installed" in message


class TestTheDownloadFailureWording:
    def test_a_local_failure_is_not_called_a_network_failure(
        self, tmp_path, bundle_zip
    ):
        archive, bundle = bundle_zip
        calls: list = []
        with pytest.raises(RulesBundleUnavailable) as refused:
            _install(
                tmp_path / "rules",
                bundle,
                archive,
                calls,
                download=_failing_download(PermissionError(13, "denied"), calls),
            )
        message = str(refused.value)
        assert "needs network access" not in message
        assert "local" in message
        assert _leftovers(tmp_path / "rules") == []

    def test_a_network_failure_still_names_network_access(self, tmp_path, bundle_zip):
        """The control."""
        archive, bundle = bundle_zip
        calls: list = []
        with pytest.raises(RulesBundleUnavailable) as refused:
            _install(
                tmp_path / "rules",
                bundle,
                archive,
                calls,
                download=_failing_download(
                    urllib.error.URLError("Network is unreachable"), calls
                ),
            )
        assert "needs network access" in str(refused.value)


class TestReplacingTheOldBundle:
    def test_a_failed_move_aside_leaves_no_directory_behind(
        self, tmp_path, bundle_zip, monkeypatch
    ):
        archive, bundle = bundle_zip
        rules = tmp_path / "rules"
        final = _install(rules, bundle, archive, [])
        (final / "wa-Security-Pillar.guard").write_text("rule weakened { }\n")
        real_replace = os.replace

        def _replace(src, dst, *args, **kwargs):
            if Path(dst).name == "old":
                raise PermissionError(13, "Operation not permitted", str(src))
            return real_replace(src, dst, *args, **kwargs)

        monkeypatch.setattr(os, "replace", _replace)
        with pytest.raises(PermissionError):
            _install(rules, bundle, archive, [])
        assert _leftovers(rules) == []
        assert final.is_dir(), "the old bundle stays where it was"


class TestConcurrentInstalls:
    def test_the_install_takes_the_lock_in_the_rules_root(
        self, tmp_path, bundle_zip, monkeypatch
    ):
        archive, bundle = bundle_zip
        taken: list = []

        @contextmanager
        def _lock(path):
            taken.append(Path(path))
            yield

        monkeypatch.setattr(
            "automated_security_helper.utils.file_lock.exclusive_lock", _lock
        )
        rules = tmp_path / "rules"
        _install(rules, bundle, archive, [])
        assert taken == [rules / ".ash-rules-install.lock"]

    def test_a_bundle_installed_while_waiting_for_the_lock_is_kept(
        self, tmp_path, bundle_zip, monkeypatch
    ):
        """The second installer finds the first one's work under the lock and
        downloads nothing, instead of failing on the final rename."""
        archive, bundle = bundle_zip
        rules = tmp_path / "rules"
        installed_meanwhile: list = []

        @contextmanager
        def _lock(path):
            # Another process installed the bundle while this one waited. Once:
            # that install takes the same (patched) lock on its way through.
            if not installed_meanwhile:
                installed_meanwhile.append(path)
                _install(rules, bundle, archive, [])
            yield

        monkeypatch.setattr(
            "automated_security_helper.utils.file_lock.exclusive_lock", _lock
        )
        calls: list = []
        final = _install(rules, bundle, archive, calls)
        assert calls == []
        assert (final / "wa-Security-Pillar.guard").is_file()
