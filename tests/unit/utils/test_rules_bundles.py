# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Rules bundle install and verification (utils/rules_bundles.py).

The archive here is built in the test with the same layout as the AWS Guard Rules
Registry's ``ruleset-build-v1.0.2.zip`` -- rule files under ``output/`` plus
``__MACOSX/`` resource-fork entries -- and with entries the installers must refuse
added. Only the network fetch is replaced; extraction, the manifest, the skip
decision and verification are the real code. The fixture bundle's pin carries the
archive's digest and ``contents_sha256`` for its two rule files, computed here
rather than by the module under test.
"""

from __future__ import annotations

import errno
import hashlib
import importlib.util
import json
import os
import urllib.error
import zipfile
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.core.exceptions import ToolDownloadIntegrityError
from automated_security_helper.utils import rules_bundles
from automated_security_helper.utils.rules_bundles import (
    MANIFEST_NAME,
    RULES_DIR_ENV,
    RulesBundleUnavailable,
    contents_digest,
    extract_bundle,
    install_rules_bundle,
    verify_installed_bundle,
)
from automated_security_helper.utils.tool_downloads import RULES_BUNDLES

pytestmark = pytest.mark.unit

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

#: The rule files GOOD_ENTRIES extracts to, as bytes.
GOOD_MEMBERS = {
    "wa-Security-Pillar.guard": b"rule A { }\n",
    "cis-aws-benchmark-level-1.guard": b"rule B { }\n",
}


def _pinned_contents(members: dict) -> str:
    """``contents_sha256`` for ``members`` (name -> bytes), written out by hand."""
    lines = "".join(
        f"{name}\t{hashlib.sha256(data).hexdigest()}\n"
        for name, data in sorted(members.items())
    )
    return hashlib.sha256(lines.encode("ascii")).hexdigest()


def _pinned(archive: Path, members: dict = GOOD_MEMBERS):
    """The real pin's shape, pinned to ``archive`` and to ``members``."""
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
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if expected_sha256 and actual != expected_sha256:
            raise ToolDownloadIntegrityError("mismatch")
        return target

    return download_file


def _offline(calls: list):
    def download_file(
        url, destination, rename_to=None, expected_sha256=None, *, mode=None
    ):
        calls.append((url, expected_sha256))
        raise urllib.error.URLError("[Errno 101] Network is unreachable")

    return download_file


def test_the_bundle_is_fetched_as_data(tmp_path, bundle_zip):
    """The rules bundle is data, not a program: the installer asks the download
    helper for the data mode, whatever the helper's default is."""
    archive, bundle = bundle_zip
    calls: list = []
    modes: list = []
    landing = _fake_download(archive, calls)

    def download_file(
        url, destination, rename_to=None, expected_sha256=None, *, mode=None
    ):
        modes.append(mode)
        return landing(url, destination, rename_to, expected_sha256)

    _install(tmp_path, bundle, archive, calls, download=download_file)
    assert modes == [0o644]


def _install(tmp_path, bundle, archive, calls, download=None, **kwargs):
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
        return install_rules_bundle(bundle.name, root=tmp_path / "rules", **kwargs)


# The install serializes on this file in the rules root and leaves it there:
# a lock file removed after its release would let a waiter that had already
# opened it run beside the next taker. It is the one entry an install, finished
# or refused, may leave behind, so the listings below leave it out.
INSTALL_LOCK = ".ash-rules-install.lock"


def _contents(rules: Path) -> list:
    return sorted(p.name for p in rules.iterdir() if p.name != INSTALL_LOCK)


def _leftovers(rules: Path) -> list:
    return [
        p.name
        for p in rules.iterdir()
        if p.name.startswith(".ash-rules") and p.name != INSTALL_LOCK
    ]


def _tree(directory: Path) -> dict:
    return {p.name: p.read_bytes() for p in sorted(directory.iterdir())}


def _script():
    spec = importlib.util.spec_from_file_location("_ipt_members", SCRIPT)
    script = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(script)
    return script


def _script_pins(bundle):
    class Pins:
        ToolNotProvisionableError = LookupError

        @staticmethod
        def get_rules_bundle(name):
            return bundle

    return Pins


def _script_problem(bundle, rules: Path):
    """install-pinned-tool --check's answer, against ``bundle`` as the pin."""
    script = _script()
    with patch.object(script, "load_pins", return_value=_script_pins(bundle)):
        return script.installed_bundle_problem(bundle.name, rules, rules)


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


class TestTheContentsDigest:
    def test_it_is_the_digest_of_sorted_name_and_digest_lines(self):
        files = {
            name: hashlib.sha256(data).hexdigest()
            for name, data in GOOD_MEMBERS.items()
        }
        assert contents_digest(files) == _pinned_contents(GOOD_MEMBERS)

    def test_names_count_as_well_as_bytes(self):
        digest = hashlib.sha256(b"rule A { }\n").hexdigest()
        assert contents_digest({"a.guard": digest}) != contents_digest(
            {"b.guard": digest}
        )

    def test_the_script_computes_the_same_value(self):
        files = {
            name: hashlib.sha256(data).hexdigest()
            for name, data in GOOD_MEMBERS.items()
        }
        assert _script().contents_digest(files) == contents_digest(files)

    def test_an_uppercase_digest_in_the_pin_still_matches(self, tmp_path, bundle_zip):
        archive, bundle = bundle_zip
        _install(tmp_path, bundle, archive, [])
        upper = replace(bundle, contents_sha256=bundle.contents_sha256.upper())
        verify_installed_bundle(upper, tmp_path / "rules")
        assert _script_problem(upper, tmp_path / "rules") is None


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
        assert _leftovers(tmp_path / "rules") == []

    def test_a_digest_mismatch_installs_nothing(self, tmp_path, bundle_zip):
        archive, bundle = bundle_zip
        wrong = replace(bundle, sha256="0" * 64)
        with pytest.raises(ToolDownloadIntegrityError):
            _install(tmp_path, wrong, archive, [])
        assert _contents(tmp_path / "rules") == []

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

    def test_an_added_rule_file_is_removed_by_the_reinstall(self, tmp_path, bundle_zip):
        archive, bundle = bundle_zip
        calls = []
        final = _install(tmp_path, bundle, archive, calls)
        (final / "extra.guard").write_text("rule extra { }\n")
        _install(tmp_path, bundle, archive, calls)
        assert len(calls) == 2
        assert not (final / "extra.guard").exists()

    def test_force_reinstalls(self, tmp_path, bundle_zip):
        archive, bundle = bundle_zip
        calls = []
        _install(tmp_path, bundle, archive, calls)
        _install(tmp_path, bundle, archive, calls, force=True)
        assert len(calls) == 2


class TestTheInstallerChecksItsOwnExtraction:
    """The archive matches its pin, but what it extracts to is not the pinned set."""

    def test_extra_rule_files_in_the_archive_install_nothing(self, tmp_path):
        archive = _zip(
            tmp_path / "ruleset-build-v1.0.2.zip",
            {**GOOD_ENTRIES, "output/added.guard": "rule added { }\n"},
        )
        bundle = _pinned(archive)
        with pytest.raises(ToolDownloadIntegrityError, match="pinned contents"):
            _install(tmp_path, bundle, archive, [])
        assert _contents(tmp_path / "rules") == []

    def test_a_changed_rule_file_leaves_the_installed_bundle_alone(
        self, tmp_path, bundle_zip
    ):
        archive, bundle = bundle_zip
        final = _install(tmp_path, bundle, archive, [])
        before = _tree(final)
        changed = _zip(
            tmp_path / "changed.zip",
            {**GOOD_ENTRIES, "output/wa-Security-Pillar.guard": "rule other { }\n"},
        )
        repinned = replace(
            bundle, sha256=hashlib.sha256(changed.read_bytes()).hexdigest()
        )
        with pytest.raises(ToolDownloadIntegrityError, match="pinned contents"):
            _install(tmp_path, repinned, changed, [], force=True)
        assert _tree(final) == before
        assert _leftovers(tmp_path / "rules") == []


class TestOffline:
    def test_a_mismatch_with_no_network_refuses_with_the_reason(
        self, tmp_path, bundle_zip
    ):
        archive, bundle = bundle_zip
        final = _install(tmp_path, bundle, archive, [])
        (final / "wa-Security-Pillar.guard").write_text("rule weakened { }\n")
        before = _tree(final)
        calls = []
        with pytest.raises(RulesBundleUnavailable) as refused:
            _install(tmp_path, bundle, archive, calls, download=_offline(calls))
        message = str(refused.value)
        assert str(final) in message
        assert "do not match the pinned contents" in message
        assert "network access" in message and "ASH container image" in message
        assert len(calls) == 1
        assert _tree(final) == before, "the rules in place are left as they were"
        assert _leftovers(tmp_path / "rules") == []
        with pytest.raises(RulesBundleUnavailable, match="pinned contents"):
            verify_installed_bundle(bundle, tmp_path / "rules")

    def test_nothing_installed_and_no_network_says_so(self, tmp_path, bundle_zip):
        archive, bundle = bundle_zip
        calls = []
        with pytest.raises(RulesBundleUnavailable) as refused:
            _install(tmp_path, bundle, archive, calls, download=_offline(calls))
        message = str(refused.value)
        assert "are not installed" in message and "does not exist" in message
        assert "network access" in message and "ASH container image" in message
        assert _contents(tmp_path / "rules") == []

    def test_a_pinned_bundle_needs_no_network(self, tmp_path, bundle_zip):
        archive, bundle = bundle_zip
        final = _install(tmp_path, bundle, archive, [])
        calls = []
        assert _install(tmp_path, bundle, archive, calls, download=_offline(calls))
        assert calls == [] and (final / "wa-Security-Pillar.guard").is_file()


class _OsWithoutRename:
    """The module's ``os`` with ``replace`` refusing, and nothing else changed.

    Bound onto the module under test only, so the interpreter's own ``os``
    (and every other module's) keeps working while the test runs.
    """

    def __init__(self, error: OSError):
        self._error = error

    def replace(self, src, dst):
        raise self._error

    def __getattr__(self, name):
        return getattr(os, name)


class TestALocalFailureIsTheDocumentedRefusal:
    """Every local failure of the install is a RulesBundleUnavailable naming the
    remedy, as the docstring promises: the lock take and the two renames used
    to let the raw OSError out, past the conversion the mkdir and mkdtemp had."""

    @contextmanager
    def _refused_lock(self, path):
        raise PermissionError(errno.EACCES, "Permission denied", str(path))
        yield  # pragma: no cover - the generator shape contextmanager needs

    def test_a_lock_that_cannot_be_opened(self, tmp_path, bundle_zip):
        archive, bundle = bundle_zip
        with (
            patch(
                "automated_security_helper.utils.file_lock.exclusive_lock",
                self._refused_lock,
            ),
            pytest.raises(RulesBundleUnavailable) as refused,
        ):
            _install(tmp_path, bundle, archive, [])
        message = str(refused.value)
        assert "install lock" in message and "could not be opened" in message
        assert RULES_DIR_ENV in message and "Permission denied" in message
        assert isinstance(refused.value.__cause__, PermissionError)
        assert _contents(tmp_path / "rules") == []

    def test_a_lock_held_too_long_names_the_other_install(self, tmp_path, bundle_zip):
        archive, bundle = bundle_zip

        @contextmanager
        def held_elsewhere(path):
            raise TimeoutError(f"the lock on {path} was held for 30 seconds")
            yield  # pragma: no cover

        with (
            patch(
                "automated_security_helper.utils.file_lock.exclusive_lock",
                held_elsewhere,
            ),
            pytest.raises(RulesBundleUnavailable, match="another ASH process"),
        ):
            _install(tmp_path, bundle, archive, [])
        assert _contents(tmp_path / "rules") == []

    def test_a_rename_into_place_that_fails(self, tmp_path, bundle_zip, monkeypatch):
        archive, bundle = bundle_zip
        monkeypatch.setattr(
            rules_bundles,
            "os",
            _OsWithoutRename(PermissionError(errno.EACCES, "Permission denied")),
        )
        with pytest.raises(RulesBundleUnavailable) as refused:
            _install(tmp_path, bundle, archive, [])
        message = str(refused.value)
        assert "could not be moved into place" in message, message
        assert RULES_DIR_ENV in message
        assert _contents(tmp_path / "rules") == [], "the staging is cleaned up"

    def test_a_bundle_in_place_that_cannot_be_moved_aside(
        self, tmp_path, bundle_zip, monkeypatch
    ):
        archive, bundle = bundle_zip
        final = _install(tmp_path, bundle, archive, [])
        before = _tree(final)
        monkeypatch.setattr(
            rules_bundles,
            "os",
            _OsWithoutRename(PermissionError(errno.EACCES, "Permission denied")),
        )
        with pytest.raises(RulesBundleUnavailable) as refused:
            _install(tmp_path, bundle, archive, [], force=True)
        message = str(refused.value)
        assert "could not be moved aside" in message, message
        assert _tree(final) == before, "the rules in place are left as they were"
        assert _leftovers(tmp_path / "rules") == []


class TestVerify:
    def test_missing_install_names_the_remedy(self, tmp_path):
        with pytest.raises(RulesBundleUnavailable, match="ash dependencies install"):
            verify_installed_bundle(REAL, tmp_path)

    def test_a_clean_install_passes(self, tmp_path, bundle_zip):
        archive, bundle = bundle_zip
        final = _install(tmp_path, bundle, archive, [])
        installed = verify_installed_bundle(bundle, tmp_path / "rules")
        assert installed.directory == final
        assert sorted(installed.files) == sorted(GOOD_MEMBERS)

    def test_an_empty_directory_is_not_the_bundle(self, tmp_path, bundle_zip):
        _, bundle = bundle_zip
        (tmp_path / rules_bundles.bundle_dir_name(bundle)).mkdir()
        with pytest.raises(RulesBundleUnavailable, match="pinned contents"):
            verify_installed_bundle(bundle, tmp_path)

    @pytest.mark.parametrize(
        "manifest",
        [None, "{", "[]", json.dumps({"url": "https://example.invalid/x.zip"})],
        ids=["deleted", "unreadable", "malformed", "names another archive"],
    )
    def test_the_manifest_plays_no_part(self, tmp_path, bundle_zip, manifest):
        archive, bundle = bundle_zip
        final = _install(tmp_path, bundle, archive, [])
        if manifest is None:
            (final / MANIFEST_NAME).unlink()
        else:
            (final / MANIFEST_NAME).write_text(manifest)
        verify_installed_bundle(bundle, tmp_path / "rules")
        assert _script_problem(bundle, tmp_path / "rules") is None

    def test_a_rule_file_that_is_gone(self, tmp_path, bundle_zip):
        archive, bundle = bundle_zip
        final = _install(tmp_path, bundle, archive, [])
        (final / "wa-Security-Pillar.guard").unlink()
        with pytest.raises(RulesBundleUnavailable, match="pinned contents"):
            verify_installed_bundle(
                bundle, tmp_path / "rules", files=["cis-aws-benchmark-level-1.guard"]
            )

    def test_a_renamed_rule_file_is_refused(self, tmp_path, bundle_zip):
        archive, bundle = bundle_zip
        final = _install(tmp_path, bundle, archive, [])
        (final / "wa-Security-Pillar.guard").rename(final / "renamed.guard")
        with pytest.raises(RulesBundleUnavailable, match="pinned contents"):
            verify_installed_bundle(bundle, tmp_path / "rules")

    def test_an_added_rule_file_is_refused(self, tmp_path, bundle_zip):
        archive, bundle = bundle_zip
        final = _install(tmp_path, bundle, archive, [])
        (final / "extra.guard").write_text("rule extra { }\n")
        with pytest.raises(RulesBundleUnavailable, match="pinned contents"):
            verify_installed_bundle(bundle, tmp_path / "rules", files=["extra.guard"])

    def test_other_files_are_not_part_of_the_bundle(self, tmp_path, bundle_zip):
        archive, bundle = bundle_zip
        final = _install(tmp_path, bundle, archive, [])
        (final / "README.md").write_text("notes\n")
        (final / "rules.guard.bak").write_text("rule old { }\n")
        installed = verify_installed_bundle(bundle, tmp_path / "rules")
        assert sorted(installed.files) == sorted(GOOD_MEMBERS)
        with pytest.raises(RulesBundleUnavailable, match="is not part of"):
            verify_installed_bundle(bundle, tmp_path / "rules", files=["README.md"])

    def test_a_name_the_installer_would_not_write_is_refused(
        self, tmp_path, bundle_zip
    ):
        archive, bundle = bundle_zip
        final = _install(tmp_path, bundle, archive, [])
        (final / ".hidden.guard").write_text("rule hidden { }\n")
        with pytest.raises(RulesBundleUnavailable, match="does not write"):
            verify_installed_bundle(bundle, tmp_path / "rules")

    def test_a_directory_named_like_a_rule_file_is_refused(self, tmp_path, bundle_zip):
        archive, bundle = bundle_zip
        final = _install(tmp_path, bundle, archive, [])
        (final / "more.guard").mkdir()
        with pytest.raises(RulesBundleUnavailable, match="not a regular file"):
            verify_installed_bundle(bundle, tmp_path / "rules")

    @pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
    def test_a_linked_rule_file_with_the_pinned_bytes_is_refused(
        self, tmp_path, bundle_zip
    ):
        """The link's target lies outside the directory the bundle was installed
        into, so whoever can write it can change the rules after the check."""
        archive, bundle = bundle_zip
        final = _install(tmp_path, bundle, archive, [])
        elsewhere = tmp_path / "elsewhere.guard"
        elsewhere.write_bytes(GOOD_MEMBERS["wa-Security-Pillar.guard"])
        (final / "wa-Security-Pillar.guard").unlink()
        (final / "wa-Security-Pillar.guard").symlink_to(elsewhere)
        with pytest.raises(RulesBundleUnavailable, match="not a regular file"):
            verify_installed_bundle(bundle, tmp_path / "rules")
        assert "not a regular file" in str(_script_problem(bundle, tmp_path / "rules"))

    def test_a_file_where_the_directory_should_be(self, tmp_path, bundle_zip):
        _, bundle = bundle_zip
        (tmp_path / rules_bundles.bundle_dir_name(bundle)).write_text("x")
        with pytest.raises(RulesBundleUnavailable, match="is not a directory"):
            verify_installed_bundle(bundle, tmp_path)
        assert "is not a directory" in str(_script_problem(bundle, tmp_path))


def _edit_rule_and_rewrite_manifest(directory: Path) -> None:
    """Change one rule file, then rewrite the manifest beside it to match."""
    (directory / "wa-Security-Pillar.guard").write_text("rule weakened { }\n")
    manifest = json.loads((directory / MANIFEST_NAME).read_text())
    manifest["files"] = {
        name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
        for name in manifest["files"]
    }
    (directory / MANIFEST_NAME).write_text(json.dumps(manifest))


class TestAnEditedRuleWithARewrittenManifest:
    def test_the_verifier_refuses_it(self, tmp_path, bundle_zip):
        archive, bundle = bundle_zip
        final = _install(tmp_path, bundle, archive, [])
        _edit_rule_and_rewrite_manifest(final)
        with pytest.raises(RulesBundleUnavailable, match="pinned contents"):
            verify_installed_bundle(bundle, tmp_path / "rules")
        with pytest.raises(RulesBundleUnavailable, match="pinned contents"):
            verify_installed_bundle(
                bundle, tmp_path / "rules", files=["wa-Security-Pillar.guard"]
            )

    def test_the_installer_downloads_it_again(self, tmp_path, bundle_zip):
        archive, bundle = bundle_zip
        calls = []
        final = _install(tmp_path, bundle, archive, calls)
        _edit_rule_and_rewrite_manifest(final)
        _install(tmp_path, bundle, archive, calls)
        assert len(calls) == 2
        assert (final / "wa-Security-Pillar.guard").read_text() == "rule A { }\n"

    def test_the_nix_check_refuses_it(self, tmp_path, bundle_zip):
        archive, bundle = bundle_zip
        final = _install(tmp_path, bundle, archive, [])
        _edit_rule_and_rewrite_manifest(final)
        problem = _script_problem(bundle, tmp_path / "rules")
        assert problem is not None and "pinned contents" in problem


class TestTheTwoInstallersAgree:
    """The image installs with install-pinned-tool; ash dependencies install skips on
    what it wrote. A drift between the two would make every image re-download, or
    fail where the scan user cannot write the directory."""

    @staticmethod
    def _script_install(bundle, archive: Path, rules: Path, package_root: Path):
        script = _script()

        def download(url, target):
            target.write_bytes(archive.read_bytes())
            return hashlib.sha256(target.read_bytes()).hexdigest()

        with (
            patch.object(script, "load_pins", return_value=_script_pins(bundle)),
            patch.object(script, "download", side_effect=download),
        ):
            return script.install_bundle(bundle.name, rules, package_root)

    def test_both_write_the_same_directory(self, tmp_path, bundle_zip):
        archive, bundle = bundle_zip
        python_dir = _install(tmp_path / "py", bundle, archive, [])
        script_dir = self._script_install(bundle, archive, tmp_path / "sh", tmp_path)

        assert _tree(script_dir) == _tree(python_dir)
        verify_installed_bundle(bundle, tmp_path / "sh")
        assert _script_problem(bundle, tmp_path / "py" / "rules") is None

    def test_the_script_refuses_a_digest_mismatch(self, tmp_path, bundle_zip):
        archive, bundle = bundle_zip
        wrong = replace(bundle, sha256="0" * 64)
        with pytest.raises(SystemExit) as exited:
            self._script_install(wrong, archive, tmp_path / "sh", tmp_path)
        assert exited.value.code == 3
        assert list((tmp_path / "sh").iterdir()) == []

    def test_the_script_refuses_contents_that_are_not_pinned(
        self, tmp_path, bundle_zip, capsys
    ):
        archive, bundle = bundle_zip
        wrong = replace(bundle, contents_sha256="0" * 64)
        with pytest.raises(SystemExit) as exited:
            self._script_install(wrong, archive, tmp_path / "sh", tmp_path)
        assert exited.value.code == 3
        assert "pinned contents" in capsys.readouterr().err
        assert list((tmp_path / "sh").iterdir()) == []


class TestRefusedArchiveEntriesInBothInstallers:
    """The same refusals in rules_bundles.extract_bundle and the image's script."""

    def test_a_rule_file_named_like_a_directory_is_not_flattened(self, tmp_path):
        # parts[1] ends in .guard, so only the depth check keeps it out.
        archive = _zip(
            tmp_path / "b.zip",
            {
                "output/ok.guard": "rule A { }\n",
                "output/x.guard/inner.guard": "rule X { }\n",
            },
        )
        staging = tmp_path / "s"
        staging.mkdir()
        assert list(extract_bundle(archive, REAL, staging)) == ["ok.guard"]
        with zipfile.ZipFile(archive) as z:
            assert [name for _, name in _script()._bundle_members(z, REAL)] == [
                "ok.guard"
            ]

    def test_the_script_refuses_an_unsafe_member_name(self, tmp_path):
        archive = _zip(tmp_path / "b.zip", {"output/bad name.guard": "x"})
        with zipfile.ZipFile(archive) as z, pytest.raises(SystemExit, match="unsafe"):
            _script()._bundle_members(z, REAL)

    def test_two_names_that_differ_only_in_case_are_refused_by_both(self, tmp_path):
        # A case-insensitive filesystem (macOS, Windows) would write the second over
        # the first, so extract_bundle folds case before it compares names. The image's
        # script has to refuse the same archive, or the two installers disagree about
        # which archives are acceptable.
        archive = _zip(
            tmp_path / "b.zip",
            {
                "output/Rules.guard": "rule A { }\n",
                "output/rules.guard": "rule B { }\n",
            },
        )
        staging = tmp_path / "s"
        staging.mkdir()
        with pytest.raises(ToolDownloadIntegrityError, match="two members"):
            extract_bundle(archive, REAL, staging)
        with (
            zipfile.ZipFile(archive) as z,
            pytest.raises(SystemExit, match="two members"),
        ):
            _script()._bundle_members(z, REAL)

    def test_the_total_size_cap_is_enforced_on_bytes_read(self, tmp_path, monkeypatch):
        # Each member is under the per-member cap; together they exceed the total.
        monkeypatch.setattr(rules_bundles, "_MAX_TOTAL_BYTES", 100)
        archive = _zip(
            tmp_path / "b.zip",
            {"output/a.guard": "x" * 60, "output/b.guard": "y" * 60},
        )
        staging = tmp_path / "s"
        staging.mkdir()
        with pytest.raises(ToolDownloadIntegrityError, match="size cap"):
            extract_bundle(archive, REAL, staging)


def test_the_real_pin_is_well_formed():
    assert REAL.url.startswith(
        "https://github.com/aws-cloudformation/aws-guard-rules-registry/"
    )
    for digest in (REAL.sha256, REAL.contents_sha256):
        assert len(digest) == 64 and digest == digest.lower()
        int(digest, 16)
    assert REAL.contents_sha256 != REAL.sha256
    assert REAL.member_dir == "output" and REAL.member_suffix == ".guard"
