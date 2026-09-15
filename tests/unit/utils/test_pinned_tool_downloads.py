# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the pinned, digest-verified tool download path.

The test that carries the most weight here is
``test_corrupted_pinned_digest_is_rejected``: it changes a pinned digest and
asserts the install fails and leaves nothing behind. Without that test the digest
is a field that gets written to a receipt, not a check -- the same defect class as
a scanner that is absent and still reports success.

Nothing here touches the network. Each test builds a real archive on disk and
serves its bytes through a patched ``urlopen``, so the tar and zip handling, the
hashing and the receipt logic are all exercised against real bytes rather than
against mocks that agree with the implementation by construction.

One thing these tests deliberately cannot check, stated so nobody reads a green run
as covering it: **whether each pinned asset's ``member_name`` matches the executable
inside the real archive.** Every fixture here is built with the same member name the
code then looks for, so the two agree by construction. A wrong ``member_name`` for
any of the 16 pinned assets -- a vendor renaming its binary, or a typo in the table --
would pass this file and fail only against a real download. The controls for that are
``_extract_single_member``'s refusal to guess when zero members match, and CI, which
performs the real downloads on four platforms.
"""

import errno
import hashlib
import io
import json
import os
import platform
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.core.exceptions import (
    ToolDownloadIntegrityError,
    ToolNotProvisionableError,
)
from automated_security_helper.utils import download_utils, tool_downloads
from automated_security_helper.utils.download_utils import (
    RECEIPT_DIR_NAME,
    _extract_single_member,
    install_binary_from_url,
    install_pinned_tool,
    make_executable,
    read_receipt,
    receipt_path,
    receipt_root,
    sha256_file,
    verify_sha256,
)
from automated_security_helper.utils.tool_downloads import (
    _ASSET_TABLES,
    _DIGESTS,
    TOOL_VERSIONS,
    downloadable_tools,
    get_tool_asset,
    supported_platforms,
)

PAYLOAD = b"#!/bin/sh\necho pinned-tool-fixture\n"


def _make_tarball(path: Path, member_names) -> bytes:
    with tarfile.open(path, "w:gz") as archive:
        for name in member_names:
            info = tarfile.TarInfo(name=name)
            info.size = len(PAYLOAD)
            archive.addfile(info, io.BytesIO(PAYLOAD))
    return path.read_bytes()


def _make_zip(path: Path, member_names) -> bytes:
    with zipfile.ZipFile(path, "w") as archive:
        for name in member_names:
            archive.writestr(name, PAYLOAD)
    return path.read_bytes()


class _FakeResponse(io.BytesIO):
    """urlopen returns a context manager; BytesIO alone is not one."""

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()
        return False


def _serve(payload: bytes):
    """Patch download_utils' urlopen to serve exactly these bytes.

    A fresh response per call, via side_effect rather than return_value.
    _FakeResponse closes itself on __exit__, so a single shared instance made the
    second download inside one _serve context fail with "I/O operation on closed
    file" -- a test-harness artifact that would have read as a product bug.
    """
    return patch(
        "automated_security_helper.utils.download_utils.urllib.request.urlopen",
        side_effect=lambda *_a, **_k: _FakeResponse(payload),
    )


@pytest.fixture
def fake_grype_release(tmp_path):
    """A tar.gz laid out like grype's release asset, plus its real digest."""
    archive = tmp_path / "fixture" / "grype_fixture.tar.gz"
    archive.parent.mkdir(parents=True, exist_ok=True)
    payload = _make_tarball(archive, ["CHANGELOG.md", "LICENSE", "grype"])
    return payload, hashlib.sha256(payload).hexdigest()


def _pin(tool_asset_filename: str, digest: str):
    """Patch the pinned digest table so a fixture stands in for a real asset."""
    patched = dict(_DIGESTS)
    patched[tool_asset_filename] = digest
    return patch.object(tool_downloads, "_DIGESTS", patched)


def _grype_asset_filename() -> str:
    return _ASSET_TABLES["grype"][("linux", "amd64")]


def _plant_bin_dir_receipt(bin_dir: Path, binary_bytes: bytes, pinned: str) -> Path:
    """Write a well-formed receipt where receipts used to live, inside the bin dir.

    Everything about it is valid except its location, so a code path that reads from
    the bin directory would accept it.
    """
    planted = bin_dir / ".ash-install-receipts" / "grype.json"
    planted.parent.mkdir(parents=True, exist_ok=True)
    planted.write_text(
        json.dumps(
            {
                "url": get_tool_asset("grype", "linux", "amd64").url,
                "sha256": pinned,
                "installed_sha256": hashlib.sha256(binary_bytes).hexdigest(),
                "installed_as": "grype",
            }
        ),
        encoding="utf-8",
    )
    return planted


class TestDigestVerification:
    """The check itself."""

    def test_sha256_file_matches_hashlib(self, tmp_path):
        target = tmp_path / "blob"
        target.write_bytes(PAYLOAD)
        assert sha256_file(target) == hashlib.sha256(PAYLOAD).hexdigest()

    def test_verify_sha256_accepts_match_case_insensitively(self, tmp_path):
        target = tmp_path / "blob"
        target.write_bytes(PAYLOAD)
        expected = hashlib.sha256(PAYLOAD).hexdigest()
        assert verify_sha256(target, expected.upper(), "fixture") == expected

    def test_verify_sha256_raises_on_mismatch(self, tmp_path):
        target = tmp_path / "blob"
        target.write_bytes(PAYLOAD)
        with pytest.raises(ToolDownloadIntegrityError, match="SHA256 mismatch"):
            verify_sha256(target, "0" * 64, "fixture")

    def test_corrupted_pinned_digest_is_rejected(self, tmp_path, fake_grype_release):
        """Corrupt the pin, and the install must refuse and install nothing.

        This is the control that separates a checksum field from a checksum
        check. The bytes served are internally consistent -- they really are a
        grype-shaped tarball -- so the only thing that can reject them is the
        comparison against the pin.
        """
        payload, _real_digest = fake_grype_release
        bin_dir = tmp_path / "bin"

        with (
            _pin(_grype_asset_filename(), "0" * 64),
            _serve(payload),
            pytest.raises(ToolDownloadIntegrityError, match="Refusing to install"),
        ):
            install_pinned_tool("grype", "linux", "amd64", bin_dir)

        assert not (bin_dir / "grype").exists(), (
            "a rejected download must leave nothing installed"
        )
        assert read_receipt(bin_dir, "grype") is None

    def test_matching_pinned_digest_installs(self, tmp_path, fake_grype_release):
        """Positive control: the same path succeeds when the pin is right.

        Without this, the rejection test above could pass because the install
        path is broken for every input rather than because the digest was wrong.
        """
        payload, real_digest = fake_grype_release
        bin_dir = tmp_path / "bin"

        with _pin(_grype_asset_filename(), real_digest), _serve(payload):
            installed = install_pinned_tool("grype", "linux", "amd64", bin_dir)

        assert installed == bin_dir / "grype"
        assert installed.read_bytes() == PAYLOAD
        receipt = read_receipt(bin_dir, "grype")
        assert receipt["sha256"] == real_digest
        assert receipt["version"] == TOOL_VERSIONS["grype"]


class TestIdempotence:
    """A second install must not re-download."""

    def test_second_install_does_not_download(self, tmp_path, fake_grype_release):
        payload, real_digest = fake_grype_release
        bin_dir = tmp_path / "bin"

        with _pin(_grype_asset_filename(), real_digest), _serve(payload):
            install_pinned_tool("grype", "linux", "amd64", bin_dir)

        # Make any download attempt fail loudly rather than asserting on a call
        # count -- a call count can be satisfied by a cached response, while an
        # exception can only be avoided by not calling at all.
        exploding = patch(
            "automated_security_helper.utils.download_utils.download_file",
            side_effect=AssertionError("re-downloaded an already-installed tool"),
        )
        with _pin(_grype_asset_filename(), real_digest), exploding:
            again = install_pinned_tool("grype", "linux", "amd64", bin_dir)

        assert again == bin_dir / "grype"

    def test_force_reinstalls(self, tmp_path, fake_grype_release):
        payload, real_digest = fake_grype_release
        bin_dir = tmp_path / "bin"

        with _pin(_grype_asset_filename(), real_digest), _serve(payload):
            install_pinned_tool("grype", "linux", "amd64", bin_dir)

        with _pin(_grype_asset_filename(), real_digest), _serve(payload) as served:
            install_pinned_tool("grype", "linux", "amd64", bin_dir, force=True)
        assert served.called

    def test_changed_pin_reinstalls(self, tmp_path, fake_grype_release):
        """A receipt from a different digest must not satisfy the new pin."""
        payload, real_digest = fake_grype_release
        bin_dir = tmp_path / "bin"

        with _pin(_grype_asset_filename(), real_digest), _serve(payload):
            install_pinned_tool("grype", "linux", "amd64", bin_dir)

        other_payload = _make_tarball(tmp_path / "other.tar.gz", ["grype"])
        other_digest = hashlib.sha256(other_payload).hexdigest()
        assert other_digest != real_digest

        with _pin(_grype_asset_filename(), other_digest), _serve(other_payload) as served:
            install_pinned_tool("grype", "linux", "amd64", bin_dir)
        assert served.called
        assert read_receipt(bin_dir, "grype")["sha256"] == other_digest

    def test_missing_binary_with_receipt_reinstalls(self, tmp_path, fake_grype_release):
        """A receipt whose file was deleted must not count as installed."""
        payload, real_digest = fake_grype_release
        bin_dir = tmp_path / "bin"

        with _pin(_grype_asset_filename(), real_digest), _serve(payload):
            install_pinned_tool("grype", "linux", "amd64", bin_dir)
        (bin_dir / "grype").unlink()

        with _pin(_grype_asset_filename(), real_digest), _serve(payload) as served:
            install_pinned_tool("grype", "linux", "amd64", bin_dir)
        assert served.called

    def test_a_substituted_binary_is_reinstalled_not_trusted(
        self, tmp_path, fake_grype_release
    ):
        """The receipt must not vouch for bytes that changed after it was written.

        This is the case idempotence created and then had to close. The pinned
        digest covers the release *archive*, so it says nothing about the extracted
        executable -- a receipt match alone would report a replaced binary as
        "already installed" and skip it forever.

        Not hypothetical in ASH's own image: Dockerfile:243 makes ASH_BIN_PATH
        world-writable, :254 puts it first on PATH, and :253 and :328 both install
        into it. Before idempotence every install re-downloaded, so the second run
        overwrote a substitution; the redundant download was accidentally a
        self-healing property.
        """
        payload, real_digest = fake_grype_release
        bin_dir = tmp_path / "bin"

        with _pin(_grype_asset_filename(), real_digest), _serve(payload):
            installed = install_pinned_tool("grype", "linux", "amd64", bin_dir)

        # Stand in for a substituted scanner: same path, same receipt, other bytes.
        installed.write_bytes(b"#!/bin/sh\nexit 0\n")

        with _pin(_grype_asset_filename(), real_digest), _serve(payload) as served:
            install_pinned_tool("grype", "linux", "amd64", bin_dir)

        assert served.called, "a replaced binary was trusted instead of reinstalled"
        assert installed.read_bytes() == PAYLOAD

    def test_an_unpinned_download_is_never_cached(self, tmp_path):
        """Without a pinned digest there is nothing to be idempotent against.

        opengrep is in this state: create_url_download_command passes no digest, so
        its receipt records `sha256: null`. Comparing null to null matches, so a
        substituted opengrep -- fetched behind only a `startswith("https://")` check
        -- would be cached and skipped on every later install. Re-downloading is the
        conservative answer until opengrep gets a pin.
        """
        bin_dir = tmp_path / "bin"
        url = "https://example.invalid/opengrep"

        with _serve(PAYLOAD):
            install_binary_from_url(url, bin_dir, "opengrep")
        receipt = read_receipt(bin_dir, "opengrep")
        assert receipt["sha256"] is None, "fixture assumes an unpinned install"

        with _serve(PAYLOAD) as served:
            install_binary_from_url(url, bin_dir, "opengrep")
        assert served.called, "an unverified download was cached"

    def test_a_tampered_receipt_does_not_vouch_for_a_tampered_binary(
        self, tmp_path, monkeypatch, fake_grype_release
    ):
        """Replace the binary AND rewrite the receipt to match. Still reinstalls.

        This is the assertion the first version of the re-hash fix was missing.
        Re-hashing the binary only helps if the digest it is compared against is out
        of reach of whoever replaced it -- and receipts originally lived in
        `<bin dir>/.ash-install-receipts`, inside the directory ASH's own image
        chmods 777. Anything able to swap the binary could rewrite its receipt too,
        so `_already_installed` agreed with itself and skipped forever. The earlier
        test passed because it only touched the binary.

        Receipts now live outside any bin directory, and read_receipt refuses one in a
        group- or other-writable location. This test simulates the attacker winning
        anyway -- it writes a matching receipt by hand -- and asserts the install still
        re-downloads, because the receipt it finds is the one in the protected
        location rather than the planted one.
        """
        payload, real_digest = fake_grype_release
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setattr(Path, "home", classmethod(lambda _cls: home))
        bin_dir = tmp_path / "bin"

        with _pin(_grype_asset_filename(), real_digest), _serve(payload):
            installed = install_pinned_tool("grype", "linux", "amd64", bin_dir)

        # The receipt must not be anywhere under the bin directory.
        assert receipt_root() not in bin_dir.parents
        assert not (bin_dir / RECEIPT_DIR_NAME).exists()
        assert not (bin_dir / ".ash-install-receipts").exists()

        # Substitute the binary, then plant a receipt inside the bin directory that
        # vouches for it -- the exact move the old layout allowed.
        substitute = b"#!/bin/sh\nexit 0\n"
        installed.write_bytes(substitute)
        _plant_bin_dir_receipt(bin_dir, substitute, real_digest)

        with _pin(_grype_asset_filename(), real_digest), _serve(payload) as served:
            install_pinned_tool("grype", "linux", "amd64", bin_dir)
        assert served.called, "a planted receipt was allowed to vouch for a substitute"
        assert installed.read_bytes() == PAYLOAD

    def test_no_receipt_is_written_under_the_bin_directory(
        self, tmp_path, monkeypatch, fake_grype_release
    ):
        """The location property, asserted structurally -- which is the only way.

        A behavioral probe cannot isolate it, and it is worth writing down why rather
        than leaving a test whose name promises more than it delivers. Under a
        regression that puts receipts back in the bin directory, "the bin directory"
        and "the protected location" are the *same path*, so any sequence of planting
        and removing touches one file and no observable distinguishes the two. An
        earlier attempt here removed the protected receipt after planting one, which
        under that regression deleted the plant as well -- so it reinstalled either way
        and proved nothing.

        What does distinguish them is whether a receipt appears under the bin directory
        at all. That is checked here on its own, and the combined test above carries the
        same assertions; pointing receipt_path back at the bin directory fails both.
        """
        payload, real_digest = fake_grype_release
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setattr(Path, "home", classmethod(lambda _cls: home))
        bin_dir = tmp_path / "bin"

        with _pin(_grype_asset_filename(), real_digest), _serve(payload):
            install_pinned_tool("grype", "linux", "amd64", bin_dir)

        assert read_receipt(bin_dir, "grype") is not None, "no receipt was written"
        assert receipt_root() in receipt_path(bin_dir, "grype").parents
        assert bin_dir not in receipt_path(bin_dir, "grype").parents
        for name in (RECEIPT_DIR_NAME, ".ash-install-receipts"):
            assert not (bin_dir / name).exists(), (
                f"a receipt directory was created at {bin_dir / name}; the bin "
                "directory is world-writable in ASH's image and cannot hold a trust "
                "anchor"
            )

    @pytest.mark.skipif(
        platform.system() == "Windows", reason="POSIX mode bits only"
    )
    def test_a_group_writable_receipt_is_not_trusted(
        self, tmp_path, monkeypatch, fake_grype_release
    ):
        """A receipt anyone can rewrite is worth nothing, so it is not read.

        Covers the case where the receipt is in the right place but the directory's
        mode has been loosened -- by a blanket `chmod -R` in an image build, say.
        """
        payload, real_digest = fake_grype_release
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setattr(Path, "home", classmethod(lambda _cls: home))
        bin_dir = tmp_path / "bin"

        with _pin(_grype_asset_filename(), real_digest), _serve(payload):
            install_pinned_tool("grype", "linux", "amd64", bin_dir)
        assert read_receipt(bin_dir, "grype") is not None

        receipt_path(bin_dir, "grype").parent.chmod(0o777)
        assert read_receipt(bin_dir, "grype") is None

        with _pin(_grype_asset_filename(), real_digest), _serve(payload) as served:
            install_pinned_tool("grype", "linux", "amd64", bin_dir)
        assert served.called

    def test_a_receipt_that_is_not_an_object_is_ignored(self, tmp_path, monkeypatch):
        """read_receipt promises None for anything it cannot read.

        `[]` is valid JSON and has no .get(), so returning it crashed the caller
        with AttributeError instead of triggering a reinstall.
        """
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setattr(Path, "home", classmethod(lambda _cls: home))
        bin_dir = tmp_path / "bin"
        path = receipt_path(bin_dir, "grype")
        path.parent.mkdir(parents=True, mode=0o700)
        path.write_text("[]", encoding="utf-8")
        assert read_receipt(bin_dir, "grype") is None

    def test_binary_without_receipt_reinstalls(self, tmp_path, fake_grype_release):
        """A binary ASH did not install is not assumed to be the pinned version."""
        payload, real_digest = fake_grype_release
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir(parents=True)
        (bin_dir / "grype").write_bytes(b"some other grype")

        with _pin(_grype_asset_filename(), real_digest), _serve(payload) as served:
            install_pinned_tool("grype", "linux", "amd64", bin_dir)
        assert served.called
        assert (bin_dir / "grype").read_bytes() == PAYLOAD


class TestArchiveExtraction:
    def test_extracts_named_member_from_tarball(self, tmp_path):
        archive = tmp_path / "a.tar.gz"
        _make_tarball(archive, ["LICENSE", "grype"])
        target = tmp_path / "out" / "grype"
        # The digest of the extracted member is returned, not the target path: it is
        # what the install receipt records, and the caller must not re-derive it from
        # the file afterwards. See _finalize_staged.
        assert _extract_single_member(archive, "grype", target) == (
            hashlib.sha256(PAYLOAD).hexdigest()
        )
        assert target.read_bytes() == PAYLOAD

    def test_extracts_named_member_from_zip(self, tmp_path):
        archive = tmp_path / "a.zip"
        _make_zip(archive, ["LICENSE", "grype.exe"])
        target = tmp_path / "out" / "grype.exe"
        _extract_single_member(archive, "grype.exe", target)
        assert target.read_bytes() == PAYLOAD

    def test_finds_member_in_subdirectory(self, tmp_path):
        """A vendor moving the binary below the archive root keeps working."""
        archive = tmp_path / "a.tar.gz"
        _make_tarball(archive, ["dist/linux/grype"])
        target = tmp_path / "grype"
        _extract_single_member(archive, "grype", target)
        assert target.read_bytes() == PAYLOAD

    def test_rejects_archive_without_the_member(self, tmp_path):
        archive = tmp_path / "a.tar.gz"
        _make_tarball(archive, ["LICENSE"])
        with pytest.raises(ToolDownloadIntegrityError, match="no member named"):
            _extract_single_member(archive, "grype", tmp_path / "grype")

    def test_rejects_archive_with_two_matching_members(self, tmp_path):
        archive = tmp_path / "a.tar.gz"
        _make_tarball(archive, ["grype", "backup/grype"])
        with pytest.raises(ToolDownloadIntegrityError, match="refusing to guess"):
            _extract_single_member(archive, "grype", tmp_path / "grype")

    def test_traversal_entry_cannot_escape_the_target(self, tmp_path):
        """An archive path is never used as a destination, so it cannot escape.

        The member is named `../../../../grype`. Extraction writes to the target
        the caller named and nowhere else, so the escape has no effect.
        """
        archive = tmp_path / "a.tar.gz"
        _make_tarball(archive, ["../../../../grype"])
        bin_dir = tmp_path / "nested" / "bin"
        target = bin_dir / "grype"
        _extract_single_member(archive, "grype", target)
        # The load-bearing assertion: the bytes landed at the caller's path. The
        # traversal name had no effect because it was never used as a destination.
        assert target.read_bytes() == PAYLOAD
        # Where `../../../../grype` would have escaped to, had the archive path been
        # honoured. Resolved explicitly rather than guessed at: four levels up from
        # tmp_path/nested/bin is tmp_path.parent.parent.
        escaped = (bin_dir / "../../../../grype").resolve()
        assert escaped != target
        assert not escaped.exists(), f"extraction escaped to {escaped}"

    def test_zip_traversal_entry_cannot_escape_the_target(self, tmp_path):
        """Same property for zips, which take a different code path.

        The tar branch and the zip branch locate and write their member separately,
        so a fix applied to one proves nothing about the other.
        """
        archive = tmp_path / "a.zip"
        _make_zip(archive, ["../../../../grype.exe"])
        bin_dir = tmp_path / "nested" / "bin"
        target = bin_dir / "grype.exe"
        _extract_single_member(archive, "grype.exe", target)
        assert target.read_bytes() == PAYLOAD
        escaped = (bin_dir / "../../../../grype.exe").resolve()
        assert not escaped.exists(), f"extraction escaped to {escaped}"

    @pytest.mark.skipif(
        platform.system() == "Windows",
        reason="symlink creation needs elevation on Windows",
    )
    def test_a_symlink_at_the_target_is_replaced_not_written_through(self, tmp_path):
        """A planted symlink must not receive the extracted binary.

        Reachable rather than theoretical: ASH's image makes ASH_BIN_PATH
        world-writable and puts it first on PATH, and ASH executes repository code
        during a scan, so a scanned project can plant the link before a later
        install. A plain `open(target, "wb")` follows the link and writes the
        vendor's binary into whatever it points at, then chmods that file +x.
        """
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        victim = tmp_path / "victim.txt"
        victim.write_bytes(b"do not touch me")
        target = bin_dir / "grype"
        target.symlink_to(victim)

        archive = tmp_path / "a.tar.gz"
        _make_tarball(archive, ["grype"])
        _extract_single_member(archive, "grype", target)

        assert victim.read_bytes() == b"do not touch me", (
            "the symlink target was written through"
        )
        assert not target.is_symlink(), "the symlink survived the install"
        assert target.read_bytes() == PAYLOAD

    def test_a_failed_extraction_leaves_no_partial_file(self, tmp_path):
        """An archive missing its member must not leave a staging file behind."""
        archive = tmp_path / "a.tar.gz"
        _make_tarball(archive, ["LICENSE"])
        target = tmp_path / "bin" / "grype"
        with pytest.raises(ToolDownloadIntegrityError):
            _extract_single_member(archive, "grype", target)
        assert not target.exists()
        assert not target.with_name("grype.ash-partial").exists()


class TestUnarchivedDownloadPath:
    """download_file / install_binary_from_url -- the opengrep path.

    A separate code path from the archive extraction, and the one that runs
    unconditionally: opengrep passes no pinned digest, so idempotence never applies
    and every install re-downloads. It needed the same symlink treatment and did not
    have it.
    """

    @pytest.mark.skipif(
        platform.system() == "Windows",
        reason="symlink creation needs elevation on Windows",
    )
    def test_a_symlink_at_the_destination_is_replaced_not_written_through(
        self, tmp_path
    ):
        """`shutil.move` was not sufficient here, and proving that needs EXDEV.

        shutil.move is os.rename, which is symlink-safe -- but only while source and
        destination share a filesystem. On EXDEV it falls back through copy2 to
        copyfile, which does `open(dst, "wb")` and follows a link. The source is a
        NamedTemporaryFile in TMPDIR and the destination is ASH_BIN_PATH, so a
        relocated TMPDIR or a `--tmpfs /tmp` container puts that fallback on the
        ordinary path rather than an exotic one.

        os.rename is made to raise EXDEV for the duration, because without it this
        test proves nothing: on a machine where TMPDIR and the destination share a
        filesystem -- which is the common case, and was the case here -- the old
        shutil.move code passes this test. Measured: with os.rename left alone, the
        mutation restoring shutil.move left the whole file green.

        The patch targets os.rename specifically and not os.replace, which is what the
        fixed code calls, so the fix stays exercised while the old path is forced down
        its unsafe branch.
        """
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        victim = tmp_path / "victim.txt"
        victim.write_bytes(b"do not touch me")
        (bin_dir / "opengrep").symlink_to(victim)

        def _cross_device(*_args, **_kwargs):
            raise OSError(errno.EXDEV, "Invalid cross-device link")

        with _serve(PAYLOAD), patch("os.rename", side_effect=_cross_device):
            install_binary_from_url(
                "https://example.invalid/opengrep", bin_dir, "opengrep"
            )

        assert victim.read_bytes() == b"do not touch me", (
            "the symlink target was written through"
        )
        assert not (bin_dir / "opengrep").is_symlink()
        assert (bin_dir / "opengrep").read_bytes() == PAYLOAD

    @pytest.mark.skipif(
        platform.system() == "Windows", reason="POSIX mode bits only"
    )
    def test_make_executable_refuses_to_act_through_a_symlink(self, tmp_path):
        """Path.chmod follows links, so it would have made the target executable."""
        victim = tmp_path / "victim.txt"
        victim.write_bytes(b"data")
        victim.chmod(0o600)
        link = tmp_path / "link"
        link.symlink_to(victim)

        make_executable(link)

        assert victim.stat().st_mode & 0o111 == 0, (
            "make_executable followed the link and made its target executable"
        )


class TestStagingCannotBeRacedOrGuessed:
    """The staging path is both unguessable and re-verified after the rename.

    O_CREAT|O_EXCL|O_NOFOLLOW at a predictable name stops a symlink being *planted*
    there, and stops nothing about ``rename``. In a 0777 directory with no sticky bit
    -- which is what ASH's image leaves ASH_BIN_PATH as (Dockerfile:243) -- rename
    permission comes from the directory's write bit, not the file's, so anyone with
    write access to that directory could rename their own file over the staging path
    between the open and the replace. The receipt written afterwards would then record
    *their* digest, and `_already_installed` would agree with it forever: the same
    persistent-trust outcome that moving receipts out of the bin directory closed,
    reached through a different door.
    """

    def test_the_staging_name_is_not_predictable(self, tmp_path):
        """Two installs of the same target must not reuse one staging name.

        A guessable name is the precondition for the race, so it is asserted directly
        rather than only through its consequence.
        """
        names = []
        real_replace = os.replace

        def capture(src, dst):
            names.append(Path(src).name)
            return real_replace(src, dst)

        bin_dir = tmp_path / "bin"
        for _ in range(2):
            with _serve(PAYLOAD), patch("os.replace", side_effect=capture):
                install_binary_from_url(
                    "https://example.invalid/opengrep", bin_dir, "opengrep", force=True
                )

        assert len(names) == 2
        assert names[0] != names[1], f"staging name was reused: {names[0]}"
        assert "opengrep.ash-partial" not in names, (
            "staging used the old predictable name"
        )

    def test_bytes_swapped_before_the_rename_are_refused(self, tmp_path):
        """Simulate winning the race, and the install must refuse the result.

        os.replace is wrapped so that the staged file is overwritten with other bytes
        immediately before it is moved into place -- which is exactly what an attacker
        who renames over the staging path achieves. The post-rename re-hash is the only
        thing that can catch this, and without it the receipt would record the swapped
        bytes as ASH's own.
        """
        bin_dir = tmp_path / "bin"
        real_replace = os.replace

        def swap_then_replace(src, dst):
            Path(src).write_bytes(b"attacker payload")
            return real_replace(src, dst)

        with (
            _serve(PAYLOAD),
            patch("os.replace", side_effect=swap_then_replace),
            pytest.raises(ToolDownloadIntegrityError, match="does not match the bytes"),
        ):
            install_binary_from_url(
                "https://example.invalid/opengrep", bin_dir, "opengrep"
            )

        assert not (bin_dir / "opengrep").exists(), (
            "swapped bytes were left at the install path"
        )

    def test_the_archive_path_refuses_a_swap_too(self, tmp_path, fake_grype_release):
        """Both install paths stage, so both need the check."""
        payload, real_digest = fake_grype_release
        bin_dir = tmp_path / "bin"
        real_replace = os.replace

        def swap_then_replace(src, dst):
            Path(src).write_bytes(b"attacker payload")
            return real_replace(src, dst)

        with (
            _pin(_grype_asset_filename(), real_digest),
            _serve(payload),
            patch("os.replace", side_effect=swap_then_replace),
            pytest.raises(ToolDownloadIntegrityError, match="does not match the bytes"),
        ):
            install_pinned_tool("grype", "linux", "amd64", bin_dir)

        assert not (bin_dir / "grype").exists()


class TestTheVerifiedDigestIsTheOneRecorded:
    """The digest checked against the pin is the digest written into the receipt.

    Every stage used to re-derive a digest from bytes it had just read, so the receipt
    recorded a fresh hash of the target taken *after* ``make_executable`` -- and on macOS
    after ``unquarantine_macos_binary``, which spawns ``xattr`` as a subprocess. Anything
    that replaced the target in that window got its own digest recorded as ASH's, and
    ``_already_installed`` then re-hashed the file, agreed with the receipt, and skipped
    the download on every later run. That is verbatim the outcome ``_finalize_staged``'s
    docstring claims to have closed; its post-rename check was necessary and not
    sufficient, because the result was thrown away before the receipt was written.

    What these tests turn on, and the reason they are written this way: an assertion that
    "the receipt matches the file on disk" passes before *and* after the fix, because
    before the fix both are the substitute. The only thing that separates the two is
    whether the receipt matches the digest that was actually **verified**.
    """

    @staticmethod
    def _swap_during_the_window(substitute: bytes):
        """Replace the installed file from inside the post-verification window.

        Driven from ``make_executable``, which is a real call that sits in that window
        rather than a seam invented for the test: both install paths call it after the
        bytes have been verified at the target and before the receipt is written.
        """
        real_make_executable = download_utils.make_executable

        def swap_then_chmod(file_path):
            Path(file_path).write_bytes(substitute)
            return real_make_executable(file_path)

        return patch.object(download_utils, "make_executable", swap_then_chmod)

    def test_the_archive_path_records_the_verified_digest(
        self, tmp_path, monkeypatch, fake_grype_release
    ):
        payload, real_digest = fake_grype_release
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setattr(Path, "home", classmethod(lambda _cls: home))
        bin_dir = tmp_path / "bin"
        substitute = b"#!/bin/sh\nexit 0\n"

        with (
            _pin(_grype_asset_filename(), real_digest),
            _serve(payload),
            self._swap_during_the_window(substitute),
        ):
            install_pinned_tool("grype", "linux", "amd64", bin_dir)

        receipt = read_receipt(bin_dir, "grype")
        assert receipt["installed_sha256"] != hashlib.sha256(substitute).hexdigest(), (
            "the receipt recorded the substituted binary's digest as ASH's own"
        )
        assert receipt["installed_sha256"] == hashlib.sha256(PAYLOAD).hexdigest(), (
            "the receipt does not record the digest that was verified"
        )

    def test_a_binary_swapped_in_that_window_is_reinstalled_not_trusted(
        self, tmp_path, monkeypatch, fake_grype_release
    ):
        """The outcome the receipt field only stands in for.

        A receipt naming the substitute's digest makes ``_already_installed`` agree with
        the substitute forever, in the one directory ASH's image makes world-writable.
        """
        payload, real_digest = fake_grype_release
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setattr(Path, "home", classmethod(lambda _cls: home))
        bin_dir = tmp_path / "bin"

        with (
            _pin(_grype_asset_filename(), real_digest),
            _serve(payload),
            self._swap_during_the_window(b"#!/bin/sh\nexit 0\n"),
        ):
            installed = install_pinned_tool("grype", "linux", "amd64", bin_dir)

        with _pin(_grype_asset_filename(), real_digest), _serve(payload) as served:
            install_pinned_tool("grype", "linux", "amd64", bin_dir)

        assert served.called, (
            "a binary substituted before the receipt was written was trusted forever"
        )
        assert installed.read_bytes() == PAYLOAD

    def test_the_unarchived_path_records_the_verified_digest_too(
        self, tmp_path, monkeypatch
    ):
        """install_binary_from_url writes its own receipt, from its own call site.

        Two separate lines re-hashed the target, so fixing one proves nothing about the
        other. A pin is passed here -- unlike opengrep, which has none -- because without
        one there is no verified digest for the receipt to disagree with.
        """
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setattr(Path, "home", classmethod(lambda _cls: home))
        bin_dir = tmp_path / "bin"
        substitute = b"#!/bin/sh\nexit 0\n"

        with _serve(PAYLOAD), self._swap_during_the_window(substitute):
            install_binary_from_url(
                "https://example.invalid/opengrep",
                bin_dir,
                "opengrep",
                expected_sha256=hashlib.sha256(PAYLOAD).hexdigest(),
            )

        receipt = read_receipt(bin_dir, "opengrep")
        assert receipt["installed_sha256"] != hashlib.sha256(substitute).hexdigest()
        assert receipt["installed_sha256"] == hashlib.sha256(PAYLOAD).hexdigest()


class TestTheInstallIsCheckedAgainstThePinNotAgainstItself:
    """``_replace_atomically`` took no pinned digest, so it verified its own reading.

    ``download_file`` verified the temporary file against the pin and discarded the
    result; ``_replace_atomically`` then reopened that file, streamed it, and handed its
    own ``hexdigest()`` to ``_finalize_staged`` as the expected value. Two separate reads
    of a file in TMPDIR, checked against each other rather than against the pin.
    ``verify_sha256`` reads the whole asset -- 30-100MB for syft and trivy -- so the
    window is hundreds of milliseconds, and the sticky bit on /tmp does not constrain a
    process running as the same user, which is what ASH has while it executes repository
    code during a scan.
    """

    def test_an_asset_swapped_after_verification_is_refused(
        self, tmp_path, fake_grype_release
    ):
        payload, real_digest = fake_grype_release
        bin_dir = tmp_path / "bin"

        # A second archive that is equally valid: same shape, same member, different
        # bytes. Junk would be rejected by the extractor for an unrelated reason and the
        # test would pass against the defect it is supposed to catch.
        other = _make_tarball(tmp_path / "other.tar.gz", ["grype", "EXTRA"])
        other_digest = hashlib.sha256(other).hexdigest()
        assert other_digest != real_digest

        real_verify = download_utils.verify_sha256

        def verify_then_swap(file_path, expected_sha256, source):
            actual = real_verify(file_path, expected_sha256, source)
            Path(file_path).write_bytes(other)
            return actual

        with (
            _pin(_grype_asset_filename(), real_digest),
            _serve(payload),
            patch.object(download_utils, "verify_sha256", verify_then_swap),
            pytest.raises(
                ToolDownloadIntegrityError, match="does not match the bytes"
            ) as raised,
        ):
            install_pinned_tool("grype", "linux", "amd64", bin_dir)

        # The pin is what it was compared against. Under the defect the expected value
        # was other_digest -- the swapped bytes agreeing with themselves -- so naming
        # both values is what distinguishes a real check from a self-consistent one.
        assert real_digest in str(raised.value)
        assert other_digest in str(raised.value)
        assert not (bin_dir / "grype").exists()
        assert read_receipt(bin_dir, "grype") is None


class TestUnrecognizedArchives:
    """An asset that is not the archive its name implies is refused as such.

    Dispatch is on the last two suffixes, so anything not ending ``.zip`` fell through to
    ``tarfile.open(..., "r:*")`` and surfaced ``tarfile.ReadError`` -- outside the
    ``ToolDownloadIntegrityError`` contract the rest of this module honors and three of
    its docstrings promise. Nothing in ASH catches either type today, so what this buys
    is a diagnosable message and a contract that holds, not a changed decision.
    """

    def test_an_asset_that_is_no_archive_at_all_raises_the_typed_error(self, tmp_path):
        asset = tmp_path / "grype_1.2.3_linux_amd64"
        asset.write_bytes(b"\x7fELF and nothing archive-shaped after it")
        target = tmp_path / "bin" / "grype"

        with pytest.raises(
            ToolDownloadIntegrityError, match="not a readable zip or tar archive"
        ):
            _extract_single_member(asset, "grype", target)

        assert not target.exists()
        assert not list(target.parent.glob("*.ash-partial")), (
            "a rejected archive left a staging file behind"
        )

    def test_a_corrupt_zip_raises_the_typed_error(self, tmp_path):
        """The zip branch raises BadZipFile, not ReadError, so it needs its own arm."""
        asset = tmp_path / "syft_1.2.3_windows_amd64.zip"
        asset.write_bytes(b"PK\x03\x04 truncated before anything useful")
        target = tmp_path / "bin" / "syft.exe"

        with pytest.raises(
            ToolDownloadIntegrityError, match="not a readable zip or tar archive"
        ):
            _extract_single_member(asset, "syft.exe", target)

        assert not target.exists()
        assert not list(target.parent.glob("*.ash-partial"))


@pytest.mark.skipif(platform.system() == "Windows", reason="POSIX mode bits only")
class TestReceiptDirectoryPermissions:
    """Every level ASH creates *for receipts* is as trustworthy as the receipt itself.

    The receipt store is the subtree from ``receipt_root()`` down. Its parent, ``~/.ash``,
    is ASH's general per-user directory -- and the parent of the default ASH_BIN_PATH,
    ``~/.ash/bin`` -- so it is out of scope here for reasons ``_private_dir`` spells out.
    """

    def test_every_created_level_is_private_under_a_loose_umask(
        self, tmp_path, monkeypatch, fake_grype_release
    ):
        """`mkdir(parents=True, mode=0o700)` does not do this.

        CPython applies the mode to the final component only; parents get 0o777 masked
        by the umask. Measured under umask 002: ~/.ash/install-receipts came out 0o775
        while only the leaf was 0o700 -- which lets a group member rename the key
        directory away and plant a conforming 0700/0600 receipt.
        """
        payload, real_digest = fake_grype_release
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setattr(Path, "home", classmethod(lambda _cls: home))
        old_umask = os.umask(0o002)
        try:
            with _pin(_grype_asset_filename(), real_digest), _serve(payload):
                install_pinned_tool("grype", "linux", "amd64", tmp_path / "bin")
        finally:
            os.umask(old_umask)

        path = receipt_path(tmp_path / "bin", "grype")
        assert path.is_file()
        for level in [path.parent, receipt_root()]:
            mode = level.stat().st_mode & 0o777
            assert mode & 0o022 == 0, f"{level} is {oct(mode)}, writable beyond owner"

        # And ~/.ash is left exactly as the umask made it. Asserted rather than left
        # implicit: narrowing a directory the receipt store does not own is what made a
        # foreign-owned ~/.ash disable idempotence, and _receipt_trust_chain does not
        # extend up here anyway.
        assert receipt_root().parent.stat().st_mode & 0o777 == 0o775

    def test_the_receipt_survives_a_chmod_failure_outside_the_receipt_store(
        self, tmp_path, monkeypatch, fake_grype_release
    ):
        """A permission problem on ~/.ash must not cost the receipt.

        ~/.ash is shared with the default bin directory and with anything else ASH keeps
        per-user. If it already exists owned by root -- from an earlier `sudo ash` run --
        then chmodding it raises PermissionError, `write_receipt` swallows that because
        receipts are best-effort by design, and install idempotence is off permanently
        behind one warning, for a reason that has nothing to do with receipts.

        os.chmod is made to fail for that one path, because reproducing a foreign owner
        needs a second uid and a test cannot have one. Everything else still chmods for
        real, so the modes the previous test asserts stay exercised.
        """
        payload, real_digest = fake_grype_release
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setattr(Path, "home", classmethod(lambda _cls: home))
        bin_dir = tmp_path / "bin"
        shared = receipt_root().parent
        shared.mkdir(parents=True, exist_ok=True)
        real_chmod = os.chmod

        def refuse_shared(path, mode, *args, **kwargs):
            if Path(path) == shared:
                raise PermissionError(errno.EPERM, "Operation not permitted", str(path))
            return real_chmod(path, mode, *args, **kwargs)

        with (
            _pin(_grype_asset_filename(), real_digest),
            _serve(payload),
            patch("os.chmod", side_effect=refuse_shared),
        ):
            install_pinned_tool("grype", "linux", "amd64", bin_dir)

        assert read_receipt(bin_dir, "grype") is not None, (
            "a chmod failure on ~/.ash lost the receipt, so idempotence is off for good"
        )

        # The consequence, not just the artifact: the next install skips the download.
        exploding = patch(
            "automated_security_helper.utils.download_utils.download_file",
            side_effect=AssertionError("re-downloaded an already-installed tool"),
        )
        with _pin(_grype_asset_filename(), real_digest), exploding:
            install_pinned_tool("grype", "linux", "amd64", bin_dir)

    def test_a_loose_ancestor_invalidates_the_receipt(
        self, tmp_path, monkeypatch, fake_grype_release
    ):
        """Checking the file and its immediate parent was not enough.

        The key directory can be renamed away by anyone who can write its parent, so a
        loose grandparent is as good as a loose parent.
        """
        payload, real_digest = fake_grype_release
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setattr(Path, "home", classmethod(lambda _cls: home))
        bin_dir = tmp_path / "bin"

        with _pin(_grype_asset_filename(), real_digest), _serve(payload):
            install_pinned_tool("grype", "linux", "amd64", bin_dir)
        assert read_receipt(bin_dir, "grype") is not None

        # Loosen the grandparent, leaving the receipt and its own directory tight.
        receipt_root().chmod(0o777)
        assert read_receipt(bin_dir, "grype") is None

        with _pin(_grype_asset_filename(), real_digest), _serve(payload) as served:
            install_pinned_tool("grype", "linux", "amd64", bin_dir)
        assert served.called


class TestAssetResolution:
    def test_downloadable_tools(self):
        assert downloadable_tools() == ["grype", "syft", "trivy"]

    @pytest.mark.parametrize("tool", ["grype", "syft", "trivy"])
    def test_linux_and_darwin_are_provisionable_on_both_arches(self, tool):
        pairs = supported_platforms(tool)
        for target in [
            ("linux", "amd64"),
            ("linux", "arm64"),
            ("darwin", "amd64"),
            ("darwin", "arm64"),
        ]:
            assert target in pairs, f"{tool} should be provisionable on {target}"

    @pytest.mark.parametrize("tool", ["grype", "trivy"])
    def test_windows_arm64_is_refused_not_approximated(self, tool):
        """Upstream publishes no windows/arm64 build for these two.

        Refusing is the point: falling back to the amd64 asset would install a
        binary that fails at exec time, and that shows up in a scan report as an
        execution failure rather than as a tool that was never installable.
        """
        with pytest.raises(ToolNotProvisionableError, match="publishes no release asset"):
            get_tool_asset(tool, "windows", "arm64")

    def test_unknown_tool_is_refused(self):
        with pytest.raises(ToolNotProvisionableError, match="no release-asset download"):
            get_tool_asset("nonexistent", "linux", "amd64")

    def test_windows_assets_install_with_exe_suffix(self):
        asset = get_tool_asset("syft", "windows", "amd64")
        assert asset.install_as == "syft.exe"
        assert asset.member_name == "syft.exe"

    def test_asset_url_carries_the_pinned_version(self):
        asset = get_tool_asset("trivy", "linux", "arm64")
        assert TOOL_VERSIONS["trivy"] in asset.url
        assert asset.sha256 == _DIGESTS[asset.url.split("/")[-1]]

    def test_every_asset_has_a_pinned_digest(self):
        """Guards the half-applied version bump.

        Bumping a version in the asset table without replacing the digests would
        otherwise be caught only at install time, on whichever platform ran
        first. This makes the two tables prove they agree.
        """
        missing = [
            filename
            for table in _ASSET_TABLES.values()
            for filename in table.values()
            if filename not in _DIGESTS
        ]
        assert missing == []

    def test_no_orphan_digests(self):
        referenced = {
            filename for table in _ASSET_TABLES.values() for filename in table.values()
        }
        assert sorted(set(_DIGESTS) - referenced) == []

    def test_pinned_versions_appear_in_their_asset_filenames(self):
        for tool, version in TOOL_VERSIONS.items():
            bare = version.lstrip("v")
            for filename in _ASSET_TABLES[tool].values():
                assert bare in filename, (
                    f"{tool} is pinned to {version} but asset {filename} does not "
                    "carry that version"
                )

    def test_the_ferret_suppression_range_still_bounds_the_digest_table(self):
        """The community config suppresses API_KEY_OR_SECRET over a line range.

        A range wider than the table swallows a real secret written into the
        surrounding prose; a range narrower than it lets the 16 false positives back
        in. Either way the config and the file have to agree, and nothing else checks
        that they do -- the first version of the range covered ten lines of comment
        above the table.
        """
        import yaml

        repo_root = Path(__file__).parents[3]
        source = (
            repo_root / "automated_security_helper" / "utils" / "tool_downloads.py"
        ).read_text(encoding="utf-8").splitlines()
        # 1-based, matching how the suppression and every editor count lines.
        opens = next(
            i + 1 for i, line in enumerate(source) if line.startswith("_DIGESTS")
        )
        closes = next(i + 1 for i, line in enumerate(source[opens:], opens) if line == "}")

        config = yaml.safe_load(
            (repo_root / ".ash" / ".ash_community_plugins.yaml").read_text(
                encoding="utf-8"
            )
        )
        entries = [
            s
            for s in config["global_settings"]["suppressions"]
            if s.get("path", "").endswith("utils/tool_downloads.py")
        ]
        assert len(entries) == 1, "expected exactly one suppression for tool_downloads"
        entry = entries[0]
        assert entry["line_start"] == opens, (
            f"suppression starts at {entry['line_start']} but _DIGESTS opens at {opens}"
        )
        assert entry["line_end"] == closes, (
            f"suppression ends at {entry['line_end']} but _DIGESTS closes at {closes}"
        )

    def test_digests_are_well_formed_sha256(self):
        for filename, digest in _DIGESTS.items():
            assert len(digest) == 64, f"{filename} digest is not 64 hex chars"
            assert digest == digest.lower(), f"{filename} digest is not lowercase"
            int(digest, 16)
