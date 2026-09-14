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
"""

import hashlib
import io
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.core.exceptions import (
    ToolDownloadIntegrityError,
    ToolNotProvisionableError,
)
from automated_security_helper.utils import tool_downloads
from automated_security_helper.utils.download_utils import (
    _extract_single_member,
    install_pinned_tool,
    read_receipt,
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
    """Patch download_utils' urlopen to serve exactly these bytes."""
    return patch(
        "automated_security_helper.utils.download_utils.urllib.request.urlopen",
        return_value=_FakeResponse(payload),
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
        assert _extract_single_member(archive, "grype", target) == target
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
        assert target.read_bytes() == PAYLOAD
        assert not (tmp_path.parent / "grype").exists()


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

    def test_digests_are_well_formed_sha256(self):
        for filename, digest in _DIGESTS.items():
            assert len(digest) == 64, f"{filename} digest is not 64 hex chars"
            assert digest == digest.lower(), f"{filename} digest is not lowercase"
            int(digest, 16)
