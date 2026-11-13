# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""install-pinned-tool's download ends, tells a short body from a bad digest, and
does not skip the license files.

Why this file exists
--------------------
Three ways the installer could go wrong without anything reporting it:

* ``download`` opened the URL with no timeout. A connection that stalled hung the
  image build, the CI opengrep install or a nix shell entry forever, and
  with-retry, which wraps every call, never reached its next attempt.
* A response the server closed short of its Content-Length was written as a
  short file and hashed, so it surfaced as a SHA256 mismatch: exit 3, the
  integrity status with-retry must never retry, for a network failure that a
  retry is the cure for.
* ``install`` returned early when the binary at the destination already matched
  its pinned digest, before the license files were staged, so a matching binary
  with a missing or incomplete license directory stayed that way and no mode
  repaired it.

Nothing here reaches the network: the opener ``download`` builds is replaced in the
loaded module.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import platform
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "automated_security_helper" / "assets" / "install-pinned-tool.py"
PACKAGE_ROOT = REPO_ROOT / "automated_security_helper"


def _load_script():
    spec = importlib.util.spec_from_file_location("_install_pinned_tool_dl", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


installer = _load_script()


class _Response:
    def __init__(self, body: bytes, content_length: int | None):
        self._body = body
        self.headers = (
            {} if content_length is None else {"Content-Length": str(content_length)}
        )

    def read(self, size: int) -> bytes:
        chunk, self._body = self._body[:size], self._body[size:]
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _serve(monkeypatch, respond) -> None:
    """Replace the opener ``download`` builds with one that answers via ``respond``.

    ``respond(url, timeout)`` returns the response. ``download`` builds its opener
    with ``urllib.request.build_opener`` so that a redirect off https is refused,
    which is why the test stand-in sits there and not on ``urlopen``.
    """

    class _Opener:
        def open(self, url, data=None, timeout=None):
            return respond(url, timeout)

    monkeypatch.setattr(
        installer.urllib.request, "build_opener", lambda *handlers: _Opener()
    )


class TestDownload:
    def test_the_socket_has_a_timeout(self, monkeypatch, tmp_path):
        seen = {}

        def respond(url, timeout):
            seen["timeout"] = timeout
            return _Response(b"abc", 3)

        _serve(monkeypatch, respond)
        installer.download("https://example.invalid/x", tmp_path / "x")
        assert seen["timeout"] is not None and seen["timeout"] > 0

    def test_a_complete_body_is_hashed_as_written(self, monkeypatch, tmp_path):
        body = b"x" * 1000
        _serve(monkeypatch, lambda url, timeout: _Response(body, 1000))
        digest = installer.download("https://example.invalid/x", tmp_path / "x")
        assert digest == hashlib.sha256(body).hexdigest()
        assert tmp_path.joinpath("x").read_bytes() == body

    def test_a_short_body_is_a_network_failure_not_a_digest_mismatch(
        self, monkeypatch, tmp_path
    ):
        _serve(monkeypatch, lambda url, timeout: _Response(b"x" * 500, 1000))
        with pytest.raises(ConnectionError, match="500 of 1000"):
            installer.download("https://example.invalid/x", tmp_path / "x")

    def test_no_content_length_is_not_a_short_read(self, monkeypatch, tmp_path):
        _serve(monkeypatch, lambda url, timeout: _Response(b"abc", None))
        assert installer.download("https://example.invalid/x", tmp_path / "x") == (
            hashlib.sha256(b"abc").hexdigest()
        )


def _tool_with_licenses_and_executable_digest():
    pins = installer.load_pins(PACKAGE_ROOT)
    arch = installer.resolve_arch(platform.machine())
    for tool in sorted(pins.TOOL_VERSIONS):
        try:
            asset = pins.get_tool_asset(tool, "linux", arch)
            entry = pins.get_third_party_license(tool)
        except Exception:
            continue
        if getattr(asset, "executable_digest", None) and entry.files:
            return asset, entry
    pytest.skip("no pinned tool with both an executable digest and a license entry")


class TestAlreadyInstalledStillOwesLicenses:
    @pytest.fixture
    def matching_binary(self, tmp_path, monkeypatch):
        asset, entry = _tool_with_licenses_and_executable_digest()
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        final = bin_dir / asset.install_as
        final.write_bytes(b"#!/bin/sh\n")
        final.chmod(0o755)
        monkeypatch.setattr(
            installer, "_sha256_file", lambda p: asset.executable_digest
        )
        monkeypatch.setattr(installer.platform, "system", lambda: "Linux")

        def fetched(url, target):
            raise RuntimeError(f"fetched {url}")

        monkeypatch.setattr(installer, "download", fetched)
        return asset, entry, bin_dir, tmp_path / "third-party"

    def test_a_populated_license_directory_takes_the_fast_path(self, matching_binary):
        asset, entry, bin_dir, third_party = matching_binary
        tool_dir = third_party / asset.tool
        tool_dir.mkdir(parents=True)
        for name in [f.name for f in entry.files] + [installer._SOURCE_FILE]:
            tool_dir.joinpath(name).write_text("x", encoding="utf-8")
        result = installer.install(asset.tool, bin_dir, PACKAGE_ROOT, third_party)
        assert result == bin_dir / asset.install_as

    def test_a_missing_license_directory_reinstalls_from_the_archive(
        self, matching_binary
    ):
        asset, _entry, bin_dir, third_party = matching_binary
        with pytest.raises(RuntimeError, match="fetched"):
            installer.install(asset.tool, bin_dir, PACKAGE_ROOT, third_party)

    def test_no_license_directory_asked_for_keeps_the_fast_path(self, matching_binary):
        asset, _entry, bin_dir, _third_party = matching_binary
        result = installer.install(asset.tool, bin_dir, PACKAGE_ROOT, None)
        assert result == bin_dir / asset.install_as


class TestThirdPartyInstalled:
    class _Entry:
        tool = "sometool"

        class _File:
            def __init__(self, name):
                self.name = name

        files = (_File("LICENSE"), _File("NOTICE"))

    def test_every_file_and_the_source_notice_must_be_present_and_non_empty(
        self, tmp_path
    ):
        entry = self._Entry()
        tool_dir = tmp_path / "sometool"
        tool_dir.mkdir()
        assert installer._third_party_installed(entry, tmp_path) is False
        for name in ("LICENSE", "NOTICE", installer._SOURCE_FILE):
            tool_dir.joinpath(name).write_text("x", encoding="utf-8")
        assert installer._third_party_installed(entry, tmp_path) is True
        tool_dir.joinpath("NOTICE").write_bytes(b"")
        assert installer._third_party_installed(entry, tmp_path) is False
        os.remove(tool_dir / "NOTICE")
        assert installer._third_party_installed(entry, tmp_path) is False
