# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An image binding lives and dies with its session, and a refused delivery
leaves the previous subject standing.

- Every path that ends a session's source record ends its image binding too, and
  the idle sweep, the session count and the reference length see image bindings.
- Finalizing an archive checks the bytes before it moves anything: a refused
  re-delivery under the same upload id leaves the delivered archive and its
  binding as they were, as the zip channel does.
- A refused upload is deleted with its file closed (Windows will not delete an
  open file).
- Changing the subject leaves no stale archive in ``image/``.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import os
import sys
import tarfile
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd

pytestmark = pytest.mark.unit

_SESSION = "session-image-lifecycle"
IMAGE_REF = "registry.example.com/team/app@sha256:" + "a" * 64


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    monkeypatch.setattr(sd, "resolve_workspace_root", lambda: tmp_path)
    # The operator's registry allowlist admits nothing by default; these rows
    # are about the binding's lifecycle, not the gate.
    monkeypatch.setenv("ASH_MCP_IMAGE_ALLOWED_REGISTRIES", "registry.example.com")
    yield tmp_path
    sd._drop_session_source_dir(_SESSION)


def _tar_bytes(member: str = "manifest.json", content: bytes = b"[]") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as archive:
        info = tarfile.TarInfo(name=member)
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _upload(payload: bytes, upload_id: str, root: Path) -> str:
    sd.set_source_image_archive_chunk(
        upload_id=upload_id,
        sequence=0,
        data_b64=base64.b64encode(payload).decode("ascii"),
        last=True,
        workspace_root=root,
        session_id=_SESSION,
    )
    return hashlib.sha256(payload).hexdigest()


def _finalize(upload_id: str, sha: str, root: Path) -> Path:
    return sd.set_source_image_archive_finalize(
        upload_id=upload_id,
        expected_sha256=sha,
        workspace_root=root,
        session_id=_SESSION,
    )


class TestEveryEndOfASessionEndsItsImage:
    def test_dropping_the_source_record_drops_the_image_binding(self, workspace):
        sd.set_source_image(IMAGE_REF, session_id=_SESSION)
        sd._drop_session_source_dir(_SESSION)
        assert sd.get_session_image_locator(_SESSION) is None

    def test_disconnect_drops_the_image_binding(self, workspace):
        from automated_security_helper.cli.mcp.sessions import get_default_registry

        sd.set_source_image(IMAGE_REF, session_id=_SESSION)
        get_default_registry().disconnect(_SESSION)
        assert sd.get_session_image_locator(_SESSION) is None

    def test_an_image_only_session_is_counted(self, workspace):
        before = sd.delivered_session_count()
        sd.set_source_image(IMAGE_REF, session_id=_SESSION)
        assert sd.delivered_session_count() == before + 1

    def test_an_image_only_session_is_not_idle(self, workspace):
        from automated_security_helper.cli.mcp.sessions import (
            _session_holds_a_binding,
        )

        holds = _session_holds_a_binding()
        assert not holds(_SESSION)
        sd.set_source_image(IMAGE_REF, session_id=_SESSION)
        assert holds(_SESSION)

    def test_a_reference_has_a_length_cap(self, workspace):
        with pytest.raises(ValueError, match="too long"):
            sd.set_source_image("a" * 5000, session_id=_SESSION)
        assert sd.get_session_image_locator(_SESSION) is None


class TestARefusedRedeliveryLeavesThePreviousSubject:
    def test_a_gzip_under_the_same_upload_id_keeps_the_delivered_archive(
        self, workspace
    ):
        good = _tar_bytes()
        delivered = _finalize("up", _upload(good, "up", workspace), workspace)
        assert delivered.read_bytes() == good

        zipped = gzip.compress(good)
        sha = _upload(zipped, "up", workspace)
        with pytest.raises(ValueError, match="gzip|compressed|tar"):
            _finalize("up", sha, workspace)

        assert delivered.read_bytes() == good
        locator = sd.get_session_image_locator(_SESSION)
        assert locator is not None and locator.oci_archive == delivered

    def test_the_refused_upload_is_removed(self, workspace):
        _finalize("up", _upload(_tar_bytes(), "up", workspace), workspace)
        sha = _upload(gzip.compress(_tar_bytes()), "up", workspace)
        with pytest.raises(ValueError):
            _finalize("up", sha, workspace)
        assert not list((workspace / _SESSION / "incoming").iterdir())


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="reads the process's open files"
)
class TestARefusedUploadIsDeletedClosed:
    def _open_paths(self) -> set:
        found = set()
        for name in os.listdir("/proc/self/fd"):
            try:
                found.add(os.readlink(f"/proc/self/fd/{name}"))
            except OSError:
                pass
        return found

    def _spy(self, monkeypatch):
        real = sd._remove_zip_still_at
        seen = {}

        def spy(final, opened, session_id, upload_id):
            seen["open"] = str(final) in self._open_paths()
            return real(final, opened, session_id, upload_id)

        monkeypatch.setattr(sd, "_remove_zip_still_at", spy)
        return seen

    def test_a_sha_mismatch_is_removed_with_the_file_closed(
        self, workspace, monkeypatch
    ):
        _upload(_tar_bytes(), "bad", workspace)
        seen = self._spy(monkeypatch)
        with pytest.raises(ValueError, match="sha256 mismatch"):
            _finalize("bad", "0" * 64, workspace)
        assert seen == {"open": False}

    def test_an_oversize_upload_is_removed_with_the_file_closed(
        self, workspace, monkeypatch
    ):
        sha = _upload(_tar_bytes(), "big", workspace)
        monkeypatch.setattr(sd, "_MAX_ZIP_BYTES", 10)
        seen = self._spy(monkeypatch)
        with pytest.raises(ValueError, match="too large"):
            _finalize("big", sha, workspace)
        assert seen == {"open": False}


class TestChangingTheSubjectLeavesNoStaleArchive:
    def _image_files(self, root: Path) -> list:
        directory = root / _SESSION / "image"
        return sorted(p.name for p in directory.iterdir()) if directory.is_dir() else []

    def test_a_reference_after_an_archive_removes_the_archive(self, workspace):
        _finalize("one", _upload(_tar_bytes(), "one", workspace), workspace)
        assert self._image_files(workspace) == ["one.tar"]
        sd.set_source_image(IMAGE_REF, session_id=_SESSION)
        assert self._image_files(workspace) == []

    def test_a_second_archive_leaves_only_itself(self, workspace):
        _finalize("one", _upload(_tar_bytes(), "one", workspace), workspace)
        stray = workspace / _SESSION / "image" / "stray.tar"
        stray.write_bytes(b"left behind by an earlier cycle")
        _finalize("two", _upload(_tar_bytes("b.json"), "two", workspace), workspace)
        assert self._image_files(workspace) == ["two.tar"]
