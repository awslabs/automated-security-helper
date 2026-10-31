#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Five source-delivery gaps, each pinned by the input or the order that passed it.

The git delivery keeps a tree's symbolic links: a config reached through one is
judged by every name it has when it is read (``test_delivered_config_links``),
so no ``core.symlinks`` setting is pinned here.

* A clone, fetch or checkout ran as a bare ``Popen`` nobody recorded, so a server
  that stopped meanwhile left it running.
* A clone with no ref of a repository whose HEAD names no commit exits 0 with an
  empty tree, which was registered as the session's source and scanned clean.
* Uploads were capped per upload id only, and an archive the finalize refused
  stayed on disk, so one session could hold any number of archives. The bound
  across uploads then read at a first chunk only, and compared the other uploads'
  bytes alone, so each upload grew to the per-upload cap on its own.
* A zip entry named with backslashes passed the traversal checks as a nested path
  and was extracted on POSIX as one flat file.
* ``clear_source`` removes the materialized profile and keeps the binding that
  named it: the binding is the source of truth, and the resolver writes the
  profile again from it when the file is gone.
"""

from __future__ import annotations

import base64
import hashlib
import io
import subprocess
import zipfile
from pathlib import Path
from typing import List
from unittest.mock import patch

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.profile_registry import (
    bind_session_config,
    clear_all_session_state,
    session_has_binding,
)
from automated_security_helper.config.ash_config import AshConfig

pytestmark = pytest.mark.unit

SESSION = "bounds-session"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _zip_bytes(entries: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries.items():
            # The entry is stored under the name as written. ``ZipInfo``
            # rewrites ``os.sep`` to ``/`` when it is built from a name, so on
            # Windows a backslash entry would otherwise reach the archive as the
            # nested path ``src/main.py``; setting the name after construction
            # keeps it literal in the archive. The reader does the same rewrite
            # into ``filename`` and keeps the archive's spelling in
            # ``orig_filename``, which is what the delivery judges.
            info = zipfile.ZipInfo(name)
            info.filename = name
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, content)
    return buf.getvalue()


def _upload(payload: bytes, upload_id: str, tmp_path: Path) -> str:
    sd.set_source_zip_chunk(
        upload_id=upload_id,
        sequence=0,
        data_b64=_b64(payload),
        last=True,
        workspace_root=tmp_path,
        session_id=SESSION,
    )
    return hashlib.sha256(payload).hexdigest()


def _finalize(upload_id: str, sha256: str, tmp_path: Path) -> Path:
    return sd.set_source_zip_finalize(
        upload_id=upload_id,
        expected_sha256=sha256,
        workspace_root=tmp_path,
        session_id=SESSION,
    )


@pytest.fixture(autouse=True)
def _forget_sessions():
    yield
    sd._SESSION_SOURCE_DIRS.clear()
    clear_all_session_state()


class _FakeProcess:
    returncode = 0
    pid = 4242

    def communicate(self, timeout=None):
        return "", ""

    def poll(self):
        return 0


class TestAGitCommandIsRecordedWhileItRuns:
    def test_the_group_is_registered_for_the_run_and_forgotten_after(self, tmp_path):
        """Red at the base: nothing registered the process with the server's groups."""
        order: List[str] = []

        def register(process):
            order.append(f"register {process.pid}")

        def unregister(process):
            order.append(f"unregister {process.pid}")

        with (
            patch.object(sd.subprocess, "Popen", return_value=_FakeProcess()),
            patch(
                "automated_security_helper.utils.subprocess_utils._register_group",
                side_effect=register,
            ),
            patch(
                "automated_security_helper.utils.subprocess_utils._unregister_group",
                side_effect=unregister,
            ),
        ):
            result = sd._run_git(["git", "--version"], env={})

        assert result.returncode == 0
        assert order == ["register 4242", "unregister 4242"]

    def test_the_group_is_forgotten_when_the_wait_raises(self):
        """A command that times out is unregistered too, after its group is stopped."""
        order: List[str] = []

        class _Hangs(_FakeProcess):
            def communicate(self, timeout=None):
                raise subprocess.TimeoutExpired(["git"], timeout or 0)

        with (
            patch.object(sd.subprocess, "Popen", return_value=_Hangs()),
            patch.object(sd, "GIT_TIMEOUT_SECONDS", 0),
            patch.object(sd, "_stop_process_group"),
            patch(
                "automated_security_helper.utils.subprocess_utils._register_group",
                side_effect=lambda p: order.append("register"),
            ),
            patch(
                "automated_security_helper.utils.subprocess_utils._unregister_group",
                side_effect=lambda p: order.append("unregister"),
            ),
            pytest.raises(sd.GitTimeoutError),
        ):
            sd._run_git(["git", "clone"], env={})

        assert order == ["register", "unregister"]


class TestAClonedRepositoryMustHaveACommit:
    def _steps(self, head_rc: int):
        calls: List[List[str]] = []

        def fake_step(cmd, *, env, what, error_type):
            calls.append(list(cmd))
            rc = head_rc if "rev-parse" in cmd else 0
            return subprocess.CompletedProcess(cmd, rc, "", "")

        return calls, fake_step

    def test_a_clone_with_no_commit_is_refused(self, tmp_path):
        """Red at the base: the clone returned with an empty tree registered as source."""
        calls, fake_step = self._steps(head_rc=1)

        with (
            patch.object(sd, "_run_git_step", side_effect=fake_step),
            pytest.raises(sd.GitCommandError, match="no commit"),
        ):
            sd._clone(
                "https://example.com/repo.git",
                None,
                depth=1,
                target=tmp_path / "clone",
                env={"PATH": "/usr/bin"},
                git="git",
            )

        assert any("rev-parse" in cmd for cmd in calls)

    def test_a_clone_with_a_commit_is_delivered(self, tmp_path):
        """Control: HEAD a commit, the clone stands; no fetch or checkout without a ref."""
        calls, fake_step = self._steps(head_rc=0)

        with patch.object(sd, "_run_git_step", side_effect=fake_step):
            sd._clone(
                "https://example.com/repo.git",
                None,
                depth=1,
                target=tmp_path / "clone",
                env={"PATH": "/usr/bin"},
                git="git",
            )

        subcommands = [
            next(
                part
                for part in cmd
                if part in ("clone", "fetch", "checkout", "rev-parse")
            )
            for cmd in calls
        ]
        assert subcommands == ["clone", "rev-parse"]


class TestUploadsAreBoundedPerSession:
    def test_a_fifth_upload_in_progress_is_refused(self, tmp_path):
        """Red at the base: any number of upload ids could each hold an archive."""
        payload = _zip_bytes({"a.py": b"print(1)\n"})
        for n in range(sd._MAX_UPLOADS_PER_SESSION):
            _upload(payload, f"upload-{n}", tmp_path)

        with pytest.raises(ValueError, match="too many uploads"):
            _upload(payload, "one-more", tmp_path)

    def test_a_restarted_upload_of_the_same_id_is_not_counted_against_itself(
        self, tmp_path
    ):
        """Control: an upload sent again under its id replaces its own file."""
        payload = _zip_bytes({"a.py": b"print(1)\n"})
        for n in range(sd._MAX_UPLOADS_PER_SESSION):
            _upload(payload, f"upload-{n}", tmp_path)

        _upload(payload, "upload-0", tmp_path)

    def test_bytes_held_across_uploads_are_bounded(self, tmp_path, monkeypatch):
        # The bound counts the upload's own bytes with the others' on every
        # chunk, so it has to admit one whole archive for the first upload to
        # land; a bound below one archive refused the first upload itself.
        payload = _zip_bytes({"a.py": b"print(1)\n"})
        monkeypatch.setattr(sd, "_MAX_INCOMING_BYTES", len(payload) + 1)
        _upload(payload, "first", tmp_path)

        with pytest.raises(ValueError, match="hold"):
            _upload(payload, "second", tmp_path)

    def test_a_first_chunk_counts_its_own_bytes_against_the_bound(
        self, tmp_path, monkeypatch
    ):
        """Red at the base: the bound compared what the OTHER uploads held, so a
        first chunk that itself crossed the bound was admitted."""
        monkeypatch.setattr(sd, "_MAX_INCOMING_BYTES", 30)
        _upload(b"x" * 20, "first", tmp_path)

        with pytest.raises(ValueError, match="hold"):
            _upload(b"y" * 15, "second", tmp_path)

    def test_a_later_chunk_that_grows_past_the_bound_is_refused(
        self, tmp_path, monkeypatch
    ):
        """Red at the base: the bound was read at an upload's first chunk only, so
        each upload could start small and grow to the per-upload cap on its own."""
        monkeypatch.setattr(sd, "_MAX_INCOMING_BYTES", 30)
        _upload(b"x" * 20, "first", tmp_path)
        sd.set_source_zip_chunk(
            upload_id="second",
            sequence=0,
            data_b64=_b64(b"y" * 5),
            last=False,
            workspace_root=tmp_path,
            session_id=SESSION,
        )

        with pytest.raises(ValueError, match="hold"):
            sd.set_source_zip_chunk(
                upload_id="second",
                sequence=1,
                data_b64=_b64(b"z" * 10),
                last=False,
                workspace_root=tmp_path,
                session_id=SESSION,
            )

        incoming = tmp_path / SESSION / "incoming"
        assert not (incoming / "second.zip.part").exists()
        assert not (incoming / "second.next").exists()
        assert (incoming / "first.zip").stat().st_size == 20

    def test_a_chunk_within_the_bound_is_appended(self, tmp_path, monkeypatch):
        """Control: the bound counts bytes, and a chunk that fits is kept."""
        monkeypatch.setattr(sd, "_MAX_INCOMING_BYTES", 30)
        _upload(b"x" * 20, "first", tmp_path)

        answer = sd.set_source_zip_chunk(
            upload_id="second",
            sequence=0,
            data_b64=_b64(b"y" * 10),
            last=False,
            workspace_root=tmp_path,
            session_id=SESSION,
        )

        assert answer["received"] == 10
        assert (tmp_path / SESSION / "incoming" / "second.zip.part").exists()

    def test_an_archive_the_finalize_refuses_is_removed(self, tmp_path):
        """Red at the base: the refused zip stayed in incoming/ until the session ended."""
        hostile = _zip_bytes({"../escape.py": b"x"})
        sha256 = _upload(hostile, "hostile", tmp_path)

        with pytest.raises(ValueError, match="traversal"):
            _finalize("hostile", sha256, tmp_path)

        assert not sd._final_zip_path(tmp_path / SESSION, "hostile").exists()

    def test_a_delivered_archive_is_removed_as_before(self, tmp_path):
        """Control: a delivery that succeeds leaves no archive either."""
        payload = _zip_bytes({"a.py": b"print(1)\n"})
        sha256 = _upload(payload, "fine", tmp_path)

        target = _finalize("fine", sha256, tmp_path)

        assert (target / "a.py").exists()
        assert not sd._final_zip_path(tmp_path / SESSION, "fine").exists()


class TestZipEntriesNamedWithBackslashesAreRefused:
    def test_a_backslash_entry_is_refused(self, tmp_path):
        """Red at the base: extracted on POSIX as the flat file ``src\\\\main.py``.

        On every platform: the reader rewrites the backslash to ``/`` in
        ``ZipInfo.filename`` on Windows, so a delivery judged by that attribute
        admitted there the archive it refused on POSIX; the archive's own
        spelling (``orig_filename``) is judged instead.
        """
        payload = _zip_bytes({"src\\main.py": b"print(1)\n"})
        sha256 = _upload(payload, "bs", tmp_path)

        with pytest.raises(ValueError, match="backslash"):
            _finalize("bs", sha256, tmp_path)

        assert not (tmp_path / SESSION / "source" / "src\\main.py").exists()

    def test_a_forward_slash_entry_is_delivered(self, tmp_path):
        """Control: the zip format's own separator is extracted as a directory."""
        payload = _zip_bytes({"src/main.py": b"print(1)\n"})
        sha256 = _upload(payload, "fs", tmp_path)

        target = _finalize("fs", sha256, tmp_path)

        assert (target / "src" / "main.py").exists()


class TestClearSourceKeepsTheBinding:
    def test_the_bound_profile_outlives_the_workspace(self, tmp_path):
        """The binding is the source of truth: its files are removed, it stays.

        An earlier shape of this test pinned the opposite: ``clear_source``
        dropped the binding with the workspace. The resolver has since been
        taught to write a bound profile again from the binding when its file is
        gone, and to refuse the scan when it cannot
        (``test_profile_registry_binding_outlives_clear_source``), so the
        binding ends with the session, not with ``clear_source``.
        """
        payload = _zip_bytes({"a.py": b"print(1)\n"})
        _finalize("fine", _upload(payload, "fine", tmp_path), tmp_path)
        bind_session_config(SESSION, config=AshConfig(), profile_name="strict")
        assert session_has_binding(SESSION)

        sd.clear_source(SESSION, workspace_root=tmp_path)

        assert session_has_binding(SESSION)
        assert sd.get_session_source_dir(SESSION) is None

    def test_another_sessions_binding_is_kept(self, tmp_path):
        """Control: a clear of one session touches no other session's binding."""
        bind_session_config("other", config=AshConfig(), profile_name="strict")

        sd.clear_source(SESSION, workspace_root=tmp_path)

        assert session_has_binding("other")
