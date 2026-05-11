# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for Track 10.2: MCP source delivery (git-ref + chunked zip upload)."""

from __future__ import annotations

import base64
import hashlib
import io
import os
import zipfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd


_SESSION = "session-test"


# ---------------------------------------------------------------------------
# Workspace-root resolution.
# ---------------------------------------------------------------------------


class TestResolveWorkspaceRoot:
    def test_env_var_wins(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "custom"))
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
        assert sd.resolve_workspace_root() == tmp_path / "custom"

    def test_falls_back_to_xdg(self, tmp_path, monkeypatch):
        monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
        monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
        assert sd.resolve_workspace_root() == tmp_path / "xdg" / "ash-mcp"

    def test_falls_back_to_home_cache(self, tmp_path, monkeypatch):
        monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
        monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
        # We can't easily fake home, but the result must end in .cache/ash-mcp.
        result = sd.resolve_workspace_root()
        assert result.name == "ash-mcp"
        assert result.parent.name == ".cache"


# ---------------------------------------------------------------------------
# session_id sanitization.
# ---------------------------------------------------------------------------


class TestSessionIdSanitization:
    def test_traversal_session_id_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="path separators"):
            sd._session_workspace(tmp_path, "../escape")

    def test_absolute_session_id_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="path separators"):
            sd._session_workspace(tmp_path, "/etc")

    def test_empty_session_id_rejected(self, tmp_path):
        with pytest.raises(ValueError):
            sd._session_workspace(tmp_path, "")


# ---------------------------------------------------------------------------
# git clone (mocked).
# ---------------------------------------------------------------------------


class TestSetSourceGit:
    def test_happy_path_calls_git_clone(self, tmp_path):
        called = {}

        def fake_run(cmd, **kw):
            called.setdefault("cmds", []).append(cmd)
            res = MagicMock()
            res.returncode = 0
            res.stdout = ""
            res.stderr = ""
            return res

        with patch.object(sd.subprocess, "run", side_effect=fake_run):
            target = sd.set_source_git(
                url="https://example.com/foo.git",
                workspace_root=tmp_path,
                session_id=_SESSION,
            )

        assert target == tmp_path / _SESSION / "source"
        assert called["cmds"][0][0:4] == ["git", "clone", "--depth", "1"]
        assert called["cmds"][0][4] == "https://example.com/foo.git"
        # Workspace was recorded.
        assert sd.get_session_source_dir(_SESSION) == target
        sd.clear_source(_SESSION, workspace_root=tmp_path)

    def test_clone_failure_raises_runtime_error(self, tmp_path):
        def fake_run(cmd, **kw):
            res = MagicMock()
            res.returncode = 128
            res.stderr = "fatal: not a repo"
            res.stdout = ""
            return res

        with patch.object(sd.subprocess, "run", side_effect=fake_run):
            with pytest.raises(RuntimeError, match="git clone failed"):
                sd.set_source_git(
                    url="https://bogus/repo.git",
                    workspace_root=tmp_path,
                    session_id=_SESSION,
                )
        sd.clear_source(_SESSION, workspace_root=tmp_path)

    def test_bad_ref_raises_runtime_error(self, tmp_path):
        # Clone succeeds; checkout fails.
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            res = MagicMock()
            res.stdout = ""
            res.stderr = ""
            if cmd[:2] == ["git", "clone"]:
                res.returncode = 0
            elif "checkout" in cmd:
                res.returncode = 1
                res.stderr = "did not match any file(s) known to git"
            else:
                # fetch is allowed to fail without aborting the operation.
                res.returncode = 1
            return res

        with patch.object(sd.subprocess, "run", side_effect=fake_run):
            with pytest.raises(RuntimeError, match="git checkout"):
                sd.set_source_git(
                    url="https://example.com/foo.git",
                    ref="does-not-exist",
                    workspace_root=tmp_path,
                    session_id=_SESSION,
                )
        sd.clear_source(_SESSION, workspace_root=tmp_path)


# ---------------------------------------------------------------------------
# Chunked zip upload helpers.
# ---------------------------------------------------------------------------


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _make_zip_bytes(entries):
    """Build an in-memory zip from {name: bytes} dict and return raw bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _make_zip_with_symlink(link_name: str, link_target: str) -> bytes:
    """Build a zip whose only entry is a symlink ``link_name`` -> ``link_target``."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo(link_name)
        # S_IFLNK | 0777 in the high half of external_attr.
        info.external_attr = (0xA1FF) << 16
        zf.writestr(info, link_target)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Chunk reassembly.
# ---------------------------------------------------------------------------


class TestChunkReassembly:
    def test_chunks_reassemble_into_finalized_zip(self, tmp_path):
        payload = _make_zip_bytes({"hello.txt": b"world"})
        # Split into two chunks.
        mid = len(payload) // 2
        c0, c1 = payload[:mid], payload[mid:]

        r0 = sd.set_source_zip_chunk(
            upload_id="u1",
            sequence=0,
            data_b64=_b64(c0),
            last=False,
            workspace_root=tmp_path,
            session_id=_SESSION,
        )
        assert r0["next_sequence"] == 1
        assert r0["last"] is False

        r1 = sd.set_source_zip_chunk(
            upload_id="u1",
            sequence=1,
            data_b64=_b64(c1),
            last=True,
            workspace_root=tmp_path,
            session_id=_SESSION,
        )
        assert r1["last"] is True

        final_path = tmp_path / _SESSION / "incoming" / "u1.zip"
        assert final_path.exists()
        assert final_path.read_bytes() == payload
        sd.clear_source(_SESSION, workspace_root=tmp_path)

    def test_out_of_order_sequence_rejected(self, tmp_path):
        payload = _make_zip_bytes({"a.txt": b"x"})
        with pytest.raises(ValueError, match="out-of-order"):
            sd.set_source_zip_chunk(
                upload_id="u2",
                sequence=5,  # expected 0
                data_b64=_b64(payload),
                last=True,
                workspace_root=tmp_path,
                session_id=_SESSION,
            )
        sd.clear_source(_SESSION, workspace_root=tmp_path)

    def test_oversize_chunk_rejected(self, tmp_path, monkeypatch):
        # Drop the chunk cap to exercise the rejection branch.
        monkeypatch.setattr(sd, "_MAX_CHUNK_BYTES", 16)
        with pytest.raises(ValueError, match="chunk too large"):
            sd.set_source_zip_chunk(
                upload_id="u3",
                sequence=0,
                data_b64=_b64(b"X" * 64),
                last=True,
                workspace_root=tmp_path,
                session_id=_SESSION,
            )
        sd.clear_source(_SESSION, workspace_root=tmp_path)

    def test_invalid_b64_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="invalid base64"):
            sd.set_source_zip_chunk(
                upload_id="u4",
                sequence=0,
                data_b64="not_valid_!!!",
                last=True,
                workspace_root=tmp_path,
                session_id=_SESSION,
            )
        sd.clear_source(_SESSION, workspace_root=tmp_path)


# ---------------------------------------------------------------------------
# Finalize: checksum + size + extraction.
# ---------------------------------------------------------------------------


def _upload(payload: bytes, upload_id: str, tmp_path: Path) -> None:
    sd.set_source_zip_chunk(
        upload_id=upload_id,
        sequence=0,
        data_b64=_b64(payload),
        last=True,
        workspace_root=tmp_path,
        session_id=_SESSION,
    )


class TestZipFinalize:
    def test_happy_path_extracts_files(self, tmp_path):
        payload = _make_zip_bytes({"src/a.py": b"print('ok')\n"})
        sha = hashlib.sha256(payload).hexdigest()
        _upload(payload, "ok", tmp_path)

        target = sd.set_source_zip_finalize(
            upload_id="ok",
            expected_sha256=sha,
            workspace_root=tmp_path,
            session_id=_SESSION,
        )
        assert (target / "src" / "a.py").read_bytes() == b"print('ok')\n"
        assert sd.get_session_source_dir(_SESSION) == target
        sd.clear_source(_SESSION, workspace_root=tmp_path)

    def test_sha256_mismatch_rejected(self, tmp_path):
        payload = _make_zip_bytes({"a.txt": b"hi"})
        _upload(payload, "shabad", tmp_path)
        with pytest.raises(ValueError, match="sha256 mismatch"):
            sd.set_source_zip_finalize(
                upload_id="shabad",
                expected_sha256="0" * 64,
                workspace_root=tmp_path,
                session_id=_SESSION,
            )
        sd.clear_source(_SESSION, workspace_root=tmp_path)

    def test_oversize_zip_rejected(self, tmp_path, monkeypatch):
        # Build a small zip and pretend the cap is even smaller.
        payload = _make_zip_bytes({"a.txt": b"hi"})
        sha = hashlib.sha256(payload).hexdigest()
        _upload(payload, "big", tmp_path)
        monkeypatch.setattr(sd, "_MAX_ZIP_BYTES", 1)
        with pytest.raises(ValueError, match="zip too large"):
            sd.set_source_zip_finalize(
                upload_id="big",
                expected_sha256=sha,
                workspace_root=tmp_path,
                session_id=_SESSION,
            )
        sd.clear_source(_SESSION, workspace_root=tmp_path)

    def test_too_many_files_rejected(self, tmp_path, monkeypatch):
        payload = _make_zip_bytes({f"f{i}.txt": b"x" for i in range(5)})
        sha = hashlib.sha256(payload).hexdigest()
        _upload(payload, "many", tmp_path)
        monkeypatch.setattr(sd, "_MAX_FILES", 2)
        with pytest.raises(ValueError, match="too many files"):
            sd.set_source_zip_finalize(
                upload_id="many",
                expected_sha256=sha,
                workspace_root=tmp_path,
                session_id=_SESSION,
            )
        sd.clear_source(_SESSION, workspace_root=tmp_path)

    def test_oversize_extraction_rejected(self, tmp_path, monkeypatch):
        payload = _make_zip_bytes({"big.bin": b"X" * 4096})
        sha = hashlib.sha256(payload).hexdigest()
        _upload(payload, "exp", tmp_path)
        monkeypatch.setattr(sd, "_MAX_EXTRACTED_BYTES", 100)
        with pytest.raises(ValueError, match="extracted size exceeds"):
            sd.set_source_zip_finalize(
                upload_id="exp",
                expected_sha256=sha,
                workspace_root=tmp_path,
                session_id=_SESSION,
            )
        sd.clear_source(_SESSION, workspace_root=tmp_path)

    def test_missing_finalized_zip_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="no finalized zip"):
            sd.set_source_zip_finalize(
                upload_id="never-uploaded",
                expected_sha256="0" * 64,
                workspace_root=tmp_path,
                session_id=_SESSION,
            )
        sd.clear_source(_SESSION, workspace_root=tmp_path)


# ---------------------------------------------------------------------------
# Traversal-defense paths (load-bearing security checks).
# ---------------------------------------------------------------------------


class TestTraversalDefenses:
    def test_traversal_entry_rejected(self, tmp_path):
        payload = _make_zip_bytes({"../etc/passwd": b"root::0:0:..."})
        sha = hashlib.sha256(payload).hexdigest()
        _upload(payload, "trav", tmp_path)
        with pytest.raises(ValueError, match="path traversal"):
            sd.set_source_zip_finalize(
                upload_id="trav",
                expected_sha256=sha,
                workspace_root=tmp_path,
                session_id=_SESSION,
            )
        sd.clear_source(_SESSION, workspace_root=tmp_path)

    def test_nested_traversal_entry_rejected(self, tmp_path):
        payload = _make_zip_bytes({"src/../../../etc/passwd": b"x"})
        sha = hashlib.sha256(payload).hexdigest()
        _upload(payload, "trav2", tmp_path)
        with pytest.raises(ValueError, match="path traversal"):
            sd.set_source_zip_finalize(
                upload_id="trav2",
                expected_sha256=sha,
                workspace_root=tmp_path,
                session_id=_SESSION,
            )
        sd.clear_source(_SESSION, workspace_root=tmp_path)

    def test_absolute_path_entry_rejected(self, tmp_path):
        payload = _make_zip_bytes({"/etc/passwd": b"root::0:0:..."})
        sha = hashlib.sha256(payload).hexdigest()
        _upload(payload, "abs", tmp_path)
        with pytest.raises(ValueError, match="absolute path"):
            sd.set_source_zip_finalize(
                upload_id="abs",
                expected_sha256=sha,
                workspace_root=tmp_path,
                session_id=_SESSION,
            )
        sd.clear_source(_SESSION, workspace_root=tmp_path)

    def test_symlink_pointing_outside_workspace_rejected(self, tmp_path):
        # Symlink "evil" -> "/etc/passwd" must be rejected pre-extraction.
        payload = _make_zip_with_symlink("evil", "/etc/passwd")
        sha = hashlib.sha256(payload).hexdigest()
        _upload(payload, "symabs", tmp_path)
        with pytest.raises(ValueError, match="resolves outside session workspace"):
            sd.set_source_zip_finalize(
                upload_id="symabs",
                expected_sha256=sha,
                workspace_root=tmp_path,
                session_id=_SESSION,
            )
        sd.clear_source(_SESSION, workspace_root=tmp_path)

    def test_symlink_with_traversal_target_rejected(self, tmp_path):
        # Symlink "evil" -> "../../etc/passwd" must be rejected.
        payload = _make_zip_with_symlink("evil", "../../etc/passwd")
        sha = hashlib.sha256(payload).hexdigest()
        _upload(payload, "symtrav", tmp_path)
        with pytest.raises(ValueError, match="resolves outside session workspace"):
            sd.set_source_zip_finalize(
                upload_id="symtrav",
                expected_sha256=sha,
                workspace_root=tmp_path,
                session_id=_SESSION,
            )
        sd.clear_source(_SESSION, workspace_root=tmp_path)


# ---------------------------------------------------------------------------
# clear_source.
# ---------------------------------------------------------------------------


class TestClearSource:
    def test_clear_source_rmtree_behavior(self, tmp_path):
        session_dir = tmp_path / _SESSION
        session_dir.mkdir(parents=True)
        (session_dir / "marker").write_text("x")
        sd._set_session_source_dir(_SESSION, session_dir / "source")

        sd.clear_source(_SESSION, workspace_root=tmp_path)

        assert not session_dir.exists()
        assert sd.get_session_source_dir(_SESSION) is None

    def test_clear_source_idempotent_on_missing(self, tmp_path):
        # Calling on a session that never existed must not raise.
        sd.clear_source("never-existed", workspace_root=tmp_path)


# ---------------------------------------------------------------------------
# MCP tool wrappers.
# ---------------------------------------------------------------------------


class TestMcpWrappers:
    def test_mcp_set_source_git_success(self, tmp_path, monkeypatch):
        from automated_security_helper.cli import mcp_tools

        def fake_clone(url, ref=None, **kw):
            # Wrapper does not pass workspace_root; fall back to resolver.
            root = kw.get("workspace_root") or sd.resolve_workspace_root()
            target = root / kw["session_id"] / "source"
            target.mkdir(parents=True, exist_ok=True)
            return target

        monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path))
        with patch.object(sd, "set_source_git", side_effect=fake_clone):
            r = mcp_tools.mcp_set_source_git(
                url="https://example.com/foo.git",
                session_id=_SESSION,
            )
        assert r["success"] is True
        assert r["source_dir"].endswith(f"{_SESSION}/source")
        sd.clear_source(_SESSION, workspace_root=tmp_path)

    def test_mcp_set_source_git_error_returns_dict(self, tmp_path, monkeypatch):
        from automated_security_helper.cli import mcp_tools

        monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path))
        with patch.object(sd, "set_source_git", side_effect=RuntimeError("boom")):
            r = mcp_tools.mcp_set_source_git(
                url="x",
                session_id=_SESSION,
            )
        assert r["success"] is False
        assert "boom" in r["error"]

    def test_mcp_zip_chunk_then_finalize_round_trip(self, tmp_path, monkeypatch):
        from automated_security_helper.cli import mcp_tools

        monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path))
        payload = _make_zip_bytes({"a.txt": b"hello"})
        sha = hashlib.sha256(payload).hexdigest()

        chunk_r = mcp_tools.mcp_set_source_zip_chunk(
            upload_id="u",
            sequence=0,
            data_b64=_b64(payload),
            last=True,
            session_id=_SESSION,
        )
        assert chunk_r["success"] is True
        assert chunk_r["last"] is True

        fin = mcp_tools.mcp_set_source_zip_finalize(
            upload_id="u",
            expected_sha256=sha,
            session_id=_SESSION,
        )
        assert fin["success"] is True
        assert (Path(fin["source_dir"]) / "a.txt").read_bytes() == b"hello"

        clear_r = mcp_tools.mcp_clear_source(session_id=_SESSION)
        assert clear_r["success"] is True
        assert not (tmp_path / _SESSION).exists()

    def test_mcp_finalize_sha_mismatch_returns_error(self, tmp_path, monkeypatch):
        from automated_security_helper.cli import mcp_tools

        monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path))
        payload = _make_zip_bytes({"a.txt": b"hello"})
        mcp_tools.mcp_set_source_zip_chunk(
            upload_id="u",
            sequence=0,
            data_b64=_b64(payload),
            last=True,
            session_id=_SESSION,
        )
        r = mcp_tools.mcp_set_source_zip_finalize(
            upload_id="u",
            expected_sha256="0" * 64,
            session_id=_SESSION,
        )
        assert r["success"] is False
        assert "sha256 mismatch" in r["error"]
        sd.clear_source(_SESSION, workspace_root=tmp_path)
