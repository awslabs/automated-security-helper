# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every path source_delivery builds from a caller-supplied id stays in the sandbox.

Why this file exists separately from ``test_source_delivery.py``
---------------------------------------------------------------
The delivery module validated ``upload_id`` on one of its three path builders.
``_part_path`` carried the check and has a single caller, on the chunk path;
``_meta_path`` and ``_final_zip_path`` built from the same untrusted value with
no check at all. ``set_source_zip_finalize`` goes through ``_final_zip_path``
and never through ``_part_path``, so the only guard in the module was off the
path that matters.

What that bought an attacker, and why the assertions are shaped this way
-----------------------------------------------------------------------
``set_source_zip_finalize``'s only precondition is that the built path exists,
which is satisfied by naming a file that already exists rather than by
uploading anything. From there it stats, hashes and then ``unlink``s the file,
on two separate branches: the oversize branch needs no knowledge of the
contents and reports the victim's exact byte count, and the checksum branch
fires on any wrong ``expected_sha256``. So the tests below assert two things per
case, and both matter:

* the call is refused *naming the id*, not refused later for some other reason.
  A test that only asserted ``pytest.raises(ValueError)`` would pass against the
  unfixed module, because the unfixed module raises "sha256 mismatch" -- after
  deleting the file.
* the file outside the session sandbox is still there afterwards. That is the
  assertion that fails loudest against the unfixed module, and it is the actual
  property under test; the message is only how we know the refusal came from the
  guard.

A guard that closes nothing is indistinguishable from a guard that closes
everything when read from the passing side, which is why every case here was
confirmed to fail before the validator landed.
"""

from __future__ import annotations

import base64
import hashlib
import io
import re
import zipfile
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd

pytestmark = pytest.mark.unit

_SESSION = "containment-session"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _zip_bytes(entries: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _zip_with_symlink(link_name: str, link_target: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo(link_name)
        # S_IFLNK | 0777 in the high half of external_attr.
        info.external_attr = 0xA1FF << 16
        zf.writestr(info, link_target)
    return buf.getvalue()


def _deliver(payload: bytes, upload_id: str, tmp_path: Path, session: str) -> Path:
    """Upload and finalize ``payload`` as one chunk; return the extracted tree."""
    sd.set_source_zip_chunk(
        upload_id=upload_id,
        sequence=0,
        data_b64=_b64(payload),
        last=True,
        workspace_root=tmp_path,
        session_id=session,
    )
    return sd.set_source_zip_finalize(
        upload_id=upload_id,
        expected_sha256=hashlib.sha256(payload).hexdigest(),
        workspace_root=tmp_path,
        session_id=session,
    )


@pytest.fixture(autouse=True)
def _forget_sessions():
    """Keep the process-local source_dir registry from leaking between tests."""
    yield
    sd._SESSION_SOURCE_DIRS.clear()


class TestEveryUploadPathBuilderValidates:
    """The validator is attached to the join, so no builder can be the weak one.

    Parametrized over all three builders on purpose: the defect was not that the
    predicate was wrong, it was that two of three builders did not run it. A test
    that exercised only the builder which already had the check would have stayed
    green through the entire lifetime of the bug.
    """

    BUILDERS = ("_part_path", "_meta_path", "_final_zip_path")

    @pytest.mark.parametrize("builder", BUILDERS)
    @pytest.mark.parametrize(
        "bad_upload_id",
        [
            "../escape",
            "../../other-session/incoming/theirs",
            "a/b",
            "sub/../..",
            "back\\slash",
            "..",
            ".",
            "",
            "nul\x00byte",
            "line\nfeed",
            # A bare Windows drive specifier needs no separator to carry path
            # meaning. See test_session_id_single_component.py for the join
            # arithmetic this closes.
            "C:",
            "C:evil",
            "a" * 129,
        ],
    )
    def test_builder_refuses_an_id_that_is_not_one_path_component(
        self, builder, bad_upload_id, tmp_path
    ):
        session_dir = tmp_path / _SESSION
        session_dir.mkdir(parents=True)
        with pytest.raises(ValueError, match="upload_id"):
            getattr(sd, builder)(session_dir, bad_upload_id)

    @pytest.mark.parametrize("builder", BUILDERS)
    def test_builder_accepts_the_ordinary_shapes_clients_send(self, builder, tmp_path):
        session_dir = tmp_path / _SESSION
        session_dir.mkdir(parents=True)
        for upload_id in (
            "u1",
            "upload-2",
            "upload_3",
            "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0",  # pragma: allowlist secret
            "tok==",
            "a~b",
            "a+b",
        ):
            built = getattr(sd, builder)(session_dir, upload_id)
            assert built.parent == session_dir / "incoming"
            assert built.name.startswith(upload_id)

    def test_a_refused_id_creates_no_incoming_directory(self, tmp_path):
        """Validation precedes the mkdir, so a rejected call leaves nothing behind."""
        session_dir = tmp_path / _SESSION
        session_dir.mkdir(parents=True)
        with pytest.raises(ValueError):
            sd._final_zip_path(session_dir, "../escape")
        assert not (session_dir / "incoming").exists()


class TestFinalizeCannotReachOutsideTheSession:
    """finalize stats, hashes and unlinks the path it builds, so it must not escape."""

    def test_traversal_upload_id_cannot_delete_another_sessions_upload(self, tmp_path):
        victim_incoming = tmp_path / "session-victim" / "incoming"
        victim_incoming.mkdir(parents=True)
        victim = victim_incoming / "theirs.zip"
        victim.write_bytes(b"another session's uploaded archive")

        with pytest.raises(ValueError, match="upload_id"):
            sd.set_source_zip_finalize(
                upload_id="../../session-victim/incoming/theirs",
                expected_sha256="0" * 64,
                workspace_root=tmp_path,
                session_id="session-attacker",
            )

        assert victim.exists(), "finalize deleted a file outside the session sandbox"
        assert victim.read_bytes() == b"another session's uploaded archive"

    def test_absolute_upload_id_cannot_delete_an_arbitrary_file(self, tmp_path):
        """With an absolute id the built path keeps no trace of the workspace root.

        ``Path('<incoming>') / '/etc/cron.d/x.zip'`` is ``/etc/cron.d/x.zip``:
        joining discards the left side entirely. The file only has to exist for
        finalize to proceed to stat, hash and unlink.
        """
        outside = tmp_path / "outside-the-workspace"
        outside.mkdir()
        victim = outside / "x.zip"
        victim.write_bytes(b"a file that is not part of any session")

        with pytest.raises(ValueError, match="upload_id"):
            sd.set_source_zip_finalize(
                upload_id=str(outside / "x"),
                expected_sha256="0" * 64,
                workspace_root=tmp_path,
                session_id="session-attacker",
            )

        assert victim.exists(), "finalize deleted a file outside the session sandbox"

    def test_the_oversize_branch_is_not_a_size_oracle_for_outside_files(
        self, tmp_path, monkeypatch
    ):
        """The oversize branch needs no digest and reports the victim's byte count.

        Separate from the checksum case because it is reachable with no knowledge
        of the target at all, and because it deletes on a different branch.

        The refusal quotes the upload_id, a path under the test's temporary
        directory, whose name can hold any digits ("64" among them), so the
        size is looked for in the rest of the text, as a number of its own.
        """
        monkeypatch.setattr(sd, "_MAX_ZIP_BYTES", 8)
        outside = tmp_path / "outside-the-workspace"
        outside.mkdir()
        victim = outside / "x.zip"
        victim.write_bytes(b"Y" * 64)
        upload_id = str(outside / "x")

        with pytest.raises(ValueError) as excinfo:
            sd.set_source_zip_finalize(
                upload_id=upload_id,
                expected_sha256="0" * 64,
                workspace_root=tmp_path,
                session_id="session-attacker",
            )

        message = str(excinfo.value)
        assert "upload_id" in message
        # The upload_id out, both as repr() quotes it, which doubles a backslash
        # (on Windows, or in a POSIX name holding one), and as str() spells it.
        # Only those: stripping every quoted span would pair an apostrophe in
        # the prose ("upload's") with a later quote and take the size with it.
        rest = message.replace(repr(upload_id), "''").replace(upload_id, "''")
        assert not re.search(r"(?<![0-9])64(?![0-9])", rest), (
            "the refusal reported the size of a file outside the sandbox",
            message,
        )
        assert victim.exists()

    def test_a_symlinked_final_zip_is_refused(self, tmp_path):
        """The id is a single component and the path still must not be a link.

        Containment alone would accept this: the link sits inside ``incoming/``.
        Following it would stat and hash whatever it points at, so the candidate
        itself is required to be a real file -- the same call the zip member
        handling makes for symlink entries.

        The unlink on the oversize and checksum branches removes the link, not
        the file it points at, so the victim's survival alone proves nothing
        about which branch ran. The assertions below pin the refusal to the path
        guard's own text and check that the link itself is still in place.
        """
        outside = tmp_path / "outside-the-workspace"
        outside.mkdir()
        victim = outside / "secret.zip"
        victim.write_bytes(b"not an uploaded archive")

        incoming = tmp_path / _SESSION / "incoming"
        incoming.mkdir(parents=True)
        link = incoming / "sneaky.zip"
        link.symlink_to(victim)

        with pytest.raises(ValueError) as excinfo:
            sd.set_source_zip_finalize(
                upload_id="sneaky",
                expected_sha256="0" * 64,
                workspace_root=tmp_path,
                session_id=_SESSION,
            )

        message = str(excinfo.value)
        assert "upload_id" in message
        # The path guard's refusal names the incoming directory; the oversize and
        # checksum branches, which run after a guard that let the link through,
        # do not. Matching the guard's text keeps a reworded later message from
        # satisfying this test.
        assert "does not name a file inside the session's incoming directory" in message
        assert "zip too large" not in message
        # No delete branch ran: the link is still a link, and its target holds
        # the bytes written above.
        assert link.is_symlink()
        assert victim.exists()
        assert victim.read_bytes() == b"not an uploaded archive"


class TestFailedRedeliveryKeepsThePreviousTree:
    """A re-delivery that is refused must not destroy what it failed to replace.

    The checksum and size guards do run before the old tree is touched, but the
    four guards a hostile or malformed archive trips -- entry count, member
    traversal, uncompressed total, symlink member -- all run after the archive is
    open, and the old tree used to be removed before that. The session stayed
    registered, pointing at an empty directory, which is the false-negative shape
    this repository treats as the worst class: a scan of it completes and reports
    clean.
    """

    def test_a_symlink_member_does_not_destroy_the_delivered_tree(self, tmp_path):
        target = _deliver(
            _zip_bytes({"app/main.py": b"print('first delivery')\n"}),
            "first",
            tmp_path,
            _SESSION,
        )
        assert (target / "app" / "main.py").exists()

        hostile = _zip_with_symlink("evil", "/etc/passwd")
        sd.set_source_zip_chunk(
            upload_id="second",
            sequence=0,
            data_b64=_b64(hostile),
            last=True,
            workspace_root=tmp_path,
            session_id=_SESSION,
        )
        with pytest.raises(ValueError, match="symlinks are not allowed"):
            sd.set_source_zip_finalize(
                upload_id="second",
                expected_sha256=hashlib.sha256(hostile).hexdigest(),
                workspace_root=tmp_path,
                session_id=_SESSION,
            )

        assert (target / "app" / "main.py").read_bytes() == b"print('first delivery')\n"
        assert sd.get_session_source_dir(_SESSION) == target

    def test_a_corrupt_archive_does_not_destroy_the_delivered_tree(self, tmp_path):
        """ZipFile() raises before any guard runs, which used to be after the rmtree."""
        target = _deliver(
            _zip_bytes({"app/main.py": b"print('first delivery')\n"}),
            "first",
            tmp_path,
            _SESSION,
        )

        garbage = b"this is not a zip archive at all"
        sd.set_source_zip_chunk(
            upload_id="garbage",
            sequence=0,
            data_b64=_b64(garbage),
            last=True,
            workspace_root=tmp_path,
            session_id=_SESSION,
        )
        with pytest.raises(zipfile.BadZipFile):
            sd.set_source_zip_finalize(
                upload_id="garbage",
                expected_sha256=hashlib.sha256(garbage).hexdigest(),
                workspace_root=tmp_path,
                session_id=_SESSION,
            )

        assert (target / "app" / "main.py").read_bytes() == b"print('first delivery')\n"

    def test_a_successful_redelivery_replaces_the_tree_and_leaves_no_staging(
        self, tmp_path
    ):
        """The swap has to be a replacement, not a merge, and has to clean up."""
        target = _deliver(
            _zip_bytes({"app/main.py": b"one\n", "app/gone.py": b"removed later\n"}),
            "first",
            tmp_path,
            _SESSION,
        )
        again = _deliver(
            _zip_bytes({"app/main.py": b"two\n"}), "second", tmp_path, _SESSION
        )

        assert again == target
        assert (target / "app" / "main.py").read_bytes() == b"two\n"
        assert not (target / "app" / "gone.py").exists(), (
            "the previous delivery's files survived the swap"
        )
        leftovers = [p.name for p in (tmp_path / _SESSION).iterdir() if p.is_dir()]
        assert sorted(leftovers) == ["incoming", "source"], leftovers

    def test_a_failed_delivery_leaves_no_staging_directory(self, tmp_path):
        hostile = _zip_with_symlink("evil", "/etc/passwd")
        sd.set_source_zip_chunk(
            upload_id="hostile",
            sequence=0,
            data_b64=_b64(hostile),
            last=True,
            workspace_root=tmp_path,
            session_id=_SESSION,
        )
        with pytest.raises(ValueError):
            sd.set_source_zip_finalize(
                upload_id="hostile",
                expected_sha256=hashlib.sha256(hostile).hexdigest(),
                workspace_root=tmp_path,
                session_id=_SESSION,
            )

        leftovers = [p.name for p in (tmp_path / _SESSION).iterdir() if p.is_dir()]
        assert leftovers == ["incoming"], leftovers


class TestASymlinkRefusalQuotesABoundedExcerpt:
    """The refusal of a symlink entry quotes the first bytes of it, not all of it.

    A link entry's content is whatever the archive says it is, up to the
    uncompressed total the validation admits. The refusal read the whole entry
    and embedded its ``repr`` in the message, which every per-character pass on
    the error path (the control-character rendering, the redaction) then walked
    on the event loop. Red at the base: the message carried the entire content.
    """

    def _refusal_for(self, link_target: bytes, tmp_path: Path) -> str:
        hostile = _zip_with_symlink("evil", link_target)
        sd.set_source_zip_chunk(
            upload_id="link",
            sequence=0,
            data_b64=_b64(hostile),
            last=True,
            workspace_root=tmp_path,
            session_id=_SESSION,
        )
        with pytest.raises(ValueError, match="symlinks are not allowed") as excinfo:
            sd.set_source_zip_finalize(
                upload_id="link",
                expected_sha256=hashlib.sha256(hostile).hexdigest(),
                workspace_root=tmp_path,
                session_id=_SESSION,
            )
        return str(excinfo.value)

    def test_a_long_link_target_is_cut_to_a_bounded_prefix(self, tmp_path):
        # Stored uncompressed, so the archive stays within one upload chunk.
        content = b"/" + b"a" * (512 * 1024)
        message = self._refusal_for(content, tmp_path)

        assert len(message) < 2 * sd._SYMLINK_TARGET_EXCERPT_BYTES, len(message)
        assert "..." in message
        assert "'evil'" in message

    def test_a_short_link_target_is_quoted_whole(self, tmp_path):
        """Control: a target within the bound is shown as it is, unmarked."""
        message = self._refusal_for(b"/etc/passwd", tmp_path)

        assert "'/etc/passwd'" in message
        assert "..." not in message
