# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scratch zip that cannot be removed does not change what a finalize answers.

Why this file exists
--------------------
``set_source_zip_finalize`` removes the assembled zip in three places: after a
refusal for the zip's size, after a refusal for its checksum, and after a
delivery that succeeded. All three are scratch cleanup. When something else holds
the file (an AV scanner or an indexer, routine on Windows) the unlink raises
``PermissionError``. Raised through, it replaced the refusal the caller is owed
with ``error_type: PermissionError``, and on the success path it made the tool
report failure for a delivery that had already taken effect at
``_set_session_source_dir``, which invites a retry of a done delivery.

The stand-in refuses every unlink of the upload's assembled zip, as another
process's hold would, whether or not the finalize still has the file open. Each
cell says which wrong behavior it fails on. No cell runs git, opens a network
connection, or needs a particular user.
"""

from __future__ import annotations

import base64
import errno
import hashlib
import io
import zipfile
from pathlib import Path
from typing import Any, List

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd

pytestmark = pytest.mark.unit

_SESSION = "session-held-zip"


@pytest.fixture
def workspace(tmp_path):
    """The workspace root; the session's record and tree are gone after the cell.

    The teardown deletes through ``shutil.rmtree``, which does not call
    ``Path.unlink``, so the planted refusal does not reach it.
    """

    yield tmp_path
    sd.clear_source(_SESSION, workspace_root=tmp_path)


def _zip_with(name: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"app/{name}.txt", name.encode("utf-8"))
    return buf.getvalue()


def _upload(payload: bytes, upload_id: str, workspace_root: Path) -> Path:
    """Send ``payload`` as one last chunk; return the assembled zip's path."""

    sd.set_source_zip_chunk(
        upload_id=upload_id,
        sequence=0,
        data_b64=base64.b64encode(payload).decode("ascii"),
        last=True,
        workspace_root=workspace_root,
        session_id=_SESSION,
    )
    assembled = workspace_root / _SESSION / "incoming" / f"{upload_id}.zip"
    assert assembled.is_file()
    return assembled


def _refuse_every_unlink_of(
    monkeypatch: pytest.MonkeyPatch, assembled: Path
) -> List[Path]:
    """Plant another process's hold: unlinking ``assembled`` raises PermissionError.

    Returns the list of refused paths, so a cell can assert the planted refusal
    was reached. Any other unlink runs the real one.
    """

    refused: List[Path] = []
    real_unlink = Path.unlink

    def refusing(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self == assembled:
            refused.append(self)
            raise PermissionError(
                errno.EACCES,
                "The process cannot access the file because it is being "
                "used by another process",
                str(self),
            )
        return real_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", refusing)
    return refused


def test_a_checksum_refusal_surfaces_when_the_zips_unlink_is_refused(
    workspace, monkeypatch
) -> None:
    """The caller is owed the checksum refusal, not the holder's error.

    Fails on an unlink that raises through: the finalize then answers
    ``PermissionError`` and the cell's ``pytest.raises(ValueError)`` does not
    catch it. The zip that stays is refused again by the same call, as the
    comment at the unlink says.
    """

    assembled = _upload(_zip_with("held-bad"), "held-bad", workspace)
    refused = _refuse_every_unlink_of(monkeypatch, assembled)

    for _ in range(2):
        with pytest.raises(ValueError, match="sha256 mismatch"):
            sd.set_source_zip_finalize(
                upload_id="held-bad",
                expected_sha256="0" * 64,
                workspace_root=workspace,
                session_id=_SESSION,
            )

    assert len(refused) == 2, "the planted unlink refusal was not reached each time"
    assert assembled.is_file()


def test_a_size_refusal_surfaces_when_the_zips_unlink_is_refused(
    workspace, monkeypatch
) -> None:
    """The caller is owed the size refusal, not the holder's error.

    Fails on an unlink that raises through, as the checksum cell does.
    """

    payload = _zip_with("held-big")
    assembled = _upload(payload, "held-big", workspace)
    refused = _refuse_every_unlink_of(monkeypatch, assembled)
    monkeypatch.setattr(sd, "_MAX_ZIP_BYTES", 1)

    with pytest.raises(ValueError, match="zip too large"):
        sd.set_source_zip_finalize(
            upload_id="held-big",
            expected_sha256=hashlib.sha256(payload).hexdigest(),
            workspace_root=workspace,
            session_id=_SESSION,
        )

    assert refused, "the planted unlink refusal was never reached"


def test_a_delivery_that_took_effect_succeeds_when_the_zips_unlink_is_refused(
    workspace, monkeypatch
) -> None:
    """The source dir was recorded before the scratch unlink runs.

    Fails on an unlink that raises through: the finalize then reports a delivery
    that already took effect as failed, and a client that trusts the answer would
    send the upload again.
    """

    payload = _zip_with("held-good")
    assembled = _upload(payload, "held-good", workspace)
    refused = _refuse_every_unlink_of(monkeypatch, assembled)

    source = sd.set_source_zip_finalize(
        upload_id="held-good",
        expected_sha256=hashlib.sha256(payload).hexdigest(),
        workspace_root=workspace,
        session_id=_SESSION,
    )

    assert (source / "app" / "held-good.txt").is_file()
    assert sd.get_session_source_dir(_SESSION) == source
    assert refused, "the planted unlink refusal was never reached"
