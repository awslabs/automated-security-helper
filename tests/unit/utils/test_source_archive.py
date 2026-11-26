# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A source zip is read under one set of rules by ``ash scan fs --archive`` and by MCP.

Why this exists
---------------
``extract_source_archive`` is the engine behind ``ash scan fs --archive FILE``, and
the MCP finalize (``set_source_zip_finalize``) extracts an upload with the same rules,
from ``utils/source_archive.py``. The rows below pin each rule on the shared function
with the real limits (100 MiB of archive, 500 MiB extracted, 50,000 members), and then
give every one of those archives to the MCP finalize as well: it has to reach the same
verdict in the same words, so the two entry points cannot drift apart. The one
difference is the noun of the link refusal, which names each entry point's archives.

Archives past a limit are cheap to build: an oversized archive is a sparse file, a
large uncompressed total is a deflated run of zeros (about half a megabyte), and the
member count is 50,001 empty members. Names zipfile will not write as given (a NUL,
which it cuts at, and a backslash, which it turns into a slash on Windows) are written
as a placeholder of the same length and swapped into the archive's bytes afterwards.
"""

from __future__ import annotations

import base64
import copy
import gzip
import hashlib
import io
import os
import tarfile
import zipfile
from pathlib import Path
from typing import Dict, Optional, Tuple, Union

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.profile_registry import clear_all_session_state
from automated_security_helper.utils import source_archive as sa
from automated_security_helper.utils.source_archive import SourceArchiveRefusal as Kind

pytestmark = pytest.mark.unit

MiB = 1024 * 1024
SESSION = "source-archive-parity"
UPLOAD = "upload"


# ---------------------------------------------------------------------------
# Archive builders.
# ---------------------------------------------------------------------------


def _zip(entries: Dict[str, bytes], compression: int = zipfile.ZIP_DEFLATED) -> bytes:
    """A zip holding ``entries``, name to content, in order."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression) as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return buffer.getvalue()


def _zip_with_modes(entries: Dict[str, Tuple[bytes, int]]) -> bytes:
    """A zip whose members carry the Unix mode given beside each content."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, (content, mode) in entries.items():
            info = zipfile.ZipInfo(name)
            info.external_attr = mode << 16
            archive.writestr(info, content)
    return buffer.getvalue()


def _renamed(payload: bytes, placeholder: str, name: bytes) -> bytes:
    """``payload``, whose one member is named ``placeholder``, with ``name`` swapped in.

    The name is replaced in the local header and in the central directory, the two
    places a zip spells it; the placeholder has to appear in nothing else.
    """
    spelled = placeholder.encode("ascii")
    assert len(spelled) == len(name)
    assert payload.count(spelled) == 2, "the placeholder must name the member only"
    return payload.replace(spelled, name)


def _flagged_encrypted(payload: bytes) -> bytes:
    """``payload``, a zip of one member, with that member's encrypted flag set.

    Bit 0 of the general purpose flags, at offset 6 of the local header and offset 8
    of the central directory header. zipfile writes no encrypted member, so the bit is
    set in the bytes; its data stays readable plain text, which is beside the point.
    """
    data = bytearray(payload)
    local = data.find(b"PK\x03\x04")
    central = data.find(b"PK\x01\x02")
    assert local == 0 and central > 0
    data[local + 6] |= 0x01
    data[central + 8] |= 0x01
    return bytes(data)


def _with_damaged_data(payload: bytes, content: bytes) -> bytes:
    """``payload`` with one byte of a stored member's ``content`` changed.

    Stored members keep their bytes as they are, so the change lands in the member's
    data and its checksum no longer matches: zipfile finds it only when it reads the
    member to its end.
    """
    at = payload.index(content)
    damaged = bytearray(payload)
    damaged[at] ^= 0xFF
    return bytes(damaged)


def _tar(gzipped: bool) -> bytes:
    """A tar (or a gzip-compressed tar) of one small source file.

    Compressed with a fixed timestamp, so the bytes are the same on every run.
    """
    buffer = io.BytesIO()
    data = b"print('hello')\n"
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo("app/main.py")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
    tar = buffer.getvalue()
    return gzip.compress(tar, mtime=0) if gzipped else tar


def _sparse(path: Path, size: int) -> Path:
    """A file of ``size`` bytes that takes no space where the filesystem allows it."""
    with path.open("wb") as handle:
        handle.truncate(size)
    return path


def _zeros_member(total: int) -> bytes:
    """One deflated member of ``total`` zero bytes, named ``zeros.bin``."""
    buffer = io.BytesIO()
    block = bytes(MiB)
    left = total
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        with archive.open("zeros.bin", "w", force_zip64=True) as member:
            while left:
                piece = block[: min(left, MiB)]
                member.write(piece)
                left -= len(piece)
    return buffer.getvalue()


def _empty_members(count: int) -> bytes:
    """``count`` empty members, ``m/0`` onwards."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for index in range(count):
            archive.writestr(f"m/{index}", b"")
    return buffer.getvalue()


@pytest.fixture(scope="module")
def over_the_extracted_total() -> bytes:
    return _zeros_member(500 * MiB + 1)


@pytest.fixture(scope="module")
def over_the_member_count() -> bytes:
    return _empty_members(50_001)


#: A source tree with nested directories, an empty directory, an empty file, binary
#: content, and two names whose dots are not a ``..`` component.
NESTED: Dict[str, bytes] = {
    "app/main.py": b"print('main')\n",
    "app/pkg/__init__.py": b"",
    "app/pkg/deep/module.py": b"VALUE = 1\n",
    "docs/guide.md": b"# Guide\n",
    "data/blob.bin": bytes(range(256)),
    "..config/settings.toml": b"[tool]\nname = 'x'\n",
    "notes..txt": b"two dots inside a name\n",
}


def _nested_tree(root: Path) -> Path:
    for name, content in NESTED.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    (root / "empty").mkdir()
    return root


def _zip_of(root: Path) -> bytes:
    """A zip of every file and directory under ``root``, as ``zipfile.write`` adds them."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(root.rglob("*")):
            archive.write(path, path.relative_to(root).as_posix())
    return buffer.getvalue()


def _tree(root: Path) -> Dict[str, Optional[bytes]]:
    """Every entry under ``root``: a file's bytes, None for a directory."""
    return {
        path.relative_to(root).as_posix(): None if path.is_dir() else path.read_bytes()
        for path in sorted(root.rglob("*"))
    }


# ---------------------------------------------------------------------------
# The two entry points.
# ---------------------------------------------------------------------------


def _archive_file(tmp_path: Path, payload: bytes) -> Path:
    archive = tmp_path / "archive.zip"
    archive.write_bytes(payload)
    return archive


def _extraction_refusal(archive: Path, destination: Path) -> sa.SourceArchiveRefused:
    with pytest.raises(sa.SourceArchiveRefused) as refused:
        sa.extract_source_archive(archive, destination)
    return refused.value


def _upload(payload: bytes, workspace: Path) -> None:
    """Send ``payload`` to the MCP delivery in chunks it accepts, the last marked."""
    workspace.mkdir(exist_ok=True)
    size = sd._MAX_CHUNK_BYTES
    chunks = [payload[at : at + size] for at in range(0, len(payload), size)]
    for sequence, chunk in enumerate(chunks):
        sd.set_source_zip_chunk(
            upload_id=UPLOAD,
            sequence=sequence,
            data_b64=base64.b64encode(chunk).decode("ascii"),
            last=sequence == len(chunks) - 1,
            workspace_root=workspace,
            session_id=SESSION,
        )


def _finalize(payload: bytes, workspace: Path) -> Path:
    return sd.set_source_zip_finalize(
        upload_id=UPLOAD,
        expected_sha256=hashlib.sha256(payload).hexdigest(),
        workspace_root=workspace,
        session_id=SESSION,
    )


def _finalize_refusal(payload: bytes, workspace: Path) -> BaseException:
    _upload(payload, workspace)
    with pytest.raises((ValueError, zipfile.BadZipFile)) as refused:
        _finalize(payload, workspace)
    return refused.value


def _verdict(error: BaseException) -> Tuple[Kind, str]:
    """The rule and the words of a refusal from either entry point.

    The finalize raises the shared refusal for every rule, and zipfile's own
    BadZipFile for bytes that are not a zip, as it always has.
    """
    if isinstance(error, sa.SourceArchiveRefused):
        return error.kind, str(error)
    if isinstance(error, zipfile.BadZipFile):
        return Kind.NOT_A_ZIP, str(error)
    raise AssertionError(f"not an archive refusal: {error!r}")


def _in_the_finalizes_words(message: str) -> str:
    """A shared-function message as the finalize words it: the link noun differs."""
    return message.replace(sa.SOURCE_ARCHIVES, sd._DELIVERY_ARCHIVES)


@pytest.fixture(autouse=True)
def _forget_sessions():
    yield
    sd._SESSION_SOURCE_DIRS.clear()
    clear_all_session_state()


# ---------------------------------------------------------------------------
# One row per rule: (archive, or the fixture that builds it; rule; message).
# ---------------------------------------------------------------------------

REFUSED = [
    pytest.param(
        "over_the_extracted_total",
        Kind.EXTRACTED_TOO_LARGE,
        f"extracted size exceeds {500 * MiB} bytes (at entry 'zeros.bin')",
        id="uncompressed-total-over-500-mib",
    ),
    pytest.param(
        "over_the_member_count",
        Kind.TOO_MANY_MEMBERS,
        "too many files in zip: 50001 > 50000",
        id="over-50000-members",
    ),
    pytest.param(
        _zip_with_modes({"evil": (b"/outside/the/tree", 0o120777)}),
        Kind.SYMLINK_MEMBER,
        "symlink 'evil' -> '/outside/the/tree': "
        "symlinks are not allowed in source archives",
        id="symlink-member",
    ),
    pytest.param(
        _zip_with_modes(
            {
                "docs/guide.md": (b"# Guide\n", 0o100644),
                "guide.md": (b"docs/guide.md", 0o120644),
            }
        ),
        Kind.SYMLINK_MEMBER,
        "symlink 'guide.md' -> 'docs/guide.md': "
        "symlinks are not allowed in source archives",
        id="refused-for-its-type-though-it-points-inside",
    ),
    pytest.param(
        _zip({"/abs/escape.py": b"x"}),
        Kind.ABSOLUTE_PATH,
        "absolute path in zip: '/abs/escape.py'",
        id="absolute-path",
    ),
    pytest.param(
        _zip({"src/../../escape.py": b"x"}),
        Kind.PATH_TRAVERSAL,
        "path traversal in zip: 'src/../../escape.py'",
        id="dotdot-component",
    ),
    pytest.param(
        _zip({"../escape.py": b"x"}),
        Kind.PATH_TRAVERSAL,
        "path traversal in zip: '../escape.py'",
        id="leading-dotdot",
    ),
    pytest.param(
        _renamed(_zip({"toolX.py": b"x"}), "toolX.py", b"tool\x00.py"),
        Kind.NUL_IN_NAME,
        "NUL in zip entry name: 'tool\\x00.py'",
        id="nul-in-a-name",
    ),
    pytest.param(
        _renamed(_zip({"pkgXmod.py": b"x"}), "pkgXmod.py", b"pkg\\mod.py"),
        Kind.BACKSLASH_IN_NAME,
        "backslash in zip entry name: 'pkg\\\\mod.py'",
        id="backslash-in-a-name",
    ),
    pytest.param(
        _zip({"": b"x"}),
        Kind.EMPTY_NAME,
        "zip entry has empty name",
        id="empty-name",
    ),
    pytest.param(
        b"plain text, not an archive\n",
        Kind.NOT_A_ZIP,
        "File is not a zip file",
        id="not-a-zip",
    ),
    pytest.param(
        _tar(gzipped=False),
        Kind.NOT_A_ZIP,
        "File is not a zip file",
        id="tar-refused-naming-zip",
    ),
    pytest.param(
        _tar(gzipped=True),
        Kind.NOT_A_ZIP,
        "File is not a zip file",
        id="gzipped-tar-refused-naming-zip",
    ),
    pytest.param(
        gzip.compress(b"print('hello')\n", mtime=0),
        Kind.NOT_A_ZIP,
        "File is not a zip file",
        id="gzip-refused-naming-zip",
    ),
]


def _payload(request: pytest.FixtureRequest, source: Union[str, bytes]) -> bytes:
    return request.getfixturevalue(source) if isinstance(source, str) else source


class TestEachRuleRefusesBeforeAnythingIsWritten:
    @pytest.mark.parametrize("source,kind,message", REFUSED)
    def test_the_shared_function_refuses_it(
        self, request, tmp_path, source, kind, message
    ):
        destination = tmp_path / "tree"
        refused = _extraction_refusal(
            _archive_file(tmp_path, _payload(request, source)), destination
        )

        assert refused.kind is kind
        assert str(refused) == message
        assert not destination.exists(), "a refused archive made the destination"

    @pytest.mark.parametrize("source,kind,message", REFUSED)
    def test_the_finalize_refuses_it_in_the_same_words(
        self, request, tmp_path, source, kind, message
    ):
        """Red at the base for the NUL row: the finalize extracted ``tool<NUL>.py``
        as ``tool``, which no Python scanner reads."""
        payload = _payload(request, source)
        shared = _verdict(
            _extraction_refusal(_archive_file(tmp_path, payload), tmp_path / "tree")
        )
        delivered = _verdict(_finalize_refusal(payload, tmp_path / "workspace"))

        assert delivered == (shared[0], _in_the_finalizes_words(shared[1]))
        assert delivered[0] is kind

    def test_the_finalize_keeps_its_own_words_for_a_link(self, tmp_path):
        payload = _zip_with_modes({"evil": (b"/outside/the/tree", 0o120777)})
        refused = _finalize_refusal(payload, tmp_path / "workspace")

        assert str(refused) == (
            "symlink 'evil' -> '/outside/the/tree': "
            "symlinks are not allowed in MCP source delivery zips"
        )

    def test_an_archive_over_100_mib_is_refused_before_it_is_read(self, tmp_path):
        destination = tmp_path / "tree"
        refused = _extraction_refusal(
            _sparse(tmp_path / "big.zip", 100 * MiB + 1), destination
        )

        assert refused.kind is Kind.ARCHIVE_TOO_LARGE
        assert str(refused) == f"zip too large: {100 * MiB + 1} > {100 * MiB} bytes"
        assert not destination.exists()

    def test_the_finalize_refuses_the_same_oversized_archive_in_the_same_words(
        self, tmp_path
    ):
        """The chunks cannot carry an archive past the limit, so the finalized file is
        grown in place, as an archive put there some other way would be."""
        workspace = tmp_path / "workspace"
        small = _zip({"a.py": b"x"})
        _upload(small, workspace)
        os.truncate(sd._final_zip_path(workspace / SESSION, UPLOAD), 100 * MiB + 1)
        with pytest.raises(ValueError) as delivered:
            _finalize(small, workspace)

        shared = _extraction_refusal(
            _sparse(tmp_path / "big.zip", 100 * MiB + 1), tmp_path / "tree"
        )
        assert _verdict(delivered.value) == _verdict(shared)


class TestTheBoundariesAreAdmitted:
    """Controls for the limits: each one admits the value at the limit itself."""

    def test_an_archive_of_exactly_100_mib_passes_the_size_rule(self, tmp_path):
        refused = _extraction_refusal(
            _sparse(tmp_path / "edge.zip", 100 * MiB), tmp_path / "tree"
        )

        # It is not a zip, the next rule: the size rule let it through.
        assert refused.kind is Kind.NOT_A_ZIP

    def test_exactly_500_mib_uncompressed_is_admitted(self):
        with zipfile.ZipFile(io.BytesIO(_zeros_member(500 * MiB))) as archive:
            members = sa.admit_zip_members(archive)

        assert [member.file_size for member in members] == [500 * MiB]

    def test_exactly_50000_members_are_admitted(self):
        with zipfile.ZipFile(io.BytesIO(_empty_members(50_000))) as archive:
            assert len(sa.admit_zip_members(archive)) == 50_000

    def test_the_limits_are_the_deliverys(self):
        limits = (sa.MAX_ARCHIVE_BYTES, sa.MAX_EXTRACTED_BYTES, sa.MAX_MEMBERS)

        assert limits == (100 * MiB, 500 * MiB, 50_000)
        assert limits == (sd._MAX_ZIP_BYTES, sd._MAX_EXTRACTED_BYTES, sd._MAX_FILES)
        assert sa.SUPPORTED_ARCHIVE_FORMATS == ("zip",)


# ---------------------------------------------------------------------------
# What is extracted.
# ---------------------------------------------------------------------------


class TestTheTreeIsExtractedAsArchived:
    def test_a_nested_tree_extracts_to_the_same_files(self, tmp_path):
        source = _nested_tree(tmp_path / "source")
        archive = _archive_file(tmp_path, _zip_of(source))
        destination = tmp_path / "tree"

        assert sa.extract_source_archive(archive, destination) == destination
        assert _tree(destination) == _tree(source)

    def test_the_finalize_delivers_the_same_tree(self, tmp_path):
        source = _nested_tree(tmp_path / "source")
        payload = _zip_of(source)
        extracted = sa.extract_source_archive(
            _archive_file(tmp_path, payload), tmp_path / "tree"
        )

        _upload(payload, tmp_path / "workspace")
        delivered = _finalize(payload, tmp_path / "workspace")

        assert _tree(delivered) == _tree(extracted) == _tree(source)

    def test_members_without_a_unix_file_type_are_regular_files(self, tmp_path):
        """Control for the link rule: Windows zip tools write no type bits, and
        ``writestr`` writes a mode with none either."""
        payload = _zip_with_modes(
            {"a.py": (b"print(1)\n", 0), "b.py": (b"print(2)\n", 0o644)}
        )

        destination = sa.extract_source_archive(
            _archive_file(tmp_path, payload), tmp_path / "tree"
        )

        assert _tree(destination) == {"a.py": b"print(1)\n", "b.py": b"print(2)\n"}

    def test_an_empty_existing_destination_is_used(self, tmp_path):
        destination = tmp_path / "tree"
        destination.mkdir()

        sa.extract_source_archive(
            _archive_file(tmp_path, _zip({"a.py": b"x"})), destination
        )

        assert _tree(destination) == {"a.py": b"x"}

    def test_a_destination_that_holds_anything_is_left_as_it_was(self, tmp_path):
        """Extracting into a tree that is already there would scan files the
        archive never held, so the call is refused, as the caller's error."""
        destination = tmp_path / "tree"
        destination.mkdir()
        (destination / "kept.txt").write_bytes(b"already here")

        with pytest.raises(OSError) as refused:
            sa.extract_source_archive(
                _archive_file(tmp_path, _zip({"a.py": b"x"})), destination
            )

        assert not isinstance(refused.value, sa.SourceArchiveRefused)
        assert _tree(destination) == {"kept.txt": b"already here"}


# ---------------------------------------------------------------------------
# What extract_source_archive adds, since it opens and extracts the file itself.
# ---------------------------------------------------------------------------


class TestTheFileItselfIsChecked:
    def test_a_path_that_is_not_a_regular_file_is_refused(self, tmp_path):
        directory = tmp_path / "a-directory.zip"
        directory.mkdir()

        refused = _extraction_refusal(directory, tmp_path / "tree")

        assert refused.kind is Kind.NOT_A_FILE
        assert str(refused) == f"{str(directory)!r} is not a regular file"

    def test_a_path_that_cannot_be_read_is_refused(self, tmp_path):
        missing = tmp_path / "missing.zip"

        refused = _extraction_refusal(missing, tmp_path / "tree")

        assert refused.kind is Kind.UNREADABLE_ARCHIVE
        assert str(refused).startswith(f"{str(missing)!r} cannot be read: ")

    def test_a_path_holding_a_nul_is_refused(self, tmp_path):
        """A ``--cli-json-input`` document can carry one; a command line cannot."""
        refused = _extraction_refusal(
            Path(f"{tmp_path}/bad\x00name.zip"), tmp_path / "tree"
        )

        assert refused.kind is Kind.UNREADABLE_ARCHIVE
        assert "is not a valid path" in str(refused)

    def test_an_encrypted_member_is_refused_before_anything_is_written(self, tmp_path):
        payload = _flagged_encrypted(_zip({"a.py": b"print(1)\n"}))
        destination = tmp_path / "tree"

        refused = _extraction_refusal(_archive_file(tmp_path, payload), destination)

        assert refused.kind is Kind.ENCRYPTED_MEMBER
        assert "'a.py'" in str(refused)
        assert not destination.exists()

    def test_a_member_whose_data_fails_its_checksum_is_refused(self, tmp_path):
        content = b"VALUE = 'stored as it is'\n"
        payload = _with_damaged_data(
            _zip({"a.py": content}, compression=zipfile.ZIP_STORED), content
        )

        refused = _extraction_refusal(
            _archive_file(tmp_path, payload), tmp_path / "tree"
        )

        assert refused.kind is Kind.UNREADABLE_MEMBER
        assert "'a.py'" in str(refused)
        assert "Bad CRC-32" in str(refused)


class TestTheRefusal:
    def test_it_is_a_value_error_whose_kind_and_words_survive_a_copy(self):
        refused = sa.SourceArchiveRefused(Kind.PATH_TRAVERSAL, "path traversal in zip")

        copied = copy.deepcopy(refused)

        assert isinstance(copied, ValueError)
        assert copied.kind is Kind.PATH_TRAVERSAL
        assert str(copied) == "path traversal in zip"

    def test_every_kind_is_a_stable_string(self):
        assert {kind.value for kind in Kind} == {
            "archive-too-large",
            "too-many-members",
            "extracted-too-large",
            "empty-name",
            "backslash-in-name",
            "absolute-path",
            "path-traversal",
            "nul-in-name",
            "symlink-member",
            "not-a-zip",
            "not-a-file",
            "unreadable-archive",
            "encrypted-member",
            "unreadable-member",
        }
