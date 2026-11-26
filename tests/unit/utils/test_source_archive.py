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

Archives zipfile cannot read are built the same way, by changing the bytes of a good
one where the zip format puts the field: a central directory entry that needs a newer
reader, a damaged compressed stream, a local header whose name is not the UTF-8 it
claims, and offsets that point before the file or past what a seek can reach. Every
one of them has to reach the caller of ``extract_source_archive`` as a refusal.
"""

from __future__ import annotations

import base64
import copy
import gzip
import hashlib
import io
import os
import struct
import tarfile
import warnings
import zipfile
import zlib
from pathlib import Path
from typing import Dict, Optional, Sequence, Tuple, Union

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


def _zip_members(entries: Sequence[Tuple[str, bytes]]) -> bytes:
    """A zip holding ``entries``, name and content, in order, a repeated name included."""
    buffer = io.BytesIO()
    with warnings.catch_warnings():
        # zipfile warns on a name it already wrote, and writes it again as asked.
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, content in entries:
                archive.writestr(name, content)
    return buffer.getvalue()


def _unicode_path_field(spelled: bytes, name: str) -> bytes:
    """A Unicode path extra field (0x7075) giving ``name`` to a member spelled ``spelled``.

    Version 1, the CRC-32 of the spelled name's bytes (zipfile reads the field only
    when it matches them), then the name in UTF-8.
    """
    data = struct.pack("<BL", 1, zlib.crc32(spelled)) + name.encode("utf-8")
    return struct.pack("<HH", 0x7075, len(data)) + data


def _zip_with_unicode_paths(
    entries: Sequence[Tuple[str, Optional[str], bytes]],
) -> bytes:
    """A zip of ``(name, the name its Unicode path field gives or None, content)``."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, unicode_path, content in entries:
            info = zipfile.ZipInfo(name)
            if unicode_path is not None:
                info.extra = _unicode_path_field(name.encode("ascii"), unicode_path)
            archive.writestr(info, content)
    return buffer.getvalue()


def _info_zip_utf8_name(name: str, content: bytes) -> bytes:
    """One stored member named ``name`` as Info-ZIP writes a name outside ASCII.

    On a UTF-8 system it stores the name's UTF-8 bytes without the UTF-8 flag, so
    zipfile reads the spelled name as cp437, and restates the name in a Unicode path
    field. zipfile sets the flag for any name outside ASCII, so a placeholder of the
    same length is written and the bytes are swapped in afterwards.
    """
    spelled = name.encode("utf-8")
    placeholder = "X" * len(spelled)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        info = zipfile.ZipInfo(placeholder)
        info.extra = _unicode_path_field(spelled, name)
        archive.writestr(info, content)
    return _renamed(buffer.getvalue(), placeholder, spelled)


def _zipfile_reads_unicode_paths() -> bool:
    """Whether this Python's zipfile extracts a member under its Unicode path field.

    From 3.12 it does; before, the field is ignored and the spelled name is used.
    """
    payload = _zip_with_unicode_paths([("a.py", "b.py", b"")])
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        return archive.infolist()[0].filename == "b.py"


ZIPFILE_READS_UNICODE_PATHS = _zipfile_reads_unicode_paths()
_NEEDS_UNICODE_PATHS = pytest.mark.skipif(
    not ZIPFILE_READS_UNICODE_PATHS,
    reason="zipfile before Python 3.12 ignores the Unicode path field",
)


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


def _with_version_needed(payload: bytes, version: int) -> bytes:
    """``payload``, a zip of one member, whose central directory entry needs ``version``.

    "Version needed to extract" is at offset 6 of the entry, in tenths (63 is 6.3);
    zipfile reads it when it opens the archive and implements up to 6.3.
    """
    data = bytearray(payload)
    central = data.find(b"PK\x01\x02")
    assert central > 0
    data[central + 6 : central + 8] = struct.pack("<H", version)
    return bytes(data)


def _with_first_data_byte_flipped(payload: bytes) -> bytes:
    """``payload``, a zip of one member, with the first byte of that member's data changed.

    The data starts after the 30-byte local header, the name and the extra field, whose
    lengths are at offsets 26 and 28 of the header.
    """
    data = bytearray(payload)
    assert data[:4] == b"PK\x03\x04"
    name_length, extra_length = struct.unpack("<HH", data[26:30])
    data[30 + name_length + extra_length] ^= 0xFF
    return bytes(data)


def _with_local_name_not_utf8(payload: bytes, name: str) -> bytes:
    """``payload``, whose one member is named ``name``, with a local header that lies.

    The local header's copy of the name gets a first byte that starts no UTF-8
    sequence, and the header claims UTF-8 (flag bit 11, offset 6). The central
    directory still spells ``name``, so the archive opens; reading the member decodes
    the local name and fails.
    """
    spelled = name.encode("ascii")
    data = bytearray(payload)
    assert data[:4] == b"PK\x03\x04" and payload.count(spelled) == 2
    at = data.index(spelled)
    data[at] = 0xFF
    (flags,) = struct.unpack("<H", data[6:8])
    data[6:8] = struct.pack("<H", flags | 0x800)
    return bytes(data)


def _with_central_directory_moved_on(payload: bytes, by: int) -> bytes:
    """``payload`` with the end record's central directory offset ``by`` bytes too far.

    zipfile takes the excess as data concatenated before the archive and subtracts it
    from every member's header offset, so the first member's comes out negative.
    """
    data = bytearray(payload)
    end = data.rfind(b"PK\x05\x06")
    (offset,) = struct.unpack("<I", data[end + 16 : end + 20])
    data[end + 16 : end + 20] = struct.pack("<I", offset + by)
    return bytes(data)


def _with_zip64_header_offset(payload: bytes, offset: int) -> bytes:
    """``payload``, a zip of one member, whose header offset is ``offset`` by zip64.

    The central directory entry's offset (at 42) is set to 0xFFFFFFFF and a zip64 extra
    field carries the real one, as zipfile writes for an archive past 4 GiB; the entry's
    extra length (at 30) and the end record's central directory size grow to match.
    """
    data = bytearray(payload)
    central = data.find(b"PK\x01\x02")
    name_length, extra_length, comment_length = struct.unpack(
        "<HHH", data[central + 28 : central + 34]
    )
    assert extra_length == 0 and comment_length == 0
    extra = struct.pack("<HHQ", 0x0001, 8, offset)
    data[central + 42 : central + 46] = struct.pack("<I", 0xFFFFFFFF)
    data[central + 30 : central + 32] = struct.pack("<H", len(extra))
    name_end = central + 46 + name_length
    data[name_end:name_end] = extra
    end = data.rfind(b"PK\x05\x06")
    (size,) = struct.unpack("<I", data[end + 12 : end + 16])
    data[end + 12 : end + 16] = struct.pack("<I", size + len(extra))
    return bytes(data)


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
    # zipfile drops "." and empty components when it extracts, so each of these
    # lands on a path the archive spells another way: probe_mod.py beside
    # ./probe_mod.py is one file on disk and two members to a reader that looks
    # members up by name, as zipimport does. Red at the base: all three were admitted.
    pytest.param(
        _zip({"./app.py": b"x"}),
        Kind.DOT_COMPONENT,
        "'.' component in zip entry name: './app.py'",
        id="leading-dot-component",
    ),
    pytest.param(
        _zip({"a/./b.py": b"x"}),
        Kind.DOT_COMPONENT,
        "'.' component in zip entry name: 'a/./b.py'",
        id="inner-dot-component",
    ),
    pytest.param(
        # Red at the base as the raw ValueError("Empty filename.") of the extraction.
        _zip({".": b"x"}),
        Kind.DOT_COMPONENT,
        "'.' component in zip entry name: '.'",
        id="a-name-that-is-one-dot",
    ),
    pytest.param(
        _zip({"pkg//mod.py": b"x"}),
        Kind.EMPTY_COMPONENT,
        "empty component in zip entry name: 'pkg//mod.py'",
        id="empty-component",
    ),
    pytest.param(
        _zip({"pkg//": b""}),
        Kind.EMPTY_COMPONENT,
        "empty component in zip entry name: 'pkg//'",
        id="a-directory-with-two-trailing-slashes",
    ),
    # One path, one member. Red at the base: the first two were extracted the later
    # over the earlier, and the rest ended in the OSError of the clash on disk.
    pytest.param(
        _zip_members([("app.py", b"EVIL = True\n"), ("app.py", b"EVIL = False\n")]),
        Kind.PATH_COLLISION,
        "zip entries 'app.py' and 'app.py' are extracted to one path",
        id="two-members-of-one-name",
    ),
    pytest.param(
        _zip_members([("pkg/", b""), ("pkg/", b"")]),
        Kind.PATH_COLLISION,
        "zip entries 'pkg/' and 'pkg/' are extracted to one path",
        id="two-directory-members-of-one-name",
    ),
    pytest.param(
        _zip_members([("pkg", b"a file"), ("pkg/", b"")]),
        Kind.PATH_COLLISION,
        "zip entries 'pkg' and 'pkg/' are extracted to one path",
        id="a-file-and-a-directory-of-one-path",
    ),
    pytest.param(
        _zip_members([("pkg", b"a file"), ("pkg/mod.py", b"x")]),
        Kind.PATH_COLLISION,
        "zip entry 'pkg/mod.py' is under 'pkg', which the archive holds as a file",
        id="a-member-under-an-earlier-file",
    ),
    pytest.param(
        _zip_members([("pkg/mod.py", b"x"), ("pkg", b"a file")]),
        Kind.PATH_COLLISION,
        "zip entry 'pkg/mod.py' is under 'pkg', which the archive holds as a file",
        id="a-file-at-the-directory-of-an-earlier-member",
    ),
    pytest.param(
        # "a-b" sorts between "a" and "a/c" when "/" is compared as itself; the rule
        # has to find "a/c" under the file "a" anyway.
        _zip_members([("a", b"a file"), ("a-b", b"x"), ("a/c", b"y")]),
        Kind.PATH_COLLISION,
        "zip entry 'a/c' is under 'a', which the archive holds as a file",
        id="a-member-under-a-file-with-a-sibling-between",
    ),
    pytest.param(
        # zipfile extracts the second member as app.py, over the first; zipimport and
        # every reader that ignores the field keep the first.
        _zip_with_unicode_paths(
            [
                ("app.py", None, b"EVIL = True\n"),
                ("zzz.py", "app.py", b"EVIL = False\n"),
            ]
        ),
        Kind.UNICODE_PATH_MISMATCH,
        "zip entry 'zzz.py' is extracted as 'app.py': "
        "its Unicode path field names another file",
        id="a-unicode-path-onto-another-member",
        marks=_NEEDS_UNICODE_PATHS,
    ),
    pytest.param(
        # Scanned as text while `import app` runs it.
        _zip_with_unicode_paths([("app.py", "app.txt", b"EVIL = True\n")]),
        Kind.UNICODE_PATH_MISMATCH,
        "zip entry 'app.py' is extracted as 'app.txt': "
        "its Unicode path field names another file",
        id="a-unicode-path-that-renames-the-member",
        marks=_NEEDS_UNICODE_PATHS,
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

    def test_paths_that_share_a_head_but_not_a_directory_are_admitted(self, tmp_path):
        """Control for the one-path rule: a file ``pkg`` and the members ``pkg-x/a.py``
        and ``pkg.py`` beside it name three paths, none under another."""
        entries = [("pkg", b"a file"), ("pkg-x/a.py", b"x"), ("pkg.py", b"y")]
        destination = sa.extract_source_archive(
            _archive_file(tmp_path, _zip_members(entries)), tmp_path / "tree"
        )

        assert _tree(destination) == {
            "pkg": b"a file",
            "pkg-x": None,
            "pkg-x/a.py": b"x",
            "pkg.py": b"y",
        }

    def test_a_directory_member_with_members_under_it_is_admitted(self, tmp_path):
        """Control: a directory and the files under it are one tree, not a clash."""
        entries = [("pkg/", b""), ("pkg/mod.py", b"x"), ("pkg/sub/", b"")]
        destination = sa.extract_source_archive(
            _archive_file(tmp_path, _zip_members(entries)), tmp_path / "tree"
        )

        assert _tree(destination) == {
            "pkg": None,
            "pkg/mod.py": b"x",
            "pkg/sub": None,
        }


class TestAUnicodePathField:
    """Rule 3: the name zipfile extracts a member under has to be the member's own."""

    def test_one_that_restates_a_utf8_name_is_admitted(self, tmp_path):
        """Info-ZIP's own shape for a name outside ASCII, from a UTF-8 system: the
        member is extracted under the name zipfile reads, by both entry points."""
        payload = _info_zip_utf8_name("docs/café.md", b"# Notes\n")
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            (written,) = archive.namelist()

        extracted = sa.extract_source_archive(
            _archive_file(tmp_path, payload), tmp_path / "tree"
        )
        _upload(payload, tmp_path / "workspace")
        delivered = _finalize(payload, tmp_path / "workspace")

        assert _tree(extracted) == {"docs": None, written: b"# Notes\n"}
        assert _tree(delivered) == _tree(extracted)

    @_NEEDS_UNICODE_PATHS
    def test_the_restated_name_is_the_utf8_one(self):
        """What the row above extracts, from 3.12: the field's name, not cp437 text."""
        payload = _info_zip_utf8_name("docs/café.md", b"# Notes\n")
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            (info,) = sa.admit_zip_members(archive)

        assert info.filename == "docs/café.md"
        assert info.orig_filename != info.filename

    @pytest.mark.skipif(
        ZIPFILE_READS_UNICODE_PATHS,
        reason="this zipfile extracts under the Unicode path field",
    )
    def test_a_zipfile_that_ignores_the_field_extracts_the_spelled_names(
        self, tmp_path
    ):
        """Why rule 3 refuses nothing before 3.12: the names extracted are the ones
        the archive spells, which every reader sees."""
        payload = _zip_with_unicode_paths([("app.py", "app.txt", b"x")])

        destination = sa.extract_source_archive(
            _archive_file(tmp_path, payload), tmp_path / "tree"
        )

        assert _tree(destination) == {"app.py": b"x"}


#: Names Windows cannot hold as spelled, and the component that makes each so.
WINDOWS_RESERVED = [
    pytest.param("a:b.py", "a:b.py", id="colon"),
    pytest.param("pkg/q?.py", "q?.py", id="question-mark"),
    pytest.param("star*.py", "star*.py", id="asterisk"),
    pytest.param("pipe|.py", "pipe|.py", id="pipe"),
    pytest.param('quote".py', 'quote".py', id="double-quote"),
    pytest.param("lt<gt>.py", "lt<gt>.py", id="angle-brackets"),
    pytest.param("tab\there.py", "tab\there.py", id="control-character"),
    pytest.param("pkg/x.py.", "x.py.", id="trailing-dot"),
    pytest.param("dir./x.py", "dir.", id="trailing-dot-on-a-directory"),
    pytest.param("x.py ", "x.py ", id="trailing-space"),
    pytest.param("nul.py", "nul.py", id="device-name-with-an-extension"),
    pytest.param("pkg/CON", "CON", id="device-name"),
    pytest.param("aux/x.py", "aux", id="device-name-as-a-directory"),
    pytest.param("COM1.txt", "COM1.txt", id="numbered-device-name"),
    pytest.param("lpt\xb9.txt", "lpt\xb9.txt", id="superscript-device-name"),
    pytest.param("nul .txt", "nul .txt", id="device-name-and-a-space"),
]


class TestNamesWindowsCannotHold:
    """Rule 2 on Windows: zipfile would rewrite these, or Windows would open a device."""

    @pytest.mark.parametrize("name,component", WINDOWS_RESERVED)
    def test_on_windows_each_is_refused(self, monkeypatch, name, component):
        monkeypatch.setattr(sa, "_ON_WINDOWS", True)

        with pytest.raises(sa.SourceArchiveRefused) as refused:
            sa.validate_member_name(name)

        assert refused.value.kind is Kind.RESERVED_NAME
        assert str(refused.value) == (
            f"reserved name on Windows in zip entry name {name!r}: {component!r}"
        )

    @pytest.mark.parametrize("name,component", WINDOWS_RESERVED)
    def test_elsewhere_each_is_a_plain_name(self, monkeypatch, name, component):
        monkeypatch.setattr(sa, "_ON_WINDOWS", False)

        sa.validate_member_name(name)

    @pytest.mark.parametrize(
        "name",
        [
            "app.py",
            "docs/guide.md",
            "..config/settings.toml",
            "notes..txt",
            "pkg/",
            "connect.py",
            "console.log",
            "nul_device.md",
            "com10.txt",
            "lpt0",
            "auxiliary/x.py",
        ],
    )
    def test_on_windows_names_it_can_hold_are_admitted(self, monkeypatch, name):
        monkeypatch.setattr(sa, "_ON_WINDOWS", True)

        sa.validate_member_name(name)

    def test_on_windows_the_finalize_refuses_one_in_the_same_words(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setattr(sa, "_ON_WINDOWS", True)
        payload = _zip({"a:b.py": b"x"})

        shared = _verdict(
            _extraction_refusal(_archive_file(tmp_path, payload), tmp_path / "tree")
        )
        delivered = _verdict(_finalize_refusal(payload, tmp_path / "workspace"))

        assert delivered == shared
        assert shared[0] is Kind.RESERVED_NAME

    @_NEEDS_UNICODE_PATHS
    def test_on_windows_the_name_a_unicode_path_field_gives_is_judged_too(
        self, monkeypatch, tmp_path
    ):
        """The field restates COM² from its UTF-8 bytes, which zipfile spells as
        cp437 text no rule refuses; extracted, it is the device COM²."""
        monkeypatch.setattr(sa, "_ON_WINDOWS", True)
        payload = _info_zip_utf8_name("COM\xb2.py", b"x")

        refused = _extraction_refusal(
            _archive_file(tmp_path, payload), tmp_path / "tree"
        )

        assert refused.kind is Kind.RESERVED_NAME
        assert str(refused) == (
            "reserved name on Windows in zip entry name 'COM\xb2.py': 'COM\xb2.py'"
        )

    @pytest.mark.skipif(os.name == "nt", reason="Windows cannot create the name")
    def test_elsewhere_a_colon_name_is_extracted_as_spelled(self, tmp_path):
        destination = sa.extract_source_archive(
            _archive_file(tmp_path, _zip({"a:b.py": b"x"})), tmp_path / "tree"
        )

        assert _tree(destination) == {"a:b.py": b"x"}

    def test_the_rule_follows_the_platform(self):
        assert sa._ON_WINDOWS is (os.name == "nt")


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

    @pytest.mark.skipif(
        not Path("/proc/self/status").is_file(), reason="needs Linux /proc"
    )
    def test_a_file_longer_than_it_measured_is_refused_once_read_past_the_limit(
        self, monkeypatch, tmp_path
    ):
        """The size is checked before the read and again after it: a file that grew
        in between is refused, not read whole. A /proc file is a regular file that
        measures 0 bytes and holds more, which is the same shape."""
        monkeypatch.setattr(sa, "MAX_ARCHIVE_BYTES", 64)

        refused = _extraction_refusal(Path("/proc/self/status"), tmp_path / "tree")

        assert refused.kind is Kind.ARCHIVE_TOO_LARGE
        assert str(refused) == "zip too large: 65 > 64 bytes"
        assert not (tmp_path / "tree").exists()

    @pytest.mark.skipif(
        os.name == "nt" or os.geteuid() == 0,
        reason="needs POSIX permissions that bind the process",
    )
    def test_a_destination_that_cannot_be_written_is_an_os_error(self, tmp_path):
        """The other half of the contract: what goes wrong writing the tree is the
        destination's, and is not reported as the archive's."""
        destination = tmp_path / "tree"
        destination.mkdir()
        destination.chmod(0o500)
        try:
            with pytest.raises(OSError) as failed:
                sa.extract_source_archive(
                    _archive_file(tmp_path, _zip({"a.py": b"x"})), destination
                )
        finally:
            destination.chmod(0o700)

        assert not isinstance(failed.value, sa.SourceArchiveRefused)
        assert isinstance(failed.value, PermissionError)


class TestWhatZipfileCannotReadIsARefusal:
    """Every way zipfile fails on a crafted archive reaches the caller as a refusal.

    ``extract_source_archive`` says every problem with the archive is a
    ``SourceArchiveRefused`` and an ``OSError`` is the destination's or the disk's, so
    a caller that tells them apart can show a refusal and stop. Each row is an
    exception zipfile raises that is neither, or an ``OSError`` raised for the
    archive's bytes alone. Red at the base: each reached the caller as it was raised.
    """

    def test_a_member_that_needs_a_newer_zip_reader_is_refused(self, tmp_path):
        """NotImplementedError from ``zipfile.ZipFile`` itself, as it opens the file."""
        payload = _with_version_needed(_zip({"a.py": b"x"}), 64)
        destination = tmp_path / "tree"

        refused = _extraction_refusal(_archive_file(tmp_path, payload), destination)

        assert refused.kind is Kind.UNREADABLE_MEMBER
        assert str(refused) == "the archive cannot be read: zip file version 6.4"
        assert not destination.exists()

    def test_control_the_newest_version_zipfile_reads_is_admitted(self, tmp_path):
        payload = _with_version_needed(_zip({"a.py": b"x"}), 63)

        destination = sa.extract_source_archive(
            _archive_file(tmp_path, payload), tmp_path / "tree"
        )

        assert _tree(destination) == {"a.py": b"x"}

    @pytest.mark.skipif(
        getattr(zipfile, "zstd", None) is None,
        reason="this zipfile has no Zstandard support (Python 3.14 adds it)",
    )
    def test_a_damaged_zstandard_member_is_refused(self, tmp_path):
        """compression.zstd.ZstdError, neither a ValueError nor an OSError."""
        content = b"print('a source line')\n" * 50
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("a.py", content, compress_type=zipfile.ZIP_ZSTANDARD)
        payload = _with_first_data_byte_flipped(buffer.getvalue())

        refused = _extraction_refusal(
            _archive_file(tmp_path, payload), tmp_path / "tree"
        )

        assert refused.kind is Kind.UNREADABLE_MEMBER
        assert str(refused).startswith("zip entry 'a.py' cannot be read: ")

    def test_a_method_whose_module_this_python_lacks_is_refused(
        self, monkeypatch, tmp_path
    ):
        """RuntimeError, which zipfile raises for an LZMA member when the lzma module
        is missing: a Python built without it reads the archive this way."""
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_LZMA) as archive:
            archive.writestr("a.py", b"print(1)\n")
        archive_path = _archive_file(tmp_path, buffer.getvalue())
        monkeypatch.setattr(zipfile, "lzma", None)

        refused = _extraction_refusal(archive_path, tmp_path / "tree")

        assert refused.kind is Kind.UNREADABLE_MEMBER
        assert str(refused) == (
            "zip entry 'a.py' cannot be read: "
            "Compression requires the (missing) lzma module"
        )

    def test_a_local_header_whose_name_is_not_the_utf8_it_claims_is_refused(
        self, tmp_path
    ):
        """UnicodeDecodeError: a ValueError, but not a refusal."""
        payload = _with_local_name_not_utf8(_zip({"aa.py": b"x"}), "aa.py")

        refused = _extraction_refusal(
            _archive_file(tmp_path, payload), tmp_path / "tree"
        )

        assert refused.kind is Kind.UNREADABLE_MEMBER
        assert str(refused).startswith("zip entry 'aa.py' cannot be read: ")
        assert "can't decode byte 0xff" in str(refused)

    def test_a_header_offset_before_the_file_is_refused(self, tmp_path):
        """An OSError (EINVAL) read from the file at the base, which the contract
        reserves for the disk: the offset is the archive's own."""
        payload = _with_central_directory_moved_on(_zip({"a.py": b"x"}), 1000)

        refused = _extraction_refusal(
            _archive_file(tmp_path, payload), tmp_path / "tree"
        )

        assert refused.kind is Kind.UNREADABLE_MEMBER
        assert str(refused).startswith("zip entry 'a.py' cannot be read: ")

    def test_a_header_offset_past_what_a_seek_can_reach_is_refused(self, tmp_path):
        """A zip64 offset of 2**63, which no seek takes."""
        payload = _with_zip64_header_offset(
            _zip({"a.py": b"x"}, compression=zipfile.ZIP_STORED), 2**63
        )

        refused = _extraction_refusal(
            _archive_file(tmp_path, payload), tmp_path / "tree"
        )

        assert refused.kind is Kind.UNREADABLE_MEMBER
        assert str(refused).startswith("zip entry 'a.py' cannot be read: ")


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
            "dot-component",
            "empty-component",
            "nul-in-name",
            "reserved-name",
            "unicode-path-mismatch",
            "path-collision",
            "symlink-member",
            "not-a-zip",
            "not-a-file",
            "unreadable-archive",
            "encrypted-member",
            "unreadable-member",
        }
