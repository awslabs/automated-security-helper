"""Regression test: validate_mcpb_archive must report a damaged archive, not crash.

WHY THIS EXISTS

The committed ash.mcpb is built deterministically so it can be drift-checked, and
`agentic-plugins check` does byte-compare it. Flipping a single byte of the
committed archive to prove that check can fail turned up a second defect in the
same run: drift was reported correctly, and then validation died with

    zlib.error: Error -3 while decompressing data: invalid distances set

escaping validate_mcpb_archive's `except (zipfile.BadZipFile,
json.JSONDecodeError, KeyError)`. The function's docstring promises an "MCPB
archive unreadable" error, so the handler was asserting a property it did not
implement.

The mechanism is worth remembering, because "it is a ZIP problem so BadZipFile
covers it" is the natural wrong assumption: zipfile validates the *container*
from the central directory, which a byte flip inside a member's compressed
payload leaves entirely intact. The failure therefore does not occur at open
time at all -- it comes out of zf.read(), from zlib, as a zlib.error.

WHAT THIS TEST PINS

Three things, and the third is the control:

  - a corrupt deflate stream is reported, not raised
  - a manifest member that is not valid UTF-8 is reported, not raised
    (json.loads on bytes decodes first, and UnicodeDecodeError is a ValueError
    but NOT a json.JSONDecodeError, so it escaped the same handler). The choice
    of payload is load-bearing and the test body explains why -- a \\xff\\xfe
    prefix is BOM-sniffed into the JSONDecodeError path that already worked.
  - an intact archive produces no errors at all, so these assertions cannot be
    satisfied by a validator that has begun rejecting everything

KNOWN LIMITATION

This covers only the decode path. validate_mcpb_archive still returns [] when
the archive is absent, which is a deliberate fail-open for backends built
without the mcpb output present -- it is not what this test is about, and the
absent-archive case is caught upstream by the drift comparison instead.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from transpiler.packagers import mcpb_archive
from validate import validate_mcpb_archive

# Carries every field schemas/mcpb-manifest.schema.json lists as required
# (name, version, description, author, server) because validate_mcpb_archive
# re-validates the embedded manifest against that schema. A fixture missing any
# of them makes the control below fail for a reason unrelated to corruption --
# which is how this set was arrived at, the control having caught exactly that.
MANIFEST = {
    "manifest_version": "0.4",
    "name": "ash",
    "version": "1.0.0",
    "description": "test fixture",
    "author": {"name": "test"},
    "server": {
        "type": "binary",
        "entry_point": "uvx",
        "mcp_config": {"command": "uvx", "args": [], "env": {}},
    },
}


def _plugins_root(tmp_path: Path, archive_bytes: bytes) -> Path:
    """Lay out the plugins_root shape validate_mcpb_archive expects."""
    root = tmp_path / "plugins"
    mcpb_dir = root / "mcpb"
    mcpb_dir.mkdir(parents=True)
    (mcpb_dir / "ash.mcpb").write_bytes(archive_bytes)
    # The on-disk source manifest, so the archive-vs-source comparison at the
    # end of the validator has something to compare against on the happy path.
    (mcpb_dir / "manifest.json").write_text(json.dumps(MANIFEST, indent=2) + "\n")
    return root


def _corrupt_deflate_stream(archive_bytes: bytes) -> bytes:
    """Replace a member's compressed payload with bytes that cannot be inflated.

    0xFF sets BFINAL=1 and BTYPE=11 in the first deflate block header, and
    BTYPE=11 is the reserved value, so zlib rejects it outright. That is chosen
    over flipping one arbitrary byte on purpose: a single flip sometimes still
    inflates and fails the CRC instead, which raises BadZipFile and would test
    the branch that already worked. This forces the zlib.error path every run.

    The central directory is left untouched, which is the whole point -- the
    archive still opens cleanly and only fails when the member is read.
    """
    with zipfile.ZipFile(__import__("io").BytesIO(archive_bytes)) as zf:
        info = zf.getinfo("manifest.json")
    # Local file header is 30 bytes, then the filename, then the payload.
    start = info.header_offset + 30 + len(info.filename.encode("utf-8"))
    end = start + info.compress_size
    data = bytearray(archive_bytes)
    data[start:end] = b"\xff" * info.compress_size
    return bytes(data)


def _archive_with_raw_manifest(payload: bytes) -> bytes:
    """A structurally valid archive whose manifest.json member is `payload`."""
    import io

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", payload)
    return buf.getvalue()


def test_intact_archive_produces_no_errors(tmp_path):
    """Control. Without this, the two tests below would also pass against a
    validator that had started rejecting every archive it was handed."""
    root = _plugins_root(tmp_path, mcpb_archive(MANIFEST))
    errors = validate_mcpb_archive(root)
    assert errors == [], f"intact archive must validate clean, got: {errors}"


def test_corrupt_deflate_stream_is_reported_not_raised(tmp_path):
    """A damaged compressed payload must come back as an error tuple.

    Before the fix this raised zlib.error straight through
    `agentic-plugins check`, so the operator got a traceback where a verdict
    was promised, and any validator sequenced after this one was skipped.
    """
    corrupted = _corrupt_deflate_stream(mcpb_archive(MANIFEST))

    # Establish that the fixture really does reproduce the reported mechanism:
    # the container opens fine and only the member read blows up. If a future
    # zipfile hardens this, the test below stops testing what it claims to and
    # this assertion is what says so.
    with zipfile.ZipFile(__import__("io").BytesIO(corrupted)) as zf:
        assert zf.namelist() == ["manifest.json"], (
            "fixture should leave the central directory intact"
        )
        with pytest.raises(Exception) as excinfo:
            zf.read("manifest.json")
    assert excinfo.type.__module__ == "zlib" or isinstance(
        excinfo.value, zipfile.BadZipFile
    ), f"fixture should fail at member-read time, got {excinfo.type!r}"

    root = _plugins_root(tmp_path, corrupted)
    errors = validate_mcpb_archive(root)

    assert len(errors) == 1, (
        f"expected exactly one unreadable-archive error, got {errors}"
    )
    assert "unreadable" in str(errors[0]).lower(), (
        f"error should be the documented 'MCPB archive unreadable' verdict, got {errors[0]!r}"
    )


def test_non_utf8_manifest_is_reported_not_raised(tmp_path):
    """A manifest member that is not valid UTF-8 must be reported too.

    json.loads on bytes decodes before parsing, so invalid UTF-8 raises
    UnicodeDecodeError -- a ValueError, but not a json.JSONDecodeError, so it
    escaped the original handler exactly as zlib.error did.

    MIND THE PAYLOAD. The obvious fixture, b"\\xff\\xfe not utf-8", does NOT
    reach that path and silently tests the branch that already worked:
    json.detect_encoding reads a leading \\xff\\xfe as a UTF-16 BOM, decodes the
    rest as UTF-16 and raises JSONDecodeError, which the original narrow tuple
    already caught. That fixture was tried first here and passed against the
    unfixed code, which is the only reason the substitution below is deliberate
    rather than arbitrary. The payload must be invalid UTF-8 that does not begin
    with a recognized BOM.
    """
    payload = b'{"a": "\xff"}'
    with pytest.raises(UnicodeDecodeError):
        json.loads(payload)  # pins the mechanism this test claims to cover

    root = _plugins_root(tmp_path, _archive_with_raw_manifest(payload))
    errors = validate_mcpb_archive(root)

    assert len(errors) == 1, (
        f"expected exactly one unreadable-archive error, got {errors}"
    )
    assert "unreadable" in str(errors[0]).lower(), (
        f"error should be the documented 'MCPB archive unreadable' verdict, got {errors[0]!r}"
    )


# ---------------------------------------------------------------------------
# The backend's smoke_test reads the same archive through its own handler, and
# carried the same two escapes. It is exercised directly here so a regression in
# either reader is caught, not only the one validate_all happens to call.
# ---------------------------------------------------------------------------


def _smoke(tmp_path: Path, archive_bytes: bytes) -> dict | None:
    from types import SimpleNamespace

    from transpiler.backends.mcpb import MCPBBackend

    out = tmp_path / "mcpb"
    out.mkdir(parents=True, exist_ok=True)
    (out / "ash.mcpb").write_bytes(archive_bytes)
    ctx = SimpleNamespace(out=out, base_dir=tmp_path / "no-base")
    return MCPBBackend().smoke_test(ctx)  # type: ignore[arg-type]


def test_smoke_test_reports_a_corrupt_deflate_stream(tmp_path):
    result = _smoke(tmp_path, _corrupt_deflate_stream(mcpb_archive(MANIFEST)))
    assert result is not None and result.get("ok") is False, result
    assert "not a valid ZIP" in result["reason"], result


def test_smoke_test_reports_a_non_utf8_manifest(tmp_path):
    result = _smoke(tmp_path, _archive_with_raw_manifest(b'{"a": "\xff"}'))
    assert result is not None and result.get("ok") is False, result
    assert "manifest.json inside archive invalid" in result["reason"], result


def test_smoke_test_reaches_the_field_check_on_an_intact_archive(tmp_path):
    """Control: an intact archive gets past both handlers. A manifest missing
    `manifest_version` is used so the result is decided by the field check,
    before any external CLI is consulted."""
    manifest = {k: v for k, v in MANIFEST.items() if k != "manifest_version"}
    result = _smoke(tmp_path, mcpb_archive(manifest))
    assert result == {
        "ok": False,
        "reason": "manifest.json missing `manifest_version`",
    }, result


# ---------------------------------------------------------------------------
# Two more single-field corruptions that leave the central directory readable
# and only fail when the member is opened. zipfile raises NotImplementedError
# for a compression method it does not implement and RuntimeError for a member
# whose encryption flag is set (it asks for a password). Neither is BadZipFile,
# so both escaped the handlers above the same way zlib.error did.
# ---------------------------------------------------------------------------

_CENTRAL_SIG = b"PK\x01\x02"


def _patch_header_field(
    archive_bytes: bytes, local_offset: int, central_offset: int, value: int
) -> bytes:
    """Overwrite one 2-byte field of manifest.json's local AND central header.

    Both copies are patched so the fixture does not depend on which header a
    given Python's zipfile consults first.
    """
    with zipfile.ZipFile(__import__("io").BytesIO(archive_bytes)) as zf:
        info = zf.getinfo("manifest.json")
    data = bytearray(archive_bytes)
    local = info.header_offset
    data[local + local_offset : local + local_offset + 2] = value.to_bytes(2, "little")
    central = data.index(_CENTRAL_SIG)
    data[central + central_offset : central + central_offset + 2] = value.to_bytes(
        2, "little"
    )
    return bytes(data)


def _unknown_compression_method(archive_bytes: bytes) -> bytes:
    # Compression method: local header offset 8, central header offset 10.
    return _patch_header_field(archive_bytes, 8, 10, 99)


def _encryption_bit_set(archive_bytes: bytes) -> bytes:
    # General purpose flag: local header offset 6, central header offset 8.
    # Bit 0 means "encrypted"; the archive is single-member and was written
    # with no other flag bits that matter here, so setting bit 0 alone is the
    # one-field change.
    with zipfile.ZipFile(__import__("io").BytesIO(archive_bytes)) as zf:
        flags = zf.getinfo("manifest.json").flag_bits
    return _patch_header_field(archive_bytes, 6, 8, flags | 0x1)


_HEADER_CORRUPTIONS = [
    pytest.param(_unknown_compression_method, NotImplementedError, id="compression-99"),
    pytest.param(_encryption_bit_set, RuntimeError, id="encryption-bit"),
]


@pytest.mark.parametrize(("corrupt", "raised"), _HEADER_CORRUPTIONS)
def test_header_corruption_is_reported_not_raised(tmp_path, corrupt, raised):
    corrupted = corrupt(mcpb_archive(MANIFEST))

    # Pin the mechanism: the archive opens, and only the member read raises
    # the exception class this case is about.
    with zipfile.ZipFile(__import__("io").BytesIO(corrupted)) as zf:
        assert zf.namelist() == ["manifest.json"]
        with pytest.raises(raised):
            zf.read("manifest.json")

    errors = validate_mcpb_archive(_plugins_root(tmp_path, corrupted))
    assert len(errors) == 1, (
        f"expected exactly one unreadable-archive error, got {errors}"
    )
    assert "unreadable" in str(errors[0]).lower(), errors[0]


@pytest.mark.parametrize(("corrupt", "raised"), _HEADER_CORRUPTIONS)
def test_smoke_test_reports_a_header_corruption(tmp_path, corrupt, raised):
    result = _smoke(tmp_path, corrupt(mcpb_archive(MANIFEST)))
    assert result is not None and result.get("ok") is False, result
    assert "not a valid ZIP" in result["reason"], result
