# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""fs_guard's bounded read and its writes outside a writable root, on every platform.

The suite beside the sandbox integration tests (tests/integration/sandbox/
test_fs_guard.py) exercises POSIX behavior and runs only in the integration
job, on Linux. These do not need POSIX, and one of them is about Windows, so
they stay unit tests: every unit-test leg runs them, Windows included.
"""

import os

import pytest

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("opener", ["open_for_write", "open_for_write_bytes"])
def test_a_write_outside_a_writable_root_opens_in_binary_mode(
    tmp_path, monkeypatch, opener
):
    """Outside a writable root, a writer given its own ``mode`` falls back to
    os.open, which unlike open() adds no O_BINARY: on Windows the CRT would then
    translate newlines under the text wrapper (text gets \\r\\r\\n) and in the
    bytes copies (LF to CRLF). With the default mode the writer is exactly
    open(), which opens in binary mode itself; the round-trip test below measures
    that path. O_BINARY is 0 on Linux, so a spare bit stands in for it here and
    is taken off again before the real call."""
    from automated_security_helper.utils.sandbox import fs_guard

    stand_in = 1 << 30
    monkeypatch.setattr(fs_guard, "_BINARY", stand_in)
    target = tmp_path / "written.out"
    seen = []
    real_open = os.open

    def recording_open(path, flags, *args, **kwargs):
        seen.append((os.fspath(path), flags))
        return real_open(path, flags & ~stand_in, *args, **kwargs)

    monkeypatch.setattr(os, "open", recording_open)
    with getattr(fs_guard, opener)(target, mode=0o600):
        pass

    fallback = [flags for path, flags in seen if path == os.fspath(target)]
    assert fallback, f"{opener} did not reach the os.open fallback: {seen}"
    assert all(flags & stand_in for flags in fallback), [hex(f) for f in fallback]


def test_a_write_outside_a_writable_root_round_trips_its_bytes(tmp_path):
    """The same property measured, on every platform: bytes come back as
    written, and text with only the text layer's own newline translation."""
    from automated_security_helper.utils.sandbox import fs_guard

    raw = tmp_path / "raw.out"
    with fs_guard.open_for_write_bytes(raw) as handle:
        handle.write(b"a\nb\r\nc")
    text = tmp_path / "text.out"
    with fs_guard.open_for_write(text) as handle:
        handle.write("a\nb")

    assert raw.read_bytes() == b"a\nb\r\nc"
    assert text.read_bytes() == "a\nb".replace("\n", os.linesep).encode()


def test_a_bounded_read_allocates_for_what_the_file_holds(tmp_path):
    """read_bytes_at_most's limit bounds the read, not its allocation: a
    BufferedReader.read(n) allocates n bytes before it reads, so a 2 KiB file
    read under a 1 GiB limit cost a 1 GiB allocation, a MemoryError (with an
    empty message) under an address-space limit. Measured with tracemalloc:
    the read's peak stays near the file's size."""
    import tracemalloc

    from automated_security_helper.utils.sandbox import fs_guard

    small = tmp_path / "small.json"
    small.write_bytes(b"x" * 2048)

    tracemalloc.start()
    try:
        data = fs_guard.read_bytes_at_most(small, (1 << 30) + 1)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    # The control: the whole file was read.
    assert data == b"x" * 2048
    assert peak < 8 << 20, f"peak {peak} bytes"


def test_a_bounded_read_still_stops_at_its_limit(tmp_path):
    """The bound itself: a file past the limit yields exactly the limit, the
    one byte past the cap the caller reads to tell "too large" apart."""
    from automated_security_helper.utils.sandbox import fs_guard

    big = tmp_path / "big.json"
    big.write_bytes(b"y" * (3 << 20))

    assert fs_guard.read_bytes_at_most(big, (2 << 20) + 1) == b"y" * ((2 << 20) + 1)
    assert fs_guard.read_bytes_at_most(big, 10) == b"y" * 10
