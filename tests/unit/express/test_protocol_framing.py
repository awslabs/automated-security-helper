# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The wire protocol: one JSON object per line, bounded, and strict about it.

No real socket: the reader's input is whatever ``recv`` returns, so a stand-in
that serves a byte script exercises framing, buffering across short reads,
several frames in one read, the size cap, and both EOF shapes (clean on a
boundary, torn mid-frame).
"""

import json

import pytest

from automated_security_helper.express import runtime

pytestmark = pytest.mark.unit


class _ScriptedSock:
    """recv() serves the script's chunks in order, then b"" forever."""

    def __init__(self, chunks):
        self._chunks = list(chunks)
        self.sent = b""

    def recv(self, size):
        return self._chunks.pop(0) if self._chunks else b""

    def sendall(self, data):
        self.sent += data


class TestSendFrame:
    def test_a_frame_is_compact_json_and_one_newline(self):
        sock = _ScriptedSock([])
        runtime.send_frame(sock, {"op": "scan", "argv": ["a", "b"]})
        assert sock.sent.endswith(b"\n")
        assert sock.sent.count(b"\n") == 1
        assert json.loads(sock.sent) == {"op": "scan", "argv": ["a", "b"]}

    def test_a_frame_past_the_cap_is_refused_before_sending(self):
        sock = _ScriptedSock([])
        with pytest.raises(runtime.ExpressProtocolError, match="cap"):
            runtime.send_frame(sock, {"pad": "x" * runtime.MAX_FRAME_BYTES})
        assert sock.sent == b""


class TestFrameReader:
    def test_one_frame_roundtrips(self):
        reader = runtime.FrameReader(_ScriptedSock([b'{"ok":true}\n']))
        assert reader.read_frame() == {"ok": True}

    def test_two_frames_in_one_chunk_are_two_reads(self):
        reader = runtime.FrameReader(_ScriptedSock([b'{"a":1}\n{"b":2}\n']))
        assert reader.read_frame() == {"a": 1}
        assert reader.read_frame() == {"b": 2}

    def test_a_frame_split_across_reads_is_assembled(self):
        reader = runtime.FrameReader(_ScriptedSock([b'{"op":', b'"scan"', b"}\n"]))
        assert reader.read_frame() == {"op": "scan"}

    def test_clean_eof_on_a_boundary_is_none(self):
        reader = runtime.FrameReader(_ScriptedSock([b'{"a":1}\n']))
        assert reader.read_frame() == {"a": 1}
        assert reader.read_frame() is None

    def test_eof_mid_frame_is_a_protocol_error_not_a_frame(self):
        reader = runtime.FrameReader(_ScriptedSock([b'{"a":']))
        with pytest.raises(runtime.ExpressProtocolError, match="mid-frame"):
            reader.read_frame()

    def test_a_line_that_is_not_json_is_a_protocol_error(self):
        reader = runtime.FrameReader(_ScriptedSock([b"hello\n"]))
        with pytest.raises(runtime.ExpressProtocolError, match="not JSON"):
            reader.read_frame()

    def test_a_json_line_that_is_not_an_object_is_a_protocol_error(self):
        reader = runtime.FrameReader(_ScriptedSock([b"[1,2]\n"]))
        with pytest.raises(runtime.ExpressProtocolError, match="not a JSON object"):
            reader.read_frame()

    def test_a_frame_nested_too_deeply_is_a_protocol_error_not_a_crash(self):
        """A line of 50,000 nested arrays is under the byte cap but far past
        any sane frame. What json.loads does with it differs by interpreter:
        CPython 3.12's C scanner raises RecursionError at this depth, while
        3.13+/3.14 bound recursion by the real C-stack headroom and can parse
        it whole, after which the reader refuses it as not a JSON object. The
        contract is the same either way -- the reader answers the protocol
        error every caller already handles, never an unhandled RecursionError
        unwinding through the daemon's loop -- so both refusal texts pass."""
        depth = 50_000
        line = b"[" * depth + b"]" * depth + b"\n"
        assert len(line) < runtime.MAX_FRAME_BYTES
        reader = runtime.FrameReader(_ScriptedSock([line]))
        with pytest.raises(
            runtime.ExpressProtocolError,
            match="nested too deeply|not a JSON object",
        ):
            reader.read_frame()

    def test_an_unbounded_line_is_cut_off_at_the_cap(self):
        chunk = b"x" * 65536
        reader = runtime.FrameReader(
            _ScriptedSock([chunk] * (runtime.MAX_FRAME_BYTES // len(chunk) + 2))
        )
        with pytest.raises(runtime.ExpressProtocolError, match="size cap"):
            reader.read_frame()
