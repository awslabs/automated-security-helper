# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for resolving which session an MCP tool call belongs to.

The session id decides which directory beneath the workspace root a call reads
and writes, so the two behaviours that matter are that a usable header is honored
(otherwise a delivered tree cannot be found again by the scan that follows) and
that an unusable one is refused rather than coerced (because coercing two
distinct ids to one value merges two callers' source trees).
"""

from __future__ import annotations

from types import MappingProxyType, SimpleNamespace
from unittest.mock import MagicMock

import pytest
from starlette.datastructures import Headers

from automated_security_helper.cli.mcp.profile_registry import DEFAULT_SESSION_ID
from automated_security_helper.cli.mcp.session_identity import (
    MCP_SESSION_ID_HEADER,
    UNIDENTIFIED_SESSION_ID,
    is_reserved_session_id,
    resolve_caller_session_id,
    resolve_session_id,
)


class TestNoSessionSupplied:
    """What a caller that names no session resolves to.

    No headers at all is the shape of stdio and of an in-process caller: no
    request is behind the call, and it is the default session. Headers that name
    no session -- absent, empty, or whitespace-only -- are a request that named
    nothing, and it is the unidentified session, never the default, which carries
    local trust.
    """

    def test_none_headers_resolve_to_default(self):
        """stdio carries no headers at all and serves a single client."""
        assert resolve_session_id(None) == DEFAULT_SESSION_ID

    def test_empty_mapping_resolves_to_default(self):
        assert resolve_session_id({}) == DEFAULT_SESSION_ID

    def test_absent_header_resolves_to_unidentified(self):
        headers = {"content-type": "application/json"}
        assert resolve_session_id(headers) == UNIDENTIFIED_SESSION_ID

    def test_empty_header_value_resolves_to_unidentified(self):
        assert (
            resolve_session_id({MCP_SESSION_ID_HEADER: ""}) == UNIDENTIFIED_SESSION_ID
        )

    def test_whitespace_only_header_resolves_to_unidentified(self):
        assert (
            resolve_session_id({MCP_SESSION_ID_HEADER: "   "})
            == UNIDENTIFIED_SESSION_ID
        )


class TestHeadersThatAreNotAMapping:
    """Headers that are not a mapping never reach the default session.

    A stand-in context whose ``headers`` was never set reads as an object that
    holds nothing (a ``MagicMock`` attribute, say). That is not the absence of
    headers, which is the in-process caller, and the default session's local
    trust is not what a misconfigured stand-in should get: it names no session.
    """

    @pytest.mark.parametrize(
        "headers",
        [
            MagicMock(),
            MagicMock(spec=["items"]),
            object(),
            "mcp-session-id: abc123",
            0,
            [(MCP_SESSION_ID_HEADER, "abc123")],
        ],
        ids=["mock", "mock-with-items", "object", "str", "zero", "pairs"],
    )
    def test_are_the_unidentified_session(self, headers):
        resolved = resolve_session_id(headers)

        assert resolved != DEFAULT_SESSION_ID
        assert resolved == UNIDENTIFIED_SESSION_ID

    def test_control_other_mappings_are_headers(self):
        """The rule is about what is not a mapping, not about what is not a dict."""
        assert resolve_session_id(MappingProxyType({})) == DEFAULT_SESSION_ID
        assert (
            resolve_session_id(MappingProxyType({MCP_SESSION_ID_HEADER: "abc123"}))
            == "abc123"
        )
        assert resolve_session_id(Headers({})) == DEFAULT_SESSION_ID
        assert resolve_session_id(Headers({MCP_SESSION_ID_HEADER: "abc123"})) == (
            "abc123"
        )


class TestUsableHeader:
    """A usable header is returned so the workspace can be found again."""

    def test_returns_header_value(self):
        headers = {MCP_SESSION_ID_HEADER: "abc123"}
        assert resolve_session_id(headers) == "abc123"

    def test_uuid_shaped_value_is_accepted(self):
        """The shape AgentCore actually sends: hyphens are not separators."""
        sid = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
        assert resolve_session_id({MCP_SESSION_ID_HEADER: sid}) == sid

    @pytest.mark.parametrize(
        "header_name",
        ["Mcp-Session-Id", "MCP-SESSION-ID", "mcp-session-id", "mCp-SeSsIoN-iD"],
    )
    def test_header_name_is_matched_case_insensitively(self, header_name):
        """HTTP header names are case-insensitive; a plain dict may be any case."""
        assert resolve_session_id({header_name: "sess-1"}) == "sess-1"

    def test_surrounding_whitespace_is_stripped(self):
        assert resolve_session_id({MCP_SESSION_ID_HEADER: "  sess-1  "}) == "sess-1"

    def test_value_at_the_length_limit_is_accepted(self):
        sid = "a" * 128
        assert resolve_session_id({MCP_SESSION_ID_HEADER: sid}) == sid

    def test_distinct_headers_resolve_to_distinct_ids(self):
        """The property the per-session workspace isolation rests on."""
        first = resolve_session_id({MCP_SESSION_ID_HEADER: "tenant-a"})
        second = resolve_session_id({MCP_SESSION_ID_HEADER: "tenant-b"})
        assert first != second


class TestUnusableHeaderIsRefused:
    """An id that could name something other than one directory is an error.

    Each of these must raise rather than return the default: falling back would
    put the caller's source in the shared default workspace, and sanitizing would
    map two ids onto one directory.
    """

    @pytest.mark.parametrize(
        "bad",
        [
            "../other-session",
            "a/b",
            "/absolute",
            "trailing/",
            "back\\slash",
            "..\\windows",
        ],
    )
    def test_path_separators_and_traversal_are_refused(self, bad):
        with pytest.raises(ValueError):
            resolve_session_id({MCP_SESSION_ID_HEADER: bad})

    @pytest.mark.parametrize("bad", [".", ".."])
    def test_relative_path_components_are_refused(self, bad):
        with pytest.raises(ValueError, match="relative-path component"):
            resolve_session_id({MCP_SESSION_ID_HEADER: bad})

    def test_nul_byte_is_refused(self):
        """A NUL truncates the path at the C boundary, so the id would name
        a different directory than it appears to."""
        with pytest.raises(ValueError, match="control characters"):
            resolve_session_id({MCP_SESSION_ID_HEADER: "sess\x00evil"})

    @pytest.mark.parametrize("bad", ["sess\nid", "sess\rid", "sess\tid", "sess\x7f"])
    def test_other_control_characters_are_refused(self, bad):
        with pytest.raises(ValueError, match="control characters"):
            resolve_session_id({MCP_SESSION_ID_HEADER: bad})

    def test_overlong_value_is_refused(self):
        with pytest.raises(ValueError, match="maximum"):
            resolve_session_id({MCP_SESSION_ID_HEADER: "a" * 129})

    @pytest.mark.parametrize(
        "reserved",
        [
            "__default__",
            "__DEFAULT__",
            "__unidentified__",
            "__Unidentified__",
            ".stdio-servers",
            ".STDIO-SERVERS",
            ".ash-mcp-scans",
            ".ASH-MCP-SCANS",
        ],
    )
    def test_a_stand_in_context_naming_a_reserved_id_is_refused(self, reserved):
        """The non-SDK branch refuses the same ids the transport branch does."""

        class _StandIn:
            headers = {MCP_SESSION_ID_HEADER: reserved}

        with pytest.raises(ValueError, match="reserved"):
            resolve_caller_session_id(_StandIn())

    def test_a_stand_in_context_naming_an_ordinary_id_is_served(self):
        class _StandIn:
            headers = {MCP_SESSION_ID_HEADER: "tenant-a"}

        assert resolve_caller_session_id(_StandIn()) == "tenant-a"

    def test_refusal_names_the_header(self):
        """The error has to say which header was wrong to be actionable."""
        with pytest.raises(ValueError, match=MCP_SESSION_ID_HEADER):
            resolve_session_id({MCP_SESSION_ID_HEADER: "a/b"})


_RESERVED_SPELLINGS = [
    "__default__",
    "__unidentified__",
    # A case-insensitive filesystem (macOS, Windows) opens the same directory for
    # these spellings.
    "__DEFAULT__",
    "__Default__",
    "__UNIDENTIFIED__",
    # The stdio servers' and the running scans' presence registries.
    ".stdio-servers",
    ".STDIO-SERVERS",
    ".ash-mcp-scans",
    # Windows drops trailing periods and spaces when it opens a name.
    "__default__.",
    "__default__..",
    "__DEFAULT__.",
    ".stdio-servers.",
    # The generated 8.3 short names of the reserved names.
    "__DEFA~1",
    "__defa~2",
    "__DEFA~1.",
    "__UNID~1",
    "STDIO-~1",
    "ASH-MC~1",
]


class TestReservedHeaderIsRefused:
    """The stand-in/header path refuses what the HTTP arm refuses.

    ``resolve_caller_session_id`` refuses a reserved session id on its HTTP arm;
    ``resolve_session_id`` serves an in-process caller's stand-in and must not
    admit a name that opens the shared default workspace.
    """

    @pytest.mark.parametrize("reserved", _RESERVED_SPELLINGS)
    def test_a_reserved_header_is_refused(self, reserved):
        with pytest.raises(ValueError, match="is reserved and cannot name a session"):
            resolve_session_id({MCP_SESSION_ID_HEADER: reserved})

    def test_the_refusal_names_the_header(self):
        with pytest.raises(ValueError, match=MCP_SESSION_ID_HEADER):
            resolve_session_id({MCP_SESSION_ID_HEADER: "__default__"})

    def test_a_reserved_header_with_surrounding_whitespace_is_refused(self):
        with pytest.raises(ValueError, match="is reserved"):
            resolve_session_id({MCP_SESSION_ID_HEADER: "  __default__  "})

    def test_no_headers_at_all_still_resolves_to_the_default(self):
        """Positive control: the in-process caller, with no request behind it,
        keeps the default session; only a request that carries headers is held
        to the rule below."""
        assert resolve_session_id(None) == DEFAULT_SESSION_ID
        assert resolve_session_id({}) == DEFAULT_SESSION_ID

    @pytest.mark.parametrize(
        "headers",
        [
            {"content-type": "application/json"},
            {MCP_SESSION_ID_HEADER: ""},
            {MCP_SESSION_ID_HEADER: "   "},
            {"Mcp-Session-Id": "", "content-type": "application/json"},
        ],
    )
    def test_naming_no_session_is_not_another_way_to_the_default(self, headers):
        """A header that spells the default is refused; leaving the header out
        must not reach the same session, and its local trust, by another road."""
        resolved = resolve_session_id(headers)
        assert resolved != DEFAULT_SESSION_ID
        assert resolved == UNIDENTIFIED_SESSION_ID

    @pytest.mark.parametrize(
        "ordinary",
        [
            "tenant-a",
            "session_test",
            "a~b",
            "__defa",
            "__defa~",
            "__DEFAU~1",
            "x__default__",
        ],
    )
    def test_names_near_a_reserved_one_still_resolve_to_themselves(self, ordinary):
        assert resolve_session_id({MCP_SESSION_ID_HEADER: ordinary}) == ordinary


class TestAStandInIsResolvedTheSameWay:
    """``resolve_caller_session_id`` hands a stand-in context to this path."""

    def test_headers_that_name_no_session_are_unidentified(self):
        ctx = SimpleNamespace(headers={"content-type": "application/json"})
        assert resolve_caller_session_id(ctx) == UNIDENTIFIED_SESSION_ID

    def test_no_headers_is_the_in_process_caller(self):
        assert resolve_caller_session_id(SimpleNamespace(headers=None)) == (
            DEFAULT_SESSION_ID
        )

    def test_a_reserved_header_is_refused(self):
        ctx = SimpleNamespace(headers={MCP_SESSION_ID_HEADER: "__default__"})
        with pytest.raises(ValueError, match="is reserved"):
            resolve_caller_session_id(ctx)

    @pytest.mark.production_header_rule
    def test_headers_that_are_a_mock_name_no_session(self):
        """The suite maps a test double's unset ``headers`` to no headers
        (tests/conftest.py); this cell opts out, so it reaches the production
        rule, under which anything that is not a mapping names no session."""
        ctx = SimpleNamespace(headers=MagicMock())
        assert resolve_caller_session_id(ctx) == UNIDENTIFIED_SESSION_ID

    def test_headers_that_are_neither_a_mock_nor_a_mapping_name_no_session(self):
        """The suite's mapping of a double's unset ``headers`` covers mocks only,
        so a plain object reaches the production rule without opting out."""
        ctx = SimpleNamespace(headers=object())
        assert resolve_caller_session_id(ctx) == UNIDENTIFIED_SESSION_ID


class TestIsReservedSessionId:
    @pytest.mark.parametrize("reserved", _RESERVED_SPELLINGS)
    def test_every_spelling_is_reserved(self, reserved):
        assert is_reserved_session_id(reserved) is True

    @pytest.mark.parametrize(
        "ordinary", ["", "tenant-a", "a~b", "__defa", "__DEFAU~1", "__defa~x", "a.b"]
    )
    def test_ordinary_names_are_not_reserved(self, ordinary):
        assert is_reserved_session_id(ordinary) is False
