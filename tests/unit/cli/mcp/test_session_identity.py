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

import pytest

from automated_security_helper.cli.mcp.profile_registry import DEFAULT_SESSION_ID
from automated_security_helper.cli.mcp.session_identity import (
    MCP_SESSION_ID_HEADER,
    resolve_session_id,
)


class TestNoSessionSupplied:
    """Absent, empty, and whitespace-only headers fall back to the default."""

    def test_none_headers_resolve_to_default(self):
        """stdio carries no headers at all and serves a single client."""
        assert resolve_session_id(None) == DEFAULT_SESSION_ID

    def test_empty_mapping_resolves_to_default(self):
        assert resolve_session_id({}) == DEFAULT_SESSION_ID

    def test_absent_header_resolves_to_default(self):
        headers = {"content-type": "application/json"}
        assert resolve_session_id(headers) == DEFAULT_SESSION_ID

    def test_empty_header_value_resolves_to_default(self):
        assert resolve_session_id({MCP_SESSION_ID_HEADER: ""}) == DEFAULT_SESSION_ID

    def test_whitespace_only_header_resolves_to_default(self):
        assert resolve_session_id({MCP_SESSION_ID_HEADER: "   "}) == DEFAULT_SESSION_ID


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

    def test_refusal_names_the_header(self):
        """The error has to say which header was wrong to be actionable."""
        with pytest.raises(ValueError, match=MCP_SESSION_ID_HEADER):
            resolve_session_id({MCP_SESSION_ID_HEADER: "a/b"})
