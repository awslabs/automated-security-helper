# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`run_ash_scan()` with no source_dir must refuse rather than scan the wrong tree.

WHY THIS EXISTS
---------------
The dangerous version of this code path falls back to the process working
directory whenever the session has no delivered source. On a network transport
that directory is the server's, holds none of the caller's code, and scanning it
completes normally with zero findings -- indistinguishable from a clean
repository. A security scan that examined nothing and reads as clean is the
failure this project exists to eliminate, so the ambiguous cases are refused.

The specific trigger is a session id that is not stable between calls: the
upload lands under one session directory and the scan looks under another. That
is unproven-but-possible on Bedrock AgentCore, where the platform mints the ids.
See cli/mcp/session_identity.py.

These tests pin all three branches and, for the two refusals, that the message
names the cause -- an error a caller cannot act on is only marginally better than
a wrong green.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.profile_registry import DEFAULT_SESSION_ID
from automated_security_helper.cli.mcp_server import _resolve_omitted_source_dir


@pytest.fixture(autouse=True)
def _clean_session_registry():
    """Keep the process-local session->source_dir map out of other tests."""
    saved = dict(sd._SESSION_SOURCE_DIRS)
    sd._SESSION_SOURCE_DIRS.clear()
    yield
    sd._SESSION_SOURCE_DIRS.clear()
    sd._SESSION_SOURCE_DIRS.update(saved)


class TestDeliveredTreeIsUsed:
    """The whole point of the no-argument form."""

    def test_returns_the_delivered_tree(self, tmp_path):
        delivered = tmp_path / "session-a" / "source"
        delivered.mkdir(parents=True)
        sd._set_session_source_dir("session-a", delivered)

        resolution = _resolve_omitted_source_dir("session-a")

        assert resolution.error is None
        assert resolution.source_dir == str(delivered)

    def test_each_session_gets_its_own_tree(self, tmp_path):
        """Two sessions must not resolve to each other's workspace."""
        first = tmp_path / "s1" / "source"
        second = tmp_path / "s2" / "source"
        for path in (first, second):
            path.mkdir(parents=True)
        sd._set_session_source_dir("s1", first)
        sd._set_session_source_dir("s2", second)

        assert _resolve_omitted_source_dir("s1").source_dir == str(first)
        assert _resolve_omitted_source_dir("s2").source_dir == str(second)


class TestStdioFallbackSurvives:
    """A transport with no session header is one local client; cwd is meant."""

    def test_default_session_with_no_delivery_uses_cwd(self):
        resolution = _resolve_omitted_source_dir(DEFAULT_SESSION_ID)

        assert resolution.error is None
        assert resolution.source_dir == str(Path.cwd().absolute())

    def test_default_session_still_prefers_a_delivered_tree(self, tmp_path):
        """Delivering over stdio is legal, and the tree wins over cwd."""
        delivered = tmp_path / "default" / "source"
        delivered.mkdir(parents=True)
        sd._set_session_source_dir(DEFAULT_SESSION_ID, delivered)

        resolution = _resolve_omitted_source_dir(DEFAULT_SESSION_ID)

        assert resolution.error is None
        assert resolution.source_dir == str(delivered)

    def test_other_sessions_holding_source_does_not_refuse_the_default(self, tmp_path):
        """The no-header fallback must not depend on what other sessions did.

        Regression: the cross-session diagnostic was originally checked first, so
        a caller sending no session header was refused whenever any other session
        happened to hold a delivered tree. A caller with no session id cannot be
        the victim of an id that rotated, so that refusal was for an unrelated
        reason -- and it broke the documented stdio default on any server that had
        served one other client.
        """
        other = tmp_path / "some-http-session" / "source"
        other.mkdir(parents=True)
        sd._set_session_source_dir("some-http-session", other)

        resolution = _resolve_omitted_source_dir(DEFAULT_SESSION_ID)

        assert resolution.error is None
        assert resolution.source_dir == str(Path.cwd().absolute())


class TestRotatingSessionIdIsRefusedLoudly:
    """Somebody delivered source; the session asking is not who.

    This is the AgentCore rotating-id signature and the case the guard is for.
    """

    def test_refuses_when_another_session_holds_source(self, tmp_path):
        other = tmp_path / "upload-session" / "source"
        other.mkdir(parents=True)
        sd._set_session_source_dir("upload-session", other)

        resolution = _resolve_omitted_source_dir("scan-session")

        assert resolution.source_dir is None
        assert resolution.error is not None
        assert resolution.error["success"] is False
        assert resolution.error["error_type"] == "session_source_mismatch"

    def test_the_message_names_the_cause_and_the_fix(self, tmp_path):
        other = tmp_path / "upload-session" / "source"
        other.mkdir(parents=True)
        sd._set_session_source_dir("upload-session", other)

        message = _resolve_omitted_source_dir("scan-session").error["error"]

        # The cause, so a caller can recognize their situation.
        assert "not stable across" in message
        assert "different workspaces" in message
        # The fix.
        assert "source_dir" in message
        # And why it refused rather than scanning something.
        assert "Refusing to scan" in message

    def test_the_message_does_not_leak_other_session_ids(self, tmp_path):
        """A count is enough; naming the other tenant is not ours to disclose."""
        other = tmp_path / "secret-tenant-session" / "source"
        other.mkdir(parents=True)
        sd._set_session_source_dir("secret-tenant-session", other)

        error = _resolve_omitted_source_dir("scan-session").error

        assert "secret-tenant-session" not in error["error"]
        assert str(other) not in error["error"]
        # The count is what makes the diagnosis possible.
        assert "1 other session" in error["error"]

    def test_never_returns_another_sessions_tree(self, tmp_path):
        """The refusal must not degrade into a cross-session read."""
        other = tmp_path / "upload-session" / "source"
        other.mkdir(parents=True)
        sd._set_session_source_dir("upload-session", other)

        resolution = _resolve_omitted_source_dir("scan-session")

        assert resolution.source_dir is None


class TestNoDeliveryAnywhereIsRefusedOnASession:
    """A real session that delivered nothing gets told to deliver something."""

    def test_refuses_with_no_source_delivered(self):
        resolution = _resolve_omitted_source_dir("a-real-session")

        assert resolution.source_dir is None
        assert resolution.error is not None
        assert resolution.error["error_type"] == "no_source_delivered"

    def test_does_not_fall_back_to_cwd(self):
        """The regression this guard prevents."""
        resolution = _resolve_omitted_source_dir("a-real-session")

        assert resolution.source_dir != str(Path.cwd().absolute())
        assert resolution.source_dir is None

    def test_the_message_names_the_tools_to_call(self):
        message = _resolve_omitted_source_dir("a-real-session").error["error"]

        assert "set_source_git" in message
        assert "set_source_zip_finalize" in message
        assert "no findings and no error" in message

    def test_the_error_echoes_the_session_it_resolved(self):
        """So a caller can see which id the scan actually used."""
        error = _resolve_omitted_source_dir("a-real-session").error

        assert error["session_id"] == "a-real-session"


class TestAStaleRegistryRecordIsRefused:
    """Registered, but the directory is no longer there.

    The registry is a process-local dict and the tree it points at is ordinary
    filesystem state, so the two can disagree: a delivery interrupted between
    clearing the old tree and putting the new one in place, or anything outside
    the server removing the directory. Handing the path back anyway produced
    "directory does not exist" from a later check, which does not tell the caller
    that re-delivering is the fix -- and if the directory survived but was empty,
    the scan completed and reported clean, which is the outcome this module
    exists to prevent.
    """

    def test_a_recorded_directory_that_is_gone_is_refused(self, tmp_path):
        delivered = tmp_path / "session-a" / "source"
        delivered.mkdir(parents=True)
        sd._set_session_source_dir("session-a", delivered)
        shutil.rmtree(delivered)

        resolution = _resolve_omitted_source_dir("session-a")

        assert resolution.source_dir is None
        assert resolution.error is not None
        assert resolution.error["error_type"] == "delivered_source_missing"

    def test_the_message_names_the_path_and_the_fix(self, tmp_path):
        delivered = tmp_path / "session-a" / "source"
        delivered.mkdir(parents=True)
        sd._set_session_source_dir("session-a", delivered)
        shutil.rmtree(delivered)

        message = _resolve_omitted_source_dir("session-a").error["error"]

        assert str(delivered) in message
        assert "set_source_git" in message
        assert "Refusing to scan" in message

    def test_a_file_where_the_tree_should_be_is_refused_too(self, tmp_path):
        """``is_dir()`` rather than ``exists()``: a file is not a scannable tree."""
        session = tmp_path / "session-a"
        session.mkdir()
        delivered = session / "source"
        delivered.write_text("not a directory")
        sd._set_session_source_dir("session-a", delivered)

        resolution = _resolve_omitted_source_dir("session-a")

        assert resolution.error is not None
        assert resolution.error["error_type"] == "delivered_source_missing"

    def test_the_default_session_does_not_fall_back_to_cwd_either(self, tmp_path):
        """A stale record is a stale record; cwd is not a substitute for it.

        Distinct from ``test_default_session_with_no_delivery_uses_cwd``: nothing
        was ever delivered there, whereas here something was and then vanished.
        Scanning cwd at that point would report on a tree the caller never sent.
        """
        delivered = tmp_path / "default" / "source"
        delivered.mkdir(parents=True)
        sd._set_session_source_dir(DEFAULT_SESSION_ID, delivered)
        shutil.rmtree(delivered)

        resolution = _resolve_omitted_source_dir(DEFAULT_SESSION_ID)

        assert resolution.source_dir is None
        assert resolution.error["error_type"] == "delivered_source_missing"
