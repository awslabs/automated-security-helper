# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The two prompts name no server directory when the caller names none.

A prompt has no request context, so it cannot tell the local client from a
network one. Both prompts defaulted source_dir to the server's working
directory, which on a network session is the server's own tree: the prompt
steered a remote agent to pass that directory to run_ash_scan explicitly,
the one target the tool refuses to fall back to by itself. The prompts now
name the session's source directory and have the agent omit source_dir, which
run_ash_scan resolves the same way for both clients.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.cli import mcp_server

pytestmark = pytest.mark.unit


def test_the_scan_prompt_names_the_sessions_directory_when_none_is_given() -> None:
    text = mcp_server.run_ash_security_scan()

    # Red before the fix: the prompt named the server's working directory.
    assert str(Path.cwd()) not in text, text
    assert "this session's source directory" in text
    assert "set_source_git" in text
    assert "with no source_dir" in text
    assert "`run_ash_scan`" in text and "`get_scan_progress`" in text


def test_the_scan_prompt_names_an_explicit_directory() -> None:
    text = mcp_server.run_ash_security_scan("/work/project")

    assert "the following directory: /work/project" in text
    assert "this session's source directory" not in text


def test_the_analysis_prompt_names_the_sessions_directory_when_none_is_given() -> None:
    text = mcp_server.analyze_security_findings()

    # Red before the fix: the prompt named the server's working directory.
    assert str(Path.cwd()) not in text, text
    assert "this session's source directory" in text
    assert "Scan Result Locations" in text


def test_the_analysis_prompt_names_an_explicit_directory() -> None:
    text = mcp_server.analyze_security_findings("/work/project")

    assert "the source_dir:\n/work/project" in text
    assert "this session's source directory" not in text
