# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The refusal strings the agent docs name must exist in the server source.

Why this file exists
--------------------
``scripts/generate_mcp_tool_reference.py`` holds editorial text (``TOOL_NOTES``)
that names server behavior by its literal strings: the ``MCPResourceError``
class name, the ``resource_exhausted`` and ``unexpected_error`` error
categories, and the two busy-directory messages ``already has an active scan``
and ``has a scan that is still stopping``. The generator's ``--check`` mode only
catches drift in tools and parameters, so renaming the exception or rewording a
message in the server leaves roughly sixteen generated copies stale while CI
stays green, and these are exactly the strings agents are told to branch on.

What this asserts
-----------------
Every refusal string the docs name exists at its raise site with the category
the docs give it: the two busy-directory messages and the ``max_concurrent_scans``
limit message are raised as ``resource_exhausted``; the busy-directory refusal
names the running scan's ``scan_id`` only to the session that owns it; an
unexpected error while a scan is being started is wrapped as an
``MCPResourceError`` with the ``unexpected_error`` category; and ``error_type``
is the exception's class name. It also asserts that the generator notes and the
generated references still name each string, so a rewrite of the docs that drops
one fails here instead of leaving the server's behavior undocumented.

Everything here is a text assert over source files. No server code is imported
and nothing runs, so this test can never start a scan.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

PACKAGE = REPO_ROOT / "automated_security_helper"
RESOURCE_MANAGEMENT = PACKAGE / "core" / "resource_management"

GENERATOR = REPO_ROOT / "scripts" / "generate_mcp_tool_reference.py"
SCAN_REGISTRY = RESOURCE_MANAGEMENT / "scan_registry.py"
ERROR_HANDLING = RESOURCE_MANAGEMENT / "error_handling.py"
EXCEPTIONS = RESOURCE_MANAGEMENT / "exceptions.py"
MCP_TOOLS = PACKAGE / "cli" / "mcp_tools.py"

REFERENCES = (
    REPO_ROOT
    / "ash-agent-plugins"
    / "agentic-coding"
    / "transpiler"
    / "_base"
    / "references"
)

#: The generated documents that carry the TOOL_NOTES text verbatim. The
#: transpiled plugin copies are byte-compared against these by the
#: ``agentic-plugins check`` gate, so one copy here covers them all.
TOOL_REFERENCE = REFERENCES / "tool-reference.md"
TROUBLESHOOTING = REFERENCES / "troubleshooting.md"

#: What the run_ash_scan and cancel_scan notes name, and so what must stay
#: raised. Each one is a literal the docs print.
DOCUMENTED = (
    "MCPResourceError",
    "resource_exhausted",
    "unexpected_error",
    "already has an active scan",
    "has a scan that is still stopping",
    "max_concurrent_scans",
)


def _text(path: Path) -> str:
    assert path.is_file(), f"guarded file missing: {path}"
    return path.read_text(encoding="utf-8")


def _raise_window(source: str, pattern: str, width: int = 600) -> str:
    """The text from a raise site's message on, long enough to hold its context."""
    site = re.search(pattern, source)
    assert site, f"the documented message is not raised: {pattern}"
    return source[site.start() : site.start() + width]


def test_the_active_scan_refusal_is_resource_exhausted():
    window = _raise_window(
        _text(SCAN_REGISTRY),
        r"raise MCPResourceError\(\s*f\"Directory \{directory_path\} "
        r"already has an active scan\"",
    )
    assert "RESOURCE_EXHAUSTED" in window, (
        "the already-active refusal no longer carries the resource_exhausted "
        "category the docs branch on"
    )


def test_the_still_stopping_refusal_is_resource_exhausted():
    window = _raise_window(
        _text(SCAN_REGISTRY),
        r"raise MCPResourceError\(\s*f\"Directory \{directory_path\} "
        r"has a scan that is still \"\s*f\"stopping",
    )
    assert "RESOURCE_EXHAUSTED" in window, (
        "the still-stopping refusal no longer carries the resource_exhausted "
        "category the docs branch on"
    )


def test_the_concurrency_limit_is_resource_exhausted_with_its_own_context_key():
    window = _raise_window(
        _text(SCAN_REGISTRY),
        r"raise MCPResourceError\(\s*f\"The MCP server is at its "
        r"max_concurrent_scans limit of \"",
    )
    assert "RESOURCE_EXHAUSTED" in window
    assert '"max_concurrent_scans": max_active' in window, (
        "the limit refusal no longer puts max_concurrent_scans in its context, "
        "so the docs cannot tell it from a busy-directory refusal"
    )


def test_the_busy_directory_refusal_names_the_scan_only_to_its_owner():
    assert re.search(
        r"if owned:\s+named\[\"scan_id\"\] = entry\.scan_id", _text(SCAN_REGISTRY)
    ), (
        "the busy-directory refusal no longer names the running scan's scan_id "
        "only when the scan is the caller's session's"
    )


def test_an_unexpected_start_error_is_wrapped_as_unexpected_error():
    assert re.search(
        r"Unexpected error starting scan:[^\n]*\n\s*context=\{[^{}]*"
        r"\"error_category\": ErrorCategory\.UNEXPECTED_ERROR\.value",
        _text(MCP_TOOLS),
    ), (
        "an unexpected error while a scan is being started no longer arrives "
        "as an MCPResourceError with the unexpected_error category"
    )


def test_the_documented_category_values_are_the_servers():
    source = _text(ERROR_HANDLING)
    for member, value in (
        ("RESOURCE_EXHAUSTED", "resource_exhausted"),
        ("UNEXPECTED_ERROR", "unexpected_error"),
    ):
        assert f'{member} = "{value}"' in source, (
            f"the {value} category value moved or was renamed"
        )


def test_error_type_is_the_exception_class_name():
    """The docs call MCPResourceError a class name; the wire shape agrees."""
    assert "class MCPResourceError" in _text(EXCEPTIONS), (
        "the MCPResourceError class the docs name does not exist"
    )
    assert '"error_type": type(error).__name__' in _text(ERROR_HANDLING), (
        "create_error_response no longer sets error_type to the exception's "
        "class name, so the documented ambiguity note is stale"
    )


def test_the_generator_notes_name_each_documented_string():
    source = _text(GENERATOR)
    for needle in DOCUMENTED:
        assert needle in source, f"TOOL_NOTES no longer documents: {needle}"


def test_the_generated_references_name_each_documented_string():
    reference = _text(TOOL_REFERENCE)
    for needle in DOCUMENTED:
        assert needle in reference, f"{TOOL_REFERENCE.name} lost: {needle}"
    troubleshooting = _text(TROUBLESHOOTING)
    for needle in ("MCPResourceError", "resource_exhausted"):
        assert needle in troubleshooting, f"{TROUBLESHOOTING.name} lost: {needle}"
