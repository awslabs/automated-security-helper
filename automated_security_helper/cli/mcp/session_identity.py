#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which session an MCP tool call belongs to.

A source tree delivered over the protocol lands in a per-session workspace, so
every tool that delivers one -- or scans the result -- has to know which session
it is acting for. The transport is what supplies that: the streamable-HTTP
transport carries an ``Mcp-Session-Id`` request header.

A multi-call delivery therefore needs that header to hold still. The chunk
uploads, the finalize that extracts them, and the scan that reads the extracted
tree all have to resolve to the same directory, so a client whose connection
carries a stable id gets a coherent workspace and one that does not gets a scan
that finds nothing.

CAUTION ON BEDROCK AGENTCORE RUNTIME. The MCP protocol contract for that target
says the platform generates the header, includes it in the request to the server,
and routes requests carrying it to the same microVM
(https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-mcp-protocol-contract.html).
Do not treat that as settled. Measured against two live runtimes, the platform
mints a fresh id on nearly every *response* and honors only the one returned by
``initialize``, so following the contract's own advice to adopt the latest
returned id produces ``404 Session not found`` on the third call. What the
container sees per *request* was not determinable from outside -- that needs
header logging inside the image -- so whether this function returns the same value
twice in one AgentCore session is an open question. On that target the caller
should pass the ``source_dir`` a delivery tool returned straight back to
``run_ash_scan`` rather than relying on the no-argument form, which is what
deploy/cdk/README.md tells adopters to do.

An unstable id does not silently misdirect a scan. ``run_ash_scan`` refuses the
no-argument form when this session holds no delivered tree, rather than falling
back to the working directory -- see ``_resolve_omitted_source_dir`` in
cli/mcp_server.py, which reports the rotating-id case specifically. Every tool
that calls this function also echoes the resolved id in its response, so two
calls compared against a live runtime settle the open question above without an
image change.

stdio carries no headers and serves a single client, so it resolves to
``DEFAULT_SESSION_ID``, the sentinel the profile registry already uses for
callers that name no session. That is also what a transport supplying no header
at all resolves to, which keeps delivery coherent (every call agrees on one
workspace) at the cost of isolation between concurrent callers.

The header is client-supplied input and is treated strictly as a namespace,
never as an identity assertion -- it selects which directory beneath the
workspace root a call may read and write, and decides nothing else. Isolation
between two callers is therefore only as strong as their ids differing, which on
AgentCore is the platform's job and on a self-hosted deployment is the fronting
proxy's. What this module does guarantee is that an id names one directory and
not a path: an id that could traverse, or that carries a separator or a control
character, is refused rather than sanitized. Sanitizing would map two distinct
ids onto one workspace and silently merge two callers' source trees.

That guarantee lives in ``session_paths.validated_path_component``, the one
implementation shared by the transport, the ``sessions`` registry and
``source_delivery``; :func:`validate_path_component` here only delegates to it.
``source_delivery`` once carried its own weaker copy of three of these
predicates, and ``session_paths`` and this module later carried two rules that
disagreed. One rule, several labels (the header, ``session_id``, ``upload_id``).
"""

from __future__ import annotations

from typing import Mapping, Optional

# Lowercase because HTTP header names are case-insensitive and this is compared
# against a lowercased key.
MCP_SESSION_ID_HEADER = "mcp-session-id"


def validate_path_component(value: str, label: str) -> str:
    """Refuse a caller-supplied value that could name anything but one directory.

    A delegate, not a rule. The rule lives in
    :func:`automated_security_helper.cli.mcp.session_paths.validated_path_component`
    and is the only one: this module and ``session_paths`` each used to carry a
    copy, the copies disagreed about ``~``, ``+``, ``=`` and length, and an id one
    accepted and the other refused was admitted at the transport and then failed
    inside the session registry. Kept under this name so the transport and its
    tests keep their import; ``label`` names the refused input in the message.

    Returns:
        ``value`` unchanged when it names exactly one path component.

    Raises:
        ValueError: under exactly the conditions ``validated_path_component``
            raises.
    """

    from automated_security_helper.cli.mcp.session_paths import (
        validated_path_component,
    )

    return validated_path_component(value, label)


def _header_value(headers: Mapping[str, str], name: str) -> Optional[str]:
    """Return the value of ``name`` from ``headers``, matched case-insensitively.

    Starlette's ``Headers`` already lowercases its keys, but a tool may be
    handed a plain dict by another transport or by a test, and HTTP header
    names are case-insensitive either way. Matching on a lowercased key works
    for both rather than depending on which mapping arrived.
    """

    for key, value in headers.items():
        if key.lower() == name:
            return value
    return None


def resolve_session_id(headers: Optional[Mapping[str, str]]) -> str:
    """Resolve the session id a tool call belongs to.

    Args:
        headers: Request headers carried by the transport, or ``None`` on a
            transport that has none (stdio). ``Context.headers`` supplies this.

    Returns:
        The ``Mcp-Session-Id`` header value when the transport carries a usable
        one, otherwise :data:`DEFAULT_SESSION_ID`.

    Raises:
        ValueError: if the header is present but could not name a single
            directory, per :func:`validate_path_component` -- it contains a path
            separator, is a relative-path component, carries a control character
            or a character with path meaning such as a drive-specifying ``:``,
            or exceeds ``session_paths.MAX_COMPONENT_LEN``. Refused rather than sanitized:
            see the module docstring.

    A header that is absent, empty, or whitespace-only is treated as "no session
    supplied" and resolves to the default, matching the ``session_id or
    DEFAULT_SESSION_ID`` form the profile registry already uses. A header that is
    present and non-empty but unusable is an error, because quietly falling back
    would put that caller's source in the shared default workspace.
    """

    # Imported here rather than at module scope: profile_registry imports the
    # config stack, and cli/mcp modules are imported from mcp_server at tool
    # registration time.
    from automated_security_helper.cli.mcp.profile_registry import (
        DEFAULT_SESSION_ID,
    )

    if not headers:
        return DEFAULT_SESSION_ID

    raw = _header_value(headers, MCP_SESSION_ID_HEADER)
    if raw is None:
        return DEFAULT_SESSION_ID

    candidate = raw.strip()
    if not candidate:
        return DEFAULT_SESSION_ID

    return validate_path_component(candidate, MCP_SESSION_ID_HEADER)


__all__ = [
    "MCP_SESSION_ID_HEADER",
    "resolve_session_id",
    "validate_path_component",
]
