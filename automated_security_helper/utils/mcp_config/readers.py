# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Detect repo-local MCP server config files and read them into ``McpServerEntry``.

Ten formats are read. Each is a row of :data:`FORMATS`: how the file is recognized, the
top-level key that holds the servers, which field spells the remote URL, which field
names the transport, and which fields mean "approve tool calls without asking".

Not targets, by design: ``.claude/settings.json`` (a policy file; an ``mcpServers``
block there is not documented) and Zed ``context_servers`` project files (unverified).
A file whose path matches no row is skipped, never guessed at.

This module only reads text. It never executes, resolves or fetches anything named in a
config file.
"""

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Tuple

from automated_security_helper.utils.mcp_config.json_spans import (
    JsonSpanError,
    JsonSpans,
    parse_json_with_spans,
)
from automated_security_helper.utils.mcp_config.model import (
    McpServerEntry,
    Span,
    pointer_join,
)
from automated_security_helper.utils.mcp_config.toml_spans import (
    TomlSpans,
    parse_toml_with_spans,
)

MAX_CONFIG_BYTES = 1024 * 1024


class McpConfigParseError(ValueError):
    """A recognized config file could not be read. Never quotes the file."""

    def __init__(self, source_file: str, reason: str, line: int = 0, col: int = 0):
        where = f" at line {line}, column {col}" if line else ""
        super().__init__(f"{source_file}: {reason}{where}")
        self.source_file = source_file
        self.reason = reason
        self.line = line
        self.col = col


@dataclass(frozen=True)
class McpConfigFormat:
    """How one vendor's config file is recognized and read."""

    format_id: str
    #: Repo-relative path, matched exactly, unless ``any_directory`` is set.
    path: str
    servers_key: str
    syntax: str = "json"  # "json" or "toml"
    #: Match on the file name in any directory instead of the exact path.
    any_directory: bool = False
    #: Fields that spell a remote URL, in the order they are tried, with the
    #: transport each one implies (None when the entry's own type field decides).
    url_fields: Tuple[Tuple[str, Optional[str]], ...] = (("url", None),)
    transport_fields: Tuple[str, ...] = ("type", "transport")
    auto_approve_fields: Tuple[str, ...] = ()


FORMATS: Tuple[McpConfigFormat, ...] = (
    McpConfigFormat("claude_code", ".mcp.json", "mcpServers"),
    McpConfigFormat("cursor", ".cursor/mcp.json", "mcpServers"),
    McpConfigFormat("vscode", ".vscode/mcp.json", "servers"),
    McpConfigFormat(
        "gemini",
        ".gemini/settings.json",
        "mcpServers",
        url_fields=(("httpUrl", "http"), ("url", "sse")),
        auto_approve_fields=("trust",),
    ),
    McpConfigFormat(
        "claude_desktop",
        "claude_desktop_config.json",
        "mcpServers",
        any_directory=True,
    ),
    McpConfigFormat("amazonq", ".amazonq/mcp.json", "mcpServers"),
    McpConfigFormat(
        "roo", ".roo/mcp.json", "mcpServers", auto_approve_fields=("alwaysAllow",)
    ),
    McpConfigFormat(
        "kiro",
        ".kiro/settings/mcp.json",
        "mcpServers",
        auto_approve_fields=("autoApprove",),
    ),
    McpConfigFormat(
        "devin",
        ".devin/mcp_config.json",
        "mcpServers",
        url_fields=(("serverUrl", None), ("url", None)),
    ),
    McpConfigFormat(
        "codex",
        ".codex/config.toml",
        "mcp_servers",
        syntax="toml",
        auto_approve_fields=("approval_mode",),
    ),
)

_BY_ID = {fmt.format_id: fmt for fmt in FORMATS}


def detect_format(rel_path: str) -> Optional[McpConfigFormat]:
    """The format of a repo-relative path, or None when it is not a target."""
    posix = PurePosixPath(rel_path.replace("\\", "/"))
    text = posix.as_posix()
    text = text.removeprefix("./")
    for fmt in FORMATS:
        if fmt.any_directory:
            if posix.name == fmt.path:
                return fmt
        elif text == fmt.path:
            return fmt
    return None


def _scalar_text(value: Any) -> Optional[str]:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return value
    return None


def _string_map(value: Any) -> Dict[str, str]:
    if not isinstance(value, dict):
        return {}
    out: Dict[str, str] = {}
    for key, item in value.items():
        text = _scalar_text(item)
        if text is not None:
            out[str(key)] = text
    return out


def _entry(
    fmt: McpConfigFormat,
    source_file: str,
    name: str,
    raw: Dict[str, Any],
    pointer: str,
    spans: Dict[str, Span],
    key_spans: Dict[str, Span],
) -> McpServerEntry:
    url: Optional[str] = None
    url_pointer: Optional[str] = None
    implied_transport: Optional[str] = None
    for field, implied in fmt.url_fields:
        candidate = raw.get(field)
        if isinstance(candidate, str) and candidate:
            url = candidate
            url_pointer = pointer_join(pointer, field)
            implied_transport = implied
            break

    transport = implied_transport
    if transport is None:
        for field in fmt.transport_fields:
            candidate = raw.get(field)
            if isinstance(candidate, str) and candidate:
                transport = candidate
                break

    command = raw.get("command")
    args = raw.get("args")
    approve = {field: raw[field] for field in fmt.auto_approve_fields if field in raw}
    prefix = pointer + "/"
    return McpServerEntry(
        source_file=source_file,
        format_id=fmt.format_id,
        server_name=name,
        pointer=pointer,
        kind="remote" if url is not None else "stdio",
        command=command if isinstance(command, str) else None,
        args=[t for t in (_scalar_text(a) for a in args) if t is not None]
        if isinstance(args, list)
        else [],
        env=_string_map(raw.get("env")),
        url=url,
        url_pointer=url_pointer,
        transport=transport,
        headers=_string_map(raw.get("headers", raw.get("http_headers"))),
        auto_approve=approve,
        spans={k: v for k, v in spans.items() if k == pointer or k.startswith(prefix)},
        key_spans={
            k: v for k, v in key_spans.items() if k == pointer or k.startswith(prefix)
        },
    )


def parse_mcp_config_text(
    text: str, rel_path: str, fmt: Optional[McpConfigFormat] = None
) -> List[McpServerEntry]:
    """Read the servers out of one config file's text.

    ``rel_path`` is recorded as ``source_file`` and, unless ``fmt`` is given, picks the
    format. Returns ``[]`` for a path that is not a target. Raises
    :class:`McpConfigParseError` for a target that is not valid; the error names a
    line and column and never quotes the text.
    """
    fmt = fmt or detect_format(rel_path)
    if fmt is None:
        return []
    source_file = rel_path.replace("\\", "/")
    parsed: JsonSpans | TomlSpans
    try:
        if fmt.syntax == "toml":
            parsed = parse_toml_with_spans(text)
        else:
            parsed = parse_json_with_spans(text)
    except JsonSpanError as exc:
        raise McpConfigParseError(source_file, exc.reason, exc.line, exc.col) from None

    document = parsed.value
    if not isinstance(document, dict):
        return []
    servers = document.get(fmt.servers_key)
    if not isinstance(servers, dict):
        return []

    base = pointer_join("", fmt.servers_key)
    entries: List[McpServerEntry] = []
    for name, raw in servers.items():
        if not isinstance(raw, dict):
            continue
        entries.append(
            _entry(
                fmt,
                source_file,
                str(name),
                raw,
                pointer_join(base, str(name)),
                parsed.spans,
                parsed.key_spans,
            )
        )
    return entries


def parse_mcp_config_file(
    path: Path, rel_path: str, fmt: Optional[McpConfigFormat] = None
) -> List[McpServerEntry]:
    """Read one config file from disk; see :func:`parse_mcp_config_text`.

    Refuses a file over :data:`MAX_CONFIG_BYTES` or one that is not UTF-8.
    """
    source_file = rel_path.replace("\\", "/")
    fmt = fmt or detect_format(rel_path)
    if fmt is None:
        return []
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_CONFIG_BYTES + 1)
    except OSError:
        raise McpConfigParseError(source_file, "file could not be read") from None
    if len(data) > MAX_CONFIG_BYTES:
        raise McpConfigParseError(source_file, "file is too large")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise McpConfigParseError(source_file, "file is not UTF-8") from None
    return parse_mcp_config_text(text, rel_path, fmt)


def format_by_id(format_id: str) -> McpConfigFormat:
    """The format row for an id; ``KeyError`` for an unknown one."""
    return _BY_ID[format_id]
