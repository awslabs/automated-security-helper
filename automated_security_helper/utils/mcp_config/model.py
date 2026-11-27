# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The normalized model for one MCP server entry read from a repo-local config file.

Every supported config format (``.mcp.json``, ``.cursor/mcp.json``, ``.codex/config.toml``
and the rest) is read into the same :class:`McpServerEntry`, so the converter and the
policy scanner never look at a vendor spelling. Each entry also carries a span table that
maps a JSON pointer inside the source file to the place in the file it came from.

Span conventions
----------------
* ``line`` and ``col`` are 1-based. ``col`` counts characters, not bytes.
* The end position is exclusive: ``end_col`` is the column just past the last character.
* For JSON the span of a pointer is the span of its VALUE token (a string includes its
  quotes; an object or array runs from its opening to its closing bracket). The span of
  the member's KEY is in ``key_spans``.
* For TOML the standard library gives no positions, so spans come from a line scan and
  cover the key's first line only (see ``toml_spans``). Pointers that have no span of
  their own (an array element, a key inside an inline table) resolve to the nearest
  parent that has one through :meth:`McpServerEntry.span`.
"""

import posixpath
from typing import Any, Dict, List, Literal, Optional, Tuple
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field


def pointer_escape(token: str) -> str:
    """Escape one reference token for a JSON pointer (RFC 6901)."""
    return token.replace("~", "~0").replace("/", "~1")


def pointer_join(base: str, token: str) -> str:
    """Append one reference token to a JSON pointer."""
    return f"{base}/{pointer_escape(token)}"


class Span(BaseModel):
    """A region of a source file: 1-based line and column, end exclusive."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    line: int
    col: int
    end_line: int
    end_col: int


class McpServerEntry(BaseModel):
    """One server entry, in the one shape every format is read into."""

    model_config = ConfigDict(extra="forbid")

    source_file: str = Field(description="Repo-relative path of the config file.")
    format_id: str = Field(description="Which reader produced this entry.")
    server_name: str
    pointer: str = Field(
        description="JSON pointer of the server entry inside the source file."
    )
    kind: Literal["stdio", "remote"] = Field(
        description=(
            "Classification by url presence alone: remote when a url field is set, "
            "stdio otherwise. The policy checks and the script conversion gate on "
            "the declared command and url fields themselves, never on this, so an "
            "entry that spells both a command and a url gets both treatments and a "
            "decoy url cannot hide a command."
        )
    )
    command: Optional[str] = None
    args: List[str] = Field(default_factory=list)
    env: Dict[str, str] = Field(default_factory=dict)
    url: Optional[str] = None
    url_pointer: Optional[str] = Field(
        default=None,
        description="Pointer of the field the url came from (url, httpUrl, serverUrl).",
    )
    transport: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    auto_approve: Dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Auto-approval settings present on the entry, keyed by the vendor's own "
            "field name (trust, autoApprove, alwaysAllow, approval_mode), raw values."
        ),
    )
    spans: Dict[str, Span] = Field(default_factory=dict)
    key_spans: Dict[str, Span] = Field(default_factory=dict)

    def span(self, relative: str = "") -> Optional[Span]:
        """The span of ``pointer + relative``, or of its nearest parent with one."""
        full = self.pointer + relative
        while True:
            found = self.spans.get(full)
            if found is not None:
                return found
            if len(full) <= len(self.pointer):
                return None
            full = full[: full.rfind("/")]

    def key_span(self, relative: str = "") -> Optional[Span]:
        """The span of the KEY of ``pointer + relative`` (the entry's own name for ``""``)."""
        found = self.key_spans.get(self.pointer + relative)
        if found is not None:
            return found
        return self.span(relative)


# The MCP config scanner's URL and command-path prefix checks and the operator's floors
# for those two lists (config/restrictions_kept.py) use these four functions, so the
# two cannot drift apart.


def split_url(url: str) -> Optional[Tuple[str, Optional[str], str]]:
    """(scheme, hostname, normalized url) of an absolute URL, or None."""
    try:
        parts = urlsplit(url.strip())
        host = parts.hostname
        # Read so that a malformed port raises ValueError here.
        _ = parts.port
    except ValueError:
        return None
    if not parts.scheme or not parts.netloc:
        return None
    netloc = parts.netloc.lower()
    rest = url.strip()[len(parts.scheme) + 3 + len(parts.netloc) :]
    return parts.scheme.lower(), host, f"{parts.scheme.lower()}://{netloc}{rest}"


def url_prefix_matches(url: str, prefix: str) -> bool:
    """Whether ``url`` starts with ``prefix``, on a URL boundary."""
    if not url.startswith(prefix):
        return False
    if prefix.endswith(("/", "?", "#")) or len(url) == len(prefix):
        return True
    return url[len(prefix)] in "/?#"


def normalized_command_path(command: str) -> str:
    """A command with its backslashes read as slashes, and a path made canonical."""
    text = command.replace("\\", "/")
    return posixpath.normpath(text) if "/" in text else text


def command_prefix_matches(path: str, prefix: str) -> bool:
    """Whether the normalized command ``path`` is, or is under, the path ``prefix``."""
    normalized_prefix = posixpath.normpath(prefix.replace("\\", "/"))
    if normalized_prefix == ".":
        return False
    if path == normalized_prefix:
        return True
    root = (
        normalized_prefix
        if normalized_prefix.endswith("/")
        else normalized_prefix + "/"
    )
    return path.startswith(root)
