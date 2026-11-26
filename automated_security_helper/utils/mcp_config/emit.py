# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Render one command-declaring ``McpServerEntry`` as a POSIX shell script and its span sidecar.

The script is text for script scanners to read. Nothing here runs, resolves or fetches
anything the config names: every function returns a string.

The emitted script has three lines, and the sidecar has one row per line::

    #!/bin/sh
    # ash-mcp-span: {"source":"<repo-relative file>","pointer":"/mcpServers/<name>","line":N,"col":C}
    KEY='value' exec 'command' 'arg1' 'arg2'

Quoting keeps one config token as one script token. Every value is single-quoted; an
embedded single quote is written with the ``'"'"'`` idiom. A character that would end the
script line or that a single-quoted word cannot carry (newline, carriage return, other
control characters, the Unicode line separators) is written as an ANSI-C ``$'...'`` word
joined to its neighbors, so the entry's command stays on one line.
"""

import hashlib
import json
import re
from typing import Any, Dict, List, Optional

from automated_security_helper.utils.mcp_config.model import McpServerEntry, Span

SHEBANG = "#!/bin/sh"
SPAN_COMMENT_PREFIX = "# ash-mcp-span: "

_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
#: Characters written as ``$'...'`` words. Tab stays inside single quotes.
_NEEDS_ANSI_C = re.compile(
    "[\\x00-\\x08\\x0a-\\x1f\\x7f"
    + "".join(chr(code) for code in (0x85, 0x2028, 0x2029))
    + chr(0xD800)
    + "-"
    + chr(0xDFFF)
    + "]+"
)

_MAX_SLUG_CHARS = 80


def posix_quote(value: str) -> str:
    """``value`` as one POSIX shell word (single-quoted, ANSI-C words where needed)."""
    if value == "":
        return "''"
    pieces: List[str] = []
    position = 0
    for special in _NEEDS_ANSI_C.finditer(value):
        if special.start() > position:
            pieces.append(_single_quoted(value[position : special.start()]))
        pieces.append(_ansi_c(special.group()))
        position = special.end()
    if position < len(value):
        pieces.append(_single_quoted(value[position:]))
    return "".join(pieces)


def _single_quoted(text: str) -> str:
    return "'" + text.replace("'", "'\"'\"'") + "'"


def _ansi_c(text: str) -> str:
    body: List[str] = []
    for character in text:
        if character == "\n":
            body.append("\\n")
        elif character == "\r":
            body.append("\\r")
        else:
            encoded = character.encode("utf-8", "surrogatepass")
            body.extend(f"\\x{byte:02x}" for byte in encoded)
    return "$'" + "".join(body) + "'"


def slug(text: str, taken: Optional[set[str]] = None) -> str:
    """A file-name-safe, deterministic name for ``text``.

    Text that is already safe (``A-Za-z0-9._-``, not starting with a dot, short) is kept.
    Anything else is changed and gets a short digest of the original appended, so two
    different names do not share a file. A name already in ``taken`` is extended with
    the digest too. The result is added to ``taken``.
    """
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", text).lstrip(".")
    changed = safe != text or len(safe) > _MAX_SLUG_CHARS or not safe
    digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:8]
    if changed:
        safe = f"{safe[:_MAX_SLUG_CHARS] or '_'}-{digest}"
    elif taken is not None and safe in taken:
        safe = f"{safe}-{digest}"
    if taken is not None:
        taken.add(safe)
    return safe


def source_slug(source_file: str, taken: Optional[set[str]] = None) -> str:
    """The directory name for one config file: ``.cursor/mcp.json`` -> ``cursor__mcp.json``."""
    parts = (part.lstrip(".") for part in source_file.split("/"))
    readable = "__".join(part for part in parts if part)
    return slug(readable, taken)


def command_line(entry: McpServerEntry) -> Optional[str]:
    """The one-line command for ``entry``, or None when it has no command to run."""
    if not entry.command:
        return None
    assignments: List[str] = []
    odd_env: List[str] = []
    for key, value in entry.env.items():
        if _ENV_NAME.match(key):
            assignments.append(f"{key}={posix_quote(value)}")
        else:
            # Not a name a shell can assign: hand it to env(1) as one quoted word.
            odd_env.append(posix_quote(f"{key}={value}"))
    words: List[str] = assignments
    words.append("exec")
    if entry.command.startswith("-"):
        words.append("--")
    if odd_env:
        words.append("env")
        words.extend(odd_env)
        if entry.command.startswith("-"):
            words.append("--")
    words.append(posix_quote(entry.command))
    words.extend(posix_quote(argument) for argument in entry.args)
    return " ".join(words)


def entry_span(entry: McpServerEntry) -> Span:
    """The span a script line maps back to: the whole server entry."""
    found = entry.span() or entry.key_span()
    if found is None:
        return Span(line=1, col=1, end_line=1, end_col=1)
    return found


def span_comment(entry: McpServerEntry, span: Span) -> str:
    """The ``# ash-mcp-span:`` line. JSON is ASCII-only, so it cannot contain a line break."""
    record = {
        "source": entry.source_file,
        "pointer": entry.pointer,
        "line": span.line,
        "col": span.col,
    }
    return SPAN_COMMENT_PREFIX + json.dumps(
        record, separators=(",", ":"), ensure_ascii=True
    )


def emit_script(entry: McpServerEntry) -> Optional[tuple[str, List[Dict[str, Any]]]]:
    """The script text and its span rows for an entry with a command, or None.

    Every entry that declares a command gets a script, whatever ``kind`` it was
    classed as: an entry spelling both a command and a url is classed remote, and
    gating on the kind would let one decoy ``url`` key keep the command away from
    the script scanners. An entry with no command has nothing to run and gets
    None (a url-only remote entry is the policy scanner's subject).
    """
    line = command_line(entry)
    if line is None:
        return None
    span = entry_span(entry)
    lines = [SHEBANG, span_comment(entry, span), line]
    rows = [
        {
            "script_line": number,
            "source_file": entry.source_file,
            "pointer": entry.pointer,
            "line": span.line,
            "col": span.col,
            "end_line": span.end_line,
            "end_col": span.end_col,
        }
        for number in range(1, len(lines) + 1)
    ]
    return "\n".join(lines) + "\n", rows


def sidecar_text(rows: List[Dict[str, Any]]) -> str:
    """The ``.spanmap.json`` bytes for ``rows``.

    Two-space indent, sorted keys, ASCII, trailing newline: the form the repo's
    pretty-format-json hook writes, so a committed copy is never rewritten.
    """
    return json.dumps(rows, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
