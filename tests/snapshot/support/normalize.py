# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The one place snapshot output is made deterministic.

Every snapshot under tests/snapshot goes through :class:`SnapshotNormalizer`, because
the ``snapshot`` and ``text_snapshot`` fixtures in tests/snapshot/conftest.py apply it
before syrupy compares anything. A test never normalizes by hand. If a test needs a
new kind of value masked, the rule goes here, so every surface gets it at once and a
reviewer reads one list of what a snapshot cannot see.

What is masked, and why each is safe to mask
--------------------------------------------
- ANSI escape sequences and carriage returns. Colour is decided by the terminal, not
  by ASH's output, and CRLF is how Windows writes a newline.
- Absolute paths the run chose: the test's tmp dirs, the system temp dir, the repo
  checkout, the home directory and the current directory. Each is replaced by a token
  (``<TMP>``, ``<REPO>`` ...) in every spelling ASH can emit: native, POSIX,
  JSON-escaped and ``file://`` URI. After the token, backslashes become ``/``, so a
  Windows path and a POSIX path snapshot identically.
- Timestamps. ISO-8601 instants, ``ASH-YYYYMMDD[HHMMSS]`` report ids, and today's date
  (plus yesterday and tomorrow, so a run that crosses midnight still matches). A date
  a fixture chose, such as a suppression's expiry, is not today and survives.
- Durations: a number followed by a time unit. Fixtures pin every duration they pass
  in, so what this masks is wall-clock time ASH measured itself.
- A bare number under a volatile key (``VOLATILE_KEYS``) in rendered JSON text, such as
  OCSF's ``"time": 1791220796403`` epoch milliseconds. Structured data already masks these
  by key; this is the same rule for JSON a command printed rather than returned.
- UUIDs, the ASH version, the Python version and the hostname.
- The pydantic minor version in its ``errors.pydantic.dev/<version>/`` help links, which
  a dependency bump changes in every config-error message.
- The frames of a traceback, rich's panel or CPython's plain one, as ``<TRACEBACK>``.
  Frames quote paths, line numbers and source lines from every file the exception
  passed through, so they move with unrelated edits. The fact that a traceback was
  shown, and the ``ExcType: message`` line after it, are kept: a message that turns
  into a traceback, or back, still shows up as a diff.
- Trailing whitespace on each line, which rich pads tables with.
- The padding in front of a rich panel's right border, on a line where a mask
  changed the text's length. rich pads ``│ [default: /home/me/.ash/bin]   │`` to the
  terminal width, so after masking, the space count still encodes how long the home
  directory was. The space run before the closing ``│`` is resized so the line keeps
  its rendered width. Only Unicode box verticals count as a border; a markdown
  ``|`` table is left alone. A masked value long enough to wrap onto another line
  on one machine and not another is not handled; snapshot at a width that fits it.

A path root is masked only where it starts a path and ends at a component boundary,
so the system temp dir ``/tmp`` does not mask the middle of ``/home/u/tmp/x``.

What is deliberately NOT masked: counts, severities, rule ids, messages, relative
paths, ordering, column layout, box-drawing characters and emoji. Those are what a
user reads, so a change to any of them must show up as a snapshot diff.
"""

from __future__ import annotations

import json
import platform
import re
import socket
import tempfile
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path, PurePath
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[3]

# CSI sequences (colours, cursor moves), OSC sequences (hyperlinks, titles), and the
# two-byte escapes rich and click emit for resets.
_ANSI = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]"
)

_UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)

# 2026-10-05T12:34:56, with optional fraction and zone; the separator may be a space.
_ISO_INSTANT = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?"
    r"(?:Z|[+-]\d{2}:?\d{2}|\s?UTC)?\b"
)

# ReportMetadata.report_id is "ASH-" + a UTC date or date-time stamp.
_REPORT_ID = re.compile(r"\bASH-\d{8}(?:\d{6})?\b")

# A number followed by a time unit: 1.2s, 350ms, 3 seconds, 0:00:01, 1m 2s, 2h 3m.
_DURATION = re.compile(
    r"(?<![\w.])(?:"
    r"\d+:\d{2}:\d{2}(?:\.\d+)?"
    r"|(?:\d+(?:\.\d+)?\s?(?:h|hr|hrs|hours?)\s?)?(?:\d+(?:\.\d+)?\s?(?:m|min|mins|minutes?)\s?)?"
    r"\d+(?:\.\d+)?\s?(?:ms|s|sec|secs|seconds?)"
    r"|\d+(?:\.\d+)?\s?(?:m|min|mins|minutes?)"
    r")(?![\w])"
)

# Durations ASH writes as bare JSON numbers. Masked by key, not by value, because a
# bare number is only a duration because of the key it sits under.
VOLATILE_KEYS = frozenset(
    {
        "duration",
        "duration_seconds",
        "elapsed",
        "elapsed_seconds",
        "execution_time",
        "scan_duration",
        "scan_duration_seconds",
        "start_time",
        "end_time",
        "generated_at",
        "logged_time",
        "report_id",
        "timestamp",
        "time",
    }
)

_TRAILING_WS = re.compile(r"[ \t]+$", re.MULTILINE)

# The verticals rich closes a panel or table row with (ROUNDED/SQUARE, HEAVY, DOUBLE).
_PANEL_VERTICALS = "│┃║"
# A panel content line: optional indent, a vertical, content, a space run, a vertical.
_PANEL_LINE = re.compile(
    rf"^(?P<body>[ ]*[{_PANEL_VERTICALS}].*?)(?P<pad>[ ]*)(?P<end>[{_PANEL_VERTICALS}])$"
)


def _keep_panel_width(rendered: str, masked: str) -> str:
    """Resize the padding before a panel's right border to undo a mask's length change.

    ``rendered`` and ``masked`` are the same text before and after masking. Lines are
    paired by position, so this only runs when masking kept the line count.
    """
    before_lines = rendered.split("\n")
    after_lines = masked.split("\n")
    if len(before_lines) != len(after_lines):
        return masked
    for i, (before, after) in enumerate(zip(before_lines, after_lines)):
        if before == after or not _PANEL_LINE.match(before):
            continue
        match = _PANEL_LINE.match(after)
        if match is None:
            continue
        pad = len(match["pad"]) + len(before) - len(after)
        if pad >= 1:
            after_lines[i] = match["body"] + " " * pad + match["end"]
    return "\n".join(after_lines)


# The same keys in JSON text: `"time": 1791220796403`. Numbers only; a string value under
# one of these keys is an ISO instant or a duration, which the rules above already mask.
_VOLATILE_JSON_NUMBER = re.compile(
    r'"('
    + "|".join(sorted(map(re.escape, VOLATILE_KEYS)))
    + r')"(\s*:\s*)-?\d+(?:\.\d+)?\b'
)

# A rich traceback panel, which ASH's log handler draws for logger.exception(). Its
# frames quote file paths, line numbers and source lines from wherever the exception
# passed, so any edit to those files would move the snapshot. The corners are rounded
# by default and square where rich's safe_box is on (ASH turns it on for Windows).
_RICH_TRACEBACK = re.compile(
    r"^([ \t]*)[╭┌]─+ Traceback \(most recent call last\) ─+[╮┐]\n"
    r"(?:.*\n)*?"
    r"\1[╰└]─+[╯┘]$",
    re.MULTILINE,
)

# CPython's own traceback: the header, then indented "File ..." and source lines. The
# closing "ExcType: message" line is not indented, so it is not consumed.
_PLAIN_TRACEBACK = re.compile(
    r"^([ \t]*)Traceback \(most recent call last\):\n(?:\1[ \t]+.*\n)+",
    re.MULTILINE,
)

# pydantic links each validation error to a page under its own minor version, so a
# dependency bump would otherwise change every config-error snapshot.
_PYDANTIC_ERROR_URL = re.compile(r"(https://errors\.pydantic\.dev/)[0-9][\w.]*/")

# A root only masks a whole path component sequence: "/tmp" must not match inside
# "/home/u/tmp/x" or at the start of "/tmpfoo".
_ROOT_BEFORE = r"(?<![\w.\-/\\])"
_ROOT_AFTER = r"(?![\w\-]|\.\w)"


def _path_spellings(path: PurePath) -> list[str]:
    """Every way ASH might print ``path``: native, POSIX, JSON-escaped and as a URI."""
    spellings: set[str] = set()
    # A PureWindowsPath stays one, so the Windows spellings can be tested on any host.
    candidates = {path, path.resolve()} if isinstance(path, Path) else {path}
    for candidate in candidates:
        native = str(candidate)
        posix = candidate.as_posix()
        spellings.update({native, posix, json.dumps(native)[1:-1]})
        if candidate.is_absolute():
            try:
                spellings.add(candidate.as_uri())
            except ValueError:
                pass
            # file:///C:/x and file:/C:/x both occur; so does a lower-cased drive.
            spellings.add("file://" + posix)
            if len(posix) > 1 and posix[1] == ":":
                spellings.add(posix[0].lower() + posix[1:])
                spellings.add(posix[0].upper() + posix[1:])
    # A one-character root such as "/" would mask every path separator.
    return sorted((s for s in spellings if len(s) > 3), key=len, reverse=True)


@dataclass
class SnapshotNormalizer:
    """Masks the values listed in the module docstring, and nothing else."""

    roots: list[tuple[PurePath, str]] = field(default_factory=list)
    extra_literals: dict[str, str] = field(default_factory=dict)

    def add_root(self, path: PurePath | str, token: str) -> None:
        """Mask ``path`` (and everything below it) as ``<token>``."""
        self.roots.append(
            (path if isinstance(path, PurePath) else Path(path), f"<{token}>")
        )

    def add_literal(self, value: str, token: str) -> None:
        """Mask one exact string, such as a scan id a test cannot choose."""
        if value:
            self.extra_literals[value] = f"<{token}>"

    # ------------------------------------------------------------------ text --

    def _replacements(self) -> list[tuple[str, str, bool]]:
        """(spelling, token, is_path) triples, longest spelling first."""
        triples: list[tuple[str, str, bool]] = []
        for path, token in self.roots:
            triples.extend(
                (spelling, token, True) for spelling in _path_spellings(path)
            )
        triples.extend(
            (literal, token, False) for literal, token in self.extra_literals.items()
        )
        # Longest first, so a tmp dir inside the repo masks as <TMP>, not <REPO>/...
        return sorted(triples, key=lambda triple: len(triple[0]), reverse=True)

    def text(self, value: str) -> str:
        out = value.replace("\r\n", "\n").replace("\r", "\n")
        out = _ANSI.sub("", out)
        out = _RICH_TRACEBACK.sub(r"\1<TRACEBACK>", out)
        out = _PLAIN_TRACEBACK.sub(r"\1<TRACEBACK>\n", out)
        rendered = out
        for spelling, token, is_path in self._replacements():
            if is_path:
                out = re.sub(
                    _ROOT_BEFORE + re.escape(spelling) + _ROOT_AFTER,
                    lambda _m, token=token: token,
                    out,
                )
            else:
                out = out.replace(spelling, token)
        out = _PYDANTIC_ERROR_URL.sub(r"\1<PYDANTIC_VERSION>/", out)
        tokens = sorted({token for _, token in self.roots}, key=len, reverse=True)
        if tokens:
            # Separators after a token: <TMP>\a\b and <TMP>\\a\\b (JSON) both become <TMP>/a/b.
            pattern = re.compile(
                "("
                + "|".join(re.escape(t) for t in tokens)
                + r")((?:(?:\\\\|\\|/)[^\s\"'<>|,;)\]}]*)+)"
            )
            out = pattern.sub(
                lambda m: m.group(1) + re.sub(r"\\\\|\\", "/", m.group(2)), out
            )
        out = _UUID.sub("<UUID>", out)
        out = _ISO_INSTANT.sub("<TIMESTAMP>", out)
        out = _REPORT_ID.sub("ASH-<REPORT_ID>", out)
        today = date.today()
        for day in (today - timedelta(days=1), today, today + timedelta(days=1)):
            out = out.replace(day.isoformat(), "<TODAY>")
        out = _DURATION.sub("<DURATION>", out)
        out = _VOLATILE_JSON_NUMBER.sub(
            lambda m: f'"{m.group(1)}"{m.group(2)}"<{m.group(1).upper()}>"', out
        )
        out = _keep_panel_width(rendered, out)
        out = _TRAILING_WS.sub("", out)
        return out

    # ------------------------------------------------------------------ data --

    def data(self, value: Any, *, _key: str | None = None) -> Any:
        """Normalize a JSON-shaped value: strings by :meth:`text`, volatile keys by name."""
        if (
            _key is not None
            and _key in VOLATILE_KEYS
            and value not in (None, "", [], {})
        ):
            return f"<{_key.upper()}>"
        if isinstance(value, dict):
            return {
                (self.text(k) if isinstance(k, str) else k): self.data(
                    v, _key=k if isinstance(k, str) else None
                )
                for k, v in value.items()
            }
        if isinstance(value, (list, tuple)):
            return [self.data(v) for v in value]
        if isinstance(value, str):
            return self.text(value)
        return value


def default_normalizer(
    *, tmp_paths: list[Path] | tuple[Path, ...] = ()
) -> SnapshotNormalizer:
    """A normalizer with every root a run can introduce already registered."""
    from automated_security_helper.utils.get_ash_version import get_ash_version

    normalizer = SnapshotNormalizer()
    for tmp in tmp_paths:
        normalizer.add_root(tmp, "TMP")
    normalizer.add_root(Path(tempfile.gettempdir()), "SYSTEM_TMP")
    normalizer.add_root(REPO_ROOT, "REPO")
    normalizer.add_root(Path.cwd(), "CWD")
    normalizer.add_root(Path.home(), "HOME")
    version = get_ash_version()
    if version:
        normalizer.add_literal(str(version), "ASH_VERSION")
    normalizer.add_literal(platform.python_version(), "PYTHON_VERSION")
    for name in {socket.gethostname(), socket.getfqdn()}:
        # Short names ("localhost", a one-letter container id) would mask ordinary words.
        if (
            name
            and len(name) >= 6
            and name not in {"localhost", "localhost.localdomain"}
        ):
            normalizer.add_literal(name, "HOSTNAME")
    return normalizer


def pinned_terminal_env() -> dict[str, str]:
    """The terminal every snapshot is rendered for: 100 columns, no colour, not a TTY."""
    return {
        "COLUMNS": "100",
        "LINES": "50",
        "TERMINAL_WIDTH": "100",
        "NO_COLOR": "1",
        "TERM": "dumb",
        "_TYPER_FORCE_DISABLE_TERMINAL": "1",
        "PYTHONIOENCODING": "utf-8",
    }


__all__ = [
    "REPO_ROOT",
    "SnapshotNormalizer",
    "VOLATILE_KEYS",
    "default_normalizer",
    "pinned_terminal_env",
]
