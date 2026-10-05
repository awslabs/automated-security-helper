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
- ANSI escape sequences and carriage returns. Color is decided by the terminal, not
  by ASH's output, and CRLF is how Windows writes a newline.
- Absolute paths the run chose: the test's tmp dirs, the system temp dir, the repo
  checkout, the home directory and the current directory. Each is replaced by a token
  (``<TMP>``, ``<REPO>`` ...) in every spelling ASH can emit: native, POSIX,
  JSON-escaped and ``file://`` URI. After the token, backslashes become ``/``, so a
  Windows path and a POSIX path snapshot identically.
- The time column of ASH's console log (rich's ``RichHandler``). This one is not
  masked here but pinned where it is drawn: tests/snapshot/conftest.py makes every
  ``LogRender`` print the constant ``[<LOG_TIME>]`` instead of the record's time, for
  every snapshot test. A text rule cannot do that job. rich prints the time only when
  it differs from the previous row's, so with a real clock whether row two has a time
  is a race with the second hand; rich's ``[%x %X]`` is 19 characters wide in the C
  locale and wider in a locale that sets LC_TIME and spells out the year or AM/PM; and
  the message column is whatever is left of the line, so every wrap point moves with
  that width. Masking the stamp after the fact fixes none of the indentation or
  wrapping. With the constant, the first row of each handler shows ``[<LOG_TIME>]``,
  every later row shows the same 12 blanks, and the message column is the same width
  under any clock, locale or TZ.
  ``_LOG_TIME`` below is the backstop for a C-locale stamp drawn some other way (it
  masks the stamp only, so such output would still fail on its indentation, loudly).
  A bare or bracketed date in a message survives.
- Instants and durations, but only for a test that opts in; see "Time" below.
- UUIDs, the ASH version, the Python version and the hostname.
- The pydantic minor version in its ``errors.pydantic.dev/<version>/`` help links, which
  a dependency bump changes in every config-error message.
- The frames of a traceback, rich's panel or CPython's plain one, as ``<TRACEBACK>``.
  Frames quote paths, line numbers and source lines from every file the exception
  passed through, so they move with unrelated edits. The fact that a traceback was
  shown, and the ``ExcType: message`` line after it, are kept: a message that turns
  into a traceback, or back, still shows up as a diff.
- ``jq-<digits>`` element ids in the ``inspect sarif-fields`` HTML report, which are
  derived from Python's per-process salted ``hash()``.
- Trailing whitespace on each line, which rich pads tables with.
- The padding in front of a rich panel's right border, on a line where a mask
  changed the text's length. rich pads ``│ [default: /home/me/.ash/bin]   │`` to the
  terminal width, so after masking, the space count still encodes how long the home
  directory was. The space run before the closing ``│`` is recomputed from the line's
  rendered width (its length before masking), so the border stays where rich drew it
  whether the mask made the text shorter (``/home/runneradmin`` -> ``<HOME>``) or
  longer (``/tmp`` -> ``<SYSTEM_TMP>``). When the masked text no longer fits in that
  width, one space is kept before the border. Either way the result depends only on
  the masked text and the panel width, not on how long the original value was. Only
  Unicode box verticals count as a border; a markdown ``|`` table is left alone. A
  masked value long enough to wrap onto another line on one machine and not another
  is not handled; snapshot at a width that fits it.

A path root is masked only where it starts a path and ends at a component boundary,
so the system temp dir ``/tmp`` does not mask the middle of ``/home/u/tmp/x``.

Time
----
Time is NOT masked by default. Three switches mask it, each off unless a test opts in
with ``@pytest.mark.snapshot_masking(<switch>=True)`` (see tests/snapshot/conftest.py),
so a new test sees every timestamp and duration it renders. A wrong instant or a wrong
duration is a defect a user reads. While masking was on by default, truncating the text
report's "Report generated:" stamp, writing OCSF's ``time`` in seconds instead of
milliseconds, and a ``<1ms`` duration defect in the text and HTML reporters all passed
the whole suite. The fix for wall-clock output is to pin the clock
(``pinned_clock`` in tests/snapshot/conftest.py, ``pin_clock`` in
support/fixture_model.py). Opting in is for output whose time cannot be pinned cheaply,
and only once the test has been shown to differ between runs, or between time zones,
without it.

- ``mask_instants``: ISO-8601 instants, ``ASH-YYYYMMDD[HHMMSS]`` report ids, the
  ``scan-YYYYMMDDHHMMSS`` id MCP get_scan_results mints per call, today's date (plus
  yesterday and tomorrow, so a run that crosses midnight still matches), and any value
  under an instant key (``INSTANT_KEYS``: ``time``, ``logged_time``, ``start_time``
  ...), in structured data and in JSON text a command printed. A date a fixture chose,
  such as a suppression's expiry, is not today and survives even with the switch on.
- ``mask_durations``: a number followed by a time unit, in prose (``1.2s``, ``350ms``,
  ``0:00:01``, ``3 seconds``).
- ``mask_duration_keys``: a number under a duration key (``DURATION_KEYS``:
  ``duration``, ``elapsed`` ...), in structured data and in JSON text.

``VOLATILE_KEYS`` is both key sets.

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
from urllib.parse import quote_from_bytes

REPO_ROOT = Path(__file__).resolve().parents[3]

# CSI sequences (colors, cursor moves), OSC sequences (hyperlinks, titles), and the
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

# RichHandler's default log_time_format "[%x %X]" in the C locale: [10/05/26 17:22:49].
# Masked before durations, which would otherwise take the HH:MM:SS half alone.
_LOG_TIME = re.compile(r"\[\d{2}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\]")

# Element ids in the `inspect sarif-fields` HTML report, built as
# f"jq-{abs(hash(path)) % 10000000}" (utils/meta_analysis/reporting.py). str hashes are
# salted per process (PYTHONHASHSEED), so the number changes on every run. Only a
# quoted value (an attribute, or the JS string argument that refers to it) is masked.
_JQ_ELEMENT_ID = re.compile(r"(?<=['\"])((?:btn-)?jq-)\d+(?=['\"])")
# The MCP get_scan_results scan_id: "scan-" + the local date-time it was read at
# (core/resource_management/scan_tracking.py mints it on every call).
_MCP_RESULTS_SCAN_ID = re.compile(r"\bscan-\d{14}\b")

# A number followed by a time unit: 1.2s, 350ms, 3 seconds, 0:00:01, 1m 2s, 2h 3m.
_DURATION = re.compile(
    r"(?<![\w.])(?:"
    r"\d+:\d{2}:\d{2}(?:\.\d+)?"
    r"|(?:\d+(?:\.\d+)?\s?(?:h|hr|hrs|hours?)\s?)?(?:\d+(?:\.\d+)?\s?(?:m|min|mins|minutes?)\s?)?"
    r"\d+(?:\.\d+)?\s?(?:ms|s|sec|secs|seconds?)"
    r"|\d+(?:\.\d+)?\s?(?:m|min|mins|minutes?)"
    r")(?![\w])"
)

# Time ASH writes as bare values. Masked by key, not by value, because a bare number is
# only a duration or an instant because of the key it sits under.
#: Lengths of time ASH measured. Masked only under ``mask_duration_keys``.
DURATION_KEYS = frozenset(
    {
        "duration",
        "duration_seconds",
        "elapsed",
        "elapsed_seconds",
        "execution_time",
        "scan_duration",
        "scan_duration_seconds",
    }
)
#: Points in time, and the report id minted from one. Masked only under
#: ``mask_instants``.
INSTANT_KEYS = frozenset(
    {
        "start_time",
        "end_time",
        "generated_at",
        "logged_time",
        "report_id",
        "timestamp",
        "time",
    }
)
VOLATILE_KEYS = DURATION_KEYS | INSTANT_KEYS

_TRAILING_WS = re.compile(r"[ \t]+$", re.MULTILINE)

# The verticals rich closes a panel or table row with (ROUNDED/SQUARE, HEAVY, DOUBLE).
_PANEL_VERTICALS = "│┃║"
# A panel content line: optional indent, a vertical, content, a space run, a vertical.
_PANEL_LINE = re.compile(
    rf"^(?P<body>[ ]*[{_PANEL_VERTICALS}].*?)(?P<pad>[ ]*)(?P<end>[{_PANEL_VERTICALS}])$"
)


def _keep_panel_width(rendered: str, masked: str) -> str:
    """Re-pad a masked panel line to the width rich rendered it at.

    ``rendered`` and ``masked`` are the same text before and after masking. Lines are
    paired by position, so this only runs when masking kept the line count. The pad is
    computed from the line's rendered width and the masked content alone, never from
    the old pad, so two machines whose masked values had different lengths produce the
    same line. Content that no longer fits keeps one space before the border.
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
        pad = max(1, len(before) - len(match["body"]) - len(match["end"]))
        after_lines[i] = match["body"] + " " * pad + match["end"]
    return "\n".join(after_lines)


def _json_number_under(keys: frozenset[str]) -> re.Pattern[str]:
    """``"<key>": <number>`` in JSON text, for one of ``keys``.

    Numbers only; a string value under one of these keys is an ISO instant or a
    duration in prose, which the text rules already handle.
    """
    return re.compile(
        r'"('
        + "|".join(sorted(map(re.escape, keys)))
        + r')"(\s*:\s*)-?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?\b'
    )


# The same keys in JSON text: `"time": 1791220796403`.
_INSTANT_JSON_NUMBER = _json_number_under(INSTANT_KEYS)
_DURATION_JSON_NUMBER = _json_number_under(DURATION_KEYS)


def _mask_json_number(match: re.Match[str]) -> str:
    return f'"{match.group(1)}"{match.group(2)}"<{match.group(1).upper()}>"'


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


def _file_uri(path: PurePath) -> str:
    """``path.as_uri()``, for an absolute concrete or pure path.

    ``PurePath.as_uri()`` is deprecated from Python 3.14 (``Path.as_uri()`` is not), and
    a pure path is how the Windows spellings are tested on any host. So a concrete path
    asks pathlib, and a pure one gets the URI CPython 3.10-3.13 built, constructed the
    same way here: ``file:///C:/x`` for a drive, ``file://server/share/x`` for UNC
    (``file:`` + its POSIX form), ``file:///x`` for POSIX; percent-encoded as UTF-8.
    """
    if isinstance(path, Path):
        return path.as_uri()
    drive = path.drive
    if len(drive) == 2 and drive[1] == ":":
        prefix, rest = "file:///" + drive, path.as_posix()[2:]
    elif drive:
        prefix, rest = "file:", path.as_posix()
    else:
        prefix, rest = "file://", str(path)
    return prefix + quote_from_bytes(rest.encode("utf-8", "surrogateescape"))


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
            spellings.add(_file_uri(candidate))
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
    # Off by default: a test opts in only for wall-clock time it cannot pin. See "Time"
    # in the module docstring.
    #: Mask ISO instants, report-id and scan-id stamps, today's date, INSTANT_KEYS.
    mask_instants: bool = False
    #: Mask "number + time unit" in prose.
    mask_durations: bool = False
    #: Mask numbers under DURATION_KEYS.
    mask_duration_keys: bool = False

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
        # The log-time backstop runs whatever the switches say: the column is pinned
        # by conftest.py, so a stamp here is drawn some other way (see the docstring).
        out = _LOG_TIME.sub("[<LOG_TIME>]", out)
        out = _JQ_ELEMENT_ID.sub(r"\1<HASH_ID>", out)
        if self.mask_instants:
            out = _ISO_INSTANT.sub("<TIMESTAMP>", out)
            out = _REPORT_ID.sub("ASH-<REPORT_ID>", out)
            out = _MCP_RESULTS_SCAN_ID.sub("scan-<SCAN_TIMESTAMP>", out)
            today = date.today()
            for day in (today - timedelta(days=1), today, today + timedelta(days=1)):
                out = out.replace(day.isoformat(), "<TODAY>")
        if self.mask_durations:
            out = _DURATION.sub("<DURATION>", out)
        if self.mask_instants:
            out = _INSTANT_JSON_NUMBER.sub(_mask_json_number, out)
        if self.mask_duration_keys:
            out = _DURATION_JSON_NUMBER.sub(_mask_json_number, out)
        out = _keep_panel_width(rendered, out)
        out = _TRAILING_WS.sub("", out)
        return out

    # ------------------------------------------------------------------ data --

    def data(self, value: Any, *, _key: str | None = None) -> Any:
        """Normalize a JSON-shaped value: strings by :meth:`text`, volatile keys by name."""
        if (
            _key is not None
            and value not in (None, "", [], {})
            and (
                (_key in INSTANT_KEYS and self.mask_instants)
                or (_key in DURATION_KEYS and self.mask_duration_keys)
            )
        ):
            # With its switch off, a volatile key's value is normalized like any
            # other: a number is kept, a string still goes through the text rules.
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
    # pytest run from a subdirectory of the checkout would otherwise mask every repo
    # path under it as <CWD>/..., and run from a parent of the checkout it would mask
    # the repo's siblings by where the developer happened to stand. Either way the
    # snapshot would depend on the directory pytest was started from.
    cwd = Path.cwd().resolve()
    repo = REPO_ROOT.resolve()
    if not (cwd.is_relative_to(repo) or repo.is_relative_to(cwd)):
        normalizer.add_root(cwd, "CWD")
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
    """The terminal every snapshot is rendered for: 100 columns, no color, not a TTY."""
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
    "DURATION_KEYS",
    "INSTANT_KEYS",
    "REPO_ROOT",
    "SnapshotNormalizer",
    "VOLATILE_KEYS",
    "default_normalizer",
    "pinned_terminal_env",
]
