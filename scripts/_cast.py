"""Core library of the terminal recording of the local tutorial.

The recording is made in steps that share this module. A recorder runs the tutorial's
commands under a terminal and measures what they print. The retimer in this module
rewrites those measured times from a storyboard, so the recording has the same length
whatever the machine did. A renderer turns the recording into an animated image.
Nothing here touches a terminal, so the module runs, and is tested, on every platform.

What it holds
-------------
* asciicast v2: ``CastHeader``, ``CastEvent`` and ``Cast``, with ``dumps_cast`` and
  ``loads_cast`` and their file forms. A header needs ``version`` 2, ``width`` and
  ``height``. The event codes are ``o`` (output), ``i`` (input), ``m`` (marker) and
  ``r`` (resize). Times never go backwards and are written with three decimals. A
  reader skips codes it does not know, as the format allows.
* the storyboard: ``parse_storyboard`` and ``load_storyboard`` read schema 1, refuse
  unknown keys the way the journey loader does, and apply the copy rules to captions
  with ``count_words`` and ``caption_problems``, the one counter those rules use.
* the retimer: ``retime`` rewrites the measured output times of every scene into the
  scene's own budget. Output is shortened to fit and never stretched.
* the scrub scan: ``scan_text`` and ``scan_cast`` look for tokens that must not appear
  in a recording (home directories, user and host names) and name each hit by its
  kind, never by its value.
* the run record: dataclasses for what a recording run observed, and
  ``canonical_json``, the one JSON form the record is written in.

Dependencies
------------
The standard library only. PyYAML is imported inside ``load_storyboard``, the one
function that reads a YAML file; ``parse_storyboard`` takes data that is already
parsed. This module imports no ``pty``, ``termios`` or ``fcntl``, and
tests/unit/docs/test_cast_core.py checks that on the syntax tree.

Times
-----
A time in a storyboard is a number of seconds that is a whole number of milliseconds.
The module keeps every duration as an integer number of milliseconds and converts to
seconds only where an asciicast event needs it, so sums of scene durations are exact
and the same input always gives the same bytes.
"""

from __future__ import annotations

import dataclasses
import json
import math
import operator
import re
from collections.abc import Collection, Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, NoReturn

CAST_VERSION = 2
#: The event codes of the asciicast v2 spec. A reader skips any other code.
EVENT_CODES = ("o", "i", "m", "r")
#: Home the cursor and erase the screen: how a scene that clears starts.
CLEAR_SCREEN = "\x1b[H\x1b[2J"


class CastError(ValueError):
    """Every refusal this module makes; the message names the place it refused."""


class CastFileError(CastError):
    """An asciicast file, or one of its parts, is refused."""


class StoryboardError(CastError):
    """A storyboard is refused."""


class RetimeError(CastError):
    """A scene cannot be retimed."""


class RecordError(CastError):
    """A run record is refused."""


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _is_number(value: object) -> bool:
    """A real number that is not a bool, NaN or infinite."""
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return isinstance(value, float) and math.isfinite(value)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _set(instance: object, name: str, value: object) -> None:
    """Assign a field of a frozen dataclass from its own ``__post_init__``."""
    object.__setattr__(instance, name, value)


# ---------------------------------------------------------------------------
# asciicast v2
# ---------------------------------------------------------------------------

_COLOR = re.compile(r"#[0-9A-Fa-f]{6}")
_RESIZE = re.compile(r"[1-9][0-9]*x[1-9][0-9]*")


def _check_color(value: object, label: str) -> None:
    if not isinstance(value, str) or _COLOR.fullmatch(value) is None:
        raise CastFileError(f"{label} {value!r} must be a #rrggbb color")


@dataclasses.dataclass(frozen=True)
class CastTheme:
    """The ``theme`` of a header: foreground, background and 8 or 16 palette colors."""

    fg: str
    bg: str
    palette: tuple[str, ...]

    def __post_init__(self) -> None:
        _check_color(self.fg, "fg")
        _check_color(self.bg, "bg")
        if isinstance(self.palette, str) or not isinstance(self.palette, (list, tuple)):
            raise CastFileError("theme palette must be a list of #rrggbb colors")
        _set(self, "palette", tuple(self.palette))
        if len(self.palette) not in (8, 16):
            raise CastFileError(
                f"theme palette must hold 8 or 16 colors, not {len(self.palette)}"
            )
        for index, color in enumerate(self.palette):
            _check_color(color, f"palette entry {index}")

    def to_json_obj(self) -> dict[str, str]:
        return {"fg": self.fg, "bg": self.bg, "palette": ":".join(self.palette)}

    @classmethod
    def from_json_obj(cls, obj: object) -> CastTheme:
        if not isinstance(obj, dict):
            raise CastFileError("the header theme must be an object")
        for key in ("fg", "bg", "palette"):
            if key not in obj:
                raise CastFileError(f"the header theme lacks {key!r}")
        palette = obj["palette"]
        if not isinstance(palette, str):
            raise CastFileError(
                "the header theme palette must be a colon-joined string"
            )
        return cls(fg=obj["fg"], bg=obj["bg"], palette=tuple(palette.split(":")))


@dataclasses.dataclass(frozen=True, kw_only=True)
class CastHeader:
    """The first line of an asciicast v2 file.

    ``version`` (2), ``width`` and ``height`` are required; every other field is
    written only when it is set.
    """

    width: int
    height: int
    version: int = CAST_VERSION
    timestamp: int | None = None
    duration: float | None = None
    idle_time_limit: float | None = None
    command: str | None = None
    title: str | None = None
    env: Mapping[str, str] | None = None
    theme: CastTheme | None = None

    def __post_init__(self) -> None:
        if not _is_int(self.version) or self.version != CAST_VERSION:
            raise CastFileError(
                f"the header version must be {CAST_VERSION}, not {self.version!r}"
            )
        for name in ("width", "height"):
            value = getattr(self, name)
            if not _is_int(value) or value < 1:
                raise CastFileError(
                    f"the header {name} must be a positive integer, not {value!r}"
                )
        if self.timestamp is not None and (
            not _is_int(self.timestamp) or self.timestamp < 0
        ):
            raise CastFileError(
                "the header timestamp must be a whole number of seconds, 0 or more, "
                f"not {self.timestamp!r}"
            )
        if self.duration is not None and (
            not _is_number(self.duration) or self.duration < 0
        ):
            raise CastFileError(
                "the header duration must be a number of seconds, 0 or more, "
                f"not {self.duration!r}"
            )
        if self.idle_time_limit is not None and (
            not _is_number(self.idle_time_limit) or self.idle_time_limit <= 0
        ):
            raise CastFileError(
                "the header idle_time_limit must be a number of seconds greater "
                f"than 0, not {self.idle_time_limit!r}"
            )
        for name in ("command", "title"):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, str) or not value):
                raise CastFileError(
                    f"the header {name} must be a non-empty string, not {value!r}"
                )
        if self.env is not None:
            env = self.env
            if not isinstance(env, Mapping) or any(
                not isinstance(key, str) or not key or not isinstance(item, str)
                for key, item in env.items()
            ):
                raise CastFileError(
                    "the header env must map non-empty strings to strings"
                )
            _set(self, "env", dict(env))
        if self.theme is not None and not isinstance(self.theme, CastTheme):
            raise CastFileError("the header theme must be a CastTheme")

    def to_json_obj(self) -> dict[str, object]:
        """The header as a JSON object, in the spec's field order."""
        obj: dict[str, object] = {
            "version": self.version,
            "width": self.width,
            "height": self.height,
        }
        if self.timestamp is not None:
            obj["timestamp"] = self.timestamp
        if self.duration is not None:
            obj["duration"] = round(self.duration, 3)
        if self.idle_time_limit is not None:
            obj["idle_time_limit"] = self.idle_time_limit
        if self.command is not None:
            obj["command"] = self.command
        if self.title is not None:
            obj["title"] = self.title
        if self.env is not None:
            obj["env"] = dict(sorted(self.env.items()))
        if self.theme is not None:
            obj["theme"] = self.theme.to_json_obj()
        return obj

    @classmethod
    def from_json_obj(cls, obj: object) -> CastHeader:
        """A header from parsed JSON. Keys the spec does not name are ignored."""
        if not isinstance(obj, dict):
            raise CastFileError("the header must be a JSON object")
        for key in ("version", "width", "height"):
            if key not in obj:
                raise CastFileError(f"the header lacks {key!r}")
        names = (
            "version",
            "width",
            "height",
            "timestamp",
            "duration",
            "idle_time_limit",
            "command",
            "title",
            "env",
        )
        fields: dict[str, Any] = {name: obj[name] for name in names if name in obj}
        if "theme" in obj:
            fields["theme"] = CastTheme.from_json_obj(obj["theme"])
        return cls(**fields)


@dataclasses.dataclass(frozen=True)
class CastEvent:
    """One ``[time, code, data]`` line: seconds since the start, a code, its text."""

    time: float
    code: str
    data: str

    def __post_init__(self) -> None:
        if not _is_number(self.time) or self.time < 0:
            raise CastFileError(
                f"event time {self.time!r} must be a number of seconds, 0 or more"
            )
        if not isinstance(self.code, str):
            raise CastFileError(f"event code {self.code!r} must be a string")
        if self.code not in EVENT_CODES:
            raise CastFileError(
                f"event code {self.code!r} is not one this module writes "
                f"({', '.join(EVENT_CODES)})"
            )
        if not isinstance(self.data, str):
            raise CastFileError(f"event data {self.data!r} must be a string")
        if self.code == "r" and _RESIZE.fullmatch(self.data) is None:
            raise CastFileError(
                f"a resize event's data must be COLSxROWS, not {self.data!r}"
            )


@dataclasses.dataclass(frozen=True)
class Cast:
    """A header and its events, with times that never go backwards."""

    header: CastHeader
    events: tuple[CastEvent, ...]

    def __post_init__(self) -> None:
        _set(self, "events", tuple(self.events))
        for index in range(1, len(self.events)):
            before, after = self.events[index - 1], self.events[index]
            if after.time < before.time:
                raise CastFileError(
                    f"event {index} at {after.time} s is earlier than the event "
                    f"before it ({before.time} s)"
                )


def format_time(seconds: float) -> str:
    """``seconds`` as an asciicast time: whole milliseconds written as ``S.mmm``."""
    if not _is_number(seconds) or seconds < 0:
        raise CastFileError(
            f"a time must be a number of seconds, 0 or more, not {seconds!r}"
        )
    milliseconds = round(seconds * 1000)
    return f"{milliseconds // 1000}.{milliseconds % 1000:03d}"


def dumps_cast(cast: Cast) -> str:
    """The text of an asciicast v2 file: the header line, then one line per event.

    The text is ASCII (non-ASCII characters are JSON escapes) and ends with one
    newline.
    """
    lines = [json.dumps(cast.header.to_json_obj())]
    lines.extend(
        f"[{format_time(event.time)}, {json.dumps(event.code)}, "
        f"{json.dumps(event.data)}]"
        for event in cast.events
    )
    return "\n".join(lines) + "\n"


def _parse_line(line: str, number: int) -> object:
    def refuse(name: str) -> NoReturn:
        raise CastFileError(f"line {number}: {name} is not valid JSON")

    try:
        return json.loads(line, parse_constant=refuse)
    except json.JSONDecodeError as exc:
        raise CastFileError(f"line {number}: not valid JSON: {exc.msg}") from exc


def _event_from_json(raw: object, number: int) -> CastEvent | None:
    if not isinstance(raw, list) or len(raw) != 3:
        raise CastFileError(f"line {number}: an event is [time, code, data]")
    time, code, data = raw
    if isinstance(code, str) and code not in EVENT_CODES:
        return None
    try:
        return CastEvent(time, code, data)
    except CastFileError as exc:
        raise CastFileError(f"line {number}: {exc}") from exc


def loads_cast(text: str) -> Cast:
    """Read asciicast v2 text. Event codes this module does not know are skipped."""
    if not text.strip():
        raise CastFileError(
            "the file is empty; an asciicast v2 file starts with its header line"
        )
    lines = text.split("\n")
    if lines[-1] == "":
        lines.pop()
    header = CastHeader.from_json_obj(_parse_line(lines[0], 1))
    events: list[CastEvent] = []
    for number, line in enumerate(lines[1:], start=2):
        event = _event_from_json(_parse_line(line, number), number)
        if event is not None:
            events.append(event)
    return Cast(header=header, events=tuple(events))


def write_cast(path: str | Path, cast: Cast) -> None:
    """Write ``cast`` to ``path`` as UTF-8 text with Unix newlines."""
    Path(path).write_text(dumps_cast(cast), encoding="utf-8", newline="\n")


def read_cast(path: str | Path) -> Cast:
    """Read the asciicast v2 file at ``path``."""
    return loads_cast(Path(path).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# The storyboard
# ---------------------------------------------------------------------------

STORYBOARD_SCHEMA = 1
JOURNEY_SUFFIX = ".journey.yaml"
TOTAL_MIN_MS = 30_000
TOTAL_MAX_MS = 60_000
MAX_CAPTION_WORDS = 7
MAX_WORDS_PER_SECOND = 3.5
EXCLUSIVE_WORDS = ("only", "every", "all", "always", "never", "each")
EXCLUSIVE_PHRASES = ("in seconds",)
#: The commands a scene may type itself, besides running a journey block.
READ_ONLY_COMMANDS = ("cat", "ls")
#: The ``ls`` flags that print the owner or the group of each file: ``-l`` and the flags
#: that imply it. A user or group name in such a column is not one the scrub scan can
#: recognize, because it finds a user name only after a slash.
LS_OWNER_FLAGS = "lgon"
PLAYBACK_MODES = ("once", "loop")
MIN_COLS, MAX_COLS = 20, 300
MIN_ROWS, MAX_ROWS = 5, 100
MAX_CHARS_PER_SECOND = 1000
#: A time in a storyboard is refused above this many seconds, before any arithmetic.
MAX_SECONDS = 3600

_TOP_KEYS = frozenset(
    {
        "schema",
        "journey",
        "terminal",
        "typing",
        "output",
        "poster_scene",
        "playback",
        "scenes",
    }
)
_TERMINAL_KEYS = frozenset({"cols", "rows", "prompt"})
_TYPING_KEYS = frozenset({"chars_per_second", "lead_in_s"})
_OUTPUT_KEYS = frozenset({"max_gap_s"})
_SCENE_KEYS = frozenset(
    {
        "id",
        "caption",
        "duration_s",
        "block",
        "hidden_blocks",
        "command",
        "comment_from",
        "clear",
        "output_window_s",
        "hold_s",
        "expect_screen",
    }
)
_SCENE_REQUIRED = frozenset({"id", "caption", "duration_s"})

_ID = re.compile(r"[a-z][a-z0-9-]*")
_JOURNEY_PATH = re.compile(r"[A-Za-z0-9_./-]+")
_COMMENT_FROM = re.compile(r"([A-Za-z0-9_./-]+)#([a-z0-9][a-z0-9_-]*)")
_WORD = re.compile(r"[^\W\d_]+")
_COMMAND_FLAG = re.compile(r"-[A-Za-z0-9]+")
_COMMAND_PATH = re.compile(r"[A-Za-z0-9_./-]+")


def count_words(text: str) -> int:
    """The caption counter: whitespace-separated words, as ``wc -w`` counts them."""
    return len(text.split())


def caption_problems(caption: str, duration_ms: int) -> list[str]:
    """What the copy rules find wrong with ``caption`` for a scene of ``duration_ms``.

    An empty list means the caption passes. A caption is one line of single-spaced
    printable words, at most 7 of them and at most 3.5 a second of the scene, with no
    digit and none of the exclusive words (only, every, all, always, never, each, and
    the phrase "in seconds"). The words are matched whole and in any letter case.
    """
    if not isinstance(caption, str):
        return ["must be a string"]
    if not caption.strip():
        return ["is empty"]
    problems: list[str] = []
    if caption != " ".join(caption.split()) or not caption.isprintable():
        problems.append(
            "must be one line of printable words separated by single spaces"
        )
    words = count_words(caption)
    if words > MAX_CAPTION_WORDS:
        problems.append(f"has more than {MAX_CAPTION_WORDS} words ({words})")
    if words * 1000 > MAX_WORDS_PER_SECOND * duration_ms:
        problems.append(
            f"carries {words} words in {duration_ms / 1000:g} s, more than "
            f"{MAX_WORDS_PER_SECOND} words a second"
        )
    if any(char.isdigit() for char in caption):
        problems.append("has a digit; captions carry no numbers")
    tokens = [token.lower() for token in _WORD.findall(caption)]
    for word in EXCLUSIVE_WORDS:
        if word in tokens:
            problems.append(f"uses the exclusive word {word!r}")
    for phrase in EXCLUSIVE_PHRASES:
        parts = phrase.split()
        if any(
            tokens[start : start + len(parts)] == parts for start in range(len(tokens))
        ):
            problems.append(f"uses the exclusive phrase {phrase!r}")
    return problems


def _long_option_lists_owners(option: str) -> bool:
    """Whether ``option`` is an ``ls`` long option that prints the owner and group of
    each file, or an abbreviation of one that ``ls`` accepts: ``--format=long``,
    ``--format=verbose``, ``--full-time`` and ``--numeric-uid-gid``."""
    if not option.startswith("--"):
        return False
    name, _, value = option[2:].partition("=")
    if not name:
        return False
    if "full-time".startswith(name) or "numeric-uid-gid".startswith(name):
        return True
    return (
        "format".startswith(name)
        and bool(value)
        and ("long".startswith(value) or "verbose".startswith(value))
    )


def _ls_owner_problem(argument: str) -> str:
    return (
        f"argument {argument!r} prints the owner and group of each file, which the "
        "scrub scan cannot recognize; ls is admitted without a long listing (the "
        f"{', '.join('-' + flag for flag in LS_OWNER_FLAGS)} flags and the options "
        "that do the same)"
    )


def command_problem(command: str) -> str | None:
    """Why ``command`` is not an admitted read-only command, or None when it is.

    Admitted: ``cat`` or ``ls`` (by that bare name), short flags such as ``-1`` or
    ``-a``, and relative paths of plain characters that stay inside the project. An
    ``ls`` flag that prints the owner and group of each file (``-l``, ``-g``, ``-o``
    and ``-n``, alone or in a bundle such as ``-la``, and the long options that do the
    same) is refused: the scrub scan cannot recognize a user or group name in that
    column. The check reads the text only; the recorder runs the command in the
    project directory.
    """
    if not isinstance(command, str) or not command.strip():
        return "the command is empty"
    if command != " ".join(command.split()):
        return "the command must be words separated by single spaces"
    program, *arguments = command.split(" ")
    if program not in READ_ONLY_COMMANDS:
        return (
            f"{program!r} is not in the read-only allowlist {list(READ_ONLY_COMMANDS)}"
        )
    paths = 0
    for argument in arguments:
        if _COMMAND_FLAG.fullmatch(argument):
            if program == "ls" and set(LS_OWNER_FLAGS) & set(argument[1:]):
                return _ls_owner_problem(argument)
            continue
        if argument.startswith("-"):
            if program == "ls" and _long_option_lists_owners(argument):
                return _ls_owner_problem(argument)
            return f"argument {argument!r} is an option other than a short flag"
        if _COMMAND_PATH.fullmatch(argument) is None:
            return f"argument {argument!r} is not a plain relative path or a short flag"
        if argument.startswith("/"):
            return (
                f"argument {argument!r} is an absolute path, not a relative path "
                "inside the project"
            )
        if ".." in argument.split("/"):
            return f"argument {argument!r} leaves the project"
        paths += 1
    if program == "cat" and paths == 0:
        return "cat needs a file to read"
    return None


def typing_ms(chars: int, chars_per_second: float) -> int:
    """Milliseconds to type ``chars`` characters at ``chars_per_second``."""
    return round(chars * 1000 / chars_per_second)


@dataclasses.dataclass(frozen=True)
class Terminal:
    """The recorded terminal: its size and the prompt each scene starts with."""

    cols: int
    rows: int
    prompt: str


@dataclasses.dataclass(frozen=True)
class TypingPolicy:
    """How a command is typed: a rate, and the pause before the first character."""

    chars_per_second: float
    lead_in_ms: int


@dataclasses.dataclass(frozen=True)
class OutputPolicy:
    """The longest pause kept between two chunks of output."""

    max_gap_ms: int


@dataclasses.dataclass(frozen=True)
class Scene:
    """One scene. ``start_ms`` is the running sum of the scenes before it."""

    scene_id: str
    caption: str
    start_ms: int
    duration_ms: int
    hold_ms: int
    block: str | None = None
    hidden_blocks: tuple[str, ...] = ()
    command: str | None = None
    comment_from: str | None = None
    clear: bool = False
    output_window_ms: int | None = None
    expect_screen: tuple[str, ...] = ()

    @property
    def end_ms(self) -> int:
        return self.start_ms + self.duration_ms

    @property
    def words(self) -> int:
        return count_words(self.caption)


@dataclasses.dataclass(frozen=True)
class Storyboard:
    """A parsed storyboard of schema 1."""

    journey: str
    terminal: Terminal
    typing: TypingPolicy
    output: OutputPolicy
    poster_scene: str
    playback: str
    scenes: tuple[Scene, ...]

    @property
    def total_ms(self) -> int:
        return sum(scene.duration_ms for scene in self.scenes)

    @property
    def total_s(self) -> float:
        return self.total_ms / 1000

    def scene(self, scene_id: str) -> Scene:
        for scene in self.scenes:
            if scene.scene_id == scene_id:
                return scene
        raise StoryboardError(f"the storyboard has no scene {scene_id!r}")


def _fail(where: str, message: str) -> NoReturn:
    raise StoryboardError(f"{where}: {message}")


def _unknown(keys: Iterable[object], allowed: Collection[str], where: str) -> None:
    """Refuse keys the schema does not name, as the journey loader does."""
    extra = sorted(str(key) for key in set(keys) - set(allowed))
    if extra:
        _fail(
            where,
            f"unknown key(s) {extra}; schema {STORYBOARD_SCHEMA} allows "
            f"{sorted(allowed)}",
        )


def _mapping(
    value: object, where: str, allowed: Collection[str], required: Collection[str]
) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(where, "must be a mapping")
    _unknown(value, allowed, where)
    missing = sorted(set(required) - set(value))
    if missing:
        _fail(where, f"missing key(s) {missing}")
    return value


def _seconds(value: object, where: str, name: str, *, positive: bool) -> int:
    """``value`` seconds as whole milliseconds; ``positive`` refuses 0."""
    if not _is_number(value):
        _fail(where, f"{name} must be a number of seconds, not {value!r}")
    if abs(value) > MAX_SECONDS:
        _fail(where, f"{name} {value!r} is out of range")
    milliseconds = round(value * 1000)
    if abs(value * 1000 - milliseconds) > 1e-6:
        _fail(where, f"{name} {value!r} is not a whole number of milliseconds")
    if positive and milliseconds <= 0:
        _fail(where, f"{name} must be greater than 0")
    if milliseconds < 0:
        _fail(where, f"{name} must be 0 or more")
    return milliseconds


def _parse_terminal(raw: object, source: str) -> Terminal:
    where = f"{source}: terminal"
    data = _mapping(raw, where, _TERMINAL_KEYS, _TERMINAL_KEYS)
    cols, rows, prompt = data["cols"], data["rows"], data["prompt"]
    if not _is_int(cols) or not MIN_COLS <= cols <= MAX_COLS:
        _fail(where, f"cols must be an integer from {MIN_COLS} to {MAX_COLS}")
    if not _is_int(rows) or not MIN_ROWS <= rows <= MAX_ROWS:
        _fail(where, f"rows must be an integer from {MIN_ROWS} to {MAX_ROWS}")
    if not isinstance(prompt, str) or not prompt or not prompt.isprintable():
        _fail(where, f"prompt must be printable characters on one line, not {prompt!r}")
    if len(prompt) > 40:
        _fail(where, "prompt must be at most 40 characters")
    return Terminal(cols=cols, rows=rows, prompt=prompt)


def _parse_typing(raw: object, source: str) -> TypingPolicy:
    where = f"{source}: typing"
    data = _mapping(raw, where, _TYPING_KEYS, _TYPING_KEYS)
    rate = data["chars_per_second"]
    if not _is_number(rate) or not 0 < rate <= MAX_CHARS_PER_SECOND:
        _fail(
            where,
            "chars_per_second must be greater than 0 and at most "
            f"{MAX_CHARS_PER_SECOND}, not {rate!r}",
        )
    lead_in = _seconds(data["lead_in_s"], where, "lead_in_s", positive=False)
    return TypingPolicy(chars_per_second=rate, lead_in_ms=lead_in)


def _parse_output(raw: object, source: str) -> OutputPolicy:
    where = f"{source}: output"
    data = _mapping(raw, where, _OUTPUT_KEYS, _OUTPUT_KEYS)
    gap = _seconds(data["max_gap_s"], where, "max_gap_s", positive=True)
    return OutputPolicy(max_gap_ms=gap)


def _journey_path(value: object, where: str) -> str:
    if (
        not isinstance(value, str)
        or _JOURNEY_PATH.fullmatch(value) is None
        or value.startswith("/")
        or ".." in value.split("/")
        or not value.endswith(JOURNEY_SUFFIX)
    ):
        _fail(
            where,
            f"journey must be a relative path to a {JOURNEY_SUFFIX} file inside "
            f"the repository, not {value!r}",
        )
    return value


def _comment_from(value: object, where: str) -> str:
    match = _COMMENT_FROM.fullmatch(value) if isinstance(value, str) else None
    if (
        match is None
        or match.group(1).startswith("/")
        or ".." in match.group(1).split("/")
    ):
        _fail(where, f"comment_from must be <relative path>#<anchor>, not {value!r}")
    return value


def _block_id(
    value: object, where: str, label: str, journey_ids: Collection[str] | None
) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        _fail(
            where,
            f"{label} must be a journey block id of lowercase letters, digits and "
            f"hyphens, not {value!r}",
        )
    if journey_ids is not None and value not in journey_ids:
        _fail(where, f"{label} {value!r} is not a journey block id")
    return value


def _hidden_blocks(
    data: dict[str, Any],
    where: str,
    journey_ids: Collection[str] | None,
    block: str | None,
    runs_nothing: bool,
) -> tuple[str, ...]:
    if "hidden_blocks" not in data:
        return ()
    raw = data["hidden_blocks"]
    if not isinstance(raw, list) or not raw:
        _fail(where, "hidden_blocks must be a non-empty list of journey block ids")
    hidden = tuple(
        _block_id(entry, where, "hidden_blocks entry", journey_ids) for entry in raw
    )
    if len(set(hidden)) != len(hidden):
        _fail(where, "hidden_blocks must not repeat an id")
    if block is not None and block in hidden:
        _fail(where, "hidden_blocks must not repeat the scene's own block")
    if runs_nothing:
        _fail(
            where, "a scene that runs nothing (comment_from) cannot have hidden_blocks"
        )
    return hidden


def _parse_scene(
    raw: object,
    index: int,
    source: str,
    journey_ids: Collection[str] | None,
    typing: TypingPolicy,
    start_ms: int,
) -> Scene:
    where = f"{source}: scenes[{index}]"
    data = _mapping(raw, where, _SCENE_KEYS, _SCENE_REQUIRED)
    scene_id = data["id"]
    if not isinstance(scene_id, str) or _ID.fullmatch(scene_id) is None:
        _fail(
            where,
            "the scene id must be lowercase letters, digits and hyphens, starting "
            f"with a letter, not {scene_id!r}",
        )
    where = f"{where} ({scene_id!r})"
    duration = _seconds(data["duration_s"], where, "duration_s", positive=True)
    hold = _seconds(data.get("hold_s", 0), where, "hold_s", positive=False)
    window = None
    if "output_window_s" in data:
        window = _seconds(
            data["output_window_s"], where, "output_window_s", positive=True
        )
    caption = data["caption"]
    problems = caption_problems(caption, duration)
    if problems:
        _fail(where, f"caption {caption!r} {'; '.join(problems)}")
    kinds = [key for key in ("block", "command", "comment_from") if key in data]
    if len(kinds) != 1:
        _fail(where, "needs exactly one of block, command or comment_from")
    block = command = comment_from = None
    if "block" in data:
        block = _block_id(data["block"], where, "block", journey_ids)
    if "command" in data:
        command = data["command"]
        problem = command_problem(command)
        if problem is not None:
            _fail(where, f"command {command!r}: {problem}")
    if "comment_from" in data:
        comment_from = _comment_from(data["comment_from"], where)
        if window is not None:
            _fail(where, "output_window_s has no use in a scene that runs nothing")
    hidden = _hidden_blocks(data, where, journey_ids, block, comment_from is not None)
    clear = data.get("clear", False)
    if not isinstance(clear, bool):
        _fail(where, f"clear must be true or false, not {clear!r}")
    expect = data.get("expect_screen", [])
    if not isinstance(expect, list) or any(
        not isinstance(item, str) or not item or not item.isprintable()
        for item in expect
    ):
        _fail(where, "expect_screen must be a list of non-empty one-line strings")
    # The command is known only for a scene that types its own; a journey block's text
    # is read at record time, so the retimer checks that scene's typing again.
    typed = typing_ms(len(command), typing.chars_per_second) if command else 0
    needed = typing.lead_in_ms + typed + (window or 0) + hold
    if needed > duration:
        _fail(
            where,
            f"is over budget: the lead-in, typing, output window and hold need "
            f"{needed} ms and the scene lasts {duration} ms",
        )
    return Scene(
        scene_id=scene_id,
        caption=caption,
        start_ms=start_ms,
        duration_ms=duration,
        hold_ms=hold,
        block=block,
        hidden_blocks=hidden,
        command=command,
        comment_from=comment_from,
        clear=clear,
        output_window_ms=window,
        expect_screen=tuple(expect),
    )


def parse_storyboard(
    data: object, journey_ids: Collection[str] | None, *, source: str = "storyboard"
) -> Storyboard:
    """Validate parsed storyboard data and return it as a ``Storyboard``.

    ``journey_ids`` are the block ids of the journey the storyboard names; ``block`` and
    ``hidden_blocks`` entries must be among them. Pass None to check only their shape.
    ``source`` names the data in every message. The scene starts are the running sum of
    the scene durations, and the total must be 30 to 60 s.
    """
    top = _mapping(data, source, _TOP_KEYS, _TOP_KEYS)
    schema = top["schema"]
    if not _is_int(schema) or schema != STORYBOARD_SCHEMA:
        _fail(source, f"schema must be {STORYBOARD_SCHEMA}, not {schema!r}")
    journey = _journey_path(top["journey"], f"{source}: journey")
    terminal = _parse_terminal(top["terminal"], source)
    typing = _parse_typing(top["typing"], source)
    output = _parse_output(top["output"], source)
    playback = top["playback"]
    if not isinstance(playback, str) or playback not in PLAYBACK_MODES:
        _fail(
            source,
            f"playback must be one of {list(PLAYBACK_MODES)}, not {playback!r}",
        )
    raw_scenes = top["scenes"]
    if not isinstance(raw_scenes, list) or not raw_scenes:
        _fail(source, "scenes must be a non-empty list")
    scenes: list[Scene] = []
    seen: set[str] = set()
    start = 0
    for index, raw in enumerate(raw_scenes):
        scene = _parse_scene(raw, index, source, journey_ids, typing, start)
        if scene.scene_id in seen:
            _fail(
                f"{source}: scenes[{index}]", f"duplicate scene id {scene.scene_id!r}"
            )
        seen.add(scene.scene_id)
        scenes.append(scene)
        start = scene.end_ms
    if not TOTAL_MIN_MS <= start <= TOTAL_MAX_MS:
        _fail(
            source,
            f"the scene durations sum to {start / 1000:g} s; the total must be "
            "30 to 60 s",
        )
    poster = top["poster_scene"]
    if not isinstance(poster, str) or poster not in seen:
        _fail(source, f"poster_scene {poster!r} names no scene")
    return Storyboard(
        journey=journey,
        terminal=terminal,
        typing=typing,
        output=output,
        poster_scene=poster,
        playback=playback,
        scenes=tuple(scenes),
    )


def load_storyboard(
    path: str | Path, journey_ids: Collection[str] | None
) -> Storyboard:
    """Read the storyboard YAML file at ``path`` and validate it.

    PyYAML is imported here and nowhere else in this module.
    """
    import yaml

    source = str(path)
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise StoryboardError(f"{source}: cannot be read: {exc}") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise StoryboardError(f"{source}: not valid YAML: {exc}") from exc
    return parse_storyboard(data, journey_ids, source=source)


# ---------------------------------------------------------------------------
# The retimer
# ---------------------------------------------------------------------------


def _record_int(value: object, where: str, name: str, minimum: int = 0) -> int:
    if not _is_int(value) or value < minimum:
        raise RecordError(
            f"{where}: {name} must be an integer of {minimum} or more, not {value!r}"
        )
    return value


def _record_text(value: object, where: str, name: str) -> str:
    if not isinstance(value, str) or not value or not value.isprintable():
        raise RecordError(
            f"{where}: {name} must be one line of printable text, not {value!r}"
        )
    return value


@dataclasses.dataclass(frozen=True)
class RawChunk:
    """A piece of output as measured: seconds since its process started, and text."""

    offset_s: float
    data: str

    def __post_init__(self) -> None:
        if not _is_number(self.offset_s) or self.offset_s < 0:
            raise RetimeError(
                "a chunk offset must be a number of seconds, 0 or more, "
                f"not {self.offset_s!r}"
            )
        if not isinstance(self.data, str):
            raise RetimeError(
                f"chunk data must be text, not {type(self.data).__name__}"
            )


@dataclasses.dataclass(frozen=True)
class SceneRun:
    """What the recorder measured for a scene: the line it typed, and its output."""

    typed: str
    chunks: tuple[RawChunk, ...] = ()

    def __post_init__(self) -> None:
        if (
            not isinstance(self.typed, str)
            or not self.typed
            or not self.typed.isprintable()
        ):
            raise RetimeError(
                f"the typed text must be one printable line, not {self.typed!r}"
            )
        _set(self, "chunks", tuple(self.chunks))


@dataclasses.dataclass(frozen=True)
class TypingSpan:
    """When a scene's command was typed, and how many characters it had."""

    start_ms: int
    end_ms: int
    chars: int

    def __post_init__(self) -> None:
        _record_int(self.start_ms, "typing span", "start_ms")
        _record_int(self.end_ms, "typing span", "end_ms")
        _record_int(self.chars, "typing span", "chars", minimum=1)
        if self.end_ms < self.start_ms:
            raise RecordError("typing span: end_ms must not be before start_ms")


@dataclasses.dataclass(frozen=True)
class RetimedScene:
    """A scene's events on the storyboard's clock, and where its time went."""

    scene_id: str
    start_ms: int
    end_ms: int
    typing: TypingSpan
    output_start_ms: int
    output_end_ms: int
    hold_ms: int
    events: tuple[CastEvent, ...]


@dataclasses.dataclass(frozen=True)
class RetimedCast:
    """Every scene retimed. ``total_ms`` is the storyboard's total."""

    scenes: tuple[RetimedScene, ...]
    total_ms: int

    @property
    def events(self) -> tuple[CastEvent, ...]:
        return tuple(event for scene in self.scenes for event in scene.events)

    @property
    def final_hold_ms(self) -> int:
        """How long the last scene rests after its last event."""
        return self.scenes[-1].hold_ms


def _event(milliseconds: int, code: str, data: str) -> CastEvent:
    return CastEvent(milliseconds / 1000, code, data)


def _window_ms(
    scene: Scene, lead_in_ms: int, typed_ms: int, *, has_output: bool
) -> int:
    """The time a scene gives its output; a RetimeError when it has none to give.

    With no ``output_window_s`` the window is what the lead-in, the typing and the
    hold leave of the scene. With one, the four must fit the scene.
    """
    fixed = lead_in_ms + typed_ms + scene.hold_ms
    if scene.output_window_ms is None:
        window = scene.duration_ms - fixed
        used = fixed
    else:
        window = scene.output_window_ms
        used = fixed + window
    if used > scene.duration_ms:
        raise RetimeError(
            f"scene {scene.scene_id!r} is over budget: its lead-in, typing, output "
            f"window and hold need {used} ms and it lasts {scene.duration_ms} ms"
        )
    if has_output and window <= 0:
        raise RetimeError(
            f"scene {scene.scene_id!r} is over budget: it has output and no time "
            "left to show it"
        )
    return window


def _retimed_offsets(
    scene_id: str, chunks: Sequence[RawChunk], max_gap_ms: int, window_ms: int
) -> list[int]:
    """Milliseconds after the end of typing at which each chunk is shown.

    Each pause between chunks (the first measured from the start of the process) is cut
    to ``max_gap_ms``. A run that is then longer than ``window_ms`` is scaled down to
    it; a shorter run keeps its own offsets, so nothing is ever stretched.
    """
    if not chunks:
        return []
    cap = max_gap_ms / 1000
    previous = 0.0
    capped = 0.0
    cumulative: list[float] = []
    for index, chunk in enumerate(chunks):
        if chunk.offset_s < previous:
            raise RetimeError(
                f"scene {scene_id!r}: chunk {index} is earlier than the chunk before it"
            )
        capped += min(chunk.offset_s - previous, cap)
        cumulative.append(capped)
        previous = chunk.offset_s
    window = window_ms / 1000
    scale = 1.0 if capped <= window else window / capped
    return [round(value * scale * 1000) for value in cumulative]


def retime_scene(storyboard: Storyboard, scene: Scene, run: SceneRun) -> RetimedScene:
    """Rewrite one scene's measured output onto the scene's own clock.

    The scene starts with its marker (the caption), an optional clear and the prompt.
    The command is typed at the storyboard's rate after the lead-in, and the output
    follows it, retimed by ``_retimed_offsets``. The rest of the scene is the hold.
    """
    policy = storyboard.typing
    typed_ms = typing_ms(len(run.typed), policy.chars_per_second)
    window = _window_ms(scene, policy.lead_in_ms, typed_ms, has_output=bool(run.chunks))
    start = scene.start_ms
    events = [_event(start, "m", scene.caption)]
    if scene.clear:
        events.append(_event(start, "o", CLEAR_SCREEN))
    events.append(_event(start, "o", storyboard.terminal.prompt))
    typing_start = start + policy.lead_in_ms
    events.extend(
        _event(typing_start + typing_ms(index, policy.chars_per_second), "o", char)
        for index, char in enumerate(run.typed)
    )
    typing_end = typing_start + typed_ms
    offsets = _retimed_offsets(
        scene.scene_id, run.chunks, storyboard.output.max_gap_ms, window
    )
    events.extend(
        [
            _event(typing_end, "o", "\r\n"),
            *(
                _event(typing_end + offset, "o", chunk.data)
                for chunk, offset in zip(run.chunks, offsets, strict=True)
            ),
        ]
    )
    output_end = typing_end + (offsets[-1] if offsets else 0)
    return RetimedScene(
        scene_id=scene.scene_id,
        start_ms=start,
        end_ms=scene.end_ms,
        typing=TypingSpan(typing_start, typing_end, len(run.typed)),
        output_start_ms=typing_end,
        output_end_ms=output_end,
        hold_ms=scene.end_ms - output_end,
        events=tuple(events),
    )


def retime(storyboard: Storyboard, runs: Mapping[str, SceneRun]) -> RetimedCast:
    """Retime every scene of ``storyboard`` from its run in ``runs``.

    The result is as long as the storyboard whatever the runs measured: each scene
    starts and ends where the storyboard says. A scene without a run, or a run for a
    scene the storyboard does not have, is refused.
    """
    ids = [scene.scene_id for scene in storyboard.scenes]
    for scene_id in ids:
        if scene_id not in runs:
            raise RetimeError(f"no run for scene {scene_id!r}")
    for scene_id in sorted(runs):
        if scene_id not in ids:
            raise RetimeError(f"runs for unknown scene {scene_id!r}")
    scenes = tuple(
        retime_scene(storyboard, scene, runs[scene.scene_id])
        for scene in storyboard.scenes
    )
    return RetimedCast(scenes=scenes, total_ms=storyboard.total_ms)


def build_cast(
    storyboard: Storyboard, retimed: RetimedCast, theme: CastTheme | None = None
) -> Cast:
    """The asciicast for a retimed storyboard: its size, its length and its events."""
    header = CastHeader(
        width=storyboard.terminal.cols,
        height=storyboard.terminal.rows,
        duration=retimed.total_ms / 1000,
        theme=theme,
    )
    return Cast(header=header, events=retimed.events)


# ---------------------------------------------------------------------------
# The scrub scan
# ---------------------------------------------------------------------------

#: How a forbidden token is matched: anywhere in the text; as a whole path component
#: (a name between slashes, so a dictionary word such as ``runner`` does not match
#: prose); or as a whole word.
MATCH_MODES = ("substring", "path-component", "word")

_SGR = re.compile(r"\x1b\[[0-9;:]*m")


@dataclasses.dataclass(frozen=True)
class ForbiddenToken:
    """Text that must not appear in a recording, named by its ``kind``.

    A hit reports the kind and never the value, so a report can be read and shared
    without repeating what it was looking for.
    """

    kind: str
    value: str
    match: str = "substring"

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or not self.kind:
            raise CastError("a forbidden token needs a kind")
        if not isinstance(self.value, str) or not self.value:
            raise CastError(f"forbidden token {self.kind!r} needs a value")
        if self.match not in MATCH_MODES:
            raise CastError(
                f"forbidden token {self.kind!r}: match must be one of "
                f"{list(MATCH_MODES)}"
            )
        if self.match != "substring" and "/" in self.value:
            raise CastError(
                f"forbidden token {self.kind!r}: a {self.match} value holds no slash"
            )

    def pattern(self) -> re.Pattern[str]:
        escaped = re.escape(self.value)
        if self.match == "word":
            return re.compile(rf"(?<![A-Za-z0-9_]){escaped}(?![A-Za-z0-9_])")
        if self.match == "path-component":
            return re.compile(
                rf"(?<=/){escaped}(?![A-Za-z0-9_@+-])(?!\.[A-Za-z0-9_@+-])"
            )
        return re.compile(escaped)


@dataclasses.dataclass(frozen=True)
class ForbiddenHit:
    """A forbidden token found: its kind, where, and in which view of the text."""

    kind: str
    where: str
    #: ``raw`` is the text as recorded; ``plain`` is the text with SGR color runs
    #: removed, which finds a token that color changes split.
    view: str

    def __str__(self) -> str:
        return f"{self.where}: forbidden {self.kind} token ({self.view} text)"


class ForbiddenTokenError(CastError):
    """The scrub scan found forbidden tokens; the message names kinds and places only."""

    def __init__(self, hits: Sequence[ForbiddenHit]) -> None:
        self.hits = tuple(hits)
        listed = "; ".join(str(hit) for hit in self.hits[:10])
        more = f"; and {len(self.hits) - 10} more" if len(self.hits) > 10 else ""
        super().__init__(f"{len(self.hits)} forbidden token hit(s): {listed}{more}")


def strip_sgr(text: str) -> str:
    """``text`` without its SGR (color and style) sequences; other sequences stay."""
    return _SGR.sub("", text)


def _scan(
    text: str,
    compiled: Sequence[tuple[ForbiddenToken, re.Pattern[str]]],
    where: str,
    skip: Collection[str] = (),
) -> list[ForbiddenHit]:
    """Hits in ``text`` for the tokens whose kind is not in ``skip``, one per kind."""
    hits: list[ForbiddenHit] = []
    seen = set(skip)
    plain = strip_sgr(text)
    views = [("raw", text)]
    if plain != text:
        views.append(("plain", plain))
    for view, body in views:
        for token, pattern in compiled:
            if token.kind not in seen and pattern.search(body):
                seen.add(token.kind)
                hits.append(ForbiddenHit(token.kind, where, view))
    return hits


def scan_text(
    text: str, tokens: Iterable[ForbiddenToken], where: str = "text"
) -> list[ForbiddenHit]:
    """The forbidden tokens in ``text``, one hit per kind.

    The text is read as recorded and, when it holds color sequences, again with them
    removed, so a path that color changes split into pieces is still found.
    """
    return _scan(text, [(token, token.pattern()) for token in tokens], where)


def scan_cast(cast: Cast, tokens: Iterable[ForbiddenToken]) -> list[ForbiddenHit]:
    """The forbidden tokens in a cast's header and events.

    The header's command, title and environment are read, then each event, then the
    output events joined into one stream, which finds a token that two events split.
    The stream reports only kinds the events did not already show.
    """
    compiled = [(token, token.pattern()) for token in tokens]
    header = cast.header
    hits: list[ForbiddenHit] = []
    if header.command is not None:
        hits += _scan(header.command, compiled, "header command")
    if header.title is not None:
        hits += _scan(header.title, compiled, "header title")
    if header.env is not None:
        for name, value in header.env.items():
            hits += _scan(f"{name}={value}", compiled, "header env")
    shown_in_events: set[str] = set()
    for index, event in enumerate(cast.events):
        found = _scan(event.data, compiled, f"event {index}")
        shown_in_events.update(hit.kind for hit in found)
        hits += found
    stream = "".join(event.data for event in cast.events if event.code == "o")
    hits += _scan(stream, compiled, "output stream", skip=shown_in_events)
    return hits


def require_clean(hits: Sequence[ForbiddenHit]) -> None:
    """Raise ``ForbiddenTokenError`` when the scan found anything."""
    if hits:
        raise ForbiddenTokenError(hits)


# ---------------------------------------------------------------------------
# The run record
# ---------------------------------------------------------------------------

RECORD_SCHEMA = 1

_RECORD_KEYS = frozenset(
    {"schema", "ash_version", "scanners", "findings", "reports", "scenes"}
)
_SCANNER_KEYS = frozenset(
    {
        "name",
        "status",
        "suppressed",
        "critical",
        "high",
        "medium",
        "low",
        "info",
        "actionable",
    }
)
_FINDING_KEYS = frozenset({"rule_id", "severity", "scanner", "location"})
_SCENE_RECORD_KEYS = frozenset(
    {"scene_id", "command", "exit_code", "end_screen", "typing"}
)
_TYPING_SPAN_KEYS = frozenset({"start_ms", "end_ms", "chars"})
_COUNT_FIELDS = (
    "suppressed",
    "critical",
    "high",
    "medium",
    "low",
    "info",
    "actionable",
)


@dataclasses.dataclass(frozen=True, kw_only=True)
class ScannerRecord:
    """One scanner's row of the summary table, as the recorded run printed it."""

    name: str
    status: str
    suppressed: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    actionable: int

    def __post_init__(self) -> None:
        where = "scanner record"
        _record_text(self.name, where, "name")
        _record_text(self.status, where, "status")
        for field in _COUNT_FIELDS:
            _record_int(getattr(self, field), where, field)


@dataclasses.dataclass(frozen=True, kw_only=True)
class FindingRecord:
    """One finding of the report the recorded run printed."""

    rule_id: str
    severity: str
    scanner: str
    location: str

    def __post_init__(self) -> None:
        for field in ("rule_id", "severity", "scanner", "location"):
            _record_text(getattr(self, field), "finding record", field)


@dataclasses.dataclass(frozen=True, kw_only=True)
class SceneRecord:
    """What one scene ran and showed: its command, exit code and end screen.

    ``exit_code`` is None for a scene that runs nothing (the install comment).
    """

    scene_id: str
    command: str
    exit_code: int | None
    end_screen: tuple[str, ...]
    typing: TypingSpan

    def __post_init__(self) -> None:
        where = "scene record"
        _record_text(self.scene_id, where, "scene_id")
        _record_text(self.command, where, "command")
        if self.exit_code is not None and not _is_int(self.exit_code):
            raise RecordError(
                f"{where}: exit_code must be an integer or null, not {self.exit_code!r}"
            )
        screen = self.end_screen
        if isinstance(screen, str) or not isinstance(screen, (list, tuple)):
            raise RecordError(f"{where}: end_screen must be a list of lines")
        for line in screen:
            if not isinstance(line, str) or "\n" in line or "\r" in line:
                raise RecordError(
                    f"{where}: end_screen must be a list of one-line strings, "
                    f"not {line!r}"
                )
        _set(self, "end_screen", tuple(screen))
        if not isinstance(self.typing, TypingSpan):
            raise RecordError(f"{where}: typing must be a typing span")


def _unique(values: Iterable[str], label: str) -> None:
    seen: set[str] = set()
    for value in values:
        if value in seen:
            raise RecordError(f"duplicate {label} {value!r}")
        seen.add(value)


def _record_sequence(
    value: object, where: str, name: str, kind: type
) -> tuple[Any, ...]:
    if isinstance(value, str) or not isinstance(value, (list, tuple)):
        raise RecordError(f"{where}: {name} must be a list")
    for item in value:
        if not isinstance(item, kind):
            raise RecordError(
                f"{where}: every entry of {name} must be a {kind.__name__}"
            )
    return tuple(value)


@dataclasses.dataclass(frozen=True, kw_only=True)
class RunRecord:
    """What a recording run observed, in canonical order.

    Scanners are sorted by name, findings by rule, scanner and location, and report
    files by name, so a record is the same whatever order the run met them in. Scenes
    keep the storyboard's order.
    """

    ash_version: str
    scanners: tuple[ScannerRecord, ...]
    findings: tuple[FindingRecord, ...]
    reports: tuple[str, ...]
    scenes: tuple[SceneRecord, ...]
    schema: int = RECORD_SCHEMA

    def __post_init__(self) -> None:
        where = "record"
        if not _is_int(self.schema) or self.schema != RECORD_SCHEMA:
            raise RecordError(
                f"{where}: schema must be {RECORD_SCHEMA}, not {self.schema!r}"
            )
        _record_text(self.ash_version, where, "ash_version")
        scanners = _record_sequence(self.scanners, where, "scanners", ScannerRecord)
        findings = _record_sequence(self.findings, where, "findings", FindingRecord)
        reports = _record_sequence(self.reports, where, "reports", str)
        scenes = _record_sequence(self.scenes, where, "scenes", SceneRecord)
        for report in reports:
            _record_text(report, where, "reports entry")
        _unique((scanner.name for scanner in scanners), "scanner")
        _unique(reports, "report")
        _unique((scene.scene_id for scene in scenes), "scene id")
        _set(self, "scanners", tuple(sorted(scanners, key=operator.attrgetter("name"))))
        _set(
            self,
            "findings",
            tuple(
                sorted(
                    findings,
                    key=operator.attrgetter(
                        "rule_id", "scanner", "location", "severity"
                    ),
                )
            ),
        )
        _set(self, "reports", tuple(sorted(reports)))
        _set(self, "scenes", scenes)


def canonical_json(value: object) -> str:
    """``value`` as the JSON this repository's files are written in: sorted keys,
    indent 2, ASCII escapes and one newline at the end. It is the form the
    ``pretty-format-json`` pre-commit hook writes, so the hook never changes it."""
    try:
        return json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n"
    except (TypeError, ValueError) as exc:
        raise CastError(f"cannot be written as JSON: {exc}") from exc


def record_to_obj(record: RunRecord) -> dict[str, Any]:
    """The record as plain dictionaries and lists."""
    return dataclasses.asdict(record)


def record_to_json(record: RunRecord) -> str:
    """The record's canonical JSON text."""
    return canonical_json(record_to_obj(record))


def _record_mapping(value: object, where: str, keys: frozenset[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RecordError(f"{where}: must be a mapping")
    extra = sorted(str(key) for key in set(value) - keys)
    if extra:
        raise RecordError(
            f"{where}: unknown key(s) {extra}; the record allows {sorted(keys)}"
        )
    missing = sorted(keys - set(value))
    if missing:
        raise RecordError(f"{where}: missing key(s) {missing}")
    return value


def _record_list(value: object, where: str, name: str) -> Sequence[object]:
    if isinstance(value, str) or not isinstance(value, (list, tuple)):
        raise RecordError(f"{where}: {name} must be a list")
    return value


def _build(where: str, make: Any, *args: Any, **kwargs: Any) -> Any:
    """``make(*args, **kwargs)``, with a RecordError's message led by ``where``."""
    try:
        return make(*args, **kwargs)
    except RecordError as exc:
        raise RecordError(f"{where}: {exc}") from exc


def record_from_obj(obj: object) -> RunRecord:
    """A ``RunRecord`` from parsed JSON; unknown or missing keys are refused."""
    data = _record_mapping(obj, "record", _RECORD_KEYS)
    scanners = []
    for index, item in enumerate(_record_list(data["scanners"], "record", "scanners")):
        where = f"scanners[{index}]"
        fields = _record_mapping(item, where, _SCANNER_KEYS)
        scanners.append(_build(where, ScannerRecord, **fields))
    findings = []
    for index, item in enumerate(_record_list(data["findings"], "record", "findings")):
        where = f"findings[{index}]"
        fields = _record_mapping(item, where, _FINDING_KEYS)
        findings.append(_build(where, FindingRecord, **fields))
    scenes = []
    for index, item in enumerate(_record_list(data["scenes"], "record", "scenes")):
        where = f"scenes[{index}]"
        fields = _record_mapping(item, where, _SCENE_RECORD_KEYS)
        span = _record_mapping(fields["typing"], f"{where}.typing", _TYPING_SPAN_KEYS)
        fields = {**fields, "typing": _build(f"{where}.typing", TypingSpan, **span)}
        scenes.append(_build(where, SceneRecord, **fields))
    return RunRecord(
        schema=data["schema"],
        ash_version=data["ash_version"],
        scanners=tuple(scanners),
        findings=tuple(findings),
        reports=_record_list(data["reports"], "record", "reports"),
        scenes=tuple(scenes),
    )


def record_from_json(text: str) -> RunRecord:
    """A ``RunRecord`` from its JSON text."""
    try:
        obj = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RecordError(f"record: not valid JSON: {exc.msg}") from exc
    return record_from_obj(obj)


def write_record(path: str | Path, record: RunRecord) -> None:
    """Write the record's canonical JSON to ``path`` with Unix newlines."""
    Path(path).write_text(record_to_json(record), encoding="utf-8", newline="\n")


def read_record(path: str | Path) -> RunRecord:
    """Read the record at ``path``."""
    return record_from_json(Path(path).read_text(encoding="utf-8"))
