"""Interface of the terminal recording core library.

Every function raises NotImplementedError and no dataclass validates anything yet; the
tests in tests/unit/docs/test_cast_core.py fail against this file until the library is
written.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Collection, Iterable, Mapping, Sequence
from pathlib import Path

CAST_VERSION = 2
EVENT_CODES = ("o", "i", "m", "r")
CLEAR_SCREEN = "\x1b[H\x1b[2J"
MATCH_MODES = ("substring", "path-component", "word")
STORYBOARD_SCHEMA = 1
RECORD_SCHEMA = 1


class CastError(ValueError):
    """Every refusal this module makes."""


class CastFileError(CastError):
    """An asciicast file or one of its parts is refused."""


class StoryboardError(CastError):
    """A storyboard is refused."""


class RetimeError(CastError):
    """A scene cannot be retimed."""


class RecordError(CastError):
    """A run record is refused."""


class ForbiddenTokenError(CastError):
    """The scrub scan found a forbidden token."""

    hits: tuple[ForbiddenHit, ...]


@dataclasses.dataclass(frozen=True)
class CastTheme:
    fg: str
    bg: str
    palette: tuple[str, ...]

    def to_json_obj(self) -> dict[str, str]:
        raise NotImplementedError


@dataclasses.dataclass(frozen=True, kw_only=True)
class CastHeader:
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

    def to_json_obj(self) -> dict[str, object]:
        raise NotImplementedError


@dataclasses.dataclass(frozen=True)
class CastEvent:
    time: float
    code: str
    data: str


@dataclasses.dataclass(frozen=True)
class Cast:
    header: CastHeader
    events: tuple[CastEvent, ...]


def format_time(seconds: float) -> str:
    raise NotImplementedError


def dumps_cast(cast: Cast) -> str:
    raise NotImplementedError


def loads_cast(text: str) -> Cast:
    raise NotImplementedError


def write_cast(path: str | Path, cast: Cast) -> None:
    raise NotImplementedError


def read_cast(path: str | Path) -> Cast:
    raise NotImplementedError


@dataclasses.dataclass(frozen=True)
class Terminal:
    cols: int
    rows: int
    prompt: str


@dataclasses.dataclass(frozen=True)
class TypingPolicy:
    chars_per_second: float
    lead_in_ms: int


@dataclasses.dataclass(frozen=True)
class OutputPolicy:
    max_gap_ms: int


@dataclasses.dataclass(frozen=True)
class Scene:
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
        raise NotImplementedError

    @property
    def words(self) -> int:
        raise NotImplementedError


@dataclasses.dataclass(frozen=True)
class Storyboard:
    journey: str
    terminal: Terminal
    typing: TypingPolicy
    output: OutputPolicy
    poster_scene: str
    playback: str
    scenes: tuple[Scene, ...]

    @property
    def total_ms(self) -> int:
        raise NotImplementedError

    @property
    def total_s(self) -> float:
        raise NotImplementedError

    def scene(self, scene_id: str) -> Scene:
        raise NotImplementedError


def count_words(text: str) -> int:
    raise NotImplementedError


def caption_problems(caption: str, duration_ms: int) -> list[str]:
    raise NotImplementedError


def command_problem(command: str) -> str | None:
    raise NotImplementedError


def typing_ms(chars: int, chars_per_second: float) -> int:
    raise NotImplementedError


def parse_storyboard(
    data: object, journey_ids: Collection[str] | None, *, source: str = "storyboard"
) -> Storyboard:
    raise NotImplementedError


def load_storyboard(
    path: str | Path, journey_ids: Collection[str] | None
) -> Storyboard:
    raise NotImplementedError


@dataclasses.dataclass(frozen=True)
class RawChunk:
    offset_s: float
    data: str


@dataclasses.dataclass(frozen=True)
class SceneRun:
    typed: str
    chunks: tuple[RawChunk, ...] = ()


@dataclasses.dataclass(frozen=True)
class TypingSpan:
    start_ms: int
    end_ms: int
    chars: int


@dataclasses.dataclass(frozen=True)
class RetimedScene:
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
    scenes: tuple[RetimedScene, ...]
    total_ms: int

    @property
    def events(self) -> tuple[CastEvent, ...]:
        raise NotImplementedError

    @property
    def final_hold_ms(self) -> int:
        raise NotImplementedError


def retime_scene(storyboard: Storyboard, scene: Scene, run: SceneRun) -> RetimedScene:
    raise NotImplementedError


def retime(storyboard: Storyboard, runs: Mapping[str, SceneRun]) -> RetimedCast:
    raise NotImplementedError


def build_cast(
    storyboard: Storyboard, retimed: RetimedCast, theme: CastTheme | None = None
) -> Cast:
    raise NotImplementedError


@dataclasses.dataclass(frozen=True)
class ForbiddenToken:
    kind: str
    value: str
    match: str = "substring"


@dataclasses.dataclass(frozen=True)
class ForbiddenHit:
    kind: str
    where: str
    view: str


def strip_sgr(text: str) -> str:
    raise NotImplementedError


def scan_text(
    text: str, tokens: Iterable[ForbiddenToken], where: str = "text"
) -> list[ForbiddenHit]:
    raise NotImplementedError


def scan_cast(cast: Cast, tokens: Iterable[ForbiddenToken]) -> list[ForbiddenHit]:
    raise NotImplementedError


def require_clean(hits: Sequence[ForbiddenHit]) -> None:
    raise NotImplementedError


@dataclasses.dataclass(frozen=True, kw_only=True)
class ScannerRecord:
    name: str
    status: str
    suppressed: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    actionable: int


@dataclasses.dataclass(frozen=True, kw_only=True)
class FindingRecord:
    rule_id: str
    severity: str
    scanner: str
    location: str


@dataclasses.dataclass(frozen=True, kw_only=True)
class SceneRecord:
    scene_id: str
    command: str
    exit_code: int | None
    end_screen: tuple[str, ...]
    typing: TypingSpan


@dataclasses.dataclass(frozen=True, kw_only=True)
class RunRecord:
    ash_version: str
    scanners: tuple[ScannerRecord, ...]
    findings: tuple[FindingRecord, ...]
    reports: tuple[str, ...]
    scenes: tuple[SceneRecord, ...]
    schema: int = RECORD_SCHEMA


def canonical_json(value: object) -> str:
    raise NotImplementedError


def record_to_obj(record: RunRecord) -> dict[str, object]:
    raise NotImplementedError


def record_to_json(record: RunRecord) -> str:
    raise NotImplementedError


def record_from_obj(obj: object) -> RunRecord:
    raise NotImplementedError


def record_from_json(text: str) -> RunRecord:
    raise NotImplementedError


def write_record(path: str | Path, record: RunRecord) -> None:
    raise NotImplementedError


def read_record(path: str | Path) -> RunRecord:
    raise NotImplementedError
