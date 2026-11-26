# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Recorded tool transcripts: the fixture format and the freshness rule.

A scanner's recorded fixture is a versioned :class:`ToolTranscript`: the argv as
executed, the environment allowlist applied, the exit code, the results-file bytes
(plus the side reports a tool writes beside them), a stderr tail, the tool's version,
and the identity of the fixture tree the tool ran over. It is STAMPED with the tool
pin the plugin declared when it was recorded (:class:`PinStamp`).

The stamp is what turns fixture rot into a red test. The pin lives in the repository
(the plugin manifest's provisioning block) and the stamp lives in the fixture, so a
pin bump leaves every transcript that was recorded at the old pin disagreeing with the
manifest, and :func:`stale_transcripts` names each one. There is no waiver list: a
fixture that is meant to record an older version (a shape ASH still has to read, such
as the previous release's SARIF) says so in the transcript itself with
``retention: historical`` and a reason, which is reviewed with the fixture.

Results bytes stay in the committed files beside the transcript file
(``transcripts.json``); the transcript names each by path and SHA-256, so the bytes
remain diffable and the transcript is a small reviewable index. :func:`verify_digests`
refuses a transcript whose bytes moved.

``provenance`` says how much the transcript knows. ``captured`` means the recording
run's argv and exit code are known (the model requires both). ``attested`` means loose
output files were upgraded into this format and only what the committed files and their
documentation say is recorded: the argv, the exit code and the stderr tail are whatever
that documentation gave, and ``None`` where it gave nothing; the model does not check an
attested transcript's argv against anything, so a reviewer reads it. A re-record replaces
an attested transcript with a captured one.

This module imports only the standard library and pydantic, so a consumer can read a
transcript without loading any plugin.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import date
from pathlib import Path
from typing import Any, Iterable, Literal, Mapping, Optional

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

#: The transcript file schema this code reads and writes.
TRANSCRIPT_SCHEMA_VERSION = 1

#: The file a fixture directory keeps its transcripts in.
TRANSCRIPT_FILE_NAME = "transcripts.json"

_ID = re.compile(r"[a-z0-9][a-z0-9._-]*")
_SHA256 = re.compile(r"[0-9a-f]{64}")
#: ASCII digits only: ``\d`` would admit any Unicode digit, and the calendar check
#: behind the shape (``date.fromisoformat``) is what refuses 2026-13-45.
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


def is_sha256(value: object) -> bool:
    """Whether *value* is a SHA-256 digest as this format spells one: 64 lower-case hex."""
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


ResultFormat = Literal["sarif", "json", "text", "csv"]
Provenance = Literal["captured", "attested"]
Retention = Literal["current", "historical"]


class TranscriptSchemaError(ValueError):
    """A transcript file this code refuses to read, with the reason as prose."""


class TranscriptRestampError(ValueError):
    """A restamp this code refuses, with the reason as prose."""


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)


def _relative_posix(value: str) -> str:
    """*value* as a normalized relative posix path: no empty, ``.`` or ``..`` segment.

    ``./out.sarif`` and ``out.sarif`` name one file, and ``.`` names the transcript
    file's own directory (whose digest could never match, since ``transcripts.json``
    holds it), so neither spelling is accepted.
    """
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or any(segment in ("", ".", "..") for segment in value.split("/"))
    ):
        raise ValueError(
            f"{value!r} is not a relative posix path without empty, '.' or '..' segments"
        )
    return value


class ToolRef(_Frozen):
    """The tool the transcript was recorded with, spelled as the tool prints it."""

    name: str
    version: str


class PinStamp(_Frozen):
    """The tool pin the plugin declared when the transcript was recorded.

    ``tool`` is the key of the pin (``ToolPin.tool``), ``version`` the pin's release
    tag as the manifest spells it.
    """

    tool: str
    version: str


class ResultsFile(_Frozen):
    """One output file of the recorded run, by path (relative to the transcript
    file's directory) and SHA-256."""

    path: str
    sha256: str
    format: ResultFormat

    @field_validator("path")
    @classmethod
    def _path(cls, value: str) -> str:
        return _relative_posix(value)

    @field_validator("sha256")
    @classmethod
    def _sha(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("sha256 is 64 lower-case hex digits")
        return value


class FixtureTree(_Frozen):
    """The input the tool ran over: paths (relative to the transcript file's
    directory) and the digest of every file under them."""

    paths: tuple[str, ...]
    sha256: str

    @field_validator("paths")
    @classmethod
    def _paths(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if not values:
            raise ValueError("a fixture tree names at least one path")
        for value in values:
            _relative_posix(value)
        return values

    @field_validator("sha256")
    @classmethod
    def _sha(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("sha256 is 64 lower-case hex digits")
        return value


class ToolTranscript(_Frozen):
    """One recorded run of one scanner's tool, stamped with the pin it was recorded at."""

    id: str
    #: The scanner's manifest name.
    scanner: str
    retention: Retention = "current"
    #: Required for (and only for) a ``historical`` transcript: why ASH keeps a
    #: recording at a version other than the pin.
    reason: Optional[str] = None
    provenance: Provenance
    tool: ToolRef
    #: The pin in force at the recording, or None for a scanner whose manifest
    #: declares no tool pin (a tool installed from a package index or by the user).
    pin_stamp: Optional[PinStamp] = None
    #: The argv as executed; None for an attested transcript whose argv nobody wrote down.
    argv: Optional[tuple[str, ...]] = None
    #: The environment variables the run was allowed to see (names only).
    env_allowlist: tuple[str, ...] = ()
    exit_code: Optional[int] = None
    stderr_tail: Optional[str] = None
    results: tuple[ResultsFile, ...]
    #: Reports a tool writes beside its results file (checkov's JSON next to its SARIF).
    side_reports: tuple[ResultsFile, ...] = ()
    fixture_tree: Optional[FixtureTree] = None
    #: A registered adapter prep (``core.plugin_conformance.PREPS``) that turns the
    #: native bytes into results; None when the results file is SARIF read as written.
    adapter_prep: Optional[str] = None
    #: The scanner's scan-time inputs are not pinned (a vulnerability database, a live
    #: advisory service): the transcript is a dated snapshot and its live cell stays
    #: scheduled whatever paths change.
    live_input: bool = False
    #: ``YYYY-MM-DD`` of the recording, when known.
    recorded_on: Optional[str] = None
    #: Other scanners that run the same tool and are held to this recording too
    #: (the trivy transcripts also serve ``trivy-repo``).
    also_for: tuple[str, ...] = ()
    #: Whether the harness reads this transcript's results as a facet corpus. False
    #: for a recording that was reduced by hand (fields left out), which cannot witness
    #: the facets it dropped; ``note`` then says what was left out.
    observable: bool = True
    #: What a reader of the transcript needs to know that no other field says.
    note: Optional[str] = None

    @property
    def scanners(self) -> tuple[str, ...]:
        """Every scanner this recording is evidence for, ``scanner`` first."""
        return (self.scanner, *self.also_for)

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        if not _ID.fullmatch(value):
            raise ValueError(f"{value!r} is not a transcript id")
        return value

    @field_validator("recorded_on")
    @classmethod
    def _recorded_on(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        if not _DATE.fullmatch(value):
            raise ValueError(f"recorded_on {value!r} is not YYYY-MM-DD")
        try:
            date.fromisoformat(value)
        except ValueError:
            raise ValueError(f"recorded_on {value!r} is not a calendar date") from None
        return value

    @model_validator(mode="after")
    def _shape(self) -> "ToolTranscript":
        if self.scanner in self.also_for or len(set(self.also_for)) != len(
            self.also_for
        ):
            raise ValueError(
                "also_for names other scanners, each once, and never the transcript's "
                "own scanner"
            )
        if (self.retention == "historical") != bool(
            self.reason and self.reason.strip()
        ):
            raise ValueError(
                "a historical transcript states why it is kept at another version "
                "(reason), and only a historical one does"
            )
        if not self.results:
            raise ValueError("a transcript records at least one results file")
        if self.provenance == "captured" and (
            self.argv is None or self.exit_code is None
        ):
            raise ValueError("a captured transcript records its argv and exit code")
        if self.argv is not None and not self.argv:
            raise ValueError(
                "argv, when recorded, names at least the executable (argv[0]); an "
                "attested run whose argv nobody wrote down records null, never []"
            )
        paths = [r.path for r in (*self.results, *self.side_reports)]
        if len(set(paths)) != len(paths):
            raise ValueError("a transcript lists a results path twice")
        return self


class Unrecorded(_Frozen):
    """A scanner whose fixture directory holds no recorded tool output yet."""

    scanner: str
    #: What a maintainer records to close the row (the input exists; the output does not).
    reason: str

    @field_validator("reason")
    @classmethod
    def _reason(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("an unrecorded row says what is missing")
        return value


class TranscriptFile(_Frozen):
    """The contents of one ``transcripts.json``."""

    schema_version: int
    transcripts: tuple[ToolTranscript, ...] = ()
    unrecorded: tuple[Unrecorded, ...] = ()

    @model_validator(mode="after")
    def _shape(self) -> "TranscriptFile":
        if self.schema_version != TRANSCRIPT_SCHEMA_VERSION:
            raise ValueError(
                f"schema_version {self.schema_version} is not the version this "
                f"ASH reads ({TRANSCRIPT_SCHEMA_VERSION})"
            )
        ids = [t.id for t in self.transcripts]
        if len(set(ids)) != len(ids):
            raise ValueError("a transcript id is used twice in one file")
        recorded = {s for t in self.transcripts for s in t.scanners}
        both = recorded & {u.scanner for u in self.unrecorded}
        if both:
            raise ValueError(
                f"{sorted(both)} is both recorded and listed as unrecorded in one file"
            )
        return self


def parse_transcript_file(data: Mapping[str, Any]) -> TranscriptFile:
    """Validate a transcript file read from data; a newer schema is refused in prose."""
    if not isinstance(data, Mapping):
        raise TranscriptSchemaError(
            f"a transcript file is a JSON object, not {type(data).__name__}"
        )
    declared = data.get("schema_version")
    if isinstance(declared, str) and declared.strip().isdecimal():
        declared = int(declared)
    if isinstance(declared, int) and declared > TRANSCRIPT_SCHEMA_VERSION:
        raise TranscriptSchemaError(
            f"this transcript file declares schema_version {declared}, but this ASH "
            f"reads schema_version {TRANSCRIPT_SCHEMA_VERSION}. It was written by a "
            "newer ASH; upgrade ASH to read it."
        )
    return TranscriptFile.model_validate(dict(data))


def load_transcript_file(path: Path) -> TranscriptFile:
    """The transcript file at *path* (a ``transcripts.json``)."""
    return parse_transcript_file(json.loads(path.read_text(encoding="utf-8")))


def dump_transcript_file(transcripts: TranscriptFile) -> str:
    """The canonical text of a transcript file (stable, so a re-record diffs by content)."""
    return (
        json.dumps(
            transcripts.model_dump(mode="json", exclude_none=False),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n"
    )


# ---------------------------------------------------------------------------
# Digests.
# ---------------------------------------------------------------------------


def file_sha256(path: Path) -> str:
    # Committed fixture bytes, not tool log text: read whole.
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _tree_files(base: Path, relative: str) -> list[Path]:
    target = base / relative
    if target.is_dir():
        return sorted(p for p in target.rglob("*") if p.is_file())
    return [target]


def tree_sha256(base: Path, paths: tuple[str, ...]) -> str:
    """One digest over every file under *paths* (relative to *base*): the sorted
    ``relative path NUL file digest`` lines, so a moved, renamed, added or edited
    file changes it."""
    lines: list[str] = []
    for relative in paths:
        for file in _tree_files(base, relative):
            lines.append(f"{file.relative_to(base).as_posix()}\0{file_sha256(file)}")
    return hashlib.sha256("\n".join(sorted(lines)).encode("utf-8")).hexdigest()


def verify_digests(transcript: ToolTranscript, base: Path) -> list[str]:
    """What is wrong with the bytes a transcript names, as sentences (empty when sound).

    *base* is the directory holding the transcript file.
    """
    problems: list[str] = []
    for entry in (*transcript.results, *transcript.side_reports):
        file = base / entry.path
        if not file.is_file():
            problems.append(f"{transcript.id}: {entry.path} is not a file")
        elif file_sha256(file) != entry.sha256:
            problems.append(
                f"{transcript.id}: {entry.path} no longer matches the digest the "
                "transcript recorded; re-record the transcript or restore the file"
            )
    tree = transcript.fixture_tree
    if tree is not None:
        missing = [p for p in tree.paths if not (base / p).exists()]
        if missing:
            problems.append(
                f"{transcript.id}: fixture tree path {missing[0]} is missing"
            )
        elif tree_sha256(base, tree.paths) != tree.sha256:
            problems.append(
                f"{transcript.id}: the fixture tree under {', '.join(tree.paths)} "
                "no longer matches the digest the transcript recorded"
            )
    return problems


# ---------------------------------------------------------------------------
# The freshness rule.
# ---------------------------------------------------------------------------


def same_release(left: str, right: str) -> bool:
    """Two release tags name one release, ignoring upstream's leading ``v``."""
    return left.strip().lstrip("v") == right.strip().lstrip("v")


def stale_transcripts(
    transcripts: Iterable[ToolTranscript],
    current_pins: Mapping[str, str],
    pinned_scanners: Optional[Mapping[str, str]] = None,
) -> list[str]:
    """Each way a transcript disagrees with the pins in force, as a sentence.

    *current_pins* is ``{pin tool key: release}`` (``plugin_provisioning.tool_versions()``).
    A ``current`` transcript carrying a stamp must carry the pin in force, so a pin bump
    turns it red until it is re-recorded; a ``historical`` one must carry a different
    version (otherwise it is current and says so). A stamp naming a tool that has no
    pin anymore is refused too.

    *pinned_scanners* is ``{scanner name: pin tool key}`` for every scanner whose manifest
    pins its tool. A ``current`` transcript of such a scanner with no stamp is refused:
    an unstamped recording could never go stale, which is the failure the stamp exists to
    prevent. (A scanner with no pin has nothing to stamp and nothing to go stale against.)
    An unstamped ``historical`` transcript of such a scanner is held to the one fact it
    has: its recorded tool version must differ from the pin in force. A stamped
    transcript of such a scanner must carry the stamp of THAT scanner's own pin.
    """
    problems: list[str] = []
    pinned_by_scanner = pinned_scanners or {}
    for transcript in transcripts:
        stamp = transcript.pin_stamp
        owned = [s for s in transcript.scanners if s in pinned_by_scanner]
        if stamp is None:
            if owned and transcript.retention == "current":
                problems.append(
                    f"{transcript.id}: {owned[0]} pins its tool "
                    f"({pinned_by_scanner[owned[0]]}) but this current transcript carries "
                    "no stamp; stamp it with the pin it was recorded at, or mark it "
                    "historical if the version it recorded is not the pin"
                )
            elif owned and transcript.retention == "historical":
                # Unstamped, so the recorded tool version is the only evidence there
                # is: a "historical" recording of the release in force is a current one.
                in_force = current_pins.get(pinned_by_scanner[owned[0]])
                if in_force is not None and same_release(
                    transcript.tool.version, in_force
                ):
                    problems.append(
                        f"{transcript.id}: marked historical but the tool version it "
                        f"records ({transcript.tool.version}) is the pin in force "
                        f"({in_force}); it is a current transcript"
                    )
            continue
        for scanner in owned:
            if stamp.tool != pinned_by_scanner[scanner]:
                problems.append(
                    f"{transcript.id}: stamped with the pin of {stamp.tool!r} but "
                    f"{scanner} pins {pinned_by_scanner[scanner]!r}; a recording "
                    "copied from another tool's fixture never goes stale on this "
                    "tool's pin bump, so re-record it for this scanner"
                )
        pinned = current_pins.get(stamp.tool)
        if pinned is None:
            problems.append(
                f"{transcript.id}: stamped with the pin of {stamp.tool!r}, which "
                "no manifest pins now; re-record it or drop the stamp with the pin"
            )
        elif transcript.retention == "current" and not same_release(
            stamp.version, pinned
        ):
            problems.append(
                f"{transcript.id}: recorded at {stamp.tool} {stamp.version} but the "
                f"manifest pins {pinned}; re-record the transcript (or, if the old "
                "recording is kept on purpose, mark it historical with the reason)"
            )
        elif transcript.retention == "historical" and same_release(
            stamp.version, pinned
        ):
            problems.append(
                f"{transcript.id}: marked historical but stamped with the pin in "
                f"force ({pinned}); it is a current transcript"
            )
        if not same_release(transcript.tool.version, stamp.version) and (
            transcript.retention == "current"
        ):
            problems.append(
                f"{transcript.id}: the tool version it records ({transcript.tool.version}) "
                f"is not the version it is stamped with ({stamp.version})"
            )
    return problems


def restamp(
    transcript: ToolTranscript,
    current_pins: Mapping[str, str],
    *,
    observed_version: str,
    results: tuple[ResultsFile, ...],
    side_reports: Optional[tuple[ResultsFile, ...]] = None,
    argv: tuple[str, ...],
    exit_code: int,
    stderr_tail: Optional[str] = None,
    recorded_on: Optional[str] = None,
    env_allowlist: tuple[str, ...] = (),
) -> ToolTranscript:
    """The final step of a re-record: *transcript* carrying the new run's results,
    the new run's record, the version the run reported, and the stamp of the pin now
    in force.

    The re-record path calls this AFTER it has run the tool and replaced the results
    bytes, passing what it recorded: *observed_version* is the version string the tool
    printed (it goes into ``tool.version`` as printed, not as the manifest spells the
    pin, so :func:`stale_transcripts` can still catch a run of the wrong binary),
    *results* are the new files' digests, and *argv*, *exit_code*, *stderr_tail*,
    *recorded_on* and *env_allowlist* are the new run's own record. They replace the
    old run's wholesale and the transcript comes back ``captured``: a re-record
    replaces an attested transcript with a captured one, and the old run's argv or
    date kept on new bytes would attest to a run that never produced them. The
    replacement really is wholesale: *side_reports* of None means the new run wrote
    none (the old entries never survive it), and ``observable``/``note`` come back
    True and None, because the new run's results are full, never the hand-reduced
    recording the old flags may have described.

    Digests identical to the transcript's own AND an unchanged tool version mean
    nothing shows a re-record happened, and the call is refused: a record (and, where
    one exists, a stamp) moved onto old bytes would hide exactly the rot the stamp
    exists to expose. Identical bytes under a NEW version are accepted, because a tool
    whose output carries no version (actionlint's JSON, cdk-nag's CSV, guarddog's
    JSON) reproduces them on a real re-record. A transcript with no stamp still gets
    the new run's record the same way; only the stamp fields have nothing to move
    (an unpinned scanner's re-record is still a new run).
    """
    stamp = transcript.pin_stamp
    pinned = None
    if stamp is not None:
        pinned = current_pins.get(stamp.tool)
        if pinned is None:
            raise TranscriptRestampError(
                f"{transcript.id}: stamped with the pin of {stamp.tool!r}, which no "
                "manifest pins now; there is no pin to restamp it with. Drop the stamp "
                "with the pin, or re-record under a pin that exists"
            )

    def _digests(entries: tuple[ResultsFile, ...]) -> set[tuple[str, str]]:
        return {(entry.path, entry.sha256) for entry in entries}

    if (
        observed_version == transcript.tool.version
        and _digests(results) == _digests(transcript.results)
        and _digests(side_reports or ()) == _digests(transcript.side_reports)
    ):
        raise TranscriptRestampError(
            f"{transcript.id}: the results digests and the tool version are the ones "
            "it already records, so nothing was re-recorded; restamp is the last step "
            "of a re-record that replaced the bytes"
        )
    data = transcript.model_dump()
    data.update(
        tool={"name": transcript.tool.name, "version": observed_version},
        retention="current",
        reason=None,
        results=[entry.model_dump() for entry in results],
        side_reports=[entry.model_dump() for entry in (side_reports or ())],
        provenance="captured",
        argv=list(argv),
        exit_code=exit_code,
        stderr_tail=stderr_tail,
        recorded_on=recorded_on,
        env_allowlist=list(env_allowlist),
        observable=True,
        note=None,
    )
    if stamp is not None:
        data["pin_stamp"] = {"tool": stamp.tool, "version": pinned}
    return ToolTranscript.model_validate(data)
