#!/usr/bin/env python3
"""Check that ASH's requirements resolve from wheels on every platform it names.

ASH installs from wheels: no step of its install builds a package from source on
the platforms its install page lists. Whether that stays true depends on what PyPI
publishes, which changes without a commit here, and on what a new requirement drags
in. This script measures it.

For each platform (Linux x86_64 and aarch64 on glibc and on musl, macOS arm64 and
x86_64, Windows x86_64 and arm64) and each Python minor version in
``requires-python``, it runs ``uv pip compile --no-build`` over a set of requirements
and keeps the outcome of that cell:

    ok           resolves, with the versions the first resolving platform got
    backtracked  resolves, but a package settled on an older version than on that
                 platform, which is what uv does when the newest release has no wheel
    fail         does not resolve

The sets are ``core`` (``[project] dependencies``), ``core+<extra>`` for each extra in
``pyproject.toml``, and, read from the plugin register rather than from pyproject,
``core+alpha`` with one ``core+alpha:<distribution>`` row per alpha pin: every member
of the alpha extra and every pin held only for a maintainer's decision, so the day a
held pin becomes a member changes no requirement and so no cell. A pin excluded for a
measured reason is not a candidate and is not measured.

The cutoff is the lock's own cooldown: ``uv.lock`` records ``exclude-newer-span``
(for example ``P7D``), and a run resolves with ``--exclude-newer`` set to that long
before now, so it sees what a ``uv lock`` run today could lock. It is computed once
per run.

Modes (exactly one):

    --check            measure every cell, compare with ``scripts/platform_wheels.json``
                       and compare the base install's dependency closure with and
                       without the alpha requirements
    --record           measure every cell and write the record
    --controls         plant a requirement that must break a cell (scancode-toolkit,
                       which has no musl wheels) and one that must move the base
                       closure (``anyio<4.16``), and fail if either does not
    --cooldown-report  list the cooldown exclusions in the register whose window has
                       ended; reads no network and runs no uv

Exit status: 0 nothing to report, 1 a difference or a failed control, 2 the run could
not measure (uv or the index did not answer, an unreadable input). A run that could
not measure never counts as a failed cell and is never recorded.

What ``--check`` fails on:

* a recorded cell whose status differs from the measured one (a cell that improves
  needs a re-record too, because the documents that cite it say where it works);
* an alpha member with no recorded row;
* a recorded row this script no longer measures, or a platform or Python version the
  record lacks;
* a version in the base install's closure that moves, or that goes missing, once the
  alpha requirements are added (a new package, or a wider marker, is not a difference);
* with ``--require-complete``, any measured row that has no recorded row.

Only the status of a cell is compared. Its detail (the distributions with no usable
wheel, the versions a pin backtracked from) is shown for the reader and is not part of
the comparison: uv's message wording is not a contract, and a different cause for the
same status leaves the statement a document makes about where it installs true.

The record, ``scripts/platform_wheels.json``, is ``json.dumps(sort_keys=True,
indent=2)``: the format the repository's JSON hook writes. A cell is ``ok``, ``fail``,
``backtracked``, or one of the last two followed by ``": <detail>"``. To record, run
``python scripts/check_platform_wheels.py --record`` with network access, read the
diff, and commit it. A ``--check`` run keeps what it measured in the file named by
``--measured-out``, which is the same format and can be committed in its place.

Standard library only, so it runs on a bare runner. It needs ``uv`` on PATH.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess  # nosec B404 - runs uv with a fixed argument list, never a shell
import sys
import tomllib
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NamedTuple

REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"
UV_LOCK = REPO_ROOT / "uv.lock"
REGISTRY = (
    REPO_ROOT / "automated_security_helper" / "base" / "plugin_provisioning.py"
)
RECORD = Path(__file__).resolve().with_name("platform_wheels.json")

FORMAT = 1
INDEX = "https://pypi.org/simple"
UV_TIMEOUT_SECONDS = 300

OK = "ok"
BACKTRACKED = "backtracked"
FAIL = "fail"
STATUSES = (OK, BACKTRACKED, FAIL)

EXIT_OK = 0
EXIT_FOUND = 1
EXIT_ERROR = 2

ORIGIN_RECORDED = "recorded by scripts/check_platform_wheels.py --record"
ORIGIN_MEASURED = (
    "measured by scripts/check_platform_wheels.py --check; copy it over "
    "scripts/platform_wheels.json to re-record"
)
COMMAND_TEMPLATE = (
    "uv pip compile --no-build --no-config --python-platform <triple> "
    "--python-version <python> --exclude-newer <exclude_newer> - "
    "(MACOSX_DEPLOYMENT_TARGET=14.0 for the macOS platforms)"
)

#: What the scancode control plants: a package whose natives publish no musl wheel,
#: with the pin it needs to import.
SCANCODE_REQUIREMENTS = ("scancode-toolkit==32.5.0", "pluggy<1.7")
#: What the closure control plants: a pin below the version the base install resolves.
ANYIO_PIN = "anyio<4.16"
#: The platform the planted scancode must still resolve on, so a failure everywhere
#: (a typo, an index outage read as a failure) is not mistaken for a musl failure.
ANCHOR_PLATFORM = "linux-x86_64-glibc"


class ResolverError(RuntimeError):
    """uv could not answer, so nothing may be recorded or compared from this run."""


class RecordError(ValueError):
    """The record cannot be read, or holds something this script does not write."""


class Result(NamedTuple):
    returncode: int
    stdout: str
    stderr: str


#: ``runner(argv, stdin, environment)``: what runs uv. Tests plant its answers.
Runner = Callable[[Sequence[str], str, Mapping[str, str]], Result]


@dataclass(frozen=True)
class Platform:
    key: str
    triple: str
    env: tuple[tuple[str, str], ...] = ()


# yara-python publishes macOS wheels for macOS 14 and later only, and uv's default
# target for the macOS platforms is older, so the macOS cells ask for 14.
_MACOS = (("MACOSX_DEPLOYMENT_TARGET", "14.0"),)

PLATFORMS: tuple[Platform, ...] = (
    Platform("linux-x86_64-glibc", "x86_64-unknown-linux-gnu"),
    Platform("linux-aarch64-glibc", "aarch64-unknown-linux-gnu"),
    Platform("linux-x86_64-musl", "x86_64-unknown-linux-musl"),
    Platform("linux-aarch64-musl", "aarch64-unknown-linux-musl"),
    Platform("macos-aarch64", "aarch64-apple-darwin", _MACOS),
    Platform("macos-x86_64", "x86_64-apple-darwin", _MACOS),
    Platform("windows-x86_64", "x86_64-pc-windows-msvc"),
    Platform("windows-aarch64", "aarch64-pc-windows-msvc"),
)

#: The only variables a resolver child sees. The index and the cutoff come from the
#: command line, so a runner's or a contributor's ``UV_INDEX_URL``,
#: ``UV_EXCLUDE_NEWER`` or ``PIP_*`` cannot change what is measured, and no token the
#: runner holds reaches a process that talks to a package index. ``LD_LIBRARY_PATH``
#: stays because actions/setup-python exports it for the shared libpython of the
#: interpreter uv has to start.
_PASSED_THROUGH = frozenset(
    {
        "PATH",
        "HOME",
        "USERPROFILE",
        "SYSTEMROOT",
        "TMPDIR",
        "TEMP",
        "TMP",
        "LANG",
        "LC_ALL",
        "LD_LIBRARY_PATH",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
        "UV_CACHE_DIR",
        "UV_PYTHON",
        "UV_PYTHON_DOWNLOADS",
        "UV_NATIVE_TLS",
        "UV_SYSTEM_CERTS",
    }
)


# ---------------------------------------------------------------------------
# Cells, time and Python versions.
# ---------------------------------------------------------------------------

_CELL = re.compile(r"(ok|backtracked|fail)(?:: (\S(?:.*\S)?))?")


def render_cell(status: str, detail: str = "") -> str:
    """A cell: its status, and ``": <detail>"`` after it when there is one."""
    if status not in STATUSES:
        raise ValueError(f"{status!r} is not a cell status")
    if status == OK and detail:
        raise ValueError("an ok cell carries no detail")
    if "\n" in detail or "\r" in detail:
        raise ValueError("a cell's detail is one line")
    return f"{status}: {detail}" if detail else status


def parse_cell(text: str) -> tuple[str, str]:
    """``(status, detail)`` of a cell, refusing anything this script does not write."""
    match = _CELL.fullmatch(text)
    if match is None or (match.group(1) == OK and match.group(2)):
        raise RecordError(
            f"{text!r} is not a cell: expected ok, or fail or backtracked with an "
            "optional ': detail'"
        )
    return match.group(1), match.group(2) or ""


_DURATION = re.compile(
    r"P(?:(?P<weeks>\d+)W)?(?:(?P<days>\d+)D)?"
    r"(?:T(?:(?P<hours>\d+)H)?(?:(?P<minutes>\d+)M)?(?:(?P<seconds>\d+)S)?)?"
)


def parse_duration(text: str) -> timedelta:
    """An ISO 8601 duration of weeks, days, hours, minutes and seconds (``P7D``).

    Months and years have no fixed length, so a cooldown given in them is refused
    rather than guessed.
    """
    match = _DURATION.fullmatch(text)
    parts = match.groupdict() if match else {}
    if match is None or not any(parts.values()) or text.endswith("T"):
        raise ValueError(
            f"{text!r} is not a duration of weeks, days, hours, minutes or seconds "
            "(an ISO 8601 form such as P7D)"
        )
    return timedelta(
        weeks=int(parts["weeks"] or 0),
        days=int(parts["days"] or 0),
        hours=int(parts["hours"] or 0),
        minutes=int(parts["minutes"] or 0),
        seconds=int(parts["seconds"] or 0),
    )


_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z")


def parse_timestamp(text: str) -> datetime:
    """A UTC timestamp written ``YYYY-MM-DDTHH:MM:SSZ``."""
    if _TIMESTAMP.fullmatch(text) is None:
        raise ValueError(f"{text!r} is not a UTC timestamp such as 2026-11-20T12:00:00Z")
    return datetime.fromisoformat(text[:-1] + "+00:00")


def format_timestamp(moment: datetime) -> str:
    """``YYYY-MM-DDTHH:MM:SSZ``: fractions are dropped, never rounded up."""
    if moment.tzinfo is None:
        raise ValueError("a timestamp needs a time zone")
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_cooldown(lock_text: str) -> tuple[str, timedelta | datetime]:
    """The cooldown ``uv.lock`` records: ``("P7D", timedelta)`` or a stored timestamp.

    ``exclude-newer-span`` wins: next to a span, uv writes a placeholder (year 1) or the
    moment the lock was made into ``exclude-newer`` and says it has no effect. A
    timestamp is used only when there is no span and it is not the placeholder.
    """
    options = tomllib.loads(lock_text).get("options")
    if not isinstance(options, dict):
        raise ValueError("uv.lock has no [options] table, so it records no exclude-newer")
    span = options.get("exclude-newer-span")
    if isinstance(span, str):
        return span, parse_duration(span)
    stamp = options.get("exclude-newer")
    moment: datetime | None = None
    if isinstance(stamp, datetime):
        moment = stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)
    elif isinstance(stamp, str):
        moment = parse_timestamp(stamp)
    if moment is not None and moment.year > 1:
        return format_timestamp(moment), moment
    raise ValueError(
        "uv.lock [options] holds no exclude-newer-span and no exclude-newer "
        "timestamp, so the cutoff of the project's cooldown cannot be read"
    )


def read_cutoff(lock_text: str, now: datetime) -> datetime:
    """The moment after which uploads are not resolved: the lock's span before *now*."""
    _, cooldown = read_cooldown(lock_text)
    if isinstance(cooldown, timedelta):
        return now - cooldown
    return cooldown


_LOWER_BOUND = re.compile(r">=\s*(\d+)\.(\d+)")
_UPPER_BOUND = re.compile(r"<\s*(\d+)\.(\d+)")


def python_versions(requires_python: str) -> tuple[str, ...]:
    """The 3.x minors ``>=3.A,<3.B`` admits: ``3.A`` up to, not including, ``3.B``."""
    lower = upper = None
    for clause in (part.strip() for part in requires_python.split(",")):
        low, high = _LOWER_BOUND.fullmatch(clause), _UPPER_BOUND.fullmatch(clause)
        if low and lower is None:
            lower = (int(low.group(1)), int(low.group(2)))
        elif high and upper is None:
            upper = (int(high.group(1)), int(high.group(2)))
        else:
            raise ValueError(f"cannot enumerate {requires_python!r}: {clause!r}")
    if lower is None or upper is None or lower[0] != 3 or upper[0] != 3:
        raise ValueError(
            f"{requires_python!r} is not of the form >=3.A,<3.B, so the Python "
            "versions to measure cannot be listed"
        )
    versions = tuple(f"3.{minor}" for minor in range(lower[1], upper[1]))
    if not versions:
        raise ValueError(f"{requires_python!r} admits no Python version")
    return versions


# ---------------------------------------------------------------------------
# The register, and the requirement sets.
# ---------------------------------------------------------------------------


def normalize_distribution(name: str) -> str:
    """A distribution name as PEP 503 compares it."""
    return re.sub(r"[-_.]+", "-", name).lower()


def load_register(path: Path) -> Any:
    """Import the plugin register by path: it is standard library only on purpose."""
    spec = importlib.util.spec_from_file_location(
        "ash_plugin_provisioning_for_platform_wheels", path
    )
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load the plugin register from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(spec.name, None)
        raise
    return module


def load_blocks(path: Path) -> Mapping[str, Any]:
    """``{scanner: provisioning block}`` from the register at *path*."""
    return load_register(path).PROVISIONING


def render_pin(pin: Any) -> tuple[str, ...]:
    """The requirement lines of a pin: the distribution, then its with-requirements.

    The markers go on every line, joined with ``and``; one that holds ``or`` is
    parenthesised first so the join keeps its meaning.
    """
    markers = [m for m in (pin.python_marker, pin.platform_marker) if m]
    if len(markers) > 1:
        markers = [f"({m})" if " or " in m else m for m in markers]
    suffix = f"; {' and '.join(markers)}" if markers else ""
    return tuple(
        f"{requirement}{suffix}"
        for requirement in (
            f"{pin.distribution}{pin.specifier}",
            *pin.with_requirements,
        )
    )


class Candidate(NamedTuple):
    distribution: str
    requirements: tuple[str, ...]
    #: True for a member of the alpha extra, False for a pin held for a decision.
    member: bool


def alpha_candidates(blocks: Mapping[str, Any]) -> list[Candidate]:
    """Every member of the alpha extra and every pin held only for a decision."""
    found = []
    for block in blocks.values():
        for pin in block.pypi_pins:
            member = pin.extra == "alpha"
            held = pin.excluded is not None and pin.excluded.reason.value == "owner_hold"
            if member or held:
                found.append(
                    Candidate(
                        normalize_distribution(pin.distribution),
                        render_pin(pin),
                        member,
                    )
                )
    return sorted(found)


def requirement_sets(
    pyproject: Mapping[str, Any], blocks: Mapping[str, Any]
) -> dict[str, tuple[str, ...]]:
    """``{row: the requirements resolved together}``; every row starts with the core."""
    project = pyproject.get("project", {})
    core = tuple(project.get("dependencies", ()))
    sets = {"core": core}
    for extra, requirements in sorted(project.get("optional-dependencies", {}).items()):
        # The register, not pyproject, says what is in the alpha extra: a pin held for
        # a decision is measured before it is a member, and the generated array
        # agrees with the register.
        if extra != "alpha":
            sets[f"core+{extra}"] = (*core, *requirements)
    candidates = alpha_candidates(blocks)
    if candidates:
        sets["core+alpha"] = (*core, *(r for c in candidates for r in c.requirements))
        for candidate in candidates:
            sets[f"core+alpha:{candidate.distribution}"] = (
                *core,
                *candidate.requirements,
            )
    return sets


def member_rows(blocks: Mapping[str, Any]) -> frozenset[str]:
    """The rows that must be recorded: the alpha members', and the combined row."""
    members = [c for c in alpha_candidates(blocks) if c.member]
    if not members:
        return frozenset()
    return frozenset({"core+alpha", *(f"core+alpha:{c.distribution}" for c in members)})


# ---------------------------------------------------------------------------
# Running uv and reading what it says.
# ---------------------------------------------------------------------------


def cell_command(uv: str, platform: Platform, python: str, exclude_newer: str) -> list[str]:
    return [
        uv,
        "pip",
        "compile",
        "--no-build",
        "--no-config",
        "--python-platform",
        platform.triple,
        "--python-version",
        python,
        "--exclude-newer",
        exclude_newer,
        "-",
    ]


def closure_command(uv: str, python: str, exclude_newer: str) -> list[str]:
    return [
        uv,
        "pip",
        "compile",
        "--universal",
        "--no-build",
        "--no-config",
        "--python-version",
        python,
        "--exclude-newer",
        exclude_newer,
        "-",
    ]


def child_environment(
    base: Mapping[str, str], platform: Platform | None = None
) -> dict[str, str]:
    """The environment of a uv child: the allowed variables, and the platform's own."""
    env = {name: value for name, value in base.items() if name in _PASSED_THROUGH}
    if platform is not None:
        env.update(platform.env)
    return env


def run_uv(argv: Sequence[str], stdin: str, env: Mapping[str, str]) -> Result:
    """The runner: uv with *argv*, *stdin* and *env*, and nothing else."""
    try:
        done = subprocess.run(  # nosec B603 - a fixed argument list and no shell
            list(argv),
            input=stdin,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=dict(env),
            timeout=UV_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ResolverError(
            f"uv timed out after {UV_TIMEOUT_SECONDS} s: {' '.join(argv[1:4])}"
        ) from exc
    except OSError as exc:
        raise ResolverError(f"cannot run {argv[0]}: {exc}") from exc
    return Result(done.returncode, done.stdout, done.stderr)


def defuse(text: str) -> str:
    """Make *text* safe to print into a CI log.

    The runner reads a line as a workflow command when ``::`` is its first thing after
    any leading white space, and it ends a line at a carriage return as well as at a
    line feed. Text from a tool or a package index must not be able to start one, so a
    ``::`` that opens a line is broken up, any ``##[`` is broken up, and a carriage
    return becomes a line break.
    """
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"(?m)^([^\S\n]*)::", r"\1: :", text)
    return text.replace("##[", "# #[")


def _excerpt(text: str, limit: int = 400) -> str:
    flat = " | ".join(line.strip() for line in defuse(text).splitlines() if line.strip())
    return flat if len(flat) <= limit else flat[: limit - 3] + "..."


_PIN = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([^\s;]+)")


def parse_pins(output: str) -> dict[str, tuple[str, ...]]:
    """``{name: versions}`` from the requirements uv prints.

    Comments, annotations and markers are skipped. A universal resolution can pin one
    package at several versions for different markers, so a name keeps every version.
    """
    found: dict[str, set[str]] = {}
    for raw in output.splitlines():
        line = raw.strip()
        match = None if not line or line.startswith("#") else _PIN.match(line)
        if match is not None:
            found.setdefault(normalize_distribution(match.group(1)), set()).add(
                match.group(2)
            )
    return {name: tuple(sorted(versions)) for name, versions in found.items()}


def resolution_failed(stderr: str) -> bool:
    """Whether uv's complaint is a failed resolution, as opposed to any other failure.

    Only a failed resolution is an answer about the requirements. A network error, a
    flag uv does not know and a crash say nothing about them.
    """
    return "No solution found when resolving dependencies" in stderr


_BLOCKER = re.compile(
    r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:[<>=!~][^\s,]*)?\s+(?:has|have) no "
    r"(?:usable wheels|wheels)"
)


def blockers(stderr: str) -> tuple[str, ...]:
    """The distributions uv says have no usable wheel. Shown, never compared."""
    return tuple(
        sorted({normalize_distribution(m.group(1)) for m in _BLOCKER.finditer(stderr)})
    )


_UV_BANNER = re.compile(r"uv (\d+\.\d+\.\d+\S*)")


def read_uv_version(runner: Runner, uv: str, environment: Mapping[str, str]) -> str:
    """The version in ``uv --version``'s first line."""
    result = runner([uv, "--version"], "", child_environment(environment))
    match = _UV_BANNER.match(result.stdout.strip()) if result.returncode == 0 else None
    if match is None:
        raise ResolverError(
            f"cannot read the version of uv from `{uv} --version`: "
            f"{_excerpt(result.stderr or result.stdout, 200)}"
        )
    return match.group(1)


@dataclass(frozen=True)
class Resolution:
    ok: bool
    pins: Mapping[str, tuple[str, ...]]
    blockers: tuple[str, ...]


def _resolve(
    runner: Runner,
    argv: Sequence[str],
    requirements: Sequence[str],
    env: Mapping[str, str],
    where: str,
) -> Resolution:
    result = runner(argv, "".join(f"{line}\n" for line in requirements), env)
    if result.returncode == 0:
        return Resolution(True, parse_pins(result.stdout), ())
    if resolution_failed(result.stderr):
        return Resolution(False, {}, blockers(result.stderr))
    raise ResolverError(
        f"uv failed for {where} (exit {result.returncode}): {_excerpt(result.stderr)}"
    )


# ---------------------------------------------------------------------------
# Measuring.
# ---------------------------------------------------------------------------


def _moved(
    reference: Mapping[str, tuple[str, ...]], pins: Mapping[str, tuple[str, ...]]
) -> list[str]:
    moved = [
        f"{name} {', '.join(reference[name])} -> {', '.join(pins[name])}"
        for name in sorted(reference.keys() & pins.keys())
        if reference[name] != pins[name]
    ]
    return moved if len(moved) <= 5 else [*moved[:5], f"and {len(moved) - 5} more"]


def _cells(outcomes: Sequence[Resolution]) -> list[str]:
    """The cell of each platform's resolution, for one set and one Python version.

    The reference is the first platform that resolved. A platform whose pins differ
    from it backtracked: uv settled on an older version because the newest had no wheel
    there.
    """
    reference = next((o.pins for o in outcomes if o.ok), None)
    cells = []
    for outcome in outcomes:
        if not outcome.ok:
            cells.append(render_cell(FAIL, ", ".join(outcome.blockers)))
            continue
        moved = _moved(reference, outcome.pins) if reference is not None else []
        cells.append(render_cell(BACKTRACKED, "; ".join(moved)) if moved else OK)
    return cells


def measure_sets(
    runner: Runner,
    uv: str,
    sets: Mapping[str, Sequence[str]],
    pythons: Sequence[str],
    exclude_newer: str,
    environment: Mapping[str, str],
    platforms: Sequence[Platform] | None = None,
) -> dict[str, dict[str, dict[str, str]]]:
    """``{row: {platform: {python: cell}}}``. Raises ResolverError and returns nothing
    when uv cannot answer for any cell: a partial measurement is never returned."""
    chosen = tuple(PLATFORMS if platforms is None else platforms)
    measured: dict[str, dict[str, dict[str, str]]] = {}
    for set_id, requirements in sets.items():
        rows: dict[str, dict[str, str]] = {platform.key: {} for platform in chosen}
        for python in pythons:
            outcomes = [
                _resolve(
                    runner,
                    cell_command(uv, platform, python, exclude_newer),
                    requirements,
                    child_environment(environment, platform),
                    f"{set_id} / {platform.key} / {python}",
                )
                for platform in chosen
            ]
            for platform, cell in zip(chosen, _cells(outcomes), strict=True):
                rows[platform.key][python] = cell
        measured[set_id] = rows
    return measured


def closure_differences(
    core: Mapping[str, tuple[str, ...]], with_alpha: Mapping[str, tuple[str, ...]]
) -> list[str]:
    """How the base install's closure changed: a version that moved or went missing.

    A package that is new, and a package that keeps its versions under a wider
    marker, are not differences: the alpha requirements may add to the closure, and
    may not change what the base install resolves to.
    """
    lines = []
    for name in sorted(core):
        if name not in with_alpha:
            lines.append(
                f"{name}: the base install resolves {', '.join(core[name])}; with the "
                "alpha requirements it is missing"
            )
        elif core[name] != with_alpha[name]:
            lines.append(
                f"{name}: the base install resolves {', '.join(core[name])}; with the "
                f"alpha requirements it resolves {', '.join(with_alpha[name])}"
            )
    return lines


def _because(resolution: Resolution) -> str:
    if resolution.blockers:
        return f" (no usable wheels: {', '.join(resolution.blockers)})"
    return ""


def closure_findings(
    runner: Runner,
    uv: str,
    core_requirements: Sequence[str],
    alpha_requirements: Sequence[str],
    python: str,
    exclude_newer: str,
    environment: Mapping[str, str],
) -> list[str]:
    """What adding the alpha requirements changes in the base install's closure.

    One universal resolution of the core alone and one of the core plus the alpha
    requirements; a version of a base package that differs is a finding.
    """
    argv = closure_command(uv, python, exclude_newer)
    env = child_environment(environment)
    base = _resolve(runner, argv, core_requirements, env, "the base closure")
    if not base.ok:
        return [f"the base install does not resolve universally{_because(base)}"]
    widened = _resolve(
        runner,
        argv,
        [*core_requirements, *alpha_requirements],
        env,
        "the base closure with the alpha requirements",
    )
    if not widened.ok:
        message = (
            "the base install plus the alpha extra does not resolve "
            f"universally{_because(widened)}"
        )
        return [message]
    return closure_differences(base.pins, widened.pins)


# ---------------------------------------------------------------------------
# The controls.
# ---------------------------------------------------------------------------


class ControlResult(NamedTuple):
    name: str
    passed: bool
    message: str


def _scancode_control(
    runner: Runner,
    uv: str,
    core_requirements: Sequence[str],
    pythons: Sequence[str],
    exclude_newer: str,
    environment: Mapping[str, str],
) -> ControlResult:
    name = "scancode-musl"
    sets = {"planted": (*core_requirements, *SCANCODE_REQUIREMENTS)}
    musl = [p for p in PLATFORMS if p.key.endswith("-musl")]
    anchor = [p for p in PLATFORMS if p.key == ANCHOR_PLATFORM]
    anchor_python = pythons[len(pythons) // 2]
    on_musl = measure_sets(
        runner, uv, sets, pythons, exclude_newer, environment, platforms=musl
    )["planted"]
    on_anchor = measure_sets(
        runner, uv, sets, (anchor_python,), exclude_newer, environment, platforms=anchor
    )["planted"]
    green = [
        f"{key} / {python}"
        for key, cells in on_musl.items()
        for python, cell in cells.items()
        if parse_cell(cell)[0] != FAIL
    ]
    anchor_cell = on_anchor[ANCHOR_PLATFORM][anchor_python]
    if green:
        return ControlResult(
            name,
            False,
            "the planted scancode-toolkit still resolves on musl, where it has no "
            f"wheels: {', '.join(green)}",
        )
    if parse_cell(anchor_cell)[0] != OK:
        return ControlResult(
            name,
            False,
            "the planted requirements also fail on "
            f"{ANCHOR_PLATFORM} / {anchor_python} ({anchor_cell}), so a failure on "
            "musl proves nothing",
        )
    cells = sum(len(c) for c in on_musl.values())
    return ControlResult(
        name,
        True,
        f"the planted scancode-toolkit fails on all {cells} musl cells and resolves on "
        f"{ANCHOR_PLATFORM} / {anchor_python}",
    )


def _anyio_control(
    runner: Runner,
    uv: str,
    core_requirements: Sequence[str],
    python: str,
    exclude_newer: str,
    environment: Mapping[str, str],
) -> ControlResult:
    name = "anyio-closure"
    argv = closure_command(uv, python, exclude_newer)
    env = child_environment(environment)
    base = _resolve(runner, argv, core_requirements, env, "the base closure")
    if not base.ok:
        return ControlResult(name, False, "the base install does not resolve universally")
    if "anyio" not in base.pins:
        return ControlResult(
            name,
            False,
            "anyio is not in the base closure, so a pin below it moves nothing; point "
            "the control at a package that is",
        )
    unconstrained = _resolve(
        runner, argv, [*core_requirements, "anyio"], env, "the base plus anyio"
    )
    planted = _resolve(
        runner, argv, [*core_requirements, ANYIO_PIN], env, f"the base plus {ANYIO_PIN}"
    )
    if not unconstrained.ok:
        return ControlResult(
            name,
            False,
            "the base install plus an unconstrained anyio does not resolve "
            f"universally{_because(unconstrained)}",
        )
    if not planted.ok:
        return ControlResult(
            name,
            False,
            f"the planted {ANYIO_PIN} cannot be met next to the base install, so it "
            "cannot show the check flagging a moved version; lower the pin until the "
            f"base install accepts it{_because(planted)}",
        )
    if closure_differences(base.pins, unconstrained.pins):
        return ControlResult(
            name,
            False,
            "an unconstrained anyio moved the base closure, so the control is invalid",
        )
    moved = [
        line
        for line in closure_differences(base.pins, planted.pins)
        if line.startswith("anyio:")
    ]
    if not moved:
        return ControlResult(
            name,
            False,
            f"the planted {ANYIO_PIN} left anyio at {', '.join(base.pins['anyio'])}: "
            "the closure check does not flag a version it must",
        )
    return ControlResult(name, True, moved[0])


def run_controls(
    runner: Runner,
    uv: str,
    core_requirements: Sequence[str],
    pythons: Sequence[str],
    exclude_newer: str,
    environment: Mapping[str, str],
) -> list[ControlResult]:
    """Plant what must be flagged and check that it is.

    A check that passes today proves nothing about whether it can fail. These plant a
    requirement with no musl wheels and a pin below the base closure, and report each
    control that did not turn red where it must.
    """
    return [
        _scancode_control(
            runner, uv, core_requirements, pythons, exclude_newer, environment
        ),
        _anyio_control(
            runner, uv, core_requirements, pythons[0], exclude_newer, environment
        ),
    ]


# ---------------------------------------------------------------------------
# The record, and comparing with it.
# ---------------------------------------------------------------------------


def build_record(
    measured: Mapping[str, Any], metadata: Mapping[str, Any]
) -> dict[str, Any]:
    return {"format": FORMAT, "metadata": dict(metadata), "sets": dict(measured)}


def render_record(record: Mapping[str, Any]) -> str:
    """The bytes of a record: what the repository's JSON hook writes."""
    return json.dumps(record, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def load_record(path: Path) -> dict[str, Any]:
    """Read and validate a record, refusing anything this script does not write."""
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RecordError(f"cannot read the record {path}: {exc}") from exc
    except ValueError as exc:
        raise RecordError(f"{path} is not JSON: {exc}") from exc
    try:
        _validate(record)
    except RecordError as exc:
        raise RecordError(f"{path}: {exc}") from exc
    return record


def _validate(record: Any) -> None:
    if not isinstance(record, dict):
        raise RecordError("the record is not a JSON object")
    if record.get("format") != FORMAT:
        raise RecordError(
            f"format {record.get('format')!r}; this script reads format {FORMAT}"
        )
    if not isinstance(record.get("metadata"), dict):
        raise RecordError("no 'metadata' object")
    sets = record.get("sets")
    if not isinstance(sets, dict):
        raise RecordError("no 'sets' object")
    for set_id, rows in sets.items():
        if not isinstance(rows, dict):
            raise RecordError(f"row {set_id!r} is not an object of platforms")
        for platform, cells in rows.items():
            if not isinstance(cells, dict):
                raise RecordError(f"{set_id!r} / {platform!r} is not an object of cells")
            for python, cell in cells.items():
                if not isinstance(cell, str):
                    raise RecordError(f"{set_id!r} / {platform!r} / {python!r}: not a cell")
                parse_cell(cell)


def write_record(path: Path, record: Mapping[str, Any]) -> None:
    """Write the record whole or not at all: a temporary file, then a rename."""
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(render_record(record), encoding="utf-8", newline="\n")
    os.replace(temporary, path)


@dataclass(frozen=True)
class Finding:
    kind: str
    where: str
    message: str
    blocking: bool = True


def _cells_of(row: Mapping[str, Mapping[str, str]]) -> set[tuple[str, str]]:
    return {(platform, python) for platform, cells in row.items() for python in cells}


def _shape_message(missing: Sequence[tuple[str, str]], gone: Sequence[tuple[str, str]]) -> str:
    def listing(cells: Sequence[tuple[str, str]]) -> str:
        shown = [f"{platform} / {python}" for platform, python in cells[:6]]
        if len(cells) > 6:
            shown.append(f"and {len(cells) - 6} more")
        return ", ".join(shown)

    parts = []
    if missing:
        parts.append(f"measured, not recorded: {listing(missing)}")
    if gone:
        parts.append(f"recorded, not measured: {listing(gone)}")
    return "the grid differs from the record (" + "; ".join(parts) + "); re-record"


def compare(
    recorded: Mapping[str, Mapping[str, Mapping[str, str]]],
    measured: Mapping[str, Mapping[str, Mapping[str, str]]],
    *,
    members: Collection[str] = (),
    require_complete: bool = False,
) -> list[Finding]:
    """What differs between the recorded rows and the measured ones.

    Only a cell's status is compared. A row nothing recorded is a failure for an alpha
    member and a note for any other row (a failure under ``require_complete``): the
    record may be completed in steps, but a member is never waved through unrecorded.
    """
    findings: list[Finding] = []
    for set_id in sorted(set(recorded) - set(measured)):
        findings.append(
            Finding("stale-row", set_id, "recorded, but this script no longer measures it")
        )
    for set_id in sorted(measured):
        if set_id not in recorded:
            if set_id in members:
                findings.append(
                    Finding("member-row", set_id, "an alpha member has no recorded row")
                )
            else:
                findings.append(
                    Finding(
                        "unrecorded-row",
                        set_id,
                        "no recorded row; it is measured and shown, not compared",
                        require_complete,
                    )
                )
            continue
        before, after = recorded[set_id], measured[set_id]
        here, there = _cells_of(before), _cells_of(after)
        if here != there:
            findings.append(
                Finding(
                    "shape", set_id, _shape_message(sorted(there - here), sorted(here - there))
                )
            )
        for platform, python in sorted(here & there):
            old, new = before[platform][python], after[platform][python]
            if parse_cell(old)[0] != parse_cell(new)[0]:
                findings.append(
                    Finding(
                        "changed",
                        f"{set_id} / {platform} / {python}",
                        f"recorded {old}, measured {new}",
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# The cooldown report.
# ---------------------------------------------------------------------------


def _until_date(distribution: str, text: str) -> date:
    stripped = text.strip()
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}(?:T.*)?", stripped) is None:
            raise ValueError(stripped)
        return date.fromisoformat(stripped[:10])
    except ValueError as exc:
        raise ValueError(
            f"{distribution}: the cooldown's until value {text!r} is not a UTC date "
            "(YYYY-MM-DD)"
        ) from exc


def cooldown_report(blocks: Mapping[str, Any], today: date) -> list[str]:
    """The pins held for a cooldown whose window ended on or before *today*.

    A pin held because it was younger than the project's cooldown can be tried in the
    extra once the window has passed. Nothing else would say so: the exclusion stays
    in the register until a person removes it.
    """
    lines = []
    for block in blocks.values():
        for pin in block.pypi_pins:
            excluded = pin.excluded
            if excluded is None or excluded.reason.value != "cooldown":
                continue
            until = _until_date(pin.distribution, excluded.until)
            if today >= until:
                lines.append(
                    f"{pin.distribution}: held for its cooldown until {until.isoformat()}, "
                    "which has passed; replace the exclusion with extra=\"alpha\" and "
                    "re-record this matrix, or record why it stays out"
                )
    return sorted(lines)


# ---------------------------------------------------------------------------
# The command line.
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="check_platform_wheels.py",
        description="Check that ASH's requirements resolve from wheels on every "
        "platform it names. Exit 0: nothing to report, 1: a difference, 2: the run "
        "could not measure.",
    )
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument(
        "--check",
        action="store_true",
        help="measure, compare with the record, and check the base closure",
    )
    modes.add_argument("--record", action="store_true", help="measure and write the record")
    modes.add_argument(
        "--controls",
        action="store_true",
        help="plant what must be flagged and fail if it is not",
    )
    modes.add_argument(
        "--cooldown-report",
        action="store_true",
        help="list cooldown exclusions whose window has ended (no network)",
    )
    parser.add_argument("--file", type=Path, default=RECORD, help="the record")
    parser.add_argument("--pyproject", type=Path, default=PYPROJECT)
    parser.add_argument("--lock", type=Path, default=UV_LOCK)
    parser.add_argument("--registry", type=Path, default=REGISTRY)
    parser.add_argument("--uv", default="uv", help="the uv executable")
    parser.add_argument(
        "--measured-out",
        type=Path,
        default=None,
        help="with --check, also write what was measured, in the record's format",
    )
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="with --check, fail on a measured row that has no recorded row",
    )
    return parser


def _inputs(
    args: argparse.Namespace, moment: datetime
) -> tuple[dict[str, Any], tuple[str, ...], str, str]:
    """``(pyproject, pythons, cutoff, cooldown label)`` from the files named."""
    pyproject = tomllib.loads(args.pyproject.read_text(encoding="utf-8"))
    lock_text = args.lock.read_text(encoding="utf-8")
    label, _ = read_cooldown(lock_text)
    cutoff = format_timestamp(read_cutoff(lock_text, moment))
    requires = pyproject.get("project", {}).get("requires-python", "")
    return pyproject, python_versions(requires), cutoff, label


def _metadata(
    uv_version: str,
    moment: datetime,
    cutoff: str,
    cooldown: str,
    pythons: Sequence[str],
    origin: str,
) -> dict[str, Any]:
    return {
        "command": COMMAND_TEMPLATE,
        "cooldown": cooldown,
        "exclude_newer": cutoff,
        "index": INDEX,
        "measured_at": format_timestamp(moment),
        "origin": origin,
        "platforms": {p.key: p.triple for p in PLATFORMS},
        "pythons": list(pythons),
        "uv_version": uv_version,
    }


def _count(measured: Mapping[str, Mapping[str, Mapping[str, str]]]) -> int:
    return sum(len(cells) for rows in measured.values() for cells in rows.values())


def _record(args: argparse.Namespace, runner: Runner, moment: datetime) -> int:
    pyproject, pythons, cutoff, cooldown = _inputs(args, moment)
    blocks = load_blocks(args.registry)
    sets = requirement_sets(pyproject, blocks)
    uv_version = read_uv_version(runner, args.uv, os.environ)
    measured = measure_sets(runner, args.uv, sets, pythons, cutoff, os.environ)
    metadata = _metadata(uv_version, moment, cutoff, cooldown, pythons, ORIGIN_RECORDED)
    write_record(args.file, build_record(measured, metadata))
    print(f"recorded {_count(measured)} cells in {len(measured)} rows to {args.file}")
    return EXIT_OK


def _check(args: argparse.Namespace, runner: Runner, moment: datetime) -> int:
    record = load_record(args.file)
    pyproject, pythons, cutoff, cooldown = _inputs(args, moment)
    blocks = load_blocks(args.registry)
    sets = requirement_sets(pyproject, blocks)
    uv_version = read_uv_version(runner, args.uv, os.environ)
    measured = measure_sets(runner, args.uv, sets, pythons, cutoff, os.environ)
    if args.measured_out is not None:
        metadata = _metadata(uv_version, moment, cutoff, cooldown, pythons, ORIGIN_MEASURED)
        write_record(args.measured_out, build_record(measured, metadata))
    findings = compare(
        record["sets"],
        measured,
        members=member_rows(blocks),
        require_complete=args.require_complete,
    )
    candidates = alpha_candidates(blocks)
    closure: list[str] = []
    closure_note = "no alpha candidate: the base closure has nothing to be compared with"
    if candidates:
        closure_note = ""
        closure = closure_findings(
            runner,
            args.uv,
            sets["core"],
            [r for c in candidates for r in c.requirements],
            pythons[0],
            cutoff,
            os.environ,
        )
    notes = [f for f in findings if not f.blocking]
    blocking = [f for f in findings if f.blocking]
    failed = bool(blocking or closure)
    lines = [
        f"## Platform wheels: {'FAILED' if failed else 'ok'}",
        "",
        f"- uv {uv_version}, index {INDEX}",
        f"- cutoff {cutoff}: {cooldown} before {format_timestamp(moment)}",
        (
            f"- {_count(measured)} cells measured in {len(measured)} rows "
            f"({len(PLATFORMS)} platforms, Python {', '.join(pythons)})"
        ),
    ]
    recorded_uv = record["metadata"].get("uv_version")
    if recorded_uv and recorded_uv != uv_version:
        notes.append(
            Finding(
                "uv-version",
                "metadata",
                f"measured with uv {uv_version}; the record was taken with {recorded_uv}",
                False,
            )
        )
    if blocking:
        lines += ["", "### Differences from the record"]
        lines += [f"- {f.kind}: {f.where}: {f.message}" for f in blocking]
    lines += ["", "### Base closure"]
    if closure_note:
        lines.append(f"- {closure_note}")
    elif closure:
        lines += [f"- {line}" for line in closure]
    else:
        lines.append("- ok: the alpha requirements move no version of the base install")
    if notes:
        lines += ["", "### Notes"]
        lines += [f"- {f.kind}: {f.where}: {f.message}" for f in notes]
    if failed:
        lines += [
            "",
            (
                "If the change is intended, re-record with "
                "`python scripts/check_platform_wheels.py --record` (it needs network "
                "access) and commit scripts/platform_wheels.json."
            ),
        ]
    print(defuse("\n".join(lines)))
    return EXIT_FOUND if failed else EXIT_OK


def _controls(args: argparse.Namespace, runner: Runner, moment: datetime) -> int:
    pyproject, pythons, cutoff, _ = _inputs(args, moment)
    core = tuple(pyproject.get("project", {}).get("dependencies", ()))
    results = run_controls(runner, args.uv, core, pythons, cutoff, os.environ)
    failed = not all(r.passed for r in results)
    lines = [f"## Platform wheels controls: {'FAILED' if failed else 'ok'}", ""]
    lines += [f"- {'ok' if r.passed else 'FAILED'}: {r.name}: {r.message}" for r in results]
    print(defuse("\n".join(lines)))
    return EXIT_FOUND if failed else EXIT_OK


def _cooldown(args: argparse.Namespace, moment: datetime) -> int:
    lines = cooldown_report(load_blocks(args.registry), moment.date())
    if not lines:
        print("no cooldown exclusion has ended")
        return EXIT_OK
    print(defuse("\n".join(["## Cooldown exclusions that have ended", "", *(f"- {x}" for x in lines)])))
    return EXIT_FOUND


def main(
    argv: Sequence[str] | None = None,
    *,
    runner: Runner | None = None,
    now: datetime | None = None,
) -> int:
    args = build_parser().parse_args(argv)
    runner = run_uv if runner is None else runner
    try:
        moment = datetime.now(timezone.utc) if now is None else now
        if args.cooldown_report:
            return _cooldown(args, moment)
        if args.record:
            return _record(args, runner, moment)
        if args.controls:
            return _controls(args, runner, moment)
        return _check(args, runner, moment)
    except (OSError, ValueError, ResolverError) as exc:
        print(f"check_platform_wheels: cannot measure: {defuse(str(exc))}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
