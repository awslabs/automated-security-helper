# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Build the fixtures for the pre-commit cost table and time ASH on them.

Run with: python scripts/measure_precommit_cost.py --help

Two things use this file. The "What it costs" table in
docs/content/how-to/pre-commit.md compares a small repository with a larger one, and
the scan-time benchmark job (.github/workflows/ash-scan-benchmark.yml) times the
measured commit against its parent and against the latest release. Both need a repository that can be
rebuilt, so every fixture is generated here, deterministically, from nothing but this
file: the same call produces the same bytes on every host, and ``fixture_digest``
fingerprints the result so a test can pin it. The figures themselves are not pinned
(wall-clock time is not stable enough to fail a build on); the doc labels them with the
venue and the date they were taken on, and the job only prints them.

The fixtures
------------
``small``  10 Python files in one package.
``large``  900 Python files across 30 packages of 30 modules each, plus a
           ``pyproject.toml`` and a ``README.md``. Every module defines a few
           functions and one class, and a small number of modules carry content a
           scanner looks at (a ``subprocess`` call with ``shell=True``, a
           hard-coded password-shaped string), so the scanners have findings to
           report rather than an empty tree. Which modules carry them is a pure
           function of the module's index.
``bench``  The ``small`` package plus a ``README.md`` and one CI config,
           ``.github/workflows/ci.yml``, with settings a workflow scanner reports
           (write-all permissions, an unpinned action, an expression pasted into a
           script). The benchmark job times this one.

The staged rows stage a file that carries a planted finding: ``pkg/mod_00.py`` (or
``pkg_00/mod_00.py`` in the large fixture) holds the ``shell=True`` call, and
``ci.yml`` holds the workflow settings. The whole-repository rows scan the whole
fixture, findings included. Scans that find something exit 2, so 2 is an expected
exit for every scan row; any other exit than 0 or 2 stops the run (see below).

The rows
--------
Each row is timed as the whole child process, warm: one discarded run first, then
``--repeats`` timed runs. The ``--staged`` rows touch the planted file and stage it
with ``git add`` before the run and leave the fixture's commit untouched. A row
reports the minimum, median, mean and maximum, the exit code of every run, and the
load average after each run.

Each ``--baseline LABEL ASH COMMIT REF`` adds a build to time against the tip
(``--ash``, labelled ``head``) in one invocation. The builds alternate (one round per
repeat, every build once per round), each on its own copy of the fixture, so a machine
that speeds up or slows down during the run affects all of them alike. The benchmark
job passes two baselines: ``prev-commit``, the parent of the measured commit, and
``prev-release``, the latest release tag. Without a baseline the single build is timed
on ``DEST`` itself, as the doc table's commands do.

A run that exits with a code outside the row's expected set stops the script with the
row, the build and the first of its stderr, so an error exit that returns quickly can
never be published as a fast scan. A host whose load average per CPU is above 1 is
refused unless ``--allow-busy`` says to time it anyway; the load average of every run
is recorded either way.

``--json`` writes the full report, ``--summary`` a Markdown table (the benchmark job
points it at ``$GITHUB_STEP_SUMMARY``), and ``--trend-in`` with ``--trend-out`` appends
one line per run to a JSON Lines trend file: the tip's figures under the keys earlier
lines carry, then each baseline's figures and the tip's difference from it. The summary
flags a scenario against a baseline when the tip median is more than 10% and 0.2 s above
that baseline's median and the tip minimum is above its minimum; it only prints, and the
exit status never depends on it.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

SMALL_FILES = 10
LARGE_PACKAGES = 30
LARGE_MODULES_PER_PACKAGE = 30
LARGE_FILES = LARGE_PACKAGES * LARGE_MODULES_PER_PACKAGE

# A scan that finds something exits 2 (ACTIONABLE_FINDINGS); 1 is a scanner error and
# 5 a refused command line, both of which a timing must never swallow. The one
# exception is a baseline that predates a flag (see ``collect``): it is left out of that
# scenario and the report says so.
SCAN_CODES = frozenset({0, 2})
USAGE_ERROR = 5
LOAD_REFUSE_RATIO = 1.0
WARN_RELATIVE = 0.10
WARN_ABSOLUTE_SECONDS = 0.2
STDERR_KEPT = 400

# The operator's git setup must not reach a fixture: an unreadable global file and no
# system file mean no commit.gpgsign, no core.hooksPath and no installed hook framework.
GIT_ISOLATION = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "fixture",
    "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
    "GIT_COMMITTER_NAME": "fixture",
    "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
    "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
    **GIT_ISOLATION,
}

_BENCH_CI_CONFIG = """\
name: CI

on:
  pull_request:
  push:

permissions: write-all

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Greet
        run: echo "${{ github.event.pull_request.title }}"
      - run: python -m pytest
"""


def _module_source(package: int, module: int) -> str:
    """One module's text: a pure function of its two indices."""
    index = package * LARGE_MODULES_PER_PACKAGE + module
    lines = [
        f'"""Module {module} of package {package} (fixture index {index})."""',
        "",
        "from __future__ import annotations",
        "",
        "import hashlib",
        "import json",
        "",
        "",
    ]
    for fn in range(4):
        lines += [
            f"def compute_{fn}(values: list[int], scale: int = {index % 7 + 1}) -> int:",
            f'    """Fold ``values`` into one number (variant {fn})."""',
            "    total = 0",
            "    for position, value in enumerate(values):",
            f"        total += (value * scale + position * {fn + 1}) % {101 + index % 13}",
            "    return total",
            "",
            "",
        ]
    lines += [
        f"class Record{index}:",
        '    """A small record with a digest."""',
        "",
        "    def __init__(self, name: str, payload: dict[str, int]) -> None:",
        "        self.name = name",
        "        self.payload = payload",
        "",
        "    def digest(self) -> str:",
        "        body = json.dumps(self.payload, sort_keys=True).encode()",
        "        return hashlib.sha256(body).hexdigest()",
        "",
    ]
    if index % 90 == 0:
        lines += [
            "",
            "def run(command: str) -> int:",
            "    import subprocess",
            "",
            "    return subprocess.call(command, shell=True)",
            "",
        ]
    if index % 150 == 7:
        lines += [
            "",
            f'PASSWORD = "fixture-not-a-secret-{index:04d}"',  # pragma: allowlist secret
            "",
        ]
    return "\n".join(lines)


def _write(path: Path, text: str) -> None:
    """Write ``text`` as UTF-8 bytes with no newline translation.

    ``Path.write_text`` turns ``\\n`` into ``\\r\\n`` on Windows, while
    ``fixture_digest`` hashes the raw bytes, so the pinned digests would differ there.
    """
    path.write_bytes(text.encode("utf-8"))


def build_fixture(dest: Path, kind: str) -> list[Path]:
    """Write fixture ``kind`` ("small", "large" or "bench") under ``dest``.

    Returns the .py files. ``dest`` must be an empty or missing directory. No git
    state is created here; ``init_repository`` does that, so the bytes and the
    repository setup can be tested separately.
    """
    if kind not in ("small", "large", "bench"):
        raise ValueError(f"unknown fixture kind {kind!r}")
    dest.mkdir(parents=True, exist_ok=True)
    if any(dest.iterdir()):
        raise ValueError(f"{dest} is not empty")
    written: list[Path] = []
    if kind in ("small", "bench"):
        package = dest / "pkg"
        package.mkdir()
        _write(package / "__init__.py", "")
        written.append(package / "__init__.py")
        for module in range(SMALL_FILES - 1):
            path = package / f"mod_{module:02d}.py"
            _write(path, _module_source(0, module))
            written.append(path)
        if kind == "bench":
            _write(dest / "README.md", "# Benchmark fixture\n")
            workflows = dest / ".github" / "workflows"
            workflows.mkdir(parents=True)
            _write(workflows / "ci.yml", _BENCH_CI_CONFIG)
        return written
    _write(
        dest / "pyproject.toml",
        '[project]\nname = "cost-fixture"\nversion = "0.0.0"\n',
    )
    _write(dest / "README.md", "# Cost fixture\n")
    for package_index in range(LARGE_PACKAGES):
        package = dest / f"pkg_{package_index:02d}"
        package.mkdir()
        for module in range(LARGE_MODULES_PER_PACKAGE):
            path = package / f"mod_{module:02d}.py"
            _write(path, _module_source(package_index, module))
            written.append(path)
    return written


def fixture_digest(root: Path) -> str:
    """SHA-256 over every file's relative path and bytes, in sorted path order.

    Skips ``.git`` so the digest depends on the generated content only.
    """
    digest = hashlib.sha256()
    # Sorted by the posix text of the relative path, not by the Path objects: Windows
    # compares Path parts case-insensitively, which puts README.md after pkg_00 where
    # every other platform puts it before, and the digest follows the order.
    for path in sorted(
        (p for p in root.rglob("*") if p.is_file() and ".git" not in p.parts),
        key=lambda p: p.relative_to(root).as_posix(),
    ):
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode() + b"\0")
        digest.update(path.read_bytes() + b"\0")
    return digest.hexdigest()


def _git_env() -> dict[str, str]:
    return {**os.environ, **_GIT_ENV}


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args], cwd=root, env=_git_env(), check=True, capture_output=True
    )


def init_repository(root: Path) -> None:
    """Make ``root`` a git repository with one commit holding the fixture."""
    for args in (
        ("init", "-q", "-b", "main"),
        ("add", "-A"),
        ("commit", "-q", "--no-verify", "-m", "fixture"),
    ):
        _git(root, *args)


def planted_python(kind: str) -> str:
    """The fixture file, relative to its root, that carries a ``shell=True`` call."""
    return "pkg_00/mod_00.py" if kind == "large" else "pkg/mod_00.py"


# --- scenarios -------------------------------------------------------------------


@dataclass(frozen=True)
class Scenario:
    """One timed command: what follows the ``ash`` executable and what it stages."""

    name: str
    args: tuple[str, ...]
    stage: str | None
    expected: frozenset[int]
    express: bool = False


_PRECOMMIT = ("--mode", "precommit")
_STAGED = (*_PRECOMMIT, "--staged")

BENCH_SCENARIOS = (
    Scenario("version", ("--version",), None, frozenset({0})),
    Scenario("staged-py", _STAGED, "pkg/mod_00.py", SCAN_CODES),
    Scenario("staged-ci-config", _STAGED, ".github/workflows/ci.yml", SCAN_CODES),
    Scenario("whole-repo", _PRECOMMIT, None, SCAN_CODES),
)


def row_scenarios(kind: str) -> tuple[Scenario, ...]:
    """The four rows of the doc's cost table, for fixture ``kind``."""
    planted = planted_python(kind)
    return (
        Scenario("whole repository, no --staged", _PRECOMMIT, None, SCAN_CODES),
        Scenario("--staged, one .py file staged", _STAGED, planted, SCAN_CODES),
        Scenario(
            "--staged, --only-scanners bandit,detect-secrets",
            (*_STAGED, "--only-scanners", "bandit,detect-secrets"),
            planted,
            SCAN_CODES,
        ),
        Scenario(
            "--staged --express, daemon warm",
            (*_STAGED, "--express"),
            planted,
            SCAN_CODES,
            express=True,
        ),
    )


def prepare(root: Path, scenario: Scenario) -> None:
    """Put ``root`` in the state ``scenario`` is timed in: committed, plus its staging."""
    _git(root, "reset", "-q", "--hard", "HEAD")
    if scenario.stage:
        path = root / scenario.stage
        path.write_bytes(path.read_bytes() + b"\n# touched\n")
        _git(root, "add", scenario.stage)


# --- running and statistics ------------------------------------------------------


class BadExit(RuntimeError):
    """A timed command exited with a code the row does not expect."""


@dataclass(frozen=True)
class Build:
    """One ASH build under test: its executable, its fixture copy and its commit."""

    label: str
    ash: list[str]
    root: Path
    commit: str = "unknown"
    ref: str = ""


@dataclass(frozen=True)
class Sample:
    seconds: float
    returncode: int
    loadavg: float | None
    stderr: str = field(default="", compare=False)


@dataclass(frozen=True)
class Stats:
    min: float
    median: float
    mean: float
    max: float


def current_loadavg() -> float | None:
    """The one-minute load average, or None where the platform has none (Windows)."""
    if not hasattr(os, "getloadavg"):
        return None
    try:
        return os.getloadavg()[0]
    except OSError:
        return None


def host_is_busy(load: float | None, cpus: int) -> bool:
    return load is not None and load / max(cpus, 1) > LOAD_REFUSE_RATIO


def alternation_order(labels: Sequence[str], repeats: int) -> list[str]:
    """Base, head, base, head, ...: every round visits every build once, in order."""
    return [label for _ in range(repeats) for label in labels]


def _run_once(argv: list[str], cwd: Path) -> Sample:
    env = {**os.environ, **GIT_ISOLATION}
    start = time.perf_counter()
    proc = subprocess.run(argv, cwd=cwd, env=env, check=False, capture_output=True)
    seconds = time.perf_counter() - start
    stderr = ""
    if proc.returncode:
        stderr = proc.stderr.decode("utf-8", "replace").strip()[:STDERR_KEPT]
    return Sample(seconds, proc.returncode, current_loadavg(), stderr)


def _check(sample: Sample, scenario: Scenario, build: Build, argv: list[str]) -> None:
    if sample.returncode in scenario.expected:
        return
    raise BadExit(
        f"{scenario.name!r} on the {build.label} build exited {sample.returncode} "
        f"(expected one of {sorted(scenario.expected)}): {' '.join(argv)}\n"
        f"stderr: {sample.stderr or '(none)'}"
    )


def collect(
    builds: Sequence[Build],
    scenario: Scenario,
    repeats: int,
    tip_label: str = "head",
) -> dict[str, list[Sample]]:
    """Time ``scenario`` on every build, alternating, after one discarded round.

    Raises ``BadExit`` at the first run whose exit code is outside the scenario's
    expected set; nothing after it runs. One exception: a baseline (any build but the
    tip) that answers the warm-up run with the usage-error code does not know the
    command line, which is what an older release does for a flag added since. It is
    left out of this scenario and its entry in the result is an empty list; the tip
    must always run.
    """
    by_label = {build.label: build for build in builds}
    for build in builds:
        prepare(build.root, scenario)
    samples: dict[str, list[Sample]] = {build.label: [] for build in builds}
    timed = list(builds)
    try:
        for build in builds:  # the warm-up round, discarded
            argv = [*build.ash, *scenario.args]
            warm = _run_once(argv, build.root)
            if (
                build.label != tip_label
                and warm.returncode == USAGE_ERROR
                and USAGE_ERROR not in scenario.expected
            ):
                timed.remove(build)
                continue
            _check(warm, scenario, build, argv)
        for label in alternation_order([b.label for b in timed], repeats):
            build = by_label[label]
            argv = [*build.ash, *scenario.args]
            sample = _run_once(argv, build.root)
            _check(sample, scenario, build, argv)
            samples[label].append(sample)
    finally:
        if scenario.express:
            for build in builds:
                subprocess.run(
                    [*build.ash, "express", "stop"],
                    cwd=build.root,
                    env={**os.environ, **GIT_ISOLATION},
                    check=False,
                    capture_output=True,
                )
    return samples


def summarize(values: Sequence[float]) -> Stats:
    return Stats(
        min=min(values),
        median=statistics.median(values),
        mean=statistics.fmean(values),
        max=max(values),
    )


def slower(
    base: Stats,
    head: Stats,
    relative: float = WARN_RELATIVE,
    absolute: float = WARN_ABSOLUTE_SECONDS,
) -> bool:
    """True when head is slower in the sense the soft warning means.

    The head median is more than ``relative`` and more than ``absolute`` seconds
    above the base median, and the head minimum is above the base minimum: timing
    noise is additive, so a median that moved while the minimum did not is noise.
    """
    return (
        head.median > base.median * (1 + relative)
        and head.median - base.median > absolute
        and head.min > base.min
    )


def make_record(build: Build, scenario: Scenario, samples: Sequence[Sample]) -> dict:
    stats = summarize([s.seconds for s in samples])
    return {
        "build": build.label,
        "commit": build.commit,
        "ref": build.ref,
        "scenario": scenario.name,
        "runs": [round(s.seconds, 4) for s in samples],
        "returncodes": [s.returncode for s in samples],
        "loadavg": [
            None if s.loadavg is None else round(s.loadavg, 2) for s in samples
        ],
        "min": round(stats.min, 4),
        "median": round(stats.median, 4),
        "mean": round(stats.mean, 4),
        "max": round(stats.max, 4),
    }


def make_comparison(base: dict, head: dict) -> dict:
    """The tip (``head``) against one baseline build, for one scenario."""
    base_stats = Stats(base["min"], base["median"], base["mean"], base["max"])
    head_stats = Stats(head["min"], head["median"], head["mean"], head["max"])
    median_delta = head["median"] - base["median"]
    return {
        "baseline": base["build"],
        "scenario": head["scenario"],
        "median_delta": round(median_delta, 4),
        "min_delta": round(head["min"] - base["min"], 4),
        "median_percent": (
            round(100 * median_delta / base["median"], 1) if base["median"] else None
        ),
        "warning": slower(base_stats, head_stats),
    }


def format_summary(report: dict) -> str:
    """Markdown for the job's step summary."""
    lines = [
        "### ASH scan-time benchmark",
        "",
        (
            "Informational only: this job never fails a pull request. Each scenario "
            f"ran {report['repeats']} times per build after one discarded warm-up "
            "round, alternating builds on one runner. The minimum is the steadiest "
            "figure on a shared runner; the median is the typical case. Seconds."
        ),
        "",
        "| Scenario | Build | Commit | min | median | mean | max | exit codes |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for rec in report["results"]:
        codes = ",".join(str(c) for c in sorted(set(rec["returncodes"])))
        ref = f"{rec['ref']} " if rec.get("ref") else ""
        lines.append(
            f"| {rec['scenario']} | {rec['build']} | {ref}`{rec['commit'][:12]}` | "
            f"{rec['min']:.3f} | {rec['median']:.3f} | {rec['mean']:.3f} | "
            f"{rec['max']:.3f} | {codes} |"
        )
    comparisons = report.get("comparisons") or []
    if comparisons:
        lines += [
            "",
            (
                "| Scenario | Against | median, tip minus baseline | "
                "min, tip minus baseline | note |"
            ),
            "|---|---|---|---|---|",
        ]
        for cmp in comparisons:
            percent = cmp["median_percent"]
            pct = "" if percent is None else f" ({percent:+.1f}%)"
            note = (
                "WARNING: the tip looks slower (median over +10% and +0.2 s, min up too)"
                if cmp["warning"]
                else ""
            )
            lines.append(
                f"| {cmp['scenario']} | {cmp['baseline']} | "
                f"{cmp['median_delta']:+.3f}{pct} | {cmp['min_delta']:+.3f} | {note} |"
            )
        if any(c["warning"] for c in comparisons):
            lines += [
                "",
                (
                    "A warning is a prompt to look, not a verdict: runners are "
                    "shared and this job is not a gate."
                ),
            ]
    for item in report.get("unsupported") or []:
        lines += [
            "",
            (
                f"Not measured: {item['scenario']} on the {item['build']} build, which "
                "does not accept that command line (an older release lacks a flag "
                "added since)."
            ),
        ]
    load = report.get("load")
    if load and load.get("max_per_cpu") is not None:
        busy = " (above 1: read these figures with care)" if load["busy"] else ""
        lines += [
            "",
            (
                f"Host: {report['host']['cpus']} CPUs, highest load average per "
                f"CPU {load['max_per_cpu']:.2f}{busy}."
            ),
        ]
    return "\n".join(lines) + "\n"


def trend_line(report: dict, date: str) -> dict:
    """One trend entry: the tip's statistics per scenario, then each baseline's.

    The first three keys are the shape every earlier line has. ``baselines`` holds,
    per baseline label, its commit, its ref (a release tag, say), its statistics and
    the tip's median and min minus its own.
    """
    stat_keys = ("min", "median", "mean", "max")
    heads = [r for r in report["results"] if r["build"] == "head"]
    line: dict = {
        "date": date,
        "commit": heads[0]["commit"] if heads else None,
        "scenarios": {r["scenario"]: {k: r[k] for k in stat_keys} for r in heads},
        "baselines": {},
    }
    for rec in report["results"]:
        if rec["build"] == "head":
            continue
        entry = line["baselines"].setdefault(
            rec["build"],
            {"commit": rec["commit"], "ref": rec.get("ref", ""), "scenarios": {}},
        )
        entry["scenarios"][rec["scenario"]] = {k: rec[k] for k in stat_keys}
    for cmp in report.get("comparisons") or []:
        scenario = line["baselines"][cmp["baseline"]]["scenarios"][cmp["scenario"]]
        scenario["tip_minus_median"] = cmp["median_delta"]
        scenario["tip_minus_min"] = cmp["min_delta"]
    skipped: dict[str, list[str]] = {}
    for item in report.get("unsupported") or []:
        skipped.setdefault(item["build"], []).append(item["scenario"])
    line["not_measured"] = skipped
    return line


def append_trend(previous: Path | None, out: Path, line: dict) -> None:
    """Write ``previous`` (when it exists) plus ``line`` to ``out``, one JSON per line."""
    text = ""
    if previous is not None and previous.is_file():
        text = previous.read_text(encoding="utf-8")
        if text and not text.endswith("\n"):
            text += "\n"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text + json.dumps(line, sort_keys=True) + "\n", encoding="utf-8")


# --- command line ----------------------------------------------------------------


def _positive_int(text: str) -> int:
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError(f"must be at least 1, got {value}")
    return value


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("kind", choices=["small", "large", "bench"])
    parser.add_argument(
        "dest", type=Path, help="empty directory to build the fixture in"
    )
    parser.add_argument(
        "--ash", default="ash", help="the ash executable to time (the tip)"
    )
    parser.add_argument("--commit", default="unknown", help="commit of the --ash build")
    parser.add_argument(
        "--baseline",
        nargs=4,
        action="append",
        default=[],
        metavar=("LABEL", "ASH", "COMMIT", "REF"),
        help=(
            "a baseline build to time against the tip, alternating with it: its "
            "label (prev-commit, prev-release), its ash executable, its commit and "
            "a name for it such as a release tag (may be empty); repeatable"
        ),
    )
    parser.add_argument("--repeats", type=_positive_int, default=3)
    parser.add_argument(
        "--only",
        action="append",
        default=[],
        metavar="SCENARIO",
        help="run only this scenario (repeatable); default is all of the kind's",
    )
    parser.add_argument(
        "--allow-busy",
        action="store_true",
        help="time the host even when its load average per CPU is above 1",
    )
    parser.add_argument(
        "--build-only",
        action="store_true",
        help="build and print the digest; time nothing",
    )
    parser.add_argument("--json", type=Path, help="write the report here")
    parser.add_argument("--summary", type=Path, help="append the Markdown summary here")
    parser.add_argument("--trend-in", type=Path, help="previous trend file, if any")
    parser.add_argument("--trend-out", type=Path, help="write the trend file here")
    return parser


def _version(build: Build) -> str:
    argv = [*build.ash, "--version"]
    proc = subprocess.run(
        argv,
        cwd=build.root,
        env={**os.environ, **GIT_ISOLATION},
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise BadExit(
            f"{' '.join(argv)} on the {build.label} build exited {proc.returncode}\n"
            f"stderr: {proc.stderr.strip()[:STDERR_KEPT] or '(none)'}"
        )
    return proc.stdout.strip() or proc.stderr.strip()


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    scenarios = BENCH_SCENARIOS if args.kind == "bench" else row_scenarios(args.kind)
    if args.only:
        known = {s.name for s in scenarios}
        unknown = [name for name in args.only if name not in known]
        if unknown:
            parser.error(
                f"unknown scenario {unknown[0]!r}; choose from {sorted(known)}"
            )
        scenarios = tuple(s for s in scenarios if s.name in args.only)

    labels = [label for label, *_ in args.baseline]
    if len(set(labels)) != len(labels) or "head" in labels:
        parser.error("baseline labels must be distinct and not 'head'")
    if args.baseline:
        roots = {label: args.dest / label for label in [*labels, "head"]}
    else:
        roots = {"head": args.dest}
    for label, root in roots.items():
        files = build_fixture(root, args.kind)
        init_repository(root)
        print(
            f"fixture={args.kind} build={label} python_files={len(files)} "
            f"digest={fixture_digest(root)}"
        )
    if args.build_only:
        return 0

    cpus = os.cpu_count() or 1
    load_before = current_loadavg()
    busy = host_is_busy(load_before, cpus)
    if busy and not args.allow_busy:
        print(
            f"refusing to time a busy host: load average {load_before:.1f} on {cpus} "
            f"CPUs is above {LOAD_REFUSE_RATIO:g} per CPU (--allow-busy times it anyway)",
            file=sys.stderr,
        )
        return 3

    builds = [
        Build(label, [ash], roots[label], commit, ref)
        for label, ash, commit, ref in args.baseline
    ]
    builds.append(Build("head", [args.ash], roots["head"], args.commit))
    try:
        versions = {b.label: _version(b) for b in builds}
        results: list[dict] = []
        unsupported: list[dict] = []
        loads: list[float] = []
        for scenario in scenarios:
            samples = collect(builds, scenario, args.repeats)
            for build in builds:
                if not samples[build.label]:
                    unsupported.append(
                        {"build": build.label, "scenario": scenario.name}
                    )
                    continue
                results.append(make_record(build, scenario, samples[build.label]))
                loads += [
                    s.loadavg for s in samples[build.label] if s.loadavg is not None
                ]
    except BadExit as error:
        print(f"stopping: {error}", file=sys.stderr)
        return 1

    comparisons = []
    for label in labels:
        for scenario in scenarios:
            pair = {r["build"]: r for r in results if r["scenario"] == scenario.name}
            if label in pair:
                comparisons.append(make_comparison(pair[label], pair["head"]))
    max_per_cpu = max(loads) / cpus if loads else None
    report = {
        "schema": 1,
        "repeats": args.repeats,
        "host": {
            "node": platform.node(),
            "machine": platform.machine(),
            "python": sys.version.split()[0],
            "cpus": cpus,
        },
        "ash": versions,
        "load": {
            "before": load_before,
            "max_per_cpu": max_per_cpu,
            "busy": busy
            or (max_per_cpu is not None and max_per_cpu > LOAD_REFUSE_RATIO),
        },
        "results": results,
        "comparisons": comparisons,
        "unsupported": unsupported,
    }

    print(
        f"host={report['host']['node']} machine={report['host']['machine']} "
        f"python={report['host']['python']} cpus={cpus}"
    )
    for label, version in versions.items():
        print(f"ash[{label}]={version}")
    for rec in results:
        print(
            f"{rec['median']:7.3f} s median (min {rec['min']:.3f}, mean "
            f"{rec['mean']:.3f}, max {rec['max']:.3f}, n={len(rec['runs'])}, "
            f"exit codes {sorted(set(rec['returncodes']))})  "
            f"[{rec['build']}] {rec['scenario']}"
        )
    for item in unsupported:
        print(
            f"not measured: [{item['build']}] {item['scenario']} (the build does not "
            "accept this command line)"
        )
    for cmp in comparisons:
        if cmp["warning"]:
            print(
                f"WARNING: {cmp['scenario']}: the tip's median is "
                f"{cmp['median_delta']:+.3f} s from {cmp['baseline']} and its minimum "
                "is up too (informational, not a failure)"
            )
    if max_per_cpu is not None and max_per_cpu > LOAD_REFUSE_RATIO:
        print(f"note: load average per CPU reached {max_per_cpu:.2f} during the run")

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if args.summary:
        with args.summary.open("a", encoding="utf-8") as handle:
            handle.write(format_summary(report))
    if args.trend_out:
        today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        append_trend(args.trend_in, args.trend_out, trend_line(report, today))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
