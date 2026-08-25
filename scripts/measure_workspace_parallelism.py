# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Measure what a workspace scan costs against one project scanned alone.

Run with: python scripts/measure_workspace_parallelism.py

Not a CI gate. Wall-clock numbers from a shared developer host or a burstable
runner are not stable enough to fail a build on, and a timing assertion that
flakes gets deleted rather than investigated. This is a manual tool that prints
evidence, and the numbers it produces belong in a document with the host and the
date beside them.

What is being measured, and why the question is subtler than it looks
--------------------------------------------------------------------
The RFC's acceptance criterion was "a 5-project workspace completes in under 1.5x
the wall clock of the slowest project scanned alone". Taking that at face value
produced a number nobody could reproduce, for two reasons that this script exists
to remove.

**The arithmetic sets a floor the implementation cannot go below.** Projects run
on a pool of ``max_parallel_projects`` workers, so the wall clock is
``ceil(N / bound)`` waves of work. Five equal projects at the default bound of 4
is two waves, so the ratio cannot be better than about 2.0 however good the
implementation is. A measured 2.35x at bound 4 is therefore mostly arithmetic and
only slightly overhead; reporting it as though the code were slow would send
someone optimising a wave count. The script prints the floor next to the
measurement so the two are never confused.

**Cache state silently decides the answer.** ``uv_tool_runner`` caches tool
probing across invocations, so the first scan in a process tree pays for
discovery and later ones do not. An earlier measurement ran the single-project arm
first, cold, and the workspace arm second, warm, and reported **0.883x** -- a
five-project workspace apparently finishing faster than one project alone. That is
not a plausible result, and it was withdrawn. It was an artefact of measuring a
cold arm against a warm one.

So this script:

* runs a full discard pass before timing anything, so neither arm is the one that
  pays for a cold cache;
* alternates the arms within each repetition, so any residual drift over the run
  lands on both;
* repeats, and reports min/median/max per arm rather than a single number;
* computes the ratio from medians, and also prints the ratio's own range, because
  a median ratio with a wide spread is a different claim from a tight one.

Which span is timed
-------------------
The **whole child process**, from ``subprocess.run`` entry to exit: interpreter
startup, plugin discovery, config resolution, the scan itself, and writing
results. That is deliberately the widest span, because it is the one a user
experiences, and because a narrower span would flatter the workspace arm -- the
per-project fixed costs are exactly what running N projects multiplies. It also
means the numbers are not a scan-phase microbenchmark and should not be quoted as
one.

Two fixture shapes, because they answer different questions
-----------------------------------------------------------
* ``equal`` -- N identically-sized projects. "The slowest project alone" is any
  one of them, so the ratio is dominated by the wave count. This is the shape that
  shows the arithmetic floor.
* ``dominant`` -- one project with many more files plus N-1 small ones. "The
  slowest project alone" is the large one, and the small projects can hide inside
  its wave. This is the shape where a ratio near 1.5x is achievable at all, and
  the one the RFC's criterion is really about.

Reporting both is the honest treatment: the criterion is reachable for one shape
and arithmetically impossible for the other, and which shape a user has is not
something the implementation controls.

The ``dominant`` shape does not currently achieve what it is for
---------------------------------------------------------------
Measured on a 192-CPU Linux host on 2026-08-25: the large project's 60 files
took 20.7s and a small project's 12 files took 21.3s. Five times the input, no
measurable difference. Wall clock here is dominated by per-scanner startup, not
by how much code there is to read, so ``--files-per-project 12`` produces no
dominant project and the shape degenerates into ``equal`` with a lopsided file
count.

That is a limitation of the fixture, not a finding about the implementation, and
it is recorded rather than quietly left because the shape's whole purpose is to
be the case where a ratio near 1.5x is reachable. Making it real means a project
big enough to be file-bound instead of startup-bound -- thousands of files, which
is minutes per run and a different tool from this one. Until then, treat the
``dominant`` number as a second sample of ``equal`` rather than as evidence about
uneven workspaces.

Known limitations
-----------------
* One host, one run. Nothing here corrects for other load on the machine, and a
  developer host running a build in another window will show it. The spread is
  printed so a contaminated run is visible rather than averaged away.
* The ``dominant`` shape does not yet produce a dominant project; see above.
* The discard pass warms the tool cache, not the filesystem cache, and not any
  state inside a scanner's own cache directory.
* ``MISSING`` scanners cost nothing. A host with more scanner tools installed will
  show larger absolute times in both arms; the ratio is the portable part.
* The projects are Python-and-Terraform only, so the mix of scanners is not
  representative of a polyglot workspace.
"""

from __future__ import annotations

import argparse
import json
import shutil
import statistics
import subprocess  # nosec B404 -- this tool runs ASH as a child process to time it
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

WORKSPACE_FILENAME = "measure.code-workspace"

#: Fixture source, written to a temporary directory and scanned. It is never
#: imported and never executed -- the point is for scanners to find something, so
#: that a timed scan is timing real work rather than an empty tree.
#:
#: The ``md5`` and ``eval`` calls are deliberate findings, not a vulnerability in
#: this script: they exist inside a string constant, so nothing here evaluates
#: anything. bandit parses an AST, which is why a string constant in this module
#: is not itself a finding while the generated file is. Same construction as
#: ``scripts/verify_external_target_scan.py``. No credential-shaped literal
#: appears, because detect-secrets matches line by line and this repository
#: self-scans.
SAMPLE_PYTHON = '''"""Measurement fixture only -- never imported, never executed."""

import hashlib


def weak_digest(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def evaluate(expression: str):
    return eval(expression)
'''

SAMPLE_TERRAFORM = """resource "aws_s3_bucket" "measurement_fixture_{index}" {{
  bucket = "ash-workspace-measurement-{index}"
}}
"""

PROJECT_CONFIG = """project_name: {name}
global_settings:
  severity_threshold: MEDIUM
"""

WORKSPACE_CONFIG = """project_name: measurement-workspace
workspace:
  max_parallel_projects: {bound}
"""


@dataclass(frozen=True)
class Arm:
    """One thing being timed, and the samples collected for it."""

    label: str
    command: List[str]
    samples: List[float]

    def summary(self) -> Dict[str, float]:
        return {
            "min": min(self.samples),
            "median": statistics.median(self.samples),
            "max": max(self.samples),
        }


def write_project(project_dir: Path, name: str, file_count: int) -> None:
    """One project with ``file_count`` scannable Python files plus one .tf."""
    source = project_dir / "src"
    source.mkdir(parents=True, exist_ok=True)
    for index in range(file_count):
        (source / f"module_{index:03d}.py").write_text(SAMPLE_PYTHON, encoding="utf-8")
    (source / "main.tf").write_text(
        SAMPLE_TERRAFORM.format(index=name.replace("-", "_")), encoding="utf-8"
    )
    config_dir = project_dir / ".ash"
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "ash.yaml").write_text(
        PROJECT_CONFIG.format(name=name), encoding="utf-8"
    )


def write_fixture(
    workspace_root: Path, project_count: int, shape: str, bound: int, unit_files: int
) -> tuple[Path, str]:
    """Build the workspace and return its definition path and slowest project key.

    ``dominant`` gives the first project ``project_count`` times as many files as
    each of the others, so that one project genuinely dominates the wall clock and
    "the slowest project alone" names something specific. ``equal`` gives every
    project the same size, which makes the wave count the whole story.
    """
    workspace_root.mkdir(parents=True, exist_ok=True)
    keys = [f"project-{index}" for index in range(project_count)]

    for position, key in enumerate(keys):
        if shape == "dominant" and position == 0:
            file_count = unit_files * project_count
        else:
            file_count = unit_files
        write_project(workspace_root / key, key, file_count)

    root_config = workspace_root / ".ash"
    root_config.mkdir(parents=True, exist_ok=True)
    (root_config / "ash.yaml").write_text(
        WORKSPACE_CONFIG.format(bound=bound), encoding="utf-8"
    )

    definition = workspace_root / WORKSPACE_FILENAME
    definition.write_text(
        json.dumps({"folders": [{"path": key} for key in keys]}, indent=2),
        encoding="utf-8",
    )
    # With 'equal' every project is the same size, so the slowest is arbitrary and
    # the first one speaks for all of them.
    return definition, keys[0]


def single_project_command(project_dir: Path, output_dir: Path) -> List[str]:
    return [
        sys.executable,
        "-m",
        "automated_security_helper.cli.main",
        "scan",
        "--source-dir",
        str(project_dir),
        "--output-dir",
        str(output_dir),
        "--phases",
        "scan",
        "--no-progress",
        "--simple",
    ]


def workspace_command(definition: Path, output_dir: Path) -> List[str]:
    return [
        sys.executable,
        "-m",
        "automated_security_helper.cli.main",
        "scan",
        "--workspace",
        str(definition),
        "--output-dir",
        str(output_dir),
        "--phases",
        "scan",
        "--no-progress",
        "--simple",
    ]


def time_once(command: Sequence[str], repo_root: Path, output_dir: Path) -> float:
    """Wall clock for one child process, in seconds.

    The output directory is removed first so no run is credited with reusing
    another's results, and ``cwd`` is the repository root so ``-m`` runs the
    working tree rather than an installed copy.
    """
    shutil.rmtree(output_dir, ignore_errors=True)
    output_dir.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    completed = subprocess.run(  # nosec B603 -- list args, no shell, argv[0] is sys.executable
        list(command),
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        errors="replace",
        check=False,
    )
    elapsed = time.monotonic() - started
    # A scan that failed outright is not a timing sample. Exit 2 is findings above
    # threshold, which is the expected outcome for this fixture.
    if completed.returncode not in (0, 2):
        raise RuntimeError(
            f"a timed scan exited {completed.returncode}, so its duration is not a "
            f"measurement of a successful scan. stderr tail:\n"
            + "\n".join((completed.stderr or "").splitlines()[-20:])
        )
    return elapsed


def format_table(arms: Iterable[Arm]) -> str:
    """Plain ASCII: Windows consoles cannot encode box drawing."""
    rows = []
    for arm in arms:
        stats = arm.summary()
        rows.append(
            (
                arm.label,
                str(len(arm.samples)),
                f"{stats['min']:.1f}",
                f"{stats['median']:.1f}",
                f"{stats['max']:.1f}",
            )
        )
    headers = ("arm", "runs", "min s", "median s", "max s")
    widths = [
        max(len(headers[column]), *(len(row[column]) for row in rows))
        for column in range(len(headers))
    ]

    def render(values: Sequence[str]) -> str:
        cells = [values[0].ljust(widths[0])]
        cells.extend(
            values[column].rjust(widths[column]) for column in range(1, len(headers))
        )
        return "  ".join(cells).rstrip()

    lines = [render(headers), "  ".join("-" * width for width in widths)]
    lines.extend(render(row) for row in rows)
    return "\n".join(lines)


def _parse_args(argv: Iterable[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Time a workspace scan against one project scanned alone, with the "
            "tool cache warmed for both arms and the arms alternated."
        )
    )
    parser.add_argument("--projects", type=int, default=5)
    parser.add_argument(
        "--bound",
        type=int,
        default=4,
        help="max_parallel_projects (default 4, the shipped default)",
    )
    parser.add_argument(
        "--repetitions",
        type=int,
        default=3,
        help="timed runs per arm (default 3; a single run reports no spread)",
    )
    parser.add_argument(
        "--shape",
        choices=("equal", "dominant", "both"),
        default="both",
        help=(
            "equal: N same-sized projects, so the wave count dominates. "
            "dominant: one large project plus N-1 small, which is the shape the "
            "RFC's 1.5x criterion is about. Default runs both"
        ),
    )
    parser.add_argument(
        "--files-per-project",
        type=int,
        default=12,
        help="scannable Python files in a small project (default 12)",
    )
    parser.add_argument("--keep-temp", action="store_true")
    return parser.parse_args(list(argv) if argv is not None else None)


def measure_shape(
    repo_root: Path,
    temp_root: Path,
    shape: str,
    args: argparse.Namespace,
) -> Dict[str, object]:
    workspace_root = temp_root / f"workspace-{shape}"
    output_dir = temp_root / f"output-{shape}"
    definition, slowest_key = write_fixture(
        workspace_root, args.projects, shape, args.bound, args.files_per_project
    )

    single = single_project_command(workspace_root / slowest_key, output_dir)
    workspace = workspace_command(definition, output_dir)

    print(f"--- shape: {shape} ---")
    print(f"  workspace:        {workspace_root}")
    print(f"  slowest project:  {slowest_key}")
    print(
        "  discard pass to warm the tool cache, so neither arm is the cold one...",
        flush=True,
    )
    time_once(workspace, repo_root, output_dir)

    single_arm = Arm("one project alone", single, [])
    workspace_arm = Arm(f"{args.projects} projects, bound {args.bound}", workspace, [])

    for repetition in range(args.repetitions):
        # Alternate the order every repetition so drift over the run does not all
        # land on one arm.
        order = (
            (single_arm, workspace_arm)
            if repetition % 2 == 0
            else (workspace_arm, single_arm)
        )
        for arm in order:
            elapsed = time_once(arm.command, repo_root, output_dir)
            arm.samples.append(elapsed)
            # flush: a run takes minutes, and with stdout redirected to a file
            # Python block-buffers, so without this the log stays empty until the
            # very end and the tool looks hung.
            print(f"  rep {repetition + 1}: {arm.label} -> {elapsed:.1f}s", flush=True)

    single_stats = single_arm.summary()
    workspace_stats = workspace_arm.summary()
    ratio = workspace_stats["median"] / single_stats["median"]
    # The best any implementation can do at this bound: one wave per full pool.
    waves = -(-args.projects // args.bound)

    print()
    print(format_table((single_arm, workspace_arm)))
    print()
    print(f"  ratio of medians:      {ratio:.3f}x")
    print(
        f"  ratio range:           "
        f"{workspace_stats['min'] / single_stats['max']:.3f}x to "
        f"{workspace_stats['max'] / single_stats['min']:.3f}x"
    )
    print(
        f"  wave count:            ceil({args.projects}/{args.bound}) = {waves}, so "
        f"a lower bound near {waves:.1f}x for equally-sized projects"
    )
    print()
    return {
        "shape": shape,
        "single": single_stats,
        "workspace": workspace_stats,
        "ratio_of_medians": ratio,
        "waves": waves,
    }


def main(argv: Iterable[str] | None = None) -> int:
    args = _parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]
    temp_root = Path(tempfile.mkdtemp(prefix="ash-measure-parallelism-"))

    shapes = ("equal", "dominant") if args.shape == "both" else (args.shape,)

    print("ASH workspace parallelism measurement")
    print(f"  repository root (child cwd): {repo_root}")
    print(f"  projects:                    {args.projects}")
    print(f"  max_parallel_projects:       {args.bound}")
    print(f"  timed runs per arm:          {args.repetitions}")
    print("  timed span:                  whole child process, start to exit")
    print()

    try:
        results = [measure_shape(repo_root, temp_root, shape, args) for shape in shapes]
    except RuntimeError as failure:
        print(f"MEASUREMENT ABANDONED: {failure}")
        return 1
    finally:
        if args.keep_temp:
            print(f"temp kept at {temp_root}")
        else:
            shutil.rmtree(temp_root, ignore_errors=True)

    print("summary")
    for entry in results:
        print(
            f"  {entry['shape']:9} ratio {entry['ratio_of_medians']:.3f}x "
            f"(arithmetic floor about {entry['waves']:.1f}x for equal projects)"
        )
    print()
    print(
        "Quote these with the host and date attached. They are wall clock on one "
        "machine, not a portable benchmark."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
