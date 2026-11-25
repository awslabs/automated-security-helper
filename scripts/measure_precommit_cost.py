# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Build the pre-commit cost-table fixtures and time the warm hook runs on them.

Run with: python scripts/measure_precommit_cost.py --help

The "What it costs" table in docs/content/how-to/pre-commit.md compares a small
repository with a larger one. A timing column is only reproducible if the
repository it was timed on can be rebuilt, so both fixtures are generated here,
deterministically, from nothing but this file: the same call produces the same
bytes on every host, and ``fixture_digest`` fingerprints the result so a test can
pin it. The figures themselves are not pinned (wall-clock time is not stable
enough to fail a build on); they are labelled in the doc with the venue and the
date they were taken on.

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

The rows
--------
Each row is timed as the whole child process, warm: one discarded run first, then
``--repeats`` timed runs, and the median is reported. The ``--staged`` rows stage
one ``.py`` file with ``git add`` before the run and leave the fixture's commit
untouched.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path

SMALL_FILES = 10
LARGE_PACKAGES = 30
LARGE_MODULES_PER_PACKAGE = 30
LARGE_FILES = LARGE_PACKAGES * LARGE_MODULES_PER_PACKAGE

_GIT_ENV = {
    "GIT_AUTHOR_NAME": "fixture",
    "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
    "GIT_COMMITTER_NAME": "fixture",
    "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
    "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z",
    "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
}


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
        lines += ["", f'PASSWORD = "fixture-not-a-secret-{index:04d}"', ""]
    return "\n".join(lines)


def build_fixture(dest: Path, kind: str) -> list[Path]:
    """Write fixture ``kind`` ("small" or "large") under ``dest``; return the .py files.

    ``dest`` must be an empty or missing directory. No git state is created here;
    ``init_repository`` does that, so the bytes and the repository setup can be
    tested separately.
    """
    if kind not in ("small", "large"):
        raise ValueError(f"unknown fixture kind {kind!r}")
    dest.mkdir(parents=True, exist_ok=True)
    if any(dest.iterdir()):
        raise ValueError(f"{dest} is not empty")
    written: list[Path] = []
    if kind == "small":
        package = dest / "pkg"
        package.mkdir()
        (package / "__init__.py").write_text("", encoding="utf-8")
        written.append(package / "__init__.py")
        for module in range(SMALL_FILES - 1):
            path = package / f"mod_{module:02d}.py"
            path.write_text(_module_source(0, module), encoding="utf-8")
            written.append(path)
        return written
    (dest / "pyproject.toml").write_text(
        '[project]\nname = "cost-fixture"\nversion = "0.0.0"\n', encoding="utf-8"
    )
    (dest / "README.md").write_text("# Cost fixture\n", encoding="utf-8")
    for package_index in range(LARGE_PACKAGES):
        package = dest / f"pkg_{package_index:02d}"
        package.mkdir()
        for module in range(LARGE_MODULES_PER_PACKAGE):
            path = package / f"mod_{module:02d}.py"
            path.write_text(_module_source(package_index, module), encoding="utf-8")
            written.append(path)
    return written


def fixture_digest(root: Path) -> str:
    """SHA-256 over every file's relative path and bytes, in sorted path order.

    Skips ``.git`` so the digest depends on the generated content only.
    """
    digest = hashlib.sha256()
    for path in sorted(
        p for p in root.rglob("*") if p.is_file() and ".git" not in p.parts
    ):
        relative = path.relative_to(root).as_posix()
        digest.update(relative.encode() + b"\0")
        digest.update(path.read_bytes() + b"\0")
    return digest.hexdigest()


def init_repository(root: Path) -> None:
    """Make ``root`` a git repository with one commit holding the fixture."""
    env = {**os.environ, **_GIT_ENV}
    for argv in (
        ["git", "init", "-q", "-b", "main"],
        ["git", "add", "-A"],
        ["git", "commit", "-q", "-m", "fixture"],
    ):
        subprocess.run(argv, cwd=root, env=env, check=True, capture_output=True)


def _time_run(argv: list[str], cwd: Path) -> float:
    start = time.perf_counter()
    subprocess.run(argv, cwd=cwd, check=False, capture_output=True)
    return time.perf_counter() - start


def _median_of(argv: list[str], cwd: Path, repeats: int) -> float:
    _time_run(argv, cwd)  # discarded warm-up
    return statistics.median(_time_run(argv, cwd) for _ in range(repeats))


def measure(root: Path, ash: str, repeats: int, staged_file: Path) -> dict[str, float]:
    """Time the table's rows (except the express row) on the repository at ``root``."""
    base = [ash, "--mode", "precommit"]
    results = {"whole repository, no --staged": _median_of(base, root, repeats)}
    env = {**os.environ, **_GIT_ENV}
    # Touch one file and stage it; the run reads the staged list from git.
    staged_file.write_text(
        staged_file.read_text(encoding="utf-8") + "\n# touched\n", encoding="utf-8"
    )
    subprocess.run(
        ["git", "add", str(staged_file)],
        cwd=root,
        env=env,
        check=True,
        capture_output=True,
    )
    results["--staged, one .py file staged"] = _median_of(
        [*base, "--staged"], root, repeats
    )
    results["--staged, --only-scanners bandit,detect-secrets"] = _median_of(
        [*base, "--staged", "--only-scanners", "bandit,detect-secrets"], root, repeats
    )
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("kind", choices=["small", "large"])
    parser.add_argument(
        "dest", type=Path, help="empty directory to build the fixture in"
    )
    parser.add_argument("--ash", default="ash", help="the ash executable to time")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument(
        "--build-only",
        action="store_true",
        help="build and print the digest; time nothing",
    )
    args = parser.parse_args(argv)

    files = build_fixture(args.dest, args.kind)
    init_repository(args.dest)
    print(
        f"fixture={args.kind} python_files={len(files)} digest={fixture_digest(args.dest)}"
    )
    if args.build_only:
        return 0
    version = subprocess.run(
        [args.ash, "--version"], capture_output=True, text=True, check=False
    )
    print(
        f"host={platform.node()} machine={platform.machine()} python={sys.version.split()[0]}"
    )
    print(
        f"ash={version.stdout.strip() or version.stderr.strip()} cpus={os.cpu_count()}"
    )
    for label, seconds in measure(args.dest, args.ash, args.repeats, files[-1]).items():
        print(f"{seconds:6.1f} s  {label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
