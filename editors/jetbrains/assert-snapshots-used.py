#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Fails on a snapshot file that no test asserted in the run that just finished.

WHY THIS EXISTS

A snapshot nobody asserts any more still looks like coverage in a review: the file is there,
it reads like the plugin's output, and nothing fails when the output it describes changes. core
ASH's syrupy suite fails the session for an unused snapshot of a module it collected, and its
check-snapshot-trailers.py --orphans covers a deleted module. This is the same rule for the
JetBrains plugin's snapshots, structural and visual, done the one way that covers both cases at
once: the snapshot helpers append the id of every snapshot they compare to a usage file, and
every file under the snapshot directory must appear in it.

A failed assertion is still recorded as used, so a failing test is reported once, by the test,
and not a second time here as an orphan pointing at the file the test is about.

It is only meaningful after a FULL run of the suite. A filtered run (`--tests X`) asserts a
subset and every other snapshot would be reported. Gradle runs this from `check`, where
assert-tests-ran.py also runs and fails a filtered run on its own terms.

REFUSED

  * a file under --snapshot-dir that is not in the usage list;
  * an empty directory under --snapshot-dir, which is what a deleted snapshot leaves locally;
  * a missing usage file, because that means the suite did not run (or ran with a helper that
    records nothing), and "nothing recorded, nothing compared" must not read as clean.

USAGE

  python3 assert-snapshots-used.py --snapshot-dir src/test/snapshots/__snapshots__ \\
      --usage build/snapshot-usage/test.txt [--delete-unused]
  python3 assert-snapshots-used.py --self-test

--delete-unused is what `-Psnapshot-update` passes: the unused files are removed and listed,
the same as syrupy's update, and the run still exits 0 so the developer can review `git status`.

Standard library only. Exit codes: 0 pass, 1 an unused snapshot or no usage file.
"""

from __future__ import annotations

import argparse
import pathlib
import sys
import tempfile


def check(
    snapshot_dir: pathlib.Path, usage: pathlib.Path, delete_unused: bool
) -> list[str]:
    """The problems, as messages; empty when every snapshot file was asserted."""
    if not usage.is_file():
        return [
            (
                f"no usage file at {usage}: the snapshot suite did not run, or ran without "
                f"recording what it compared, so no snapshot can be shown to be in use"
            )
        ]
    used = {
        line.strip()
        for line in usage.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    if not snapshot_dir.is_dir():
        return (
            []
            if not used
            else [
                f"{len(used)} snapshot(s) were asserted but {snapshot_dir} does not exist"
            ]
        )

    problems = []
    for path in sorted(snapshot_dir.rglob("*")):
        rel = path.relative_to(snapshot_dir).as_posix()
        if path.is_dir():
            if not any(p.is_file() for p in path.rglob("*")):
                if delete_unused:
                    print(f"removed empty snapshot directory {rel}/")
                else:
                    problems.append(
                        f"{snapshot_dir.as_posix()}/{rel}/ is empty; delete it"
                    )
            continue
        if rel in used:
            continue
        if delete_unused:
            path.unlink()
            print(f"removed unused snapshot {rel}")
        else:
            problems.append(
                f"{snapshot_dir.as_posix()}/{rel} is not asserted by any test. Delete it (or run "
                f"the suite with -Psnapshot-update, which deletes it) and commit with a "
                f"'Snapshot-Update: <reason>' trailer."
            )
    if delete_unused:
        # Bottom-up, so a directory emptied by the deletions above goes too.
        for path in sorted(
            snapshot_dir.rglob("*"), key=lambda p: len(p.parts), reverse=True
        ):
            if path.is_dir() and not any(path.iterdir()):
                path.rmdir()
    return problems


def self_test() -> int:
    failures = []
    with tempfile.TemporaryDirectory(prefix="snapshots-used-") as tmp:
        root = pathlib.Path(tmp)
        snaps = root / "__snapshots__"
        (snaps / "ATest").mkdir(parents=True)
        (snaps / "ATest/one.txt").write_text("x")
        (snaps / "ATest/two.png").write_text("x")
        usage = root / "usage.txt"
        usage.write_text("ATest/one.txt\nATest/two.png\n")
        if got := check(snaps, usage, False):
            failures.append(f"clean tree reported: {got}")
        (snaps / "Gone").mkdir()
        (snaps / "Gone/old.txt").write_text("x")
        (snaps / "Empty").mkdir()
        dirty = "\n".join(check(snaps, usage, False))
        for expected in ("Gone/old.txt is not asserted", "Empty/ is empty"):
            if expected not in dirty:
                failures.append(f"missed {expected!r}: {dirty}")
        if not check(snaps, root / "absent.txt", False):
            failures.append("a missing usage file passed")
        if got := check(snaps, usage, True):
            failures.append(f"--delete-unused still reported: {got}")
        if (snaps / "Gone").exists() or (snaps / "Empty").exists():
            failures.append(
                "--delete-unused left the unused files or their directories"
            )
        if not (snaps / "ATest/one.txt").exists():
            failures.append("--delete-unused removed a used snapshot")
    for failure in failures:
        print(f"self-test: {failure}", file=sys.stderr)
    print(f"assert-snapshots-used self-test: {len(failures)} failure(s)")
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--snapshot-dir", type=pathlib.Path)
    parser.add_argument("--usage", type=pathlib.Path)
    parser.add_argument("--delete-unused", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    opts = parser.parse_args(argv)
    if opts.self_test:
        return self_test()
    if not opts.snapshot_dir or not opts.usage:
        parser.error("--snapshot-dir and --usage are required")
    problems = check(opts.snapshot_dir, opts.usage, opts.delete_unused)
    for problem in problems:
        print(f"unused snapshot: {problem}", file=sys.stderr)
    count = (
        len(opts.usage.read_text(encoding="utf-8").splitlines())
        if opts.usage.is_file()
        else 0
    )
    print(f"snapshot usage: {count} assertion(s) recorded, {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
