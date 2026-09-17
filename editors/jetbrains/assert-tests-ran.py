#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Asserts the plugin's test suite actually ran, and that every compiled test reported.

WHY THIS EXISTS AS A SEPARATE CHECK

A Gradle test task with no tests SUCCEEDS. That much was expected, and the task carries a
doLast that fails on a zero test count.

The doLast is not sufficient, and this file exists because a negative control proved it. With
the test sources moved aside, Gradle reported:

    > Task :unitTest NO-SOURCE
    BUILD SUCCESSFUL

A task Gradle skips as NO-SOURCE never runs its actions, so the in-task guard was never
reached and the build was green with zero tests -- exactly the silent pass the guard was
written to prevent, in the one case the guard could not see. That is the whole argument for
observing a gate fail before trusting it.

So the check has to live outside the task, and it has to be reachable from `check` whether or
not the task ran. It reads two artifacts and compares them:

  * the JUnit XML results, which exist only if a test JVM started; and
  * the compiled test classes, which exist only if there were test sources.

Comparing them closes the stale-artifact hole as well. A results directory left over from an
earlier run would satisfy a check that only looked for XML, and after the test sources are
removed `compileTestJava` removes their .class files -- so a compiled-class count of zero
fails even when yesterday's XML is still on disk.

WHAT ELSE IS REFUSED, AND WHY EACH ONE IS NOT PEDANTRY

  * Any failure or error. Obvious, and here so this script is the single place the suite's
    verdict is read.
  * Any SKIPPED test. Nothing in this suite is conditional: there are no assumptions and no
    disabled tests. A skipped test is a test that cannot fail, so a skip means something
    changed and is worth a red build rather than a line in a report nobody opens.
  * A compiled test class with no corresponding suite in the results. This is the shape of
    failure a filter typo produces: `--tests '*Anotation*'` runs a subset, reports green, and
    looks identical to a full run in every summary line.
  * The absence of the one class whose assertion cannot be satisfied by a silent scan, named
    by --require-suite.

USAGE

  python3 assert-tests-ran.py \
      --results build/test-results/unitTest \
      --test-classes build/classes/java/test \
      --require-suite io.github.awslabs.ash.jetbrains.AnnotationCountTest

Exit codes: 0 pass, 1 the suite did not run as expected.
"""

from __future__ import annotations

import argparse
import pathlib
import sys
import xml.etree.ElementTree as ElementTree


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", required=True)
    parser.add_argument("--test-classes", required=True)
    parser.add_argument("--require-suite", action="append", default=[])
    return parser.parse_args(argv)


def compiled_test_suites(test_classes: pathlib.Path) -> set[str]:
    """The fully-qualified names of the compiled top-level test classes.

    Nested classes are excluded: JUnit reports a nested test class inside its outer class's
    suite, so counting them would demand result files that never exist. Helper classes without
    "Test" in the name are excluded for the same reason -- Fixtures.java compiles and reports
    nothing.
    """
    suites: set[str] = set()
    for path in test_classes.rglob("*.class"):
        name = path.stem
        if "$" in name or not name.endswith("Test"):
            continue
        package = path.parent.relative_to(test_classes).as_posix().replace("/", ".")
        suites.add(f"{package}.{name}" if package != "." else name)
    return suites


def main(argv: list[str]) -> int:
    args = parse_args(argv[1:])
    here = pathlib.Path(__file__).resolve().parent
    results_dir = (here / args.results).resolve()
    test_classes = (here / args.test_classes).resolve()

    problems: list[str] = []

    compiled = compiled_test_suites(test_classes) if test_classes.is_dir() else set()
    if not compiled:
        problems.append(
            f"no compiled test classes under {test_classes}. Either there are no test sources, "
            "or compileTestJava did not run. A test task with no sources is skipped as "
            "NO-SOURCE and reports success, which is why this is checked from outside the task."
        )

    result_files = sorted(results_dir.glob("TEST-*.xml")) if results_dir.is_dir() else []
    if not result_files:
        problems.append(
            f"no JUnit XML results under {results_dir}. No test JVM started, so nothing was "
            "verified. That is a failure and not a skip."
        )

    tests = failures = errors = skipped = 0
    reported: set[str] = set()
    for path in result_files:
        # The file was written by Gradle's own test listener moments ago. It is read with the
        # stdlib parser and no entity handling; assert-coverage.py carries the longer note on
        # why defusedxml is not a dependency of this directory.
        root = ElementTree.fromstring(path.read_text(encoding="utf-8"))  # noqa: S314
        tests += int(root.get("tests", "0"))
        failures += int(root.get("failures", "0"))
        errors += int(root.get("errors", "0"))
        skipped += int(root.get("skipped", "0"))
        reported.add(root.get("name", ""))

    print(
        f"tests: {tests} run, {failures} failed, {errors} errored, {skipped} skipped, "
        f"across {len(reported)} suite(s)"
    )

    if tests == 0 and result_files:
        problems.append("0 tests ran. A suite that cannot fail passes.")
    if failures or errors:
        problems.append(f"{failures} failed and {errors} errored")
    if skipped:
        problems.append(
            f"{skipped} test(s) skipped, and nothing in this suite is meant to be conditional. "
            "A skipped test is a test that cannot fail."
        )

    missing = sorted(compiled - reported)
    if missing:
        problems.append(
            "compiled but reported no results: "
            + ", ".join(missing)
            + ". A filter typo runs a subset, reports green, and looks identical to a full run."
        )

    for required in args.require_suite:
        if required not in reported:
            problems.append(
                f"{required} did not run. That is the class asserting a NON-ZERO number of "
                "annotations from a planted secret, which is the only assertion here that a "
                "silent scan cannot satisfy."
            )

    if problems:
        sys.stderr.write("Test-run check failed:\n")
        for problem in problems:
            sys.stderr.write(f"  - {problem}\n")
        return 1

    print(f"  OK: every compiled suite reported, including {len(args.require_suite)} required")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
