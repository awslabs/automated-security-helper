#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Gates the JetBrains plugin's Java coverage, and audits what the gate does not cover.

WHY THIS EXISTS

The coverage standard this repository holds itself to names Python and TypeScript, each
gated independently at 90% and never blended. This plugin is a third language and the
standard did not mention it. That is not permission to ship ungated, so this script applies
the same 90% here and prints it as its own number. Nothing about it touches, reads or
contributes to anyone else's figure.

WHY A PERCENTAGE ALONE IS NOT THE GATE

Copied in reasoning, not in code, from the header comment of
.github/workflows/ash-typescript-ci.yml. A threshold can be satisfied by measuring less,
and the shrink looks like a config tidy-up in review. That workflow pairs its threshold with
assert-coverage-scope.mjs, which pins the file count and the statement denominator, and
assert-coverage-completeness.mjs, which takes a census from `git ls-files` and requires every
tracked production file to be either measured or named in an exclusions file with a reason.

The mechanism has to differ here because the tool differs, and getting that wrong would be
worse than not checking. jest omits source that no test imports from its report ENTIRELY, so
an unmeasured TypeScript file is invisible rather than visibly bad; that is the specific hole
assert-coverage-completeness.mjs was written to close. JaCoCo does not have that hole: it
enumerates the classes in classDirectories, so a class no test touches appears at 0%.

So the cheap way to game a JaCoCo gate is not a narrowed crawler root. It is a widened
exclusion pattern: one line in coverage-exclusions.json and the percentage rises with no test
written. Five checks follow from that, and the third is the one that matters most here:

  1. LINE and BRANCH coverage over the non-excluded classes, each at or above the minimum.
     Reported separately, never averaged.
  2. Floors on the number of measured classes and on the line denominator. Floors and not
     equalities, for the reason assert-coverage-scope.mjs gives: adding a class legitimately
     raises both and a floor does not need editing when it does, while removing one lowers
     them and fails.
  3. Every excluded class must be named in coverage-exclusions.json, and every entry there
     must still be true. An `ide-glue` entry carries a maxLines budget that is re-measured
     against the file, because an exclusion with no budget is a place to hide logic.
  4. A census from `git ls-files`, so a tracked source file that is in neither the report nor
     the exclusion list fails. This is the check JaCoCo makes cheap and not unnecessary: a
     class can still be absent from the report because it did not compile into the measured
     output directory at all.
  5. A missing or unparseable report is a failure, not a skip. "No report" and "a clean
     report" must not look the same, which is the failure mode this repository has hit
     repeatedly.

USAGE

  python3 assert-coverage.py \
    --report build/reports/jacoco/test/jacocoTestReport.xml \
    --exclusions coverage-exclusions.json \
    --source-root src/main/java \
    --repo-root ../.. \
    --min-line-ratio 0.90 --min-branch-ratio 0.90 \
    --min-classes 9 --min-lines 300

Exit codes: 0 pass, 1 a check failed, 2 the script could not run its checks at all.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import xml.etree.ElementTree as ElementTree

# Parsing goes through defusedxml. Only the reading entry point comes from it -- defusedxml
# does not re-export Element or ParseError, both of which are used below, so the stdlib module
# above stays imported for those. ParseError is the same class either way, so the except clause
# in load_report keeps working.
#
# The import is at module scope and has no fallback ON PURPOSE. If defusedxml is missing this
# gate must fail, not quietly parse with xml.etree and report a coverage verdict: a gate that
# degrades to a no-op when a dependency is unavailable still prints a pass, which is the exact
# failure this directory's checks exist to remove. verify-in-container.sh step 3 provisions it,
# because gradle:jdk21 has python3 and no package manager at all.
#
# Exit 2, not 1, per the code table in the docstring: this is "could not run its checks at
# all" rather than "a check failed". Written as a write-then-exit because sys.exit(str) sets
# the status to 1, which would report a missing parser as an ordinary coverage failure.
try:
    from defusedxml.ElementTree import fromstring
except ImportError:  # pragma: no cover - the message is the whole point
    sys.stderr.write(
        "assert-coverage.py needs defusedxml and it is not importable.\n"
        "This gate does not fall back to xml.etree, because a coverage gate that still\n"
        "prints a verdict after losing its XML parser is worse than one that stops.\n"
        "In CI, editors/jetbrains/verify-in-container.sh step 3 fetches the wheel and puts\n"
        "it on PYTHONPATH. To run the Gradle tasks by hand, do that step first, or run the\n"
        "whole script: bash editors/jetbrains/verify-in-container.sh\n"
    )
    sys.exit(2)

# Kinds a coverage-exclusions.json entry may declare. The kind selects the staleness test, so
# an unknown kind is a failure rather than a pass with no test run.
KIND_IDE_GLUE = "ide-glue"
KNOWN_KINDS = {KIND_IDE_GLUE}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True)
    parser.add_argument("--exclusions", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--min-line-ratio", type=float, required=True)
    parser.add_argument("--min-branch-ratio", type=float, required=True)
    parser.add_argument("--min-classes", type=int, required=True)
    parser.add_argument("--min-lines", type=int, required=True)
    return parser.parse_args(argv)


def load_report(path: pathlib.Path) -> ElementTree.Element:
    """Reads the JaCoCo XML report, treating absence as a failure rather than a skip."""
    if not path.exists():
        raise Failure(
            f"no coverage report at {path}.\n"
            "The suite either did not run or did not emit an XML report. That is a failure\n"
            "and not a skip: a gate that passes because it found nothing to check is the\n"
            "silent pass this whole branch exists to remove."
        )
    text = path.read_text(encoding="utf-8")

    # Refused before parsing, and it is the entity DECLARATION that is refused rather than the
    # doctype: JaCoCo's own report opens with
    # <!DOCTYPE report PUBLIC "-//JACOCO//DTD Report 1.1//EN" ...>, so rejecting every doctype
    # would reject every real report. Both attacks on a stdlib XML parser -- an external
    # entity reference and a recursive internal one -- need an <!ENTITY declaration, and
    # nothing JaCoCo writes has one.
    #
    # KEPT after the parser became defusedxml, which now refuses entities itself. Two reasons
    # to hold both rather than delete this as redundant. It is a control that works and needs
    # nothing fetched, so it still holds if the provisioning in verify-in-container.sh is ever
    # changed or reordered. And the two do not say the same thing: defusedxml raises
    # EntitiesForbidden, a parser error about a class of document, while this raises Failure
    # with the sentence a reader needs -- that JaCoCo does not write entities, so this file is
    # either not a JaCoCo report or has been altered. Measured, so the overlap is not assumed:
    # defusedxml's ElementTree defaults to forbid_dtd=False and forbid_entities=True, so a real
    # JaCoCo report with its DOCTYPE parses and a document carrying <!ENTITY does not.
    if "<!ENTITY" in text:
        raise Failure(
            f"{path} declares an XML entity. JaCoCo does not write one, so this is either not "
            "a JaCoCo report or has been altered."
        )

    try:
        return fromstring(text)
    except ElementTree.ParseError as error:
        raise Failure(f"{path} is not parseable XML: {error}") from error


class Failure(Exception):
    """A condition that stops the checks from being meaningful. Exit code 2."""


def counter(element: ElementTree.Element, kind: str) -> tuple[int, int]:
    """Returns (covered, missed) for a JaCoCo counter, or (0, 0) when it is absent.

    Absent is not the same as zero, and the difference matters for BRANCH: a class with no
    conditionals has no BRANCH counter at all, and treating that as 0-of-0 rather than as
    0-covered-of-something is what keeps such a class from dragging the ratio down.
    """
    for child in element.findall("counter"):
        if child.get("type") == kind:
            return int(child.get("covered", "0")), int(child.get("missed", "0"))
    return 0, 0


def ratio(covered: int, missed: int) -> float:
    total = covered + missed
    # A zero denominator returns 0.0 rather than 1.0. "Nothing to measure" must never read as
    # "everything is covered"; that is the vacuous pass this file is built to refuse.
    return 0.0 if total == 0 else covered / total


def main(argv: list[str]) -> int:
    args = parse_args(argv[1:])
    here = pathlib.Path(__file__).resolve().parent
    repo_root = (here / args.repo_root).resolve()
    report_path = (here / args.report).resolve()
    exclusions_path = (here / args.exclusions).resolve()

    report = load_report(report_path)
    exclusions = json.loads(exclusions_path.read_text(encoding="utf-8"))["exclusions"]

    for entry in exclusions:
        if entry.get("kind") not in KNOWN_KINDS:
            raise Failure(
                f"{exclusions_path.name} entry for {entry.get('path')} has kind "
                f"{entry.get('kind')!r}, which selects no staleness test. Add the kind to "
                "KNOWN_KINDS along with the test that makes it expire, or use an existing one."
            )
        if entry["kind"] == KIND_IDE_GLUE and "maxLines" not in entry:
            raise Failure(
                f"{exclusions_path.name} entry for {entry['path']} is {KIND_IDE_GLUE} with no "
                "maxLines. The budget is what stops the exclusion becoming a place to hide "
                "logic, so an entry without one is not a check."
            )
        if not entry.get("reason", "").strip():
            raise Failure(
                f"{exclusions_path.name} entry for {entry['path']} has no reason. The point of "
                "the file is that the claim is auditable and re-tested, not remembered."
            )

    problems: list[str] = []
    problems += check_coverage(report, exclusions, args)
    problems += check_exclusions_are_still_true(report, exclusions, repo_root)
    problems += check_census(report, exclusions, repo_root, args.source_root, here)

    if problems:
        sys.stderr.write("Coverage gate failed:\n")
        for problem in problems:
            sys.stderr.write(f"  - {problem}\n")
        return 1
    return 0


def excluded_patterns(exclusions: list[dict]) -> list[str]:
    return [entry["classPattern"] for entry in exclusions]


def is_excluded(class_name: str, exclusions: list[dict]) -> bool:
    for pattern in excluded_patterns(exclusions):
        if pattern.endswith("*"):
            if class_name.startswith(pattern[:-1]):
                return True
        elif class_name == pattern:
            return True
    return False


def measured_classes(report: ElementTree.Element) -> list[ElementTree.Element]:
    """Every class in the report, from every package."""
    classes: list[ElementTree.Element] = []
    for package in report.findall("package"):
        classes.extend(package.findall("class"))
    return classes


def class_name_of(element: ElementTree.Element) -> str:
    # JaCoCo writes the internal name with slashes, and a nested class with a dollar sign.
    # Both are converted so a pattern in the exclusions file can be written the way a Java
    # developer would write it.
    return element.get("name", "").replace("/", ".")


def check_coverage(
    report: ElementTree.Element, exclusions: list[dict], args: argparse.Namespace
) -> list[str]:
    """The threshold and the denominator floors, over the non-excluded classes only."""
    problems: list[str] = []
    line_covered = line_missed = branch_covered = branch_missed = 0
    gated = 0
    per_class: list[tuple[str, float, int]] = []

    for element in measured_classes(report):
        name = class_name_of(element)
        if is_excluded(name, exclusions):
            continue
        gated += 1
        covered, missed = counter(element, "LINE")
        line_covered += covered
        line_missed += missed
        per_class.append((name, ratio(covered, missed), covered + missed))
        covered, missed = counter(element, "BRANCH")
        branch_covered += covered
        branch_missed += missed

    line_ratio = ratio(line_covered, line_missed)
    branch_ratio = ratio(branch_covered, branch_missed)
    line_total = line_covered + line_missed

    # Printed before any verdict, so the number is in the log whether the gate passes or not.
    # It is this tree's own number and is not combined with the Python or TypeScript figures.
    sys.stdout.write(
        "coverage (JetBrains plugin, Java, gated set only):\n"
        f"  line   {line_ratio * 100:.2f}%  ({line_covered}/{line_total})\n"
        f"  branch {branch_ratio * 100:.2f}%  "
        f"({branch_covered}/{branch_covered + branch_missed})\n"
        f"  classes gated {gated}, excluded {len(exclusions)}\n"
    )

    if line_ratio < args.min_line_ratio:
        worst = sorted(p for p in per_class if p[2] > 0)
        worst.sort(key=lambda p: p[1])
        detail = ", ".join(f"{n.rsplit('.', 1)[-1]} {r * 100:.0f}%" for n, r, _ in worst[:5])
        problems.append(
            f"line coverage {line_ratio * 100:.2f}% is below the required "
            f"{args.min_line_ratio * 100:.2f}%. Least covered: {detail}"
        )
    if branch_ratio < args.min_branch_ratio:
        problems.append(
            f"branch coverage {branch_ratio * 100:.2f}% is below the required "
            f"{args.min_branch_ratio * 100:.2f}%"
        )

    if gated < args.min_classes:
        problems.append(
            f"the gate measured {gated} classes, expected at least {args.min_classes}. "
            "A class that stopped being compiled into the measured output, or that gained an "
            "exclusion, raises the percentage by shrinking the denominator rather than by "
            "being tested."
        )
    if line_total < args.min_lines:
        problems.append(
            f"the line denominator is {line_total}, expected at least {args.min_lines}. "
            "Coverage went up because less was measured."
        )
    return problems


def check_exclusions_are_still_true(
    report: ElementTree.Element, exclusions: list[dict], repo_root: pathlib.Path
) -> list[str]:
    """Re-tests every exclusion, so one that stopped being true fails instead of persisting."""
    problems: list[str] = []
    tracked = tracked_files(repo_root)
    reported = {class_name_of(element) for element in measured_classes(report)}

    for entry in exclusions:
        path = entry["path"]
        pattern = entry["classPattern"]

        if path not in tracked:
            problems.append(
                f"{path} is excluded from coverage but is not tracked by git. An exclusion "
                "that guards nothing is a stale exclusion; delete the entry."
            )
            continue

        source = repo_root / path
        lines = len(source.read_text(encoding="utf-8").splitlines())
        budget = entry["maxLines"]
        if lines > budget:
            problems.append(
                f"{path} is {lines} lines, over its declared budget of {budget}. The budget is "
                "the check on the claim that this file holds no decisions. Either move the new "
                "code into a measured class, or justify a larger budget in the entry's reason."
            )

        # An exclusion for a pattern that matches nothing in the report is also stale: the
        # class was renamed, moved, or is no longer compiled, and the entry now protects a name
        # that does not exist.
        if not any(matches(name, pattern) for name in reported):
            problems.append(
                f"{pattern} matches no class in the coverage report. The entry for {path} is "
                "stale: the class was renamed or is no longer built."
            )
    return problems


def matches(class_name: str, pattern: str) -> bool:
    if pattern.endswith("*"):
        return class_name.startswith(pattern[:-1])
    return class_name == pattern


def check_census(
    report: ElementTree.Element,
    exclusions: list[dict],
    repo_root: pathlib.Path,
    source_root: str,
    here: pathlib.Path,
) -> list[str]:
    """Every tracked source file must be measured or excluded.

    The census comes from `git ls-files` and not from the report, for the reason
    assert-coverage-completeness.mjs gives: nothing inside a report can reveal a file that was
    never loaded. JaCoCo makes this less likely than jest does, and not impossible -- a class
    excluded from the compile task, or a file under a source root the build does not read,
    is absent from the report exactly as an unimported TypeScript file is.

    One case a future contributor will meet and should not treat as a bug in this check: a
    `package-info.java` or `module-info.java` carrying no annotations produces no class file, so
    it is tracked, compiled by the same task as everything else, and absent from the report.
    Verified by adding one, which failed here as intended. It is NOT special-cased, on purpose.
    "Nothing can measure this file" is exactly the disposition coverage-exclusions.json exists
    to record as a committed claim, and a silent skip for a whole file-name pattern is the
    opposite of that. Add an entry with a new kind and the staleness test that fits it.
    """
    problems: list[str] = []
    prefix = f"{here.relative_to(repo_root).as_posix()}/{source_root}/"
    excluded_paths = {entry["path"] for entry in exclusions}

    # Package-qualified, not by basename. Two classes in different packages can share a file
    # name, and a basename comparison would report the second as measured on the strength of
    # the first -- a false pass in the one check whose whole job is to find a file nothing
    # looked at.
    #
    # The pair comes from the class elements' own attributes rather than from the report's
    # sourcefile elements: JaCoCo emits those only when the report task was given
    # sourceDirectories, and reading them made this census report every file as missing when
    # none was.
    reported_sources = set()
    for package in report.findall("package"):
        package_path = package.get("name", "")
        for element in package.findall("class"):
            source = element.get("sourcefilename")
            if source:
                reported_sources.add(f"{package_path}/{source}" if package_path else source)

    for tracked in sorted(tracked_files(repo_root)):
        if not tracked.startswith(prefix) or not tracked.endswith(".java"):
            continue
        if tracked in excluded_paths:
            continue
        # The path relative to the source root IS the package path plus the file name, which is
        # exactly the key built above. That equivalence is what a Java source layout guarantees.
        if tracked[len(prefix):] not in reported_sources:
            problems.append(
                f"{tracked} is tracked but appears in neither the coverage report nor "
                "coverage-exclusions.json. Either it is not being compiled into the measured "
                "output, or it needs an entry with a reason."
            )
    return problems


def tracked_files(repo_root: pathlib.Path) -> set[str]:
    """`git ls-files`, which knows about files no harness has ever seen.

    Unlike a directory walk it cannot be fooled by a build artifact, and unlike the coverage
    report it can see a file nothing has loaded.
    """
    result = subprocess.run(  # noqa: S603
        ["git", "-C", str(repo_root), "ls-files", "-z"],
        capture_output=True,
        check=True,
    )
    # -z, because a path with a newline in it would otherwise split into two entries and the
    # census would ask about files that do not exist.
    return {name for name in result.stdout.decode("utf-8").split("\0") if name}


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Failure as failure:
        sys.stderr.write(f"coverage gate could not run: {failure}\n")
        sys.exit(2)
