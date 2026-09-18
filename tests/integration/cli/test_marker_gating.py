# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No test in this directory may be reachable only with two flags.

WHY THIS EXISTS
---------------
``tests/conftest.py`` skips anything marked ``integration`` unless ``--run-integration``
is passed, and separately skips anything marked ``slow`` unless ``--run-slow`` is passed.
The conftest in this directory adds ``integration`` to everything here, and adds ``slow``
to any test whose *function name* contains "workflow", "lifecycle" or "end_to_end".

A test that picks up both markers therefore needs both flags, and running with
``--run-integration`` alone produces a green result that quietly skipped it. That is the
same failure mode this directory's conftest docstring records twice already: an unscoped
version of those name rules reached the whole repository and silently skipped a CI gate,
the scoping fix was applied to the slow rules only, and a unit test named
``..._integration.py`` then had all fourteen of its tests skipped in full runs while
passing in isolation. Both were found by diffing skipped-test ids against a baseline,
which is the only signal the failure emits.

The MCP modules in this directory are named to avoid those three words for exactly that
reason -- ``test_mcp_scan_workflow.py`` holds no test function with "workflow" in its
name -- and this module is what keeps that true. Without it the naming choice is a
convention in a docstring, and the next person to add
``test_end_to_end_scan_workflow`` gets a test that never runs and no warning.

HOW THE KEYWORDS ARE DERIVED
----------------------------
From the conftest's source text, not from a copy. A duplicated list would rot the moment
someone added a fourth keyword, and this module would then certify as safe a name that
had just become unsafe. ``_slow_keywords`` reads the literal out of the conftest and
fails loudly if it cannot find it, which is the honest behavior for a guard that has
lost track of what it is guarding.

WHAT THIS DOES NOT CHECK
------------------------
Whether a test *should* be slow. A genuinely long test is entitled to the marker; the
problem is only that the marker is applied by name rather than by measurement, so it
lands on tests that are not slow and hides them. If a test here ever does need the slow
gate, add it to ``DOUBLE_GATED_EXEMPTIONS`` with a reason.

It also does not check the ``integration`` marker or the path scoping. Those are the
conftest's own behavior and changing them is a decision about the whole tree, not about
this directory.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Dict, List, Set

HERE = Path(__file__).resolve().parent
CONFTEST = HERE / "conftest.py"

# The literal the conftest uses to decide which names get the slow marker. Matched rather
# than copied so that a fourth keyword cannot be added without this guard noticing.
KEYWORD_LIST = re.compile(
    r"for keyword in \[((?:\s*\"[a-z_]+\"\s*,?)+)\]", re.MULTILINE
)

# Tests that are allowed to need --run-slow as well as --run-integration.
#
# Every entry costs something: it is a test that a plain `--run-integration` run reports
# as green without executing. Each needs a reason, and the reason has to say why the
# double gate is right rather than merely why it is currently true.
DOUBLE_GATED_EXEMPTIONS: Dict[str, str] = {
    "test_file_based_tracking_workflow": (
        "Pre-existing. This test calls mcp_get_scan_results(scan_id) while that "
        "function's parameter is output_dir, so it fails with KeyError: 'scan_id' on "
        "the error response it gets back. Renaming it to drop the slow gate would turn "
        "a silent skip into a red test, and repairing it is not part of the change that "
        "added this guard. Remove this entry when the test is fixed and renamed."
    ),
}


def _slow_keywords() -> Set[str]:
    """Return the name fragments the conftest turns into a ``slow`` marker."""
    source = CONFTEST.read_text(encoding="utf-8")
    match = KEYWORD_LIST.search(source)
    assert match, (
        f"Could not find the slow-marker keyword list in {CONFTEST}. This guard reads "
        "it out of the conftest so the two cannot drift; if the hook was rewritten, "
        "update KEYWORD_LIST to match the new form rather than hardcoding the "
        "keywords, or this test will certify names that are no longer safe."
    )
    return set(re.findall(r"\"([a-z_]+)\"", match.group(1)))


def _test_function_names(path: Path) -> List[str]:
    """Return every test function name defined in ``path``, including methods."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: List[str] = []
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef)
        ) and node.name.startswith("test_"):
            names.append(node.name)
    return names


def test_the_keyword_list_is_the_one_this_guard_was_written_against() -> None:
    """Guard the guard: an empty or unrecognized keyword set makes the check vacuous.

    If the regex stopped matching, ``_slow_keywords`` would already have failed. This
    asserts the stronger thing -- that the set is non-empty and still contains the three
    words the module docstrings and the file naming were chosen around. A fourth keyword
    is not a failure by itself, but it means some existing name may have just become
    double-gated, so it should be a deliberate edit here.
    """
    keywords = _slow_keywords()
    assert keywords, "The conftest names no slow keywords, so nothing below can fail"
    assert {"workflow", "lifecycle", "end_to_end"} <= keywords, (
        f"The slow-marker keywords are now {sorted(keywords)}. The three this "
        "directory's naming was chosen around are gone or renamed; re-read the module "
        "docstrings that mention them before changing this assertion."
    )


def test_no_test_here_needs_run_slow_as_well_as_run_integration() -> None:
    """Every test in this directory executes under ``--run-integration`` alone.

    Collected by parsing each module's source rather than by asking pytest, because the
    thing being checked is the *name*, and a name is available statically. Going through
    collection would also mean this test's verdict depended on which flags the current
    run happened to pass, which is the opposite of what a guard should do.
    """
    keywords = _slow_keywords()
    offenders: Dict[str, List[str]] = {}

    modules = sorted(HERE.glob("test_*.py"))
    assert len(modules) >= 2, (
        f"Found only {[m.name for m in modules]} in {HERE}. If the glob stopped "
        "matching, this test passes while checking nothing."
    )

    for module in modules:
        for name in _test_function_names(module):
            if name in DOUBLE_GATED_EXEMPTIONS:
                continue
            hits = sorted(keyword for keyword in keywords if keyword in name.lower())
            if hits:
                offenders.setdefault(module.name, []).append(
                    f"{name} ({', '.join(hits)})"
                )

    assert not offenders, (
        "These tests will be marked slow by this directory's conftest, so a run with "
        f"--run-integration but not --run-slow reports green without executing them: "
        f"{offenders}.\n"
        "Rename the test for the property it checks rather than for the shape of the "
        "flow it exercises, or -- if it genuinely belongs behind the slow gate -- add "
        "it to DOUBLE_GATED_EXEMPTIONS with a reason."
    )


def test_the_exemptions_are_not_stale() -> None:
    """An exemption naming a test that no longer exists has to go.

    Otherwise the list rots into a permanent allowlist: a name left here after the test
    was renamed or deleted keeps suppressing nothing, and the next reader has no way to
    tell which entries are load-bearing.
    """
    defined: Set[str] = set()
    for module in sorted(HERE.glob("test_*.py")):
        defined.update(_test_function_names(module))

    keywords = _slow_keywords()
    for name, reason in DOUBLE_GATED_EXEMPTIONS.items():
        assert name in defined, (
            f"{name!r} is exempted from the double-gating check but no test by that "
            "name exists in this directory. Remove the exemption."
        )
        assert any(keyword in name.lower() for keyword in keywords), (
            f"{name!r} is exempted from the double-gating check but its name matches "
            f"none of {sorted(keywords)}, so it is not double-gated and the exemption "
            "does nothing. Remove it."
        )
        assert reason.strip(), f"{name!r} is exempted with no reason given"
