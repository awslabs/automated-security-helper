#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Shipped text in the deploy tree describes behavior in neutral words.

Why this file exists
--------------------
The deploy tree's comments, docstrings, test names and docs are read by adopters who
have only a checkout. Two kinds of wording do not help them:

*   Labels of the private process that produced a change: names of notes, paths and
    item labels that are not in the repository, which a reader cannot follow.
*   Words that frame code as a contest between parties rather than say what it does.
    A test variable that names the file a test removes, or a comment that says why a
    key is checked, reads more plainly in terms of the file and the check.

Each pattern below matched real text in the tree before it was reworded, so both
checks can fail. This file is not scanned, since it has to name the patterns.

What is not checked here, because the same words are part of the domain: a scanner's
"vulnerability database", severity level values such as ``high`` in a threshold
setting, and a dependency advisory identifier. Those are reviewed by hand.
"""

from __future__ import annotations

import pathlib
import re
from typing import Iterator, Tuple

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
ROOTS = (REPO_ROOT / "deploy", REPO_ROOT / "tests" / "unit" / "deploy")

#: Text files a reader opens. Extensionless files are the container scripts the
#: images install (ash-container-init, ash-mcp-serve).
_SUFFIXES = {".ts", ".py", ".md", ".tf", ".hcl", ".sh", ".tftpl", ".yml", ".yaml"}
#: Generated or vendored content, which nobody here writes.
_SKIPPED_PARTS = {"node_modules", ".terraform", "templates", "dist", "__pycache__"}

#: Labels of the review process that produced these changes. They name notes and
#: paths that are not in the repository, so a reader of the shipped file cannot
#: follow them; the text has to describe the behavior instead.
_PROCESS_LABELS = re.compile(
    r"deploy audit|gateprobe|research/audit|interface notes|mcp cluster"
    r"|config hardening|MCP hardening|D6 fallback|the reviewer\b",
    re.IGNORECASE,
)

#: Adversarial framing. Each one has a plain alternative: the key that is checked,
#: the file a test removes, the step that is skipped.
_ADVERSARIAL_WORDS = re.compile(
    r"\battack|\bexploit|\bmalicious|\bbypass|\bevil\b|\bvictim|\bsevere\b",
    re.IGNORECASE,
)


def _shipped_lines() -> Iterator[Tuple[str, int, str]]:
    from tests.utils.helpers import iter_repo_files

    for root in ROOTS:
        # Pruned as it walks: deploy/cdk/node_modules is installed per run.
        for path in sorted(iter_repo_files(root, skip_dirs=frozenset(_SKIPPED_PARTS))):
            if (
                not path.is_file()
                or _SKIPPED_PARTS & set(path.parts)
                or path.name == pathlib.Path(__file__).name
                or path.name.endswith("-lock.json")
            ):
                continue
            if path.suffix not in _SUFFIXES and not (
                path.suffix == "" and path.parent.name == "files"
            ):
                continue
            text = path.read_text(encoding="utf-8")
            for number, line in enumerate(text.splitlines(), start=1):
                yield str(path.relative_to(REPO_ROOT)), number, line


def test_the_scan_reads_the_tree():
    """Not vacuous: the scan reaches every kind of file it claims to read."""
    files = {where for where, _, _ in _shipped_lines()}
    for expected in (
        "deploy/README.md",
        "deploy/cdk/lib/ash-container-scripts.ts",
        "deploy/terraform/modules/codecommit-gate/files/ash_pr_gate.py",
        "deploy/terraform/modules/ash-image-pipeline/files/ash-container-init",
        "deploy/terraform/modules/fargate/variables.tf",
        "deploy/terraform/modules/agentcore/tests/mcp_trust.tftest.hcl",
        "tests/unit/deploy/test_deploy_gate_claims.py",
    ):
        assert expected in files, expected


def test_shipped_comments_and_test_names_name_no_review_process():
    offending = [
        f"{where}:{number}"
        for where, number, line in _shipped_lines()
        if _PROCESS_LABELS.search(line)
    ]
    assert offending == []


def test_shipped_text_frames_behavior_without_adversarial_words():
    offending = [
        f"{where}:{number}: {line.strip()[:120]}"
        for where, number, line in _shipped_lines()
        if _ADVERSARIAL_WORDS.search(line)
    ]
    assert offending == [], "\n".join(offending)
