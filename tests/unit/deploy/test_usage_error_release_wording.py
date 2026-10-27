# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The deploy targets must not date ASH's usage-error exit code to 3.7.1.

Why this file exists
--------------------
The deploy targets, their docs and their tests explain exit 5, ASH's usage-error
code, in terms of which releases have it. They said "ASH releases after 3.7.0" and
"later releases" (than 3.7.0). That is false for 3.7.1, a patch release on 3.7.0
that the `v3` tag points at: its CLI has no exit 5, its `ash scan` ignores an
unknown option, and click reports the usage errors it does raise as 2, exactly as
3.7.0 does. The first release with exit 5 is the one after 3.7.1.

What is asserted
----------------
No text file under deploy/ or tests/unit/deploy/ dates the code to "after 3.7.0",
or says "later releases" exit 5 or refuse a value; and the corrected wording is
present, so a walk that read nothing cannot pass.
"""

from __future__ import annotations

import re
from pathlib import Path

from tests.utils.helpers import iter_repo_files

REPO_ROOT = Path(__file__).resolve().parents[3]
ROOTS = (REPO_ROOT / "deploy", REPO_ROOT / "tests" / "unit" / "deploy")
SKIP = frozenset({"node_modules", ".terraform", "cdk.out", "dist", "__pycache__"})

WRONG = re.compile(
    r"after v?3\.7\.0\b|ASH after 3\.7\.0|later releases (?:exit 5|refuse)",
    re.IGNORECASE,
)
RIGHT = "releases after 3.7.1"


def _texts():
    for root in ROOTS:
        for path in iter_repo_files(root, skip_dirs=SKIP):
            if path == Path(__file__).resolve():
                continue
            try:
                yield path, path.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue


def test_no_deploy_text_dates_exit_5_to_the_release_after_3_7_0():
    wrong = [
        f"  {path.relative_to(REPO_ROOT).as_posix()}:{number}: {line.strip()[:120]}"
        for path, text in _texts()
        for number, line in enumerate(text.splitlines(), 1)
        if WRONG.search(line)
    ]
    assert not wrong, (
        "These lines say exit 5 comes from releases after 3.7.0. 3.7.1 has no exit "
        "5 either; say 'releases after 3.7.1':\n" + "\n".join(wrong)
    )


def test_the_walk_reads_the_corrected_wording():
    found = {
        path.relative_to(REPO_ROOT).as_posix()
        for path, text in _texts()
        if RIGHT in text
    }
    assert {
        "deploy/terraform/modules/codecommit-gate/files/ash_pr_gate.py",
        "deploy/cdk/lib/ash-container-scripts.ts",
    } <= found, sorted(found)
