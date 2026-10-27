#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the deploy docs say about the gates' configuration and scope is what they do.

Why this file exists
--------------------
Four kinds of sentence would describe the CodeCommit gates and the sharded pipeline
more strongly than they behave:

*   "a pull request never chooses the rules it is judged by". The gates pass ASH an
    operator config, so the pull request's own ``.ash.yaml`` is not read, but ASH
    still hands some scanners a configuration file committed in the scanned tree
    (an in-tree ``bandit.yaml`` is passed to bandit), so the claim has to be limited
    to ASH's own config.
*   The shard and merge projects "never read the repository's config". They never
    read its ASH config (they scan with the base config or ``{}``), but scanners
    still read their own config files committed in the scanned tree, so the claim
    has to be limited to ASH's config here too.
*   ``--changed-files-only`` and ``--base-ref`` are refused because "a narrowed scan
    switches off the completeness check". Measured, it does not: with both scanners
    MISSING the narrowed scan still exits 1. What narrowing does is stop findings
    outside the diff from counting, and drop findings in any file whose name git
    quotes.
*   The Terraform gate's ``scan_egress_cidr`` row said the function calls SSM; it
    does only when a base config parameter is set.

Each check reads the files a reader, or the handler's own refusal message, would
show.
"""

from __future__ import annotations

import pathlib
import re
from typing import Iterator, Tuple

from tests.utils.helpers import iter_repo_files

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
DEPLOY = REPO_ROOT / "deploy"
GATE_HANDLER = (
    DEPLOY / "terraform" / "modules" / "codecommit-gate" / "files" / "ash_pr_gate.py"
)
CDK_SCRIPTS = DEPLOY / "cdk" / "lib" / "ash-container-scripts.ts"
GATE_README = DEPLOY / "terraform" / "modules" / "codecommit-gate" / "README.md"


_COMMENT_LEADERS = {"*", "#", "#:", "//"}


def _texts() -> Iterator[Tuple[str, str]]:
    """Every deploy README and variable file, plus the two gate scripts."""
    from tests.utils.helpers import iter_repo_files

    # Pruned as it walks: deploy/cdk/node_modules is installed per run.
    paths = sorted(
        p
        for p in iter_repo_files(
            DEPLOY, skip_dirs=frozenset({"node_modules", ".terraform"})
        )
        if p.suffix == ".md" or p.name == "variables.tf"
    )
    paths += [GATE_HANDLER, CDK_SCRIPTS]
    for path in paths:
        # Joined to one line without comment leaders, so a phrase wrapped across
        # lines of a comment or docstring is still found.
        words = path.read_text(encoding="utf-8").split()
        text = " ".join(w for w in words if w not in _COMMENT_LEADERS)
        yield str(path.relative_to(REPO_ROOT)), text


def _found(pattern: str) -> list[str]:
    regex = re.compile(pattern, re.IGNORECASE)
    return [where for where, text in _texts() if regex.search(text)]


def test_the_texts_checked_are_found():
    """Not vacuous: the READMEs, variables and both scripts are read."""
    names = [where for where, _ in _texts()]
    assert len(names) >= 10
    assert str(GATE_HANDLER.relative_to(REPO_ROOT)) in names


def test_no_claim_that_a_pull_request_never_chooses_its_rules():
    assert _found(r"never chooses? the rules") == []


def test_no_unqualified_claim_that_the_pipeline_never_reads_the_repository_config():
    assert _found(r"never read the repository's config") == []


def test_narrowing_is_not_said_to_switch_off_the_completeness_check():
    assert _found(r"narrow\w*[^.]{0,80}switches off the completeness check") == []


def test_the_gate_egress_row_says_when_ssm_is_called():
    rows = [
        line
        for line in GATE_README.read_text(encoding="utf-8").splitlines()
        if line.startswith("| `scan_egress_cidr`")
    ]
    assert len(rows) == 1
    assert "SSM" not in rows[0] or "base_config_ssm_parameter_name" in rows[0]
