# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""getting-started/platform-teams.md's tutorial: the operator config holds the gate.

The page rolls ASH out across repositories. Steps 1, 4, 5 and 6 need a container
runtime, a registry, CI runners, vulnerability databases or AWS, and are not run here:
the image build and push, the CI job, the database refresh and the places findings are
sent are boundaries of this twin, as they are of the docs runner (their blocks are
marked ``illustrative``).

Steps 2 and 3 run on one machine, and they carry the page's central claim: a
repository's own config file cannot change the verdict of a scan that names the
operator's. The twin runs the page's own blocks of both steps, in order, with the exit
code each block is marked with: the operator config is written and kept outside every
git checkout, a repository holding one hardcoded password fails the scan (exit 2), the
repository's ``.ashrc.yaml`` turns the gate off for a scan that names no operator
config (exit 0), and the scan that names it fails again (exit 2). Those blocks also
run in test_docs_examples.py, one page at a time; here they open a longer arc.

The page then says what a repository cannot do through its config: "turn off the gate,
raise the threshold, disable scanners, or add suppressions". Its own blocks show the
first. The twin adds the fourth, as a pair: a repository config that suppresses the
finding changes the verdict of a scan that does not name the operator's (so the config
is read, and the run is not one that would have passed anyway), and does not change the
verdict of a scan that does.

Raising the threshold and disabling a scanner are not twinned. A threshold cannot be
raised past this project's finding: ASH grades detect-secrets findings CRITICAL
(how-to/set-the-gate.md), so every threshold fails on it. A scanner a config turns off
leaves a scan with no scanner to run, which ends with exit 1 and says nothing about
whether the gate held.

And step 4's claim about the operator config's path: "ASH inside the container refuses
an ``ASH_CONFIG`` that names no file too, with exit code 3, instead of scanning with the
defaults". The container is out of reach here; the refusal is ASH's, and the twin runs it
on the host.

detect-secrets ships with ASH, so nothing but ASH has to be installed.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest


def _load(name: str, path: Path):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


jt = _load("_ash_journey_twin", Path(__file__).resolve().parent / "journey_twin.py")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.name == "nt",
        reason="the docs runner is documented POSIX-only (docs_runner.py:41-47)",
    ),
]

PAGE = "docs/content/getting-started/platform-teams.md"
#: The scans the twin adds itself are spelled as ASH 3.9 reads them (``ash scan fs``,
#: ``--only-scanners``); the page's own blocks run as the page spells them.
SCAN = 'ash scan fs --config "$OPERATOR_CONFIG" --only-scanners detect-secrets'
PLAIN_SCAN = "ash scan fs --only-scanners detect-secrets"
FAILS = "Exiting due to 1 actionable findings found in ASH scan"


def _repo_config_pair(twin, config: str) -> None:
    """The repository's config changes a plain scan, and not a scan with the operator's."""
    twin.run(f"cat > .ashrc.yaml <<'EOF'\n{config}\nEOF")
    twin.run(PLAIN_SCAN, code=0, absent=("Exiting due to",))
    twin.run(SCAN, code=2, prints=(FAILS,))


def test_the_operator_config_holds_the_gate_a_repository_cannot_move(tmp_path, request):
    root = jt.docs_root(request.config)
    page = jt.parse_page(PAGE, root)

    twin = jt.Twin("the platform teams tutorial")
    operator = jt.only_block(
        jt.blocks_under(page, r"2\."), "OPERATOR_CONFIG=", lang="bash"
    )
    twin.run(operator.body, code=jt.block_exit(operator))
    twin.run(
        'ash config validate --config "$OPERATOR_CONFIG"',
        prints=("Configuration is valid!",),
    )
    for block in jt.blocks_under(page, r"3\."):
        if block.lang == "bash":
            twin.run(block.body, code=jt.block_exit(block))

    # The page's last scan ran with the repository's gate-off config in place and the
    # operator's named; the repository's other attempts are tried the same way.
    _repo_config_pair(
        twin,
        "global_settings:\n"
        "  suppressions:\n"
        "    - path: app.py\n"
        "      rule_id: SECRET-SECRET-KEYWORD\n"
        "      reason: The repository says this is fine",
    )
    twin.run(
        'ASH_CONFIG="$HOME/ash-operator/no-such-file.yaml" '
        "ash scan fs --only-scanners detect-secrets",
        code=3,
        absent=("actionable findings",),
    )
    twin.execute(tmp_path, root)
