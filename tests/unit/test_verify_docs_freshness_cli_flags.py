# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the CLI-flag arm of scripts/verify_docs_freshness.py.

This gate had no tests, and it was green while covering none of the flags it was
supposed to cover. Two independent defects produced that:

1. It asked ``flag.lower() not in docs_lower`` -- a substring test. Any flag that
   is a prefix of a longer documented one passed without appearing anywhere.
   ``--ash-revision`` passed on ``--ash-revision-to-install``.
2. It extracted flags with the pattern ``"(--[a-z][a-z0-9-]*)"``, so it never
   considered a short form. ``-q``, ``-V``, ``-C`` and ``-rev`` were invisible.

Both are now fixed, and the point of this module is that the fix is testable. A
gate with no negative control cannot be distinguished from a gate that cannot
fail, so the central test here removes a flag from a docs body and asserts the
check reports it.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "verify_docs_freshness.py"


def _load_script():
    """Import the freshness script by path.

    ``scripts/`` is not a package, and mutating ``sys.path`` at import time would
    leak into every other test sharing this xdist worker. Registering the module
    in ``sys.modules`` under its own name keeps ``from __future__ import
    annotations`` resolvable inside it.
    """
    spec = importlib.util.spec_from_file_location(
        "ash_verify_docs_freshness", SCRIPT_PATH
    )
    assert spec is not None and spec.loader is not None, SCRIPT_PATH
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def script():
    return _load_script()


@pytest.fixture(scope="module")
def real_spellings(script):
    return script.cli_option_spellings()


@pytest.fixture(scope="module")
def real_docs(script):
    return script.read_text(script.CLI_REFERENCE_MD)


class TestTheGatePassesOnThisRepo:
    def test_no_flag_is_undocumented(self, script):
        assert script.check_cli_flags() == []


class TestTheGateCanFail:
    """The negative control. Everything else here is worthless without it."""

    def test_removing_a_documented_flag_is_reported(
        self, script, real_spellings, real_docs
    ):
        assert "--source-dir" in real_spellings
        mutilated = real_docs.replace("--source-dir", "--redacted-for-this-test")
        failures = script.check_cli_flags(spellings=real_spellings, docs=mutilated)
        assert any("--source-dir" in f for f in failures), (
            "the gate did not notice a flag vanishing from the docs, so it cannot "
            f"fail and proves nothing when it passes. failures={failures}"
        )

    def test_an_undocumented_short_form_is_reported(self, script, real_docs):
        """Defect 2: short forms used to be invisible to the extraction."""
        failures = script.check_cli_flags(
            spellings={"-Z"} | {f"--filler-{i}" for i in range(80)},
            docs=real_docs,
        )
        assert any(f.strip().startswith("CLI flag -Z ") for f in failures), failures

    def test_a_prefix_of_a_longer_flag_does_not_count_as_documented(self, script):
        """Defect 1: the exact case that shipped.

        A docs body mentioning only ``--ash-revision-to-install`` must not satisfy
        ``--ash-revision``. Under the old substring test this passed silently.
        """
        docs = "| `--ash-revision-to-install` | install a revision |\n"
        failures = script.check_cli_flags(
            spellings={"--ash-revision"} | {f"--filler-{i}" for i in range(80)},
            docs=docs,
        )
        assert any("--ash-revision is exposed" in f for f in failures), failures

    def test_the_whole_token_rule_still_matches_a_real_mention(self, script):
        """Control for the test above: the rule must not reject everything.

        A rule that never matched would make every flag "undocumented" and the
        prefix test above would pass for the wrong reason.
        """
        docs = "| `--ash-revision` | deprecated |\n"
        assert script.flag_is_documented("--ash-revision", docs)
        assert not script.flag_is_documented("--ash-revision-to-install", docs)


class TestDerivedNegationsAreCoveredByTheirPositiveForm:
    """Replaces a hand-maintained skip list.

    typer derives ``--no-X`` from ``--X``, and the docs describe the pair, so a
    negation is documented when its positive form is. The list this replaced held
    ``--no-color``, which is why the ``-c``/``--no-color`` divergence went
    unflagged.
    """

    def test_a_negation_passes_when_the_positive_form_is_documented(self, script):
        docs = "| `--quiet`, `-q` | hush |\n"
        failures = script.check_cli_flags(
            spellings={"--quiet", "-q", "--no-quiet"}
            | {f"--filler-{i}" for i in range(80)},
            docs=docs + "".join(f"`--filler-{i}`\n" for i in range(80)),
        )
        assert not any("--no-quiet" in f for f in failures), failures

    def test_a_negation_is_still_reported_when_the_positive_form_is_absent(
        self, script
    ):
        """The rule must not wave through every --no- flag."""
        failures = script.check_cli_flags(
            spellings={"--no-such-thing"} | {f"--filler-{i}" for i in range(80)},
            docs="".join(f"`--filler-{i}`\n" for i in range(80)),
        )
        assert any("--no-such-thing" in f for f in failures), failures

    def test_the_old_skip_list_members_are_gone(self, script):
        """Only framework-injected spellings may be skipped now."""
        assert script.FRAMEWORK_SPELLINGS == frozenset(
            {"--help", "-h", "--install-completion", "--show-completion"}
        )


class TestExtractionSeesTheRealSurface:
    def test_short_forms_are_extracted(self, real_spellings):
        """Pins the fix for defect 2 against the live CLI."""
        for short in ("-q", "-V", "-C", "-rev", "-v", "-d"):
            assert short in real_spellings, (
                f"{short} is exposed by the CLI but the freshness check cannot "
                "see it, so it can never report it as undocumented"
            )

    def test_derived_negations_are_extracted(self, real_spellings):
        """These appear in no source literal; only introspection finds them."""
        assert "--no-quiet" in real_spellings
        assert "--no-color" in real_spellings

    def test_enough_spellings_to_be_meaningful(self, real_spellings):
        assert len(real_spellings) >= 80, len(real_spellings)


class TestTheGateRefusesToPassVacuously:
    """An empty or tiny spellings set must be an error, not clean docs.

    Without a floor, anything that breaks introspection -- a renamed subcommand, a
    swallowed import error -- yields zero failures and the gate reports PASS. That
    is the failure mode this whole module exists to prevent, so it is pinned
    rather than left to inspection.
    """

    @pytest.mark.parametrize("spellings", [set(), {"-q"}, {"--a", "--b", "--c"}])
    def test_a_short_spellings_set_is_reported_as_a_broken_check(
        self, script, spellings, real_docs
    ):
        failures = script.check_cli_flags(spellings=spellings, docs=real_docs)
        assert failures, "an implausibly small flag set reported clean docs"
        assert any("cannot be trusted" in f for f in failures), failures

    def test_the_floor_is_below_the_real_count(self, script, real_spellings):
        """Otherwise the gate would fail on a correct repo."""
        assert script.MIN_EXPECTED_SPELLINGS < len(real_spellings)
