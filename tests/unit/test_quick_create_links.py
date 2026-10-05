# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The quick-create links must name parameters the templates actually declare.

Why this file exists
--------------------
``deploy/quick-create-links.md`` advertises a one-click CloudFormation launch per
committed template. Its links pass parameters as ``param_<Name>`` in the URL fragment,
and **CloudFormation silently ignores a ``param_`` name the template does not declare**,
along with any parameter whose ``NoEcho`` is true. So ``param_AshVerison`` is not an
error. The console opens, the field is absent, the template's default quietly applies, and
the adopter deploys something other than what the link promised -- with nothing reporting
it at any point.

That failure is invisible to every other gate in this repository. The template drift gate
compares synthesized templates and never reads the document; a markdown link checker would
see a syntactically fine URL. Only comparing each ``param_`` name against the target
template's own ``Parameters`` block catches it.

``.github/workflows/ash-iac-drift.yml`` runs the same checks on every pull request. This
file holds them up from the other side, for two reasons the workflow cannot cover. It runs
on the whole unit-test matrix, which includes Python 3.10 -- so it is what proves the
renderer really is standard-library-only, since ``tomli`` is not a dependency and a TOML
config would have raised ``ModuleNotFoundError`` there. And it runs in the ordinary suite,
so a contributor sees a failure locally rather than on a red build.

What is deliberately NOT done here
----------------------------------
This file never calls the writing path. Rendering over the committed document would repair
the drift it is looking for and pass on the second run --
``tests/unit/test_version_template_round_trip.py`` records the same hazard and resolves it
the same way, by comparing in memory.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "render_quick_create_links.py"
DOC = REPO_ROOT / "deploy" / "quick-create-links.md"


def _load_renderer():
    """Import the renderer, which lives in scripts/ and is not an installed module."""
    spec = importlib.util.spec_from_file_location(
        "ash_render_quick_create_links", SCRIPT_PATH
    )
    assert spec is not None and spec.loader is not None, SCRIPT_PATH
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def renderer():
    if not SCRIPT_PATH.is_file():
        pytest.fail(f"{SCRIPT_PATH} is missing; the links cannot be verified.")
    return _load_renderer()


class TestTheValidatorCanFail:
    """The positive control. Without it a clean report proves nothing."""

    def test_self_test_rejects_every_planted_defect(self, renderer, capsys):
        """A misspelled, NoEcho, stale, non-S3 or illegally-named link must be rejected.

        This also asserts a CORRECT link is accepted, inside ``self_test`` itself --
        otherwise a validator that rejected everything would satisfy all five negative
        cases and still be useless.
        """
        assert renderer.self_test() == 0, capsys.readouterr().err

    def test_an_unknown_parameter_name_is_rejected(self, renderer):
        """The single most important assertion in this file, stated directly.

        Spelled out separately from ``self_test`` so that deleting a case from that
        function cannot quietly remove the one defect CloudFormation will not report.
        """
        stacks = renderer.load_templates()
        plan, problems = renderer.parameter_plan(stacks)
        assert not problems, problems

        hosting = {
            "bucket": "example-bucket",
            "bucket_region": "us-east-1",
            "key_prefix": "",
            "launch_regions": ["us-east-1"],
        }
        stack = min(stacks)
        url = renderer.quick_create_url(hosting, stack, "us-east-1", plan[stack])

        assert renderer.validate_url(url, stacks, plan) == [], (
            "a correctly generated link was rejected, so the assertion below is vacuous"
        )

        found = renderer.validate_url(
            url + "&param_ThisParameterDoesNotExist=1", stacks, plan
        )
        assert any("not a parameter" in line for line in found), found

    def test_a_declared_parameter_outside_the_plan_is_rejected(self, renderer):
        """A real parameter of the stack, but not one the link is supposed to set.

        It passes the unknown-name and NoEcho checks, so nothing else catches it -- and its
        value cannot be checked, because the plan holds no expected value to compare it
        against. Rejecting is what makes "every value in a generated link is derived from
        the template" true of the whole link rather than only of the planned names.
        """
        stacks = renderer.load_templates()
        plan, problems = renderer.parameter_plan(stacks)
        assert not problems, problems

        hosting = {
            "bucket": "example-bucket",
            "bucket_region": "us-east-1",
            "key_prefix": "",
            "launch_regions": ["us-east-1"],
        }
        stack = min(stacks)
        planned = {name for name, _ in plan[stack]}
        extra = sorted(
            name
            for name, spec in stacks[stack].items()
            if name not in planned and not renderer.is_noecho(spec)
        )
        assert extra, (
            f"{stack} declares no unplanned, non-NoEcho parameter to test with"
        )

        url = renderer.quick_create_url(hosting, stack, "us-east-1", plan[stack])
        assert renderer.validate_url(url, stacks, plan) == [], (
            "a correctly generated link was rejected, so the assertion below is vacuous"
        )

        found = renderer.validate_url(f"{url}&param_{extra[0]}=whatever", stacks, plan)
        assert any("not one this link is supposed to set" in line for line in found), (
            found
        )


class TestTheCommittedDocumentIsCurrent:
    def test_the_document_matches_a_fresh_render(self, renderer):
        """Compared in memory; nothing is written. See the module docstring."""
        expected, problems = renderer.render_text()
        assert not problems, problems
        assert DOC.is_file(), f"{DOC} is missing. Run the renderer and commit it."
        assert DOC.read_text(encoding="utf-8") == expected, (
            f"{DOC.relative_to(REPO_ROOT)} is stale. Regenerate it with "
            "'python3 scripts/render_quick_create_links.py render' and commit the result."
        )

    def test_check_passes_against_the_committed_templates(self, renderer, capsys):
        assert renderer.check() == 0, capsys.readouterr().err


class TestEveryTemplateIsClassified:
    """A new template must be a decision, not a silent default or a false alarm.

    The prepopulated names are image-build parameters, and a target that consumes a prebuilt
    image URI declares none of them -- correctly. Before ``STACK_CLASSES`` existed, such a
    template tripped the per-stack floor with a message blaming the template's ``Parameters``
    block, and the repair that message invited was lowering the floor, which would have
    removed the vacuity guard for every other stack.
    """

    def test_every_committed_template_is_classified(self, renderer):
        """This is the assertion that fires the day a sixth template lands."""
        stacks = renderer.load_templates()
        unclassified = sorted(set(stacks) - set(renderer.STACK_CLASSES))
        assert not unclassified, (
            f"these committed templates are not in STACK_CLASSES: {unclassified}. Add each "
            f"as {renderer.WITH_PREPOPULATED!r} if its link should carry the prepopulated "
            f"parameters, or {renderer.WITHOUT_PREPOPULATED!r} if it declares none of them. "
            "Do not lower MIN_PARAMS_PER_STACK to make this pass."
        )

    def test_no_classification_outlives_its_template(self, renderer):
        stacks = renderer.load_templates()
        stale = sorted(set(renderer.STACK_CLASSES) - set(stacks))
        assert not stale, (
            f"STACK_CLASSES classifies templates that do not exist: {stale}. A "
            "classification for a missing stack reads as coverage and checks nothing."
        )

    def test_an_unclassified_template_is_rejected(self, renderer):
        """The positive control, stated directly rather than only inside self_test."""
        stacks = renderer.load_templates()
        _, baseline = renderer.parameter_plan(stacks)
        assert not baseline, (
            f"the committed tree already reports problems, so this control is vacuous: "
            f"{baseline}"
        )

        probe = dict(stacks)
        probe["AshNotClassifiedByAnything"] = {"SomeImageUri": {"Type": "String"}}
        _, problems = renderer.parameter_plan(probe)
        about = [p for p in problems if "AshNotClassifiedByAnything" in p]
        assert about, "an unclassified template was accepted"
        assert any("does not classify" in p for p in about), (
            f"rejected, but not as unclassified -- the message must name the decision "
            f"rather than blame the Parameters block. Got: {about}"
        )


class TestThePlanIsNotEmpty:
    """Floors. A derivation that silently produced nothing would otherwise pass."""

    def test_every_prepopulated_name_is_declared_and_not_noecho(self, renderer):
        stacks = renderer.load_templates()
        assert stacks, "no committed templates were found; nothing was checked"

        offenders = []
        for stack, params in stacks.items():
            for name in renderer.PREPOPULATED:
                spec = params.get(name)
                if spec is None:
                    continue
                if renderer.is_noecho(spec):
                    offenders.append(f"{stack}.{name} is NoEcho")
        assert not offenders, offenders

    def test_the_plan_clears_its_floors(self, renderer):
        stacks = renderer.load_templates()
        plan, problems = renderer.parameter_plan(stacks)
        assert not problems, problems
        assert len(stacks) >= renderer.MIN_STACKS
        total = sum(len(pairs) for pairs in plan.values())
        assert total >= renderer.MIN_TOTAL_PARAM_ASSERTIONS, (
            f"only {total} parameter assertion(s); the gate would be near-vacuous"
        )
