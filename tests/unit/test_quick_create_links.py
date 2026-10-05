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

    def test_the_eks_operator_is_a_prebuilt_image_consumer(self, renderer):
        """AshEksOperator deploys an operator image built elsewhere, so it has no link params.

        It arrived on a separate branch from this gate and was the first template that
        declares none of the prepopulated names. Pin both halves of why it is
        WITHOUT_PREPOPULATED: it takes the image as a URI, and it declares no build input.
        """
        params = renderer.load_templates()["AshEksOperator"]
        assert renderer.STACK_CLASSES["AshEksOperator"] == renderer.WITHOUT_PREPOPULATED
        assert "OperatorImageUri" in params
        assert not set(renderer.PREPOPULATED) & set(params), (
            "AshEksOperator now declares an image-build parameter; reclassify it as "
            f"{renderer.WITH_PREPOPULATED!r} so its link carries the value."
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


def _hosting(bucket: str, bucket_region: str = "us-east-1", **extra):
    hosting = {
        "bucket": bucket,
        "bucket_region": bucket_region,
        "key_prefix": "",
        "launch_regions": ["us-east-1"],
    }
    hosting.update(extra)
    return hosting


def _template_url_of(link: str) -> str:
    """The decoded templateURL a rendered console link carries."""
    import urllib.parse

    fragment = link.split("#", 1)[1]
    query = fragment.split("?", 1)[1]
    return dict(urllib.parse.parse_qsl(query))["templateURL"]


class TestTheTemplateUrlIsAddressable:
    """The templateURL must be one S3 will serve over HTTPS for the configured bucket.

    S3's virtual-hosted wildcard certificate (``*.s3.<region>.amazonaws.com``) matches one
    DNS label, so a bucket whose name contains a period cannot be reached virtual-hosted
    over HTTPS -- the TLS handshake fails before CloudFormation reads a byte. See
    https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html. Such a
    bucket has to use the path-style form, which the CloudFormation quick-create page lists
    as supported:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/cfn-console-create-stacks-quick-create-links.html
    """

    def test_a_dotted_bucket_uses_path_style(self, renderer):
        url = renderer.template_url(_hosting("my.bucket.name"), "AshFargate")
        assert url == (
            "https://s3.us-east-1.amazonaws.com/my.bucket.name/AshFargate.template.json"
        )

    def test_a_dotted_bucket_link_passes_the_validator(self, renderer):
        stacks = renderer.load_templates()
        plan, problems = renderer.parameter_plan(stacks)
        assert not problems, problems
        link = renderer.quick_create_url(
            _hosting("my.bucket.name"), "AshFargate", "us-east-1", plan["AshFargate"]
        )
        assert renderer.validate_url(link, stacks, plan) == []
        assert _template_url_of(link).startswith("https://s3.us-east-1.amazonaws.com/")

    def test_a_dotted_bucket_virtual_hosted_link_is_rejected(self, renderer):
        """The form the old renderer emitted, which is a TLS failure, must not pass."""
        import urllib.parse

        stacks = renderer.load_templates()
        plan, _ = renderer.parameter_plan(stacks)
        good = renderer.quick_create_url(
            _hosting("my.bucket.name"), "AshFargate", "us-east-1", plan["AshFargate"]
        )
        broken = good.replace(
            urllib.parse.quote(
                "https://s3.us-east-1.amazonaws.com/my.bucket.name/", safe=""
            ),
            urllib.parse.quote(
                "https://my.bucket.name.s3.us-east-1.amazonaws.com/", safe=""
            ),
        )
        assert broken != good
        found = renderer.validate_url(broken, stacks, plan)
        assert any("period" in line for line in found), found

    def test_a_dotless_bucket_stays_virtual_hosted(self, renderer):
        url = renderer.template_url(_hosting("my-bucket-name"), "AshFargate")
        assert url == (
            "https://my-bucket-name.s3.us-east-1.amazonaws.com/AshFargate.template.json"
        )

    @pytest.mark.parametrize(
        "region", ["us-east-1", "us-west-2", "eu-west-2", "ap-southeast-2"]
    )
    def test_the_bucket_region_is_the_endpoint_region(self, renderer, region):
        assert renderer.hosting_problems(_hosting("my-bucket", region)) == []
        assert renderer.template_url(_hosting("my-bucket", region), "AshFargate") == (
            f"https://my-bucket.s3.{region}.amazonaws.com/AshFargate.template.json"
        )
        assert renderer.template_url(_hosting("my.bucket", region), "AshFargate") == (
            f"https://s3.{region}.amazonaws.com/my.bucket/AshFargate.template.json"
        )

    def test_the_launch_region_is_independent_of_the_bucket_region(self, renderer):
        stacks = renderer.load_templates()
        plan, _ = renderer.parameter_plan(stacks)
        link = renderer.quick_create_url(
            _hosting("my-bucket", "eu-west-2"),
            "AshFargate",
            "us-east-1",
            plan["AshFargate"],
        )
        assert link.startswith(
            "https://us-east-1.console.aws.amazon.com/cloudformation/home?region=us-east-1#"
        )
        assert ".s3.eu-west-2.amazonaws.com/" in _template_url_of(link)
        assert renderer.validate_url(link, stacks, plan) == []

    def test_the_key_prefix_is_kept_and_encoded(self, renderer):
        url = renderer.template_url(
            _hosting("my-bucket", key_prefix="ash/v 1+x/"), "AshFargate"
        )
        assert url == (
            "https://my-bucket.s3.us-east-1.amazonaws.com/ash/v%201%2Bx/AshFargate.template.json"
        )


class TestTheConsoleRegionIsConsistent:
    """The console host and ``?region=`` must name the same Region.

    The renderer always builds them from one value, so only a hand edit of the committed
    document can make them disagree. That is the case `check` exists for, and nothing
    else catches it: the console reads ``?region=``, so the link opens and launches in a
    Region other than the one its host name shows.
    """

    def _good(self, renderer):
        stacks = renderer.load_templates()
        plan, problems = renderer.parameter_plan(stacks)
        assert not problems, problems
        link = renderer.quick_create_url(
            _hosting("my-bucket"), "AshFargate", "us-east-1", plan["AshFargate"]
        )
        assert renderer.validate_url(link, stacks, plan) == [], "control link rejected"
        return link, stacks, plan

    def test_a_host_region_that_disagrees_is_rejected(self, renderer):
        link, stacks, plan = self._good(renderer)
        broken = link.replace(
            "https://us-east-1.console.", "https://eu-west-1.console.", 1
        )
        assert broken != link
        found = renderer.validate_url(broken, stacks, plan)
        assert any("disagree" in line for line in found), found

    def test_a_query_region_that_disagrees_is_rejected(self, renderer):
        link, stacks, plan = self._good(renderer)
        broken = link.replace("?region=us-east-1#", "?region=eu-west-1#", 1)
        assert broken != link
        found = renderer.validate_url(broken, stacks, plan)
        assert any("disagree" in line for line in found), found


class TestParametersAreUrlEncoded:
    def test_the_template_url_and_every_value_round_trip(self, renderer):
        import urllib.parse

        stacks = renderer.load_templates()
        plan, problems = renderer.parameter_plan(stacks)
        assert not problems, problems
        stack = "AshImagePipeline"
        hosting = _hosting("my.bucket.name", key_prefix="ash/")
        link = renderer.quick_create_url(hosting, stack, "us-east-1", plan[stack])

        query = link.split("#", 1)[1].split("?", 1)[1]
        # Nothing that would split or terminate the fragment's query survives raw.
        for raw in (" ", "?", "*", "(", ")", "://"):
            assert raw not in query, (raw, query)
        decoded = dict(urllib.parse.parse_qsl(query))
        assert decoded["templateURL"] == renderer.template_url(hosting, stack)
        for name, value in plan[stack]:
            assert decoded[f"param_{name}"] == value
        assert any(" " in value for _, value in plan[stack]), (
            "no planned value needs encoding, so this test checks nothing"
        )


class TestTheHostingConfigIsValidated:
    @pytest.mark.parametrize(
        ("bucket", "fragment"),
        [
            ("My-Bucket", "lowercase"),
            ("my_bucket", "lowercase"),
            ("ab", "3 and 63"),
            ("a" * 64, "3 and 63"),
            ("-bucket", "begin and end"),
            ("bucket.", "begin and end"),
            ("my..bucket", "adjacent periods"),
            ("192.168.5.4", "IP address"),
            # Every reserved prefix and suffix, so dropping either check, or any one
            # entry from its tuple, fails here. The names are otherwise valid, so no
            # other rule can produce the expected message.
            ("xn--ash-templates", "prefix S3 reserves"),
            ("sthree-ash-templates", "prefix S3 reserves"),
            ("amzn-s3-demo-ash-templates", "prefix S3 reserves"),
            ("ash-templates-s3alias", "suffix S3 reserves"),
            ("ash-templates--ol-s3", "suffix S3 reserves"),
            ("ash.templates.mrap", "suffix S3 reserves"),
            ("ash-templates--x-s3", "suffix S3 reserves"),
            ("ash-templates--table-s3", "suffix S3 reserves"),
        ],
    )
    def test_an_invalid_bucket_name_is_rejected(self, renderer, bucket, fragment):
        problems = renderer.hosting_problems(_hosting(bucket))
        assert any(fragment in p for p in problems), problems

    def test_a_bucket_without_a_region_is_rejected(self, renderer):
        problems = renderer.hosting_problems(_hosting("my-bucket", ""))
        assert any("bucket_region" in p for p in problems), problems

    @pytest.mark.parametrize("region", ["cn-north-1", "us-gov-west-1", "us-east-one"])
    def test_a_region_outside_the_aws_partition_is_rejected(self, renderer, region):
        assert renderer.hosting_problems(_hosting("my-bucket", region))
        assert renderer.hosting_problems(_hosting("my-bucket", launch_regions=[region]))

    def test_the_shipping_default_is_valid(self, renderer):
        assert renderer.hosting_problems(renderer.load_hosting()) == []


class TestRenderedLinksPointAtCommittedTemplates:
    """End to end: configure a bucket, render, then run `check` on what was rendered."""

    @pytest.mark.parametrize("bucket", ["my-bucket-name", "my.bucket.name"])
    def test_render_then_check(self, renderer, tmp_path, monkeypatch, capsys, bucket):
        import json

        config = tmp_path / "hosting.json"
        config.write_text(
            json.dumps(
                {
                    "bucket": bucket,
                    "bucket_region": "eu-west-2",
                    "key_prefix": "ash/",
                    "launch_regions": ["us-east-1", "eu-west-2"],
                }
            ),
            encoding="utf-8",
        )
        out = tmp_path / "quick-create-links.md"
        monkeypatch.setattr(renderer, "HOSTING_CONFIG", config)
        monkeypatch.setattr(renderer, "DOC_OUTPUT", out)

        assert renderer.render(write=True) == 0, capsys.readouterr().err
        text = out.read_text(encoding="utf-8")
        links = renderer.CONSOLE_URL_RE.findall(text)
        committed = {p.name for p in renderer.TEMPLATE_DIR.glob("*.template.json")}
        assert len(links) == len(committed) * 2

        for link in links:
            url = _template_url_of(link)
            assert url.rsplit("/", 1)[-1] in committed, url
            if "." in bucket:
                assert url.startswith(
                    f"https://s3.eu-west-2.amazonaws.com/{bucket}/ash/"
                )
            else:
                assert url.startswith(
                    f"https://{bucket}.s3.eu-west-2.amazonaws.com/ash/"
                )

        assert renderer.check() == 0, capsys.readouterr().err

    def test_render_refuses_an_invalid_bucket(
        self, renderer, tmp_path, monkeypatch, capsys
    ):
        import json

        config = tmp_path / "hosting.json"
        config.write_text(
            json.dumps(
                {
                    "bucket": "My_Bucket",
                    "bucket_region": "us-east-1",
                    "key_prefix": "",
                    "launch_regions": ["us-east-1"],
                }
            ),
            encoding="utf-8",
        )
        out = tmp_path / "quick-create-links.md"
        monkeypatch.setattr(renderer, "HOSTING_CONFIG", config)
        monkeypatch.setattr(renderer, "DOC_OUTPUT", out)
        assert renderer.render(write=True) == 1
        assert "My_Bucket" in capsys.readouterr().err
        assert not out.exists()
