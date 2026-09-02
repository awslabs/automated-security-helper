"""cdk-nag against a real nag pack, with no mocks anywhere.

Why this file exists, since ten tests already cover the same function:
``tests/unit/utils/test_cdk_nag_wrapper_regression.py`` mocks ``cdk_nag`` throughout, so it
asserts against a stand-in whose constructor accepts any keyword. That suite stays green no
matter what the installed cdk-nag's API actually is, which is how a breaking major bump landed
without a single red test.

These tests instantiate the real pack against the real installed cdk-nag and assert on rule
and finding counts. They are deliberately the opposite trade: slower, dependent on the
``[cdk]`` extra, and unable to pass while the wrapper cannot call its own dependency.

The skip is guarded on purpose. A test that silently skips when the extra is missing protects
nothing, and CI installed no extras at the time this was written -- so an unguarded
``importorskip`` here would have reproduced the original blind spot in a new file. Setting
``ASH_REQUIRE_CDK_EXTRA=1`` turns the skip into a hard failure; CI sets it.
"""

import json
import os
from pathlib import Path

import pytest


def _require_cdk_nag():
    """Import cdk_nag, or skip -- unless the environment forbids skipping."""
    try:
        import cdk_nag  # noqa: F401
    except Exception as exc:  # pragma: no cover - environment-dependent
        if os.environ.get("ASH_REQUIRE_CDK_EXTRA", "").strip() in ("1", "YES", "TRUE", "true"):
            pytest.fail(
                "ASH_REQUIRE_CDK_EXTRA is set but the [cdk] extra is not importable "
                f"({type(exc).__name__}: {exc}). This test must RUN in CI, not skip: a "
                "silent skip is what let a breaking cdk-nag major bump land green."
            )
        pytest.skip(f"[cdk] extra not installed ({type(exc).__name__})")


# A template that must produce findings. An S3 bucket with no encryption, no access logging
# and no SSL enforcement trips several AwsSolutions rules. A compliant fixture would make
# every assertion below vacuous, so the fixture being non-compliant is load-bearing.
NON_COMPLIANT_TEMPLATE = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Description": "Deliberately non-compliant fixture for cdk-nag integration coverage",
    "Resources": {
        "UnencryptedBucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {"BucketName": "ash-cdk-nag-integration-fixture"},
        },
    },
}


@pytest.fixture()
def non_compliant_template(tmp_path: Path) -> Path:
    path = tmp_path / "non_compliant.template.json"
    path.write_text(json.dumps(NON_COMPLIANT_TEMPLATE, indent=2))
    return path


class TestRealNagPack:
    def test_pack_constructs_against_installed_cdk_nag(self):
        """The wrapper's own construction call must work on the installed major.

        This is the narrowest possible statement of the defect: whatever keyword arguments
        the wrapper passes, the installed cdk-nag has to accept them. Asserting it here means
        a future major bump fails on this line with a clear message rather than silently
        producing an empty report.
        """
        _require_cdk_nag()
        from automated_security_helper.utils.cdk_nag_wrapper import (
            _build_nag_pack,
        )

        pack = _build_nag_pack("AwsSolutionsChecks")
        assert pack is not None
        assert type(pack).__name__ == "AwsSolutionsChecks"

    def test_scan_produces_findings_on_a_non_compliant_template(
        self, non_compliant_template: Path, tmp_path: Path
    ):
        """A known-bad template must yield a non-zero finding count.

        This is the assertion the mock-based suite cannot make. Zero findings here means
        either the rules did not run or their results were discarded -- the two halves of the
        reported defect -- and both are indistinguishable from a clean scan without it.
        """
        _require_cdk_nag()
        from automated_security_helper.utils.cdk_nag_wrapper import (
            run_cdk_nag_against_cfn_template,
        )

        response = run_cdk_nag_against_cfn_template(
            template_path=non_compliant_template,
            nag_packs=["AwsSolutionsChecks"],
            outdir=tmp_path / "cdk-out",
        )

        assert response is not None, (
            "wrapper returned None for a valid CloudFormation template"
        )

        findings = [f for pack_findings in response.results.values() for f in pack_findings]
        assert len(findings) > 0, (
            "cdk-nag produced zero findings on a deliberately non-compliant template. "
            "Either no rule was evaluated or the results were dropped."
        )

        # Rule identity matters as much as the count: a non-empty list of findings with no
        # rule ids would still be useless downstream, and SARIF requires the rule.
        rule_ids = {f.ruleId for f in findings if getattr(f, "ruleId", None)}
        assert rule_ids, "findings carried no ruleId"
        assert any(rid.startswith("AwsSolutions-") for rid in rule_ids), (
            f"expected at least one AwsSolutions rule, got {sorted(rule_ids)}"
        )

    def test_failure_is_not_reported_as_success(self, tmp_path: Path):
        """A template the wrapper cannot process must not come back as an empty success.

        Feeding it something that is not a CloudFormation template is the cheapest way to
        exercise the failure path. The wrapper may return None or raise; what it must not do
        is return a response whose empty results later render as a clean pass.
        """
        _require_cdk_nag()
        from automated_security_helper.utils.cdk_nag_wrapper import (
            run_cdk_nag_against_cfn_template,
        )

        not_a_template = tmp_path / "not_a_template.json"
        not_a_template.write_text(json.dumps({"this": "is not cloudformation"}))

        try:
            response = run_cdk_nag_against_cfn_template(
                template_path=not_a_template,
                nag_packs=["AwsSolutionsChecks"],
                outdir=tmp_path / "cdk-out-bad",
            )
        except Exception:
            # Raising is an acceptable outcome; the caller is responsible for surfacing it.
            return

        assert response is None, (
            "wrapper returned a populated response for a non-CloudFormation input; an "
            "empty-but-successful result is what makes a total failure look clean"
        )
