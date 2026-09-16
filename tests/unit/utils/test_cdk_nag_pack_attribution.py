# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A finding has to name the plugin that produced it, not the tool that ran the scan.

``validation-report.json`` is CDK's policy-validation report, not cdk-nag's. Every plugin
registered on the app writes into the same ``pluginReports`` array, and from aws-cdk-lib 2.262.0
the CDK registers one of its own unconditionally: ``CloudFormationValidatePlugin``, whose
``PLUGIN_NAME`` is the literal string ``"CloudFormation Validate"`` and whose rules are
``@aws/cloudformation-validate`` ids such as ``F3017`` and ``W3010``. A measured run against a
template carrying a placeholder KMS key identifier returns both ``"AwsSolutions"`` and
``"CloudFormation Validate"`` in one report.

The pack name reached ``properties.tags`` as an unlabelled positional entry and reached nothing
else. So a consumer asking "what produced F3017, and where is it documented" got the answer
"cdk-nag" -- which is wrong, and is why the rule's help pointer aimed at cdk-nag's RULES.md, a
document that does not mention F3017 and does not describe the mechanism that governs it.

These tests drive ``_violations_from_validation_report`` against a written report rather than
through a synthesis, because translating the report is that function's whole job and the report
is its only input. The fixture is a trimmed copy of a report produced by the installed
aws-cdk-lib 2.267.0 and cdk-nag 3.0.2; ``TestReportAttribution`` in
``tests/integration/scanners/test_cdk_nag_real_pack.py`` asserts the same properties against a
live synthesis, so the fixture cannot drift into fiction without something going red.
"""

import json
from pathlib import Path


def _write_report(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / "validation-report.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


# A two-plugin report, which is the ordinary case rather than an edge case: registering any nag
# pack on an app whose CDK is >= 2.262.0 produces one.
TWO_PLUGIN_REPORT = {
    "version": "2.1.0",
    "title": "Validation Report",
    "pluginReports": [
        {
            "pluginName": "AwsSolutions",
            "violations": [
                {
                    "ruleName": "AwsSolutions-S1",
                    "description": "The S3 Bucket has server access logs disabled.",
                    "severity": "error",
                    "violatingConstructs": [
                        {"constructPath": "ASHCDKNagScanner/tpl/ProbeBucket"}
                    ],
                }
            ],
        },
        {
            "pluginName": "CloudFormation Validate",
            "violations": [
                {
                    "ruleName": "F3017",
                    "description": (
                        "BucketEncryption.ServerSideEncryptionConfiguration.0."
                        "ServerSideEncryptionByDefault.KMSMasterKeyID: 'my-kms-key' "
                        "is not a valid KMS key identifier"
                    ),
                    "severity": "warning",
                    "violatingConstructs": [
                        {"constructPath": "ASHCDKNagScanner/tpl/ProbeBucket"}
                    ],
                }
            ],
        },
    ],
}


class TestOriginatingPackIsCarriedOnTheFinding:
    def test_each_finding_records_the_plugin_that_produced_it(self, tmp_path: Path):
        """The pack travels on the finding record, not only as a dict key.

        The per-pack mapping this function returns is consumed by a loop in the scanner that
        binds the key to a variable, logs it, and extends one flat list -- so the key is gone by
        the time SARIF is assembled. Putting the pack on the finding is what survives that.
        """
        from automated_security_helper.utils.cdk_nag_wrapper import (
            _violations_from_validation_report,
        )

        per_pack, failure = _violations_from_validation_report(
            _write_report(tmp_path, TWO_PLUGIN_REPORT)
        )

        assert failure is None
        assert set(per_pack) == {"AwsSolutions", "CloudFormation Validate"}

        for pack_name, findings in per_pack.items():
            assert findings, f"pack {pack_name!r} produced no findings"
            for finding in findings:
                assert finding.pack == pack_name, (
                    f"finding {finding.rule_id} landed under pack {pack_name!r} but records "
                    f"its pack as {finding.pack!r}"
                )

    def test_the_pack_survives_into_the_serialized_finding_record(self, tmp_path: Path):
        """``as_dict()`` is the property bag the scanner reads back out of SARIF.

        ``cdk_nag_finding`` is indexed by these exact keys downstream, so a pack that exists on
        the object but not in this dict is a pack the reporting path still cannot see.
        """
        from automated_security_helper.utils.cdk_nag_wrapper import (
            _violations_from_validation_report,
        )

        per_pack, _ = _violations_from_validation_report(
            _write_report(tmp_path, TWO_PLUGIN_REPORT)
        )

        record = per_pack["CloudFormation Validate"][0].as_dict()
        assert record["pack"] == "CloudFormation Validate"
        assert record["rule_id"] == "F3017"

        # The control: the nag pack's own finding must record its own pack, not the foreign one.
        nag_record = per_pack["AwsSolutions"][0].as_dict()
        assert nag_record["pack"] == "AwsSolutions"
