# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Secret findings from semgrep and opengrep are secret findings too.

Both are SAST scanners, and neither tags a secret finding ``secret``: their
``generic.secrets.*`` rules (ASH's default ``p/ci`` ruleset holds them) carry
``CWE-798: Use of Hard-coded Credentials`` in the rule's tags, and the results
carry no tags at all. The fixture is the SARIF opengrep 1.30.2 writes for the two
p/ci AWS rules (``tests/utils/secret_bearing_scan.opengrep_secret_sarif``), passed
through ``attach_scanner_details`` and merged as ``ScanResultProcessor`` merges it.
"""

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sarif_utils import attach_scanner_details
from automated_security_helper.utils.secret_masking import (
    is_secret_finding,
    mask_secrets_in_results,
)
from tests.utils.secret_bearing_scan import (
    FIXTURE_FILES,
    KEY_ID_USE_LINE,
    SECRETS,
    opengrep_secret_sarif,
)

pytestmark = pytest.mark.unit


def _scanner_report(scanner_name, sarif):
    report = SarifReport.model_validate(sarif)
    return attach_scanner_details(
        report, scanner_name=scanner_name, scanner_version="1.0.0"
    )


def _bandit_neighbor():
    """bandit's B602 on settings.py line 4, whose context holds line 3."""
    lines = FIXTURE_FILES["settings.py"].splitlines(keepends=True)
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Bandit"}},
                "results": [
                    {
                        "ruleId": "B602",
                        "level": "error",
                        "message": {
                            "text": "subprocess call with shell=True identified, "
                            "security issue."
                        },
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "settings.py"},
                                    "region": {
                                        "startLine": 4,
                                        "endLine": 4,
                                        "snippet": {"text": lines[3]},
                                    },
                                    "contextRegion": {
                                        "startLine": 3,
                                        "endLine": 4,
                                        "snippet": {"text": lines[2] + lines[3]},
                                    },
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }


def _model(scanner_name, driver_name="Opengrep OSS"):
    model = AshAggregatedResults()
    model.sarif.merge_sarif_report(
        _scanner_report(scanner_name, opengrep_secret_sarif(driver_name=driver_name))
    )
    model.sarif.merge_sarif_report(_scanner_report("bandit", _bandit_neighbor()))
    return model


@pytest.mark.parametrize(
    "scanner_name, driver_name",
    [("opengrep", "Opengrep OSS"), ("semgrep", "Semgrep OSS")],
)
class TestGrepSecretFindings:
    def test_each_p_ci_secret_result_is_a_secret_finding(
        self, scanner_name, driver_name
    ):
        model = _model(scanner_name, driver_name)
        grep_secret_rule_ids = {
            rule_id
            for rule_id in (result.ruleId for result in model.sarif.get_all_results())
            if rule_id.startswith("generic.secrets.")
        }
        assert len(grep_secret_rule_ids) == 2

        from automated_security_helper.utils.secret_masking import (
            secret_rule_ids,
        )

        metadata_ids = secret_rule_ids(model.sarif)
        for result in model.sarif.get_all_results():
            if result.ruleId in grep_secret_rule_ids:
                assert is_secret_finding(result, metadata_ids), result.ruleId
            else:
                assert not is_secret_finding(result, metadata_ids), result.ruleId

    def test_their_values_are_masked_in_their_own_and_neighboring_snippets(
        self, scanner_name, driver_name
    ):
        model = _model(scanner_name, driver_name)
        assert SECRETS.key_id in model.sarif.model_dump_json()

        mask_secrets_in_results(model)

        dumped = model.sarif.model_dump_json()
        assert SECRETS.key_id not in dumped
        assert SECRETS.long_key not in dumped
        b602 = next(
            result
            for result in model.sarif.get_all_results()
            if result.ruleId == "B602"
        )
        context = b602.locations[0].physicalLocation.root.contextRegion.snippet.text
        assert context.endswith(KEY_ID_USE_LINE)


def _tagged(rule_id, tags=None, tool_tags=None, scanner="semgrep"):
    """One result whose rule carries ``tags``, merged as the engine merges it."""
    rule = {"id": rule_id}
    if tags is not None:
        rule["properties"] = {"tags": tags}
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Semgrep OSS", "rules": [rule]}},
                "results": [
                    {
                        "ruleId": rule_id,
                        "message": {"text": "finding"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "app.py"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                        **(
                            {"properties": {"tags": tool_tags}}
                            if tool_tags is not None
                            else {}
                        ),
                    }
                ],
            }
        ],
    }
    model = AshAggregatedResults()
    model.sarif.merge_sarif_report(_scanner_report(scanner, sarif))
    return model


class TestWhatCountsAsASecretRule:
    @pytest.mark.parametrize(
        "tags",
        [
            ["CWE-798: Use of Hard-coded Credentials", "security"],
            ["CWE-259: Use of Hard-coded Password"],
            ["CWE-321: Use of Hard-coded Cryptographic Key"],
            ["security", "external/cwe/cwe-798"],
            ["cwe-259"],
        ],
    )
    def test_a_hard_coded_credential_cwe_in_the_rule_tags(self, tags):
        from automated_security_helper.utils.secret_masking import (
            secret_rule_ids,
        )

        model = _tagged("python.lang.security.audit.some-rule", tags)

        assert secret_rule_ids(model.sarif) == {"python.lang.security.audit.some-rule"}

    def test_a_cwe_on_the_result_tags(self):
        model = _tagged("python.lang.example", tool_tags=["CWE-798"])
        result = model.sarif.get_all_results()[0]

        assert is_secret_finding(result)

    @pytest.mark.parametrize(
        "rule_id",
        [
            "generic.secrets.security.detected-private-key.detected-private-key",
            "acme.secrets.gitleaks.generic-api-key",
        ],
    )
    def test_a_secrets_rule_id(self, rule_id):
        model = _tagged(rule_id)

        assert is_secret_finding(model.sarif.get_all_results()[0])

    @pytest.mark.parametrize(
        "rule_id, tags",
        [
            ("python.lang.security.audit.subprocess-shell-true", ["CWE-78"]),
            ("python.lang.security.audit.subprocess-shell-true", ["CWE-7980"]),
            ("python.lang.correctness.secretsless-name", None),
        ],
    )
    def test_other_rules_are_not_secret_rules(self, rule_id, tags):
        from automated_security_helper.utils.secret_masking import (
            secret_rule_ids,
        )

        model = _tagged(rule_id, tags)
        result = model.sarif.get_all_results()[0]

        assert not is_secret_finding(result, secret_rule_ids(model.sarif))


class TestSecretDetectionIsTheNarrowerQuestion:
    """``is_secret_detection``: what the Bedrock summary reporter counts, not sends.

    A hard-coded password check (bandit B105-B107, tagged CWE-259) is a secret
    finding for masking, because its message quotes the value, but it is not a
    detection of a credential: its masked message is still useful to a summary.
    """

    def test_a_p_ci_secret_rule_is_a_detection(self):
        from automated_security_helper.utils.secret_masking import (
            is_secret_detection,
            secret_detection_rule_ids,
        )

        model = _model("semgrep", "Semgrep OSS")
        ids = secret_detection_rule_ids(model.sarif)
        detections = [
            result.ruleId
            for result in model.sarif.get_all_results()
            if is_secret_detection(result, ids)
        ]

        assert sorted(detections) == sorted(
            result.ruleId
            for result in model.sarif.get_all_results()
            if result.ruleId.startswith("generic.secrets.")
        )

    def test_a_hard_coded_password_check_is_a_secret_finding_but_not_a_detection(
        self,
    ):
        from automated_security_helper.utils.secret_masking import (
            is_secret_detection,
            secret_detection_rule_ids,
            secret_rule_ids,
        )

        model = _tagged("B105", ["security", "external/cwe/cwe-259"], scanner="bandit")
        result = model.sarif.get_all_results()[0]

        assert is_secret_finding(result, secret_rule_ids(model.sarif))
        assert not is_secret_detection(result, secret_detection_rule_ids(model.sarif))
