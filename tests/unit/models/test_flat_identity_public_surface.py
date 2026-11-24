"""The public surface a comparison reads a finding's identity through."""

import pytest

from automated_security_helper.models.flat_vulnerability import (
    FlatVulnerability,
    assign_identity_ids,
)
from automated_security_helper.schemas.sarif_schema_model import Result
from automated_security_helper.utils.finding_diff import fallback_key
from automated_security_helper.utils.finding_identity import canonical, key_base

pytestmark = pytest.mark.unit


def finding(line=10, message="msg", fingerprint=None):
    payload = {
        "ruleId": "R1",
        "message": {"text": message},
        "properties": {"issue_severity": "LOW"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "a.py"},
                    "region": {"startLine": line},
                }
            }
        ],
    }
    if fingerprint:
        payload["fingerprints"] = {"key": fingerprint}
    return FlatVulnerability.from_sarif_result(
        Result.model_validate(payload), "scanner", "scanner"
    )


def test_assigned_finding_exposes_message_and_location_free_base():
    vuln = finding(line=10, message="hello")
    assign_identity_ids([vuln])
    assert vuln.identity_message == "hello"
    assert vuln.has_fingerprint_identity is False
    base = vuln.identity_base
    assert base == key_base(vuln._assigned_identity_key)
    assert "startLine" not in base
    assert base["scanner"] == "scanner"


def test_fingerprinted_finding_reports_a_fingerprint_identity():
    vuln = finding(fingerprint="unique")
    assign_identity_ids([vuln])
    assert vuln.has_fingerprint_identity is True


def test_finding_with_identity_but_no_assigned_key_uses_the_identity_base():
    vuln = finding()
    assert vuln.identity is not None
    # The state of a row whose id was not taken from an assigned key.
    vuln._assigned_identity_key = None
    assert vuln.has_fingerprint_identity is False
    assert vuln.identity_base == dict(vuln.identity.base)


def test_finding_without_identity_exposes_nothing():
    vuln = FlatVulnerability.from_additional_report({"id": "x"}, "scanner")
    assert vuln.identity is None
    assert vuln.identity_base is None
    assert vuln.identity_message is None
    assert vuln.has_fingerprint_identity is False


def test_identity_base_is_a_copy():
    vuln = finding()
    assign_identity_ids([vuln])
    vuln.identity_base["scanner"] = "changed"
    assert vuln.identity_base["scanner"] == "scanner"


def test_fallback_key_is_built_from_the_public_surface():
    vuln = finding(message="hello")
    assign_identity_ids([vuln])
    assert fallback_key(vuln) == (
        canonical(vuln.identity_base),
        "hello",
        "LOW",
    )


def test_fallback_key_is_none_for_a_fingerprinted_finding():
    vuln = finding(fingerprint="unique")
    assign_identity_ids([vuln])
    assert fallback_key(vuln) is None
