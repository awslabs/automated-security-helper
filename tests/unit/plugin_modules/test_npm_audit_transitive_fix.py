# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression test for #222: transitive-only npm vulnerabilities must produce SARIF results.

Before the fix, _convert_npm_audit_to_sarif skipped vulnerabilities whose
`via` entries were all strings (transitive references to other packages).
Only `via` entries that were dicts (direct advisories) produced Results,
so transitive-only vulnerabilities were silently dropped.

The fix adds a second pass that creates a Result for any vulnerability
where has_dict_via is False and via_items is non-empty.
"""
import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
)


@pytest.fixture
def npm_scanner(test_plugin_context):
    scanner = NpmAuditScanner(
        context=test_plugin_context, config=NpmAuditScannerConfig()
    )
    scanner.exit_code = 0
    return scanner


def test_transitive_only_via_produces_result(npm_scanner):
    """When all via entries are strings, a Result should still be created.

    npm audit JSON for transitive vulnerabilities looks like:

        "nth-check": {
            "name": "nth-check",
            "severity": "high",
            "via": ["css-select"],
            "nodes": ["node_modules/nth-check"]
        }

    Before #222, this produced zero Results because the loop only created
    Results for dict-typed via entries.
    """
    npm_audit_json = {
        "vulnerabilities": {
            "nth-check": {
                "name": "nth-check",
                "severity": "high",
                "via": ["css-select"],
                "range": ">=1.0.0 <2.0.2",
                "nodes": ["node_modules/nth-check"],
                "fixAvailable": True,
            }
        }
    }

    sarif = npm_scanner._convert_npm_audit_to_sarif(npm_audit_json, "/fake")

    results = sarif.runs[0].results
    assert len(results) > 0, "Transitive-only vulnerability must produce a Result"
    assert "nth-check" in results[0].message.root.text


def test_direct_via_still_produces_result(npm_scanner):
    """A vulnerability with dict-typed via entries must still work."""
    npm_audit_json = {
        "vulnerabilities": {
            "lodash": {
                "name": "lodash",
                "severity": "critical",
                "via": [
                    {
                        "title": "Prototype Pollution",
                        "url": "https://github.com/advisories/GHSA-1234",
                        "cvss": {"score": 9.8},
                        "cwe": ["CWE-400"],
                    }
                ],
                "range": "<4.17.21",
                "nodes": ["node_modules/lodash"],
                "fixAvailable": True,
            }
        }
    }

    sarif = npm_scanner._convert_npm_audit_to_sarif(npm_audit_json, "/fake")

    results = sarif.runs[0].results
    assert len(results) > 0
    assert "lodash" in results[0].message.root.text


def test_mixed_via_only_creates_direct_results(npm_scanner):
    """When via contains both dicts and strings, only dicts produce Results
    (the transitive branch is only for the all-strings case)."""
    npm_audit_json = {
        "vulnerabilities": {
            "qs": {
                "name": "qs",
                "severity": "high",
                "via": [
                    {
                        "title": "Prototype Pollution in qs",
                        "url": "https://github.com/advisories/GHSA-5678",
                        "cvss": {"score": 7.5},
                        "cwe": ["CWE-1321"],
                    },
                    "express",
                ],
                "range": "<6.3.3",
                "nodes": ["node_modules/qs"],
                "fixAvailable": True,
            }
        }
    }

    sarif = npm_scanner._convert_npm_audit_to_sarif(npm_audit_json, "/fake")

    results = sarif.runs[0].results
    assert len(results) >= 1
    # The result should come from the dict via, not the transitive path
    rule_ids = [r.ruleId for r in results]
    assert not any("transitive" in rid for rid in rule_ids)
