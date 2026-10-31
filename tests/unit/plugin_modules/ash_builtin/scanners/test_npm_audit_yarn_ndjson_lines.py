# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""yarn's NDJSON is split at line feeds only.

``str.splitlines`` also splits at U+2028, U+2029, U+0085, U+000B and U+000C,
which a JSON string may hold unescaped (``JSON.stringify`` writes them as they
are). An advisory title holding one broke its event line in two: neither half
parsed, so a yarn 1 advisory was silently dropped, and a yarn 4 report was read
as an error.
"""

from __future__ import annotations

import json

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    _ndjson_lines,
)

pytestmark = pytest.mark.unit

#: Separators ``str.splitlines`` honors that JSON lets a string hold unescaped
#: (code points at or above U+0020). JSON requires the control characters below
#: U+0020 (U+000B, U+000C) to be escaped, so they never reach the stream raw.
#: Spelled with chr() so the source holds no raw separator character.
SEPARATORS = {
    "line-separator": chr(0x2028),
    "paragraph-separator": chr(0x2029),
    "next-line": chr(0x0085),
}
FORM_FEED = chr(0x0C)


def _dumps(value) -> str:
    """As yarn writes it: JSON.stringify leaves these code points unescaped."""
    return json.dumps(value, ensure_ascii=False)


def _yarn_1_advisory(title: str) -> str:
    advisory = {
        "type": "auditAdvisory",
        "data": {
            "resolution": {"id": 1065, "path": "lodash"},
            "advisory": {
                "module_name": "lodash",
                "id": 1065,
                "title": title,
                "url": "https://github.com/advisories/GHSA-p6mc-m468-83gw",
                "severity": "high",
                "cwe": ["CWE-1321"],
                "vulnerable_versions": ">=3.7.0 <4.17.19",
                "patched_versions": ">=4.17.19",
                "findings": [{"version": "4.17.11", "paths": ["lodash"]}],
            },
        },
    }
    summary = {
        "type": "auditSummary",
        "data": {"vulnerabilities": {"high": 1}, "totalDependencies": 1},
    }
    return _dumps(advisory) + "\n" + _dumps(summary) + "\n"


def _yarn_4_advisory(title: str) -> str:
    line = {
        "value": "lodash",
        "children": {
            "ID": 1065,
            "Issue": title,
            "URL": "https://github.com/advisories/GHSA-p6mc-m468-83gw",
            "Severity": "high",
            "Vulnerable Versions": ">=3.7.0 <4.17.19",
            "Tree Versions": ["4.17.11"],
            "Dependents": ["app@workspace:."],
        },
    }
    return _dumps(line) + "\n"


@pytest.mark.parametrize("name", sorted(SEPARATORS))
def test_a_separator_inside_a_yarn_1_title_does_not_drop_the_advisory(name):
    title = f"Prototype{SEPARATORS[name]}Pollution"
    stdout = _yarn_1_advisory(title)
    assert SEPARATORS[name] in stdout, "the separator must reach the stream raw"
    response = {"stdout": stdout, "stderr": "", "returncode": 8}

    report, reason = NpmAuditScanner._parse_yarn_audit(1, response)

    assert reason is None, reason
    (record,) = report["yarn_advisories"]
    assert record["package"] == "lodash"
    assert record["title"] == title
    assert record["versions"] == {"4.17.11": ["lodash"]}


@pytest.mark.parametrize("name", sorted(SEPARATORS))
def test_a_separator_inside_a_yarn_4_title_does_not_fail_the_report(name):
    title = f"Prototype{SEPARATORS[name]}Pollution"
    stdout = _yarn_4_advisory(title)
    assert SEPARATORS[name] in stdout, "the separator must reach the stream raw"
    response = {"stdout": stdout, "stderr": "", "returncode": 1}

    report, reason = NpmAuditScanner._parse_yarn_audit(4, response)

    assert reason is None, reason
    (record,) = report["yarn_advisories"]
    assert record["package"] == "lodash"
    assert record["title"] == title


def test_a_broken_line_is_still_a_problem():
    """Control: a line that is not JSON for a reason of yarn's own still fails
    the report, so the split change loosens nothing else."""
    response = {
        "stdout": "not json at all\n" + _yarn_4_advisory("Prototype Pollution"),
        "stderr": "",
        "returncode": 1,
    }

    report, reason = NpmAuditScanner._parse_yarn_audit(4, response)

    assert report is None
    assert "yarn audit reported an error" in (reason or ""), reason


def test_ndjson_lines_splits_at_line_feeds_only():
    text = "a" + SEPARATORS["line-separator"] + "b\nc\r\nd" + FORM_FEED + "e"

    assert _ndjson_lines(text) == [
        "a" + SEPARATORS["line-separator"] + "b\n",
        "c\r\n",
        "d" + FORM_FEED + "e",
    ]
    assert _ndjson_lines("x\n") == ["x\n"]
    assert _ndjson_lines("") == []
