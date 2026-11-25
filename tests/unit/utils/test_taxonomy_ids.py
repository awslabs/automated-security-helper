# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The CVE and CWE readings are one shared helper for the flat model and OCSF."""

import pytest

from automated_security_helper.models import flat_vulnerability
from automated_security_helper.plugin_modules.ash_builtin.reporters import (
    ocsf_reporter,
)
from automated_security_helper.utils import taxonomy_ids
from automated_security_helper.utils.taxonomy_ids import (
    cve_of_rule_id,
    cwes_of_tags,
)

pytestmark = pytest.mark.unit


def test_both_consumers_use_the_same_helper_object():
    assert flat_vulnerability.cve_of_rule_id is taxonomy_ids.cve_of_rule_id
    assert ocsf_reporter.cve_of_rule_id is taxonomy_ids.cve_of_rule_id
    assert flat_vulnerability.cwes_of_tags is taxonomy_ids.cwes_of_tags


@pytest.mark.parametrize(
    "rule_id, expected",
    [
        ("CVE-2019-20477", "CVE-2019-20477"),
        ("CVE-2022-40897-setuptools", "CVE-2022-40897"),
        ("cve-2022-40897", "CVE-2022-40897"),
        ("  CVE-2019-20477  ", "CVE-2019-20477"),
        ("B602", None),
        ("GHSA-xxxx-yyyy-zzzz", None),
        ("vendor.CVE-2019-20477", None),
        ("CVE-2019", None),
        ("CVE-2019-204779x", None),
        ("", None),
        (None, None),
        (12345, None),
    ],
)
def test_cve_of_rule_id(rule_id, expected):
    assert cve_of_rule_id(rule_id) == expected


@pytest.mark.parametrize(
    "tags, expected",
    [
        (["external/cwe/cwe-78"], ["CWE-78"]),
        (["CWE-798: Use of Hard-coded Credentials"], ["CWE-798"]),
        (["CWE-798"], ["CWE-798"]),
        (["external/cwe/cwe-78", "CWE-78: OS Command Injection"], ["CWE-78"]),
        (["CWE-89", "external/cwe/cwe-78"], ["CWE-89", "CWE-78"]),
        (["owasp/cwe-78", "see CWE-78", "CWE-78x"], []),
        (["security", None, 7], []),
        ([], []),
    ],
)
def test_cwes_of_tags(tags, expected):
    assert cwes_of_tags(tags) == expected
