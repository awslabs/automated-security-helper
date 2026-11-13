# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The identity keys match the Security Hub reporter's, field for field.

The Security Hub reporter builds its finding ``Id`` from the same key as the
flattened ``id`` (``"ash/" + sha256(json.dumps([target, key], sort_keys=True))``),
and takes its keys from ``utils/finding_identity.identity_keys``. ``EXPECTED`` is
what the reporter's own ``build_asff_findings`` built for the results below, at
the commit that implemented identity contract v2 on its branch, before it called
the shared functions. The flattened findings' keys have to equal it, and so do
the keys behind the Ids the reporter sends now, or Security Hub Ids would have
changed.

The results cover a finding alone with its key, findings sharing a key (with an
exact duplicate), two without a column, a dotted and a backslashed path, a finding
without a location, a non-ASCII message, a column of 1 against none, a workspace
project, semgrep's placeholder fingerprint, a unique, a shared and a column-shared
fingerprint, partial fingerprints alone and behind a placeholder, and two packages
of one lockfile.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
    SecurityHubReporter,
    SecurityHubReporterConfig,
    SecurityHubReporterConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    Message1,
    PhysicalLocation,
    PhysicalLocation2,
    PropertyBag,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.finding_identity import identity_keys

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


def res(rule, uri, line, col=None, text="m", fp=None, pfp=None, props=None):
    """One result, with only the fields given."""
    kw = {
        "ruleId": rule,
        "level": "error",
        "message": Message(root=Message1(text=text)),
    }
    if uri is not None:
        region = {"startLine": line, "endLine": line}
        if col is not None:
            region["startColumn"] = col
        kw["locations"] = [
            Location(
                physicalLocation=PhysicalLocation(
                    root=PhysicalLocation2(
                        artifactLocation=ArtifactLocation(uri=uri),
                        region=Region(**region),
                    )
                )
            )
        ]
    if fp is not None:
        kw["fingerprints"] = fp
    if pfp is not None:
        kw["partialFingerprints"] = pfp
    if props is not None:
        kw["properties"] = PropertyBag(**props)
    return Result(**kw)


def report():
    """Three scanners' results, in a fixed order."""
    bandit = [
        res("B602", "src/app.py", 10, None, "lone"),
        res("B602", "src/app.py", 20, 5, "dup"),
        res("B602", "src/app.py", 20, 9, "dup"),
        res("B602", "src/app.py", 20, 5, "dup"),
        res("B602", "src/app.py", 30, None, "first"),
        res("B602", "src/app.py", 30, None, "second"),
        res("B602", "./src/b.py", 1, None, "dotted"),
        res("B602", "src\\win\\c.py", 2, None, "backslash"),
        res("B602", None, None, None, "nowhere"),
        res("B602", "src/app.py", 40, 1, "café"),
        res("B602", "src/app.py", 40, 2, "café"),
        res("B602", "src/app.py", 50, 1, "z"),
        res("B602", "src/app.py", 50, None, "z"),
        res("B105", "src/app.py", 60, None, "proj", props={"workspace_project": "api"}),
    ]
    semgrep = [
        res("r1", "a.py", 3, 1, "p", fp={"matchBasedId/v1": "requires login"}),
        res("r1", "a.py", 4, 1, "p", fp={"matchBasedId/v1": "requires login"}),
        res("r1", "a.py", 5, 1, "u", fp={"matchBasedId/v1": "abc"}),
        res("r1", "a.py", 6, 1, "s", fp={"matchBasedId/v1": "same"}),
        res("r1", "a.py", 7, 1, "s", fp={"matchBasedId/v1": "same"}),
        res("r1", "a.py", 8, 1, "q", pfp={"primaryLocationLineHash": "p1"}),
        res("r1", "a.py", 9, 1, "q", fp={"x": " Requires Login"}, pfp={"y": "q9"}),
        res("r1", "a.py", 10, 3, "c", fp={"matchBasedId/v1": "col"}),
        res("r1", "a.py", 10, 30, "c", fp={"matchBasedId/v1": "col"}),
    ]
    grype = [
        res(
            "GHSA-1",
            "package-lock.json",
            1,
            None,
            "v",
            props={"package_name": "left-pad", "package_version": "1.0.0"},
        ),
        res(
            "GHSA-1",
            "package-lock.json",
            1,
            None,
            "v",
            props={"package_name": "right-pad", "package_version": "1.0.0"},
        ),
    ]
    runs = [
        Run(tool=Tool(driver=ToolComponent(name=name)), results=results)
        for name, results in (
            ("bandit", bandit),
            ("semgrep", semgrep),
            ("grype", grype),
        )
    ]
    return SarifReport(version="2.1.0", runs=runs)


EXPECTED = [
    {
        "endLine": 10,
        "file": "src/app.py",
        "package": [None, None],
        "project": None,
        "rule": "B602",
        "scanner": "bandit",
        "startLine": 10,
    },
    {
        "endLine": 20,
        "file": "src/app.py",
        "occurrence": "7e0b8c99",
        "package": [None, None],
        "project": None,
        "rule": "B602",
        "scanner": "bandit",
        "startLine": 20,
    },
    {
        "endLine": 20,
        "file": "src/app.py",
        "occurrence": "a7abac45",
        "package": [None, None],
        "project": None,
        "rule": "B602",
        "scanner": "bandit",
        "startLine": 20,
    },
    {
        "endLine": 20,
        "file": "src/app.py",
        "occurrence": "7e0b8c99",
        "ordinal": 1,
        "package": [None, None],
        "project": None,
        "rule": "B602",
        "scanner": "bandit",
        "startLine": 20,
    },
    {
        "endLine": 30,
        "file": "src/app.py",
        "occurrence": "54e3b237",
        "package": [None, None],
        "project": None,
        "rule": "B602",
        "scanner": "bandit",
        "startLine": 30,
    },
    {
        "endLine": 30,
        "file": "src/app.py",
        "occurrence": "1dbc8c31",
        "package": [None, None],
        "project": None,
        "rule": "B602",
        "scanner": "bandit",
        "startLine": 30,
    },
    {
        "endLine": 1,
        "file": "src/b.py",
        "package": [None, None],
        "project": None,
        "rule": "B602",
        "scanner": "bandit",
        "startLine": 1,
    },
    {
        # A relative path's backslash is part of a POSIX file name: sanitizing
        # writes "/" for the separators of a path made on Windows. Keyed
        # src/win/c.py until findings in a\b.py and a/b.py stopped sharing an Id.
        "endLine": 2,
        "file": "src\\win\\c.py",
        "package": [None, None],
        "project": None,
        "rule": "B602",
        "scanner": "bandit",
        "startLine": 2,
    },
    {
        "endLine": None,
        "file": None,
        "package": [None, None],
        "project": None,
        "rule": "B602",
        "scanner": "bandit",
        "startLine": None,
    },
    {
        "endLine": 40,
        "file": "src/app.py",
        "occurrence": "dc9fc9d7",
        "package": [None, None],
        "project": None,
        "rule": "B602",
        "scanner": "bandit",
        "startLine": 40,
    },
    {
        "endLine": 40,
        "file": "src/app.py",
        "occurrence": "70c83b60",
        "package": [None, None],
        "project": None,
        "rule": "B602",
        "scanner": "bandit",
        "startLine": 40,
    },
    {
        "endLine": 50,
        "file": "src/app.py",
        "occurrence": "3865f079",
        "package": [None, None],
        "project": None,
        "rule": "B602",
        "scanner": "bandit",
        "startLine": 50,
    },
    {
        "endLine": 50,
        "file": "src/app.py",
        "occurrence": "032cb2a0",
        "package": [None, None],
        "project": None,
        "rule": "B602",
        "scanner": "bandit",
        "startLine": 50,
    },
    {
        "endLine": 60,
        "file": "src/app.py",
        "package": [None, None],
        "project": "api",
        "rule": "B105",
        "scanner": "bandit",
        "startLine": 60,
    },
    {
        "endLine": 3,
        "file": "a.py",
        "package": [None, None],
        "project": None,
        "rule": "r1",
        "scanner": "semgrep",
        "startLine": 3,
    },
    {
        "endLine": 4,
        "file": "a.py",
        "package": [None, None],
        "project": None,
        "rule": "r1",
        "scanner": "semgrep",
        "startLine": 4,
    },
    {
        "file": "a.py",
        "fingerprints": [["matchBasedId/v1", "abc"]],
        "package": [None, None],
        "project": None,
        "rule": "r1",
        "scanner": "semgrep",
    },
    {
        "endLine": 6,
        "file": "a.py",
        "package": [None, None],
        "project": None,
        "rule": "r1",
        "scanner": "semgrep",
        "startLine": 6,
    },
    {
        "endLine": 7,
        "file": "a.py",
        "package": [None, None],
        "project": None,
        "rule": "r1",
        "scanner": "semgrep",
        "startLine": 7,
    },
    {
        "file": "a.py",
        "package": [None, None],
        "partialFingerprints": [["primaryLocationLineHash", "p1"]],
        "project": None,
        "rule": "r1",
        "scanner": "semgrep",
    },
    {
        "file": "a.py",
        "package": [None, None],
        "partialFingerprints": [["y", "q9"]],
        "project": None,
        "rule": "r1",
        "scanner": "semgrep",
    },
    {
        "endLine": 10,
        "file": "a.py",
        "occurrence": "0884e271",
        "package": [None, None],
        "project": None,
        "rule": "r1",
        "scanner": "semgrep",
        "startLine": 10,
    },
    {
        "endLine": 10,
        "file": "a.py",
        "occurrence": "c9e9067b",
        "package": [None, None],
        "project": None,
        "rule": "r1",
        "scanner": "semgrep",
        "startLine": 10,
    },
    {
        "endLine": 1,
        "file": "package-lock.json",
        "package": ["left-pad", None],
        "project": None,
        "rule": "GHSA-1",
        "scanner": "grype",
        "startLine": 1,
    },
    {
        "endLine": 1,
        "file": "package-lock.json",
        "package": ["right-pad", None],
        "project": None,
        "rule": "GHSA-1",
        "scanner": "grype",
        "startLine": 1,
    },
]


def test_the_keys_equal_the_security_hub_reporters():
    model = AshAggregatedResults()
    model.sarif = report()

    keys = identity_keys([vuln.identity for vuln in model.to_flat_vulnerabilities()])

    assert len(keys) == len(EXPECTED)
    for index, (key, expected) in enumerate(zip(keys, EXPECTED)):
        assert key == expected, (index, key, expected)


def _lone_finding_ids(tmp_path, uri: str) -> tuple[str, str]:
    """The flattened ``id`` and the Security Hub ``Id`` of one bandit finding at *uri*."""
    reporter = SecurityHubReporter(
        context=PluginContext(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            config=AshConfig(project_name="not-the-scope"),
        ),
        config=SecurityHubReporterConfig(
            enabled=True,
            options=SecurityHubReporterConfigOptions(
                aws_region="us-east-1", findings_scope="pinned-scope"
            ),
        ),
    )
    model = AshAggregatedResults()
    model.sarif = SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="bandit")),
                results=[res("B602", uri, 3, None, "same")],
            )
        ],
    )
    [finding] = reporter.build_asff_findings(
        model, account_id="123456789012", region="us-east-1"
    )
    [flat] = model.to_flat_vulnerabilities()
    return flat.id, finding["Id"]


def test_a_name_holding_a_backslash_is_a_different_finding_from_its_slash_spelling(
    tmp_path,
):
    """a\\b.py and a/b.py are two files on POSIX. Each is keyed as its own file,
    so neither takes the other's Id and Security Hub keeps both findings."""
    backslash = _lone_finding_ids(tmp_path, "a\\b.py")
    slash = _lone_finding_ids(tmp_path, "a/b.py")

    assert backslash[0] != slash[0]
    assert backslash[1] != slash[1]


def test_a_windows_path_is_still_the_same_finding_as_its_slash_spelling(tmp_path):
    windows = _lone_finding_ids(tmp_path, "C:\\repo\\src\\app.py")
    slash = _lone_finding_ids(tmp_path, "C:/repo/src/app.py")

    assert windows == slash


def test_the_security_hub_ids_are_the_hash_of_these_keys(tmp_path):
    """The Ids the reporter sends for these results, each the contract v2 hash of
    the findings_scope and the key above. Security Hub updates a finding whose Id
    it already has, so a changed Id would open every finding a second time."""
    reporter = SecurityHubReporter(
        context=PluginContext(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            config=AshConfig(project_name="not-the-scope"),
        ),
        config=SecurityHubReporterConfig(
            enabled=True,
            options=SecurityHubReporterConfigOptions(
                aws_region="us-east-1", findings_scope="pinned-scope"
            ),
        ),
    )
    model = AshAggregatedResults()
    model.sarif = report()

    findings = reporter.build_asff_findings(
        model, account_id="123456789012", region="us-east-1"
    )

    expected = [
        "ash/"
        + hashlib.sha256(
            json.dumps(["pinned-scope", key], sort_keys=True).encode("utf-8")
        ).hexdigest()
        for key in EXPECTED
    ]
    assert len(findings) == len(expected)
    for index, (finding, want) in enumerate(zip(findings, expected)):
        assert finding["Id"] == want, (index, EXPECTED[index])
