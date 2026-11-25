# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""grype's fix versions reach the flat model's ``fix_available``.

The flat model reads ``fix_available`` from a result's properties; grype's
adapter never wrote it, so the native ``fix`` {state, versions} was dropped. The
adapter reads the one place grype's SARIF carries it: the rule's help text, which
grype's presenter writes as ``Fix Version: <versions>`` beside ``Package:`` and
``Version:`` (a real run is committed in ``tests/test_data/outputs/
ash_aggregated_results.json``, rule ``GHSA-3h5v-q93c-6h6q-ws``).

The conformance row is the repository's native grype fixture
(``tests/test_data/scanners/grype/grype.src.json``): the SARIF here is rendered
from its matches in the presenter's shape, so each native ``fix.versions`` is the
value the adapter must carry to the flat model. The rest pin the fail-closed
correlation: a result that cannot be tied to exactly one rule, package and
version gets nothing, and an empty fix list is never written as False.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
    GrypeScanner,
    GrypeScannerConfig,
    GrypeScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[4]
NATIVE = REPO_ROOT / "tests" / "test_data" / "scanners" / "grype" / "grype.src.json"


def _help(vuln_id, severity, name, version, fix, kind, location) -> str:
    # The text grype's SARIF presenter writes (read from a real run).
    return (
        f"Vulnerability {vuln_id}\nSeverity: {severity}\nPackage: {name}\n"
        f"Version: {version}\nFix Version: {fix}\nType: {kind}\n"
        f"Location: {location}\nData Namespace: github:language:{kind}\n"
        f"Link: [{vuln_id}](https://github.com/advisories/{vuln_id})"
    )


def _sarif_from(native: dict) -> dict:
    """grype's SARIF for *native* matches: one rule per vulnerability and package."""
    rules, results = [], []
    for match in native["matches"]:
        vuln, artifact = match["vulnerability"], match["artifact"]
        rule_id = f"{vuln['id']}-{artifact['name']}"
        location = artifact["locations"][0]["path"]
        if rule_id not in {rule["id"] for rule in rules}:
            rules.append(
                {
                    "id": rule_id,
                    "name": "RubyGemMatcherExactDirectMatch",
                    "helpUri": "https://github.com/anchore/grype",
                    "help": {
                        "text": _help(
                            vuln["id"],
                            vuln["severity"].lower(),
                            artifact["name"],
                            artifact["version"],
                            ", ".join(vuln["fix"]["versions"]),
                            artifact["type"],
                            location,
                        )
                    },
                    "properties": {"purls": [artifact["purl"]]},
                }
            )
        results.append(
            {
                "ruleId": rule_id,
                "ruleIndex": [r["id"] for r in rules].index(rule_id),
                "level": "error",
                "message": {
                    "text": f"A {vuln['severity'].lower()} vulnerability in "
                    f"{artifact['type']} package: {artifact['name']}, version "
                    f"{artifact['version']} was found at: {location}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": location},
                            "region": {"startLine": 1, "startColumn": 1},
                        }
                    }
                ],
            }
        )
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "grype", "rules": rules}},
                "results": results,
            }
        ],
    }


@pytest.fixture(scope="module")
def native() -> dict:
    return json.loads(NATIVE.read_text(encoding="utf-8"))


@pytest.fixture
def scanner(tmp_path) -> GrypeScanner:
    source = tmp_path / "src"
    source.mkdir()
    context = PluginContext(
        source_dir=source,
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "work",
        config=get_default_config(),
    )
    return GrypeScanner(
        context=context,
        config=GrypeScannerConfig(
            enabled=True, options=GrypeScannerConfigOptions(offline=True)
        ),
    )


def _process(scanner: GrypeScanner, sarif: dict, tmp_path: Path) -> SarifReport:
    report = SarifReport.model_validate(sarif)
    return scanner._post_process_sarif(report, [], tmp_path / "src")


def _fix(result):
    properties = result.properties
    return None if properties is None else getattr(properties, "fix_available", None)


def test_the_fixture_has_fixed_matches_for_the_row_to_mean_something(native):
    states = [m["vulnerability"]["fix"]["state"] for m in native["matches"]]
    assert states and set(states) == {"fixed"}
    assert all(m["vulnerability"]["fix"]["versions"] for m in native["matches"])


def test_every_fixed_native_match_reaches_the_flat_model(scanner, native, tmp_path):
    report = _process(scanner, _sarif_from(native), tmp_path)
    run = report.runs[0]
    assert len(run.results) == len(native["matches"]) == 8
    for result, match in zip(run.results, native["matches"]):
        assert match["vulnerability"]["fix"]["state"] == "fixed"
        assert _fix(result) is True, result.ruleId
        flat = FlatVulnerability.from_sarif_result(result, "grype", "SCA", run)
        assert flat.fix_available is True, result.ruleId


def test_the_package_identity_is_still_written_beside_it(scanner, native, tmp_path):
    report = _process(scanner, _sarif_from(native), tmp_path)
    properties = report.runs[0].results[0].properties
    dumped = properties.model_dump(exclude_none=True)
    assert dumped["fix_available"] is True
    assert dumped["package_name"] == "addressable"
    assert dumped["package_version"] == "2.7.0"


@pytest.mark.parametrize("empty", ["", "   "])
def test_an_empty_fix_list_attaches_nothing_not_false(scanner, native, tmp_path, empty):
    # grype writes an empty "Fix Version:" for not-fixed, wont-fix and unknown
    # alike, so the empty list cannot say that no fix exists.
    sarif = _sarif_from(native)
    for rule in sarif["runs"][0]["tool"]["driver"]["rules"]:
        rule["help"]["text"] = rule["help"]["text"].replace(
            "Fix Version: " + _versions(rule), "Fix Version: " + empty
        )
    report = _process(scanner, sarif, tmp_path)
    for result in report.runs[0].results:
        assert _fix(result) is None
        flat = FlatVulnerability.from_sarif_result(result, "grype", "SCA")
        assert flat.fix_available is None


def _versions(rule: dict) -> str:
    for line in rule["help"]["text"].splitlines():
        if line.startswith("Fix Version:"):
            return line.partition(":")[2].strip()
    raise AssertionError("no Fix Version line")


def _mutated(native, edit):
    sarif = _sarif_from(native)
    edit(sarif["runs"][0])
    return sarif


def _rule_for(run: dict, name: str) -> dict:
    return next(r for r in run["tool"]["driver"]["rules"] if r["id"].endswith(name))


def _results_for(run: dict, rule_id: str) -> list:
    return [r for r in run["results"] if r["ruleId"] == rule_id]


def _drop_the_help(run):
    _rule_for(run, "-addressable").pop("help")


def _duplicate_the_rule(run):
    rule = _rule_for(run, "-addressable")
    run["tool"]["driver"]["rules"].append(copy.deepcopy(rule))


def _repeat_the_fix_line(run):
    help_ = _rule_for(run, "-addressable")["help"]
    help_["text"] += "\nFix Version: 9.9.9"


def _drop_the_fix_line(run):
    help_ = _rule_for(run, "-addressable")["help"]
    help_["text"] = "\n".join(
        line for line in help_["text"].splitlines() if not line.startswith("Fix ")
    )


def _another_package_version_in_the_rule(run):
    help_ = _rule_for(run, "-addressable")["help"]
    help_["text"] = help_["text"].replace("Version: 2.7.0", "Version: 2.6.0")


def _another_package_name_in_the_rule(run):
    help_ = _rule_for(run, "-addressable")["help"]
    help_["text"] = help_["text"].replace("Package: addressable", "Package: other")


def _point_at_another_rule(run):
    rule = _rule_for(run, "-addressable")
    for result in _results_for(run, rule["id"]):
        result["ruleIndex"] = 1


def _message_of_another_shape(run):
    rule = _rule_for(run, "-addressable")
    for result in _results_for(run, rule["id"]):
        result["message"]["text"] = "A high vulnerability (fixed in 2.8.0)"


@pytest.mark.parametrize(
    "edit",
    [
        _drop_the_help,
        _duplicate_the_rule,
        _repeat_the_fix_line,
        _drop_the_fix_line,
        _another_package_version_in_the_rule,
        _another_package_name_in_the_rule,
        _point_at_another_rule,
        _message_of_another_shape,
    ],
)
def test_a_result_that_cannot_be_tied_to_one_statement_gets_nothing(
    scanner, native, tmp_path, edit
):
    report = _process(scanner, _mutated(native, edit), tmp_path)
    results = report.runs[0].results
    addressable = [r for r in results if r.ruleId.endswith("-addressable")]
    assert len(addressable) == 1
    assert _fix(addressable[0]) is None
    # The control: every other result, correlated, is still attached.
    assert [_fix(r) for r in results if r not in addressable] == [True] * 7


def test_a_result_with_no_rule_gets_nothing(scanner, native, tmp_path):
    def drop_rule(run):
        rules = run["tool"]["driver"]["rules"]
        rules.pop(0)
        for result in run["results"]:
            result.pop("ruleIndex")

    report = _process(scanner, _mutated(native, drop_rule), tmp_path)
    results = report.runs[0].results
    assert _fix(results[0]) is None
    assert [_fix(r) for r in results[1:]] == [True] * 7


def test_a_report_with_no_rules_or_runs_is_left_as_it_was(scanner, tmp_path):
    empty = SarifReport.model_validate({"version": "2.1.0", "runs": []})
    assert _process(scanner, empty.model_dump(by_alias=True), tmp_path).runs == []
    bare = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "grype"}},
                "results": [
                    {
                        "ruleId": "CVE-1-x",
                        "message": {
                            "text": "A high vulnerability in npm package: x, "
                            "version 1.0.0 was found at: package.json"
                        },
                    }
                ],
            }
        ],
    }
    report = _process(scanner, bare, tmp_path)
    assert _fix(report.runs[0].results[0]) is None
