# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Real GuardDog over the inert fixture packages.

The unit tests feed the converter GuardDog output captured once from the pinned
version. This runs the pinned GuardDog itself -- installed through the scanner's
own uv path if it is not already present -- so a change in what GuardDog reports
for these fixtures, or in the JSON it prints, fails here rather than silently
diverging from the captures.

Runs in CI in the ``integration-test`` job (``--run-integration``), which has
network access for the install and for the one ``verify`` test.
"""

import shutil
from pathlib import Path
from typing import Any, List

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_guarddog_plugins.guarddog_scanner import (
    GuardDogScanner,
    GuardDogScannerConfig,
    GuardDogScannerConfigOptions,
)
from automated_security_helper.utils.config_trust import record_provenance

PluginContext.model_rebuild()

pytestmark = pytest.mark.integration

FIXTURE_REPO = (
    Path(__file__).resolve().parents[2]
    / "test_data"
    / "scanners"
    / "guarddog"
    / "fixture_repo"
)
HIT_LIMIT_REPO = FIXTURE_REPO.parent / "hit_limit_repo"


def _scanner(
    tmp_path: Path, repo: Path, config: AshConfig | None = None, **options
) -> GuardDogScanner:
    output = tmp_path / "out"
    output.mkdir(parents=True, exist_ok=True)
    context = PluginContext(
        source_dir=repo,
        output_dir=output,
        work_dir=output / "converted",
        config=config if config is not None else AshConfig(),
    )
    scanner = GuardDogScanner(
        context=context,
        config=GuardDogScannerConfig(
            enabled=True, options=GuardDogScannerConfigOptions(**options)
        ),
    )
    assert scanner.validate_plugin_dependencies(), (
        "GuardDog could not be installed or found; this test must run the real tool"
    )
    return scanner


def _rows(report):
    return sorted(
        (
            r.ruleId,
            r.properties.issue_severity,
            r.locations[0].physicalLocation.root.artifactLocation.uri,
            r.locations[0].physicalLocation.root.region.startLine,
        )
        for r in report.runs[0].results
    )


def test_real_guarddog_finds_the_suspicious_fixtures_and_only_those(tmp_path):
    repo = tmp_path / "src"
    shutil.copytree(FIXTURE_REPO, repo)
    # A malicious-looking file under node_modules must not be read at all.
    vendored = repo / "npm_clean" / "node_modules" / "evil"
    vendored.mkdir(parents=True)
    shutil.copyfile(repo / "npm_suspicious" / "index.js", vendored / "index.js")

    scanner = _scanner(tmp_path, repo)
    report = scanner.scan(target=repo, target_type="source")

    assert scanner.targets_attempted == 8
    assert scanner.targets_failed == 0
    assert _rows(report) == sorted(
        [
            ("threat-network-exfiltration", "HIGH", "pypi_suspicious/setup.py", 17),
            ("threat-process-download-exec", "HIGH", "pypi_suspicious/setup.py", 15),
            ("threat-process-download-exec", "HIGH", "pypi_suspicious/setup.py", 16),
            ("threat-process-download-exec", "HIGH", "pypi_suspicious/setup.py", 17),
            (
                "threat-runtime-obfuscation-base64exec",
                "HIGH",
                "pypi_suspicious/setup.py",
                15,
            ),
            (
                "threat-runtime-obfuscation-base64exec",
                "HIGH",
                "npm_suspicious/index.js",
                3,
            ),
            (
                "threat-runtime-obfuscation-base64exec",
                "HIGH",
                "go_suspicious/main.go",
                11,
            ),
            (
                "threat-runtime-obfuscation-base64exec",
                "HIGH",
                "action_suspicious/index.js",
                2,
            ),
            (
                "threat-runtime-obfuscation-base64exec",
                "HIGH",
                "gem_suspicious/lib/ash_guarddog_fixture.rb",
                4,
            ),
        ]
    )


def test_real_guarddog_rule_exclusion_is_honored(tmp_path):
    repo = tmp_path / "src"
    shutil.copytree(FIXTURE_REPO / "go_suspicious", repo / "go_suspicious")
    scanner = _scanner(
        tmp_path,
        repo,
        ecosystems=["go"],
        exclude_rules=["threat-runtime-obfuscation-base64exec"],
    )
    report = scanner.scan(target=repo, target_type="source")
    assert _rows(report) == []
    assert scanner.targets_attempted == 1 and scanner.targets_failed == 0


def test_real_guarddog_verify_reads_a_requirements_file(tmp_path):
    repo = tmp_path / "src"
    repo.mkdir()
    (repo / "requirements.txt").write_text("six==1.16.0\n")
    scanner = _scanner(
        tmp_path,
        repo,
        ecosystems=["pypi"],
        verify=True,
        include_capabilities=True,
    )
    report = scanner.scan(target=repo, target_type="source")
    assert scanner.targets_attempted == 1 and scanner.targets_failed == 0
    rows = _rows(report)
    assert rows, "six 1.16.0 calls exec(); GuardDog reports it as a capability"
    assert all(uri == "requirements.txt" and line == 1 for _, _, uri, line in rows)
    assert {r.properties.package_name for r in report.runs[0].results} == {"six"}


def test_real_guarddog_takes_an_ecosystem_specific_exclusion(tmp_path):
    """typosquatting exists for pypi but not github_action, which rejects it."""
    repo = tmp_path / "src"
    shutil.copytree(FIXTURE_REPO / "pypi_suspicious", repo / "pypi_suspicious")
    shutil.copytree(FIXTURE_REPO / "action_suspicious", repo / "action_suspicious")
    scanner = _scanner(
        tmp_path,
        repo,
        ecosystems=["pypi", "github_action"],
        exclude_rules=["typosquatting"],
    )
    report = scanner.scan(target=repo, target_type="source")
    assert scanner.targets_attempted == 2 and scanner.targets_failed == 0
    assert {uri.split("/")[0] for _, _, uri, _ in _rows(report)} == {
        "pypi_suspicious",
        "action_suspicious",
    }


def _lines_of(report: Any, rule_id: str) -> List[int]:
    return sorted(line for rule, _, _, line in _rows(report) if rule == rule_id)


def test_real_guarddog_reports_every_match_with_max_hits_zero(tmp_path):
    """GuardDog 3.2.0 stops threat-runtime-obfuscation-base64exec after one hit.

    The fixture has three; options.max_hits 0 runs GuardDog's own CLI with every
    rule's limit removed, so all three are reported.
    """
    repo = tmp_path / "src"
    shutil.copytree(HIT_LIMIT_REPO, repo)
    rule = "threat-runtime-obfuscation-base64exec"

    capped = _scanner(tmp_path / "default", repo, ecosystems=["pypi"])
    default_report = capped.scan(target=repo, target_type="source")
    unlimited = _scanner(tmp_path / "unlimited", repo, ecosystems=["pypi"], max_hits=0)
    unlimited_report = unlimited.scan(target=repo, target_type="source")

    assert _lines_of(default_report, rule) == [15]
    assert _lines_of(unlimited_report, rule) == [15, 19, 23]
    assert unlimited.targets_attempted == 1 and unlimited.targets_failed == 0


def test_real_guarddog_lowers_limits_only_when_the_operator_set_max_hits(tmp_path):
    """pypi_suspicious/setup.py has three download-exec matches (limit 3)."""
    repo = tmp_path / "src"
    shutil.copytree(FIXTURE_REPO / "pypi_suspicious", repo / "pypi_suspicious")
    rule = "threat-process-download-exec"
    operator = AshConfig()
    record_provenance(operator, in_tree=[])

    lowered = _scanner(
        tmp_path / "operator", repo, config=operator, ecosystems=["pypi"], max_hits=1
    ).scan(target=repo, target_type="source")
    from_tree = _scanner(tmp_path / "tree", repo, ecosystems=["pypi"], max_hits=1).scan(
        target=repo, target_type="source"
    )

    assert len(_lines_of(lowered, rule)) == 1
    assert _lines_of(from_tree, rule) == [15, 16, 17]
