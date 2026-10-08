# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""GuardDog scanner: result conversion, target discovery, failure handling.

What is real here
-----------------
The JSON fed to the converter is real GuardDog 3.2.0 output, captured from the
inert fixture packages in ``tests/test_data/scanners/guarddog/fixture_repo`` and
committed under ``tests/test_data/scanners/guarddog/captured``. To regenerate it,
run ``guarddog <ecosystem> scan <fixture package dir> --output-format json`` for
each ``scan_<ecosystem>_<package>.json`` and replace the ``package`` field with
``<scanned-dir>/<package>`` (it holds an absolute local path). The verify capture
is ``guarddog pypi verify verify_pypi_requirements.txt --output-format json`` with
the download paths replaced the same way.

The scanner tests drive the real ``scan()`` over a copy of the fixture tree and
patch two seams only: the dependency probe and ``_run_subprocess``, which serves
the captured JSON for whichever package was staged, so discovery, staging, the
argv ASH builds and the failure paths are all exercised as written.

Negative controls
-----------------
``test_mutated_capture_does_not_match_the_expectation`` changes one field of the
real capture at a time (rule id, severity, line, file) and asserts the converted
result no longer equals the expectation the positive test pins, so the positive
assertion is shown to depend on each of those fields.
"""

from __future__ import annotations

import copy
import json
import logging
import os
import platform
import shutil
from pathlib import Path
from typing import Any, Dict, List, Literal

import pytest
from pydantic import ValidationError

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.plugin_modules.ash_guarddog_plugins.guarddog_scanner import (
    GUARDDOG_DEFAULT_VERSION_CONSTRAINT,
    GUARDDOG_PYTHON_REQUEST,
    GuardDogScanner,
    GuardDogScannerConfig,
    GuardDogScannerConfigOptions,
    _risk_severity,
    convert_guarddog_scan_result,
    manifest_line_for,
)

PluginContext.model_rebuild()

DATA = Path(__file__).resolve().parents[3] / "test_data" / "scanners" / "guarddog"
FIXTURE_REPO = DATA / "fixture_repo"
CAPTURED = DATA / "captured"

#: Which capture answers a scan of which fixture package.
CAPTURE_FOR = {
    ("pypi", "pypi_suspicious"): "scan_pypi_pypi_suspicious.json",
    ("pypi", "pypi_clean"): "scan_pypi_pypi_clean.json",
    ("npm", "npm_suspicious"): "scan_npm_npm_suspicious.json",
    ("npm", "npm_clean"): "scan_npm_npm_clean.json",
    ("go", "go_suspicious"): "scan_go_go_suspicious.json",
    ("github_action", "action_suspicious"): "scan_github_action_action_suspicious.json",
    ("rubygems", "gem_suspicious"): "scan_rubygems_gem_suspicious.json",
    ("crates", "crate_suspicious"): "scan_crates_crate_suspicious.json",
}


def _capture(name: str) -> Any:
    return json.loads((CAPTURED / name).read_text(encoding="utf-8"))


def _summary(converted) -> List[tuple]:
    rows = []
    for result in converted.results:
        location = result.locations[0].physicalLocation.root
        rows.append(
            (
                result.ruleId,
                result.properties.issue_severity,
                result.level.value if hasattr(result.level, "value") else result.level,
                location.artifactLocation.uri,
                location.region.startLine if location.region else None,
            )
        )
    return sorted(rows)


# The five risks GuardDog 3.2.0 forms for pypi_suspicious/setup.py, each HIGH.
PYPI_SUSPICIOUS_EXPECTED = sorted(
    [
        ("threat-network-exfiltration", "HIGH", "error", "pkg/setup.py", 17),
        ("threat-process-download-exec", "HIGH", "error", "pkg/setup.py", 15),
        ("threat-process-download-exec", "HIGH", "error", "pkg/setup.py", 16),
        ("threat-process-download-exec", "HIGH", "error", "pkg/setup.py", 17),
        ("threat-runtime-obfuscation-base64exec", "HIGH", "error", "pkg/setup.py", 15),
    ]
)


# --------------------------------------------------------------------------- #
# Conversion of real GuardDog output
# --------------------------------------------------------------------------- #


def test_real_capture_converts_to_one_result_per_risk():
    converted = convert_guarddog_scan_result(
        _capture("scan_pypi_pypi_suspicious.json"), uri_prefix="pkg", ecosystem="pypi"
    )
    assert _summary(converted) == PYPI_SUSPICIOUS_EXPECTED
    # Every reported rule has a descriptor, and capability-only rules have none.
    assert set(converted.rules) == {r[0] for r in PYPI_SUSPICIOUS_EXPECTED}


def _mutate_rule(doc):
    doc["risks"][0]["threat_rule"] = "threat-something-else"


def _mutate_severity(doc):
    doc["risks"][0]["severity"] = "low"


def _mutate_line(doc):
    doc["risks"][0]["threat_location"] = "setup.py:99"


def _mutate_file(doc):
    doc["risks"][0]["threat_location"] = "other.py:17"


@pytest.mark.parametrize(
    "mutate", [_mutate_rule, _mutate_severity, _mutate_line, _mutate_file]
)
def test_mutated_capture_does_not_match_the_expectation(mutate):
    doc = _capture("scan_pypi_pypi_suspicious.json")
    mutate(doc)
    converted = convert_guarddog_scan_result(doc, uri_prefix="pkg", ecosystem="pypi")
    assert _summary(converted) != PYPI_SUSPICIOUS_EXPECTED


@pytest.mark.parametrize(
    "capture,expected",
    [
        (
            "scan_npm_npm_suspicious.json",
            [
                (
                    "threat-runtime-obfuscation-base64exec",
                    "HIGH",
                    "error",
                    "p/index.js",
                    3,
                )
            ],
        ),
        (
            "scan_go_go_suspicious.json",
            [
                (
                    "threat-runtime-obfuscation-base64exec",
                    "HIGH",
                    "error",
                    "p/main.go",
                    11,
                )
            ],
        ),
        (
            "scan_github_action_action_suspicious.json",
            [
                (
                    "threat-runtime-obfuscation-base64exec",
                    "HIGH",
                    "error",
                    "p/index.js",
                    2,
                )
            ],
        ),
        (
            "scan_rubygems_gem_suspicious.json",
            [
                (
                    "threat-runtime-obfuscation-base64exec",
                    "HIGH",
                    "error",
                    "p/lib/ash_guarddog_fixture.rb",
                    4,
                )
            ],
        ),
        ("scan_pypi_pypi_clean.json", []),
        ("scan_npm_npm_clean.json", []),
        # Only a capability match: context, not a finding, by default.
        ("scan_crates_crate_suspicious.json", []),
    ],
)
def test_each_ecosystem_capture(capture, expected):
    doc = _capture(capture)
    converted = convert_guarddog_scan_result(doc, uri_prefix="p", ecosystem="x")
    assert _summary(converted) == sorted(expected)


def test_capabilities_are_info_and_only_on_request():
    doc = _capture("scan_crates_crate_suspicious.json")
    off = convert_guarddog_scan_result(doc, uri_prefix="", ecosystem="crates")
    on = convert_guarddog_scan_result(
        doc, uri_prefix="", ecosystem="crates", include_capabilities=True
    )
    assert off.results == []
    assert _summary(on) == [("capability-process-spawn", "INFO", "none", "build.rs", 4)]


def test_a_threat_guarddog_did_not_correlate_is_low():
    doc = _capture("scan_npm_npm_suspicious.json")
    doc["risks"] = []
    converted = convert_guarddog_scan_result(doc, uri_prefix="", ecosystem="npm")
    assert _summary(converted) == [
        ("threat-runtime-obfuscation-base64exec", "LOW", "note", "index.js", 3)
    ]
    assert "not correlated" in converted.results[0].message.root.text


def test_a_risk_and_its_threat_match_are_reported_once():
    doc = _capture("scan_npm_npm_suspicious.json")
    converted = convert_guarddog_scan_result(doc, uri_prefix="", ecosystem="npm")
    assert len(converted.results) == 1


def test_a_metadata_rule_that_fired_is_medium():
    doc = _capture("scan_pypi_pypi_clean.json")
    doc["results"]["typosquatting"] = "This package closely ressembles: requests"
    converted = convert_guarddog_scan_result(doc, uri_prefix="pkg", ecosystem="pypi")
    assert _summary(converted) == [("typosquatting", "MEDIUM", "warning", "pkg", None)]


def test_metadata_rules_that_did_not_fire_are_ignored():
    doc = _capture("scan_pypi_pypi_clean.json")
    doc["results"]["typosquatting"] = None
    doc["results"]["deceptive_author"] = {}
    assert (
        convert_guarddog_scan_result(doc, uri_prefix="", ecosystem="pypi").results == []
    )


@pytest.mark.parametrize(
    "value,expected",
    [
        ("high", "HIGH"),
        ("medium", "MEDIUM"),
        ("low", "LOW"),
        ("HIGH", "HIGH"),
        ("?", "MEDIUM"),
        (None, "MEDIUM"),
    ],
)
def test_risk_severity_mapping(value, expected):
    assert _risk_severity(value) == expected


def test_verify_findings_land_on_the_manifest_line_with_package_identity():
    entries = _capture("verify_pypi_requirements.json")
    entry = entries[0]
    manifest = (CAPTURED / "verify_pypi_requirements.txt").read_text()
    default = convert_guarddog_scan_result(
        entry["result"],
        uri_prefix="",
        ecosystem="pypi",
        dependency=(entry["dependency"], entry["version"]),
        manifest_uri="requirements.txt",
        manifest_line=manifest_line_for(manifest, entry["dependency"]),
    )
    # The capture holds only a capability match in six, which is not a finding.
    assert default.results == []
    on = convert_guarddog_scan_result(
        entry["result"],
        uri_prefix="",
        ecosystem="pypi",
        include_capabilities=True,
        dependency=(entry["dependency"], entry["version"]),
        manifest_uri="requirements.txt",
        manifest_line=manifest_line_for(manifest, entry["dependency"]),
    )
    assert _summary(on) == [
        ("capability-process-spawn", "INFO", "none", "requirements.txt", 1)
    ]
    props = on.results[0].properties
    assert props.package_name == "six"
    assert props.package_version == "1.16.0"
    assert "six.py:735" in on.results[0].message.root.text


def test_verify_risk_in_a_dependency_is_reported_on_the_manifest():
    entries = _capture("verify_pypi_requirements.json")
    result = copy.deepcopy(entries[0]["result"])
    result["risks"] = [
        {
            "name": "risk.runtime.obfuscation",
            "severity": "high",
            "threat_rule": "threat-runtime-obfuscation-base64exec",
            "threat_location": "six/evil.py:3",
            "threat_description": "Detects base64 decoding followed by code execution",
            "threat_code": "exec(base64.b64decode(x))",
            "mitre_tactics": ["defense-evasion"],
        }
    ]
    converted = convert_guarddog_scan_result(
        result,
        uri_prefix="",
        ecosystem="pypi",
        dependency=("six", "1.16.0"),
        manifest_uri="sub/requirements.txt",
        manifest_line=3,
    )
    assert _summary(converted) == [
        (
            "threat-runtime-obfuscation-base64exec",
            "HIGH",
            "error",
            "sub/requirements.txt",
            3,
        )
    ]
    assert converted.results[0].message.root.text.startswith("Dependency six 1.16.0:")


@pytest.mark.parametrize(
    "text,name,expected",
    [
        ("six==1.16.0\n", "six", 1),
        ("# comment\nsixer==1\nsix>=1\n", "six", 3),
        ('{\n  "dependencies": {\n    "left-pad": "1.0.0"\n  }\n}\n', "left-pad", 3),
        ("require github.com/a/b v1.0.0\n", "github.com/a/b", 1),
        ("nothing\n", "six", None),
    ],
)
def test_manifest_line_for(text, name, expected):
    assert manifest_line_for(text, name) == expected


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #


def test_guarddog_is_on_by_default_once_its_module_is_listed():
    assert GuardDogScannerConfig().enabled is True


@pytest.mark.parametrize("bad", ["--metadata=/etc/passwd", "-r", "Threat-X", "a b", ""])
def test_rule_names_are_validated(bad):
    with pytest.raises(ValidationError):
        GuardDogScannerConfigOptions(rules=[bad])
    with pytest.raises(ValidationError):
        GuardDogScannerConfigOptions(exclude_rules=[bad])


def test_rules_and_exclude_rules_are_exclusive():
    with pytest.raises(ValidationError):
        GuardDogScannerConfigOptions(
            rules=["typosquatting"], exclude_rules=["bundled_binary"]
        )


def test_unknown_ecosystem_is_rejected():
    with pytest.raises(ValidationError):
        GuardDogScannerConfigOptions(ecosystems=["maven"])


# --------------------------------------------------------------------------- #
# The scanner, with GuardDog itself replaced by its captured output
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _no_real_version_probe(monkeypatch):
    # model_post_init asks uv for GuardDog's version, which would download it.
    monkeypatch.setattr(
        GuardDogScanner, "_get_uv_tool_version", lambda self, name: "3.2.0"
    )


class _HostPlatform:
    """The ``platform`` module as GuardDog's scanner sees it, with ``system`` pinned."""

    def __init__(self, system: str) -> None:
        self._system = system

    def system(self) -> str:
        return self._system

    def __getattr__(self, name: str) -> Any:
        return getattr(platform, name)


@pytest.fixture(autouse=True)
def _a_supported_host(monkeypatch):
    """Run these tests as on Linux, whatever the host.

    GuardDog cannot be installed on Windows, so the scanner reports SKIPPED there
    (test_windows_is_an_unsupported_platform_with_no_install_command covers that).
    Every other test exercises the scan itself, with GuardDog replaced by its
    captured output, so it pins only the scanner module's view of the OS, not the
    process-wide ``platform`` module the rest of ASH reads.
    """
    import automated_security_helper.plugin_modules.ash_guarddog_plugins.guarddog_scanner as module

    monkeypatch.setattr(module, "platform", _HostPlatform("Linux"))


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "src"
    shutil.copytree(FIXTURE_REPO, repo)
    return repo


def _scanner(repo: Path, tmp_path: Path, **options) -> GuardDogScanner:
    output = tmp_path / "out"
    output.mkdir(exist_ok=True)
    context = PluginContext(
        source_dir=repo,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    return GuardDogScanner(
        context=context,
        config=GuardDogScannerConfig(
            enabled=True, options=GuardDogScannerConfigOptions(**options)
        ),
    )


def _tree(root: Path) -> frozenset:
    """A directory's files as (relative path, content) pairs.

    Content as well as names: npm_suspicious and npm_clean hold the same two
    file names, so names alone cannot tell which one was staged.
    """
    return frozenset(
        (p.relative_to(root).as_posix(), p.read_bytes())
        for p in root.rglob("*")
        if p.is_file()
    )


def _fixture_files() -> Dict[str, frozenset]:
    return {pkg.name: _tree(pkg) for pkg in FIXTURE_REPO.iterdir()}


#: Rule sets the fake ``list-rules`` reports. Like GuardDog 3.2.0, the metadata
#: rule typosquatting exists for pypi and npm and not for the other ecosystems.
BASE_RULES = [
    "capability-process-spawn",
    "threat-runtime-obfuscation-base64exec",
    "threat-process-download-exec",
]
RULES_BY_ECOSYSTEM = {
    "pypi": BASE_RULES + ["typosquatting"],
    "npm": BASE_RULES + ["typosquatting"],
}


def _rules_table(names: List[str]) -> str:
    rows = "\n".join(f"| Source code | {n:<40} | description |" for n in names)
    return (
        "+---+---+---+\n| Rule type   | Rule name | Description |\n+---+---+---+\n"
        f"{rows}\n+---+---+---+\n"
    )


class FakeGuardDog:
    """Stands in for ``_run_subprocess``: answers with the captured JSON."""

    def __init__(self):
        self.calls: List[List[str]] = []
        self.staged: List[frozenset] = []
        self.staged_dirs: List[Path] = []
        self.overrides: Dict[tuple, Dict[str, Any]] = {}
        self.default_response: Dict[str, Any] | None = None
        self.files = _fixture_files()

    def package_for(self, staged: Path) -> str:
        found = _tree(staged)
        self.staged.append(found)
        for name, files in self.files.items():
            if files == found:
                return name
        raise AssertionError(
            f"staged files match no fixture package: {sorted(n for n, _ in found)}"
        )

    def __call__(
        self,
        scanner,
        command,
        results_dir=None,
        stdout_preference="write",
        stderr_preference="write",
        cwd=None,
        env=None,
        timeout=None,
    ):
        self.calls.append(list(command))
        ecosystem, mode = command[1], command[2]
        if mode == "list-rules":
            key = (ecosystem, "list-rules")
            spec = self.overrides.get(key) or {
                "returncode": 0,
                "stdout": _rules_table(RULES_BY_ECOSYSTEM.get(ecosystem, BASE_RULES)),
            }
        else:
            path = Path(command[3])
            if mode == "scan":
                self.staged_dirs.append(path)
                key = (ecosystem, self.package_for(path))
            else:
                key = (ecosystem, "verify")
            spec = self.overrides.get(key) or self.default_response
        if spec is None:
            stdout = (CAPTURED / CAPTURE_FOR[key]).read_text(encoding="utf-8")
            spec = {"returncode": 0, "stdout": stdout, "stderr": ""}
        if callable(spec):
            spec = spec(command)
        results_dir = Path(results_dir)
        if spec.get("stdout"):
            (results_dir / "GuardDogScanner.stdout.log").write_text(spec["stdout"])
        if spec.get("stderr"):
            (results_dir / "GuardDogScanner.stderr.log").write_text(spec["stderr"])
        response = {"returncode": spec.get("returncode", 0)}
        if spec.get("timed_out"):
            response["timed_out"] = True
        scanner.exit_code = max(scanner.exit_code, response["returncode"])
        return response


@pytest.fixture
def fake(monkeypatch):
    fake = FakeGuardDog()
    monkeypatch.setattr(
        GuardDogScanner,
        "_run_subprocess",
        lambda self, **kw: fake(self, **kw),
    )
    monkeypatch.setattr(
        GuardDogScanner, "validate_plugin_dependencies", lambda self: True
    )
    return fake


def _rows(report) -> List[tuple]:
    return sorted(
        (
            r.ruleId,
            r.properties.issue_severity,
            r.locations[0].physicalLocation.root.artifactLocation.uri,
            r.locations[0].physicalLocation.root.region.startLine,
        )
        for r in report.runs[0].results
    )


def test_scan_reports_every_suspicious_package_and_no_clean_one(tmp_path, fake):
    repo = _repo(tmp_path)
    scanner = _scanner(repo, tmp_path)
    report = scanner.scan(target=repo, target_type="source")

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
    # One invocation per package root, each with its own ecosystem.
    invoked = sorted((c[1], c[2]) for c in fake.calls)
    assert invoked == sorted(
        [
            ("pypi", "scan"),
            ("pypi", "scan"),
            ("npm", "scan"),
            ("npm", "scan"),
            ("go", "scan"),
            ("github_action", "scan"),
            ("rubygems", "scan"),
            ("crates", "scan"),
        ]
    )
    assert scanner.targets_attempted == 8 and scanner.targets_failed == 0
    assert all("--output-format" in c and "json" in c for c in fake.calls)
    on_disk = json.loads(
        (scanner.results_dir / "source" / "guarddog.sarif").read_text()
    )
    assert len(on_disk["runs"][0]["results"]) == 9


def test_excluded_directories_symlinks_and_ignores_are_not_staged(tmp_path, fake):
    repo = _repo(tmp_path)
    pkg = repo / "npm_suspicious"
    (pkg / "node_modules" / "evil").mkdir(parents=True)
    (pkg / "node_modules" / "evil" / "index.js").write_text("eval(atob('x'))\n")
    (pkg / ".venv").mkdir()
    (pkg / ".venv" / "x.py").write_text("exec(1)\n")
    outside = tmp_path / "outside.js"
    outside.write_text("eval(atob('x'))\n")
    try:
        (pkg / "linked.js").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable on this platform")
    (pkg / "ignored.js").write_text("eval(atob('x'))\n")

    scanner = _scanner(
        repo,
        tmp_path,
        ecosystems=["npm"],
        excluded_paths=[IgnorePathWithReason(path="**/ignored.js", reason="test")],
    )
    scanner.scan(
        target=repo,
        target_type="source",
        global_ignore_paths=[IgnorePathWithReason(path="npm_clean/**", reason="test")],
    )
    # npm_suspicious was staged with exactly its committed files; npm_clean never.
    assert fake.staged == [fake.files["npm_suspicious"]]


def test_a_nested_package_of_the_same_ecosystem_is_scanned_on_its_own(tmp_path, fake):
    repo = _repo(tmp_path)
    shutil.copytree(
        FIXTURE_REPO / "npm_clean", repo / "npm_suspicious" / "vendor" / "inner"
    )
    fake.files["inner"] = fake.files["npm_clean"]
    scanner = _scanner(repo, tmp_path, ecosystems=["npm"])
    scanner.scan(target=repo, target_type="source")
    # The parent's staging tree does not contain the nested root's files.
    assert fake.files["npm_suspicious"] in fake.staged
    assert len(fake.staged) == 3


def test_a_finding_matched_by_two_ecosystems_is_reported_once(tmp_path, fake):
    repo = _repo(tmp_path)
    # Make pypi_suspicious also an npm package root; both scans then see setup.py.
    (repo / "pypi_suspicious" / "package.json").write_text('{"name": "x"}\n')
    fake.files["pypi_suspicious_both"] = _tree(repo / "pypi_suspicious")
    capture = (CAPTURED / "scan_pypi_pypi_suspicious.json").read_text()
    fake.overrides[("pypi", "pypi_suspicious_both")] = {
        "returncode": 0,
        "stdout": capture,
    }
    fake.overrides[("npm", "pypi_suspicious_both")] = {
        "returncode": 0,
        "stdout": capture,
    }
    scanner = _scanner(repo, tmp_path, ecosystems=["pypi", "npm"])
    report = scanner.scan(target=repo, target_type="source")
    setup_rows = [r for r in _rows(report) if r[2] == "pypi_suspicious/setup.py"]
    assert len(setup_rows) == 5


def test_no_packages_attempts_nothing(tmp_path, fake):
    repo = tmp_path / "src"
    repo.mkdir()
    (repo / "README.md").write_text("hello\n")
    scanner = _scanner(repo, tmp_path)
    report = scanner.scan(target=repo, target_type="source")
    assert report.runs[0].results == []
    assert scanner.targets_attempted == 0
    assert fake.calls == []


@pytest.mark.parametrize(
    "spec,needle",
    [
        (
            {"returncode": 1, "stderr": "ERROR: Error occurred while scanning target"},
            "exited 1",
        ),
        ({"returncode": 124, "timed_out": True}, "timed out after"),
        ({"returncode": 0, "stdout": ""}, "printed no result"),
        ({"returncode": 0, "stdout": "not json"}, "not JSON"),
        ({"returncode": 0, "stdout": "[]"}, "not a scan result object"),
        (
            {
                "returncode": 0,
                "stdout": json.dumps(
                    {"results": {}, "errors": {"rule-x": "yara failed"}, "risks": []}
                ),
            },
            "some rules did not run",
        ),
    ],
)
def test_a_failed_invocation_is_an_error_and_the_report_is_kept(
    tmp_path, fake, spec, needle
):
    repo = _repo(tmp_path)
    fake.overrides[("go", "go_suspicious")] = spec
    scanner = _scanner(repo, tmp_path)
    with pytest.raises(ScannerError) as raised:
        scanner.scan(target=repo, target_type="source")
    assert needle in str(raised.value)
    assert "go scan of go_suspicious" in str(raised.value)
    assert scanner.targets_failed == 1 and scanner.targets_attempted == 8
    on_disk = json.loads(
        (scanner.results_dir / "source" / "guarddog.sarif").read_text()
    )
    assert on_disk["runs"][0]["invocations"][0]["executionSuccessful"] is False
    # The other packages' findings were kept on disk.
    assert len(on_disk["runs"][0]["results"]) >= 8


def test_scan_timeout_is_passed_to_each_invocation(tmp_path, fake, monkeypatch):
    seen = []
    original = FakeGuardDog.__call__

    def spy(self, scanner, command, **kw):
        seen.append(kw.get("timeout"))
        return original(self, scanner, command, **kw)

    monkeypatch.setattr(FakeGuardDog, "__call__", spy)
    repo = _repo(tmp_path)
    scanner = _scanner(repo, tmp_path, scan_timeout=42, ecosystems=["go"])
    scanner.scan(target=repo, target_type="source")
    assert seen == [42.0]


SANDBOX_UNAVAILABLE = {
    "returncode": 1,
    "stderr": "ERROR: Kernel-level sandbox is not available on this platform. Use --no-sandbox to scan without it.\n",
}


def test_sandbox_auto_falls_back_once_and_warns(tmp_path, fake, caplog):
    repo = _repo(tmp_path)

    def answer(command):
        if "--no-sandbox" in command:
            return None  # fall through to the capture
        return SANDBOX_UNAVAILABLE

    def spec_for(command):
        result = answer(command)
        if result is None:
            key = (command[1], fake.package_for(Path(command[3])))
            return {
                "returncode": 0,
                "stdout": (CAPTURED / CAPTURE_FOR[key]).read_text(),
            }
        return result

    fake.default_response = spec_for
    scanner = _scanner(repo, tmp_path, ecosystems=["npm", "go"])
    with caplog.at_level(logging.WARNING, logger="ash"):
        report = scanner.scan(target=repo, target_type="source")
    assert len(report.runs[0].results) == 2
    with_sandbox = [c for c in fake.calls if "--no-sandbox" not in c]
    assert len(with_sandbox) == 1, "only the first invocation should try the sandbox"
    assert "sandbox is not available" in caplog.text


def test_sandbox_required_reports_error(tmp_path, fake):
    repo = _repo(tmp_path)
    fake.default_response = SANDBOX_UNAVAILABLE
    scanner = _scanner(repo, tmp_path, ecosystems=["go"], sandbox="required")
    with pytest.raises(
        ScannerError,
        match="sandbox is not available on this platform and options.sandbox is 'required'",
    ):
        scanner.scan(target=repo, target_type="source")
    assert all("--sandbox" in c and "--no-sandbox" not in c for c in fake.calls)


def test_sandbox_disabled_never_asks_for_it(tmp_path, fake):
    repo = _repo(tmp_path)
    scanner = _scanner(repo, tmp_path, ecosystems=["go", "npm"], sandbox="disabled")
    scanner.scan(target=repo, target_type="source")
    assert fake.calls and all("--no-sandbox" in c for c in fake.calls)


def test_rules_reach_argv_as_separate_values(tmp_path, fake):
    repo = _repo(tmp_path)
    scanner = _scanner(
        repo,
        tmp_path,
        ecosystems=["go"],
        exclude_rules=["threat-runtime-obfuscation-base64exec"],
    )
    scanner.scan(target=repo, target_type="source")
    call = next(c for c in fake.calls if c[2] == "scan")
    index = call.index("--exclude-rules")
    assert call[index + 1] == "threat-runtime-obfuscation-base64exec"


def test_verify_is_off_by_default(tmp_path, fake):
    repo = _repo(tmp_path)
    (repo / "requirements.txt").write_text("six==1.16.0\n")
    _scanner(repo, tmp_path).scan(target=repo, target_type="source")
    assert all(c[2] == "scan" for c in fake.calls)


def test_verify_offline_is_not_attempted_and_is_an_error(tmp_path, fake, monkeypatch):
    monkeypatch.setenv("ASH_OFFLINE", "true")
    repo = _repo(tmp_path)
    (repo / "requirements.txt").write_text("six==1.16.0\n")
    scanner = _scanner(repo, tmp_path, verify=True, ecosystems=["pypi"])
    with pytest.raises(ScannerError) as raised:
        scanner.scan(target=repo, target_type="source")
    assert "pypi verify of requirements.txt: not attempted" in str(raised.value)
    assert "offline mode" in str(raised.value)
    assert all(c[2] == "scan" for c in fake.calls)


def test_verify_online_reads_the_manifest_and_its_findings(tmp_path, fake):
    repo = _repo(tmp_path)
    (repo / "requirements.txt").write_text("six==1.16.0\n")
    fake.overrides[("pypi", "verify")] = {
        "returncode": 0,
        "stdout": (CAPTURED / "verify_pypi_requirements.json").read_text(),
        "stderr": "INFO: Scanning using at most 8 parallel worker threads\n",
    }
    scanner = _scanner(
        repo, tmp_path, verify=True, ecosystems=["pypi"], include_capabilities=True
    )
    report = scanner.scan(target=repo, target_type="source")
    verify_calls = [c for c in fake.calls if c[2] == "verify"]
    assert len(verify_calls) == 1
    assert Path(verify_calls[0][3]) == (repo / "requirements.txt").absolute()
    assert ("capability-process-spawn", "INFO", "requirements.txt", 1) in _rows(report)


def test_verify_that_logged_an_error_and_printed_nothing_is_not_clean(tmp_path, fake):
    """GuardDog prints [] and exits 0 when the registry is unreachable."""
    repo = _repo(tmp_path)
    (repo / "requirements.txt").write_text("six==1.16.0\n")
    fake.overrides[("pypi", "verify")] = {
        "returncode": 0,
        "stdout": "[]",
        "stderr": "ERROR: Received error HTTPSConnectionPool(host='pypi.org', port=443): Max retries exceeded\n",
    }
    scanner = _scanner(repo, tmp_path, verify=True, ecosystems=["pypi"])
    with pytest.raises(ScannerError, match="Max retries exceeded"):
        scanner.scan(target=repo, target_type="source")


def test_verify_uses_its_own_timeout_and_parallelism(tmp_path, fake, monkeypatch):
    seen = {}
    original = FakeGuardDog.__call__

    def spy(self, scanner, command, **kw):
        if command[2] == "verify":
            seen["timeout"] = kw.get("timeout")
            seen["parallelism"] = (kw.get("env") or {}).get("GUARDDOG_PARALLELISM")
        return original(self, scanner, command, **kw)

    monkeypatch.setattr(FakeGuardDog, "__call__", spy)
    repo = _repo(tmp_path)
    (repo / "requirements.txt").write_text("six==1.16.0\n")
    fake.overrides[("pypi", "verify")] = {"returncode": 124, "timed_out": True}
    scanner = _scanner(
        repo,
        tmp_path,
        verify=True,
        ecosystems=["pypi"],
        verify_timeout=7,
        verify_parallelism=3,
    )
    with pytest.raises(ScannerError, match="timed out after 7.0s"):
        scanner.scan(target=repo, target_type="source")
    assert seen == {"timeout": 7.0, "parallelism": "3"}


# --------------------------------------------------------------------------- #
# Installation and availability
# --------------------------------------------------------------------------- #


def test_install_command_pins_version_and_interpreter(tmp_path):
    repo = tmp_path / "src"
    repo.mkdir()
    scanner = _scanner(repo, tmp_path)
    assert scanner.uv_tool_install_commands == [
        f"uv tool install --python {GUARDDOG_PYTHON_REQUEST} guarddog{GUARDDOG_DEFAULT_VERSION_CONSTRAINT}"
    ]
    # get_installation_commands splits on whitespace: each piece must stay whole.
    commands = scanner.get_installation_commands("linux", "amd64")
    assert [
        "uv",
        "tool",
        "install",
        "--python",
        GUARDDOG_PYTHON_REQUEST,
        "guarddog==3.2.0",
    ] in commands


def test_missing_offline_names_the_remedy(tmp_path, monkeypatch):
    monkeypatch.setenv("ASH_OFFLINE", "true")
    repo = tmp_path / "src"
    repo.mkdir()
    scanner = _scanner(repo, tmp_path)
    monkeypatch.setattr(
        GuardDogScanner, "_validate_uv_tool_availability", lambda self: True
    )
    monkeypatch.setattr(
        GuardDogScanner,
        "_get_tool_installation_info",
        lambda self: {"available": False},
    )
    monkeypatch.setattr(
        "automated_security_helper.plugin_modules.ash_guarddog_plugins.guarddog_scanner.get_uv_tool_command",
        lambda name: None,
    )
    assert scanner.validate_plugin_dependencies() is False
    reason = scanner.dependency_unavailable_reason
    assert "offline mode" in reason and "nixpkgs" in reason
    assert f"--python '{GUARDDOG_PYTHON_REQUEST}'" in reason


# --------------------------------------------------------------------------- #
# Through the real scan phase: opt-in, MISSING and ERROR (#640)
# --------------------------------------------------------------------------- #


class _ControlConfig(ScannerPluginConfigBase):
    name: Literal["guarddog-test-control"] = "guarddog-test-control"
    enabled: bool = True


class _ControlScanner(ScannerPluginBase[_ControlConfig]):
    """An ordinary scanner that ran clean, so a run without GuardDog has a result."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = _ControlConfig()
        self.command = "guarddog-test-control"
        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError

    def scan(self, target, target_type, global_ignore_paths=None, config=None):
        return SarifReport.model_validate(
            {
                "version": "2.1.0",
                "runs": [{"tool": {"driver": {"name": "c"}}, "results": []}],
            }
        )


def _phase_run(tmp_path, monkeypatch, *, enabled_by: str | None, tool: str):
    """Run the real ScanPhase over the fixture repo with only GuardDog loaded.

    ``tool`` is "missing" (dependency probe fails), "broken" (GuardDog exits 1 on
    every package) or "ok" (captured output).
    """
    from unittest.mock import MagicMock

    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.core.phases.scan_phase import ScanPhase
    from automated_security_helper.core.unified_metrics import (
        populate_metrics_from_unified_source,
    )
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    repo = _repo(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    # "default": the module is loaded (GuardDogScanner is in the plugin set) and
    # nothing else is said, which runs it; "selection": also named in --scanners;
    # "off": the config turns it off.
    config = get_default_config()
    if enabled_by == "off":
        from automated_security_helper.config.ash_config import AshConfig

        config = AshConfig.model_validate(
            {
                **config.model_dump(by_alias=True),
                "scanners": {
                    **config.scanners.model_dump(by_alias=True),
                    "guarddog": {"enabled": False},
                },
            }
        )
    context = PluginContext(
        source_dir=repo, output_dir=out, work_dir=out / "converted", config=config
    )
    fake = FakeGuardDog()
    if tool == "broken":
        fake.default_response = {"returncode": 1, "stderr": "ERROR: boom\n"}
    monkeypatch.setattr(
        GuardDogScanner, "_run_subprocess", lambda self, **kw: fake(self, **kw)
    )
    monkeypatch.setattr(
        GuardDogScanner, "validate_plugin_dependencies", lambda self: tool != "missing"
    )
    aggregated = AshAggregatedResults()
    phase = ScanPhase(
        plugin_context=context,
        plugins=[_ControlScanner, GuardDogScanner],
        progress_display=MagicMock(),
        asharp_model=aggregated,
    )
    results = phase._execute_phase(
        aggregated_results=aggregated,
        enabled_scanners=(
            ["guarddog", "guarddog-test-control"] if enabled_by == "selection" else []
        ),
        parallel=False,
    )
    return (
        context,
        fake,
        populate_metrics_from_unified_source(aggregated_results=results),
    )


def _exit_code(context, results):
    from automated_security_helper.interactions.run_ash_scan import (
        ScanOptions,
        _compute_exit_code,
    )

    opts = ScanOptions(source_dir=context.source_dir, output_dir=context.output_dir)
    return _compute_exit_code(results, opts, config_fail_on_findings=False)


def test_disabled_guarddog_runs_nothing_even_with_the_tool_missing(
    tmp_path, monkeypatch
):
    """`scanners.guarddog.enabled: false` with the module listed: not run, exit 0."""
    context, fake, results = _phase_run(
        tmp_path, monkeypatch, enabled_by="off", tool="missing"
    )
    row = results.scanner_results.get("guarddog")
    assert row is not None and row.status.value == "SKIPPED"
    assert fake.calls == []
    assert _exit_code(context, results) == 0


@pytest.mark.parametrize("enabled_by", ["default", "selection"])
def test_enabled_guarddog_runs_and_reports(tmp_path, monkeypatch, enabled_by):
    context, fake, results = _phase_run(
        tmp_path, monkeypatch, enabled_by=enabled_by, tool="ok"
    )
    row = results.scanner_results["guarddog"]
    assert row.status.value == "FAILED"  # HIGH findings over the MEDIUM default
    assert row.finding_count == 9
    assert len(fake.calls) == 8


@pytest.mark.parametrize("enabled_by", ["default", "selection"])
def test_enabled_but_missing_is_missing_and_exits_1(tmp_path, monkeypatch, enabled_by):
    from automated_security_helper.interactions.run_ash_scan import (
        incomplete_scanner_reason,
        incomplete_scanners,
    )

    context, fake, results = _phase_run(
        tmp_path, monkeypatch, enabled_by=enabled_by, tool="missing"
    )
    assert results.scanner_results["guarddog"].status.value == "MISSING"
    listed = incomplete_scanners(results)
    assert [name for name, _ in listed] == ["guarddog"]
    assert incomplete_scanner_reason(listed[0][1]) == "missing_dependencies"
    assert _exit_code(context, results) == 1
    assert fake.calls == []


def test_enabled_and_erroring_is_error_and_exits_1(tmp_path, monkeypatch):
    from automated_security_helper.interactions.run_ash_scan import incomplete_scanners

    context, fake, results = _phase_run(
        tmp_path, monkeypatch, enabled_by="default", tool="broken"
    )
    assert results.scanner_results["guarddog"].status.value == "ERROR"
    assert [name for name, _ in incomplete_scanners(results)] == ["guarddog"]
    assert _exit_code(context, results) == 1


# --------------------------------------------------------------------------- #
# Suppressions apply to GuardDog findings (rule/path/line, symbol, package)
# --------------------------------------------------------------------------- #


def _suppressed(tmp_path, report, **suppression):
    from automated_security_helper.models.core import AshSuppression
    from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif

    config = AshConfig()
    config.global_settings.suppressions = [AshSuppression(reason="test", **suppression)]
    repo = tmp_path / "supp-src"
    if not repo.exists():
        shutil.copytree(FIXTURE_REPO, repo)
    context = PluginContext(
        source_dir=repo,
        output_dir=tmp_path / "supp-out",
        work_dir=tmp_path / "supp-out" / "converted",
        config=config,
    )
    applied = apply_suppressions_to_sarif(copy.deepcopy(report), context)
    return sorted(
        (
            r.ruleId,
            r.locations[0].physicalLocation.root.region.startLine
            if r.locations[0].physicalLocation.root.region
            else None,
        )
        for r in applied.runs[0].results
        if r.suppressions
    )


def _pypi_report() -> SarifReport:
    converted = convert_guarddog_scan_result(
        _capture("scan_pypi_pypi_suspicious.json"),
        uri_prefix="pypi_suspicious",
        ecosystem="pypi",
    )
    return SarifReport(
        version="2.1.0",
        runs=[{"tool": {"driver": {"name": "GuardDog"}}, "results": converted.results}],
    )


def test_rule_path_and_line_suppression(tmp_path):
    got = _suppressed(
        tmp_path,
        _pypi_report(),
        rule_id="threat-process-download-exec",
        path="pypi_suspicious/setup.py",
        line_start=16,
        line_end=16,
    )
    assert got == [("threat-process-download-exec", 16)]


def test_rule_suppression_without_a_line_covers_the_rule_only(tmp_path):
    got = _suppressed(
        tmp_path,
        _pypi_report(),
        rule_id="threat-process-download-exec",
        path="pypi_suspicious/setup.py",
    )
    assert got == [
        ("threat-process-download-exec", 15),
        ("threat-process-download-exec", 16),
        ("threat-process-download-exec", 17),
    ]


def test_symbol_suppression(tmp_path):
    try:
        import tree_sitter_python  # noqa: F401
    except ImportError as exc:  # pragma: no cover - environment-dependent
        # The unit-test CI legs install the [symbols] extra and set this, so there
        # the test fails rather than skips; see tests/unit/utils/test_symbol_suppressions.py.
        if os.environ.get("ASH_REQUIRE_SYMBOLS_EXTRA", "").strip().upper() in (
            "1",
            "YES",
            "TRUE",
        ):
            pytest.fail(
                f"ASH_REQUIRE_SYMBOLS_EXTRA is set but tree-sitter is missing ({exc})"
            )
        pytest.skip(f"[symbols] extra not installed ({exc})")
    got = _suppressed(
        tmp_path,
        _pypi_report(),
        rule_id="threat-network-exfiltration",
        path="pypi_suspicious/setup.py",
        symbol="PostInstall.run",
    )
    assert got == [("threat-network-exfiltration", 17)]
    # A symbol the finding is not inside suppresses nothing.
    assert (
        _suppressed(
            tmp_path,
            _pypi_report(),
            rule_id="threat-network-exfiltration",
            path="pypi_suspicious/setup.py",
            symbol="NoSuchClass.run",
        )
        == []
    )


def test_package_suppression_applies_to_verify_findings(tmp_path):
    entry = _capture("verify_pypi_requirements.json")[0]
    converted = convert_guarddog_scan_result(
        entry["result"],
        uri_prefix="",
        ecosystem="pypi",
        include_capabilities=True,
        dependency=("six", "1.16.0"),
        manifest_uri="requirements.txt",
        manifest_line=1,
    )
    report = SarifReport(
        version="2.1.0",
        runs=[{"tool": {"driver": {"name": "GuardDog"}}, "results": converted.results}],
    )
    assert _suppressed(
        tmp_path,
        report,
        rule_id="capability-*",
        path="requirements.txt",
        package_name="six",
    ) == [("capability-process-spawn", 1)]
    assert (
        _suppressed(
            tmp_path,
            report,
            rule_id="capability-*",
            path="requirements.txt",
            package_name="seven",
        )
        == []
    )


# --------------------------------------------------------------------------- #
# Review round 1: rule names per ecosystem, and gaps the mutants found
# --------------------------------------------------------------------------- #


def test_an_exclusion_is_passed_only_to_ecosystems_that_know_it(tmp_path, fake):
    """GuardDog exits 2 on an --exclude-rules name its ecosystem does not have."""
    repo = _repo(tmp_path)
    scanner = _scanner(repo, tmp_path, exclude_rules=["typosquatting"])
    scanner.scan(target=repo, target_type="source")
    scans = [c for c in fake.calls if c[2] == "scan"]
    assert scans
    for call in scans:
        has = "--exclude-rules" in call
        assert has == (call[1] in ("pypi", "npm")), call


def test_a_rules_selection_no_ecosystem_rule_matches_skips_that_ecosystem(
    tmp_path, fake
):
    repo = _repo(tmp_path)
    scanner = _scanner(
        repo, tmp_path, ecosystems=["pypi", "go"], rules=["typosquatting"]
    )
    scanner.scan(target=repo, target_type="source")
    scans = [c for c in fake.calls if c[2] == "scan"]
    assert {c[1] for c in scans} == {"pypi"}
    assert all(c[c.index("--rules") + 1] == "typosquatting" for c in scans)
    # go was not run, and not counted as attempted.
    assert scanner.targets_attempted == 2


def test_a_rule_name_no_ecosystem_knows_is_an_error(tmp_path, fake):
    repo = _repo(tmp_path)
    scanner = _scanner(
        repo, tmp_path, ecosystems=["go"], exclude_rules=["no-such-rule"]
    )
    with pytest.raises(ScannerError, match="no-such-rule"):
        scanner.scan(target=repo, target_type="source")


def test_list_rules_failing_fails_that_ecosystems_targets(tmp_path, fake):
    repo = _repo(tmp_path)
    fake.overrides[("go", "list-rules")] = {"returncode": 1, "stderr": "boom\n"}
    scanner = _scanner(
        repo, tmp_path, ecosystems=["go", "npm"], exclude_rules=["typosquatting"]
    )
    with pytest.raises(
        ScannerError, match="go scan of go_suspicious: could not list its rules"
    ):
        scanner.scan(target=repo, target_type="source")
    assert {c[1] for c in fake.calls if c[2] == "scan"} == {"npm"}


def test_no_rule_options_means_no_list_rules_call(tmp_path, fake):
    repo = _repo(tmp_path)
    _scanner(repo, tmp_path).scan(target=repo, target_type="source")
    assert not [c for c in fake.calls if c[2] == "list-rules"]


def test_verify_passes_the_rule_options(tmp_path, fake):
    repo = _repo(tmp_path)
    (repo / "requirements.txt").write_text("six==1.16.0\n")
    fake.overrides[("pypi", "verify")] = {
        "returncode": 0,
        "stdout": (CAPTURED / "verify_pypi_requirements.json").read_text(),
    }
    scanner = _scanner(
        repo,
        tmp_path,
        verify=True,
        ecosystems=["pypi"],
        exclude_rules=["typosquatting"],
    )
    scanner.scan(target=repo, target_type="source")
    (verify,) = [c for c in fake.calls if c[2] == "verify"]
    assert verify[verify.index("--exclude-rules") + 1] == "typosquatting"


def test_a_dependency_guarddog_could_not_check_is_a_failed_target(tmp_path, fake):
    repo = _repo(tmp_path)
    (repo / "requirements.txt").write_text("six==1.16.0\n")
    entries = _capture("verify_pypi_requirements.json")
    entries[0]["result"]["errors"] = {"download-package": "404 Not Found"}
    fake.overrides[("pypi", "verify")] = {
        "returncode": 0,
        "stdout": json.dumps(entries),
    }
    scanner = _scanner(repo, tmp_path, verify=True, ecosystems=["pypi"])
    with pytest.raises(ScannerError, match="six: download-package: 404 Not Found"):
        scanner.scan(target=repo, target_type="source")


@pytest.mark.parametrize(
    "rel,expected",
    [
        (".github/workflows/ci.yml", True),
        (".github/workflows/ci.yaml", True),
        ("sub/.github/workflows/ci.yml", True),
        ("ci.yml", False),
        (".github/ci.yml", False),
        ("docs/workflows/ci.yml", False),
        (".github/workflows/notes.txt", False),
    ],
)
def test_github_action_verify_reads_only_workflow_files(rel, expected):
    from automated_security_helper.plugin_modules.ash_guarddog_plugins.guarddog_scanner import (
        _is_verify_manifest,
    )

    assert _is_verify_manifest("github_action", rel) is expected


def test_the_output_dir_inside_the_source_is_not_staged(tmp_path, fake):
    repo = _repo(tmp_path)
    output = repo / "ash-out"
    (output / "copy").mkdir(parents=True)
    shutil.copytree(FIXTURE_REPO / "npm_suspicious", output / "copy" / "npm_suspicious")
    context = PluginContext(
        source_dir=repo,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    scanner = GuardDogScanner(
        context=context,
        config=GuardDogScannerConfig(
            enabled=True, options=GuardDogScannerConfigOptions(ecosystems=["npm"])
        ),
    )
    report = scanner.scan(target=repo, target_type="source")
    assert len(fake.staged) == 2  # npm_clean and npm_suspicious, not the copy
    assert not [r for r in _rows(report) if r[2].startswith("ash-out/")]


def test_staging_is_removed_after_the_scan_even_when_it_fails(tmp_path, fake):
    repo = _repo(tmp_path)
    fake.overrides[("go", "go_suspicious")] = {"returncode": 1, "stderr": "boom"}
    scanner = _scanner(repo, tmp_path, ecosystems=["go", "npm"])
    with pytest.raises(ScannerError):
        scanner.scan(target=repo, target_type="source")
    assert fake.staged_dirs
    assert not any(d.exists() for d in fake.staged_dirs)
    assert not fake.staged_dirs[0].parent.exists()


def test_dedup_keeps_the_higher_severity(tmp_path, fake):
    """The same match, correlated in one scan (HIGH) and not in another (LOW)."""
    repo = _repo(tmp_path)
    (repo / "pypi_suspicious" / "package.json").write_text('{"name": "x"}\n')
    fake.files["both"] = _tree(repo / "pypi_suspicious")
    correlated = _capture("scan_pypi_pypi_suspicious.json")
    uncorrelated = copy.deepcopy(correlated)
    uncorrelated["risks"] = []
    # The uncorrelated (LOW) copy is served to the scan that runs first (npm).
    fake.overrides[("npm", "both")] = {
        "returncode": 0,
        "stdout": json.dumps(uncorrelated),
    }
    fake.overrides[("pypi", "both")] = {
        "returncode": 0,
        "stdout": json.dumps(correlated),
    }
    scanner = _scanner(repo, tmp_path, ecosystems=["pypi", "npm"])
    report = scanner.scan(target=repo, target_type="source")
    setup = [r for r in _rows(report) if r[2] == "pypi_suspicious/setup.py"]
    assert (
        "threat-runtime-obfuscation-base64exec",
        "HIGH",
        "pypi_suspicious/setup.py",
        15,
    ) in setup
    assert (
        "threat-runtime-obfuscation-base64exec",
        "LOW",
        "pypi_suspicious/setup.py",
        15,
    ) not in setup


def test_the_same_finding_in_two_dependencies_is_kept_twice():
    entries = _capture("verify_pypi_requirements.json")
    result = entries[0]["result"]
    one = convert_guarddog_scan_result(
        result,
        uri_prefix="",
        ecosystem="pypi",
        include_capabilities=True,
        dependency=("six", "1.16.0"),
        manifest_uri="requirements.txt",
        manifest_line=1,
    )
    two = convert_guarddog_scan_result(
        result,
        uri_prefix="",
        ecosystem="pypi",
        include_capabilities=True,
        dependency=("six", "1.17.0"),
        manifest_uri="requirements.txt",
        manifest_line=1,
    )
    assert one.keys and two.keys and one.keys[0] != two.keys[0]


def test_the_matched_code_is_the_region_snippet():
    converted = convert_guarddog_scan_result(
        _capture("scan_npm_npm_suspicious.json"), uri_prefix="", ecosystem="npm"
    )
    region = converted.results[0].locations[0].physicalLocation.root.region
    assert "eval(Buffer.from(" in region.snippet.text


def test_a_rule_list_that_parses_to_nothing_fails_that_ecosystem(tmp_path, fake):
    """A reformatted list-rules table must not silently drop the exclusions."""
    repo = _repo(tmp_path)
    fake.overrides[("go", "list-rules")] = {
        "returncode": 0,
        "stdout": "Rule name\nnothing here\n",
    }
    scanner = _scanner(
        repo, tmp_path, ecosystems=["go", "npm"], exclude_rules=["typosquatting"]
    )
    with pytest.raises(
        ScannerError, match="go scan of go_suspicious: could not list its rules"
    ):
        scanner.scan(target=repo, target_type="source")
    assert {c[1] for c in fake.calls if c[2] == "scan"} == {"npm"}
    # The go package root counts as attempted and failed; the two npm roots ran.
    assert (scanner.targets_attempted, scanner.targets_failed) == (3, 1)


def test_an_unknown_rule_with_nothing_run_says_the_configuration_is_unusable(
    tmp_path, fake
):
    repo = tmp_path / "src"
    shutil.copytree(FIXTURE_REPO / "go_suspicious", repo / "go_suspicious")
    scanner = _scanner(repo, tmp_path, ecosystems=["go"], rules=["no-such-rule"])
    with pytest.raises(ScannerError, match="configuration is not usable.*no-such-rule"):
        scanner.scan(target=repo, target_type="source")


def test_metadata_only_rules_warn_that_a_local_scan_checks_nothing(
    tmp_path, fake, caplog
):
    repo = _repo(tmp_path)
    scanner = _scanner(repo, tmp_path, ecosystems=["pypi"], rules=["typosquatting"])
    with caplog.at_level(logging.WARNING, logger="ash"):
        scanner.scan(target=repo, target_type="source")
    assert "only metadata rules" in caplog.text


def test_windows_is_an_unsupported_platform_with_no_install_command(
    tmp_path, monkeypatch
):
    """nono-py, a GuardDog 3.2.0 dependency, has no Windows build (seen failing in CI)."""
    import automated_security_helper.plugin_modules.ash_guarddog_plugins.guarddog_scanner as module

    repo = tmp_path / "src"
    repo.mkdir()
    scanner = _scanner(repo, tmp_path)
    assert scanner.get_installation_commands("windows", "amd64") == []
    assert scanner.get_installation_commands("linux", "amd64") != []
    monkeypatch.setattr(module.platform, "system", lambda: "Windows")
    assert "nono-py" in scanner.unsupported_platform_reason()
    assert scanner.validate_plugin_dependencies() is False
    monkeypatch.setattr(module.platform, "system", lambda: "Linux")
    assert scanner.unsupported_platform_reason() is None


def test_staging_is_inside_the_results_directory(tmp_path, fake):
    """Under --sandbox GuardDog can read the results directory but not $TMPDIR.

    Staged under the system temp directory, the sandboxed GuardDog was handed a path
    that did not exist for it, took it for a package name and tried to download it,
    so the sandbox parity run reported GuardDog ERROR (bwrap) or PASSED with no
    findings (landlock) where the unsandboxed run reported 9 findings.
    """
    repo = _repo(tmp_path)
    scanner = _scanner(repo, tmp_path, ecosystems=["go", "npm"])

    scanner.scan(target=repo, target_type="source")

    results_dir = Path(scanner.results_dir).resolve()
    assert fake.staged_dirs
    for staged in fake.staged_dirs:
        assert staged.resolve().is_relative_to(results_dir), staged


def test_a_write_to_a_staged_file_does_not_reach_the_source(tmp_path):
    """The staging tree is sandbox-writable, so it must not share inodes with the source."""
    root = tmp_path / "pkg"
    root.mkdir()
    original = root / "setup.py"
    original.write_text("print('original')\n")
    before = original.stat()
    staging = tmp_path / "results" / "staging-x"
    staging.mkdir(parents=True)

    GuardDogScanner._stage(root, [original], staging)
    (staging / "setup.py").write_text("print('changed through the staging tree')\n")

    assert original.read_text() == "print('original')\n"
    after = original.stat()
    assert (after.st_ino, after.st_nlink) == (before.st_ino, before.st_nlink)
    assert (staging / "setup.py").stat().st_ino != before.st_ino
