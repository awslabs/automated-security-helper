# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""pip-audit scanner: conversion, discovery, argv and failure handling.

What the JSON here is
---------------------
``POSITIVE`` and ``NEGATIVE`` are written to the shape pip-audit 2.10.1's own
``pip_audit/_format/json.py`` emits (``{"dependencies": [...], "fixes": [...]}``;
a skipped dependency is ``{"name", "skip_reason"}``); they let the scan() flow
tests control every field. The converter over a REAL capture of pip-audit 2.10.1
is tested in ``test_pip_audit_captured_report.py`` against
``tests/test_data/scanners/pip-audit/captured/``.

The scanner tests drive the real ``scan()`` over a tree built in ``tmp_path`` and
replace only ``_run_subprocess`` (a fake that records argv, cwd and timeout and
writes the report where the argv says) and the dependency check.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import OfflineStrategy
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules import ash_pip_audit_plugins
from automated_security_helper.plugin_modules.ash_pip_audit_plugins import (
    pip_audit_scanner as module,
)
from automated_security_helper.plugin_modules.ash_pip_audit_plugins.pip_audit_scanner import (
    ADVISORY_LEVEL,
    ADVISORY_SEVERITY,
    PIP_AUDIT_DEFAULT_VERSION_CONSTRAINT,
    PipAuditConversionError,
    PipAuditScanner,
    PipAuditScannerConfig,
    PipAuditScannerConfigOptions,
    convert_pip_audit_json,
    is_requirements_file,
    requirement_line_for,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sandbox.policy import SandboxRequirements

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()

REQUIREMENTS = "# pinned\nFlask==0.5\njinja2==3.1.4\nFlask_Login==0.6.3\n"

POSITIVE: Dict[str, Any] = {
    "dependencies": [
        {
            "name": "flask",
            "version": "0.5",
            "vulns": [
                {
                    "id": "PYSEC-2019-179",
                    "fix_versions": ["1.0"],
                    "aliases": ["CVE-2019-1010083", "GHSA-5wv5-4vpf-pj6m"],
                    "description": "The Pallets Project Flask before 1.0 is affected.",
                },
                {
                    "id": "PYSEC-2018-66",
                    "fix_versions": [],
                    "aliases": [],
                    "description": "No fix is published.",
                },
            ],
        },
        {"name": "jinja2", "version": "3.1.4", "vulns": []},
    ],
    "fixes": [],
}
NEGATIVE: Dict[str, Any] = {
    "dependencies": [
        {"name": "flask", "version": "3.0.3", "vulns": []},
        {"name": "jinja2", "version": "3.1.4", "vulns": []},
    ],
    "fixes": [],
}
# Hand-written from the capture above: (rule, severity, level, uri, line).
POSITIVE_EXPECTED = sorted(
    [
        ("PYSEC-2019-179", "HIGH", "error", "requirements.txt", 2),
        ("PYSEC-2018-66", "HIGH", "error", "requirements.txt", 2),
    ]
)


def _rows(results) -> List[tuple]:
    rows = []
    for result in results:
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


# --------------------------------------------------------------------------- #
# Conversion
# --------------------------------------------------------------------------- #


class TestConversion:
    def test_positive_capture_is_rated_and_located(self):
        results, rules, skipped = convert_pip_audit_json(
            POSITIVE, uri="requirements.txt", requirements_text=REQUIREMENTS
        )
        assert _rows(results) == POSITIVE_EXPECTED
        assert set(rules) == {"PYSEC-2019-179", "PYSEC-2018-66"}
        assert skipped == []

    def test_negative_control_has_no_findings(self):
        results, rules, skipped = convert_pip_audit_json(
            NEGATIVE, uri="requirements.txt", requirements_text=REQUIREMENTS
        )
        assert (results, rules, skipped) == ([], {}, [])

    def test_every_result_carries_severity_and_level_that_agree(self):
        results, _, _ = convert_pip_audit_json(
            POSITIVE, uri="requirements.txt", requirements_text=REQUIREMENTS
        )
        assert ADVISORY_SEVERITY == "HIGH" and ADVISORY_LEVEL == "error"
        for result in results:
            assert result.properties.issue_severity == ADVISORY_SEVERITY
            assert getattr(result.level, "value", result.level) == ADVISORY_LEVEL

    def test_message_and_properties_carry_the_package_and_fix(self):
        results, _, _ = convert_pip_audit_json(
            POSITIVE, uri="requirements.txt", requirements_text=REQUIREMENTS
        )
        by_id = {r.ruleId: r for r in results}
        fixed = by_id["PYSEC-2019-179"]
        text = fixed.message.root.text
        assert "flask 0.5" in text and "CVE-2019-1010083" in text
        assert "Fixed in: 1.0" in text
        assert fixed.properties.fix_versions == ["1.0"]
        assert (
            "No fixed version is published" in by_id["PYSEC-2018-66"].message.root.text
        )

    def test_a_changed_field_changes_the_rows(self):
        mutated = json.loads(json.dumps(POSITIVE))
        mutated["dependencies"][0]["vulns"][0]["id"] = "PYSEC-0000-0"
        results, _, _ = convert_pip_audit_json(
            mutated, uri="requirements.txt", requirements_text=REQUIREMENTS
        )
        assert _rows(results) != POSITIVE_EXPECTED

    def test_the_same_package_listed_twice_yields_one_result_per_advisory(self):
        # A requirements file that names a package twice (two environment
        # markers, a repeated line) makes pip-audit list one dependency entry
        # per line; the fingerprint is (advisory, file, package, version), so a
        # second entry for the same pin must not produce a second result.
        entry = POSITIVE["dependencies"][0]
        document = {"dependencies": [entry, json.loads(json.dumps(entry))]}
        results, _, _ = convert_pip_audit_json(
            document, uri="requirements.txt", requirements_text=REQUIREMENTS
        )
        assert _rows(results) == POSITIVE_EXPECTED
        prints = [r.partialFingerprints["pip-audit/v1"] for r in results]
        assert len(prints) == len(set(prints))
        # Control: the same package at another version is another finding.
        other = json.loads(json.dumps(entry))
        other["version"] = "0.6"
        results, _, _ = convert_pip_audit_json(
            {"dependencies": [entry, other]},
            uri="requirements.txt",
            requirements_text=REQUIREMENTS,
        )
        assert len(results) == 4

    def test_a_skipped_dependency_is_reported_not_converted(self):
        document = {
            "dependencies": [
                {"name": "internal-lib", "skip_reason": "Dependency not found on PyPI"}
            ],
            "fixes": [],
        }
        results, _, skipped = convert_pip_audit_json(document, uri="r.txt")
        assert results == []
        assert skipped == ["internal-lib: Dependency not found on PyPI"]

    @pytest.mark.parametrize(
        "document",
        [
            [],  # the README's bare array: not what the source emits
            "text",
            {},
            {"dependencies": "x"},
            {"dependencies": [{"version": "1"}]},
            {"dependencies": [{"name": "a", "version": "1", "vulns": [{"x": 1}]}]},
        ],
    )
    def test_unreadable_documents_are_refused(self, document):
        with pytest.raises(PipAuditConversionError):
            convert_pip_audit_json(document, uri="r.txt")

    def test_requirement_line_matches_normalized_names(self):
        assert requirement_line_for(REQUIREMENTS, "flask") == 2
        assert requirement_line_for(REQUIREMENTS, "flask-login") == 4
        assert requirement_line_for(REQUIREMENTS, "absent") is None
        # A comment or option line never names a package.
        assert requirement_line_for("# flask\n--index-url x\n", "flask") is None

    @pytest.mark.parametrize(
        "path,expected",
        [
            ("requirements.txt", True),
            ("sub/requirements-dev.txt", True),
            ("dev-requirements.txt", True),
            ("requirements_test.txt", True),
            ("requirements/base.txt", True),
            ("notes.txt", False),
            ("requirements.txt.bak", False),
            ("my_requirements_doc.md", False),
        ],
    )
    def test_requirements_file_names(self, path, expected):
        assert is_requirements_file(path) is expected


# --------------------------------------------------------------------------- #
# Config and class declarations
# --------------------------------------------------------------------------- #


class TestAlphaPlugin:
    def test_on_by_default_once_its_module_is_listed(self):
        assert PipAuditScannerConfig().enabled is True

    def test_the_module_exports_the_scanner(self):
        assert ash_pip_audit_plugins.ASH_SCANNERS == [PipAuditScanner]
        assert ash_pip_audit_plugins.ASH_REPORTERS == []

    def test_declarations(self):
        assert PipAuditScannerConfig().name == "pip-audit"
        assert PipAuditScanner.python_only is True
        assert PipAuditScanner.offline_strategy is OfflineStrategy.SKIP_OFFLINE
        assert PipAuditScanner.success_exit_codes == {0, 1}
        assert PipAuditScanner.sandbox_requirements == SandboxRequirements(network=True)
        assert PIP_AUDIT_DEFAULT_VERSION_CONSTRAINT.startswith("==")

    def test_an_unknown_service_is_rejected(self):
        with pytest.raises(ValueError):
            PipAuditScannerConfigOptions(vulnerability_service="esms")  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# The scanner, with pip-audit replaced by a fake
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _no_real_version_probe(monkeypatch):
    monkeypatch.setattr(
        PipAuditScanner,
        "_get_uv_tool_version",
        lambda self, name, package_name=None: "2.10.1",
    )


def _tree(tmp_path: Path) -> Path:
    repo = tmp_path / "src"
    (repo / "svc").mkdir(parents=True)
    (repo / "node_modules" / "x").mkdir(parents=True)
    (repo / "requirements.txt").write_text(REQUIREMENTS)
    (repo / "svc" / "requirements-dev.txt").write_text("flask==3.0.3\n")
    (repo / "node_modules" / "x" / "requirements.txt").write_text("flask==0.5\n")
    (repo / "notes.txt").write_text("flask==0.5\n")
    (repo / "README.md").write_text("# demo\n")
    return repo


def _scanner(repo: Path, tmp_path: Path, **options) -> PipAuditScanner:
    output = tmp_path / "out"
    output.mkdir(exist_ok=True)
    context = PluginContext(
        source_dir=repo,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    return PipAuditScanner(
        context=context,
        config=PipAuditScannerConfig(
            enabled=True, options=PipAuditScannerConfigOptions(**options)
        ),
    )


def _flag(command: List[str], name: str) -> str:
    prefix = f"--{name}="
    (value,) = [c[len(prefix) :] for c in command if c.startswith(prefix)]
    return value


class FakePipAudit:
    """Stands in for ``_run_subprocess``: writes the report the argv names."""

    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []
        #: requirements label -> spec. A spec is {"returncode", "report" (a str
        #: written verbatim, or a dict dumped as JSON), "stderr", "timed_out"}.
        self.specs: Dict[str, Dict[str, Any]] = {}
        self.default: Dict[str, Any] = {"returncode": 0, "report": NEGATIVE}

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
        report = Path(_flag(command, "output"))
        requirements = Path(_flag(command, "requirement"))
        label = requirements.relative_to(scanner.context.source_dir).as_posix()
        self.calls.append(
            {
                "command": list(command),
                "cwd": Path(cwd) if cwd else None,
                "timeout": timeout,
                "label": label,
                "report_existed": report.exists(),
            }
        )
        spec = self.specs.get(label, self.default)
        body = spec.get("report")
        if body is not None:
            report.write_text(body if isinstance(body, str) else json.dumps(body))
        if spec.get("stderr"):
            (Path(results_dir) / "PipAuditScanner.stderr.log").write_text(
                spec["stderr"]
            )
        response: Dict[str, Any] = {"returncode": spec.get("returncode", 0)}
        if spec.get("timed_out"):
            response["timed_out"] = True
        scanner.exit_code = max(scanner.exit_code, response["returncode"])
        return response


@pytest.fixture
def fake(monkeypatch):
    fake = FakePipAudit()
    monkeypatch.setattr(
        PipAuditScanner, "_run_subprocess", lambda self, **kw: fake(self, **kw)
    )
    monkeypatch.setattr(PipAuditScanner, "validate_plugin_dependencies", lambda s: True)
    return fake


class TestInvocation:
    def test_one_run_per_requirements_file_with_every_fixed_flag(self, tmp_path, fake):
        repo = _tree(tmp_path)
        scanner = _scanner(repo, tmp_path)
        scanner.scan(target=repo, target_type="source")

        # node_modules and a non-requirements .txt are not audited.
        assert sorted(c["label"] for c in fake.calls) == [
            "requirements.txt",
            "svc/requirements-dev.txt",
        ]
        for call in fake.calls:
            command = call["command"]
            assert command[0] == "pip-audit"
            assert command[1:9] == [
                "--format=json",
                "--vulnerability-service=pypi",
                "--progress-spinner=off",
                "--desc=on",
                "--aliases=on",
                "--no-deps",
                "--disable-pip",
                "--timeout=15",
            ]
            assert _flag(command, "requirement") == str(repo / call["label"])
            # The invocation directory is under ASH's results directory, so the
            # cache and the report are written there and nowhere else.
            assert str(call["cwd"]) in _flag(command, "output")
            assert _flag(command, "cache-dir").startswith(str(call["cwd"]))
            assert call["cwd"].is_relative_to(tmp_path / "out")
            # Every option is one token; none is a bare short option.
            assert all(c == "pip-audit" or c.startswith("--") for c in command), command

    @pytest.mark.parametrize(
        "forbidden",
        [
            "--fix",
            "--dry-run",
            "--strict",
            "--index-url",
            "--extra-index-url",
            "--ignore-vuln",
            "--osv-url",
            "--require-hashes",
            "-r",
            "--local",
        ],
    )
    def test_flags_that_change_the_tree_or_reach_elsewhere_are_never_passed(
        self, tmp_path, fake, forbidden
    ):
        repo = _tree(tmp_path)
        scanner = _scanner(repo, tmp_path, vulnerability_service="osv")
        scanner.scan(target=repo, target_type="source")
        assert fake.calls
        for call in fake.calls:
            assert not any(
                c == forbidden or c.startswith(f"{forbidden}=") for c in call["command"]
            )

    def test_service_and_timeout_options_reach_argv(self, tmp_path, fake):
        repo = _tree(tmp_path)
        scanner = _scanner(
            repo, tmp_path, vulnerability_service="osv", request_timeout=30
        )
        scanner.scan(target=repo, target_type="source")
        command = fake.calls[0]["command"]
        assert "--vulnerability-service=osv" in command and "--timeout=30" in command

    def test_global_ignore_paths_leave_a_file_out(self, tmp_path, fake):
        repo = _tree(tmp_path)
        scanner = _scanner(repo, tmp_path)
        scanner.scan(
            target=repo,
            target_type="source",
            global_ignore_paths=[
                IgnorePathWithReason(path="svc/**", reason="not shipped")
            ],
        )
        assert [c["label"] for c in fake.calls] == ["requirements.txt"]

    def test_a_symlinked_requirements_file_is_not_audited(self, tmp_path, fake):
        repo = _tree(tmp_path)
        outside = tmp_path / "outside.txt"
        outside.write_text("flask==0.5\n")
        (repo / "requirements-link.txt").symlink_to(outside)
        scanner = _scanner(repo, tmp_path)
        scanner.scan(target=repo, target_type="source")
        assert fake.calls
        assert "requirements-link.txt" not in {c["label"] for c in fake.calls}

    def test_a_tree_with_no_requirements_attempts_nothing(self, tmp_path, fake):
        repo = tmp_path / "src"
        repo.mkdir()
        (repo / "main.py").write_text("print(1)\n")
        scanner = _scanner(repo, tmp_path)
        report = scanner.scan(target=repo, target_type="source")
        assert fake.calls == []
        assert scanner.targets_attempted == 0
        assert isinstance(report, SarifReport) and report.runs[0].results == []


class TestReport:
    def test_findings_are_located_on_the_requirements_line(self, tmp_path, fake):
        repo = _tree(tmp_path)
        fake.specs["requirements.txt"] = {"returncode": 1, "report": POSITIVE}
        scanner = _scanner(repo, tmp_path)
        report = scanner.scan(target=repo, target_type="source")
        assert isinstance(report, SarifReport)
        assert _rows(report.runs[0].results) == POSITIVE_EXPECTED
        assert scanner.targets_attempted == 2 and scanner.targets_failed == 0

    def test_negative_control_is_clean(self, tmp_path, fake):
        repo = _tree(tmp_path)
        fake.default = {"returncode": 0, "report": NEGATIVE}
        report = _scanner(repo, tmp_path).scan(target=repo, target_type="source")
        assert isinstance(report, SarifReport)
        assert report.runs[0].results == []

    def test_the_sarif_file_is_written_and_round_trips(self, tmp_path, fake):
        repo = _tree(tmp_path)
        fake.specs["requirements.txt"] = {"returncode": 1, "report": POSITIVE}
        scanner = _scanner(repo, tmp_path)
        report = scanner.scan(target=repo, target_type="source")
        assert isinstance(report, SarifReport)
        # Under the scanner's results directory.
        written = list((tmp_path / "out").rglob("pip-audit.sarif"))
        assert len(written) == 1
        again = SarifReport.model_validate_json(written[0].read_text())
        assert len(again.runs[0].results) == len(report.runs[0].results) == 2


class TestExitStatus:
    @pytest.mark.parametrize("code", [0, 1])
    def test_exit_0_and_1_with_a_report_succeed(self, tmp_path, fake, code):
        repo = _tree(tmp_path)
        fake.default = {"returncode": code, "report": NEGATIVE}
        report = _scanner(repo, tmp_path).scan(target=repo, target_type="source")
        assert isinstance(report, SarifReport)

    def test_exit_1_without_a_report_fails_and_does_not_quote_stderr(
        self, tmp_path, fake
    ):
        repo = _tree(tmp_path)
        fake.default = {
            "returncode": 1,
            "report": None,
            "stderr": "ERROR: invalid requirements input: SECRET-LINE-FROM-THE-TREE",
        }
        scanner = _scanner(repo, tmp_path)
        with pytest.raises(ScannerError) as raised:
            scanner.scan(target=repo, target_type="source")
        message = str(raised.value)
        assert "wrote no report" in message and "PipAuditScanner.stderr.log" in message
        assert "SECRET-LINE-FROM-THE-TREE" not in message
        assert all("SECRET-LINE-FROM-THE-TREE" not in e for e in scanner.errors)

    @pytest.mark.parametrize("code", [2, 126, 137])
    def test_any_other_code_fails_even_with_a_report_on_disk(
        self, tmp_path, fake, code
    ):
        repo = _tree(tmp_path)
        fake.default = {"returncode": code, "report": POSITIVE}
        with pytest.raises(ScannerError, match=f"exited {code}"):
            _scanner(repo, tmp_path).scan(target=repo, target_type="source")

    def test_a_report_left_by_an_earlier_run_is_removed_first(self, tmp_path, fake):
        repo = _tree(tmp_path)
        fake.default = {"returncode": 0, "report": NEGATIVE}
        scanner = _scanner(repo, tmp_path)
        scanner.scan(target=repo, target_type="source")
        scanner.scan(target=repo, target_type="source")
        assert [c["report_existed"] for c in fake.calls] == [False] * len(fake.calls)

    def test_a_failure_in_one_file_keeps_the_findings_of_the_others(
        self, tmp_path, fake
    ):
        repo = _tree(tmp_path)
        fake.specs["requirements.txt"] = {"returncode": 1, "report": POSITIVE}
        fake.specs["svc/requirements-dev.txt"] = {"returncode": 2, "report": None}
        scanner = _scanner(repo, tmp_path)
        with pytest.raises(ScannerError, match="1 of 2 requirements file"):
            scanner.scan(target=repo, target_type="source")
        written = list((tmp_path / "out").rglob("pip-audit.sarif"))
        assert len(written) == 1
        kept = SarifReport.model_validate_json(written[0].read_text())
        assert _rows(kept.runs[0].results) == POSITIVE_EXPECTED


class TestTimeout:
    def test_the_scan_timeout_reaches_the_subprocess(self, tmp_path, fake):
        repo = _tree(tmp_path)
        fake.default = {"returncode": 0, "report": NEGATIVE}
        _scanner(repo, tmp_path, scan_timeout=77).scan(
            target=repo, target_type="source"
        )
        assert {c["timeout"] for c in fake.calls} == {77.0}

    def test_a_timeout_fails_the_scan_and_says_so(self, tmp_path, fake):
        repo = _tree(tmp_path)
        fake.default = {"returncode": 124, "report": None, "timed_out": True}
        with pytest.raises(ScannerError, match="timed out after 5.0s"):
            _scanner(repo, tmp_path, scan_timeout=5).scan(
                target=repo, target_type="source"
            )


class TestMalformedOutput:
    @pytest.mark.parametrize(
        "body,fragment",
        [
            ("", "not JSON"),
            ("not json at all", "not JSON"),
            ("[]", "cannot read"),  # the README's array shape
            ('{"dependencies": "x"}', "cannot read"),
            ('{"dependencies": [{"version": "1"}]}', "cannot read"),
        ],
    )
    def test_an_unreadable_report_fails_the_scan(self, tmp_path, fake, body, fragment):
        repo = _tree(tmp_path)
        fake.default = {"returncode": 0, "report": body}
        with pytest.raises(ScannerError, match=fragment):
            _scanner(repo, tmp_path).scan(target=repo, target_type="source")

    def test_a_skipped_dependency_makes_the_run_not_clean(self, tmp_path, fake):
        repo = _tree(tmp_path)
        fake.default = {
            "returncode": 0,
            "report": {
                "dependencies": [{"name": "private-lib", "skip_reason": "not on PyPI"}],
                "fixes": [],
            },
        }
        with pytest.raises(ScannerError, match="private-lib: not on PyPI"):
            _scanner(repo, tmp_path).scan(target=repo, target_type="source")


class TestDependencyCheck:
    def _missing(self, monkeypatch):
        monkeypatch.setattr(
            PipAuditScanner, "_validate_uv_tool_availability", lambda self: True
        )
        monkeypatch.setattr(
            PipAuditScanner,
            "_get_tool_installation_info",
            lambda self: {"available": False},
        )
        monkeypatch.setattr(
            PipAuditScanner, "_install_uv_tool", lambda self, timeout=None: False
        )
        monkeypatch.setattr(module, "get_uv_tool_command", lambda name: None)

    def test_a_missing_tool_names_the_install_command(self, tmp_path, monkeypatch):
        repo = _tree(tmp_path)
        self._missing(monkeypatch)
        scanner = _scanner(repo, tmp_path)
        assert scanner.validate_plugin_dependencies() is False
        reason = scanner.dependency_unavailable_reason
        assert "uv tool install 'pip-audit==2.10.1'" in reason
        assert "--tool pip-audit" in reason
        assert "ash_pip_audit_plugins" in reason

    def test_a_missing_tool_skips_the_scan_without_running_anything(
        self, tmp_path, monkeypatch
    ):
        repo = _tree(tmp_path)
        self._missing(monkeypatch)
        calls: List[Any] = []
        monkeypatch.setattr(
            PipAuditScanner, "_run_subprocess", lambda self, **kw: calls.append(kw)
        )
        scanner = _scanner(repo, tmp_path)
        assert scanner.scan(target=repo, target_type="source") is False
        assert calls == []

    def test_offline_is_refused_with_the_reason(self, tmp_path, monkeypatch, caplog):
        monkeypatch.setenv("ASH_OFFLINE", "true")
        repo = _tree(tmp_path)
        scanner = _scanner(repo, tmp_path)
        with caplog.at_level(logging.DEBUG):
            assert scanner.validate_plugin_dependencies() is False
        assert "has no offline mode" in scanner.dependency_unavailable_reason

    def test_a_reason_already_recorded_is_honored(self, tmp_path):
        repo = _tree(tmp_path)
        scanner = _scanner(repo, tmp_path)
        scanner.dependency_unavailable_reason = "recorded earlier"
        assert scanner.validate_plugin_dependencies() is False


class TestInstall:
    def test_the_install_command_pins_the_version(self, tmp_path):
        repo = tmp_path / "src"
        repo.mkdir()
        scanner = _scanner(repo, tmp_path)
        assert scanner.uv_tool_install_commands == [
            f"uv tool install pip-audit{PIP_AUDIT_DEFAULT_VERSION_CONSTRAINT}"
        ]

    @pytest.mark.parametrize(
        "platform,arch",
        [
            ("linux", "amd64"),
            ("linux", "arm64"),
            ("darwin", "amd64"),
            ("darwin", "arm64"),
            ("windows", "amd64"),
        ],
    )
    def test_install_commands_cover_every_platform(self, tmp_path, platform, arch):
        repo = tmp_path / "src"
        repo.mkdir()
        commands = _scanner(repo, tmp_path).get_installation_commands(platform, arch)
        assert ["uv", "tool", "install", "pip-audit==2.10.1"] in commands

    def test_a_tool_version_option_overrides_the_default(self, tmp_path):
        repo = tmp_path / "src"
        repo.mkdir()
        scanner = _scanner(repo, tmp_path, tool_version=">=2.9,<3")
        assert scanner._get_tool_version_constraint() == ">=2.9,<3"
