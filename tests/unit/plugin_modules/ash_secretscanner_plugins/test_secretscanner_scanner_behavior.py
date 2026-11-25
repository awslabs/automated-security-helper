# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""SecretScannerScanner: the image gate, the invocation, severity and failures.

The tool's JSON below is written by hand from the output structs in
deepfence/SecretScanner v2.5.8 (output/output.go and YaraHunter's pkg/output),
not captured from a run: the tool publishes no binary to capture with. The
matched text is a plain placeholder, not a credential. The subprocess is a fake,
so the tests run on every platform without the tool.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_facets import FacetState, ScannerFacets
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_secretscanner_plugins as pkg
from automated_security_helper.plugin_modules.ash_secretscanner_plugins import (
    secretscanner_scanner as ss,
)
from automated_security_helper.plugin_modules.ash_secretscanner_plugins.secretscanner_scanner import (
    SECRETSCANNER_SEVERITY_MAP,
    SecretScannerConfig,
    SecretScannerConfigOptions,
    SecretScannerScanner,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.config_trust import record_provenance
from automated_security_helper.utils.sandbox.policy import SandboxRequirements

pytestmark = pytest.mark.unit

IMAGE = "registry.example.com/team/app:1.2.3"
PLACEHOLDER = "EXAMPLE-NOT-A-CREDENTIAL"


def _entry(severity: Optional[str] = "high", **extra: Any) -> Dict[str, Any]:
    entry: Dict[str, Any] = {
        "Image Layer ID": "layer-1",
        "Matched Rule Name": "aws-access-key",
        "Matched Part": "contents",
        "Severity": severity,
        "Severity Score": 8.5,
        "Full File Name": "/app/config/settings.env",
        "rule meta": [],
        "matches": [{"Offset": 12, "Data": PLACEHOLDER}],
    }
    if severity is None:
        del entry["Severity"]
    entry.update(extra)
    return entry


def _document(*entries: Dict[str, Any], key: str = "IOC") -> str:
    return json.dumps(
        {
            "Timestamp": "2026-11-18T00:00:00Z",
            "Image Name": IMAGE,
            "Image ID": "sha256:0",
            "Container ID": "",
            key: list(entries),
        }
    )


class FakeSecretScanner:
    """Stands in for _run_subprocess: records the call, serves canned output."""

    def __init__(
        self,
        stdout: str = "",
        exit_code: int = 0,
        stderr: str = "",
        timed_out: bool = False,
    ):
        self.stdout, self.exit_code, self.stderr = stdout, exit_code, stderr
        self.timed_out = timed_out
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, timeout=None, **kwargs):
            self.calls.append(
                {"argv": list(command), "timeout": timeout, "kwargs": kwargs}
            )
            if self.timed_out:
                scanner.exit_code = -9
                return {"timed_out": True}
            scanner.exit_code = self.exit_code
            return {
                "returncode": self.exit_code,
                "stdout": self.stdout,
                "stderr": self.stderr,
            }

        return run


def _scanner(
    source: Path, tmp_path: Path, *, operator: bool = True, **options
) -> SecretScannerScanner:
    """``operator``: the options came from the operator, or from the scanned tree."""
    config = get_default_config()
    record_provenance(
        config,
        in_tree=[] if operator else [source / ".ash" / ".ash.yaml"],
        trusted=AshConfig(),
    )
    return SecretScannerScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "out" / "converted",
            config=config,
        ),
        config=SecretScannerConfig(
            enabled=True, options=SecretScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("print(1)\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(ss, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner, fake, monkeypatch, target_type="source"):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(scanner.context.source_dir), target_type=target_type
    )


def _findings(report) -> List[tuple]:
    return [
        (
            r.ruleId,
            getattr(r.level, "value", r.level),
            getattr(r.properties, "issue_severity", None),
            r.locations[0].physicalLocation.root.artifactLocation.uri,
        )
        for r in report.get_all_results()
    ]


class TestCommunityPlugin:
    def test_the_module_exports_the_scanner(self):
        assert pkg.ASH_SCANNERS == [SecretScannerScanner]
        assert pkg.ASH_REPORTERS == []

    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert SecretScannerConfig().enabled is True
        assert SecretScannerConfig().name == "secretscanner"

    def test_class_vars_are_set_deliberately(self):
        assert SecretScannerScanner.python_only is False
        assert SecretScannerScanner.success_exit_codes == {0}


class TestGate:
    def test_no_image_runs_nothing_and_reports_nothing(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeSecretScanner(stdout=_document(_entry()))
        report = _run(scanner, fake, monkeypatch)
        assert fake.calls == []
        assert report.get_all_results() == []
        assert scanner.targets_attempted == 0

    def test_a_blank_image_is_no_image(self, tree, tmp_path, on_path, monkeypatch):
        scanner = _scanner(tree, tmp_path, image_name="   ")
        fake = FakeSecretScanner(stdout=_document(_entry()))
        _run(scanner, fake, monkeypatch)
        assert fake.calls == []

    def test_an_image_the_scanned_tree_set_is_ignored(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, operator=False, image_name=IMAGE)
        fake = FakeSecretScanner(stdout=_document(_entry()))
        report = _run(scanner, fake, monkeypatch)
        assert fake.calls == []
        assert report.get_all_results() == []

    def test_the_converted_target_is_not_scanned_again(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, image_name=IMAGE)
        fake = FakeSecretScanner(stdout=_document(_entry()))
        report = _run(scanner, fake, monkeypatch, target_type="converted")
        assert fake.calls == []
        assert report.get_all_results() == []

    @pytest.mark.parametrize(
        "bad", ["-image-name=x", "--flag", "a b", "img;rm", "img\nx"]
    )
    def test_an_image_that_is_not_a_reference_fails_the_scan(
        self, bad, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, image_name=bad)
        fake = FakeSecretScanner(stdout=_document(_entry()))
        with pytest.raises(ScannerError):
            _run(scanner, fake, monkeypatch)
        assert fake.calls == []


class TestInvocation:
    def test_every_fixed_flag_and_the_image(self, tree, tmp_path, on_path, monkeypatch):
        scanner = _scanner(tree, tmp_path, image_name=IMAGE)
        fake = FakeSecretScanner(stdout=_document(_entry()))
        _run(scanner, fake, monkeypatch)
        assert len(fake.calls) == 1
        argv = fake.calls[0]["argv"]
        assert argv[0] == "SecretScanner"
        assert argv[1] == "-output=json"
        assert argv[2] == f"-image-name={IMAGE}"
        assert argv[3].startswith("-temp-directory=")
        assert Path(argv[3].split("=", 1)[1]).parts[-1] == "secretscanner-tmp"
        assert len(argv) == 4

    @pytest.mark.parametrize(
        "flag",
        [
            "-local",
            "-enable-updater",
            "-config-path",
            "-rules-path",
            "-console-url",
            "-deepfence-key",
            "-socket-path",
            "-http-port",
            "-standalone-http-port",
            "-container-id",
        ],
    )
    def test_flags_that_read_the_tree_or_reach_the_network_are_never_passed(
        self, flag, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, image_name=IMAGE)
        fake = FakeSecretScanner(stdout=_document(_entry()))
        _run(scanner, fake, monkeypatch)
        assert not any(
            a.split("=", 1)[0].lstrip("-") == flag.lstrip("-")
            for a in fake.calls[0]["argv"]
        )

    def test_the_scan_timeout_reaches_the_subprocess(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, image_name=IMAGE, scan_timeout=77)
        fake = FakeSecretScanner(stdout=_document(_entry()))
        _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 77


class TestReport:
    def test_a_finding_is_rated_and_located(self, tree, tmp_path, on_path, monkeypatch):
        scanner = _scanner(tree, tmp_path, image_name=IMAGE)
        fake = FakeSecretScanner(stdout=_document(_entry()))
        report = _run(scanner, fake, monkeypatch)
        assert _findings(report) == [
            ("aws-access-key", "error", "HIGH", "/app/config/settings.env")
        ]
        assert scanner.targets_attempted == 1

    def test_the_older_secrets_key_is_read_too(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, image_name=IMAGE)
        fake = FakeSecretScanner(stdout=_document(_entry(), key="Secrets"))
        report = _run(scanner, fake, monkeypatch)
        assert len(report.get_all_results()) == 1

    def test_negative_control_an_image_with_no_findings_is_clean(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, image_name=IMAGE)
        fake = FakeSecretScanner(stdout=_document())
        report = _run(scanner, fake, monkeypatch)
        assert report.get_all_results() == []
        assert scanner.targets_attempted == 1

    @pytest.mark.parametrize(
        "severity,expected",
        [
            ("high", ("HIGH", "error")),
            ("medium", ("MEDIUM", "warning")),
            ("low", ("LOW", "note")),
            ("High", ("HIGH", "error")),
            (None, ("MEDIUM", "warning")),
            ("critical", ("HIGH", "error")),
        ],
    )
    def test_severity_and_level_agree_row_by_row(
        self, severity, expected, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, image_name=IMAGE)
        fake = FakeSecretScanner(stdout=_document(_entry(severity)))
        report = _run(scanner, fake, monkeypatch)
        (_, level, issue_severity, _) = _findings(report)[0]
        assert (issue_severity, level) == expected

    def test_the_map_holds_the_three_tool_severities(self):
        assert set(SECRETSCANNER_SEVERITY_MAP) == {"high", "medium", "low"}

    def test_the_matched_text_never_reaches_the_report(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, image_name=IMAGE)
        fake = FakeSecretScanner(
            stdout=_document(_entry(**{"Matched Contents": PLACEHOLDER}))
        )
        report = _run(scanner, fake, monkeypatch)
        assert PLACEHOLDER not in report.model_dump_json()

    def test_a_finding_with_no_file_is_located_at_the_image(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, image_name=IMAGE)
        fake = FakeSecretScanner(stdout=_document(_entry(**{"Full File Name": ""})))
        report = _run(scanner, fake, monkeypatch)
        assert _findings(report)[0][3] == IMAGE


class TestFailures:
    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, image_name=IMAGE, scan_timeout=5)
        fake = FakeSecretScanner(timed_out=True)
        with pytest.raises(ScannerError, match="timed out"):
            _run(scanner, fake, monkeypatch)

    @pytest.mark.parametrize("code", [1, 2, 126, 137])
    def test_a_nonzero_exit_fails_even_with_findings_on_stdout(
        self, code, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, image_name=IMAGE)
        fake = FakeSecretScanner(stdout=_document(_entry()), exit_code=code)
        with pytest.raises(ScannerError):
            _run(scanner, fake, monkeypatch)

    @pytest.mark.parametrize(
        "stdout",
        [
            "",
            "   \n",
            "not json at all",
            "[1, 2, 3]",
            '{"Image Name": "x"}',
            '{"IOC": "nope"}',
            '{"IOC": [1]}',
        ],
    )
    def test_malformed_output_fails_the_scan(
        self, stdout, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, image_name=IMAGE)
        fake = FakeSecretScanner(stdout=stdout)
        with pytest.raises(ScannerError):
            _run(scanner, fake, monkeypatch)

    def test_stderr_is_not_copied_into_the_errors(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, image_name=IMAGE)
        fake = FakeSecretScanner(exit_code=1, stderr=f"matched {PLACEHOLDER}")
        with pytest.raises(ScannerError) as raised:
            _run(scanner, fake, monkeypatch)
        assert PLACEHOLDER not in str(raised.value)
        assert PLACEHOLDER not in " ".join(scanner.errors)


class TestDependencyCheck:
    def test_missing_binary(self, tree, tmp_path, monkeypatch):
        monkeypatch.setattr(ss, "find_executable", lambda cmd: None)
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is False

    def test_present_binary(self, tree, tmp_path, on_path):
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is True

    def test_an_unavailable_reason_wins_over_a_binary_on_path(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        scanner.dependency_unavailable_reason = "refused"
        assert scanner.validate_plugin_dependencies() is False


class TestSandboxRequirements:
    """The strict default is deliberate: reading an image needs the Docker socket,
    which no sandbox grant covers yet, and the tool must never be given a network."""

    def test_the_declaration_is_the_strict_default(self):
        assert SecretScannerScanner.sandbox_requirements == SandboxRequirements()

    def test_no_network_no_env_no_paths(self):
        requirements = SecretScannerScanner.sandbox_requirements
        assert requirements.network is False
        assert requirements.network_requires_grant is False
        assert tuple(requirements.env_prefixes) == ()
        assert tuple(requirements.env_names) == ()
        assert tuple(requirements.read_paths) == ()
        assert tuple(requirements.cache_paths) == ()

    def test_an_instance_reads_the_same_declaration(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path, image_name=IMAGE)
        assert scanner.sandbox_requirements == SandboxRequirements()


_CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "secretscanner"
    / "captured"
)


def _comparable(report) -> List[Dict[str, Any]]:
    rows = []
    for result in report.get_all_results():
        properties = result.properties.model_dump() if result.properties else {}
        rows.append(
            {
                "rule": result.ruleId,
                "level": getattr(result.level, "value", result.level),
                "message": result.message.root.text,
                "uri": result.locations[0].physicalLocation.root.artifactLocation.uri,
                "region": result.locations[0].physicalLocation.root.region,
                "properties": {k: v for k, v in properties.items() if v is not None},
            }
        )
    return rows


class TestCapturedSamples:
    """The converter over the committed sample JSON, against the committed SARIF.

    The samples are hand-written from the tool's output structs, not captured (see
    captured/README.md), so this pins the mapping, not the tool's real output."""

    def _convert(self, tree, tmp_path, name: str):
        text = (_CAPTURED / f"{name}.json").read_text(encoding="utf-8")
        scanner = _scanner(tree, tmp_path, image_name=IMAGE)
        return scanner.convert_output(text, IMAGE)

    @pytest.mark.parametrize("name", ["positive", "negative"])
    def test_the_converter_reproduces_the_committed_sarif(self, name, tree, tmp_path):
        expected = SarifReport.model_validate(
            json.loads((_CAPTURED / f"{name}.sarif").read_text(encoding="utf-8"))
        )
        actual = self._convert(tree, tmp_path, name)
        assert _comparable(actual) == _comparable(expected)

    def test_positive_sample_is_not_vacuous(self, tree, tmp_path):
        report = self._convert(tree, tmp_path, "positive")
        assert len(report.get_all_results()) == 3

    def test_negative_sample_has_no_results(self, tree, tmp_path):
        assert self._convert(tree, tmp_path, "negative").get_all_results() == []

    def test_severity_mapping_over_the_sample(self, tree, tmp_path):
        report = self._convert(tree, tmp_path, "positive")
        assert [
            (
                getattr(r.level, "value", r.level),
                getattr(r.properties, "issue_severity", None),
            )
            for r in report.get_all_results()
        ] == [("error", "HIGH"), ("warning", "MEDIUM"), ("note", "LOW")]

    def test_the_placeholder_secret_is_in_the_sample_and_not_in_the_report(
        self, tree, tmp_path
    ):
        assert PLACEHOLDER in (_CAPTURED / "positive.json").read_text(encoding="utf-8")
        report = self._convert(tree, tmp_path, "positive")
        assert PLACEHOLDER not in report.model_dump_json()


class TestFacetsDeclaration:
    def test_the_scanner_declares_its_own_facets(self):
        assert isinstance(vars(SecretScannerScanner).get("facets"), ScannerFacets)
        assert isinstance(
            vars(SecretScannerScanner).get("operational_facets"),
            opsf.ScannerOperationalFacets,
        )

    def test_the_register_names_the_scanner_its_config_carries(self):
        row = SecretScannerScanner.operational_facets
        assert row.scanner_name == SecretScannerConfig().name == "secretscanner"

    def test_the_mirrored_fields_agree_with_the_class(self, tree, tmp_path):
        row = SecretScannerScanner.operational_facets
        scanner = _scanner(tree, tmp_path)
        assert row.exit_codes.success_exit_codes == tuple(
            sorted(SecretScannerScanner.success_exit_codes)
        )
        assert row.network.offline_strategy is SecretScannerScanner.offline_strategy
        assert row.targets.tool_type is scanner.tool_type
        assert row.runtime.python_only is bool(scanner.is_python_only())
        assert row.runtime.use_uv_tool is bool(scanner.use_uv_tool)

    def test_the_matched_text_is_declared_dropped_not_mapped(self):
        snippet = SecretScannerScanner.facets.snippet
        assert snippet.state is FacetState.DROPPED
        assert "Data" in (snippet.native_field or "")
