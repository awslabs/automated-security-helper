# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Behavior of the Polaris community scanner with the subprocess replaced.

The positive report below is a trimmed copy of what ``polaris audit`` v10.2.6 wrote for
``deploy.yaml`` (a Deployment ``web`` in namespace ``demo`` with ``hostNetwork: true``, a
privileged ``nginx:latest`` container and no resource limits), run as
``polaris audit --audit-path ./deploy.yaml --format=json --only-show-failed-tests
--output-file=out.json``. Checks were dropped to keep it short; the field names, nesting
and severities are as Polaris wrote them. The negative report is Polaris's output for a
directory that holds one YAML file that is not Kubernetes.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_polaris_plugins
from automated_security_helper.plugin_modules.ash_polaris_plugins import (
    polaris_scanner as ps,
)
from automated_security_helper.plugin_modules.ash_polaris_plugins.polaris_scanner import (
    PolarisScanner,
    PolarisScannerConfig,
    PolarisScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit


def _check(check_id, message, severity, category, details=None) -> Dict[str, Any]:
    return {
        "ID": check_id,
        "Message": message,
        "Details": details,
        "Success": False,
        "Severity": severity,
        "Category": category,
        "Mutations": None,
    }


POSITIVE: Dict[str, Any] = {
    "PolarisOutputVersion": "1.0",
    "AuditTime": "2026-11-19T15:44:52Z",
    "SourceType": "Path",
    "SourceName": ".",
    "DisplayName": ".",
    "ClusterInfo": {
        "Version": "unknown",
        "Nodes": 0,
        "Pods": 0,
        "Namespaces": 0,
        "Controllers": 1,
    },
    "Results": [
        {
            "Name": "web",
            "Namespace": "demo",
            "Kind": "Deployment",
            "Results": {
                "deploymentMissingReplicas": _check(
                    "deploymentMissingReplicas",
                    "Only one replica is scheduled",
                    "warning",
                    "Reliability",
                ),
            },
            "PodResult": {
                "Name": "",
                "Results": {
                    "hostNetworkSet": _check(
                        "hostNetworkSet",
                        "Host network should not be configured",
                        "danger",
                        "Security",
                    ),
                },
                "ContainerResults": [
                    {
                        "Name": "nginx",
                        "Results": {
                            "cpuLimitsMissing": _check(
                                "cpuLimitsMissing",
                                "CPU limits should be set",
                                "warning",
                                "Efficiency",
                            ),
                            "runAsPrivileged": _check(
                                "runAsPrivileged",
                                "Should not be running as privileged",
                                "danger",
                                "Security",
                            ),
                        },
                    }
                ],
            },
            "CreatedTime": "0001-01-01T00:00:00Z",
        }
    ],
    "Score": 40,
}

NEGATIVE: Dict[str, Any] = {
    "PolarisOutputVersion": "1.0",
    "AuditTime": "2026-11-19T15:45:00Z",
    "SourceType": "Path",
    "SourceName": ".",
    "DisplayName": ".",
    "ClusterInfo": {
        "Version": "unknown",
        "Nodes": 0,
        "Pods": 0,
        "Namespaces": 0,
        "Controllers": 0,
    },
    "Results": [],
    "Score": 100,
}

DEPLOY_YAML = """\
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: demo
spec:
  replicas: 1
"""

#: (ruleId, SARIF level, ASH severity, uri, line), written out by hand from POSITIVE and
#: DEPLOY_YAML (metadata.name is on line 4: apiVersion, kind, metadata, name), in the
#: order the converter emits: the controller's checks, then the pod's, then each
#: container's, each sorted by check id.
POSITIVE_EXPECTED = [
    ("deploymentMissingReplicas", "warning", "MEDIUM", "k8s/deploy.yaml", 4),
    ("hostNetworkSet", "error", "HIGH", "k8s/deploy.yaml", 4),
    ("cpuLimitsMissing", "warning", "MEDIUM", "k8s/deploy.yaml", 4),
    ("runAsPrivileged", "error", "HIGH", "k8s/deploy.yaml", 4),
]


def _findings(report: SarifReport) -> List[tuple]:
    out = []
    for r in report.get_all_results():
        loc = r.locations[0].physicalLocation.root
        out.append(
            (
                r.ruleId,
                getattr(r.level, "value", r.level),
                getattr(r.properties, "issue_severity", None),
                loc.artifactLocation.uri,
                loc.region.startLine,
            )
        )
    return out


class FakePolaris:
    """Stands in for _run_subprocess: records argv, writes a report where argv says."""

    def __init__(
        self,
        document: Optional[Any] = None,
        exit_code: int = 3,
        text: Optional[str] = None,
        write: bool = True,
        timed_out: bool = False,
        stderr: str = "",
    ):
        self.document = POSITIVE if document is None else document
        self.exit_code, self.text, self.write = exit_code, text, write
        self.timed_out, self.stderr = timed_out, stderr
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            self.calls.append(
                {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            )
            if self.timed_out:
                scanner.exit_code = -9
                return {"timed_out": True}
            out = next(a for a in command if a.startswith("--output-file="))
            path = Path(out.split("=", 1)[1])
            if self.write:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    self.text if self.text is not None else json.dumps(self.document),
                    encoding="utf-8",
                )
            scanner.exit_code = self.exit_code
            return {"returncode": self.exit_code, "stdout": "", "stderr": self.stderr}

        return run

    @property
    def argv(self) -> List[str]:
        return self.calls[0]["argv"]


def _scanner(
    source: Path, tmp_path: Path, output: Optional[Path] = None, **options
) -> PolarisScanner:
    config = get_default_config()
    output = output if output is not None else tmp_path / "out"
    return PolarisScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=config,
        ),
        config=PolarisScannerConfig(
            enabled=True, options=PolarisScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "k8s").mkdir(parents=True)
    (src / "k8s" / "deploy.yaml").write_text(DEPLOY_YAML)
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(ps, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner, fake, monkeypatch, target_type="source"):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(scanner.context.source_dir), target_type=target_type
    )


class TestCommunityPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert PolarisScannerConfig().enabled is True
        assert PolarisScannerConfig().name == "polaris"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "polaris")

    def test_the_module_exports_the_scanner(self):
        assert ash_polaris_plugins.ASH_SCANNERS == [PolarisScanner]
        assert ash_polaris_plugins.ASH_REPORTERS == []

    def test_the_plugin_has_no_option_that_lets_the_tree_choose_findings(self):
        own = set(PolarisScannerConfigOptions.model_fields) - set(
            ps.ScannerOptionsBase.model_fields
        )
        assert own == set()

    def test_class_vars(self):
        assert PolarisScanner.python_only is False
        assert PolarisScanner.success_exit_codes == {0, 3}
        assert PolarisScanner.offline_strategy.name == "BUNDLED"


class TestInvocation:
    def test_every_fixed_flag_and_the_scan_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakePolaris()
        _run(scanner, fake, monkeypatch)
        argv = fake.argv
        assert argv[:2] == ["polaris", "audit"]
        assert "--audit-path=." in argv
        assert "--format=json" in argv
        assert "--only-show-failed-tests=true" in argv
        assert "--set-exit-code-on-danger=true" in argv
        assert "--disallow-exemptions=true" in argv
        assert any(a.startswith("--output-file=") for a in argv)
        assert fake.calls[0]["cwd"] in (None, tree)

    def test_every_option_is_one_token(self, tree, tmp_path, on_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        fake = FakePolaris()
        _run(scanner, fake, monkeypatch)
        assert all(a.startswith("--") or a in ("polaris", "audit") for a in fake.argv)

    @pytest.mark.parametrize(
        "flag",
        [
            "--config",
            "--merge-config",
            "--output-url",
            "--context",
            "--namespace",
            "--resource",
            "--helm-chart",
            "--insights-host",
            "--skip-ssl-validation",
        ],
    )
    def test_flags_that_read_the_tree_or_reach_a_cluster_or_network_are_never_passed(
        self, flag, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakePolaris()
        _run(scanner, fake, monkeypatch)
        assert not any(a == flag or a.startswith(flag + "=") for a in fake.argv)

    def test_a_converted_target_is_an_absolute_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        converted = tmp_path / "out" / "converted"
        converted.mkdir(parents=True)
        (converted / "x.yaml").write_text(DEPLOY_YAML)
        scanner = _scanner(tree, tmp_path)
        fake = FakePolaris(document=NEGATIVE, exit_code=0)
        monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
        scanner.scan(target=converted, target_type="converted")
        assert f"--audit-path={converted.absolute().as_posix()}" in fake.argv

    def test_a_missing_target_never_reaches_the_tool(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakePolaris()
        monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
        scanner.scan(target=tmp_path / "nope", target_type="source")
        assert fake.calls == []

    def test_a_report_left_by_an_earlier_run_is_not_read_as_this_runs(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        first = FakePolaris()
        _run(scanner, first, monkeypatch)
        stale = Path(
            next(a for a in first.argv if a.startswith("--output-file=")).split("=", 1)[
                1
            ]
        )
        assert stale.exists()
        with pytest.raises(ScannerError):
            _run(scanner, FakePolaris(write=False, exit_code=0), monkeypatch)


class TestReport:
    def test_positive_report_is_located_and_rated(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakePolaris(), monkeypatch)
        assert isinstance(report, SarifReport)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_negative_control_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakePolaris(document=NEGATIVE, exit_code=0)
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert isinstance(report, SarifReport)
        assert report.runs and _findings(report) == []

    def test_container_findings_name_the_container(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakePolaris(), monkeypatch)
        by_rule = {r.ruleId: r.message.root.text for r in report.get_all_results()}
        assert "container nginx" in by_rule["runAsPrivileged"]
        assert "container" not in by_rule["hostNetworkSet"]

    @pytest.mark.parametrize(
        "severity,expected",
        [
            ("danger", ("error", "HIGH")),
            ("warning", ("warning", "MEDIUM")),
            ("somethingnew", ("error", "HIGH")),
        ],
    )
    def test_severity_mapping_row_by_row(
        self, severity, expected, tree, tmp_path, on_path, monkeypatch
    ):
        doc = copy.deepcopy(POSITIVE)
        doc["Results"][0]["Results"]["deploymentMissingReplicas"]["Severity"] = severity
        report = _run(_scanner(tree, tmp_path), FakePolaris(document=doc), monkeypatch)
        first = _findings(report)[0]
        assert first[0] == "deploymentMissingReplicas"
        assert first[1:3] == expected

    def test_ignore_severity_and_successful_checks_are_not_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        doc = copy.deepcopy(POSITIVE)
        doc["Results"][0]["Results"]["deploymentMissingReplicas"]["Severity"] = "ignore"
        doc["Results"][0]["PodResult"]["Results"]["hostNetworkSet"]["Success"] = True
        report = _run(_scanner(tree, tmp_path), FakePolaris(document=doc), monkeypatch)
        assert [f[0] for f in _findings(report)] == [
            "cpuLimitsMissing",
            "runAsPrivileged",
        ]

    def test_an_object_defined_in_two_files_is_reported_against_both(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / "k8s" / "copy.yml").write_text(DEPLOY_YAML)
        report = _run(_scanner(tree, tmp_path), FakePolaris(), monkeypatch)
        uris = {f[3] for f in _findings(report)}
        assert uris == {"k8s/deploy.yaml", "k8s/copy.yml"}

    def test_an_object_no_file_defines_is_dropped(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / "k8s" / "deploy.yaml").write_text(
            "kind: Service\nmetadata:\n  name: x\n"
        )
        report = _run(_scanner(tree, tmp_path), FakePolaris(), monkeypatch)
        assert _findings(report) == []

    def test_a_file_reached_through_a_link_is_not_a_location(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        outside = tmp_path / "outside.yaml"
        outside.write_text(DEPLOY_YAML)
        (tree / "k8s" / "deploy.yaml").unlink()
        (tree / "k8s" / "link.yaml").symlink_to(outside)
        report = _run(_scanner(tree, tmp_path), FakePolaris(), monkeypatch)
        assert _findings(report) == []

    def test_a_file_under_ashs_output_directory_is_not_a_location(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        out = tree / ".ash" / "ash_output"
        out.mkdir(parents=True)
        (tree / "k8s" / "deploy.yaml").unlink()
        (out / "copy.yaml").write_text(DEPLOY_YAML)
        # ASH's default output directory is the one under the scanned tree.
        report = _run(_scanner(tree, tmp_path, output=out), FakePolaris(), monkeypatch)
        assert _findings(report) == []

    def test_every_result_carries_severity_and_level(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakePolaris(), monkeypatch)
        for r in report.get_all_results():
            assert getattr(r.properties, "issue_severity") in ("HIGH", "MEDIUM")
            level = getattr(r.level, "value", r.level)
            assert (level == "error") == (r.properties.issue_severity == "HIGH")


class TestExitStatusAndFailures:
    def test_zero_and_three_succeed(self, tree, tmp_path, on_path, monkeypatch):
        for code in (0, 3):
            fake = FakePolaris(exit_code=code)
            assert isinstance(
                _run(_scanner(tree, tmp_path), fake, monkeypatch), SarifReport
            )

    @pytest.mark.parametrize("code", [1, 2, 4, 126, 137])
    def test_any_other_code_fails_even_with_a_report_on_disk(
        self, code, tree, tmp_path, on_path, monkeypatch
    ):
        with pytest.raises(ScannerError, match="exited"):
            _run(_scanner(tree, tmp_path), FakePolaris(exit_code=code), monkeypatch)

    def test_a_run_that_wrote_no_report_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        with pytest.raises(ScannerError):
            _run(_scanner(tree, tmp_path), FakePolaris(write=False), monkeypatch)

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=5)
        fake = FakePolaris(timed_out=True)
        # The shared template flow words it "<Name> timed out after '<n>' s and was
        # killed, so it produced no results file" (timeout_limit_token).
        with pytest.raises(
            ScannerError,
            match=r"PolarisScanner timed out after '5' s and was killed, so it "
            r"produced no results file",
        ):
            _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 5

    @pytest.mark.parametrize(
        "text",
        [
            "not json",
            "[1, 2]",
            '"a string"',
            "{}",
            '{"PolarisOutputVersion": "1.0", "Results": {"a": 1}}',
            '{"PolarisOutputVersion": "1.0", "Results": [1]}',
            '{"PolarisOutputVersion": "9.0", "Results": []}',
            '{"Results": []}',
        ],
    )
    def test_malformed_output_fails_the_scan(
        self, text, tree, tmp_path, on_path, monkeypatch
    ):
        with pytest.raises(ScannerError):
            _run(
                _scanner(tree, tmp_path),
                FakePolaris(text=text, exit_code=0),
                monkeypatch,
            )

    def test_an_empty_report_file_is_not_a_clean_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        with pytest.raises(ScannerError):
            _run(
                _scanner(tree, tmp_path), FakePolaris(text="", exit_code=0), monkeypatch
            )

    def test_null_results_is_a_clean_scan(self, tree, tmp_path, on_path, monkeypatch):
        doc = dict(NEGATIVE, Results=None)
        report = _run(
            _scanner(tree, tmp_path),
            FakePolaris(document=doc, exit_code=0),
            monkeypatch,
        )
        assert _findings(report) == []

    def test_stderr_is_not_copied_into_errors(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakePolaris(stderr='level=info msg="secret-path/in/tree"')
        _run(scanner, fake, monkeypatch)
        assert not any("secret-path" in e for e in scanner.errors)

    def test_the_failure_message_does_not_quote_the_log(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakePolaris(exit_code=1, stderr="LEAKY-LOG-LINE")
        with pytest.raises(ScannerError) as raised:
            _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert "LEAKY-LOG-LINE" not in str(raised.value)
        assert "stderr.log" in str(raised.value)

    def test_missing_binary_is_reported_as_unsatisfied_dependencies(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(ps, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        fake = FakePolaris()
        assert _run(scanner, fake, monkeypatch) is False
        assert scanner.dependencies_satisfied is False
        assert fake.calls == []

    def test_dependency_check_finds_the_binary_on_path(self, tree, tmp_path, on_path):
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is True


class TestInstall:
    def test_install_commands_cover_every_published_platform(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
        scanner = _scanner(tmp_path, tmp_path)
        for platform, arch in [
            ("linux", "amd64"),
            ("linux", "arm64"),
            ("darwin", "amd64"),
            ("darwin", "arm64"),
            ("windows", "amd64"),
        ]:
            commands = scanner.get_installation_commands(platform, arch)
            assert commands, f"no install command for {platform}/{arch}"
            # A command is a CustomCommand whose argv runs the module-local installer.
            argv = " ".join(str(a) for a in commands[0].args)
            assert "polaris_install" in argv and platform in argv and arch in argv
