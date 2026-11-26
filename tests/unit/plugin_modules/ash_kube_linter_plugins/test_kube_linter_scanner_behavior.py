# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""KubeLinterScanner: the invocation, the exit status, and the severity it assigns.

The subprocess is replaced by a fake, so these run on every platform without the
binary. Most tests feed it a small report built to the shape KubeLinter v0.8.3's SARIF
formatter produces (ruleId is the check name, no result level, every region at line 1).
``TestCapturedFixture`` feeds it the files a real v0.8.3 run wrote
(tests/test_data/scanners/kube-linter/captured, whose README gives the argv and inputs).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_kube_linter_plugins
from automated_security_helper.plugin_modules.ash_kube_linter_plugins import (
    kube_linter_scanner as kls,
)
from automated_security_helper.plugin_modules.ash_kube_linter_plugins.kube_linter_scanner import (
    HIGH_SEVERITY_CHECKS,
    KubeLinterScanner,
    KubeLinterScannerConfig,
    KubeLinterScannerConfigOptions,
    severity_for_check,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit

_CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "kube-linter"
    / "captured"
)


def _result(rule_id: str, uri: str, name: str) -> Dict[str, Any]:
    return {
        "ruleId": rule_id,
        "message": {"text": f"container has a problem\nobject: default/{name}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": 1},
                }
            }
        ],
    }


def _report(results: List[Dict[str, Any]]) -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "kube-linter",
                            "version": "v0.8.3",
                            "informationUri": "https://github.com/stackrox/kube-linter",
                        }
                    },
                    "results": results,
                }
            ],
        }
    )


#: Written out by hand: a privileged container is HIGH, a missing resource limit is MEDIUM.
POSITIVE = _report(
    [
        _result("privileged-container", "deploy/app.yaml", "app"),
        _result("unset-cpu-requirements", "deploy/app.yaml", "app"),
    ]
)
POSITIVE_EXPECTED = [
    ("privileged-container", "error", "HIGH", "deploy/app.yaml", 1),
    ("unset-cpu-requirements", "warning", "MEDIUM", "deploy/app.yaml", 1),
]
NEGATIVE = _report([])


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


class FakeKubeLinter:
    """Stands in for _run_subprocess: records argv and writes a report."""

    def __init__(
        self,
        sarif_text: Optional[str] = POSITIVE,
        exit_code: int = 1,
        stderr: str = "",
        timed_out: bool = False,
    ):
        self.sarif_text, self.exit_code = sarif_text, exit_code
        self.stderr, self.timed_out = stderr, timed_out
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            self.calls.append(
                {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            )
            output = next(a for a in command if a.startswith("--output="))
            path = Path(output.split("=", 1)[1])
            if self.sarif_text is not None:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(self.sarif_text, encoding="utf-8")
            scanner.exit_code = self.exit_code
            return {
                "returncode": self.exit_code,
                "stdout": "",
                "stderr": self.stderr,
                "timed_out": self.timed_out,
            }

        return run

    @property
    def argv(self) -> List[str]:
        return self.calls[0]["argv"]


def _scanner(source: Path, tmp_path: Path, **options) -> KubeLinterScanner:
    config = get_default_config()
    output = tmp_path / "out"
    return KubeLinterScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=config,
        ),
        config=KubeLinterScannerConfig(
            enabled=True, options=KubeLinterScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "deploy").mkdir(parents=True)
    (src / "deploy" / "app.yaml").write_text("kind: Deployment\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(kls, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner, fake, monkeypatch, target=None, target_type="source"):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(target or scanner.context.source_dir), target_type=target_type
    )


def _flag(argv: List[str], prefix: str) -> Optional[str]:
    for token in argv:
        if token.startswith(prefix):
            return token[len(prefix) :]
    return None


class TestAlphaPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert KubeLinterScannerConfig().enabled is True
        assert KubeLinterScannerConfig().name == "kube-linter"

    def test_the_builtin_config_does_not_declare_it(self):
        assert not hasattr(get_default_config().scanners, "kube-linter")
        assert not hasattr(get_default_config().scanners, "kube_linter")

    def test_the_module_exports_the_scanner(self):
        assert ash_kube_linter_plugins.ASH_SCANNERS == [KubeLinterScanner]
        assert ash_kube_linter_plugins.ASH_REPORTERS == []

    def test_class_vars_are_set_deliberately(self):
        assert KubeLinterScanner.python_only is False
        assert KubeLinterScanner.success_exit_codes == {0, 1}
        from automated_security_helper.core.enums import OfflineStrategy

        assert KubeLinterScanner.offline_strategy == OfflineStrategy.BUNDLED


class TestInvocation:
    def test_every_fixed_flag_and_the_scan_path(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        fake = FakeKubeLinter()
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        argv = fake.argv
        assert argv[:2] == ["kube-linter", "lint"]
        assert "--format=sarif" in argv
        assert _flag(argv, "--output=").endswith("source/kube-linter.sarif")
        assert argv[-2:] == ["--", "."]

    def test_the_tree_config_is_never_read(self, tree, tmp_path, monkeypatch, on_path):
        (tree / ".kube-linter.yaml").write_text(
            "checks:\n  doNotAutoAddDefaults: true\n"
        )
        fake = FakeKubeLinter()
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        config = Path(_flag(fake.argv, "--config="))
        assert config.read_text() == "{}\n"
        assert tree not in config.parents

    @pytest.mark.parametrize(
        "flag", ["--add-all-built-in", "--do-not-auto-add-defaults", "--verbose"]
    )
    def test_flags_that_change_the_checks_are_never_passed(
        self, flag, tree, tmp_path, monkeypatch, on_path
    ):
        fake = FakeKubeLinter()
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert flag not in fake.argv

    def test_converted_target_is_an_absolute_path(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        converted = tmp_path / "out" / "converted"
        converted.mkdir(parents=True)
        (converted / "x.yaml").write_text("kind: Pod\n")
        fake = FakeKubeLinter()
        _run(
            _scanner(tree, tmp_path),
            fake,
            monkeypatch,
            target=converted,
            target_type="converted",
        )
        assert fake.argv[-1] == converted.absolute().as_posix()

    def test_a_missing_target_never_reaches_the_tool(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        fake = FakeKubeLinter()
        _run(_scanner(tree, tmp_path), fake, monkeypatch, target=tmp_path / "nope")
        assert fake.calls == []


class TestReport:
    def test_positive_report_is_rated_and_located(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        report = _run(_scanner(tree, tmp_path), FakeKubeLinter(), monkeypatch)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_negative_control_has_no_findings(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        report = _run(
            _scanner(tree, tmp_path),
            FakeKubeLinter(sarif_text=NEGATIVE, exit_code=0),
            monkeypatch,
        )
        assert _findings(report) == []

    def test_every_result_is_tagged(self, tree, tmp_path, monkeypatch, on_path):
        report = _run(_scanner(tree, tmp_path), FakeKubeLinter(), monkeypatch)
        for result in report.get_all_results():
            assert {"kubernetes", "iac"} <= set(result.properties.tags)

    def test_no_report_with_exit_zero_means_no_object_was_found(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        report = _run(
            _scanner(tree, tmp_path),
            FakeKubeLinter(sarif_text=None, exit_code=0),
            monkeypatch,
        )
        assert isinstance(report, SarifReport)
        assert _findings(report) == []

    def test_results_under_ashs_output_dir_are_dropped(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        out = tree / ".ash" / "ash_output"
        text = _report(
            [
                _result("privileged-container", "deploy/app.yaml", "app"),
                _result("privileged-container", ".ash/ash_output/copy.yaml", "copy"),
            ]
        )
        scanner = _scanner(tree, tmp_path)
        scanner.context.output_dir = out
        report = _run(scanner, FakeKubeLinter(sarif_text=text), monkeypatch)
        assert [f[3] for f in _findings(report)] == ["deploy/app.yaml"]


class TestSeverity:
    @pytest.mark.parametrize("check", sorted(HIGH_SEVERITY_CHECKS))
    def test_high_checks_are_high_and_error(self, check):
        severity, level = severity_for_check(check)
        assert (severity, level.value) == ("HIGH", "error")

    @pytest.mark.parametrize(
        "check", ["unset-cpu-requirements", "no-read-only-root-fs", "latest-tag", None]
    )
    def test_every_other_check_is_medium_and_warning(self, check):
        severity, level = severity_for_check(check)
        assert (severity, level.value) == ("MEDIUM", "warning")


class TestExitStatus:
    def test_exit_zero_and_one_with_a_report_succeed(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        for code in (0, 1):
            report = _run(
                _scanner(tree, tmp_path / str(code)),
                FakeKubeLinter(exit_code=code),
                monkeypatch,
            )
            assert isinstance(report, SarifReport)

    @pytest.mark.parametrize("code", [2, 126, 137])
    def test_any_other_code_fails_even_with_a_report_on_disk(
        self, code, tree, tmp_path, monkeypatch, on_path
    ):
        with pytest.raises(ScannerError):
            _run(_scanner(tree, tmp_path), FakeKubeLinter(exit_code=code), monkeypatch)

    def test_exit_one_without_a_report_is_a_failed_scan(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        with pytest.raises(ScannerError):
            _run(
                _scanner(tree, tmp_path),
                FakeKubeLinter(sarif_text=None, exit_code=1),
                monkeypatch,
            )

    def test_a_report_left_by_an_earlier_run_is_removed(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path)
        scanner.results_dir = tmp_path / "out" / "results"
        stale = scanner.results_dir / "source" / "kube-linter.sarif"
        stale.parent.mkdir(parents=True)
        stale.write_text(POSITIVE)
        _, results_file, _ = scanner._execute_scan(tree, "source", [])
        assert results_file == stale
        assert not stale.exists()

    def test_timeout_fails_the_scan(self, tree, tmp_path, monkeypatch, on_path):
        scanner = _scanner(tree, tmp_path)
        fake = FakeKubeLinter(sarif_text=None, exit_code=124, timed_out=True)
        with pytest.raises(ScannerError, match="timed out after"):
            _run(scanner, fake, monkeypatch)
        # The limit reached the subprocess call: the option's value, not unbounded.
        assert scanner.config.options.scan_timeout == 1800
        assert fake.calls[0]["timeout"] == 1800

    def test_the_timeout_option_reaches_the_subprocess(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=42)
        fake = FakeKubeLinter()
        _run(scanner, fake, monkeypatch)
        assert fake.calls[0]["timeout"] == 42

    def test_stderr_is_not_copied_into_errors(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        _run(
            scanner,
            FakeKubeLinter(stderr="object: default/SENTINEL-TEXT"),
            monkeypatch,
        )
        assert "SENTINEL-TEXT" not in " ".join(scanner.errors)
        assert "SENTINEL-TEXT" not in " ".join(scanner.output)

    def test_failure_message_names_the_log_and_not_its_text(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path)
        scanner.exit_code = 2
        message = scanner._describe_scan_failure(
            ValueError("boom"), tmp_path / "source" / "kube-linter.sarif"
        )
        assert "KubeLinterScanner.stderr.log" in message
        assert "not quoted" in message


class TestMalformedOutput:
    @pytest.mark.parametrize(
        "text", ["not json at all", "[1, 2, 3]", '{"version": "2.1.0"}', "{"]
    )
    def test_an_unreadable_report_fails_the_scan(
        self, text, tree, tmp_path, monkeypatch, on_path
    ):
        with pytest.raises(Exception):
            _run(
                _scanner(tree, tmp_path),
                FakeKubeLinter(sarif_text=text, exit_code=1),
                monkeypatch,
            )


class TestDependencyCheck:
    def test_missing_binary(self, tree, tmp_path, monkeypatch):
        monkeypatch.setattr(kls, "find_executable", lambda cmd: None)
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is False

    def test_present_binary(self, tree, tmp_path, on_path):
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is True

    def test_scan_with_the_tool_absent_does_not_run_it(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(kls, "find_executable", lambda cmd: None)
        fake = FakeKubeLinter()
        result = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert result is False
        assert fake.calls == []


class TestInstall:
    def test_no_platform_carries_an_empty_command_list(self, tree, tmp_path):
        """An empty command list would read as installable while installing nothing."""
        scanner = _scanner(tree, tmp_path)
        assert scanner.custom_install_commands
        for platform, arches in scanner.custom_install_commands.items():
            for arch, commands in arches.items():
                assert commands, (platform, arch)

    def test_install_commands_cover_every_pinned_platform(self, tree, tmp_path):
        from automated_security_helper.utils.tool_downloads import supported_platforms

        published = supported_platforms(kls.KUBE_LINTER_TOOL_NAME)
        assert len(published) == 6, published
        table = _scanner(tree, tmp_path).custom_install_commands
        for platform, arch in published:
            assert table[platform][arch], (platform, arch)

    def test_the_pin_is_the_release_the_plugin_was_written_against(self):
        from automated_security_helper.utils.tool_downloads import TOOL_VERSIONS

        assert TOOL_VERSIONS[kls.KUBE_LINTER_TOOL_NAME] == kls.PINNED_VERSION

    def test_construction_survives_a_table_without_the_pin(
        self, tree, tmp_path, monkeypatch
    ):
        """A pin missing from tool_downloads must not make the scanner unbuildable,
        and must leave the install table empty rather than half filled."""
        from automated_security_helper.core.exceptions import (
            ToolNotProvisionableError,
        )

        def refuse(tool):
            raise ToolNotProvisionableError(f"{tool} has no release-asset table")

        monkeypatch.setattr(kls, "pinned_tool_install_commands", refuse)
        assert _scanner(tree, tmp_path).custom_install_commands == {}

    def test_the_install_hint_names_the_pinned_install(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(kls, "find_executable", lambda cmd: None)
        messages = []
        monkeypatch.setattr(
            kls.ASH_LOGGER, "warning", lambda msg, *a, **k: messages.append(msg)
        )
        _scanner(tree, tmp_path).validate_plugin_dependencies()
        assert messages and "ash dependencies install" in messages[0]
        assert "--tool kube-linter" in messages[0]
        assert "ash_kube_linter_plugins" in messages[0]
        assert kls.PINNED_VERSION in messages[0]

    def test_without_the_pin_the_hint_names_no_command_that_cannot_work(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(kls, "find_executable", lambda cmd: None)
        monkeypatch.setattr(kls, "downloadable_tools", list)
        messages = []
        monkeypatch.setattr(
            kls.ASH_LOGGER, "warning", lambda msg, *a, **k: messages.append(msg)
        )
        _scanner(tree, tmp_path).validate_plugin_dependencies()
        assert messages and "ash dependencies install" not in messages[0]
        assert kls.PINNED_VERSION in messages[0]


class TestCapturedFixture:
    """The same checks over the files a real kube-linter 0.8.3 run wrote.

    ``captured/README.md`` records the argv, the version and the inputs; the tests below
    pin what that README says about the files.
    """

    #: ruleId, SARIF level, ASH severity, uri, line: every result the real run reported
    #: for ``captured/positive/deployment.yaml`` (a privileged Deployment, no requests).
    CAPTURED_EXPECTED = [
        ("no-read-only-root-fs", "warning", "MEDIUM", "positive/deployment.yaml", 1),
        (
            "privilege-escalation-container",
            "error",
            "HIGH",
            "positive/deployment.yaml",
            1,
        ),
        ("privileged-container", "error", "HIGH", "positive/deployment.yaml", 1),
        ("run-as-non-root", "warning", "MEDIUM", "positive/deployment.yaml", 1),
        ("unset-cpu-requirements", "warning", "MEDIUM", "positive/deployment.yaml", 1),
        (
            "unset-memory-requirements",
            "warning",
            "MEDIUM",
            "positive/deployment.yaml",
            1,
        ),
    ]

    def test_the_positive_file_is_rated_and_located(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        fake = FakeKubeLinter(
            sarif_text=_CAPTURED.joinpath("positive.sarif").read_text()
        )
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert _findings(report) == self.CAPTURED_EXPECTED

    def test_the_negative_file_has_no_findings(
        self, tree, tmp_path, monkeypatch, on_path
    ):
        fake = FakeKubeLinter(
            sarif_text=_CAPTURED.joinpath("negative.sarif").read_text(), exit_code=0
        )
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert _findings(report) == []

    def test_every_high_check_in_the_capture_is_in_the_table(self):
        captured = json.loads(_CAPTURED.joinpath("positive.sarif").read_text())
        rated_high = {
            r["ruleId"]
            for r in captured["runs"][0]["results"]
            if severity_for_check(r["ruleId"])[0] == "HIGH"
        }
        assert rated_high == {"privilege-escalation-container", "privileged-container"}
        assert rated_high <= HIGH_SEVERITY_CHECKS

    def test_every_default_check_is_rated_by_the_table(self):
        """The 31 checks the capture's driver lists: none is unrated, none is CRITICAL."""
        captured = json.loads(_CAPTURED.joinpath("negative.sarif").read_text())
        rules = {r["id"] for r in captured["runs"][0]["tool"]["driver"]["rules"]}
        assert len(rules) == 31
        # The HIGH entries the default checks do not include never fire under ASH's stub
        # config; the docs and the module docstring say so, and this pins the set.
        assert HIGH_SEVERITY_CHECKS - rules == {
            "access-to-create-pods",
            "access-to-secrets",
            "cluster-admin-role-binding",
            "privileged-ports",
            "wildcard-in-rules",
        }
        for rule in rules:
            assert severity_for_check(rule)[0] in {"HIGH", "MEDIUM"}

    def test_the_result_shape_the_adapter_relies_on(self):
        """What the capture shows: no level, no fingerprint, line 1, a relative uri."""
        results = json.loads(_CAPTURED.joinpath("positive.sarif").read_text())["runs"][
            0
        ]["results"]
        assert results
        for result in results:
            assert set(result) == {"ruleId", "ruleIndex", "message", "locations"}
            region = result["locations"][0]["physicalLocation"]["region"]
            assert region == {"startLine": 1}
            uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            assert not uri.startswith("/")
            assert (
                "\nobject: shop/demo apps/v1, Kind=Deployment"
                in result["message"]["text"]
            )

    def test_the_readme_names_the_tool_version_argv_and_inputs(self):
        readme = _CAPTURED.joinpath("README.md").read_text()
        assert "kube-linter 0.8.3" in readme
        assert "--format=sarif --output=" in readme
        for name in ("positive/deployment.yaml", "negative/configmap.yaml"):
            assert name in readme
            assert _CAPTURED.joinpath(name).is_file()
        assert _CAPTURED.joinpath("empty-config.yaml").read_text().strip() == "{}"


class TestSandboxRequirements:
    def test_the_strict_default_is_declared(self):
        from automated_security_helper.utils.sandbox.policy import SandboxRequirements

        assert KubeLinterScanner.sandbox_requirements == SandboxRequirements()
        assert KubeLinterScanner.sandbox_requirements.network is False


class TestFacets:
    def test_the_scanner_declares_its_own_facets(self):
        from automated_security_helper.base.scanner_facets import (
            SCANNER_FACETS_ATTR,
            FacetState,
            ScannerFacets,
        )

        declared = vars(KubeLinterScanner).get(SCANNER_FACETS_ATTR)
        assert isinstance(declared, ScannerFacets)
        # Fail closed: no resource identity is claimed from message prose.
        assert declared.resource_id.state is FacetState.NA
        assert declared.resource_type.state is FacetState.NA

    def test_the_severity_cell_names_the_table_not_a_native_level(self):
        assert "HIGH_SEVERITY_CHECKS" in KubeLinterScanner.facets.severity.native_field

    def test_the_adapter_never_writes_a_resource_id(self):
        source = Path(kls.__file__).read_text(encoding="utf-8")
        assert "ash_resource_id" not in source
