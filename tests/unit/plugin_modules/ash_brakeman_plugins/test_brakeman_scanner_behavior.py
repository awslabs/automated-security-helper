# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""BrakemanScanner: argv, exit status, severity mapping and failure handling.

POSITIVE_CAPTURE and NEGATIVE_CAPTURE are the committed captures under
``tests/test_data/scanners/brakeman/captured/`` (see its README): what Brakeman 8.1.1
wrote for the argv in ``test_every_fixed_flag_and_the_scan_path``, run in a directory
whose ``app/controllers/users_controller.rb`` interpolates ``params`` into a SQL string
(line 3), into ``system`` (line 7) and into ``redirect_to`` (line 8), and in one whose
controller does none of these. The scan() tests replace the subprocess with a fake that
serves them, so they run on every platform without Ruby or the gem.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_brakeman_plugins
from automated_security_helper.plugin_modules.ash_brakeman_plugins import (
    brakeman_scanner as bs,
)
from automated_security_helper.plugin_modules.ash_brakeman_plugins.brakeman_scanner import (
    BrakemanScanner,
    BrakemanScannerConfig,
    BrakemanScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.config_trust import record_provenance
from automated_security_helper.utils.sandbox.policy import SandboxRequirements

pytestmark = pytest.mark.unit

CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "brakeman"
    / "captured"
)


def _capture(name: str) -> Dict[str, Any]:
    return json.loads((CAPTURED / name).read_text(encoding="utf-8"))


POSITIVE_CAPTURE = _capture("positive.sarif")
NEGATIVE_CAPTURE = _capture("negative.sarif")

#: What POSITIVE_CAPTURE must produce: (ruleId, SARIF level, ASH severity, uri, line).
#: Written out by hand from the capture, not derived from the code under test.
POSITIVE_EXPECTED = [
    ("BRAKE0014", "error", "HIGH", "app/controllers/users_controller.rb", 7),
    ("BRAKE0018", "error", "HIGH", "app/controllers/users_controller.rb", 8),
    ("BRAKE0000", "warning", "MEDIUM", "app/controllers/users_controller.rb", 3),
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


def _with_levels(*levels: Optional[str]) -> Dict[str, Any]:
    """The positive capture with each result's level replaced (None removes it)."""
    document = copy.deepcopy(POSITIVE_CAPTURE)
    results = document["runs"][0]["results"]
    for result, level in zip(results, levels):
        if level is None:
            result.pop("level", None)
        else:
            result["level"] = level
    return document


class FakeBrakeman:
    """Stands in for _run_subprocess: records argv, writes the report where it says."""

    def __init__(
        self,
        report: Any = POSITIVE_CAPTURE,
        exit_code: int = 3,
        stderr: str = "",
        timed_out: bool = False,
        write_report: bool = True,
        raw: Optional[str] = None,
    ):
        self.report, self.exit_code, self.stderr = report, exit_code, stderr
        self.timed_out, self.write_report, self.raw = timed_out, write_report, raw
        self.calls: List[dict] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            call = {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            for token in command:
                # The stubs are removed when the run ends: read them now.
                if token.startswith("--config-file="):
                    call["config_text"] = Path(token.split("=", 1)[1]).read_text()
                if token.startswith("--ignore-config="):
                    call["ignore_text"] = Path(token.split("=", 1)[1]).read_text()
            self.calls.append(call)
            if self.timed_out:
                scanner.exit_code = -9
                return {"timed_out": True}
            scanner.exit_code = self.exit_code
            if self.write_report:
                output = next(
                    Path(t.split("=", 1)[1])
                    for t in command
                    if t.startswith("--output=")
                )
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_text(
                    self.raw if self.raw is not None else json.dumps(self.report)
                )
            return {"returncode": self.exit_code, "stdout": "", "stderr": self.stderr}

        return run


def _scanner(source: Path, tmp_path: Path, **options) -> BrakemanScanner:
    config = get_default_config()
    record_provenance(config, in_tree=[], trusted=AshConfig())
    return BrakemanScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "out" / "converted",
            config=config,
        ),
        config=BrakemanScannerConfig(
            enabled=True, options=BrakemanScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "app" / "controllers").mkdir(parents=True)
    (src / "app" / "controllers" / "users_controller.rb").write_text(
        "class UsersController < ApplicationController\nend\n"
    )
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(bs, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner: BrakemanScanner, fake: FakeBrakeman, monkeypatch, **kw):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(scanner.context.source_dir), target_type="source", **kw
    )


class TestCommunityPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert BrakemanScannerConfig().enabled is True
        assert BrakemanScannerConfig().name == "brakeman"

    def test_the_module_exports_the_scanner(self):
        assert ash_brakeman_plugins.ASH_SCANNERS == [BrakemanScanner]
        assert ash_brakeman_plugins.ASH_REPORTERS == []

    def test_the_scanner_declares_how_it_runs(self):
        assert BrakemanScanner.python_only is False
        assert BrakemanScanner.success_exit_codes == {0, 3, 4}
        assert BrakemanScanner.sandbox_requirements == SandboxRequirements()

    def test_the_sandbox_policy_is_the_strict_default_field_by_field(self):
        """Brakeman reads the scan tree and its own gem; it needs no network, no
        extra path and no extra environment variable under the sandbox."""
        requirements = BrakemanScanner.sandbox_requirements
        assert requirements.network is False
        assert requirements.network_requires_grant is False
        assert not requirements.read_paths
        assert not requirements.cache_paths
        assert not requirements.env_prefixes
        assert not requirements.env_names

    def test_the_committed_captures_are_what_the_tests_serve(self):
        """The captured directory is the corpus: results in the positive one, none in
        the negative one, and the version the README names."""
        for name in ("positive.sarif", "negative.sarif"):
            run = _capture(name)["runs"][0]
            assert run["tool"]["driver"]["name"] == "Brakeman"
            assert run["tool"]["driver"]["semanticVersion"] == "8.1.1"
        assert len(POSITIVE_CAPTURE["runs"][0]["results"]) == 3
        assert NEGATIVE_CAPTURE["runs"][0]["results"] == []

    def test_there_are_no_options_beyond_the_base_ones(self):
        assert set(BrakemanScannerConfigOptions.model_fields) == set(
            ScannerOptionsBase.model_fields
        )


class TestLicenseGate:
    """Brakeman is free for non-commercial use only, so ASH never installs it."""

    def test_ash_ships_no_install_command(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path)
        assert not scanner.custom_install_commands

    def test_missing_binary_is_reported_as_unsatisfied_dependencies(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(bs, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        fake = FakeBrakeman()
        assert _run(scanner, fake, monkeypatch) is False
        assert scanner.dependencies_satisfied is False
        assert fake.calls == []

    def test_the_missing_message_names_the_license_and_the_install(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(bs, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is False
        message = scanner.missing_dependency_reason()
        assert "non-commercial" in message
        assert "gem install brakeman" in message

    def test_a_present_binary_passes_the_check(self, tree, tmp_path, on_path):
        assert _scanner(tree, tmp_path).validate_plugin_dependencies() is True

    def test_a_recorded_unavailable_reason_fails_the_check(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path)
        scanner.dependency_unavailable_reason = "refused"
        assert scanner.validate_plugin_dependencies() is False
        assert scanner.missing_dependency_reason() == "refused"


class TestInvocation:
    def test_every_fixed_flag_and_the_scan_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeBrakeman()
        _run(scanner, fake, monkeypatch)
        argv = fake.calls[0]["argv"]
        assert argv[0] == "brakeman"
        assert argv[1:4] == ["--format=sarif", argv[2], "--no-pager"]
        assert argv[2].startswith("--output=")
        assert argv[2].endswith("/source/brakeman.sarif")
        assert argv[4:6] == ["--quiet", "--no-progress"]
        assert argv[6].startswith("--config-file=")
        assert argv[7].startswith("--ignore-config=")
        assert argv[8:] == ["--path=."]

    def test_the_tree_configuration_is_replaced_by_empty_files_outside_the_tree(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeBrakeman()
        _run(scanner, fake, monkeypatch)
        call = fake.calls[0]
        assert call["config_text"].strip() == "{}"
        assert json.loads(call["ignore_text"])["ignored_warnings"] == []
        for token in call["argv"]:
            if token.startswith(("--config-file=", "--ignore-config=")):
                stub = Path(token.split("=", 1)[1]).resolve()
                assert not stub.is_relative_to(tree.resolve())

    @pytest.mark.parametrize(
        "flag",
        [
            "--force",
            "--force-scan",
            "--allow-check-paths-in-config",
            "--github-repo",
            "--compare",
            "--absolute-paths",
            "--ensure-latest",
            "--create-config",
            "--no-exit-on-warn",
        ],
    )
    def test_flags_that_read_the_tree_or_reach_the_network_are_never_passed(
        self, flag, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeBrakeman()
        _run(scanner, fake, monkeypatch)
        assert not [t for t in fake.calls[0]["argv"] if t.split("=")[0] == flag]

    def test_a_converted_target_is_passed_as_an_absolute_path(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        converted = tmp_path / "converted"
        (converted / "app").mkdir(parents=True)
        (converted / "app" / "x.rb").write_text("x = 1\n")
        scanner = _scanner(tree, tmp_path)
        fake = FakeBrakeman()
        monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
        scanner.scan(target=converted, target_type="converted")
        assert fake.calls[0]["argv"][-1] == f"--path={converted.absolute().as_posix()}"
        assert fake.calls[0]["argv"][2].endswith("/converted/brakeman.sarif")

    def test_a_missing_target_never_reaches_the_tool(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeBrakeman()
        monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
        scanner.scan(target=tmp_path / "absent", target_type="source")
        assert fake.calls == []


class TestReport:
    def test_positive_capture_is_rated_and_located(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakeBrakeman(), monkeypatch)
        assert isinstance(report, SarifReport)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_negative_control_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeBrakeman(report=NEGATIVE_CAPTURE, exit_code=0)
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert isinstance(report, SarifReport)
        assert report.get_all_results() == []

    def test_results_are_failures_and_tagged_security(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakeBrakeman(), monkeypatch)
        for result in report.get_all_results():
            assert getattr(result.kind, "value", result.kind) == "fail"
            assert "security" in result.properties.tags

    @pytest.mark.parametrize(
        "level, severity",
        [("error", "HIGH"), ("warning", "MEDIUM"), ("note", "LOW")],
    )
    def test_each_level_maps_to_one_severity(
        self, level, severity, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeBrakeman(report=_with_levels(level, level, level))
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert {f[1:3] for f in _findings(report)} == {(level, severity)}

    def test_a_result_without_a_level_is_medium_and_warning(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeBrakeman(report=_with_levels(None, "none", "warning"))
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert {f[1:3] for f in _findings(report)} == {("warning", "MEDIUM")}

    def test_a_mixed_report_keeps_level_and_severity_in_step(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeBrakeman(report=_with_levels("note", None, "error"))
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert [f[1:3] for f in _findings(report)] == [
            ("note", "LOW"),
            ("warning", "MEDIUM"),
            ("error", "HIGH"),
        ]

    def test_the_report_round_trips_as_sarif(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path), FakeBrakeman(), monkeypatch)
        again = SarifReport.model_validate(
            json.loads(report.model_dump_json(by_alias=True, exclude_none=True))
        )
        assert _findings(again) == POSITIVE_EXPECTED


class TestNoRailsApplication:
    def test_exit_4_with_no_report_is_a_clean_no_op(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeBrakeman(
            exit_code=4,
            write_report=False,
            stderr="Please supply the path to a Rails application",
        )
        report = _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert isinstance(report, SarifReport)
        assert report.get_all_results() == []
        assert len(report.runs) == 1

    def test_the_no_op_does_not_leak_stderr_into_the_errors(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeBrakeman(exit_code=4, write_report=False, stderr="NOISE-IN-STDERR")
        _run(scanner, fake, monkeypatch)
        assert not any("NOISE-IN-STDERR" in line for line in scanner.errors)


class TestExitStatus:
    @pytest.mark.parametrize("code", [0, 3])
    def test_clean_and_warnings_found_succeed(
        self, code, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeBrakeman(report=NEGATIVE_CAPTURE, exit_code=code)
        assert isinstance(
            _run(_scanner(tree, tmp_path), fake, monkeypatch), SarifReport
        )

    @pytest.mark.parametrize("code", [1, 2, 5, 6, 7, 8, 9, 126, 255])
    def test_every_other_code_fails_even_with_a_report_on_disk(
        self, code, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeBrakeman(exit_code=code)
        with pytest.raises(ScannerError, match=f"exited with code {code}"):
            _run(_scanner(tree, tmp_path), fake, monkeypatch)

    def test_a_run_that_wrote_no_report_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeBrakeman(exit_code=0, write_report=False)
        with pytest.raises(ScannerError):
            _run(_scanner(tree, tmp_path), fake, monkeypatch)

    def test_a_report_left_by_an_earlier_run_is_not_read_as_this_runs(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        _run(_scanner(tree, tmp_path), FakeBrakeman(), monkeypatch)
        again = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(again, FakeBrakeman(exit_code=3, write_report=False), monkeypatch)

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=5)
        fake = FakeBrakeman(timed_out=True)
        with pytest.raises(ScannerError, match=r"timed out after '?5'? s"):
            _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 5

    def test_stderr_is_not_copied_into_the_errors_or_the_failure_message(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeBrakeman(exit_code=7, stderr="QUOTED-SOURCE-LINE-xyzzy")
        with pytest.raises(ScannerError) as raised:
            _run(scanner, fake, monkeypatch)
        assert "QUOTED-SOURCE-LINE-xyzzy" not in str(raised.value)
        assert not any("QUOTED-SOURCE-LINE-xyzzy" in line for line in scanner.errors)
        assert "not quoted" in str(raised.value)


class TestMalformedOutput:
    @pytest.mark.parametrize(
        "raw",
        [
            "not json at all",
            "{",
            "[]",
            '"a string"',
            "{}",
            '{"version": "2.1.0", "runs": []}',
            '{"version": "2.1.0", "runs": "nope"}',
        ],
    )
    def test_a_report_that_is_not_sarif_fails_the_scan(
        self, raw, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeBrakeman(raw=raw, exit_code=3)
        with pytest.raises(ScannerError):
            _run(_scanner(tree, tmp_path), fake, monkeypatch)

    def test_an_empty_report_file_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeBrakeman(raw="", exit_code=0)
        with pytest.raises(ScannerError):
            _run(_scanner(tree, tmp_path), fake, monkeypatch)


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
class TestLinksLeavingTheTree:
    """Brakeman 8.1.1 reads a symlinked file that points outside the app (measured),
    so each such link goes in ``--skip-files`` and a link that cannot be named alone
    refuses the scan. The value is matched as ``<escaped>\\z`` against
    ``/<path below the root>`` with no anchor at the start (AppTree.regex_for_paths).
    """

    def _link(self, tree: Path, tmp_path: Path, relative: str) -> None:
        outside = tmp_path / "outside" / "secret.rb"
        outside.parent.mkdir(exist_ok=True)
        outside.write_text("x = 1\n")
        link = tree / relative
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(outside)

    def _skip(self, argv: List[str]) -> List[str]:
        return [t for t in argv if t.startswith("--skip-files=")]

    def test_a_link_leaving_the_tree_is_named_in_skip_files(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        self._link(tree, tmp_path, "app/controllers/link_out.rb")
        fake = FakeBrakeman()
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        argv = fake.calls[0]["argv"]
        assert self._skip(argv) == ["--skip-files=/app/controllers/link_out.rb"]
        assert argv[-1] == "--path=."

    def test_every_link_is_named_in_one_value(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        self._link(tree, tmp_path, "app/controllers/link_a.rb")
        self._link(tree, tmp_path, "app/models/link_b.rb")
        fake = FakeBrakeman()
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        value = self._skip(fake.calls[0]["argv"])[0].split("=", 1)[1]
        assert sorted(value.split(",")) == [
            "/app/controllers/link_a.rb",
            "/app/models/link_b.rb",
        ]

    def test_a_link_that_stays_inside_the_tree_is_not_named(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / "app" / "controllers" / "inside.rb").symlink_to(
            tree / "app" / "controllers" / "users_controller.rb"
        )
        fake = FakeBrakeman()
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert self._skip(fake.calls[0]["argv"]) == []

    def test_a_tree_with_no_link_gets_no_skip_files(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        fake = FakeBrakeman()
        _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert self._skip(fake.calls[0]["argv"]) == []

    def test_a_link_whose_path_another_file_ends_with_refuses_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        # "/app/x.rb" would also skip "vendor/app/x.rb".
        self._link(tree, tmp_path, "app/x.rb")
        (tree / "vendor" / "app").mkdir(parents=True)
        (tree / "vendor" / "app" / "x.rb").write_text("y = 2\n")
        fake = FakeBrakeman()
        with pytest.raises(ScannerError, match="app/x.rb"):
            _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert fake.calls == []

    def test_a_link_with_a_comma_refuses_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        self._link(tree, tmp_path, "app/a,b.rb")
        fake = FakeBrakeman()
        with pytest.raises(ScannerError, match="a,b.rb"):
            _run(_scanner(tree, tmp_path), fake, monkeypatch)
        assert fake.calls == []
