# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""DockleScanner: the gate, the argv, severity mapping and failure handling.

Most tests use a report built by hand from what Dockle's SARIF writer is documented
to emit (pkg/report/sarif.go and writer.go in goodwithtech/dockle: ``ruleId``, a
``level`` of error, warning, note or none, ``message.text`` and one location). The
subprocess is replaced by a fake that writes the report where the argv says, so those
tests run on every platform without the binary. ``TestCapturedReports`` runs the same
severity mapping over REAL Dockle 0.4.15 reports committed under
``tests/test_data/scanners/dockle/captured/`` (see its README). ``TestImageScan``
drives the image dispatch (``scan_image``) the same way, with the image asset's
locator in place of the operator's options.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.asset import ImageLocator
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules import ash_dockle_plugins
from automated_security_helper.plugin_modules.ash_dockle_plugins import (
    dockle_scanner as ds,
)
from automated_security_helper.plugin_modules.ash_dockle_plugins.dockle_scanner import (
    DockleScanner,
    DockleScannerConfig,
    DockleScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.config_trust import record_provenance

pytestmark = pytest.mark.unit

IMAGE = "registry.example.com/team/app:1.2.3"


def _result(rule: str, level: Optional[str], text: str, uri: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "ruleId": rule,
        "message": {"text": text},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
    }
    if level is not None:
        result["level"] = level
    return result


def _report(results: List[Dict[str, Any]]) -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Dockle",
                            "informationUri": "https://github.com/goodwithtech/dockle",
                        }
                    },
                    "results": results,
                }
            ],
        }
    )


#: What the table in the module docstring says each Dockle level becomes.
FINDINGS = [
    # rule, SARIF level written by Dockle, expected ASH severity
    ("CIS-DI-0009", "error", "HIGH"),
    ("CIS-DI-0001", "warning", "MEDIUM"),
    ("CIS-DI-0005", "note", "LOW"),
    ("DKL-DI-0006", "none", "INFO"),
]
POSITIVE = _report(
    [_result(rule, level, f"alert for {rule}", IMAGE) for rule, level, _ in FINDINGS]
)
NEGATIVE = _report([])


class FakeDockle:
    """Stands in for _run_subprocess: records argv, writes a report."""

    def __init__(
        self,
        report: Optional[str] = POSITIVE,
        exit_code: int = 0,
        stderr: str = "",
        timed_out: bool = False,
    ):
        self.report, self.exit_code, self.stderr = report, exit_code, stderr
        self.timed_out = timed_out
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            self.calls.append(
                {"argv": list(command), "env": env, "timeout": timeout, "cwd": cwd}
            )
            if self.timed_out:
                scanner.exit_code = -9
                return {"timed_out": True}
            output = next(a for a in command if a.startswith("--output="))
            path = Path(output.split("=", 1)[1])
            if self.report is not None:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(self.report, encoding="utf-8")
            scanner.exit_code = self.exit_code
            return {"returncode": self.exit_code, "stdout": "", "stderr": self.stderr}

        return run

    @property
    def argv(self) -> List[str]:
        return self.calls[0]["argv"]


def _scanner(
    source: Path, tmp_path: Path, *, operator: bool = True, **options
) -> DockleScanner:
    """``operator``: the options came from the operator, or from the scanned tree."""
    config = get_default_config()
    record_provenance(
        config,
        in_tree=[] if operator else [source / ".ash" / ".ash.yaml"],
        trusted=AshConfig(),
    )
    return DockleScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "out" / "converted",
            config=config,
        ),
        config=DockleScannerConfig(
            enabled=True, options=DockleScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    src.mkdir()
    (src / "Dockerfile").write_text("FROM alpine:3.20\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(ds, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner, fake, monkeypatch, target_type: str = "source"):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(scanner.context.source_dir), target_type=target_type
    )


def _findings(report: SarifReport) -> List[tuple]:
    return [
        (
            r.ruleId,
            getattr(r.level, "value", r.level),
            getattr(r.properties, "issue_severity", None),
        )
        for r in report.get_all_results()
    ]


class TestAlphaPlugin:
    def test_the_module_exports_the_scanner(self):
        assert ash_dockle_plugins.ASH_SCANNERS == [DockleScanner]
        assert ash_dockle_plugins.ASH_REPORTERS == []

    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert DockleScannerConfig().enabled is True
        assert DockleScannerConfig().name == "dockle"

    def test_declared_class_attributes(self):
        assert DockleScanner.success_exit_codes == {0}
        assert DockleScanner.python_only is False
        assert DockleScanner.sandbox_requirements.network_requires_grant is True


class TestGate:
    def test_no_image_is_a_clean_skip_and_dockle_never_starts(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeDockle()
        assert _run(scanner, fake, monkeypatch) is True
        assert fake.calls == []
        assert "needs a container image" in scanner._nothing_scanned_reason

    def test_the_converted_target_is_not_scanned_again(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, image=IMAGE)
        fake = FakeDockle()
        assert _run(scanner, fake, monkeypatch, target_type="converted") is True
        assert fake.calls == []

    def test_an_image_set_by_the_scanned_tree_is_ignored(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, operator=False, image=IMAGE)
        fake = FakeDockle()
        assert _run(scanner, fake, monkeypatch) is True
        assert fake.calls == []

    @pytest.mark.parametrize("bad", ["-v", "--debug", "a b", "img;rm", ""])
    def test_a_name_that_is_not_an_image_reference_is_never_run(
        self, bad, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, image=bad)
        fake = FakeDockle()
        if bad == "":
            # An empty name is the same as no name: the gate skips.
            assert _run(scanner, fake, monkeypatch) is True
        else:
            with pytest.raises(ScannerError, match="not an image reference"):
                _run(scanner, fake, monkeypatch)
        assert fake.calls == []

    def test_both_an_image_and_a_tarball_fail_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        tarball = tmp_path / "image.tar"
        tarball.write_bytes(b"x")
        scanner = _scanner(tree, tmp_path, image=IMAGE, image_tarball=tarball)
        fake = FakeDockle()
        with pytest.raises(ScannerError, match="both set"):
            _run(scanner, fake, monkeypatch)
        assert fake.calls == []

    def test_a_tarball_that_is_not_a_file_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, image_tarball=tmp_path / "missing.tar")
        fake = FakeDockle()
        with pytest.raises(ScannerError, match="not a file"):
            _run(scanner, fake, monkeypatch)
        assert fake.calls == []


class TestInvocation:
    def test_every_fixed_flag_and_the_image_after_double_dash(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, image=IMAGE)
        fake = FakeDockle()
        _run(scanner, fake, monkeypatch)
        argv = fake.argv
        assert argv[0] == "dockle"
        assert "--format=sarif" in argv
        assert "--no-color" in argv
        output = next(a for a in argv if a.startswith("--output="))
        assert output.endswith("/source/dockle.sarif")
        assert argv[-2:] == ["--", IMAGE]
        # Every option before the image is one --flag or --flag=value token.
        assert all(a.startswith("--") for a in argv[1:-2])

    def test_a_tarball_is_passed_with_input_and_no_image(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        tarball = tmp_path / "image.tar"
        tarball.write_bytes(b"x")
        scanner = _scanner(tree, tmp_path, image_tarball=tarball)
        fake = FakeDockle()
        _run(scanner, fake, monkeypatch)
        assert f"--input={tarball.resolve().as_posix()}" in fake.argv
        assert "--" not in fake.argv

    @pytest.mark.parametrize(
        "flag",
        [
            "--exit-code",
            "-c",
            "--ignore",
            "-i",
            "--accept-key",
            "--sensitive-file",
            "--username",
            "--password",
            "--insecure",
            "--host",
        ],
    )
    def test_flags_that_change_what_is_reported_or_carry_credentials_are_never_passed(
        self, flag, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, image=IMAGE)
        fake = FakeDockle()
        _run(scanner, fake, monkeypatch)
        assert not any(a == flag or a.startswith(flag + "=") for a in fake.argv)

    def test_the_working_directory_is_not_the_scanned_tree(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, image=IMAGE)
        fake = FakeDockle()
        _run(scanner, fake, monkeypatch)
        cwd = Path(fake.calls[0]["cwd"])
        assert cwd != tree and tree not in cwd.parents

    def test_a_report_left_by_an_earlier_run_is_removed_first(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, image=IMAGE)
        _run(scanner, FakeDockle(report=POSITIVE), monkeypatch)
        # The second run writes nothing: the first run's report must not be read.
        with pytest.raises(ScannerError):
            _run(scanner, FakeDockle(report=None), monkeypatch)


class TestReport:
    def test_findings_are_rated_row_by_row_and_the_level_agrees(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, image=IMAGE)
        report = _run(scanner, FakeDockle(), monkeypatch)
        assert isinstance(report, SarifReport)
        assert _findings(report) == [
            ("CIS-DI-0009", "error", "HIGH"),
            ("CIS-DI-0001", "warning", "MEDIUM"),
            ("CIS-DI-0005", "note", "LOW"),
            ("DKL-DI-0006", "none", "INFO"),
        ]

    def test_negative_control_a_clean_image_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, image=IMAGE)
        report = _run(scanner, FakeDockle(report=NEGATIVE), monkeypatch)
        assert isinstance(report, SarifReport)
        assert report.get_all_results() == []

    def test_a_result_without_a_level_is_medium(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        text = _report([_result("CIS-DI-0001", None, "x", IMAGE)])
        report = _run(
            _scanner(tree, tmp_path, image=IMAGE), FakeDockle(report=text), monkeypatch
        )
        assert _findings(report) == [("CIS-DI-0001", "warning", "MEDIUM")]

    def test_every_rated_finding_carries_the_container_tags(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(_scanner(tree, tmp_path, image=IMAGE), FakeDockle(), monkeypatch)
        for result in report.get_all_results():
            assert {"container-image", "security"} <= set(result.properties.tags)

    def test_the_sarif_round_trips(self, tree, tmp_path, on_path, monkeypatch):
        report = _run(_scanner(tree, tmp_path, image=IMAGE), FakeDockle(), monkeypatch)
        again = SarifReport.model_validate(json.loads(report.model_dump_json()))
        assert _findings(again) == _findings(report)


_CAPTURED = Path(__file__).resolve().parents[3] / "test_data/scanners/dockle/captured"


class TestCapturedReports:
    """The severity mapping over what Dockle 0.4.15 actually wrote."""

    def test_the_positive_capture_covers_all_four_levels(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        text = (_CAPTURED / "positive.sarif").read_text(encoding="utf-8")
        report = _run(
            _scanner(tree, tmp_path, image=IMAGE),
            FakeDockle(report=text),
            monkeypatch,
        )
        assert isinstance(report, SarifReport)
        assert sorted(_findings(report)) == sorted(
            [
                ("CIS-DI-0010", "error", "HIGH"),
                ("DKL-LI-0001", "error", "HIGH"),
                ("CIS-DI-0001", "warning", "MEDIUM"),
                ("CIS-DI-0005", "note", "LOW"),
                ("CIS-DI-0006", "note", "LOW"),
                ("DKL-LI-0002", "none", "INFO"),
            ]
        )

    def test_negative_control_the_clean_capture_has_no_error_or_warning(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        text = (_CAPTURED / "negative.sarif").read_text(encoding="utf-8")
        report = _run(
            _scanner(tree, tmp_path, image=IMAGE),
            FakeDockle(report=text),
            monkeypatch,
        )
        severities = {severity for _, _, severity in _findings(report)}
        assert severities == {"LOW", "INFO"}
        assert len(_findings(report)) == 4

    def test_the_captures_are_dockle_sarif(self):
        for name in ("positive", "negative"):
            document = json.loads((_CAPTURED / f"{name}.sarif").read_text("utf-8"))
            assert document["version"] == "2.1.0"
            assert document["runs"][0]["tool"]["driver"]["name"] == "Dockle"


class TestExitStatus:
    @pytest.mark.parametrize("code", [1, 2, 126, 137])
    def test_a_non_zero_exit_fails_the_scan_even_with_findings_on_disk(
        self, code, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, image=IMAGE)
        with pytest.raises(ScannerError, match="this run failed|exit code"):
            _run(scanner, FakeDockle(report=POSITIVE, exit_code=code), monkeypatch)

    def test_exit_zero_with_findings_succeeds(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        report = _run(
            _scanner(tree, tmp_path, image=IMAGE),
            FakeDockle(report=POSITIVE, exit_code=0),
            monkeypatch,
        )
        assert len(report.get_all_results()) == 4

    def test_a_run_that_wrote_no_report_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        with pytest.raises(ScannerError):
            _run(
                _scanner(tree, tmp_path, image=IMAGE),
                FakeDockle(report=None),
                monkeypatch,
            )

    def test_stderr_is_not_copied_into_the_errors(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, image=IMAGE)
        _run(
            scanner,
            FakeDockle(stderr="FATAL pull of secret-registry.internal denied"),
            monkeypatch,
        )
        assert not any("secret-registry" in line for line in scanner.errors)

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, image=IMAGE, scan_timeout=5)
        fake = FakeDockle(timed_out=True)
        with pytest.raises(ScannerError, match=r"timed out after '5' s"):
            _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 5


class TestMalformedOutput:
    @pytest.mark.parametrize(
        "text",
        [
            "this is not json",
            "{",
            "[]",
            "{}",
            json.dumps({"version": "2.1.0", "runs": []}),
            json.dumps({"runs": [{"tool": "not an object"}]}),
        ],
    )
    def test_a_report_that_is_not_a_sarif_run_fails_the_scan(
        self, text, tree, tmp_path, on_path, monkeypatch
    ):
        with pytest.raises(ScannerError):
            _run(
                _scanner(tree, tmp_path, image=IMAGE),
                FakeDockle(report=text),
                monkeypatch,
            )


class TestDependencyCheck:
    def test_missing_binary_is_reported_as_unsatisfied_dependencies(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(ds, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path, image=IMAGE)
        fake = FakeDockle()
        assert _run(scanner, fake, monkeypatch) is False
        assert scanner.dependencies_satisfied is False
        assert fake.calls == []

    def test_present_binary_satisfies_the_check(self, tree, tmp_path, on_path):
        assert _scanner(tree, tmp_path, image=IMAGE).validate_plugin_dependencies()

    def test_an_unavailable_reason_wins_over_a_binary_on_path(
        self, tree, tmp_path, on_path
    ):
        scanner = _scanner(tree, tmp_path, image=IMAGE)
        scanner.dependency_unavailable_reason = "refused"
        assert scanner.validate_plugin_dependencies() is False


class TestInstall:
    def test_install_commands_cover_every_published_platform(self, tree, tmp_path):
        # The pin lives in the shared table; fail closed if its row goes missing,
        # rather than finding no platform to check and passing.
        from automated_security_helper.utils.tool_downloads import (
            downloadable_tools,
            supported_platforms,
        )

        assert "dockle" in downloadable_tools()
        scanner = _scanner(tree, tmp_path, image=IMAGE)
        platforms = supported_platforms("dockle")
        assert platforms, "the dockle table lists no platform"
        for platform, arch in platforms:
            commands = scanner.get_installation_commands(platform, arch)
            assert commands, f"no install command for {platform}/{arch}"
            assert "dockle" in commands[0]


#: A saved image in ``docker save`` form (a manifest.json, a config, one layer).
_SAVED_IMAGE = _CAPTURED / "positive-image.tar"


def _run_image(scanner, fake, monkeypatch, image: ImageLocator):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan_image(image=image)


def _oci_layout_tarball(path: Path) -> Path:
    """A tarball holding an OCI layout's marker and index and no manifest.json."""
    with tarfile.open(path, "w") as archive:
        for name, data in (
            ("oci-layout", b'{"imageLayoutVersion": "1.0.0"}'),
            ("index.json", b'{"schemaVersion": 2, "manifests": []}'),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return path


class TestImageScan:
    """The image dispatch: the image asset's locator, not the operator's options."""

    def test_the_register_claim_and_the_image_dispatch_travel_together(self):
        assert "_execute_image_scan" in vars(DockleScanner)
        targets = DockleScanner.operational_facets.targets
        assert targets.kinds == (opsf.TargetKind.CONTAINER_IMAGE,)

    def test_a_reference_follows_double_dash_and_needs_no_option(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeDockle()
        report = _run_image(scanner, fake, monkeypatch, ImageLocator(ref=IMAGE))
        assert isinstance(report, SarifReport)
        argv = fake.argv
        assert argv[0] == "dockle"
        assert "--format=sarif" in argv and "--no-color" in argv
        output = next(a for a in argv if a.startswith("--output="))
        assert output.endswith("/image/dockle.sarif")
        assert argv[-2:] == ["--", IMAGE]
        assert not any(a.startswith("--input=") for a in argv)
        cwd = Path(fake.calls[0]["cwd"])
        assert cwd != tree and tree not in cwd.parents

    def test_a_docker_save_archive_is_passed_with_input(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeDockle()
        _run_image(scanner, fake, monkeypatch, ImageLocator(oci_archive=_SAVED_IMAGE))
        assert f"--input={_SAVED_IMAGE.absolute().as_posix()}" in fake.argv
        assert "--" not in fake.argv

    def test_an_oci_layout_directory_is_a_clean_skip_and_dockle_never_starts(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        layout = tmp_path / "layout"
        layout.mkdir()
        scanner = _scanner(tree, tmp_path)
        fake = FakeDockle()
        image = ImageLocator(oci_layout=layout)
        assert _run_image(scanner, fake, monkeypatch, image) is True
        assert fake.calls == []
        assert "OCI image-layout directory" in scanner._nothing_scanned_reason

    def test_an_oci_layout_tarball_is_a_clean_skip_and_dockle_never_starts(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        archive = _oci_layout_tarball(tmp_path / "image.tar")
        scanner = _scanner(tree, tmp_path)
        fake = FakeDockle()
        image = ImageLocator(oci_archive=archive)
        assert _run_image(scanner, fake, monkeypatch, image) is True
        assert fake.calls == []
        assert "no manifest.json" in scanner._nothing_scanned_reason

    def test_a_reference_that_is_not_an_image_reference_is_never_run(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeDockle()
        with pytest.raises(ScannerError, match="not an image reference"):
            _run_image(scanner, fake, monkeypatch, ImageLocator(ref="-v"))
        assert fake.calls == []

    def test_the_captured_report_is_rated_through_the_image_dispatch(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        text = (_CAPTURED / "positive.sarif").read_text(encoding="utf-8")
        report = _run_image(
            _scanner(tree, tmp_path),
            FakeDockle(report=text),
            monkeypatch,
            ImageLocator(oci_archive=_SAVED_IMAGE),
        )
        assert sorted(_findings(report)) == sorted(
            [
                ("CIS-DI-0010", "error", "HIGH"),
                ("DKL-LI-0001", "error", "HIGH"),
                ("CIS-DI-0001", "warning", "MEDIUM"),
                ("CIS-DI-0005", "note", "LOW"),
                ("CIS-DI-0006", "note", "LOW"),
                ("DKL-LI-0002", "none", "INFO"),
            ]
        )

    @pytest.mark.parametrize("code", [1, 2])
    def test_a_non_zero_exit_fails_the_image_scan(
        self, code, tree, tmp_path, on_path, monkeypatch
    ):
        with pytest.raises(ScannerError):
            _run_image(
                _scanner(tree, tmp_path),
                FakeDockle(report=POSITIVE, exit_code=code),
                monkeypatch,
                ImageLocator(ref=IMAGE),
            )
