# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""GgshieldScanner: the opt-in gate, the argv, the report and the failure cases.

The report served by the fake subprocess is built by ``_report`` from the shape
``ggshield``'s ``SecretSARIFOutputHandler`` writes (read from its source: SARIF
2.1.0, one run, no ``rules`` array, ``ruleId`` the detector's display name, level
``error`` on every result, ``partialFingerprints["secret/v1"]``, 1-based regions).
It is NOT a capture: it exercises URI forms and edge cases the captured run
does not show, and the expected findings below are written out by hand. The
report ggshield itself wrote is served by
``test_ggshield_captured_report_and_sandbox.py``. The scan() tests replace the
subprocess, so they run on every platform without ggshield, uv or network.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import OfflineStrategy
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules import ash_ggshield_plugins
from automated_security_helper.plugin_modules.ash_ggshield_plugins import (
    ggshield_scanner as gs,
)
from automated_security_helper.plugin_modules.ash_ggshield_plugins.ggshield_scanner import (
    API_KEY_ENV,
    GgshieldScanner,
    GgshieldScannerConfig,
    GgshieldScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sandbox.policy import SandboxRequirements

pytestmark = pytest.mark.unit

#: A stand-in for a key. Not a real credential; it only has to be found or not
#: found in output.
FAKE_KEY_VALUE = "not-a-real-key-for-tests"


def _location(uri: str, line: int, c0: int, c1: int) -> Dict[str, Any]:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {
                "startLine": line,
                "startColumn": c0,
                "endLine": line,
                "endColumn": c1,
            },
        }
    }


def _result(rule: str, uri: str, line: int, **extra: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "ruleId": rule,
        "level": "error",
        "message": {
            "text": f"Secret detected: {rule}.\nMatches: [apikey](0)",
            "markdown": f"Secret detected: {rule}.",
        },
        "locations": [_location(uri, line, 9, 30)],
        "relatedLocations": [
            {
                "id": 0,
                **_location(uri, line, 9, 30),
                "message": {"text": "apikey"},
            }
        ],
        "partialFingerprints": {"secret/v1": f"fingerprint-{rule}-{line}"},
    }
    result.update(extra)
    return result


def _report(results: List[Dict[str, Any]]) -> str:
    return json.dumps(
        {
            "version": "2.1.0",
            "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "organization": "GitGuardian",
                            "name": "ggshield",
                            "version": "1.56.1",
                            "informationUri": "https://github.com/GitGuardian/ggshield",
                        },
                        "extensions": [{"name": "secret", "version": "2.0.0"}],
                    },
                    "results": results,
                }
            ],
        }
    )


def _positive(source: Path) -> str:
    """Three findings, one per way ggshield may spell a location."""
    root = source.absolute().as_posix()
    return _report(
        [
            _result("Generic High Entropy Secret", f"{root}/app.py", 3),
            _result("Private Key", "./services/settings.py", 7),
            # A level other than error must still come out error / CRITICAL.
            _result("Generic Password", f"file://{root}/notes.txt", 1, level="warning"),
        ]
    )


#: What _positive must produce: (ruleId, SARIF level, ASH severity, uri, line).
POSITIVE_EXPECTED = [
    ("Generic High Entropy Secret", "error", "CRITICAL", "app.py", 3),
    ("Private Key", "error", "CRITICAL", "services/settings.py", 7),
    ("Generic Password", "error", "CRITICAL", "notes.txt", 1),
]

NEGATIVE = _report([])


class FakeGgshield:
    """Stands in for _run_subprocess: records the call, writes the report."""

    def __init__(
        self,
        report_text: Optional[str] = None,
        exit_code: int = 1,
        stderr: str = "",
        timed_out: bool = False,
    ):
        self.report_text, self.exit_code = report_text, exit_code
        self.stderr, self.timed_out = stderr, timed_out
        self.calls: List[Dict[str, Any]] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, cwd=None, **_):
            self.calls.append(
                {
                    "argv": list(command),
                    "env": env,
                    "timeout": timeout,
                    "cwd": cwd,
                    "cwd_was_dir": cwd is not None and Path(cwd).is_dir(),
                    "cwd_listing": (
                        [p.name for p in Path(cwd).iterdir()]
                        if cwd is not None and Path(cwd).is_dir()
                        else None
                    ),
                }
            )
            if self.timed_out:
                scanner.exit_code = -9
                return {"timed_out": True}
            if self.report_text is not None:
                path = Path(_flag(command, "--output="))
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(self.report_text, encoding="utf-8")
            scanner.exit_code = self.exit_code
            return {
                "returncode": self.exit_code,
                "stdout": "",
                "stderr": self.stderr,
            }

        return run

    @property
    def argv(self) -> List[str]:
        return self.calls[0]["argv"]


def _flag(argv: List[str], prefix: str) -> Optional[str]:
    for token in argv:
        if token.startswith(prefix):
            return token[len(prefix) :]
    return None


def _scanner(
    source: Path, tmp_path: Path, output_dir: Optional[Path] = None
) -> GgshieldScanner:
    output = output_dir or tmp_path / "out"
    return GgshieldScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=get_default_config(),
        ),
        config=GgshieldScannerConfig(
            enabled=True, options=GgshieldScannerConfigOptions()
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "services").mkdir(parents=True)
    (src / "app.py").write_text("print(1)\n")
    (src / "services" / "settings.py").write_text("DEBUG = False\n")
    return src


@pytest.fixture(autouse=True)
def key_set(monkeypatch):
    """Every test starts with a key; the gate tests remove it."""
    monkeypatch.setenv(API_KEY_ENV, FAKE_KEY_VALUE)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)


@pytest.fixture
def deps_ok(monkeypatch):
    """The tool is installed: the dependency check is not what these tests probe."""
    monkeypatch.setattr(GgshieldScanner, "validate_plugin_dependencies", lambda s: True)


def _run(scanner, fake, monkeypatch, target_type="source", **kw):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(scanner.context.source_dir), target_type=target_type, **kw
    )


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


class TestCommunityPlugin:
    def test_the_scanner_is_off_by_default(self):
        assert GgshieldScannerConfig().enabled is False

    def test_the_config_names_the_scanner(self):
        assert GgshieldScannerConfig().name == "ggshield"

    def test_the_module_exports_the_scanner(self):
        assert ash_ggshield_plugins.ASH_SCANNERS == [GgshieldScanner]
        assert ash_ggshield_plugins.ASH_REPORTERS == []

    def test_needs_the_network_so_offline_skips_it(self):
        assert GgshieldScanner.offline_strategy is OfflineStrategy.SKIP_OFFLINE
        assert GgshieldScanner.python_only is False

    def test_the_sandbox_grants_network_and_only_the_gitguardian_variables(self):
        required = GgshieldScanner.sandbox_requirements
        assert required != SandboxRequirements()
        assert required.network is True
        assert required.env_names == (API_KEY_ENV,)
        assert required.env_prefixes == ("GITGUARDIAN_",)


class TestOptInGate:
    def test_without_the_key_the_dependency_check_fails_and_names_the_variable(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.delenv(API_KEY_ENV)
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is False
        assert API_KEY_ENV in (scanner.dependency_unavailable_reason or "")
        assert scanner.dependencies_satisfied is False

    def test_a_blank_key_is_no_key(self, tree, tmp_path, monkeypatch):
        monkeypatch.setenv(API_KEY_ENV, "   ")
        scanner = _scanner(tree, tmp_path)
        assert scanner.validate_plugin_dependencies() is False

    def test_a_scan_without_the_key_never_starts_the_tool(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.delenv(API_KEY_ENV)
        scanner = _scanner(tree, tmp_path)
        fake = FakeGgshield(report_text=NEGATIVE, exit_code=0)
        assert not _run(scanner, fake, monkeypatch)
        assert fake.calls == []

    def test_the_key_value_is_hidden_from_logs(self, tree, tmp_path):
        scanner = _scanner(tree, tmp_path)
        assert FAKE_KEY_VALUE in scanner._environment_values()

    def test_the_missing_key_reason_never_holds_a_key(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        monkeypatch.delenv(API_KEY_ENV)
        reason = scanner._api_key_missing_reason()
        assert reason and FAKE_KEY_VALUE not in reason

    def test_with_the_key_the_gate_is_open(self, tree, tmp_path):
        assert _scanner(tree, tmp_path)._api_key_missing_reason() is None


class TestToolAbsent:
    def test_no_uv_and_no_binary_is_unavailable_with_an_install_hint(
        self, tree, tmp_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        monkeypatch.setattr(scanner, "resolve_deferred_tool_version", lambda: None)
        monkeypatch.setattr(scanner, "_validate_uv_tool_availability", lambda: False)
        monkeypatch.setattr(gs, "get_uv_tool_command", lambda name: None)
        assert scanner.validate_plugin_dependencies() is False
        reason = scanner.dependency_unavailable_reason or ""
        assert "uv tool install" in reason
        assert "--tool ggshield" in reason

    def test_a_scan_with_the_tool_absent_does_not_run_it(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(
            GgshieldScanner, "validate_plugin_dependencies", lambda s: False
        )
        scanner = _scanner(tree, tmp_path)
        fake = FakeGgshield(report_text=NEGATIVE, exit_code=0)
        assert not _run(scanner, fake, monkeypatch)
        assert fake.calls == []


class TestInvocation:
    def test_every_fixed_flag_and_the_scan_path(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeGgshield(report_text=_positive(tree))
        _run(scanner, fake, monkeypatch)
        argv = fake.argv
        assert argv[:4] == ["ggshield", "secret", "scan", "path"]
        for flag in ("--recursive", "--yes", "--all-secrets", "--format=sarif"):
            assert flag in argv
        output = _flag(argv, "--output=")
        assert output and output.endswith("source/ggshield.sarif")
        assert argv[-2:] == ["--", tree.absolute().as_posix()]

    @pytest.mark.parametrize(
        "forbidden",
        [
            "--ignore-known-secrets",
            "--exit-zero",
            "--show-secrets",
            "--use-gitignore",
            "--exclude",
            "--banlist-detector",
            "--source-uuid",
            "--with-incident-details",
            "--insecure",
            "--allow-self-signed",
            "--json",
        ],
    )
    def test_flags_that_hide_findings_or_change_what_is_sent_are_never_passed(
        self, tree, tmp_path, deps_ok, monkeypatch, forbidden
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeGgshield(report_text=_positive(tree))
        _run(scanner, fake, monkeypatch)
        assert not any(
            t == forbidden or t.startswith(forbidden + "=") for t in fake.argv
        )

    def test_the_tool_runs_in_an_empty_directory_outside_the_tree(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeGgshield(report_text=_positive(tree))
        _run(scanner, fake, monkeypatch)
        call = fake.calls[0]
        # Read while the subprocess "ran": the directory is removed with the run.
        assert call["cwd_was_dir"] and call["cwd_listing"] == []
        cwd = Path(call["cwd"])
        assert tree.resolve() not in cwd.resolve().parents
        assert cwd.resolve() != tree.resolve()

    def test_the_timeout_reaches_the_subprocess(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeGgshield(report_text=_positive(tree))
        _run(scanner, fake, monkeypatch)
        timeout = fake.calls[0]["timeout"]
        assert (
            timeout is not None and 0 < timeout <= scanner.config.options.scan_timeout
        )

    def test_a_report_left_by_an_earlier_run_is_removed_first(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        _run(scanner, FakeGgshield(report_text=_positive(tree)), monkeypatch)
        # The second run writes nothing: the first run's report must not be read.
        with pytest.raises(ScannerError):
            _run(scanner, FakeGgshield(report_text=None, exit_code=0), monkeypatch)

    def test_a_target_holding_ashs_output_dir_is_refused_before_the_tool_starts(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, output_dir=tree / ".ash" / "ash_output")
        fake = FakeGgshield(report_text=_positive(tree))
        with pytest.raises(ScannerError, match="output directory"):
            _run(scanner, fake, monkeypatch)
        assert fake.calls == []

    def test_ignore_paths_are_refused_before_the_tool_starts(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeGgshield(report_text=_positive(tree))
        with pytest.raises(ScannerError, match="ignore_paths"):
            _run(
                scanner,
                fake,
                monkeypatch,
                global_ignore_paths=[
                    IgnorePathWithReason(path="vendor/", reason="third party")
                ],
            )
        assert fake.calls == []


class TestReport:
    def test_findings_are_rated_critical_error_and_located_in_the_source(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        report = _run(
            _scanner(tree, tmp_path),
            FakeGgshield(report_text=_positive(tree)),
            monkeypatch,
        )
        assert isinstance(report, SarifReport)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_negative_control_a_clean_scan_has_no_findings(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        report = _run(
            _scanner(tree, tmp_path),
            FakeGgshield(report_text=NEGATIVE, exit_code=0),
            monkeypatch,
        )
        assert isinstance(report, SarifReport)
        assert report.get_all_results() == []

    def test_results_are_tagged_and_keep_their_fingerprint(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        report = _run(
            _scanner(tree, tmp_path),
            FakeGgshield(report_text=_positive(tree)),
            monkeypatch,
        )
        first = report.get_all_results()[0]
        assert {"secret", "security"} <= set(first.properties.tags)
        assert first.partialFingerprints == {
            "secret/v1": "fingerprint-Generic High Entropy Secret-3"
        }

    def test_an_empty_fingerprint_is_dropped(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        blank = _result("Private Key", "./app.py", 1)
        blank["partialFingerprints"] = {"secret/v1": ""}
        report = _run(
            _scanner(tree, tmp_path),
            FakeGgshield(report_text=_report([blank])),
            monkeypatch,
        )
        assert report.get_all_results()[0].partialFingerprints is None

    def test_a_snippet_is_overwritten(self, tree, tmp_path, deps_ok, monkeypatch):
        leaked = _result("Private Key", "./app.py", 1)
        leaked["locations"][0]["physicalLocation"]["region"]["snippet"] = {
            "text": "VALUE-THAT-MUST-NOT-SURVIVE"
        }
        report = _run(
            _scanner(tree, tmp_path),
            FakeGgshield(report_text=_report([leaked])),
            monkeypatch,
        )
        assert "VALUE-THAT-MUST-NOT-SURVIVE" not in report.model_dump_json()

    def test_the_report_round_trips_as_sarif(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        report = _run(
            _scanner(tree, tmp_path),
            FakeGgshield(report_text=_positive(tree)),
            monkeypatch,
        )
        again = SarifReport.model_validate(json.loads(report.model_dump_json()))
        assert _findings(again) == POSITIVE_EXPECTED


class TestRelativeUri:
    @pytest.mark.parametrize(
        ("uri", "expected"),
        [
            ("/work/src/a/b.py", "a/b.py"),
            ("file:///work/src/a/b.py", "a/b.py"),
            ("./a/b.py", "a/b.py"),
            ("a/b.py", "a/b.py"),
            ("/elsewhere/b.py", "/elsewhere/b.py"),
            ("/work/src2/b.py", "/work/src2/b.py"),
        ],
    )
    def test_uri_forms(self, uri, expected):
        assert gs._relative_uri(uri, Path("/work/src")) == expected


class TestExitStatus:
    def test_zero_and_one_are_success(self, tree, tmp_path, deps_ok, monkeypatch):
        for code in (0, 1):
            scanner = _scanner(tree, tmp_path)
            report = _run(
                scanner, FakeGgshield(report_text=NEGATIVE, exit_code=code), monkeypatch
            )
            assert isinstance(report, SarifReport)

    @pytest.mark.parametrize(
        ("code", "words"),
        [
            (2, "usage"),
            (3, "authentication"),
            (4, "did not respond"),
            (128, "unexpected"),
        ],
    )
    def test_any_other_code_fails_even_with_a_report_on_disk(
        self, tree, tmp_path, deps_ok, monkeypatch, code, words
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeGgshield(report_text=_positive(tree), exit_code=code)
        with pytest.raises(ScannerError, match=words):
            _run(scanner, fake, monkeypatch)

    def test_a_run_that_wrote_no_report_fails_the_scan(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        with pytest.raises(ScannerError):
            _run(scanner, FakeGgshield(report_text=None, exit_code=0), monkeypatch)

    def test_stderr_is_not_copied_into_the_errors(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeGgshield(
            report_text=_positive(tree), stderr="line quoted from the scanned tree"
        )
        _run(scanner, fake, monkeypatch)
        assert "quoted from the scanned tree" not in " ".join(scanner.errors)

    def test_the_failure_message_names_the_log_and_does_not_quote_it(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeGgshield(
            report_text=None, exit_code=3, stderr="line quoted from the scanned tree"
        )
        with pytest.raises(ScannerError) as raised:
            _run(scanner, fake, monkeypatch)
        message = str(raised.value)
        assert "stderr.log" in message
        assert "quoted from the scanned tree" not in message
        assert FAKE_KEY_VALUE not in message

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, deps_ok, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeGgshield(timed_out=True)
        with pytest.raises(ScannerError, match="timed out"):
            _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= scanner.config.options.scan_timeout


class TestMalformedReport:
    @pytest.mark.parametrize(
        "text",
        [
            "not json at all",
            "",
            "[]",
            "{}",
            json.dumps({"version": "2.1.0", "runs": []}),
        ],
    )
    def test_an_unreadable_report_fails_the_scan_and_never_reads_as_clean(
        self, tree, tmp_path, deps_ok, monkeypatch, text
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeGgshield(report_text=text, exit_code=0)
        with pytest.raises(ScannerError):
            _run(scanner, fake, monkeypatch)
