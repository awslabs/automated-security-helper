# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""CargoDenyScanner: target selection, invocation, severity and failure handling.

The captured output below is what cargo-deny 0.21.0 (the pinned version) wrote to
stderr with ``--format=json --hide-inclusion-graph`` for a two-crate project
(``smallvec =0.6.10`` and ``atty =0.2.14``) on 2026-11-19. Only the long advisory
``description`` and ``notes`` texts were shortened. The scan() tests replace the
subprocess with a fake that serves that output, so they run on every platform
without the binary or a Rust toolchain.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_base import _folded_exit_code
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules import ash_cargo_deny_plugins as pkg
from automated_security_helper.plugin_modules.ash_cargo_deny_plugins import (
    cargo_deny_scanner as cds,
)
from automated_security_helper.plugin_modules.ash_cargo_deny_plugins.cargo_deny_scanner import (
    COMPLETED_EXIT_CODES,
    DIAGNOSTIC_SEVERITY_MAP,
    CargoDenyScanner,
    CargoDenyScannerConfig,
    CargoDenyScannerConfigOptions,
    convert_cargo_deny_output,
    parse_json_lines,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.config_trust import record_provenance
from automated_security_helper.utils.sandbox.policy import SandboxRequirements

pytestmark = pytest.mark.unit

_REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


def _advisory_line(
    advisory_id: str,
    package: str,
    version: str,
    code: str,
    title: str,
    kind: Optional[str],
    url: str,
    aliases: List[str],
) -> str:
    """One captured advisory diagnostic (descriptions and notes shortened)."""
    return json.dumps(
        {
            "fields": {
                "advisory": {
                    "aliases": aliases,
                    "categories": [],
                    "collection": "crates",
                    "cvss": None,
                    "date": "2021-01-08",
                    "description": "(shortened)",
                    "expect-deleted": False,
                    "id": advisory_id,
                    "informational": kind,
                    "keywords": [],
                    "license": "CC0-1.0",
                    "package": package,
                    "references": [],
                    "related": [],
                    "source": None,
                    "title": title,
                    "url": url,
                    "withdrawn": None,
                },
                "code": code,
                "labels": [
                    {
                        "column": 1,
                        "line": 5,
                        "message": f"{code} advisory detected",
                        "span": f"{package} {version} {_REGISTRY}",
                    }
                ],
                "message": title,
                "notes": [f"ID: {advisory_id}"],
                "severity": "error",
            },
            "type": "diagnostic",
        }
    )


SUMMARY_FAILING = json.dumps(
    {
        "fields": {"advisories": {"errors": 4, "helps": 0, "notes": 0, "warnings": 0}},
        "type": "summary",
    }
)
SUMMARY_CLEAN = json.dumps(
    {
        "fields": {"advisories": {"errors": 0, "helps": 0, "notes": 0, "warnings": 0}},
        "type": "summary",
    }
)

POSITIVE_STDERR = "\n".join(
    [
        _advisory_line(
            "RUSTSEC-2018-0018",
            "smallvec",
            "0.6.10",
            "unsound",
            "smallvec creates uninitialized value of any type",
            "unsound",
            "https://github.com/servo/rust-smallvec/issues/126",
            ["CVE-2018-25023", "GHSA-55m5-whcv-c49c"],
        ),
        _advisory_line(
            "RUSTSEC-2021-0003",
            "smallvec",
            "0.6.10",
            "vulnerability",
            "Buffer overflow in SmallVec::insert_many",
            None,
            "https://github.com/servo/rust-smallvec/issues/252",
            ["CVE-2021-25900"],
        ),
        _advisory_line(
            "RUSTSEC-2021-0145",
            "atty",
            "0.2.14",
            "unsound",
            "Potential unaligned read",
            "unsound",
            "https://github.com/softprops/atty/issues/50",
            ["GHSA-g98v-hv3f-hcfr"],
        ),
        _advisory_line(
            "RUSTSEC-2024-0375",
            "atty",
            "0.2.14",
            "unmaintained",
            "`atty` is unmaintained",
            "unmaintained",
            "https://github.com/softprops/atty/issues/57",
            [],
        ),
        SUMMARY_FAILING,
    ]
)
NEGATIVE_STDERR = SUMMARY_CLEAN

#: Captured with --locked and no Cargo.lock: the run failed, so there is no summary.
NO_LOCK_STDERR = "\n".join(
    [
        json.dumps(
            {
                "fields": {
                    "level": "ERROR",
                    "message": "failed to fetch crates: error: cannot create the lock "
                    "file because --locked was passed to prevent this",
                    "timestamp": "2026-11-19T15:50:37.870061353Z",
                },
                "type": "log",
            }
        ),
        json.dumps(
            {
                "fields": {
                    "level": "ERROR",
                    "message": "`cargo metadata` exited with an error",
                    "timestamp": "2026-11-19T15:50:38.152821712Z",
                },
                "type": "log",
            }
        ),
    ]
)

#: Written out by hand from the capture above, not derived from the converter:
#: (ruleId, SARIF level, ASH severity, uri, package, version).
POSITIVE_EXPECTED = [
    ("RUSTSEC-2018-0018", "error", "HIGH", "Cargo.lock", "smallvec", "0.6.10"),
    ("RUSTSEC-2021-0003", "error", "HIGH", "Cargo.lock", "smallvec", "0.6.10"),
    ("RUSTSEC-2021-0145", "error", "HIGH", "Cargo.lock", "atty", "0.2.14"),
    ("RUSTSEC-2024-0375", "error", "HIGH", "Cargo.lock", "atty", "0.2.14"),
]


def _findings(report: SarifReport) -> List[tuple]:
    out = []
    for r in report.get_all_results():
        props = r.properties
        out.append(
            (
                r.ruleId,
                getattr(r.level, "value", r.level),
                getattr(props, "issue_severity", None),
                r.locations[0].physicalLocation.root.artifactLocation.uri,
                getattr(props, "package_name", None),
                getattr(props, "package_version", None),
            )
        )
    return out


class FakeCargoDeny:
    """Stands in for _run_subprocess: records the call, serves captured stderr."""

    def __init__(
        self,
        stderr: str = POSITIVE_STDERR,
        exit_code: int = 1,
        timed_out: bool = False,
        per_manifest: Optional[Dict[str, Dict[str, Any]]] = None,
    ):
        self.stderr, self.exit_code, self.timed_out = stderr, exit_code, timed_out
        self.per_manifest = per_manifest or {}
        self.calls: List[dict] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, timeout=None, **kwargs):
            self.calls.append(
                {"argv": list(command), "timeout": timeout, "kwargs": kwargs}
            )
            manifest = next(
                a.split("=", 1)[1] for a in command if a.startswith("--manifest-path=")
            )
            behavior = self.per_manifest.get(manifest, {})
            # Like the real _run_subprocess, FOLD this run's code into the
            # scanner's accumulator (the worst so far); assigning it would hide a
            # scan() that reads the accumulator as the current run's code.
            if self.timed_out or behavior.get("timed_out"):
                scanner.exit_code = _folded_exit_code(scanner, scanner.exit_code, -9)
                return {"timed_out": True}
            code = behavior.get("exit_code", self.exit_code)
            if code is not None:
                scanner.exit_code = _folded_exit_code(scanner, scanner.exit_code, code)
            return {
                "returncode": code,
                "stdout": "",
                "stderr": behavior.get("stderr", self.stderr),
            }

        return run


def _scanner(
    source: Path, tmp_path: Path, *, operator: bool = True, **options
) -> CargoDenyScanner:
    """``operator``: the options came from the operator, or from the scanned tree."""
    config = get_default_config()
    record_provenance(
        config,
        in_tree=[] if operator else [source / ".ash" / ".ash.yaml"],
        trusted=AshConfig(),
    )
    return CargoDenyScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "out" / "converted",
            config=config,
        ),
        config=CargoDenyScannerConfig(
            enabled=True, options=CargoDenyScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "svc").mkdir(parents=True)
    (src / "lib").mkdir()
    (src / "target" / "pkg").mkdir(parents=True)
    (src / "Cargo.toml").write_text('[package]\nname = "root"\n')
    (src / "Cargo.lock").write_text("version = 4\n")
    (src / "svc" / "Cargo.toml").write_text('[package]\nname = "svc"\n')
    (src / "svc" / "Cargo.lock").write_text("version = 4\n")
    # A workspace member has no lock of its own; the root's run covers it.
    (src / "lib" / "Cargo.toml").write_text('[package]\nname = "lib"\n')
    (src / "target" / "pkg" / "Cargo.toml").write_text('[package]\nname = "t"\n')
    (src / "target" / "pkg" / "Cargo.lock").write_text("version = 4\n")
    (src / "main.py").write_text("print(1)\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(cds, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner: CargoDenyScanner, fake: FakeCargoDeny, monkeypatch, **kw):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(scanner.context.source_dir), target_type="source", **kw
    )


class TestAlphaPlugin:
    def test_scanner_is_on_by_default_once_its_module_is_listed(self):
        assert CargoDenyScannerConfig().enabled is True

    def test_the_config_name_is_the_tool_name(self):
        assert CargoDenyScannerConfig().name == "cargo-deny"

    def test_the_module_exports_the_scanner(self):
        assert pkg.ASH_SCANNERS == [CargoDenyScanner]
        assert pkg.ASH_REPORTERS == []

    def test_scanner_states_what_the_tool_needs(self):
        assert CargoDenyScanner.python_only is False
        assert CargoDenyScanner.success_exit_codes == COMPLETED_EXIT_CODES
        assert COMPLETED_EXIT_CODES == set(range(16))

    def test_sandbox_asks_for_the_network_and_cargo_home_only(self):
        req = CargoDenyScanner.sandbox_requirements
        assert req != SandboxRequirements()
        assert req.network is True
        assert set(req.cache_paths) == {"~/.cargo", "$CARGO_HOME"}
        assert set(req.env_prefixes) == {"CARGO_", "RUSTUP_"}


class TestTargets:
    def test_only_manifests_with_a_lock_beside_them_are_run(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeCargoDeny()
        _run(scanner, fake, monkeypatch)
        manifests = [
            next(a for a in c["argv"] if a.startswith("--manifest-path="))
            for c in fake.calls
        ]
        # lib/ has no lock and target/ is build output.
        assert manifests == [
            "--manifest-path=Cargo.toml",
            "--manifest-path=svc/Cargo.toml",
        ]
        assert scanner.targets_attempted == 2
        assert scanner.targets_failed == 0

    def test_a_tree_with_no_cargo_project_never_reaches_the_tool(
        self, tmp_path, on_path, monkeypatch
    ):
        src = tmp_path / "src"
        src.mkdir()
        (src / "main.py").write_text("print(1)\n")
        scanner = _scanner(src, tmp_path)
        fake = FakeCargoDeny()
        report = _run(scanner, fake, monkeypatch)
        assert fake.calls == []
        assert _findings(report) == []
        assert scanner.targets_attempted == 0

    def test_an_ignored_path_is_not_scanned(self, tree, tmp_path, on_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        fake = FakeCargoDeny()
        _run(
            scanner,
            fake,
            monkeypatch,
            global_ignore_paths=[IgnorePathWithReason(path="svc/**", reason="test")],
        )
        assert len(fake.calls) == 1

    def test_a_missing_target_never_reaches_the_tool(
        self, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tmp_path, tmp_path)
        fake = FakeCargoDeny()
        monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
        report = scanner.scan(target=tmp_path / "gone", target_type="source")
        assert fake.calls == []
        assert _findings(report) == []


class TestInvocation:
    def test_every_fixed_flag_and_the_check_after_the_subcommand(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeCargoDeny()
        _run(scanner, fake, monkeypatch)
        argv = fake.calls[0]["argv"]
        assert argv[0] == "cargo-deny"
        assert argv[1:6] == [
            "--manifest-path=Cargo.toml",
            "--locked",
            "--format=json",
            "--log-level=warn",
            "--color=never",
        ]
        assert argv[6].startswith("--config=")
        # Global flags come before the subcommand.
        assert argv[7:] == ["check", "--hide-inclusion-graph", "advisories"]

    def test_the_scan_runs_in_the_source_directory(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeCargoDeny()
        _run(scanner, fake, monkeypatch)
        # No cwd override: the base runs the tool in context.source_dir, so the
        # relative manifest path and the report URIs are source-relative.
        assert "cwd" not in fake.calls[0]["kwargs"]

    @pytest.mark.parametrize(
        "checks",
        [["advisories", "sources"], ["licenses"], ["bans", "licenses"]],
    )
    def test_checks_follow_the_subcommand(
        self, tree, tmp_path, on_path, monkeypatch, checks
    ):
        scanner = _scanner(tree, tmp_path, checks=checks)
        fake = FakeCargoDeny()
        _run(scanner, fake, monkeypatch)
        argv = fake.calls[0]["argv"]
        assert argv[argv.index("check") + 2 :] == checks

    @pytest.mark.parametrize(
        "flag",
        [
            "--offline",
            "--frozen",
            "--format=sarif",
            "--metadata-path",
            "--allow",
            "--deny",
            "--warn",
            "-A",
            "-D",
            "-W",
            "--audit-compatible-output",
            "--disable-fetch",
        ],
    )
    def test_flags_that_hide_findings_or_change_the_source_are_never_passed(
        self, tree, tmp_path, on_path, monkeypatch, flag
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeCargoDeny()
        _run(scanner, fake, monkeypatch)
        assert flag not in fake.calls[0]["argv"]

    def test_an_unknown_check_is_refused_by_the_options_model(self):
        with pytest.raises(ValueError):
            CargoDenyScannerConfigOptions(checks=["advisories; rm"])


class TestConfiguration:
    def _config_arg(self, fake: FakeCargoDeny) -> Path:
        arg = next(a for a in fake.calls[0]["argv"] if a.startswith("--config="))
        return Path(arg.split("=", 1)[1])

    def test_a_deny_toml_in_the_tree_is_not_read(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / "deny.toml").write_text(
            '[advisories]\nignore = ["RUSTSEC-2021-0003"]\n'
        )
        scanner = _scanner(tree, tmp_path)
        fake = FakeCargoDeny()
        _run(scanner, fake, monkeypatch)
        config = self._config_arg(fake)
        assert config.name == "cargo-deny-default.toml"
        assert tree not in config.parents
        assert config.read_text() == "[advisories]\n"

    def test_an_operator_config_outside_the_tree_is_used(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        outside = tmp_path / "policy" / "deny.toml"
        outside.parent.mkdir()
        outside.write_text("[licenses]\nallow = []\n")
        scanner = _scanner(tree, tmp_path, config_file=str(outside))
        fake = FakeCargoDeny()
        _run(scanner, fake, monkeypatch)
        assert self._config_arg(fake) == outside

    def test_a_config_the_tree_chose_is_ignored(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        evil = tmp_path / "policy" / "deny.toml"
        evil.parent.mkdir()
        evil.write_text('[advisories]\nignore = ["RUSTSEC-2021-0003"]\n')
        scanner = _scanner(tree, tmp_path, operator=False, config_file=str(evil))
        fake = FakeCargoDeny()
        _run(scanner, fake, monkeypatch)
        assert self._config_arg(fake).name == "cargo-deny-default.toml"

    def test_a_missing_operator_config_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(
            tree, tmp_path, config_file=str(tmp_path / "policy" / "nope.toml")
        )
        fake = FakeCargoDeny()
        with pytest.raises(ScannerError, match="does not exist"):
            _run(scanner, fake, monkeypatch)
        assert fake.calls == []


class TestReport:
    def test_positive_capture_is_rated_and_located(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / "svc" / "Cargo.toml").unlink()
        (tree / "svc" / "Cargo.lock").unlink()
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeCargoDeny(), monkeypatch)
        assert _findings(report) == POSITIVE_EXPECTED

    def test_each_manifest_reports_on_its_own_lock(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        report = _run(scanner, FakeCargoDeny(), monkeypatch)
        uris = {f[3] for f in _findings(report)}
        assert uris == {"Cargo.lock", "svc/Cargo.lock"}
        assert len(_findings(report)) == 8

    def test_negative_control_clean_capture_has_no_findings(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeCargoDeny(stderr=NEGATIVE_STDERR, exit_code=0)
        report = _run(scanner, fake, monkeypatch)
        assert _findings(report) == []
        assert scanner.targets_failed == 0

    def test_advisory_details_are_kept_on_the_result(self):
        converted = convert_cargo_deny_output(
            POSITIVE_STDERR, manifest_uri="Cargo.toml"
        )
        first = converted.results[0]
        assert "RUSTSEC-2018-0018" in converted.rules
        assert "smallvec creates uninitialized value" in first.message.root.text
        assert "https://github.com/servo/rust-smallvec/issues/126" in (
            first.message.root.text
        )
        assert first.properties.aliases == ["CVE-2018-25023", "GHSA-55m5-whcv-c49c"]
        assert first.properties.cargo_deny_code == "unsound"

    def test_summary_and_log_lines_are_not_findings(self):
        converted = convert_cargo_deny_output(
            NEGATIVE_STDERR + "\n" + NO_LOCK_STDERR, manifest_uri="Cargo.toml"
        )
        assert converted.results == []

    def test_converted_results_survive_a_sarif_round_trip(self):
        report = SarifReport.model_validate_json(
            _round_trip(
                convert_cargo_deny_output(POSITIVE_STDERR, manifest_uri="a/Cargo.toml")
            )
        )
        assert {f[3] for f in _findings(report)} == {"a/Cargo.lock"}

    @pytest.mark.parametrize(
        "severity,expected",
        [
            ("error", ("HIGH", "error")),
            ("bug", ("HIGH", "error")),
            ("warning", ("MEDIUM", "warning")),
            ("note", ("LOW", "note")),
            ("help", ("INFO", "none")),
            # A severity the tool did not document errs to the more severe rating.
            ("catastrophe", ("HIGH", "error")),
            ("", ("HIGH", "error")),
        ],
    )
    def test_severity_mapping_agrees_between_level_and_issue_severity(
        self, severity, expected
    ):
        line = json.dumps(
            {
                "fields": {
                    "code": "unlicensed",
                    "message": "demo = 1.0.0 is unlicensed",
                    "severity": severity,
                },
                "type": "diagnostic",
            }
        )
        converted = convert_cargo_deny_output(line, manifest_uri="Cargo.toml")
        (result,) = converted.results
        assert (
            result.properties.issue_severity,
            getattr(result.level, "value", result.level),
        ) == expected
        # A non-advisory finding sits on the manifest and carries its own code.
        assert result.ruleId == "unlicensed"
        assert result.locations[0].physicalLocation.root.artifactLocation.uri == (
            "Cargo.toml"
        )

    def test_the_map_has_exactly_the_documented_severities(self):
        assert set(DIAGNOSTIC_SEVERITY_MAP) == {
            "bug",
            "error",
            "warning",
            "note",
            "help",
        }


def _round_trip(converted) -> str:
    from automated_security_helper.schemas.sarif_schema_model import (
        Run,
        Tool,
        ToolComponent,
    )

    report = SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="cargo-deny")),
                results=converted.results,
            )
        ],
    )
    return report.model_dump_json(exclude_none=True, by_alias=True)


class TestExitStatus:
    @pytest.mark.parametrize("code", [0, 1, 2, 4, 8, 15])
    def test_a_check_bitset_with_a_summary_completes(
        self, tree, tmp_path, on_path, monkeypatch, code
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeCargoDeny(exit_code=code)
        report = _run(scanner, fake, monkeypatch)
        assert scanner.targets_failed == 0
        assert len(_findings(report)) == 8

    @pytest.mark.parametrize("code", [16, 101, 126, 127, 137, -9, None])
    def test_any_other_exit_code_fails_even_with_a_report_on_stderr(
        self, tree, tmp_path, on_path, monkeypatch, code
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeCargoDeny(exit_code=code)
        with pytest.raises(ScannerError, match="not a check result"):
            _run(scanner, fake, monkeypatch)
        assert scanner.targets_failed == 2

    def test_exit_1_without_a_summary_is_a_failed_run_not_an_advisory(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeCargoDeny(stderr=NO_LOCK_STDERR, exit_code=1)
        with pytest.raises(ScannerError) as raised:
            _run(scanner, fake, monkeypatch)
        message = str(raised.value)
        assert "without a summary" in message
        # The tool's own ERROR log text is named, so the cause is visible.
        assert "cargo metadata" in message
        assert scanner.targets_failed == scanner.targets_attempted == 2

    def test_one_failed_project_does_not_hide_the_others(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeCargoDeny(
            per_manifest={"svc/Cargo.toml": {"stderr": NO_LOCK_STDERR, "exit_code": 1}}
        )
        report = _run(scanner, fake, monkeypatch)
        assert len(_findings(report)) == 4
        assert scanner.targets_failed == 1
        assert any("svc/Cargo.toml" in e for e in scanner.errors)

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=600)
        fake = FakeCargoDeny(timed_out=True)
        with pytest.raises(ScannerError, match="timed out"):
            _run(scanner, fake, monkeypatch)
        timeout = fake.calls[0]["timeout"]
        assert timeout is not None and 0 < timeout <= 600
        # The time budget is shared: later projects are not started after a timeout.
        assert len(fake.calls) == 1

    @pytest.mark.parametrize(
        "stderr",
        [
            "",
            "not json at all\n",
            '{"type": "summary"',  # truncated JSON
            "[1, 2, 3]\n",  # valid JSON that is not an object
            '{"type": "diagnostic"}\n',  # an object with no summary
        ],
    )
    def test_malformed_or_empty_output_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch, stderr
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeCargoDeny(stderr=stderr, exit_code=1)
        with pytest.raises(ScannerError, match="without a summary"):
            _run(scanner, fake, monkeypatch)

    def test_garbage_lines_among_good_ones_are_skipped(self):
        text = "warning: something\n" + POSITIVE_STDERR + "\n{broken\n"
        assert len(parse_json_lines(text)) == 5
        assert (
            len(convert_cargo_deny_output(text, manifest_uri="Cargo.toml").results) == 4
        )

    def test_a_diagnostic_with_no_fields_is_not_a_finding(self):
        text = '{"type": "diagnostic"}\n{"type": "diagnostic", "fields": 3}\n'
        assert convert_cargo_deny_output(text, manifest_uri="Cargo.toml").results == []

    def test_a_stale_report_is_removed_before_the_next_run(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        results_dir = Path(scanner.results_dir or scanner.context.output_dir) / "source"
        results_dir.mkdir(parents=True, exist_ok=True)
        stale = results_dir / "cargo-deny.sarif"
        stale.write_text("stale")
        _run(scanner, FakeCargoDeny(), monkeypatch)
        assert stale.read_text() != "stale"


class TestDependencyCheck:
    def test_missing_binary_is_reported_with_the_install_hint(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(cds, "find_executable", lambda cmd: None)
        scanner = _scanner(tmp_path, tmp_path)
        warnings: List[str] = []
        monkeypatch.setattr(
            cds.ASH_LOGGER, "warning", lambda msg, *a, **k: warnings.append(msg)
        )
        assert scanner.validate_plugin_dependencies() is False
        assert "ash dependencies install" in warnings[0]
        assert "ash_cargo_deny_plugins" in warnings[0]
        assert "--tool cargo-deny" in warnings[0]

    def test_present_binary_and_toolchain_pass(self, tmp_path, on_path):
        scanner = _scanner(tmp_path, tmp_path)
        assert scanner.validate_plugin_dependencies() is True

    def test_a_missing_toolchain_is_a_missing_dependency_with_a_reason(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(
            cds,
            "find_executable",
            lambda cmd: "/fake/bin/cargo-deny" if cmd == "cargo-deny" else None,
        )
        scanner = _scanner(tmp_path, tmp_path)
        assert scanner.validate_plugin_dependencies() is False
        assert "cargo not found" in (scanner.dependency_unavailable_reason or "")

    def test_offline_is_unavailable_whatever_is_installed(
        self, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tmp_path, tmp_path)
        monkeypatch.setattr(scanner, "_scanner_offline", lambda: True)
        assert scanner.validate_plugin_dependencies() is False
        assert "advisory database" in (scanner.dependency_unavailable_reason or "")

    def test_an_earlier_unavailable_reason_wins(self, tmp_path, on_path):
        scanner = _scanner(tmp_path, tmp_path)
        scanner.dependency_unavailable_reason = "earlier"
        assert scanner.validate_plugin_dependencies() is False


class TestPinnedInstall:
    """cargo-deny is pinned by the plugin's own installer (cargo_deny_install.py).

    Nothing here patches the download table: construction has to work as it
    ships, without a cargo-deny entry in the shared tool_downloads tables.
    """

    def test_construction_needs_no_shared_download_table(self, tmp_path):
        scanner = _scanner(tmp_path, tmp_path)
        assert scanner.command == "cargo-deny"

    def test_an_install_command_is_declared_for_every_published_platform(
        self, tmp_path, monkeypatch
    ):
        from automated_security_helper.plugin_modules.ash_cargo_deny_plugins import (
            cargo_deny_install,
        )

        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
        scanner = _scanner(tmp_path, tmp_path)
        declared = {
            (platform, arch)
            for platform, arches in scanner.custom_install_commands.items()
            for arch, commands in arches.items()
            if commands
        }
        assert declared == set(cargo_deny_install.ASSETS)
        for arches in scanner.custom_install_commands.values():
            for commands in arches.values():
                assert "install_cargo_deny" in " ".join(commands[0].args)

    def test_the_module_does_not_use_the_shared_download_table(self):
        assert not hasattr(cds, "pinned_tool_install_commands")


class TestExitCodeIsThisRunsOwn:
    """_run_subprocess folds each run's code into the scanner's accumulator."""

    def test_a_failed_first_project_does_not_fail_the_next(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        # "." (the root) runs first and fails with 101; svc then completes with 1.
        # Read from the folded accumulator, svc would read 101 and fail too.
        fake = FakeCargoDeny(
            per_manifest={"Cargo.toml": {"stderr": "", "exit_code": 101}}
        )
        report = _run(scanner, fake, monkeypatch)
        assert scanner.targets_failed == 1
        assert len(_findings(report)) == 4
        assert any("Cargo.toml: cargo-deny exited 101" in e for e in scanner.errors)

    def test_a_clean_first_project_does_not_hide_the_next_one_failing(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeCargoDeny(
            per_manifest={
                "Cargo.toml": {"stderr": NEGATIVE_STDERR, "exit_code": 0},
                "svc/Cargo.toml": {"stderr": NO_LOCK_STDERR, "exit_code": 1},
            }
        )
        _run(scanner, fake, monkeypatch)
        assert scanner.targets_failed == 1
        assert any("svc/Cargo.toml" in e for e in scanner.errors)

    def test_the_recorded_code_is_the_bitset_of_every_runs_checks(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeCargoDeny(
            per_manifest={
                "Cargo.toml": {"stderr": POSITIVE_STDERR, "exit_code": 1},
                "svc/Cargo.toml": {"stderr": POSITIVE_STDERR, "exit_code": 4},
            }
        )
        _run(scanner, fake, monkeypatch)
        assert scanner.exit_code == 5


_CAPTURED = (
    Path(__file__).resolve().parents[3]
    / "test_data"
    / "scanners"
    / "cargo-deny"
    / "captured"
)


class TestCapturedFixtures:
    """The committed capture files, read from disk and scanned end to end."""

    def _text(self, name: str) -> str:
        path = _CAPTURED / name
        assert path.is_file(), path
        return path.read_text(encoding="utf-8")

    def test_the_positive_capture_is_the_inline_capture(self):
        on_disk = [
            json.loads(line) for line in self._text("positive.jsonl").splitlines()
        ]
        inline = [json.loads(line) for line in POSITIVE_STDERR.splitlines()]
        assert [d["type"] for d in on_disk] == ["diagnostic"] * 4 + ["summary"]
        assert [d["fields"].get("advisory", {}).get("id") for d in on_disk] == [
            d["fields"].get("advisory", {}).get("id") for d in inline
        ]

    def test_the_positive_capture_maps_every_advisory(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeCargoDeny(stderr=self._text("positive.jsonl"), exit_code=1)
        report = _run(scanner, fake, monkeypatch)
        rows = _findings(report)
        assert len(rows) == 8
        by_rule = {row[0]: row for row in rows}
        assert set(by_rule) == {row[0] for row in POSITIVE_EXPECTED}
        for expected in POSITIVE_EXPECTED:
            assert by_rule[expected[0]][1:3] == expected[1:3]
            assert by_rule[expected[0]][4:] == expected[4:]

    def test_the_negative_capture_is_a_clean_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeCargoDeny(stderr=self._text("negative.jsonl"), exit_code=0)
        report = _run(scanner, fake, monkeypatch)
        assert _findings(report) == []
        assert scanner.targets_failed == 0

    def test_the_no_lock_capture_is_a_failed_run(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeCargoDeny(stderr=self._text("no-lock.jsonl"), exit_code=1)
        with pytest.raises(ScannerError, match="without a summary"):
            _run(scanner, fake, monkeypatch)

    @pytest.mark.parametrize(
        "diagnostic_severity, ash_severity, sarif_level",
        [
            ("error", "HIGH", "error"),
            ("warning", "MEDIUM", "warning"),
            ("note", "LOW", "note"),
            ("help", "INFO", "none"),
            ("invented", "HIGH", "error"),
        ],
    )
    def test_severity_mapping_over_the_captured_report(
        self, diagnostic_severity, ash_severity, sarif_level
    ):
        """The captured advisory with only its severity changed, converted."""
        lines = self._text("positive.jsonl").splitlines()
        first = json.loads(lines[0])
        first["fields"]["severity"] = diagnostic_severity
        converted = convert_cargo_deny_output(
            json.dumps(first), manifest_uri="Cargo.toml"
        )
        (result,) = converted.results
        assert getattr(result.level, "value", result.level) == sarif_level
        assert result.properties.issue_severity == ash_severity


class TestNothingToScan:
    def test_a_tree_with_a_locked_project_has_something_to_scan(self, tree, tmp_path):
        assert _scanner(tree, tmp_path).nothing_to_scan_reason() is None

    def test_a_tree_without_a_cargo_lock_has_nothing_to_scan(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        (src / "Cargo.toml").write_text('[package]\nname = "x"\n')
        (src / "main.py").write_text("print(1)\n")
        reason = _scanner(src, tmp_path).nothing_to_scan_reason()
        assert reason is not None and "Cargo.lock" in reason

    def test_only_a_target_directory_project_is_nothing_to_scan(self, tmp_path):
        src = tmp_path / "src"
        (src / "target" / "pkg").mkdir(parents=True)
        (src / "target" / "pkg" / "Cargo.toml").write_text("[package]\n")
        (src / "target" / "pkg" / "Cargo.lock").write_text("version = 4\n")
        assert _scanner(src, tmp_path).nothing_to_scan_reason() is not None
