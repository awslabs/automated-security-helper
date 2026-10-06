# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""HadolintScanner: severity mapping, target selection and failure handling.

The parser tests read SARIF and JSON that hadolint 2.15.1 (the pinned version)
actually wrote for the fixtures under tests/test_data/scanners/hadolint; see the
README in captured/ for the argv. The scan() tests replace the subprocess with a
fake that serves those captured files, so they run on every platform without the
binary. tests/integration/scanners/test_hadolint_scanner.py runs the real one.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Dict, List, Optional

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    hadolint_scanner as hs,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.hadolint_scanner import (
    HadolintScanner,
    HadolintScannerConfig,
    HadolintScannerConfigOptions,
    is_dockerfile_name,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

FIXTURES = Path(__file__).resolve().parents[3] / "test_data" / "scanners" / "hadolint"
CAPTURED = FIXTURES / "captured"


def _load(name: str):
    return json.loads((CAPTURED / name).read_text(encoding="utf-8"))


def _findings(report: SarifReport) -> List[tuple]:
    """(ruleId, SARIF level, ASH severity, uri, line) for every result, in order."""
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


def _levels_from(json_name: str) -> Dict[str, str]:
    seen: Dict[str, set] = {}
    for e in _load(json_name):
        seen.setdefault(e["code"], set()).add(e["level"])
    return {k: next(iter(v)) for k, v in seen.items() if len(v) == 1}


#: What the positive fixture must produce. Written out by hand from the
#: fixtures' contents, not derived from the parser under test.
POSITIVE_EXPECTED = [
    ("DL3007", "warning", "MEDIUM", "Dockerfile", 2),
    ("DL3015", "note", "LOW", "Dockerfile", 3),
    ("DL3008", "warning", "MEDIUM", "Dockerfile", 3),
    ("DL3009", "note", "LOW", "Dockerfile", 3),
    ("DL3003", "warning", "MEDIUM", "Dockerfile", 4),
    ("SC2086", "note", "LOW", "Dockerfile", 4),
    ("SC2006", "none", "INFO", "Dockerfile", 5),
    ("DL4000", "error", "HIGH", "Dockerfile", 6),
    ("DL1000", "error", "HIGH", "services/Dockerfile.broken", 3),
    ("DL3013", "warning", "MEDIUM", "services/api.Dockerfile", 2),
    ("DL3042", "warning", "MEDIUM", "services/api.Dockerfile", 2),
    ("DL3002", "warning", "MEDIUM", "services/api.Dockerfile", 3),
    ("DL3066", "note", "LOW", "services/api.Dockerfile", 3),
]


class TestOptIn:
    def test_scanner_is_opt_in_and_config_defaults_off(self):
        assert HadolintScanner.OPT_IN is True
        assert HadolintScannerConfig().enabled is False
        assert HadolintScannerConfig().name == "hadolint"

    def test_default_ash_config_has_it_disabled(self):
        assert get_default_config().scanners.hadolint.enabled is False


class TestDockerfileNames:
    @pytest.mark.parametrize(
        "name",
        [
            "Dockerfile",
            "Containerfile",
            "api.Dockerfile",
            "Dockerfile.prod",
            "Dockerfile.broken",
            "-x.Dockerfile",
        ],
    )
    def test_linted(self, name):
        assert is_dockerfile_name(name)

    @pytest.mark.parametrize(
        "name",
        [
            "dockerfile",
            "Dockerfile.dockerignore",
            "api.Dockerfile.dockerignore",
            ".dockerignore",
            ".Dockerfile",
            "Dockerfile.",
            "Dockerfiles",
            "docker-compose.yml",
            "Containerfile.prod",
        ],
    )
    def test_not_linted(self, name):
        assert not is_dockerfile_name(name)


class TestSeverityMapping:
    def test_captured_positive_maps_every_hadolint_level(self):
        report = SarifReport.model_validate(_load("positive.sarif"))
        HadolintScanner.apply_severity_mapping(report, _levels_from("positive.json"))
        assert _findings(report) == POSITIVE_EXPECTED

    @pytest.mark.parametrize(
        ("index", "field", "value"),
        [
            (0, "ruleId", "DL3006"),
            (1, "level", "warning"),
            (3, "line", 99),
            (8, "uri", "services/api.Dockerfile"),
        ],
    )
    def test_negative_control_a_mutated_finding_fails_the_expectation(
        self, index, field, value
    ):
        """Mutate one captured result; the same assertion must now fail.

        Proves the comparison above reads rule id, level and location rather
        than passing on any report of the right length.
        """
        raw = copy.deepcopy(_load("positive.sarif"))
        result = raw["runs"][0]["results"][index]
        if field == "ruleId":
            result["ruleId"] = value
        elif field == "level":
            result["level"] = value
        elif field == "line":
            result["locations"][0]["physicalLocation"]["region"]["startLine"] = value
        else:
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = (
                value
            )
        report = SarifReport.model_validate(raw)
        HadolintScanner.apply_severity_mapping(report, _levels_from("positive.json"))
        assert _findings(report) != POSITIVE_EXPECTED

    def test_without_the_json_table_every_note_is_low(self):
        """The fail-safe direction: style is never reported below info."""
        report = SarifReport.model_validate(_load("positive.sarif"))
        HadolintScanner.apply_severity_mapping(report, None)
        sc2006 = [f for f in _findings(report) if f[0] == "SC2006"]
        assert sc2006 == [("SC2006", "note", "LOW", "Dockerfile", 5)]

    def test_the_table_cannot_downgrade_a_warning_or_error(self):
        report = SarifReport.model_validate(_load("positive.sarif"))
        HadolintScanner.apply_severity_mapping(
            report, {"DL3007": "style", "DL4000": "style"}
        )
        by_rule = {f[0]: f for f in _findings(report)}
        assert by_rule["DL3007"][1:3] == ("warning", "MEDIUM")
        assert by_rule["DL4000"][1:3] == ("error", "HIGH")

    def test_the_table_cannot_promote_a_note_past_info(self):
        """A note is info or style; any other level from the table is ignored."""
        report = SarifReport.model_validate(_load("positive.sarif"))
        HadolintScanner.apply_severity_mapping(report, {"DL3015": "error"})
        by_rule = {f[0]: f for f in _findings(report)}
        assert by_rule["DL3015"][1:3] == ("note", "LOW")

    def test_a_code_at_two_levels_is_not_refined(self, monkeypatch, tmp_path):
        """Ambiguous JSON levels for one code leave that code's notes at LOW."""
        scanner = _scanner(tmp_path, tmp_path)
        responses = iter(
            [
                {
                    "stdout": json.dumps(
                        [
                            {"code": "SC2006", "level": "style"},
                            {"code": "SC2006", "level": "info"},
                            {"code": "DL3015", "level": "info"},
                        ]
                    )
                }
            ]
        )

        def run(command, **_):
            scanner.exit_code = 0
            return next(responses)

        monkeypatch.setattr(scanner, "_run_subprocess", run)
        table = scanner._hadolint_levels(["hadolint"], [["Dockerfile"]], tmp_path, None)
        assert table == {"DL3015": "info"}

    def test_a_result_without_a_level_is_high(self):
        """ASH's SARIF model defaults Result.level to error, so this is HIGH."""
        raw = copy.deepcopy(_load("positive.sarif"))
        del raw["runs"][0]["results"][0]["level"]
        report = SarifReport.model_validate(raw)
        HadolintScanner.apply_severity_mapping(report, None)
        assert _findings(report)[0][1:3] == ("error", "HIGH")

    def test_an_unknown_level_is_high(self):
        report = SarifReport.model_validate(_load("positive.sarif"))
        report.runs[0].results[0].level = "bogus"
        HadolintScanner.apply_severity_mapping(report, None)
        assert _findings(report)[0][1:3] == ("error", "HIGH")

    def test_user_config_ignores_and_overrides_are_honored(self):
        """configured/.hadolint.yaml ignores DL3007 and makes DL3008 style."""
        report = SarifReport.model_validate(_load("configured.sarif"))
        HadolintScanner.apply_severity_mapping(report, _levels_from("configured.json"))
        by_rule = {f[0]: f for f in _findings(report)}
        assert "DL3007" not in by_rule
        assert by_rule["DL3008"][1:3] == ("none", "INFO")

    def test_negative_fixture_is_clean(self):
        report = SarifReport.model_validate(_load("negative.sarif"))
        assert _findings(report) == []


# ---------------------------------------------------------------------------
# scan() with the subprocess replaced
# ---------------------------------------------------------------------------


class FakeHadolint:
    """Stands in for _run_subprocess: records argv/env, writes captured output."""

    def __init__(
        self,
        sarif: Optional[str] = "positive.sarif",
        json_name: Optional[str] = "positive.json",
        exit_code: int = 0,
        stderr: str = "",
        json_exit_code: int = 0,
        timed_out: bool = False,
        sarif_call_overrides: Optional[Dict[int, dict]] = None,
        stdout_even_on_failure: bool = False,
    ):
        self.sarif, self.json_name = sarif, json_name
        self.exit_code, self.stderr = exit_code, stderr
        self.json_exit_code, self.timed_out = json_exit_code, timed_out
        # Index of a SARIF invocation (0 = first chunk) -> what it does instead.
        self.sarif_call_overrides = sarif_call_overrides or {}
        self.stdout_even_on_failure = stdout_even_on_failure
        self.calls: List[dict] = []

    def __call__(self, scanner):
        def run(command, results_dir=None, env=None, timeout=None, **_):
            self.calls.append({"argv": list(command), "env": env, "timeout": timeout})
            assert "--output" not in command, "nixpkgs' hadolint has no --output"
            fmt = command[command.index("--format") + 1]
            override = {}
            if fmt == "sarif":
                index = sum(1 for c in self.calls if "sarif" in c["argv"]) - 1
                override = self.sarif_call_overrides.get(index, {})
            if self.timed_out or override.get("timed_out"):
                scanner.exit_code = -9
                return {"timed_out": True}
            name, code = (
                (self.sarif, override.get("exit_code", self.exit_code))
                if fmt == "sarif"
                else (self.json_name, self.json_exit_code)
            )
            scanner.exit_code = code
            serve = name and (code == 0 or self.stdout_even_on_failure)
            stdout = (CAPTURED / name).read_text() if serve else ""
            stderr = override.get("stderr", self.stderr)
            return {"returncode": code, "stdout": stdout, "stderr": stderr}

        return run


def _scanner(source: Path, tmp_path: Path, **options) -> HadolintScanner:
    return HadolintScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "out" / "converted",
            config=get_default_config(),
        ),
        config=HadolintScannerConfig(
            enabled=True, options=HadolintScannerConfigOptions(**options)
        ),
    )


@pytest.fixture
def tree(tmp_path) -> Path:
    src = tmp_path / "src"
    (src / "services").mkdir(parents=True)
    (src / "Dockerfile").write_text("FROM ubuntu:latest\n")
    (src / "services" / "api.Dockerfile").write_text("FROM python:3.12\n")
    (src / "services" / "Dockerfile.dockerignore").write_text("x\n")
    (src / "app.py").write_text("print(1)\n")
    return src


@pytest.fixture
def on_path(monkeypatch):
    monkeypatch.setattr(hs, "find_executable", lambda cmd: f"/fake/bin/{cmd}")


def _run(scanner: HadolintScanner, fake: FakeHadolint, monkeypatch, **kw):
    monkeypatch.setattr(scanner, "_run_subprocess", fake(scanner))
    return scanner.scan(
        target=Path(scanner.context.source_dir), target_type="source", **kw
    )


class TestScan:
    def test_files_are_passed_explicitly_after_double_dash(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeHadolint()
        report = _run(scanner, fake, monkeypatch)
        argv = fake.calls[0]["argv"]
        assert argv[0] == "hadolint"
        assert "--no-fail" in argv
        assert argv[argv.index("--format") + 1] == "sarif"
        files = argv[argv.index("--") + 1 :]
        assert files == ["Dockerfile", "services/api.Dockerfile"]
        assert scanner.targets_attempted == 2
        assert scanner.targets_failed == 0
        assert _findings(report) == POSITIVE_EXPECTED

    def test_json_pass_runs_with_the_same_files_and_config(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / ".hadolint.yaml").write_text("ignored: []\n")
        scanner = _scanner(tree, tmp_path)
        fake = FakeHadolint()
        _run(scanner, fake, monkeypatch)
        sarif_argv, json_argv = (c["argv"] for c in fake.calls)
        assert json_argv[json_argv.index("--format") + 1] == "json"
        assert (
            sarif_argv[sarif_argv.index("--") :] == json_argv[json_argv.index("--") :]
        )
        cfg = (tree / ".hadolint.yaml").resolve().as_posix()
        assert sarif_argv[sarif_argv.index("--config") + 1] == cfg
        assert json_argv[json_argv.index("--config") + 1] == cfg

    def test_json_pass_is_skipped_when_there_is_no_note(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeHadolint(sarif="negative.sarif")
        _run(scanner, fake, monkeypatch)
        assert len(fake.calls) == 1

    def test_a_failed_json_pass_keeps_the_sarif_verdict_and_reports_low(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        # The failed pass still prints a usable table, so only the exit-code
        # check can be what keeps the notes at LOW.
        fake = FakeHadolint(json_exit_code=1, stdout_even_on_failure=True)
        report = _run(scanner, fake, monkeypatch)
        assert scanner.exit_code == 0
        assert ("SC2006", "note", "LOW", "Dockerfile", 5) in _findings(report)

    def test_invocation_env_vars_are_removed_and_policy_vars_kept(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        monkeypatch.setenv("HADOLINT_FORMAT", "json")
        monkeypatch.setenv("HADOLINT_NOFAIL", "false")
        monkeypatch.setenv("HADOLINT_IGNORE", "DL3007")
        scanner = _scanner(tree, tmp_path)
        fake = FakeHadolint()
        _run(scanner, fake, monkeypatch)
        for call in fake.calls:
            assert "HADOLINT_FORMAT" not in call["env"]
            assert "HADOLINT_NOFAIL" not in call["env"]
            assert call["env"]["HADOLINT_IGNORE"] == "DL3007"

    def test_no_dockerfiles_is_an_empty_report_with_zero_targets(
        self, tmp_path, on_path, monkeypatch
    ):
        src = tmp_path / "src"
        src.mkdir()
        (src / "app.py").write_text("print(1)\n")
        scanner = _scanner(src, tmp_path)
        fake = FakeHadolint()
        report = _run(scanner, fake, monkeypatch)
        assert fake.calls == []
        assert scanner.targets_attempted == 0
        assert report.runs and report.runs[0].results == []

    def test_global_ignore_paths_remove_a_dockerfile(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path)
        fake = FakeHadolint()
        _run(
            scanner,
            fake,
            monkeypatch,
            global_ignore_paths=[
                IgnorePathWithReason(path="services/**", reason="test")
            ],
        )
        argv = fake.calls[0]["argv"]
        assert argv[argv.index("--") + 1 :] == ["Dockerfile"]

    def test_output_directory_inside_the_source_is_not_scanned(
        self, tree, on_path, monkeypatch
    ):
        out = tree / ".ash" / "ash_output"
        (out / "scanners").mkdir(parents=True)
        (out / "scanners" / "Dockerfile").write_text("FROM x\n")
        scanner = HadolintScanner(
            context=PluginContext(
                source_dir=tree, output_dir=out, config=get_default_config()
            ),
            config=HadolintScannerConfig(enabled=True),
        )
        fake = FakeHadolint()
        _run(scanner, fake, monkeypatch)
        argv = fake.calls[0]["argv"]
        assert argv[argv.index("--") + 1 :] == ["Dockerfile", "services/api.Dockerfile"]

    @pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
    def test_a_symlink_leaving_the_tree_is_not_followed(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        outside = tmp_path / "outside"
        outside.write_text("secret\n")
        (tree / "linked.Dockerfile").symlink_to(outside)
        scanner = _scanner(tree, tmp_path)
        fake = FakeHadolint()
        _run(scanner, fake, monkeypatch)
        argv = fake.calls[0]["argv"]
        assert argv[argv.index("--") + 1 :] == ["Dockerfile", "services/api.Dockerfile"]
        assert not any("outside" in a for a in argv)

    @pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
    def test_a_symlink_inside_the_tree_is_linted_under_its_own_name(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        (tree / "alias.Dockerfile").symlink_to(tree / "Dockerfile")
        scanner = _scanner(tree, tmp_path)
        fake = FakeHadolint()
        _run(scanner, fake, monkeypatch)
        argv = fake.calls[0]["argv"]
        assert argv[argv.index("--") + 1 :] == [
            "Dockerfile",
            "alias.Dockerfile",
            "services/api.Dockerfile",
        ]

    def test_a_config_parse_error_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """hadolint ignores a bad config and exits 0; ASH must not."""
        (tree / ".hadolint.yaml").write_text("ignored: [\n")
        scanner = _scanner(tree, tmp_path)
        fake = FakeHadolint(
            stderr="\"Error parsing your config file in  '.hadolint.yaml':\\n...\""
        )
        with pytest.raises(ScannerError, match="could not parse its configuration"):
            _run(scanner, fake, monkeypatch)

    def test_a_configured_config_file_that_is_missing_fails_the_scan(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, config_file="nope/.hadolint.yaml")
        fake = FakeHadolint()
        with pytest.raises(ScannerError, match="does not exist"):
            _run(scanner, fake, monkeypatch)
        assert fake.calls == []

    def test_a_non_zero_exit_fails_the_scan(self, tree, tmp_path, on_path, monkeypatch):
        scanner = _scanner(tree, tmp_path)
        fake = FakeHadolint(exit_code=1)
        with pytest.raises(ScannerError, match="did not complete"):
            _run(scanner, fake, monkeypatch)

    def test_a_timeout_fails_the_scan_and_says_so(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        scanner = _scanner(tree, tmp_path, scan_timeout=5)
        fake = FakeHadolint(timed_out=True)
        with pytest.raises(ScannerError, match="timed out after 5"):
            _run(scanner, fake, monkeypatch)
        assert 0 < fake.calls[0]["timeout"] <= 5

    def test_missing_binary_is_reported_as_unsatisfied_dependencies(
        self, tree, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(hs, "find_executable", lambda cmd: None)
        scanner = _scanner(tree, tmp_path)
        fake = FakeHadolint()
        assert _run(scanner, fake, monkeypatch) is False
        assert scanner.dependencies_satisfied is False
        assert fake.calls == []


class TestLargeTreesAndBudgets:
    def test_a_long_file_list_is_split_and_the_results_merged(
        self, tmp_path, on_path, monkeypatch
    ):
        src = tmp_path / "src"
        names = []
        for i in range(400):
            d = src / ("d" * 60 + f"{i:03d}")
            d.mkdir(parents=True)
            (d / "Dockerfile").write_text("FROM x\n")
            names.append(f"{d.name}/Dockerfile")
        scanner = _scanner(src, tmp_path)
        fake = FakeHadolint(sarif="positive.sarif", json_name="positive.json")
        report = _run(scanner, fake, monkeypatch)

        sarif_calls = [c for c in fake.calls if "sarif" in c["argv"]]
        assert len(sarif_calls) > 1
        passed = [
            a for c in sarif_calls for a in c["argv"][c["argv"].index("--") + 1 :]
        ]
        assert sorted(passed) == sorted(names)
        for call in fake.calls:
            assert len(" ".join(call["argv"])) <= hs._MAX_COMMAND_LINE_CHARS
        assert len(_findings(report)) == len(POSITIVE_EXPECTED) * len(sarif_calls)
        assert scanner.targets_attempted == 400

    @staticmethod
    def _many(tmp_path: Path, count: int = 400) -> Path:
        src = tmp_path / "src"
        for i in range(count):
            d = src / ("d" * 60 + f"{i:03d}")
            d.mkdir(parents=True)
            (d / "Dockerfile").write_text("FROM x\n")
        return src

    @pytest.mark.parametrize(
        ("override", "message"),
        [
            ({"timed_out": True}, "timed out after"),
            ({"exit_code": 1}, "did not complete"),
            (
                {"stderr": "Error parsing your config file in '.hadolint.yaml'"},
                "could not parse its configuration",
            ),
        ],
        ids=["timeout", "exit", "config-error"],
    )
    def test_a_failure_in_a_later_chunk_fails_the_scan(
        self, tmp_path, on_path, monkeypatch, override, message
    ):
        scanner = _scanner(self._many(tmp_path), tmp_path, scan_timeout=60)
        fake = FakeHadolint(sarif_call_overrides={1: override})
        with pytest.raises(ScannerError, match=message):
            _run(scanner, fake, monkeypatch)
        assert scanner.end_time is not None, "_post_scan must run however it ends"

    def test_the_json_pass_covers_every_chunk(self, tmp_path, on_path, monkeypatch):
        scanner = _scanner(self._many(tmp_path), tmp_path)
        fake = FakeHadolint()
        _run(scanner, fake, monkeypatch)
        sarif = [c["argv"] for c in fake.calls if "sarif" in c["argv"]]
        json_ = [c["argv"] for c in fake.calls if "json" in c["argv"]]
        assert [a[a.index("--") :] for a in sarif] == [
            a[a.index("--") :] for a in json_
        ]

    def test_chunks_count_the_fixed_arguments_against_the_cap(self):
        """A long --config path is part of every command line, so it is budgeted."""
        base = ["hadolint", "--no-fail", "--no-color", "--config", "/" + "c" * 20_000]
        paths = [f"dir{i:04d}/" + "p" * 80 + "/Dockerfile" for i in range(200)]
        chunks = hs._argv_chunks(base, paths)
        assert [p for chunk in chunks for p in chunk] == paths
        for chunk in chunks:
            line = " ".join(HadolintScanner._format_args(base, "sarif", chunk))
            assert len(line) <= hs._MAX_COMMAND_LINE_CHARS

    def test_every_run_shares_one_deadline(self, tree, tmp_path, on_path, monkeypatch):
        """The JSON pass gets what the SARIF pass left, not a fresh budget."""
        clock = iter([100.0, 100.0, 103.0])
        monkeypatch.setattr(hs, "_now", lambda: next(clock))
        scanner = _scanner(tree, tmp_path, scan_timeout=5)
        fake = FakeHadolint()
        _run(scanner, fake, monkeypatch)
        sarif_call, json_call = fake.calls
        assert sarif_call["timeout"] == pytest.approx(5)
        assert json_call["timeout"] == pytest.approx(2)

    def test_an_exhausted_budget_skips_the_json_pass_and_reports_low(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        clock = iter([100.0, 100.0, 106.0])
        monkeypatch.setattr(hs, "_now", lambda: next(clock))
        scanner = _scanner(tree, tmp_path, scan_timeout=5)
        fake = FakeHadolint()
        report = _run(scanner, fake, monkeypatch)
        assert len(fake.calls) == 1
        assert ("SC2006", "note", "LOW", "Dockerfile", 5) in _findings(report)

    @pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
    def test_a_discovered_config_symlinked_outside_the_tree_is_not_used(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        outside = tmp_path / "outside.yaml"
        outside.write_text("ignored: [DL3007]\n")
        (tree / ".hadolint.yaml").symlink_to(outside)
        scanner = _scanner(tree, tmp_path)
        fake = FakeHadolint()
        _run(scanner, fake, monkeypatch)
        # Leaving --config off is not enough: hadolint would read ./.hadolint.yaml
        # from its working directory itself. An explicit empty config stops that.
        argv = fake.calls[0]["argv"]
        stub = Path(argv[argv.index("--config") + 1])
        assert stub.read_text().strip() == "{}"
        assert not stub.resolve().is_relative_to(tree.resolve())
        assert stub != outside

    @pytest.mark.skipif(os.name == "nt", reason="no /dev/zero or FIFOs on Windows")
    @pytest.mark.parametrize("kind", ["device", "fifo", "directory"])
    def test_a_discovered_config_that_is_not_a_regular_file_is_not_read(
        self, tree, tmp_path, on_path, monkeypatch, kind
    ):
        """hadolint would open it itself; /dev/zero exhausts its memory."""
        if kind == "device":
            (tree / ".hadolint.yaml").symlink_to("/dev/zero")
        elif kind == "fifo":
            fifo = tmp_path / "fifo"
            os.mkfifo(fifo)
            (tree / ".hadolint.yml").symlink_to(fifo)
        else:
            (tree / ".hadolint.yaml").mkdir()
        scanner = _scanner(tree, tmp_path)
        fake = FakeHadolint()
        _run(scanner, fake, monkeypatch)
        argv = fake.calls[0]["argv"]
        stub = Path(argv[argv.index("--config") + 1])
        assert stub.read_text().strip() == "{}"

    def test_no_config_at_all_passes_no_config(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        """No --config, so hadolint's user-level config still applies."""
        scanner = _scanner(tree, tmp_path)
        fake = FakeHadolint()
        _run(scanner, fake, monkeypatch)
        assert all("--config" not in call["argv"] for call in fake.calls)

    @pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
    def test_an_explicitly_configured_config_outside_the_tree_is_used(
        self, tree, tmp_path, on_path, monkeypatch
    ):
        outside = tmp_path / "shared" / "hadolint.yaml"
        outside.parent.mkdir()
        outside.write_text("ignored: [DL3007]\n")
        scanner = _scanner(tree, tmp_path, config_file=str(outside))
        fake = FakeHadolint()
        _run(scanner, fake, monkeypatch)
        argv = fake.calls[0]["argv"]
        assert argv[argv.index("--config") + 1] == outside.resolve().as_posix()


class TestInstall:
    def test_install_commands_cover_every_published_platform(self, tmp_path):
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
            assert "hadolint" in commands[0]
        assert scanner.get_installation_commands("windows", "arm64") == []


class TestRedistributionNotices:
    """The image ships hadolint (GPL-3.0); its notices must ship with it, current."""

    REPO = Path(__file__).resolve().parents[4]
    DOC_DIR = REPO / "automated_security_helper" / "assets" / "third_party" / "hadolint"

    def test_the_license_is_upstreams_verbatim(self):
        import hashlib

        # sha256 of LICENSE at github.com/hadolint/hadolint tag v2.15.1.
        digest = hashlib.sha256((self.DOC_DIR / "LICENSE").read_bytes()).hexdigest()
        assert (
            digest
            == (
                "589ed823e9a84c56feb95ac58e7cf384626b9cbf4fda2a907bc36e103de1bad2"  # pragma: allowlist secret
            )
        )

    def test_the_source_notice_names_the_pinned_version(self):
        from automated_security_helper.utils.tool_downloads import TOOL_VERSIONS

        text = (self.DOC_DIR / "SOURCE.txt").read_text(encoding="utf-8")
        version = TOOL_VERSIONS["hadolint"]
        assert f"hadolint {version}" in text
        assert f"/releases/tag/{version}" in text
        assert f"/archive/refs/tags/{version}.tar.gz" in text
        assert "hadolint" in (self.DOC_DIR / "ThirdPartyNotices.txt").read_text(
            encoding="utf-8"
        )

    def test_the_dockerfile_installs_the_notices_with_the_binary(self):
        dockerfile = (self.REPO / "Dockerfile").read_text(encoding="utf-8")
        assert (
            "COPY automated_security_helper/assets/third_party/hadolint/ "
            "/usr/share/doc/hadolint/"
        ) in dockerfile

    def test_the_repository_notice_lists_it(self):
        from automated_security_helper.utils.tool_downloads import TOOL_VERSIONS

        notice = (self.REPO / "NOTICE").read_text(encoding="utf-8")
        assert f"hadolint {TOOL_VERSIONS['hadolint']}" in notice
        assert "/usr/share/doc/hadolint/" in notice
