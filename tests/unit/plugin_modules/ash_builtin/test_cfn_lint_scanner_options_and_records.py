"""cfn-lint: option validation, the operator's config file, and what one scan records.

Pinned here against ``CfnLintScanner`` with only ``_run_subprocess`` faked, as
``test_cfn_lint_scanner.py`` does:

* a region or rule id ending in a newline passed the validators (``$`` matches
  before a trailing newline) and was handed to cfn-lint with it;
* a custom rule whose id holds ``_`` or ``-`` was outside every mandatory prefix,
  so a template's own ``ignore_checks`` could turn it off;
* a response's flags, not its ``error`` key, say what happened (a signal death
  read as "could not be started"; a timeout ASH could not end read as killed);
* the base class kept the LARGEST exit code of several invocations, which loses
  cfn-lint's error bit (2 and 4 read as 4); the codes are combined by OR, and a
  failed invocation's code outranks them;
* under an operator's ``ignore_checks: [E]`` the E0003 configuration error was
  dropped, so a template cfn-lint could not open read as linted and clean;
* the operator's ``.cfnlintrc`` ``include_checks`` and ``mandatory_checks`` were
  replaced whole by the command line and silently dropped;
* a ``.cfnlintrc`` that is not UTF-8 escaped the read's ``except`` as a bare
  UnicodeDecodeError; the refused-config warning repeated per invocation;
* a batch was costed by the raw path where the command line carries the
  ``glob.escape``-d one, and the invocation's fixed arguments were not costed at
  all, so a full batch could overrun the command-line budget;
* a URI cfn-lint percent-encoded, or one holding a backslash on POSIX, matched no
  template and kept its absolute form;
* ``exit_code`` was reset to 0 (a target with no template recorded a run);
  failures were recorded twice; stale per-batch files from an earlier run stayed
  beside the report; a damaged template was never named; a target that could not
  be listed raised a bare OSError;
* with no uv, a cfn-lint on PATH was declared satisfied unverified.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    cfn_lint_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_lint_scanner import (
    _ARGV_CHAR_BUDGET,
    _CHECK_PATTERN,
    _REGION_PATTERN,
    CfnLintScanner,
    CfnLintScannerConfig,
    CfnLintScannerConfigOptions,
    _combined_exit_code,
    _invocation_failure,
    mandatory_prefixes,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils import pre_installed_tool, uv_tool_runner
from automated_security_helper.utils.cfn_template_discovery import TemplateDiscovery
from automated_security_helper.utils.config_trust import record_provenance
from automated_security_helper.utils.pre_installed_tool import PreInstalledToolVerdict
from automated_security_helper.utils.subprocess_utils import (
    COULD_NOT_STOP_SUFFIX,
    WAS_KILLED_ENDING,
)
from automated_security_helper.utils.uv_tool_runner import (
    _reset_uv_tool_runner_caches,
)

pytestmark = pytest.mark.unit

#: The uv the real-resolver tests find. The probe spawns it with the process
#: boundary replaced, so nothing is created at this path.
UV_PATH = os.path.abspath("/opt/uv/bin/uv")

FIXTURES = (
    Path(__file__).resolve().parents[3] / "test_data" / "scanners" / "cfn_lint_guard"
)
CAPTURED_COMPLIANT = FIXTURES / "captured" / "cfn-lint-1.57.1-compliant.sarif"


@pytest.fixture
def repo(ash_temp_path) -> Path:
    target = ash_temp_path / "repo"
    shutil.copytree(FIXTURES / "repo", target)
    return target


def _scanner(repo: Path, *, operator: bool = True, **options) -> CfnLintScanner:
    config = get_default_config()
    record_provenance(
        config,
        in_tree=[] if operator else [repo / ".ash" / ".ash.yaml"],
        trusted=AshConfig(),
    )
    context = PluginContext(
        source_dir=repo,
        output_dir=repo / ".ash" / "ash_output",
        work_dir=repo / ".ash" / "ash_output" / "converted",
        config=config,
    )
    return CfnLintScanner(
        context=context,
        config=CfnLintScannerConfig(
            enabled=True, options=CfnLintScannerConfigOptions(**options)
        ),
    )


def _mandatory(args: list) -> list:
    value = next(a for a in args if a.startswith("--mandatory-checks="))
    return value.split("=", 1)[1].split(",")


class _FakeCfnLint:
    """Writes the captured compliant SARIF for each invocation; one code per call."""

    def __init__(self, codes=(0,)):
        self.codes = list(codes)
        self.calls: list = []

    def __call__(self, command, **kwargs):
        self.calls.append(list(command))
        code = self.codes[min(len(self.calls) - 1, len(self.codes) - 1)]
        output = next(
            a.split("=", 1)[1] for a in command if a.startswith("--output-file=")
        )
        Path(output).write_text(CAPTURED_COMPLIANT.read_text(), encoding="utf-8")
        return {"stdout": "", "stderr": "", "returncode": code}


def _run(scanner, fake):
    with (
        patch.object(CfnLintScanner, "validate_plugin_dependencies", return_value=True),
        patch.object(CfnLintScanner, "_run_subprocess", side_effect=fake),
    ):
        return scanner.scan(
            target=Path(scanner.context.source_dir), target_type="source"
        )


class TestValidators:
    def test_a_trailing_newline_is_refused(self):
        assert _REGION_PATTERN.match("us-east-1") is not None
        assert _REGION_PATTERN.match("us-east-1\n") is None
        assert _CHECK_PATTERN.match("W2001") is not None
        assert _CHECK_PATTERN.match("W2001\n") is None

    def test_custom_rule_id_characters_are_in_the_mandatory_prefixes(self):
        prefixes = mandatory_prefixes([])
        assert "_" in prefixes and "-" in prefixes
        with_ignore = mandatory_prefixes(["W2001"])
        assert "W_" in with_ignore and "W-" in with_ignore


class TestInvocationFailureWording:
    def test_a_bare_error_is_still_could_not_be_started(self):
        assert _invocation_failure({"error": "No such file"}) == (
            "cfn-lint could not be started: No such file"
        )
        assert (
            CfnLintScanner._batch_failure(
                {"error": "No such file"}, Path("batch.sarif"), values=()
            )
            == "cfn-lint could not be started: No such file"
        )

    def test_a_timeout_ash_ended_says_killed(self):
        text = CfnLintScanner._batch_failure(
            {"returncode": -9, "timed_out": True}, Path("batch.sarif"), values=()
        )
        assert text == f"cfn-lint timed out{WAS_KILLED_ENDING}"

    def test_a_timeout_ash_could_not_end_says_so(self):
        text = _invocation_failure({"timed_out": True, "returncode": None})
        assert text is not None and text.startswith("cfn-lint timed out")
        assert COULD_NOT_STOP_SUFFIX in text and WAS_KILLED_ENDING not in text

    def test_the_other_flags_are_named(self):
        assert _invocation_failure({"error": "SIGSEGV", "signaled": True}) == (
            "cfn-lint did not finish: SIGSEGV"
        )
        assert _invocation_failure({"error": "disk full", "post_run_error": True}) == (
            "cfn-lint ran, but ASH could not record its output: disk full"
        )
        assert _invocation_failure({"error": "halted", "cancelled": True}) == (
            "cfn-lint was cancelled: halted"
        )
        assert _invocation_failure({"error": "big", "result_rejected": True}) == (
            "cfn-lint's result was rejected: big"
        )
        assert _invocation_failure({"returncode": 0}) is None


class TestCombinedExitCode:
    def test_completed_runs_combine_by_or(self):
        assert _combined_exit_code([2, 4]) == 6
        assert _combined_exit_code([0, 0]) == 0
        assert _combined_exit_code([8, 2, 4]) == 14

    def test_a_failed_invocation_outranks_the_completed_ones(self):
        assert _combined_exit_code([2, 1, 4]) == 1
        assert _combined_exit_code([2, 32]) == 32
        assert _combined_exit_code([None]) == 1

    def test_no_invocation_is_none(self):
        assert _combined_exit_code([]) is None


class TestOptionArgs:
    def test_the_configuration_error_rule_is_always_mandatory(self, repo):
        args = _scanner(repo, ignore_checks=["E"])._option_args()
        mandatory = _mandatory(args)
        assert any("E0003".startswith(prefix) for prefix in mandatory)
        assert not any("E3002".startswith(prefix) for prefix in mandatory)

    def test_the_operators_file_include_and_mandatory_checks_apply(
        self, repo, tmp_path
    ):
        rc = tmp_path / "operator" / ".cfnlintrc"
        rc.parent.mkdir()
        rc.write_text(
            "include_checks:\n  - I\nmandatory_checks:\n  - W2001\n  - --bad\n",
            encoding="utf-8",
        )
        args = _scanner(repo, config_file=str(rc))._option_args()
        start = args.index("--include-checks") + 1
        assert args[start] == "I"
        assert "W2001" in _mandatory(args)
        assert "--bad" not in args

    def test_a_file_that_is_not_utf8_stops_the_scan(self, repo, tmp_path):
        rc = tmp_path / "operator" / ".cfnlintrc"
        rc.parent.mkdir()
        rc.write_bytes(b"\xff\xfe\x00ignore_checks: [W]\n")
        with pytest.raises(ScannerError, match="could not read"):
            _scanner(repo, config_file=str(rc))._option_args()

    def test_a_refused_config_file_is_warned_about_once(self, repo, caplog):
        scanner = _scanner(repo, operator=False, config_file=".cfnlintrc")
        with caplog.at_level("WARNING", logger="ash"):
            scanner._option_args()
            scanner._option_args()
        assert caplog.text.count("Ignoring scanners.cfn-lint.options.config_file") == 1


class TestBatches:
    def test_a_path_is_costed_as_escaped(self):
        paths = ["a[1].yaml", "b.yaml"]
        # glob.escape wraps only "[" (and "*", "?"): a[1].yaml becomes a[[]1].yaml,
        # 11 characters. Raw: 10 + 1 + 6 + 1 = 17 fits 18; escaped: 12 + 7 = 19
        # does not, so a budget of 18 splits the pair only under the escaped cost.
        assert CfnLintScanner.batches(paths, budget=18) == [["a[1].yaml"], ["b.yaml"]]
        assert CfnLintScanner.batches(paths, budget=19) == [paths]

    def test_the_fixed_arguments_are_costed_too(self, repo, monkeypatch):
        probe = _FakeCfnLint()
        _run(_scanner(repo), probe)
        assert len(probe.calls) == 1
        argv = probe.calls[0]
        files = argv[argv.index("--") + 1 :]
        assert len(files) == 2
        fixed = sum(len(a) + 1 for a in argv[: argv.index("--") + 1])
        # Room for the first template and one more character: the second does not fit.
        monkeypatch.setattr(
            cfn_lint_scanner, "_ARGV_CHAR_BUDGET", fixed + len(files[0]) + 2
        )
        fake = _FakeCfnLint()
        _run(_scanner(repo), fake)
        assert len(fake.calls) == 2
        for call in fake.calls:
            assert sum(len(a) + 1 for a in call) <= cfn_lint_scanner._ARGV_CHAR_BUDGET
        assert cfn_lint_scanner._ARGV_CHAR_BUDGET < _ARGV_CHAR_BUDGET


class TestNormalizeReport:
    def _report(self, uri: str) -> SarifReport:
        return SarifReport.model_validate(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "cfn-lint"}},
                        "results": [
                            {
                                "ruleId": "W2001",
                                "message": {"text": "unused"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": uri}
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        )

    def _uri(self, report: SarifReport) -> str:
        return (
            report.runs[0]
            .results[0]
            .locations[0]
            .physicalLocation.root.artifactLocation.uri
        )

    def test_a_percent_encoded_uri_is_matched(self, repo):
        shown = {"/x/a b.yaml": "a b.yaml"}
        report = _scanner(repo).normalize_report(self._report("/x/a%20b.yaml"), shown)
        assert self._uri(report) == "a b.yaml"

    def test_a_backslash_in_a_name_is_matched_as_written(self, repo):
        shown = {"/x/a\\b.yaml": "a\\b.yaml"}
        report = _scanner(repo).normalize_report(self._report("/x/a\\b.yaml"), shown)
        assert self._uri(report) == "a\\b.yaml"


class TestOneScansRecords:
    def test_a_target_with_no_template_records_no_exit_code(self, ash_temp_path):
        source = ash_temp_path / "src"
        source.mkdir()
        (source / "README.md").write_text("no templates\n", encoding="utf-8")
        scanner = _scanner(source)
        scanner.exit_code = 6
        fake = _FakeCfnLint()
        _run(scanner, fake)
        assert fake.calls == []
        assert scanner.exit_code is None

    def test_two_invocations_codes_are_combined_by_or(self, repo):
        scanner = _scanner(repo, honor_inline_ignores=True)
        fake = _FakeCfnLint(codes=(2, 4))
        report = _run(scanner, fake)
        assert len(fake.calls) == 2
        assert scanner.exit_code == 6
        assert report.runs[0].invocations[0].exitCode == 6

    def test_each_failure_is_recorded_once_with_the_shown_path(self, repo):
        scanner = _scanner(repo)
        found = TemplateDiscovery(
            templates=[repo / "templates" / "compliant.yaml"],
            unmodelable=[(repo / "bad.yaml", "Resources is not a mapping")],
            unparseable=[("broken.yaml", "it could not be parsed")],
        )
        with (
            patch.object(cfn_lint_scanner, "discover_templates", return_value=found),
            patch.object(
                CfnLintScanner, "validate_plugin_dependencies", return_value=True
            ),
            patch.object(
                CfnLintScanner,
                "_run_subprocess",
                return_value={"error": "No such file"},
            ),
        ):
            scanner.scan(target=repo, target_type="source")
        joined = "\n".join(scanner.errors)
        assert joined.count("did not evaluate bad.yaml") == 1
        assert repo.as_posix() not in joined
        assert joined.count("did not evaluate templates/compliant.yaml") == 1
        assert "Skipped broken.yaml: it could not be parsed" in joined
        assert scanner.targets_attempted == 2 and scanner.targets_failed == 2
        # Both failed targets are recorded by name as targets the tool never
        # evaluated, with the shown path, so the run's error record names them.
        assert sorted(scanner.unevaluated_targets) == [
            "bad.yaml",
            "templates/compliant.yaml",
        ]

    def test_stale_and_read_batch_files_do_not_outlive_the_scan(self, repo):
        scanner = _scanner(repo)
        results_dir = Path(scanner.results_dir) / "source"
        results_dir.mkdir(parents=True, exist_ok=True)
        stale = results_dir / "cfn-lint.7.sarif"
        stale.write_text("{}", encoding="utf-8")
        _run(scanner, _FakeCfnLint())
        assert not stale.exists()
        assert sorted(p.name for p in results_dir.glob("cfn-lint*.sarif")) == [
            "cfn-lint.sarif"
        ]

    def test_a_target_that_cannot_be_listed_is_a_scanner_error(self, repo):
        scanner = _scanner(repo)
        with (
            patch.object(
                Path, "iterdir", side_effect=PermissionError(13, "Permission denied")
            ),
            pytest.raises(ScannerError, match="cannot list"),
        ):
            scanner.scan(target=repo, target_type="source")


class TestBinaryOnPathWithoutUv:
    def _check(self, repo, checked):
        scanner = _scanner(repo)
        with (
            patch.object(
                CfnLintScanner, "resolve_deferred_tool_version", return_value=None
            ),
            patch.object(
                CfnLintScanner, "_validate_uv_tool_availability", return_value=False
            ),
            patch.object(
                cfn_lint_scanner,
                "get_uv_tool_command",
                return_value=["/usr/bin/cfn-lint"],
            ),
            patch.object(
                pre_installed_tool, "verify_pre_installed_tool", return_value=checked
            ),
        ):
            return scanner, scanner.validate_plugin_dependencies()

    def test_a_verified_binary_runs_directly(self, repo):
        checked = PreInstalledToolVerdict(
            "satisfied", "/usr/bin/cfn-lint", "cfn-lint[sarif]", "ok"
        )
        scanner, accepted = self._check(repo, checked)
        assert accepted is True and scanner.use_uv_tool is False

    def test_a_binary_that_falls_short_is_missing_with_the_reason(self, repo):
        checked = PreInstalledToolVerdict(
            "unsatisfied", "/usr/bin/cfn-lint", "cfn-lint[sarif]", "sarif extra absent"
        )
        scanner, accepted = self._check(repo, checked)
        assert accepted is False
        assert "sarif extra absent" in (scanner.dependency_unavailable_reason or "")

    def test_an_unverifiable_binary_runs_with_a_warning(self, repo, caplog):
        checked = PreInstalledToolVerdict(
            "unverifiable", "/usr/bin/cfn-lint", "cfn-lint[sarif]", "no uv to ask"
        )
        with caplog.at_level("WARNING", logger="ash"):
            scanner, accepted = self._check(repo, checked)
        assert accepted is True and scanner.use_uv_tool is False
        assert "could not be verified" in caplog.text


class TestResolverOfflineMode:
    """The consolidated resolver is asked under the scanner's own offline mode.

    ``options.offline: true`` puts cfn-lint offline while the rest of the run
    stays online (``_scanner_offline``), and the mixin hands that mode to every
    uv call it makes. The two ``get_uv_tool_command`` calls of the dependency
    check passed no ``offline`` at all, so the resolver read ASH's global mode
    alone and probed PyPI online for a scanner the operator had put offline.
    """

    @staticmethod
    def _record(calls):
        def resolver(tool_name, **kwargs):
            calls.append((tool_name, dict(kwargs)))
            return None

        return resolver

    def _uv_absent(self, repo, **opts):
        scanner = _scanner(repo, **opts)
        calls: list = []
        with (
            patch.dict(os.environ, {}, clear=False),
            patch.object(
                CfnLintScanner, "resolve_deferred_tool_version", return_value=None
            ),
            patch.object(
                CfnLintScanner, "_validate_uv_tool_availability", return_value=False
            ),
            patch.object(cfn_lint_scanner, "get_uv_tool_command", self._record(calls)),
        ):
            os.environ.pop("ASH_OFFLINE", None)
            assert scanner.validate_plugin_dependencies() is False
        return calls

    def _install_failed(self, repo, **opts):
        scanner = _scanner(repo, **opts)
        calls: list = []
        with (
            patch.dict(os.environ, {}, clear=False),
            patch.object(
                CfnLintScanner, "resolve_deferred_tool_version", return_value=None
            ),
            patch.object(
                CfnLintScanner, "_validate_uv_tool_availability", return_value=True
            ),
            patch.object(
                CfnLintScanner,
                "_get_tool_installation_info",
                return_value={"available": False},
            ),
            patch.object(CfnLintScanner, "_install_uv_tool", return_value=False),
            patch.object(cfn_lint_scanner, "get_uv_tool_command", self._record(calls)),
        ):
            os.environ.pop("ASH_OFFLINE", None)
            assert scanner.validate_plugin_dependencies() is False
        return calls

    def test_the_uv_absent_branch_passes_the_scanners_offline_mode(self, repo):
        ((asked, kwargs),) = self._uv_absent(repo, offline=True)
        assert asked == "cfn-lint"
        assert kwargs.get("offline") is True

    def test_the_final_fallback_passes_the_scanners_offline_mode(self, repo):
        ((asked, kwargs),) = self._install_failed(repo, offline=True)
        assert asked == "cfn-lint"
        assert kwargs.get("offline") is True

    def test_a_scanner_that_follows_ash_asks_online_when_ash_is(self, repo):
        for calls in (
            self._uv_absent(repo, offline=False),
            self._install_failed(repo, offline=False),
        ):
            ((_, kwargs),) = calls
            assert kwargs.get("offline") is False

    def _real_resolver_probe(self, repo, **opts):
        """Through the real resolver with only the process boundary replaced:
        the probe it spawns, as argv and environment."""
        scanner = _scanner(repo, **opts)
        spawn = MagicMock(
            return_value=subprocess.CompletedProcess([], 0, "v1.57.1\n", "")
        )
        with (
            patch.dict(os.environ, {}, clear=False),
            patch.object(uv_tool_runner, "spawn_run", spawn),
            patch.object(uv_tool_runner, "find_uv_or_none", lambda: UV_PATH),
            patch.object(uv_tool_runner, "find_executable", lambda name: None),
            patch.object(
                CfnLintScanner, "resolve_deferred_tool_version", return_value=None
            ),
            patch.object(
                CfnLintScanner, "_validate_uv_tool_availability", return_value=False
            ),
        ):
            os.environ.pop("ASH_OFFLINE", None)
            os.environ.pop("UV_OFFLINE", None)
            _reset_uv_tool_runner_caches()
            try:
                assert scanner.validate_plugin_dependencies() is True
            finally:
                _reset_uv_tool_runner_caches()
        return spawn.call_args.args[0], spawn.call_args.kwargs["env"]

    def test_the_probe_runs_offline_for_a_scanner_offline_by_its_options(self, repo):
        """The resolver's own probe carries the mode: ``uv tool run --offline``
        with ``UV_OFFLINE`` set, while ASH itself is online."""
        argv, env = self._real_resolver_probe(repo, offline=True)
        assert argv[:4] == [UV_PATH, "tool", "run", "--offline"]
        assert argv[-2:] == ["cfn-lint", "--version"]
        assert env.get("UV_OFFLINE") == "1"

    def test_the_probe_runs_online_for_a_scanner_that_follows_ash(self, repo):
        argv, env = self._real_resolver_probe(repo, offline=False)
        assert "--offline" not in argv
        assert argv[:3] == [UV_PATH, "tool", "run"]
        assert "UV_OFFLINE" not in env


def test_the_captured_fixture_is_read_by_the_fake():
    data = json.loads(CAPTURED_COMPLIANT.read_text(encoding="utf-8"))
    assert data["runs"][0]["results"] == []
