"""checkov: the paths it is given and writes back, and the options it is run with.

Pinned here against ``CheckovScanner`` with no checkov run, as
``test_checkov_skip_path_edges.py`` does:

* the refusal of a target whose link values break checkov's terraform module
  finder walked the tree a second time for its message, and indexed an empty
  list when the links were gone; the operator's own ``skip_path`` values were
  never checked on their own, so a refusal blamed a link they caused;
* a link under ``node_modules`` or a virtualenv got a ``--skip-path`` value of
  its own, though checkov is told to skip those directories whole, and a large
  ``node_modules`` reached the argument-list limit;
* a target that is the filesystem root gave values starting ``//``;
* a path outside the source directory lost its ``..`` climb; a name that is not
  UTF-8 came back as U+FFFD; a scan set that could not be read failed the whole
  report;
* ``CKV_`` variables never reached checkov under the sandbox;
* an empty ``config_file`` named the source directory; an operator file's
  ``framework`` and ``skip-path`` were overridden by ASH's own command line;
* ``--skip-download`` was decided at construction, before ``--offline`` took
  effect; a previous run's reports stayed to be read as this run's; the JSON
  report was rewritten in place, so a failed write left it truncated, and the
  failure was logged at DEBUG;
* the working directory checkov ran in was not the one the paths were rebuilt
  against when the root lay inside the tree; with no uv, a checkov on PATH was
  declared satisfied unverified, and the final fallback left ``use_uv_tool`` on.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess  # nosec B404
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    checkov_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
    CheckovScannerConfig,
    CheckovScannerConfigOptions,
    _link_named_in_refusal,
    _skip_path_root,
    _source_relative_path,
    _under_a_known_ignore_path,
    rewrite_checkov_paths,
)
from automated_security_helper.utils import pre_installed_tool, uv_tool_runner
from automated_security_helper.utils.pre_installed_tool import PreInstalledToolVerdict
from automated_security_helper.utils.uv_tool_runner import (
    _reset_uv_tool_runner_caches,
)

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(os.name == "nt", reason="POSIX paths"),
]

#: The uv the real-resolver tests find. The probe spawns it with the process
#: boundary replaced, so nothing is created at this path.
UV_PATH = os.path.abspath("/opt/uv/bin/uv")

PluginContext.model_rebuild()


def _scanner(source: Path, output: Path, **opts) -> CheckovScanner:
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    return CheckovScanner(
        context=context,
        config=CheckovScannerConfig(options=CheckovScannerConfigOptions(**opts)),
    )


def _sarif(*uris):
    return {
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "CKV_TEST",
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": uri}}}
                        ],
                    }
                    for uri in uris
                ]
            }
        ]
    }


def _uris(document):
    return [
        location["physicalLocation"]["artifactLocation"]["uri"]
        for run in document["runs"]
        for result in run["results"]
        for location in result["locations"]
    ]


def _skip_values(argv):
    values = [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "--skip-path"]
    values.extend(
        a[len("--skip-path=") :] for a in argv if a.startswith("--skip-path=")
    )
    return values


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover
        pytest.skip(f"symlink creation unavailable: {exc}")


class TestHelpers:
    def test_the_named_link_is_taken_from_the_given_list(self, tmp_path):
        with patch.object(
            checkov_scanner, "file_links_leaving_tree", side_effect=AssertionError
        ):
            assert _link_named_in_refusal(tmp_path, ["a.tf", "b (1).tf"]) == "b (1).tf"
            assert _link_named_in_refusal(tmp_path, ["a.tf"]) == "a.tf"
            assert "leaves the scanned tree" in _link_named_in_refusal(tmp_path, [])

    def test_links_under_known_ignore_directories_are_recognized(self):
        assert _under_a_known_ignore_path("node_modules/pkg/link.tf")
        assert _under_a_known_ignore_path("sub/venv/link.tf")
        assert _under_a_known_ignore_path(".venv/link.tf")
        assert not _under_a_known_ignore_path("src/node_modules.tf")
        assert not _under_a_known_ignore_path("node_modules")

    def test_the_root_target_has_no_trailing_slash(self):
        assert _skip_path_root(Path("/")) == ""
        assert _skip_path_root(Path("/x/y")) == "/x/y"

    def test_a_path_outside_the_working_directory_keeps_its_climb(self):
        assert _source_relative_path("/x/elsewhere/a.tf", "/x/src") == (
            "/../elsewhere/a.tf"
        )
        assert _source_relative_path("/x/src/sub/a.tf", "/x/src") == "/sub/a.tf"


class TestLinkSkipValues:
    def test_a_link_under_node_modules_gets_no_value_of_its_own(self, tmp_path):
        outside = tmp_path / "outside.tf"
        outside.write_text("", encoding="utf-8")
        source = tmp_path / "src"
        (source / "node_modules" / "pkg").mkdir(parents=True)
        (source / "app").mkdir()
        _symlink_or_skip(source / "node_modules" / "pkg" / "link.tf", outside)
        _symlink_or_skip(source / "app" / "link.tf", outside)
        assert CheckovScanner._links_leaving_tree(source) == ["app/link.tf"]

    def test_the_filesystem_root_gives_single_slash_values(self, tmp_path):
        scanner = _scanner(tmp_path / "src", tmp_path / "out")
        values = scanner._link_skip_patterns(Path("/"), ["etc/x.tf"])
        assert values == ["^/etc/x[.]tf$"]

    def test_the_operators_skip_path_is_named_when_it_breaks_the_module_finder(
        self, tmp_path
    ):
        source = tmp_path / "src"
        source.mkdir()
        (source / "main.tf").write_text("", encoding="utf-8")
        scanner = _scanner(
            source,
            tmp_path / "out",
            skip_path=[IgnorePathWithReason(path="vendor(", reason="broken")],
        )
        with pytest.raises(ScannerError, match="skip_path"):
            scanner._execute_scan(source, "source", [])


class TestRewrittenPaths:
    def test_a_name_that_is_not_utf8_round_trips(self, tmp_path):
        source = tmp_path / "repo"
        source.mkdir()
        # %E9 is a lone latin-1 byte, not UTF-8; the file need not exist.
        document = _sarif(source.as_posix().lstrip("/") + "/caf%E9.tf")
        rewrite_checkov_paths(document, ran_in="/", source_dir=str(source))
        assert _uris(document) == ["caf%E9.tf"]

    def test_a_scan_set_that_cannot_be_read_does_not_fail_the_report(self, tmp_path):
        source = tmp_path / "repo"
        source.mkdir()

        def broken():
            raise OSError("scan set unreadable")

        document = _sarif(source.as_posix().lstrip("/") + "/missing.tf")
        rewrite_checkov_paths(
            document, ran_in="/", source_dir=str(source), scanned_files=broken
        )
        assert _uris(document) == ["missing.tf"]


def test_ckv_variables_reach_checkov_under_the_sandbox():
    assert "CKV_" in CheckovScanner.sandbox_requirements.env_prefixes
    assert "CHECKOV_" in CheckovScanner.sandbox_requirements.env_prefixes


class TestConfigFile:
    def test_an_empty_config_file_names_no_file(self, tmp_path, caplog):
        source = tmp_path / "src"
        source.mkdir()
        with caplog.at_level(logging.WARNING, logger="ash"):
            scanner = _scanner(source, tmp_path / "out", config_file="  ")
        assert [a for a in scanner.args.extra_args if a.key == "--config-file"] == []
        assert "empty scanners.checkov.options.config_file" in caplog.text

    def test_the_operators_file_framework_and_skip_path_reach_the_command_line(
        self, tmp_path
    ):
        source = tmp_path / "src"
        source.mkdir()
        config = tmp_path / "conf" / ".checkov.yaml"
        config.parent.mkdir()
        config.write_text(
            "framework:\n  - terraform\nskip-path:\n  - vendor/\n", encoding="utf-8"
        )
        scanner = _scanner(source, tmp_path / "out", config_file=str(config))
        frameworks = [
            a.value for a in scanner.args.extra_args if a.key == "--framework"
        ]
        assert frameworks == ["terraform"]
        skips = [
            a.key[len("--skip-path=") :]
            for a in scanner.args.extra_args
            if a.key.startswith("--skip-path=")
        ]
        assert "vendor/" in skips

    def test_an_explicit_frameworks_option_outranks_the_file(self, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        config = tmp_path / "conf" / ".checkov.yaml"
        config.parent.mkdir()
        config.write_text("framework:\n  - terraform\n", encoding="utf-8")
        scanner = _scanner(
            source,
            tmp_path / "out",
            config_file=str(config),
            frameworks=["cloudformation"],
        )
        frameworks = [
            a.value for a in scanner.args.extra_args if a.key == "--framework"
        ]
        assert frameworks == ["cloudformation"]


class TestOneScansArguments:
    def test_skip_download_follows_the_offline_mode_at_scan_time(self, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        (source / "main.tf").write_text("", encoding="utf-8")
        scanner = _scanner(source, tmp_path / "out")
        assert not any(a.key == "--skip-download" for a in scanner.args.extra_args)
        with patch.object(CheckovScanner, "_scanner_offline", return_value=True):
            argv, _, _ = scanner._execute_scan(source, "source", [])
        assert "--skip-download" in argv
        with patch.object(CheckovScanner, "_scanner_offline", return_value=False):
            argv, _, _ = scanner._execute_scan(source, "source", [])
        assert "--skip-download" not in argv

    def test_a_previous_runs_reports_are_removed_before_the_run(self, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        (source / "main.tf").write_text("", encoding="utf-8")
        scanner = _scanner(source, tmp_path / "out")
        results_dir = Path(scanner.results_dir) / "source"
        results_dir.mkdir(parents=True, exist_ok=True)
        stale_sarif = results_dir / "results_sarif.sarif"
        stale_json = results_dir / "results_json.json"
        stale_sarif.write_text("{}", encoding="utf-8")
        stale_json.write_text("{}", encoding="utf-8")
        _, results_file, _ = scanner._execute_scan(source, "source", [])
        assert results_file == stale_sarif
        assert not stale_sarif.exists() and not stale_json.exists()

    def test_the_working_directory_is_kept_for_the_rewrite(self, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        scanner = _scanner(source, tmp_path / "out")
        results_dir = Path(scanner.results_dir) / "source"
        assert scanner._checkov_cwd is None
        chosen = scanner._subprocess_cwd(results_dir)
        assert scanner._checkov_cwd == chosen == Path("/")


class TestJsonReportRewrite:
    def _results(self, scanner) -> Path:
        results_dir = Path(scanner.results_dir) / "source"
        results_dir.mkdir(parents=True, exist_ok=True)
        results_file = results_dir / "results_sarif.sarif"
        results_file.write_text(
            json.dumps({"version": "2.1.0", "runs": []}), encoding="utf-8"
        )
        return results_file

    def test_the_json_report_is_rewritten_with_no_leftover(self, tmp_path):
        source = tmp_path / "src"
        source.mkdir()
        (source / "main.tf").write_text("", encoding="utf-8")
        scanner = _scanner(source, tmp_path / "out")
        results_file = self._results(scanner)
        json_report = results_file.parent / "results_json.json"
        json_report.write_text(
            json.dumps(
                {
                    "results": {
                        "failed_checks": [
                            {
                                "file_abs_path": (source / "main.tf").as_posix(),
                                "repo_file_path": "/wrong/main.tf",
                            }
                        ]
                    }
                }
            ),
            encoding="utf-8",
        )
        scanner._read_results_file(results_file)
        rewritten = json.loads(json_report.read_text(encoding="utf-8"))
        assert rewritten["results"]["failed_checks"][0]["repo_file_path"] == "/main.tf"
        assert sorted(p.name for p in results_file.parent.iterdir()) == [
            "results_json.json",
            "results_sarif.sarif",
        ]

    def test_a_json_report_that_cannot_be_rewritten_is_a_warning(
        self, tmp_path, caplog
    ):
        source = tmp_path / "src"
        source.mkdir()
        scanner = _scanner(source, tmp_path / "out")
        results_file = self._results(scanner)
        (results_file.parent / "results_json.json").write_text(
            "{not json", encoding="utf-8"
        )
        with caplog.at_level(logging.WARNING, logger="ash"):
            scanner._read_results_file(results_file)
        assert "Could not rewrite the paths" in caplog.text
        assert any(r.levelno == logging.WARNING for r in caplog.records)

    def test_the_json_report_is_written_through_the_atomic_guard(self, tmp_path):
        """The rewrite is staged and renamed by fs_guard's atomic form.

        A staging file written by hand and renamed with ``os.replace`` was a write
        below the output directory that the output-writers audit
        (tests/unit/utils/test_output_writers_use_fs_guard.py) found unguarded; the
        atomic form stages, renames and cleans up itself, and leaves no sibling.
        """
        source = tmp_path / "src"
        source.mkdir()
        scanner = _scanner(source, tmp_path / "out")
        results_file = self._results(scanner)
        json_report = results_file.parent / "results_json.json"
        document = {"results": {"failed_checks": []}}
        json_report.write_text(json.dumps(document), encoding="utf-8")
        with patch.object(
            checkov_scanner,
            "open_for_atomic_write",
            wraps=checkov_scanner.open_for_atomic_write,
        ) as atomic:
            scanner._read_results_file(results_file)
        atomic.assert_called_once()
        assert Path(atomic.call_args.args[0]) == json_report
        assert json.loads(json_report.read_text(encoding="utf-8")) == document
        assert sorted(p.name for p in results_file.parent.iterdir()) == [
            "results_json.json",
            "results_sarif.sarif",
        ]


class TestDependencyFallbacks:
    def _without_uv(self, tmp_path, checked):
        scanner = _scanner(tmp_path / "src", tmp_path / "out")
        with (
            patch.object(
                CheckovScanner, "resolve_deferred_tool_version", return_value=None
            ),
            patch.object(
                CheckovScanner, "_validate_uv_tool_availability", return_value=False
            ),
            patch.object(
                checkov_scanner,
                "get_uv_tool_command",
                return_value=["/usr/bin/checkov"],
            ),
            patch.object(
                pre_installed_tool, "verify_pre_installed_tool", return_value=checked
            ),
        ):
            return scanner, scanner.validate_plugin_dependencies()

    def test_a_verified_binary_runs_directly(self, tmp_path):
        checked = PreInstalledToolVerdict(
            "satisfied", "/usr/bin/checkov", "checkov>=3.2.0,<4.0.0", "ok"
        )
        scanner, accepted = self._without_uv(tmp_path, checked)
        assert accepted is True and scanner.use_uv_tool is False

    def test_a_binary_that_falls_short_is_missing(self, tmp_path):
        checked = PreInstalledToolVerdict(
            "unsatisfied", "/usr/bin/checkov", "checkov>=3.2.0,<4.0.0", "too old"
        )
        scanner, accepted = self._without_uv(tmp_path, checked)
        assert accepted is False
        assert "too old" in (scanner.dependency_unavailable_reason or "")

    def test_the_final_fallback_runs_a_path_binary_directly(self, tmp_path):
        scanner = _scanner(tmp_path / "src", tmp_path / "out")
        with (
            patch.object(
                CheckovScanner, "resolve_deferred_tool_version", return_value=None
            ),
            patch.object(
                CheckovScanner, "_validate_uv_tool_availability", return_value=True
            ),
            patch.object(
                CheckovScanner,
                "_get_tool_installation_info",
                return_value={"available": False},
            ),
            patch.object(CheckovScanner, "_install_uv_tool", return_value=False),
            patch.object(
                checkov_scanner,
                "get_uv_tool_command",
                return_value=["/usr/bin/checkov"],
            ),
        ):
            assert scanner.validate_plugin_dependencies() is True
        assert scanner.use_uv_tool is False
        assert scanner.dependencies_satisfied is True


class TestResolverOfflineMode:
    """The consolidated resolver is asked under the scanner's own offline mode.

    ``options.offline: true`` puts checkov offline while the rest of the run
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

    def _uv_absent(self, tmp_path, **opts):
        scanner = _scanner(tmp_path / "src", tmp_path / "out", **opts)
        calls: list = []
        with (
            patch.dict(os.environ, {}, clear=False),
            patch.object(
                CheckovScanner, "resolve_deferred_tool_version", return_value=None
            ),
            patch.object(
                CheckovScanner, "_validate_uv_tool_availability", return_value=False
            ),
            patch.object(checkov_scanner, "get_uv_tool_command", self._record(calls)),
        ):
            os.environ.pop("ASH_OFFLINE", None)
            assert scanner.validate_plugin_dependencies() is False
        return calls

    def _install_failed(self, tmp_path, **opts):
        scanner = _scanner(tmp_path / "src", tmp_path / "out", **opts)
        calls: list = []
        with (
            patch.dict(os.environ, {}, clear=False),
            patch.object(
                CheckovScanner, "resolve_deferred_tool_version", return_value=None
            ),
            patch.object(
                CheckovScanner, "_validate_uv_tool_availability", return_value=True
            ),
            patch.object(
                CheckovScanner,
                "_get_tool_installation_info",
                return_value={"available": False},
            ),
            patch.object(CheckovScanner, "_install_uv_tool", return_value=False),
            patch.object(checkov_scanner, "get_uv_tool_command", self._record(calls)),
        ):
            os.environ.pop("ASH_OFFLINE", None)
            assert scanner.validate_plugin_dependencies() is False
        return calls

    def test_the_uv_absent_branch_passes_the_scanners_offline_mode(self, tmp_path):
        ((asked, kwargs),) = self._uv_absent(tmp_path, offline=True)
        assert asked == "checkov"
        assert kwargs.get("offline") is True

    def test_the_final_fallback_passes_the_scanners_offline_mode(self, tmp_path):
        ((asked, kwargs),) = self._install_failed(tmp_path, offline=True)
        assert asked == "checkov"
        assert kwargs.get("offline") is True

    def test_a_scanner_that_follows_ash_asks_online_when_ash_is(self, tmp_path):
        for calls in (
            self._uv_absent(tmp_path, offline=False),
            self._install_failed(tmp_path, offline=False),
        ):
            ((_, kwargs),) = calls
            assert kwargs.get("offline") is False

    def _real_resolver_probe(self, tmp_path, **opts):
        """Through the real resolver with only the process boundary replaced:
        the probe it spawns, as argv and environment."""
        scanner = _scanner(tmp_path / "src", tmp_path / "out", **opts)
        spawn = MagicMock(
            return_value=subprocess.CompletedProcess([], 0, "checkov 3.2.0\n", "")
        )
        with (
            patch.dict(os.environ, {}, clear=False),
            patch.object(uv_tool_runner, "spawn_run", spawn),
            patch.object(uv_tool_runner, "find_uv_or_none", lambda: UV_PATH),
            patch.object(uv_tool_runner, "find_executable", lambda name: None),
            patch.object(
                CheckovScanner, "resolve_deferred_tool_version", return_value=None
            ),
            patch.object(
                CheckovScanner, "_validate_uv_tool_availability", return_value=False
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

    def test_the_probe_runs_offline_for_a_scanner_offline_by_its_options(
        self, tmp_path
    ):
        """The resolver's own probe carries the mode: ``uv tool run --offline``
        with ``UV_OFFLINE`` set, while ASH itself is online."""
        argv, env = self._real_resolver_probe(tmp_path, offline=True)
        assert argv[:4] == [UV_PATH, "tool", "run", "--offline"]
        assert argv[-2:] == ["checkov", "--version"]
        assert env.get("UV_OFFLINE") == "1"

    def test_the_probe_runs_online_for_a_scanner_that_follows_ash(self, tmp_path):
        argv, env = self._real_resolver_probe(tmp_path, offline=False)
        assert "--offline" not in argv
        assert argv[:3] == [UV_PATH, "tool", "run"]
        assert "UV_OFFLINE" not in env
