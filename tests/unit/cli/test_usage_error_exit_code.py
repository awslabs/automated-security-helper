# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every usage error of every ``ash`` command exits one code of its own.

click exits 2 for a usage error -- an unknown option or command, a value outside an
option's choices, a missing required option -- and 2 is ASH's code for actionable
findings; 1 is its code for a failed or incomplete scan. Every usage error, click's
and ASH's own refusals of an invocation alike, exits a third code,
``ASH_EXIT_USAGE_ERROR``, so a CI gate that treats 2 as "the scan found problems"
does not read a mistyped flag as a scan that ran and found something, and the
operator sees that the command line is the problem.

The value is spelled once below, as the published contract, and every other
assertion goes through that name.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from tests.utils.env_assertions import environ_value
from tests.utils.process_guard import refuse_process_starts

pytestmark = pytest.mark.unit

#: The published value of ``ASH_EXIT_USAGE_ERROR``. Pinned here, once, because it is
#: a contract callers branch on; ``test_the_code_is_published`` ties it to the name.
USAGE_ERROR_EXIT = 5

#: The published value of ``ash dependencies install``'s bad-selection code
#: (``ASH_EXIT_BAD_SELECTION``): an unknown --tool, and a --plugin-type that is none
#: of the three, keep 2.
BAD_SELECTION_EXIT = 2


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    """The output without color codes, panel borders or rich's line wrapping."""
    text = _ANSI.sub("", text)
    return " ".join(text.replace("│", " ").replace("╭", " ").replace("╰", " ").split())


@pytest.fixture
def in_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    for name in ("ASH_SOURCE_DIR", "ASH_OUTPUT_DIR", "ASH_MODE", "ASH_SCANNERS"):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "src").mkdir()
    return tmp_path


def _invoke(args, **kwargs):
    return CliRunner().invoke(app, list(args), **kwargs)


@pytest.fixture
def started_processes(monkeypatch: pytest.MonkeyPatch) -> list:
    """Every process start a test tried; each one raises.

    For the tests here that run a whole command in this process: each stubs what
    the command would run, so a process means a real tool ran, or an index install.
    The routes it covers are tests/utils/process_guard.py's, each pinned by a case in
    TestTheProcessGuardSeesEveryStart.
    """
    return refuse_process_starts(monkeypatch)


#: Bound before any test runs, as a module that imports Popen by name would hold it.
_PREBOUND_POPEN = subprocess.Popen

#: Where a prebound Popen's start lands, in the running interpreter's own
#: spelling - the same predicate the guard patches by: where subprocess binds
#: _fork_exec (3.11+), Popen calls it there by name; where it does not, the
#: call reaches _posixsubprocess.fork_exec itself. On the by-attribute
#: interpreters the case therefore pins the _posixsubprocess patch, not the
#: subprocess._fork_exec one, which does not exist there.
_PREBOUND_POPEN_PATCH_POINT = (
    "subprocess._fork_exec"
    if hasattr(subprocess, "_fork_exec")
    else "_posixsubprocess.fork_exec"
)

#: A program that does not exist. An exec* case names it, so if its patch were
#: dropped the call would fail with an OSError instead of replacing the test
#: process (under -n 0, pytest itself) with another program.
_NO_SUCH_PROGRAM = "/nonexistent/ash-guard-test-program"


def _fork_and_exit(fork):
    """Call *fork*; a child exits at once and the parent reaps it.

    So a fork the guard missed fails its case instead of leaving a second copy of
    the test worker running tests (measured with the fixture reverted: the orphan
    kept running tests after pytest exited).
    """
    result = fork()
    pid = result[0] if isinstance(result, tuple) else result
    if pid == 0:
        os._exit(0)
    os.waitpid(pid, 0)


def _reaped(pid):
    os.waitpid(pid, 0)


def _spawn_with_multiprocessing():
    from multiprocessing import util

    _reaped(util.spawnv_passfds(_true_program(), ["true"], []))


def _start_with_forkserver():
    import multiprocessing

    process = multiprocessing.get_context("forkserver").Process(target=os.getpid)
    process.start()
    process.join()


def _true_program():
    """The absolute path of true(1), for the calls that do not search PATH."""
    import shutil

    return shutil.which("true") or "/bin/true"


#: One case per patch point in started_processes, with the patch that must catch
#: it: each fails if that patch is dropped.
_PROCESS_STARTS = [
    pytest.param(
        lambda: subprocess.run(["true"], check=False), "subprocess.Popen", id="run"
    ),
    pytest.param(
        lambda: _PREBOUND_POPEN(["true"]).wait(),
        _PREBOUND_POPEN_PATCH_POINT,
        id="prebound-popen",
    ),
    pytest.param(
        _spawn_with_multiprocessing,
        "_posixsubprocess.fork_exec",
        id="multiprocessing-spawn",
    ),
    pytest.param(_start_with_forkserver, "multiprocessing forkserver", id="forkserver"),
    pytest.param(lambda: os.system("true"), "os.system", id="os-system"),
    pytest.param(
        lambda: _reaped(os.posix_spawn(_true_program(), ["true"], {})),
        "os.posix_spawn",
        id="posix-spawn",
    ),
    pytest.param(
        lambda: _reaped(os.posix_spawnp("true", ["true"], dict(os.environ))),
        "os.posix_spawnp",
        id="posix-spawnp",
    ),
    pytest.param(lambda: _fork_and_exit(os.fork), "os.fork", id="fork"),
    pytest.param(lambda: _fork_and_exit(os.forkpty), "os.forkpty", id="forkpty"),
    pytest.param(lambda: os.execl(_NO_SUCH_PROGRAM, "x"), "os.execl", id="execl"),
    pytest.param(
        lambda: os.execle(_NO_SUCH_PROGRAM, "x", {}), "os.execle", id="execle"
    ),
    pytest.param(lambda: os.execlp(_NO_SUCH_PROGRAM, "x"), "os.execlp", id="execlp"),
    pytest.param(
        lambda: os.execlpe(_NO_SUCH_PROGRAM, "x", {}), "os.execlpe", id="execlpe"
    ),
    pytest.param(lambda: os.execv(_NO_SUCH_PROGRAM, ["x"]), "os.execv", id="execv"),
    pytest.param(
        lambda: os.execve(_NO_SUCH_PROGRAM, ["x"], {}), "os.execve", id="execve"
    ),
    pytest.param(lambda: os.execvp(_NO_SUCH_PROGRAM, ["x"]), "os.execvp", id="execvp"),
    pytest.param(
        lambda: os.execvpe(_NO_SUCH_PROGRAM, ["x"], {}), "os.execvpe", id="execvpe"
    ),
    pytest.param(
        lambda: __import__("posix").system("true"), "posix.system", id="posix-system"
    ),
    pytest.param(
        lambda: _fork_and_exit(__import__("posix").fork), "posix.fork", id="posix-fork"
    ),
    pytest.param(
        lambda: _reaped(__import__("posix").posix_spawn(_true_program(), ["true"], {})),
        "posix.posix_spawn",
        id="posix-posix-spawn",
    ),
    pytest.param(
        lambda: _reaped(__import__("posix").posix_spawnp("true", ["true"], {})),
        "posix.posix_spawnp",
        id="posix-posix-spawnp",
    ),
    pytest.param(
        lambda: _fork_and_exit(__import__("posix").forkpty),
        "posix.forkpty",
        id="posix-forkpty",
    ),
    pytest.param(
        lambda: __import__("posix").execv(_NO_SUCH_PROGRAM, ["x"]),
        "posix.execv",
        id="posix-execv",
    ),
    pytest.param(
        lambda: __import__("posix").execve(_NO_SUCH_PROGRAM, ["x"], {}),
        "posix.execve",
        id="posix-execve",
    ),
]


@pytest.mark.skipif(os.name == "nt", reason="the POSIX process primitives")
class TestTheProcessGuardSeesEveryStart:
    """started_processes has to see a process however it is started."""

    @pytest.mark.parametrize("start, patch_point", _PROCESS_STARTS)
    def test_is_refused_and_recorded(self, started_processes, start, patch_point):
        with pytest.raises(AssertionError, match="the test started a process") as e:
            start()

        assert f"({patch_point})" in str(e.value), str(e.value)
        assert len(started_processes) == 1


class TestTheProcessGuardLeavesPopenAClass:
    """Code imported under the guard may use subprocess.Popen as the class it is
    without starting anything: an annotation such as ``subprocess.Popen[bytes]``,
    which Python evaluates at definition before 3.14, or an isinstance check."""

    def test_popen_can_still_be_subscripted(self, started_processes):
        assert subprocess.Popen[bytes].__args__ == (bytes,)
        assert started_processes == []

    def test_popen_is_still_a_popen_class(self, started_processes):
        assert isinstance(subprocess.Popen, type)
        assert issubclass(subprocess.Popen, _PREBOUND_POPEN)

    def test_a_popen_made_before_the_guard_is_still_a_popen(self, started_processes):
        """Made without running __init__, so no process starts; marked as having
        no child so that its __del__ has nothing to do."""
        made_before = object.__new__(_PREBOUND_POPEN)
        made_before._child_created = False
        assert isinstance(made_before, subprocess.Popen)
        assert not isinstance(object(), subprocess.Popen)

    def test_constructing_popen_is_refused_and_recorded(self, started_processes):
        with pytest.raises(AssertionError, match=r"\(subprocess\.Popen\)"):
            subprocess.Popen(["true"])
        assert started_processes == [["true"]]

    def test_a_module_naming_popen_bytes_in_an_annotation_loads_under_it(
        self, started_processes
    ):
        """mcp's Windows helpers annotate a parameter as subprocess.Popen[bytes], and
        config_sources imports them (through cli.mcp.sandbox) the first time a test
        in a worker loads a config. Loaded afresh under the guard, the module must
        load."""
        import importlib.util

        spec = importlib.util.find_spec("mcp.os.win32.utilities")
        assert spec is not None and spec.origin, (
            "mcp's Windows helpers are not installed"
        )
        fresh = importlib.util.spec_from_file_location(
            "_win32_utilities_loaded_under_the_guard", spec.origin
        )
        module = importlib.util.module_from_spec(fresh)
        fresh.loader.exec_module(module)

        assert hasattr(module, "FallbackProcess")
        assert started_processes == []


class TestTheCodeIsPublished:
    def test_the_constant_and_the_table_agree(self):
        from automated_security_helper.core.constants import (
            ASH_EXIT_CODES,
            ASH_EXIT_USAGE_ERROR,
        )

        assert ASH_EXIT_USAGE_ERROR == USAGE_ERROR_EXIT
        assert ASH_EXIT_CODES[ASH_EXIT_USAGE_ERROR] == "usage error"

    def test_it_is_not_any_other_outcome(self):
        from automated_security_helper.core.constants import ASH_EXIT_CODES

        others = {code for code in ASH_EXIT_CODES if code != USAGE_ERROR_EXIT}
        assert others == {0, 1, 2, 3, 4}, (
            "the usage-error code has to be one no other outcome uses, or a gate "
            "cannot tell a refused command line from a scan result"
        )

    def test_workspace_mode_publishes_the_same_code(self):
        from automated_security_helper.models.workspace import (
            WORKSPACE_EXIT_CODES,
            WorkspaceExitCode,
        )

        assert WorkspaceExitCode.USAGE_ERROR == USAGE_ERROR_EXIT
        assert WORKSPACE_EXIT_CODES[USAGE_ERROR_EXIT] == "usage error"

    def test_every_place_that_names_it_agrees(self, in_tmp, started_processes):
        """The CHANGELOG, the exit-codes reference page, the constants and the
        ash://exit-codes resource each name the usage-error code, and
        ``ash dependencies install``'s bad-selection code for an unknown --tool and a
        --plugin-type that is none of the three; and each of those exits with the
        code named for it."""
        import json

        from automated_security_helper.cli.mcp_server import _build_ash_exit_codes
        from automated_security_helper.core.constants import (
            ASH_EXIT_BAD_SELECTION,
            ASH_EXIT_BAD_SELECTION_MEANING,
            ASH_EXIT_CODES,
        )

        root = Path(__file__).resolve().parents[3]
        changelog = " ".join(
            (root / "CHANGELOG.md").read_text(encoding="utf-8").split()
        )
        # The exit-code tables moved from docs/content/docs/cli-reference.md to
        # the reference section's own page when the docs were restructured.
        reference = (
            root / "docs" / "content" / "reference" / "exit-codes.md"
        ).read_text(encoding="utf-8")
        resource = json.loads(_build_ash_exit_codes())
        install = resource.get("commands", {}).get("ash dependencies install", {})
        bin_path = str(in_tmp / "bin")
        plugin_type_named = "a `--plugin-type` that is none of"
        places = {
            "the CHANGELOG": (
                "A command-line usage error (an unknown option or a bad option value) "
                f"now exits {USAGE_ERROR_EXIT} instead of 2." in changelog
            ),
            "the exit-codes reference's table": re.search(
                rf"^\| {USAGE_ERROR_EXIT} \| A usage error", reference, re.MULTILINE
            )
            is not None,
            "ASH_EXIT_CODES": ASH_EXIT_CODES.get(USAGE_ERROR_EXIT) == "usage error",
            "ash://exit-codes": resource.get(str(USAGE_ERROR_EXIT)) == "usage error",
            "an unknown option": _invoke(["config", "get", "--bogus"]).exit_code
            == USAGE_ERROR_EXIT,
            "a bad option value": _invoke(
                ["build-image", "--build-target", "bogus"]
            ).exit_code
            == USAGE_ERROR_EXIT,
            "the CHANGELOG's bad selection": (
                f"`ash dependencies install --tool` that it cannot select, and "
                f"{plugin_type_named} `converter`, `scanner` and `reporter`, exit "
                f"{BAD_SELECTION_EXIT}" in changelog
            ),
            # The page names the two selections in its opening paragraph, not in
            # a table row of their own.
            # One pattern from the code through both selections, over the page with
            # its whitespace normalized as the CHANGELOG's is, so a re-wrapped
            # paragraph still reads and a phrase elsewhere on the page does not.
            "the exit-codes reference's dependencies install sentence": (
                re.search(
                    rf"Two `ash dependencies install` selections exit "
                    rf"{BAD_SELECTION_EXIT} instead: a `--tool` name[^.|]*, and a "
                    r"`--plugin-type` other than `converter`, `scanner`, or `reporter`",
                    " ".join(reference.split()),
                )
                is not None
            ),
            "ASH_EXIT_BAD_SELECTION": ASH_EXIT_BAD_SELECTION == BAD_SELECTION_EXIT
            and "a --plugin-type that is none of" in ASH_EXIT_BAD_SELECTION_MEANING,
            "ash://exit-codes commands": install.get(str(BAD_SELECTION_EXIT))
            == ASH_EXIT_BAD_SELECTION_MEANING,
            "an unknown --tool": _invoke(
                ["dependencies", "install", "--bin-path", bin_path]
                + ["--tool", "no-such-tool"]
            ).exit_code
            == BAD_SELECTION_EXIT,
            "a --plugin-type that is none of the three": _invoke(
                ["dependencies", "install", "--bin-path", bin_path]
                + ["--plugin-type", "bogus"]
            ).exit_code
            == BAD_SELECTION_EXIT,
        }
        disagree = sorted(place for place, agrees in places.items() if not agrees)
        assert not disagree, f"these do not say the code named for them: {disagree}"
        assert started_processes == [], "a refused command line started a process"


#: click's own usage errors, one per command and per kind of error. None of these
#: does any work: each is refused while the command line is parsed, or by ASH's own
#: `typer.BadParameter` before anything is read.
CLICK_USAGE_ERRORS = [
    pytest.param(["--scaners", "bandit"], "No such option", id="root-unknown-option"),
    pytest.param(["scna"], "No such command", id="unknown-command"),
    pytest.param(["--mode", "bogus"], "Invalid value", id="root-bad-choice"),
    pytest.param(["scan", "--mode", "bogus"], "Invalid value", id="scan-bad-mode"),
    pytest.param(
        ["scan", "--strategy", "sideways"], "Invalid value", id="scan-bad-strategy"
    ),
    pytest.param(
        ["scan", "--shard-index", "first"], "Invalid value", id="scan-not-an-int"
    ),
    pytest.param(
        ["scan", "--no-progress", "--source-dir", "src", "--output-formats", "pdf"],
        "not a valid format",
        id="scan-bad-output-format",
    ),
    pytest.param(["merge"], "Missing option", id="merge-missing-required-option"),
    pytest.param(
        ["merge", "--output-dir", "o", "--results", "r", "--output-formats", "pdf"],
        "pdf",
        id="merge-bad-output-format",
    ),
    pytest.param(["report", "--bogus"], "No such option", id="report-unknown-option"),
    pytest.param(["config"], "Missing command", id="group-without-a-command"),
    pytest.param(["config", "get", "--bogus"], "No such option", id="config-get"),
    pytest.param(["plugin", "list", "--bogus"], "No such option", id="plugin-list"),
    pytest.param(
        ["dependencies", "install", "--bogus"], "No such option", id="dependencies"
    ),
    pytest.param(
        ["inspect", "findings", "--bogus"], "No such option", id="inspect-findings"
    ),
    pytest.param(["mcp", "--bogus"], "No such option", id="mcp"),
    pytest.param(["get-genai-guide", "--bogus"], "No such option", id="genai-guide"),
    pytest.param(
        ["build-image", "--build-target", "bogus"],
        "Invalid value",
        id="build-image-bad-choice",
    ),
]


@pytest.mark.parametrize("args, fragment", CLICK_USAGE_ERRORS)
def test_a_click_usage_error_exits_the_usage_code(in_tmp, args, fragment):
    result = _invoke(args)

    assert result.exit_code == USAGE_ERROR_EXIT, (
        f"ash {' '.join(args)} exited {result.exit_code}: {result.output}"
    )
    assert fragment in _plain(result.output)
    assert isinstance(result.exception, SystemExit), result.exception


@pytest.mark.parametrize(
    "plugin_types",
    [("nosuch",), ("scanner", "nosuch"), ("scanners",)],
    ids=["unknown", "beside-a-known-one", "plural"],
)
def test_a_plugin_type_outside_the_choices_installs_nothing(
    in_tmp, started_processes, plugin_types
):
    """``ash dependencies install --plugin-type`` took any text, and every value but
    converter and reporter meant scanner, so a mistyped type installed the
    scanners' dependencies and exited 0. A value that is none of the three is
    refused with an unknown --tool's code, ``ash dependencies install``'s
    bad-selection code, before the bin path is made or anything is installed. The
    refusal names the value as "Unknown plugin type(s): <value>" and lists the
    plugin types."""
    bin_path = in_tmp / "bin"
    args = [arg for value in plugin_types for arg in ("--plugin-type", value)]
    result = _invoke(["dependencies", "install", "--bin-path", str(bin_path), *args])

    assert result.exit_code == BAD_SELECTION_EXIT, (
        f"exited {result.exit_code}: {result.output}"
    )
    assert f"Unknown plugin type(s): {plugin_types[-1]}" in result.output
    assert "converter, scanner, reporter" in result.output
    assert not bin_path.exists(), "the install started"
    assert "Installing ASH dependencies" not in result.output
    assert started_processes == [], "the install ran a process"


def test_an_unknown_plugin_type_is_shown_with_its_controls_escaped(
    in_tmp, started_processes
):
    result = _invoke(
        ["dependencies", "install", "--bin-path", str(in_tmp / "bin")]
        + ["--plugin-type", "x\x1b[31mred"]
    )

    assert result.exit_code == BAD_SELECTION_EXIT, (
        f"exited {result.exit_code}: {result.output!r}"
    )
    # The operator's control is shown as text, never written through: the raw
    # sequence is absent and its escape is present. Not "no escape anywhere":
    # the console's own styling carries escapes wherever the environment turns
    # color on (the hosted Windows runners do), and that is not the operator's.
    assert "x\x1b[31mred" not in result.output, repr(result.output)
    assert "x\\x1b[31mred" in result.output, repr(result.output)
    assert started_processes == [], "the install ran a process"


def test_a_cli_json_input_error_exits_the_usage_code(in_tmp):
    document = in_tmp / "params.json"
    document.write_text('{"no_such_parameter": 1}', encoding="utf-8")

    result = _invoke(["scan", "--cli-json-input", str(document)])

    assert result.exit_code == USAGE_ERROR_EXIT, result.output
    assert "unknown key 'no_such_parameter'" in _plain(result.output)


@pytest.mark.parametrize(
    "args",
    [
        ["--help"],
        ["--version"],
        ["scan", "--help"],
        ["scan", "--version"],
        ["config", "--help"],
        ["merge", "--help"],
        ["build-image", "--help"],
        ["mcp", "--help"],
        ["scan", "--generate-cli-skeleton"],
    ],
    ids=lambda args: " ".join(args),
)
def test_help_and_version_exit_zero(in_tmp, args):
    result = _invoke(args)

    assert result.exit_code == 0, result.output


class TestAshsOwnRefusalsOfAnInvocation:
    """The refusals ASH makes itself, before any scanner runs."""

    def _scan(self, *extra):
        with patch("automated_security_helper.cli.scan.run_ash_scan") as run:
            result = _invoke(["scan", "--no-progress", *extra])
        run.assert_not_called()
        return result

    def test_a_missing_source_dir(self, in_tmp):
        result = self._scan("--source-dir", "does-not-exist")

        assert result.exit_code == USAGE_ERROR_EXIT, result.output
        assert "Source directory does not exist" in _plain(result.stderr)

    def test_a_source_dir_that_is_a_file(self, in_tmp):
        (in_tmp / "file.py").write_text("x = 1\n", encoding="utf-8")

        result = self._scan("--source-dir", "file.py")

        assert result.exit_code == USAGE_ERROR_EXIT, result.output

    @pytest.mark.parametrize(
        "shard_args",
        [
            ["--shard-index", "0"],
            ["--shard-count", "2"],
            ["--shard-index", "2", "--shard-count", "2"],
            ["--shard-index", "0", "--shard-count", "2", "--workspace", "auto"],
        ],
        ids=["index-only", "count-only", "out-of-range", "with-workspace"],
    )
    def test_an_unusable_shard_selection(self, in_tmp, shard_args):
        result = self._scan(*shard_args)

        assert result.exit_code == USAGE_ERROR_EXIT, result.output

    def test_workspace_refusals_keep_their_own_code(self, in_tmp):
        """Code 4 is the workspace contract's, so its refusals are not moved."""
        from automated_security_helper.models.workspace import WorkspaceExitCode

        result = self._scan("--dry-run")

        assert result.exit_code == WorkspaceExitCode.WORKSPACE_ERROR, result.output

    def test_a_scanner_selection_that_names_no_scanner(self, in_tmp):
        """``--scanners`` naming nothing that exists is a mistyped argument."""
        from automated_security_helper.core.exceptions import ScannerSelectionError

        with patch(
            "automated_security_helper.core.orchestrator.ASHScanOrchestrator.create",
            side_effect=ScannerSelectionError(
                "None of the requested scanners exist: detect_secrets."
            ),
        ):
            result = _invoke(
                [
                    "scan",
                    "--no-progress",
                    "--source-dir",
                    "src",
                    "--output-dir",
                    "out",
                    "--scanners",
                    "detect_secrets",
                ]
            )

        assert result.exit_code == USAGE_ERROR_EXIT, result.output
        assert "detect_secrets" in _plain(result.output)

    def test_report_with_a_format_no_reporter_has(self, in_tmp):
        from automated_security_helper.models.asharp_model import (
            AshAggregatedResults,
        )

        out = in_tmp / "out"
        out.mkdir()
        (out / "ash_aggregated_results.json").write_text(
            AshAggregatedResults().model_dump_json(by_alias=True), encoding="utf-8"
        )

        result = _invoke(
            ["report", "--output-dir", "out", "--format", "not-a-reporter"]
        )

        assert result.exit_code == USAGE_ERROR_EXIT, result.output
        assert "not-a-reporter" in _plain(result.output)

    def test_dependencies_install_keeps_2_for_a_tool_it_cannot_select(self):
        """Not a usage-error 5: the CLI reference documents 2 for an
        ``ash dependencies install --tool`` this command cannot select."""
        from automated_security_helper.cli.dependencies import EXIT_BAD_SELECTION

        assert EXIT_BAD_SELECTION == 2

    @pytest.mark.parametrize(
        "args, fragment",
        [
            pytest.param(
                ["--transport", "carrier-pigeon"], "--transport", id="transport"
            ),
            pytest.param(
                ["--stateless-http"], "--stateless-http", id="stateless-http-on-stdio"
            ),
            pytest.param(
                ["--auth-header-name", "X-Token"], "auth", id="auth-name-without-value"
            ),
            pytest.param(
                ["--auth-header-value", "secret"], "auth", id="auth-value-without-name"
            ),
            pytest.param(["--verbose", "--quiet"], "quiet", id="verbose-and-quiet"),
            pytest.param(["--debug", "--quiet"], "quiet", id="debug-and-quiet"),
        ],
    )
    def test_mcp_option_validation(self, in_tmp, args, fragment):
        with (
            patch(
                "automated_security_helper.cli.mcp.validate_mcp_dependencies",
                return_value=True,
            ),
            patch("automated_security_helper.cli.mcp_server.run_mcp_server") as run,
        ):
            result = _invoke(["mcp", *args])

        run.assert_not_called()
        assert result.exit_code == USAGE_ERROR_EXIT, result.output
        assert fragment in _plain(result.output).lower()


class TestNamesASHDoesNotKnow:
    """An unknown name is a usage error wherever the command checks it."""

    def test_report_with_an_unknown_format_and_no_results(self, in_tmp):
        """Checked before the results are read: the name is wrong either way."""
        result = _invoke(["report", "--output-dir", "out", "--format", "bogus"])

        assert result.exit_code == USAGE_ERROR_EXIT, result.output
        assert "Reporter plugin 'bogus' not found" in _plain(result.output)

    def test_dependencies_install_with_an_unknown_tool(
        self, in_tmp, started_processes, monkeypatch
    ):
        """No plugin is registered, so every --tool name is unknown.

        Real plugins would be built, and building them runs their tools'
        `--version` (and, uncached, `uv tool run` installs from the index). The
        command also sets ASH_BIN_PATH for the rest of the process. It is set first
        in a monkeypatch context, so leaving the context gives this worker its own
        value back, and the test checks that it did.
        """
        bin_path = in_tmp / "bin"
        before = os.environ.get("ASH_BIN_PATH")
        with (
            monkeypatch.context() as scoped,
            patch("automated_security_helper.cli.dependencies.load_plugins"),
            patch(
                "automated_security_helper.cli.dependencies.ash_plugin_manager"
                ".plugin_modules",
                return_value=[],
            ),
        ):
            scoped.setenv("ASH_BIN_PATH", str(bin_path))
            result = _invoke(
                [
                    "dependencies",
                    "install",
                    "--bin-path",
                    str(bin_path),
                    "--tool",
                    "not-a-real-tool",
                ]
            )

        assert started_processes == []
        assert environ_value("ASH_BIN_PATH") == before, (
            "the command's ASH_BIN_PATH outlived the test"
        )
        # Not 5: the CLI reference documents 2 for a --tool this command cannot select.
        assert result.exit_code == 2, result.output
        assert "not-a-real-tool" in _plain(result.output)
        # Refused by the installer's own check, not by the argument parser.
        assert "No such option" not in _plain(result.output)

    def test_scanners_canceled_by_exclude_scanners(self, in_tmp, started_processes):
        """Refused when the engine is built, before any phase runs.

        If the refusal were lost, the emptied allowlist would mean every scanner
        and the scan would run them all; the phases are stubbed so that shows up
        as a failure here instead of a real scan.
        """
        with patch(
            "automated_security_helper.core.execution_engine.ScanExecutionEngine"
            ".execute_phases",
            side_effect=AssertionError("the scan ran its phases"),
        ) as execute_phases:
            result = _invoke(
                [
                    "scan",
                    "--no-progress",
                    "--source-dir",
                    "src",
                    "--output-dir",
                    "out",
                    "--scanners",
                    "bandit",
                    "--exclude-scanners",
                    "bandit",
                ]
            )

        execute_phases.assert_not_called()
        assert started_processes == []
        assert result.exit_code == USAGE_ERROR_EXIT, result.output
        assert "cancels itself" in _plain(result.output)

    @pytest.mark.parametrize(
        "selection, fragment",
        [
            pytest.param(
                ["--scanners", "bandit", "--exclude-scanners", "bandit"],
                "cancels itself",
                id="canceled",
            ),
            pytest.param(
                ["--scanners", "not-a-real-scanner"],
                "None of the requested scanners exist",
                id="unknown",
            ),
        ],
    )
    @pytest.mark.parametrize(
        "changed_files_only", [False, True], ids=["full", "changed-files-only"]
    )
    def test_a_refused_selection_starts_no_process_and_deletes_nothing(
        self, in_tmp, started_processes, selection, fragment, changed_files_only
    ):
        """Refused before ASH asks git anything or clears the output directory.

        A scan runs git three ways: for the scanned directory's repository
        (scan_source), for the --changed-files-only diff, and for the files
        committed to the output directory. A refused selection reaches none of them,
        and the previous results stay, so a mistyped --scanners keeps the last
        scan's results. The phases are stubbed to fail the test if they run, so the
        refusal has to come before them.
        """
        out = in_tmp / "out"
        (out / "reports").mkdir(parents=True)
        previous = out / "ash_aggregated_results.json"
        previous.write_text("{}", encoding="utf-8")
        report = out / "reports" / "ash.sarif"
        report.write_text("{}", encoding="utf-8")
        args = [
            "scan",
            "--no-progress",
            "--source-dir",
            "src",
            "--output-dir",
            "out",
            *selection,
        ]
        if changed_files_only:
            args.append("--changed-files-only")

        with patch(
            "automated_security_helper.core.execution_engine.ScanExecutionEngine"
            ".execute_phases",
            side_effect=AssertionError("the scan ran its phases"),
        ) as execute_phases:
            result = _invoke(args)

        execute_phases.assert_not_called()
        assert started_processes == []
        assert result.exit_code == USAGE_ERROR_EXIT, result.output
        assert fragment in _plain(result.output)
        assert previous.read_text(encoding="utf-8") == "{}"
        assert report.read_text(encoding="utf-8") == "{}"


class TestWorkspaceScannerSelection:
    """The same selection checks as a single scan, made once for the workspace.

    A refused selection stops the workspace with the usage-error code before any
    project starts (``_scan_one_project`` is never called), so no project-level
    handler records it as that project's failure.
    """

    @pytest.fixture
    def workspace(self, in_tmp):
        for name in ("api", "web"):
            (in_tmp / name).mkdir()
        (in_tmp / "demo.code-workspace").write_text(
            '{"folders": [{"path": "api"}, {"path": "web"}]}', encoding="utf-8"
        )
        return "demo.code-workspace"

    def _scan(self, workspace, *selection):
        with patch(
            "automated_security_helper.workspace.execution._scan_one_project"
        ) as scan_one_project:
            result = _invoke(
                [
                    "scan",
                    "--no-progress",
                    "--workspace",
                    workspace,
                    "--output-dir",
                    "out",
                    *selection,
                ]
            )
        scan_one_project.assert_not_called()
        return result

    def test_a_name_no_scanner_has(self, workspace):
        result = self._scan(workspace, "--scanners", "not-a-scanner")

        assert result.exit_code == USAGE_ERROR_EXIT, result.output
        assert "not-a-scanner" in _plain(result.output)

    def test_a_selection_that_cancels_itself(self, workspace):
        result = self._scan(
            workspace, "--scanners", "bandit", "--exclude-scanners", "bandit"
        )

        assert result.exit_code == USAGE_ERROR_EXIT, result.output
        assert "cancels itself" in _plain(result.output)

    @pytest.mark.parametrize(
        "selection",
        [
            ("--scanners", "bandit,semgrep"),
            ("--scanners", "bandit, semgrep"),
            ("--scanners", "bandit", "--scanners", "semgrep"),
            ("--scanners", "BANDIT"),
            ("--scanners", "Bandit,SEMGREP"),
            ("--scanners", "bandit,not-a-scanner"),
            ("--scanners", "bandit,semgrep", "--exclude-scanners", "semgrep"),
        ],
        ids=[
            "comma-list",
            "comma-and-space",
            "repeated-flag",
            "upper-case",
            "mixed-case-list",
            "partly-unknown",
            "list-minus-one",
        ],
    )
    def test_a_selection_a_single_scan_accepts_reaches_the_projects(
        self, workspace, selection
    ):
        """The engine splits each item on commas and compares case-insensitively.

        The pre-check read ``bandit,semgrep`` as one name and refused it, so a
        selection every single scan accepts exited 5 in a workspace.
        """
        with patch(
            "automated_security_helper.workspace.execution._scan_one_project",
            side_effect=RuntimeError("probe: a project scan started"),
        ) as scan_one_project:
            result = _invoke(
                [
                    "scan",
                    "--no-progress",
                    "--workspace",
                    workspace,
                    "--output-dir",
                    "out",
                    *selection,
                ]
            )

        output = _plain(result.output)
        assert result.exit_code != USAGE_ERROR_EXIT, output
        assert "None of the requested scanners exist" not in output
        assert "cancels itself" not in output
        assert scan_one_project.called

    @pytest.mark.parametrize(
        "selection, fragment",
        [
            (
                ("--scanners", "bandit", "--exclude-scanners", "bandit,semgrep"),
                "cancels itself",
            ),
            (
                (
                    "--scanners",
                    "bandit,semgrep",
                    "--exclude-scanners",
                    "semgrep, bandit",
                ),
                "cancels itself",
            ),
            (
                ("--scanners", "BANDIT", "--exclude-scanners", "bandit"),
                "cancels itself",
            ),
            (
                ("--scanners", "bandit", "--exclude-scanners", "BANDIT"),
                "cancels itself",
            ),
            (
                ("--scanners", "not-a-scanner,also-not-one"),
                "None of the requested scanners exist: also-not-one, not-a-scanner",
            ),
        ],
        ids=[
            "excluded-by-a-list",
            "both-lists",
            "upper-case-selected",
            "upper-case-excluded",
            "a-list-of-unknown-names",
        ],
    )
    def test_a_selection_a_single_scan_refuses_is_refused_here_too(
        self, workspace, selection, fragment
    ):
        result = self._scan(workspace, *selection)

        assert result.exit_code == USAGE_ERROR_EXIT, result.output
        assert fragment in _plain(result.output)

    @pytest.mark.parametrize(
        "scanners, excluded, refused",
        [
            (["bandit,semgrep"], [], False),
            (["bandit, semgrep"], [], False),
            (["BANDIT"], [], False),
            (["bandit"], ["bandit,semgrep"], True),
            (["not-a-scanner,also-not-one"], [], True),
        ],
        ids=["comma-list", "comma-and-space", "upper-case", "canceled", "unknown"],
    )
    def test_the_mcp_workspace_tool_reads_a_selection_the_same_way(
        self, in_tmp, scanners, excluded, refused
    ):
        """scan_workspace builds its settings with its own _scan_options."""
        from automated_security_helper.cli.mcp.workspace import _scan_options
        from automated_security_helper.core.exceptions import ScannerSelectionError
        from automated_security_helper.interactions.run_ash_scan import (
            build_project_scan_settings,
        )
        from automated_security_helper.workspace.execution import (
            refuse_unresolvable_scanner_selection,
        )
        from automated_security_helper.workspace.resolver import resolve_workspace

        (in_tmp / "api").mkdir()
        workspace = in_tmp / "dev.code-workspace"
        workspace.write_text('{"folders": [{"path": "api"}]}', encoding="utf-8")
        plan = resolve_workspace(workspace)
        # What prewarm_plugin_registry does before the pre-check runs for real:
        # the judgment is against loaded plugins, not whatever earlier tests in
        # this process happened to register.
        from automated_security_helper.plugins.loader import load_internal_plugins

        load_internal_plugins()
        settings = build_project_scan_settings(
            _scan_options(
                plan,
                output_dir=None,
                config_overrides=None,
                scanners=scanners,
                excluded_scanners=excluded,
                offline=False,
                allow_missing_projects=False,
            )
        )

        if refused:
            with pytest.raises(ScannerSelectionError):
                refuse_unresolvable_scanner_selection(plan, settings)
        else:
            refuse_unresolvable_scanner_selection(plan, settings)

    def test_the_mcp_workspace_tool_reports_the_same_code(self):
        from automated_security_helper.cli.mcp.workspace import _exit_code_for
        from automated_security_helper.core.exceptions import ScannerSelectionError

        assert _exit_code_for(ScannerSelectionError("x")) == USAGE_ERROR_EXIT

    def test_an_empty_registry_defers_to_the_projects(self, in_tmp):
        """A registry nothing has filled proves nothing about the selection, so
        the pre-check defers instead of refusing every name against an empty
        list. The scan phase makes the same call: with no registered scanners
        it skips its own check rather than refuse."""
        from unittest.mock import patch as mock_patch

        from automated_security_helper.cli.mcp.workspace import _scan_options
        from automated_security_helper.interactions.run_ash_scan import (
            build_project_scan_settings,
        )
        from automated_security_helper.plugins import ash_plugin_manager
        from automated_security_helper.workspace.execution import (
            refuse_unresolvable_scanner_selection,
        )
        from automated_security_helper.workspace.resolver import resolve_workspace

        (in_tmp / "api").mkdir()
        workspace = in_tmp / "dev.code-workspace"
        workspace.write_text('{"folders": [{"path": "api"}]}', encoding="utf-8")
        plan = resolve_workspace(workspace)
        settings = build_project_scan_settings(
            _scan_options(
                plan,
                output_dir=None,
                config_overrides=None,
                scanners=["not-a-scanner"],
                excluded_scanners=[],
                offline=False,
                allow_missing_projects=False,
            )
        )

        with mock_patch.object(ash_plugin_manager, "plugin_modules", return_value=[]):
            refuse_unresolvable_scanner_selection(plan, settings)


class TestTheSelectionPreCheckJudgesOnlyThisWorkspacesPlugins:
    """The pre-check answers from the plugins THIS workspace can run.

    The plugin registry is process-wide. In a process that runs more than one
    scan -- the MCP server above all -- it holds every module any earlier scan,
    session or tool loaded. A pre-check that reads it whole leaks another
    session's scanner names into a refusal the client sees, and accepts a name
    only another session's plugins provide, selecting nothing in every project.
    """

    @pytest.fixture
    def workspace(self, in_tmp):
        for name in ("api", "web"):
            (in_tmp / name).mkdir()
        (in_tmp / "demo.code-workspace").write_text(
            '{"folders": [{"path": "api"}, {"path": "web"}]}', encoding="utf-8"
        )
        return "demo.code-workspace"

    @pytest.fixture
    def foreign_scanner(self, monkeypatch):
        """A scanner another scan in this process registered.

        Served under a module no project of these workspaces lists, so no
        project here could ever run it. The registration is removed afterwards;
        the manager's memo follows the registrations, so popping the entry is
        enough.
        """
        import sys
        import types

        from automated_security_helper.plugins import ash_plugin_manager

        module = types.ModuleType("foreign_ash_plugins")

        class GhostScanner:
            ash_plugin_type = "scanner"

        GhostScanner.__module__ = "foreign_ash_plugins"
        module.GhostScanner = GhostScanner
        monkeypatch.setitem(sys.modules, "foreign_ash_plugins", module)
        ash_plugin_manager.register_plugin_module(
            "scanner", "foreign_ash_plugins", "foreign_ash_plugins"
        )
        yield "ghostscanner"
        ash_plugin_manager.remove_plugin_module_registration(
            "scanner", "foreign_ash_plugins"
        )

    def _scan(self, workspace, *args):
        with patch(
            "automated_security_helper.workspace.execution._scan_one_project"
        ) as scan_one_project:
            result = _invoke(
                [
                    "scan",
                    "--no-progress",
                    "--workspace",
                    workspace,
                    "--output-dir",
                    "out",
                    *args,
                ]
            )
        return result, scan_one_project

    def test_a_refusal_names_no_scanner_from_outside_the_workspace(
        self, workspace, foreign_scanner
    ):
        """The refusal's list of registered scanners reaches the operator, and
        over MCP the client: names loaded by someone else in the process are
        another session's business, not part of this workspace's answer."""
        result, _ = self._scan(workspace, "--scanners", "not-a-scanner")

        assert result.exit_code == USAGE_ERROR_EXIT, result.output
        assert foreign_scanner not in _plain(result.output), result.output

    def test_a_name_only_a_foreign_module_provides_is_refused(
        self, workspace, foreign_scanner
    ):
        """No project of this workspace loads the foreign module, so a selection
        naming only its scanner selects nothing in every project: the same
        refusal as a name nothing registers, not a scan of everything."""
        result, scan_one_project = self._scan(workspace, "--scanners", foreign_scanner)

        assert result.exit_code == USAGE_ERROR_EXIT, result.output
        scan_one_project.assert_not_called()

    def test_the_refusal_wording_is_the_single_scans(self, workspace):
        """One builder makes the no-match refusal everywhere, so the workspace's
        wording cannot drift from the one a single scan prints."""
        result, _ = self._scan(workspace, "--scanners", "not-a-scanner")

        output = _plain(result.output)
        assert result.exit_code == USAGE_ERROR_EXIT, output
        assert "Refused rather than scanned" in output, output
        assert "selects nothing" in output, output
        assert "report itself clean" in output, output

    def test_the_cancel_wording_is_the_single_scans(self, workspace):
        """The self-cancelling selection's refusal shares the engine's wording,
        reasoning sentence included."""
        result, _ = self._scan(
            workspace, "--scanners", "bandit", "--exclude-scanners", "bandit"
        )

        output = _plain(result.output)
        assert result.exit_code == USAGE_ERROR_EXIT, output
        assert "cancels itself" in output, output
        assert "Refused rather than guessed" in output, output

    def test_an_uncertain_scanner_name_defers_to_the_projects(
        self, workspace, monkeypatch
    ):
        """A loaded scanner class that declares no name is configured under a name
        the pre-check cannot read, so the pre-check cannot prove a selection
        matches nothing: it defers, and each project's own scan phase judges the
        selection against the names that are authoritative there."""
        import sys
        import types

        from automated_security_helper.plugins import ash_plugin_manager

        module = types.ModuleType("mystery_ash_plugins")

        class UnnamedScanner:
            ash_plugin_type = "scanner"

        UnnamedScanner.__module__ = "mystery_ash_plugins"
        module.UnnamedScanner = UnnamedScanner
        monkeypatch.setitem(sys.modules, "mystery_ash_plugins", module)
        # Registered the way an imported plugin module's classes are; what makes
        # it this run's, though, is the --ash-plugin-modules listing below.
        ash_plugin_manager.register_plugin_module(
            "scanner", "mystery_ash_plugins", "mystery_ash_plugins"
        )
        try:
            with patch(
                "automated_security_helper.workspace.execution._scan_one_project",
                side_effect=RuntimeError("probe: a project scan started"),
            ) as scan_one_project:
                result = _invoke(
                    [
                        "scan",
                        "--no-progress",
                        "--workspace",
                        workspace,
                        "--output-dir",
                        "out",
                        "--ash-plugin-modules",
                        "mystery_ash_plugins",
                        "--scanners",
                        "shape-shifter",
                    ]
                )
        finally:
            ash_plugin_manager.remove_plugin_module_registration(
                "scanner", "mystery_ash_plugins"
            )

        output = _plain(result.output)
        assert result.exit_code != USAGE_ERROR_EXIT, output
        assert "None of the requested scanners exist" not in output, output
        assert scan_one_project.called

    def test_every_built_in_scanner_declares_the_name_it_is_configured_under(self):
        """The guard that keeps the deferral above theoretical: the pre-check may
        refuse by declared names only because every scanner ASH ships declares
        one, and it is the name its own config carries."""
        from automated_security_helper.base.plugin_config import (
            declared_plugin_name,
            plugin_config_key,
        )
        from automated_security_helper.plugins import ash_plugin_manager
        from automated_security_helper.plugins.loader import load_internal_plugins

        load_internal_plugins()
        scanners = ash_plugin_manager.plugin_modules("scanner")
        built_in = [
            cls
            for cls in scanners
            if getattr(cls, "__module__", "").startswith("automated_security_helper.")
        ]
        assert built_in, "no built-in scanner resolved; the guard measured nothing"
        for cls in built_in:
            declared = declared_plugin_name(cls)
            assert declared, f"{cls.__name__} declares no name"
            assert declared == plugin_config_key(cls), cls.__name__


class TestWorkspaceDryRunRefusesTheSameSelections:
    """``--dry-run`` answers for the scan it describes.

    A dry run that exits 0 for a selection the real run refuses tells the
    operator the command line is good, and the real run then refuses it: the
    same pre-check runs in both, with the same code and the same text.
    """

    @pytest.fixture
    def workspace(self, in_tmp):
        (in_tmp / "api").mkdir()
        (in_tmp / "demo.code-workspace").write_text(
            '{"folders": [{"path": "api"}]}', encoding="utf-8"
        )
        return "demo.code-workspace"

    def _dry_run(self, workspace, *selection):
        with patch(
            "automated_security_helper.workspace.execution._scan_one_project"
        ) as scan_one_project:
            result = _invoke(
                [
                    "scan",
                    "--no-progress",
                    "--workspace",
                    workspace,
                    "--output-dir",
                    "out",
                    "--dry-run",
                    *selection,
                ]
            )
        scan_one_project.assert_not_called()
        return result

    def test_a_name_no_scanner_has_is_refused(self, workspace):
        result = self._dry_run(workspace, "--scanners", "not-a-scanner")

        output = _plain(result.output)
        assert result.exit_code == USAGE_ERROR_EXIT, output
        assert "None of the requested scanners exist: not-a-scanner" in output, output

    def test_a_selection_that_cancels_itself_is_refused(self, workspace):
        result = self._dry_run(
            workspace, "--scanners", "bandit", "--exclude-scanners", "bandit"
        )

        output = _plain(result.output)
        assert result.exit_code == USAGE_ERROR_EXIT, output
        assert "cancels itself" in output, output

    def test_control_a_runnable_selection_still_prints_the_plan(self, workspace):
        result = self._dry_run(workspace, "--scanners", "bandit")

        output = _plain(result.output)
        assert result.exit_code == 0, output
        assert "None of the requested scanners exist" not in output, output

    @pytest.mark.parametrize("named_by", ["command-line", "project-config"])
    def test_a_plugin_module_outside_the_namespace_is_refused_as_the_run_refuses_it(
        self, in_tmp, workspace, named_by
    ):
        """The pre-check reads the scanners this workspace's plugins provide, so
        the dry run loads those plugin modules first, as the real run does. A
        module outside ASH's plugin namespace is refused before anything is
        imported: an invalid configuration, exit 3, in the real run. The dry run
        refuses it with the same code and the same sentence, not as an error it
        did not expect, exit 1 with nothing printed."""
        if named_by == "command-line":
            selection: tuple = ("--ash-plugin-modules", "os.path")
        else:
            config_dir = in_tmp / "api" / ".ash"
            config_dir.mkdir()
            (config_dir / ".ash.yaml").write_text(
                "ash_plugin_modules:\n  - os.path\n", encoding="utf-8"
            )
            selection = ()

        with patch(
            "automated_security_helper.workspace.execution._scan_one_project"
        ) as scan_one_project:
            real = _invoke(
                [
                    "scan",
                    "--no-progress",
                    "--workspace",
                    workspace,
                    "--output-dir",
                    "out",
                    *selection,
                ]
            )
        scan_one_project.assert_not_called()
        dry = self._dry_run(workspace, *selection)

        real_output, dry_output = _plain(real.output), _plain(dry.output)
        assert real.exit_code == _INVALID_CONFIG_EXIT, real_output
        assert dry.exit_code == _INVALID_CONFIG_EXIT, (dry.exception, dry_output)
        refusal = _PLUGIN_MODULE_REFUSAL.search(real_output)
        assert refusal is not None, real_output
        assert "'os.path'" in refusal.group(0), real_output
        assert refusal.group(0) in dry_output, dry_output

    def test_a_plugin_whose_import_crashes_is_named_as_the_run_names_it(
        self, in_tmp, workspace, monkeypatch
    ):
        """A plugin module in the namespace whose top-level code raises something
        other than ImportError: every import failure of a configured module is
        the same loss, so the real run refuses with exit 3, naming the module
        and its error, and the dry run answers the same input with the same
        refusal in the same words."""
        import sys

        site = in_tmp / "site"
        package = "crashing_ash_plugins"
        (site / package).mkdir(parents=True)
        (site / package / "__init__.py").write_text(
            'raise ValueError("this plugin cannot initialise")\n', encoding="utf-8"
        )
        monkeypatch.syspath_prepend(str(site))
        monkeypatch.delitem(sys.modules, package, raising=False)
        selection = ("--ash-plugin-modules", package)

        with patch(
            "automated_security_helper.workspace.execution._scan_one_project"
        ) as scan_one_project:
            real = _invoke(
                [
                    "scan",
                    "--no-progress",
                    "--workspace",
                    workspace,
                    "--output-dir",
                    "out",
                    *selection,
                ]
            )
        scan_one_project.assert_not_called()
        dry = self._dry_run(workspace, *selection)

        real_output, dry_output = _plain(real.output), _plain(dry.output)
        assert real.exit_code == 3, real_output
        assert "which failed to import" in real_output, real_output
        assert "'crashing_ash_plugins'" in real_output, real_output
        assert "this plugin cannot initialise" in real_output, real_output
        assert dry.exit_code == 3, (dry.exception, dry_output)
        assert "which failed to import" in dry_output, (dry.exception, dry_output)
        assert "'crashing_ash_plugins'" in dry_output, dry_output
        assert "this plugin cannot initialise" in dry_output, dry_output

    def test_a_pre_check_workspace_refusal_keeps_its_exit_code(
        self, workspace, monkeypatch
    ):
        """A WorkspaceDefinitionError raised while the dry run's pre-check runs
        is the workspace's own refusal: the real run answers it with the
        workspace code and its message, so the dry run does too, rather than
        reading it as an error nothing expected."""
        from automated_security_helper.core.exceptions import WorkspaceDefinitionError
        from automated_security_helper.models.workspace import WorkspaceExitCode
        from automated_security_helper.workspace import execution

        def refuse(plan, settings):
            raise WorkspaceDefinitionError("probe: the definition is refused here")

        monkeypatch.setattr(execution, "prewarm_plugin_registry", refuse)

        dry = self._dry_run(workspace)

        output = _plain(dry.output)
        assert dry.exit_code == int(WorkspaceExitCode.WORKSPACE_ERROR), (
            dry.exception,
            output,
        )
        assert "probe: the definition is refused here" in output, output
        assert "Exiting due to exception" not in output, output

    def test_the_dry_run_logs_the_import_crashs_error_text(
        self, in_tmp, workspace, monkeypatch
    ):
        """A crashing plugin is a recorded import refusal now, not an
        unexpected failure, so there is no traceback to log; what debugging
        needs -- the module and its error's own words -- is on the loader's
        warning record and in the refusal."""
        import logging
        import sys

        from automated_security_helper.utils.log import ASH_LOGGER

        site = in_tmp / "site"
        package = "crashing_ash_plugins"
        (site / package).mkdir(parents=True)
        (site / package / "__init__.py").write_text(
            'raise ValueError("this plugin cannot initialise")\n', encoding="utf-8"
        )
        monkeypatch.syspath_prepend(str(site))
        monkeypatch.delitem(sys.modules, package, raising=False)
        records: list[logging.LogRecord] = []

        def keep(record: logging.LogRecord) -> bool:
            records.append(record)
            return True

        ASH_LOGGER.addFilter(keep)
        try:
            dry = self._dry_run(workspace, "--ash-plugin-modules", package)
        finally:
            ASH_LOGGER.removeFilter(keep)

        assert dry.exit_code == 3, (dry.exception, _plain(dry.output))
        crashed = [
            r for r in records if "this plugin cannot initialise" in r.getMessage()
        ]
        assert crashed, [r.getMessage() for r in records]
        # The record that names the module beside the error's words.
        assert any("crashing_ash_plugins" in r.getMessage() for r in crashed), [
            (r.getMessage(), r.exc_info) for r in crashed
        ]


#: The workspace's code for a project config it cannot use (WorkspaceExitCode
#: INVALID_PROJECT_CONFIG), which the loader's plugin-module refusal maps to.
_INVALID_CONFIG_EXIT = 3

#: The loader's refusal of a plugin module outside the namespace, up to its last
#: sentence; the prefix each surface puts before it is that surface's own.
_PLUGIN_MODULE_REFUSAL = re.compile(r"ash_plugin_modules names .*?ASH_PLUGIN_MODULES\.")


class TestPathsThatDoNotExist:
    def test_merge_results_that_do_not_exist(self, in_tmp):
        result = _invoke(["merge", "--output-dir", "out", "--results", "nowhere"])

        assert result.exit_code == USAGE_ERROR_EXIT, result.output
        assert "--results path does not exist: nowhere" in _plain(result.output)

    @pytest.mark.parametrize("name", ["no[/such]", "no[bold]such"])
    def test_merge_results_whose_name_reads_as_markup(self, in_tmp, name):
        """The path is the operator's text, printed as given.

        It is not read as Rich markup, so a closing tag raises no MarkupError
        and an opening one is not dropped.
        """
        result = _invoke(["merge", "--output-dir", "out", "--results", name])

        assert result.exit_code == USAGE_ERROR_EXIT, result.output
        assert f"--results path does not exist: {name}" in _plain(result.output)

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs a named pipe")
    def test_merge_results_that_are_neither_a_file_nor_a_directory(self, in_tmp):
        os.mkfifo(in_tmp / "a-pipe")

        result = _invoke(["merge", "--output-dir", "out", "--results", "a-pipe"])

        assert result.exit_code == USAGE_ERROR_EXIT, result.output
        assert "neither a file nor a directory" in _plain(result.output)


class TestStateProblemsStayAtOne:
    """Nothing the operator typed is wrong; what they asked for is not there yet."""

    def test_use_existing_without_results(self, in_tmp):
        with patch("automated_security_helper.cli.scan.run_ash_scan") as run:
            result = _invoke(
                ["scan", "--no-progress", "--source-dir", "src", "--use-existing"]
            )

        run.assert_not_called()
        assert result.exit_code == 1, result.output
        assert "--use-existing" in _plain(result.stderr)

    def test_report_without_results(self, in_tmp):
        result = _invoke(["report", "--output-dir", "out", "--format", "flat-json"])

        assert result.exit_code == 1, result.output

    def test_merge_results_directory_that_holds_more_than_one(self, in_tmp):
        for shard in ("a", "b"):
            (in_tmp / "shards" / shard).mkdir(parents=True)
            (in_tmp / "shards" / shard / "ash_aggregated_results.json").write_text(
                "{}", encoding="utf-8"
            )

        result = _invoke(["merge", "--output-dir", "out", "--results", "shards"])

        assert result.exit_code == 1, result.output
        assert "contains 2 results files" in _plain(result.output)

    def test_merge_results_directory_that_holds_no_results(self, in_tmp):
        (in_tmp / "empty-shard").mkdir()

        result = _invoke(["merge", "--output-dir", "out", "--results", "empty-shard"])

        assert result.exit_code == 1, result.output
        assert "No ash_aggregated_results.json found" in _plain(result.output)

    @pytest.mark.parametrize(
        "content",
        [
            pytest.param("T=wJalrXUtnFEMIK7MDENG", id="not-json"),
            pytest.param('{"metadata": "T=wJalrXUtnFEMIK7MDENG"}', id="schema-invalid"),
        ],
    )
    def test_merge_does_not_print_what_an_unreadable_shard_holds(self, in_tmp, content):
        """The refusal names the file and why it is unreadable, not its content.

        pydantic's message quotes up to about 50 characters of the input as
        input_value, so the refusal of a shard results file names the file and
        why it is unreadable, never pydantic's text.
        """
        (in_tmp / "shard0.json").write_text(content, encoding="utf-8")

        result = _invoke(["merge", "--output-dir", "out", "--results", "shard0.json"])

        output = _plain(result.output)
        assert result.exit_code == 1, result.output
        assert "Could not read shard results from shard0.json" in output
        assert "wJalrXUtnFEMIK7MDENG" not in output


class TestModesThatRunASHAgainCarryTheCodeOut:
    """Container and Nix mode run a second ASH. Its usage error must reach the host."""

    def _opts(self, tmp_path: Path, **overrides):
        from automated_security_helper.interactions.run_ash_scan import ScanOptions

        kwargs = {"source_dir": tmp_path / "src", "output_dir": tmp_path / "out"}
        kwargs.update(overrides)
        (tmp_path / "src").mkdir(exist_ok=True)
        return ScanOptions(**kwargs)

    def test_container_mode_exits_with_the_inner_usage_code(self, tmp_path):
        from automated_security_helper.interactions import run_ash_scan as mod

        opts = self._opts(tmp_path)
        logger = MagicMock()
        inner = subprocess.CompletedProcess(
            args=["docker", "run"], returncode=USAGE_ERROR_EXIT, stdout="", stderr=""
        )
        with (
            patch.object(mod, "run_ash_container", return_value=inner),
            patch.object(mod, "container_was_started", return_value=True),
            pytest.raises(SystemExit) as exit_info,
        ):
            mod._run_container_mode(opts, logger)

        assert exit_info.value.code == USAGE_ERROR_EXIT
        logged = " ".join(str(call.args[0]) for call in logger.error.call_args_list)
        assert "usage error" in logged, (
            f"the host has to say what the inner code means, not call it unknown: {logged}"
        )

    @pytest.mark.parametrize(
        "inner_code", [3, 4, USAGE_ERROR_EXIT], ids=["config", "workspace", "usage"]
    )
    def test_nix_mode_exits_with_the_inner_code_when_nothing_was_scanned(
        self, tmp_path, inner_code
    ):
        from automated_security_helper.interactions import run_ash_scan as mod

        opts = self._opts(tmp_path, mode="nix")
        logger = MagicMock()
        inner = subprocess.CompletedProcess(args=["nix"], returncode=inner_code)
        with (
            patch.object(mod, "run_ash_nix", return_value=inner),
            patch.object(mod, "nix_preflight", lambda: None),
            pytest.raises(SystemExit) as exit_info,
        ):
            mod._run_nix_mode(opts, logger)

        assert exit_info.value.code == inner_code, (
            f"the inner scan exited {inner_code} and wrote no results; the host "
            f"reported {exit_info.value.code}, which names a different problem"
        )

    def test_nix_mode_exits_one_for_a_shell_that_never_ran_ash(self, tmp_path):
        """A status ASH does not publish is nix's own, so it stays a plain failure."""
        from automated_security_helper.interactions import run_ash_scan as mod

        opts = self._opts(tmp_path, mode="nix")
        inner = subprocess.CompletedProcess(args=["nix"], returncode=100)
        with (
            patch.object(mod, "run_ash_nix", return_value=inner),
            patch.object(mod, "nix_preflight", lambda: None),
            pytest.raises(SystemExit) as exit_info,
        ):
            mod._run_nix_mode(opts, MagicMock())

        assert exit_info.value.code == 1
