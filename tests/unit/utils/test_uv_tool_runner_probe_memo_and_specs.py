# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The uv runner's probes answer the question the scan asks, and remember only
uv's own answers.

Each test here pins one fix in ``utils/uv_tool_runner.py``:

* ``get_uv_tool_command`` keys its memo by the offline mode and the ``--from``
  spec, probes that spec, and does not remember a probe that never exited.
* ``checked_requirement`` refuses a constraint glued onto the package name
  (``bandit`` + ``2`` names ``bandit2``) when told which package was meant.
* ``list_available_tools`` turns a listing that timed out or could not spawn
  into the runner's own error, so ``is_tool_installed`` answers False.
* ``install_tool_with_version`` reinstalls a listed tool when asked to.
* ``run_tool`` and the probes honor a caller's own offline mode, and build the
  ``--from`` spec on the package that provides the tool.
* a probe that never exited does not pin the tool to its PATH binary, and a
  timed-out run under ``check`` is a failed run on the fallback branch too.
"""

from __future__ import annotations

import os
import subprocess  # nosec B404
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from automated_security_helper.utils import uv_tool_runner
from automated_security_helper.utils.uv_tool_runner import (
    UVToolRunner,
    UVToolRunnerError,
    _reset_uv_tool_runner_caches,
    checked_requirement,
    get_uv_tool_command,
)

pytestmark = pytest.mark.unit

UV_PATH = os.path.abspath("/opt/uv/bin/uv")


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    _reset_uv_tool_runner_caches()
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.delenv("UV_OFFLINE", raising=False)
    yield
    _reset_uv_tool_runner_caches()


@pytest.fixture
def spawn(monkeypatch):
    """The process boundary, replaced; the probe's uv and no direct binary."""
    mock = MagicMock()
    mock.return_value = subprocess.CompletedProcess([], 1, "", "")
    monkeypatch.setattr(uv_tool_runner, "spawn_run", mock)
    monkeypatch.setattr(uv_tool_runner, "find_uv_or_none", lambda: UV_PATH)
    monkeypatch.setattr(uv_tool_runner, "find_executable", lambda name: None)
    return mock


@pytest.fixture
def runner():
    r = UVToolRunner(uv_executable=UV_PATH)
    r._uv_available_cache = True
    return r


class TestGetUvToolCommandMemo:
    def test_an_offline_miss_is_not_served_to_an_online_lookup(
        self, spawn, monkeypatch
    ):
        monkeypatch.setenv("ASH_OFFLINE", "1")
        assert get_uv_tool_command("bandit") is None
        monkeypatch.delenv("ASH_OFFLINE")
        assert get_uv_tool_command("bandit") is None
        assert spawn.call_count == 2, spawn.call_args_list
        assert "--offline" in spawn.call_args_list[0].args[0]
        assert "--offline" not in spawn.call_args_list[1].args[0]

    def test_a_probe_that_timed_out_is_not_remembered_as_absence(
        self, spawn, monkeypatch
    ):
        """With the retry window closed at once, the next call probes again."""
        monkeypatch.setattr(uv_tool_runner, "_UV_PROBE_RETRY_SECONDS", 0.0)
        spawn.side_effect = subprocess.TimeoutExpired(["uv"], 5)
        assert get_uv_tool_command("bandit") is None
        assert get_uv_tool_command("bandit") is None
        assert spawn.call_count == 2

    def test_a_probe_that_timed_out_does_not_pin_the_path_binary(
        self, spawn, monkeypatch
    ):
        """One slow probe used to remember the PATH binary for the rest of the
        process; this call runs it, the next call (past the window) asks uv again."""
        monkeypatch.setattr(uv_tool_runner, "_UV_PROBE_RETRY_SECONDS", 0.0)
        monkeypatch.setattr(
            uv_tool_runner, "find_executable", lambda name: "/usr/bin/bandit"
        )
        spawn.side_effect = subprocess.TimeoutExpired(["uv"], 5)
        assert get_uv_tool_command("bandit") == ["/usr/bin/bandit"]
        assert get_uv_tool_command("bandit") == ["/usr/bin/bandit"]
        assert spawn.call_count == 2
        spawn.side_effect = None
        spawn.return_value = subprocess.CompletedProcess([], 0, "1.7.9", "")
        assert get_uv_tool_command("bandit") == ["uv", "tool", "run", "bandit"]

    def test_a_timed_out_probe_opens_a_retry_window(self, spawn, monkeypatch):
        """Inside the window no caller pays the probe's timeout again, and
        nothing is remembered: the answer is the PATH binary for that call."""
        monkeypatch.setattr(uv_tool_runner, "_UV_PROBE_RETRY_SECONDS", 3600.0)
        monkeypatch.setattr(
            uv_tool_runner, "find_executable", lambda name: "/usr/bin/bandit"
        )
        spawn.side_effect = subprocess.TimeoutExpired(["uv"], 5)
        assert get_uv_tool_command("bandit") == ["/usr/bin/bandit"]
        assert get_uv_tool_command("bandit") == ["/usr/bin/bandit"]
        assert spawn.call_count == 1
        assert uv_tool_runner._uv_command_cache == {}

    def test_a_callers_own_offline_mode_reaches_the_probe(self, spawn, monkeypatch):
        monkeypatch.delenv("ASH_OFFLINE", raising=False)
        assert get_uv_tool_command("bandit", offline=True) is None
        assert "--offline" in spawn.call_args.args[0]
        assert spawn.call_args.kwargs["env"]["UV_OFFLINE"] == "1"

    def test_a_miss_from_inside_a_sandbox_scope_is_not_remembered(
        self, spawn, monkeypatch, tmp_path
    ):
        """A non-zero exit under a sandbox scope is the wrapper's view of the
        tool, not uv's: served from the memo, one backend's refusal answered
        every caller on the host for the rest of the process."""
        from automated_security_helper.utils.sandbox import scope as sandbox_scope

        scoped = sandbox_scope.SandboxScope(
            backend=SimpleNamespace(name="zz-backend"),
            scanner_name="zz-scanner",
            requirements=None,
            source_dir=tmp_path,
            output_dir=tmp_path,
            results_dir=tmp_path,
            scan_target=None,
            offline=False,
        )
        monkeypatch.setattr(
            uv_tool_runner, "find_executable", lambda name: "/usr/bin/bandit"
        )
        with sandbox_scope.sandbox_scope(scoped):
            assert get_uv_tool_command("bandit") == ["/usr/bin/bandit"]
        assert uv_tool_runner._uv_probe_answers == {}
        assert uv_tool_runner._uv_command_cache == {}
        spawn.return_value = subprocess.CompletedProcess([], 0, "1.7.9", "")
        assert get_uv_tool_command("bandit") == ["uv", "tool", "run", "bandit"]
        assert spawn.call_count == 2

    def test_a_success_from_inside_a_sandbox_scope_is_uvs_own(
        self, spawn, monkeypatch, tmp_path
    ):
        """The control: a tool that answered under the wrapper is remembered."""
        from automated_security_helper.utils.sandbox import scope as sandbox_scope

        scoped = sandbox_scope.SandboxScope(
            backend=SimpleNamespace(name="zz-backend"),
            scanner_name="zz-scanner",
            requirements=None,
            source_dir=tmp_path,
            output_dir=tmp_path,
            results_dir=tmp_path,
            scan_target=None,
            offline=False,
        )
        spawn.return_value = subprocess.CompletedProcess([], 0, "1.7.9", "")
        with sandbox_scope.sandbox_scope(scoped):
            assert get_uv_tool_command("bandit") == ["uv", "tool", "run", "bandit"]
        assert get_uv_tool_command("bandit") == ["uv", "tool", "run", "bandit"]
        assert spawn.call_count == 1

    def test_a_from_spec_probe_gets_the_environment_building_budget(self, spawn):
        """Resolving a spec with extras and a constraint on a cold cache builds
        an environment; under the bare name's 5 s budget that probe was killed
        on every dependency check, and a timed-out probe is never remembered."""
        get_uv_tool_command("bandit", from_spec="bandit[sarif]>=1.7")
        assert spawn.call_args.kwargs["timeout"] == (
            uv_tool_runner._UV_TOOL_VERSION_PROBE_TIMEOUT
        )
        assert (
            spawn.call_args.kwargs["timeout"] > uv_tool_runner._UV_VERSION_PROBE_TIMEOUT
        )

    def test_a_bare_name_probe_keeps_the_short_budget(self, spawn):
        """The control: the tool uv already has is still probed under 5 s."""
        get_uv_tool_command("bandit")
        assert spawn.call_args.kwargs["timeout"] == (
            uv_tool_runner._UV_VERSION_PROBE_TIMEOUT
        )


class TestValidateCachedToolTellsAProbeThatDidNotRun:
    def test_a_timed_out_probe_is_not_a_broken_tool(self, spawn, runner):
        spawn.side_effect = subprocess.TimeoutExpired(["uv"], 15)
        result = runner.validate_cached_tool("bandit")
        assert result["probed"] is False
        assert result["is_functional"] is False
        assert "did not run" in result["error"], result["error"]

    def test_a_tool_that_exits_0_without_a_version_on_stdout_runs(self, spawn, runner):
        """Some tools print --version on stderr; exit 0 is the tool running."""
        spawn.return_value = subprocess.CompletedProcess([], 0, "", "bandit 1.7.9\n")
        result = runner.validate_cached_tool("bandit")
        assert result["probed"] is True
        assert result["is_functional"] is True
        assert result["version"] is None

    def test_a_probe_that_exits_non_zero_is_a_broken_tool(self, spawn, runner):
        """The control: an exited failure still reads as not functional."""
        spawn.return_value = subprocess.CompletedProcess([], 1, "", "boom")
        result = runner.validate_cached_tool("bandit")
        assert result["probed"] is True
        assert result["is_functional"] is False
        assert "exited 1" in result["error"], result["error"]

    def test_a_refused_spec_is_not_a_broken_tool(self, spawn, runner):
        result = runner.validate_cached_tool("bandit", "bandit2", package="bandit")
        assert result["probed"] is False
        assert result["is_functional"] is False
        assert spawn.call_count == 0


class TestATimeoutUnderCheckIsAFailedRun:
    def test_the_fallback_branch_raises_under_check(self, spawn, runner):
        spawn.side_effect = subprocess.TimeoutExpired(["uv"], 5)
        with pytest.raises(UVToolRunnerError) as raised:
            runner.run_tool("bandit", check=True)
        assert "timed out" in str(raised.value), str(raised.value)

    def test_without_check_the_timeout_is_returned(self, spawn, runner):
        """The control: the mixin's shape, a flagged result and no raise."""
        spawn.side_effect = subprocess.TimeoutExpired(["uv"], 5)
        result = runner.run_tool("bandit", check=False)
        assert getattr(result, "timed_out", False) is True


class TestTheProbeSpecAndItsMemo:
    """``get_uv_tool_command`` probes the ``--from`` spec the scan runs, holds it
    to the package, and remembers each form's answer under its own key. These
    sat under the timeout-under-check class above, where a run of the memo
    class by name skipped them."""

    def test_a_probe_that_exited_non_zero_is_remembered(self, spawn):
        """The control: uv's own answer about the tool is still memoized."""
        assert get_uv_tool_command("bandit") is None
        assert get_uv_tool_command("bandit") is None
        assert spawn.call_count == 1

    def test_the_probe_runs_the_from_spec_the_scan_runs(self, spawn):
        """The command carries the --from it was probed under: a bare
        ``uv tool run bandit`` resolves another environment than the one
        that answered."""
        spawn.return_value = subprocess.CompletedProcess([], 0, "1.7.9", "")
        command = get_uv_tool_command("bandit", from_spec="bandit[sarif]>=1.7")
        assert command == [
            "uv",
            "tool",
            "run",
            "--from",
            "bandit[sarif]>=1.7",
            "bandit",
        ]
        argv = spawn.call_args.args[0]
        assert argv[-4:] == ["--from", "bandit[sarif]>=1.7", "bandit", "--version"]

    def test_a_from_spec_naming_another_package_is_refused_without_a_probe(self, spawn):
        """A constraint glued onto the name ("bandit" + "2") used to run
        ``uv tool run --from bandit2 bandit --version``, an index install of
        bandit2 from the dependency check."""
        assert (
            get_uv_tool_command("bandit", from_spec="bandit2", package="bandit") is None
        )
        assert spawn.call_count == 0

    def test_a_from_spec_for_the_named_package_is_probed(self, spawn):
        """The control: the same spelling check passes a real spec."""
        spawn.return_value = subprocess.CompletedProcess([], 0, "1.7.9", "")
        assert (
            get_uv_tool_command(
                "bandit", from_spec="Bandit[sarif]>=1.7", package="bandit"
            )
            is not None
        )
        assert spawn.call_count == 1

    def test_the_bare_probe_and_the_from_spec_probe_are_remembered_apart(self, spawn):
        assert get_uv_tool_command("bandit") is None
        assert get_uv_tool_command("bandit", from_spec="bandit[sarif]") is None
        assert spawn.call_count == 2


class TestCheckedRequirementNamesThePackage:
    def test_a_glued_constraint_that_renames_the_package_is_refused(self):
        with pytest.raises(UVToolRunnerError):
            checked_requirement("bandit2", "the tool spec", package="bandit")

    def test_the_version_probe_holds_its_spec_to_the_package(self, spawn, runner):
        """get_tool_version refused only url, marker and specifier faults; a
        glued constraint went to uv as a probe of, and install from, bandit2."""
        assert runner.get_tool_version("bandit", "bandit2", package="bandit") is None
        assert spawn.call_count == 0
        spawn.return_value = subprocess.CompletedProcess([], 0, "1.7.9\n", "")
        assert runner.get_tool_version("bandit", "bandit>=1.7", package="bandit")
        assert spawn.call_count == 1

    def test_the_same_package_in_another_spelling_passes(self):
        assert (
            checked_requirement("Detect_Secrets>=1", package="detect-secrets")
            == "Detect_Secrets>=1"
        )

    def test_run_tool_refuses_a_constraint_glued_onto_the_name(self, spawn, runner):
        with pytest.raises(UVToolRunnerError):
            runner.run_tool("bandit", version_constraint="2")
        assert spawn.call_count == 0


class TestListingFailuresAreTheRunnersOwn:
    def test_a_listing_that_timed_out_reads_as_not_installed(self, spawn, runner):
        spawn.side_effect = subprocess.TimeoutExpired(["uv", "tool", "list"], 30)
        assert runner.is_tool_installed("bandit") is False

    def test_a_listing_whose_spawn_failed_reads_as_not_installed(self, spawn, runner):
        spawn.side_effect = OSError(11, "try again")
        assert runner.is_tool_installed("bandit") is False


class TestReinstall:
    def test_reinstall_runs_uv_tool_install_for_a_listed_tool(
        self, spawn, runner, monkeypatch
    ):
        monkeypatch.setattr(runner, "is_tool_installed", lambda name: True)
        spawn.return_value = subprocess.CompletedProcess([], 0, "", "")
        assert (
            runner.install_tool_with_version("bandit", timeout=10, reinstall=True)
            is True
        )
        argv = spawn.call_args.args[0]
        assert argv[:3] == [UV_PATH, "tool", "install"], argv
        assert "--reinstall" in argv
        assert argv[-1] == "bandit"

    def test_without_reinstall_a_listed_tool_is_left_as_it_is(
        self, spawn, runner, monkeypatch
    ):
        """The control: the default still answers True and installs nothing."""
        monkeypatch.setattr(runner, "is_tool_installed", lambda name: True)
        assert runner.install_tool_with_version("bandit") is True
        assert spawn.call_count == 0


class TestTheCallersOfflineMode:
    def test_a_callers_false_cannot_switch_ash_offline_off(self, monkeypatch):
        """ASH's mode can be added to, never switched off for one scanner."""
        monkeypatch.setenv("ASH_OFFLINE", "1")
        assert uv_tool_runner._offline_for(False) is True
        assert uv_tool_runner._offline_for(None) is True
        monkeypatch.delenv("ASH_OFFLINE")
        assert uv_tool_runner._offline_for(False) is False
        assert uv_tool_runner._offline_for(True) is True

    def test_a_package_named_like_the_command_passes_no_from(self, spawn, runner):
        """run_tool emitted `--from bandit bandit` where the probes'
        _uv_from_spec read None, so the two argvs resolved apart."""
        spawn.return_value = subprocess.CompletedProcess([], 0, "", "")
        runner.run_tool("bandit", package_name="Bandit")
        assert "--from" not in spawn.call_args.args[0]

    def test_run_tool_honors_the_callers_offline_mode(self, spawn, runner):
        spawn.return_value = subprocess.CompletedProcess([], 0, "", "")
        runner.run_tool("bandit", offline=True)
        call = spawn.call_args
        assert "--offline" in call.args[0]
        assert call.kwargs["env"]["UV_OFFLINE"] == "1"

    def test_run_tool_without_a_mode_follows_ash(self, spawn, runner):
        """The control: with no caller mode and ASH online, nothing is offline."""
        spawn.return_value = subprocess.CompletedProcess([], 0, "", "")
        runner.run_tool("bandit")
        call = spawn.call_args
        assert "--offline" not in call.args[0]
        assert "UV_OFFLINE" not in call.kwargs["env"]

    def test_the_version_probe_honors_the_callers_offline_mode(self, spawn, runner):
        spawn.return_value = subprocess.CompletedProcess([], 0, "1.0\n", "")
        runner.get_tool_version("bandit", offline=True)
        assert "--offline" in spawn.call_args.args[0]

    def test_an_install_asked_to_run_offline_installs_nothing(
        self, spawn, runner, monkeypatch
    ):
        monkeypatch.setattr(runner, "is_tool_installed", lambda name: False)
        assert runner.install_tool_with_version("bandit", offline=True) is False
        assert spawn.call_count == 0


class TestTheFromSpecIsBuiltOnThePackage:
    def test_extras_ride_the_package_name_not_the_executable(self, spawn, runner):
        spawn.return_value = subprocess.CompletedProcess([], 0, "", "")
        runner.run_tool(
            "jupyter-nbconvert", package_name="nbconvert", package_extras=["webpdf"]
        )
        argv = spawn.call_args.args[0]
        assert argv.count("--from") == 1, argv
        position = argv.index("--from")
        assert argv[position + 1] == "nbconvert[webpdf]"
        assert argv[position + 2] == "jupyter-nbconvert"

    def test_a_bare_package_name_is_still_the_from_spec(self, spawn, runner):
        """The control: the pre-existing shape, a package name alone."""
        spawn.return_value = subprocess.CompletedProcess([], 0, "", "")
        runner.run_tool("jupyter-nbconvert", package_name="nbconvert")
        argv = spawn.call_args.args[0]
        position = argv.index("--from")
        assert argv[position + 1 : position + 3] == ["nbconvert", "jupyter-nbconvert"]
