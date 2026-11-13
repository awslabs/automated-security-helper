# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the thin client delegates, and every road back to the cold run.

The client's one promise is that a wrong answer is impossible: it either runs
the scan on the daemon (same code, forked warm) or answers ``None`` and the
cold run proceeds untouched. These tests pin the ``None`` roads -- not a scan,
``--no-express``, a express child, no daemon, a stale daemon without ``--express`` --
and the ``--express`` autostart/restart choreography, with the socket layer
replaced by recorded stand-ins (no daemon runs in the unit tier).
"""

import pytest

from automated_security_helper.express import client, runtime

pytestmark = pytest.mark.unit


class TestClassification:
    @pytest.mark.parametrize(
        "argv",
        [
            ["scan"],
            ["scan", "--source-dir", "x"],
            [],
            ["--source-dir", "x", "--mode", "precommit"],
            ["--express"],
        ],
    )
    def test_scan_shapes_are_delegable(self, argv):
        assert client.is_scan_invocation(argv)

    @pytest.mark.parametrize(
        "argv",
        [
            ["report"],
            ["express", "start"],
            ["config", "validate"],
            ["mcp"],
            ["--help"],
            ["scan", "--help"],
            ["--version"],
            ["scan", "--no-express"],
            # A token that merely looks like a subcommand classifies the whole
            # invocation as not-a-scan: the cold run parses the truth, so the
            # mistake costs warmth, never correctness.
            ["--scanners", "report"],
        ],
    )
    def test_everything_else_runs_cold(self, argv):
        assert not client.is_scan_invocation(argv)

    def test_the_non_scan_list_matches_the_registered_cli(self):
        """The classifier's subcommand list is pinned to the real Typer app, so a
        new subcommand cannot drift past it unnoticed. ``scan`` is the one
        registered name that is deliberately not in the list."""
        import typer.main as typer_main

        from automated_security_helper.cli.main import app

        registered = set(typer_main.get_command(app).commands.keys())
        assert registered - {"scan"} == set(client.NON_SCAN_SUBCOMMANDS)

    def test_no_express_beats_express_wherever_both_appear(self):
        assert not client.wants_express(["--express", "--no-express"])
        assert not client.wants_express(["--no-express", "--express"])
        assert client.wants_express(["scan", "--express"])
        assert not client.wants_express(["scan"])


class TestColdRoads:
    @pytest.mark.parametrize(
        "environ",
        [
            {"_ASH_COMPLETE": "bash_complete"},
            {"_ASHV3_COMPLETE": "zsh_complete"},
            {"_AUTOMATED_SECURITY_HELPER_COMPLETE": "complete"},
            {"_AGENTIC_SECURITY_HARNESS_COMPLETE": "complete"},
            {"COMP_WORDS": "ash ", "COMP_CWORD": "1"},
        ],
    )
    def test_shell_completion_never_starts_a_scan(self, monkeypatch, environ):
        """TAB after ``ash `` re-invokes the program with the completion
        protocol's environment and an argv that classifies as a bare scan;
        with a daemon up, that must complete, not scan the working directory
        into the completion."""
        monkeypatch.setattr(runtime, "express_supported", lambda: True)
        monkeypatch.setattr(
            client, "_connect", lambda *_: pytest.fail("completion must not connect")
        )
        assert client.completion_in_progress(environ)
        assert client.delegated_exit_code([], environ=environ) is None

    def test_every_declared_completion_name_is_read(self):
        """The reads are spelled out one by one (so the environment audits can
        resolve them), and this ties each spelling back to the declared set."""
        for name in sorted(client.COMPLETION_ENV_NAMES):
            assert client.completion_in_progress({name: "complete"}), name

    def test_an_ordinary_environment_is_not_a_completion(self):
        """An unrelated ``_*_COMPLETE``-shaped variable (a profile's
        ``_SETUP_COMPLETE=1``, a CI image's) must not read as a completion:
        that switched express off for every scan of that shell, silently."""
        assert not client.completion_in_progress(
            {
                "PATH": "/usr/bin",
                "ASH_MODE": "local",
                "_COMPLETED_STEPS": "3",
                "_SETUP_COMPLETE": "1",
            }
        )

    def test_the_completion_names_are_the_console_scripts(self):
        """One completion variable per console script pyproject declares, in
        click's derived spelling, so a renamed or added alias cannot leave a
        completion that scans the working directory."""
        import re
        from pathlib import Path

        pyproject = (Path(__file__).resolve().parents[3] / "pyproject.toml").read_text(
            encoding="utf-8"
        )
        block = re.search(r"\[project\.scripts\](.*?)\n\[", pyproject, re.DOTALL).group(
            1
        )
        scripts = re.findall(r"(?m)^([A-Za-z0-9-]+) *=", block)
        assert scripts, "no console scripts found in pyproject.toml"
        derived = {
            "_" + name.upper().replace("-", "_") + "_COMPLETE" for name in scripts
        }
        assert derived == set(client.COMPLETION_ENV_NAMES)

    def test_a_express_child_never_delegates_again(self, monkeypatch):
        monkeypatch.setattr(
            client, "_connect", lambda *_: pytest.fail("a child must not connect")
        )
        assert (
            client.delegated_exit_code(["scan"], environ={runtime.CHILD_ENV: "1"})
            is None
        )

    def test_no_express_runs_cold_without_touching_the_socket(self, monkeypatch):
        # Supported is forced on so this test means the same thing on Windows,
        # where the platform gate would otherwise answer first.
        monkeypatch.setattr(runtime, "express_supported", lambda: True)
        monkeypatch.setattr(
            client, "_connect", lambda *_: pytest.fail("--no-express must not connect")
        )
        assert client.delegated_exit_code(["scan", "--no-express"], environ={}) is None

    def test_an_unsupported_platform_runs_cold(self, monkeypatch, capsys):
        monkeypatch.setattr(runtime, "express_supported", lambda: False)
        monkeypatch.setattr(
            client, "_connect", lambda *_: pytest.fail("unsupported must not connect")
        )
        assert client.delegated_exit_code(["scan"], environ={}) is None
        assert capsys.readouterr().err == "", "without --express the fallback is silent"

    def test_an_unsupported_platform_with_the_flag_says_so_once(
        self, monkeypatch, capsys
    ):
        """--express asked for the daemon by name, so the one place there can
        never be one is said out loud (the docs promise the line), while the
        flagless scan above stays silent."""
        monkeypatch.setattr(runtime, "express_supported", lambda: False)
        monkeypatch.setattr(
            client, "_connect", lambda *_: pytest.fail("unsupported must not connect")
        )
        assert client.delegated_exit_code(["scan", "--express"], environ={}) is None
        assert "running cold" in capsys.readouterr().err

    def test_no_socket_and_no_express_flag_runs_cold(self, monkeypatch, tmp_path):
        monkeypatch.setattr(runtime, "express_supported", lambda: True)
        monkeypatch.setattr(runtime, "socket_path", lambda *_: tmp_path / "none.sock")
        monkeypatch.setattr(
            client, "autostart", lambda *_: pytest.fail("must not autostart")
        )
        assert client.delegated_exit_code(["scan"], environ={}) is None

    def test_any_unexpected_failure_is_the_cold_answer_not_a_crash(self, monkeypatch):
        def boom(*_):
            raise RuntimeError("socket machinery exploded")

        monkeypatch.setattr(runtime, "express_supported", lambda: True)
        monkeypatch.setattr(runtime, "socket_path", boom)
        assert client.delegated_exit_code(["scan"], environ={}) is None


class _Recorder:
    """Records the delegation choreography the tests below assert on."""

    def __init__(self, monkeypatch, tmp_path, outcomes):
        self.calls = []
        self.outcomes = list(outcomes)
        path = tmp_path / "express.sock"
        # The daemonize and the sockets are the recorded stand-ins, and the
        # platform gate is forced on, so the choreography means the same thing
        # on every OS the unit tier runs on.
        monkeypatch.setattr(runtime, "express_supported", lambda: True)
        monkeypatch.setattr(runtime, "socket_path", lambda *_: path)
        monkeypatch.setattr(client, "_connect", self._connect)
        monkeypatch.setattr(client, "await_daemon", self._await)
        monkeypatch.setattr(client, "autostart", self._autostart)
        monkeypatch.setattr(client, "stop_daemon", self._stop)
        monkeypatch.setattr(client, "_run_on_daemon", self._run)
        self.connectable = False

    def _connect(self, path):
        self.calls.append("connect")
        return object() if self.connectable else None

    def _await(self, path, timeout=None):
        self.calls.append("await")
        return object()

    def _autostart(self, environ):
        self.calls.append("autostart")
        self.connectable = True
        return True

    def _stop(self, path):
        self.calls.append("stop")

    def _run(self, sock, argv, environ, *, explicit):
        self.calls.append("run")
        return self.outcomes.pop(0)


class TestExpressFlagChoreography:
    def test_autostart_then_use_when_no_daemon_and_express_asked(
        self, monkeypatch, tmp_path
    ):
        recorder = _Recorder(monkeypatch, tmp_path, outcomes=[("exit", 2)])
        code = client.delegated_exit_code(["scan", "--express"], environ={})
        assert code == 2
        assert recorder.calls == ["connect", "autostart", "await", "run"]

    def test_a_stale_daemon_is_restarted_once_under_express(
        self, monkeypatch, tmp_path
    ):
        recorder = _Recorder(
            monkeypatch, tmp_path, outcomes=[("stale", None), ("exit", 0)]
        )
        recorder.connectable = True
        code = client.delegated_exit_code(["scan", "--express"], environ={})
        assert code == 0
        assert recorder.calls == ["connect", "run", "stop", "autostart", "await", "run"]

    def test_a_stale_daemon_without_express_is_the_silent_cold_fallback(
        self, monkeypatch, tmp_path
    ):
        recorder = _Recorder(monkeypatch, tmp_path, outcomes=[("stale", None)])
        recorder.connectable = True
        assert client.delegated_exit_code(["scan"], environ={}) is None
        assert recorder.calls == ["connect", "run"], "no stop, no restart"

    def test_a_busy_daemon_is_never_restarted_even_under_express(
        self, monkeypatch, tmp_path
    ):
        """A restart on busy would kill the scans the daemon is busy with, so a
        non-stale refusal under --express is still the cold fallback."""
        recorder = _Recorder(monkeypatch, tmp_path, outcomes=[("fallback", None)])
        recorder.connectable = True
        assert client.delegated_exit_code(["scan", "--express"], environ={}) is None
        assert recorder.calls == ["connect", "run"]

    def test_a_second_refusal_after_the_restart_is_the_cold_fallback(
        self, monkeypatch, tmp_path
    ):
        recorder = _Recorder(
            monkeypatch, tmp_path, outcomes=[("stale", None), ("stale", None)]
        )
        recorder.connectable = True
        assert client.delegated_exit_code(["scan", "--express"], environ={}) is None
        assert recorder.calls == ["connect", "run", "stop", "autostart", "await", "run"]


class TestRequestEnvironment:
    """The request carries the client's WHOLE environment minus the denylist,
    and the child's environment becomes exactly the request's. An allowlist
    here was one forgotten scanner variable away from "same command, different
    findings", which is the one thing express may never produce."""

    def test_everything_travels_except_the_denylist(self):
        environ = {
            "ASH_CONFIG": "/cfg.yaml",
            "GIT_INDEX_FILE": ".git/index.lock-side",
            "AWS_PROFILE": "reporting",
            "HTTPS_PROXY": "http://proxy.example:3128",
            "SEMGREP_APP_TOKEN": "token",
            # The point of the denylist inversion: names no allowlist named.
            "SEMGREP_RULES": "p/default",
            "PIP_INDEX_URL": "https://mirror.example/simple",
            "KUBECONFIG": "/u/user/.kube/config",
            "SSH_AUTH_SOCK": "/run/agent.sock",
            "SOME_RANDOM_VAR": "carried-too",
            # The denied names.
            "LD_PRELOAD": "never-carried",
            runtime.CHILD_ENV: "1",
        }
        carried = runtime.request_environment(environ)
        carried_names = sorted(carried)
        assert "SOME_RANDOM_VAR" in carried_names
        assert "SEMGREP_RULES" in carried_names
        assert "LD_PRELOAD" not in carried_names
        assert runtime.CHILD_ENV not in carried_names
        assert len(carried_names) == len(environ) - 2

    def test_the_denylist_is_small_and_names_only_express_internals_and_preload(
        self,
    ):
        assert runtime.REQUEST_ENV_DENYLIST == {runtime.CHILD_ENV, "LD_PRELOAD"}

    def test_an_arbitrary_client_variable_reaches_the_child(self):
        """The regression the inversion exists for: a variable no allowlist
        ever named must reach the forked scan exactly as a cold run sees it."""
        child_environ = {}
        runtime.apply_request_env({"CHECKOV_ANSWER": "42"}, child_environ)
        assert child_environ == {"CHECKOV_ANSWER": "42"}

    def test_a_proxy_variable_reaches_the_child_and_a_stale_one_is_removed(self):
        child_environ = {"HTTPS_PROXY": "http://old-proxy:1", "PATH": "/usr/bin"}
        runtime.apply_request_env(
            {"HTTPS_PROXY": "http://proxy.example:3128", "PATH": "/usr/bin"},
            child_environ,
        )
        assert child_environ["HTTPS_PROXY"] == "http://proxy.example:3128"
        runtime.apply_request_env({"PATH": "/usr/bin"}, child_environ)
        assert "HTTPS_PROXY" not in child_environ

    def test_the_child_environment_becomes_exactly_the_requests(self):
        daemon_environ = {
            "ASH_CONFIG": "/stale.yaml",  # absent from the request: removed
            "ASH_MODE": "local",  # present in the request: replaced
            "LD_LIBRARY_PATH": "/daemon-own",  # the daemon's residue: removed too
            runtime.CHILD_ENV: "1",  # never removed, never overwritten
        }
        runtime.apply_request_env(
            {"ASH_MODE": "precommit", runtime.CHILD_ENV: "0"}, daemon_environ
        )
        assert daemon_environ == {
            "ASH_MODE": "precommit",
            runtime.CHILD_ENV: "1",
        }

    def test_a_denied_request_key_is_ignored_by_the_child(self):
        environ = {}
        runtime.apply_request_env({"LD_PRELOAD": "nope"}, environ)
        assert environ == {}


class TestSignalExitCode:
    """A signal recorded during a refused or broken handshake must not vanish
    into a cold run: it maps to the exit code the cold run would have died
    with, SIGTERM outranking SIGINT (a CI timeout reads as 143 even when an
    interrupt also landed)."""

    def test_nothing_pending_means_no_exit(self):
        assert client._signal_exit_code([]) is None

    def test_sigint_maps_to_130(self):
        import signal as signal_module

        assert client._signal_exit_code([int(signal_module.SIGINT)]) == 130

    def test_sigterm_maps_to_143_and_outranks_sigint(self):
        import signal as signal_module

        pending = [int(signal_module.SIGINT), int(signal_module.SIGTERM)]
        assert client._signal_exit_code(pending) == 143


class TestScrubbedDaemonEnvironment:
    def test_one_invocations_incidentals_do_not_become_daemon_state(self):
        """The autostarted daemon outlives the scan that started it, so the
        starting shell's one-off state -- a commit hook's GIT_INDEX_FILE above
        all -- must not be inherited by every later scan's child. Honoured
        variables travel per request instead."""
        environ = {
            "PATH": "/usr/bin",
            "HOME": "/u/user",
            "LANG": "C.UTF-8",
            "TERM": "xterm",
            "XDG_RUNTIME_DIR": "/run/user/1000",
            runtime.IDLE_ENV: "120",
            "GIT_INDEX_FILE": ".git/index.hook",  # the hook incidental
            "ASH_CONFIG": "/cfg.yaml",  # honoured, but per-request
            "AWS_PROFILE": "prod",  # a shell credential
            "VIRTUAL_ENV": "/some/venv",
        }
        kept = runtime.scrubbed_daemon_environment(environ)
        assert kept == {
            "PATH": "/usr/bin",
            "HOME": "/u/user",
            "LANG": "C.UTF-8",
            "TERM": "xterm",
            "XDG_RUNTIME_DIR": "/run/user/1000",
            runtime.IDLE_ENV: "120",
        }
