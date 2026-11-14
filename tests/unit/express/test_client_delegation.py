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

import os as os_module
import signal

import pytest

from automated_security_helper.express import client, runtime

pytestmark = pytest.mark.unit

needs_sighup = pytest.mark.skipif(
    not hasattr(signal, "SIGHUP"), reason="this platform has no SIGHUP"
)


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
        """The declared set is the one list the check reads, so every name in
        it must read as a completion."""
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
        from pathlib import Path

        try:
            import tomllib
        except ModuleNotFoundError:  # Python 3.10
            import tomli as tomllib

        pyproject = tomllib.loads(
            (Path(__file__).resolve().parents[3] / "pyproject.toml").read_text(
                encoding="utf-8"
            )
        )
        scripts = list(pyproject["project"]["scripts"])
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

    def __init__(
        self, monkeypatch, tmp_path, outcomes, *, autostart_ok=True, await_ok=True
    ):
        self.calls = []
        self.outcomes = list(outcomes)
        # The two switches that make a start fail: autostart answering False
        # (the daemon died before binding) and await_daemon answering None
        # (it never accepted within the start window).
        self.autostart_ok = autostart_ok
        self.await_ok = await_ok
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
        return object() if self.await_ok else None

    def _autostart(self, environ):
        self.calls.append("autostart")
        if self.autostart_ok:
            self.connectable = True
        return self.autostart_ok

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

    @pytest.mark.parametrize(
        ("stale_daemon", "switches", "calls", "said"),
        [
            pytest.param(
                False,
                {"autostart_ok": False},
                ["connect", "autostart"],
                "the daemon did not come up; running cold. Its log is",
                id="first-start-dies-before-binding",
            ),
            pytest.param(
                False,
                {"await_ok": False},
                ["connect", "autostart", "await"],
                "the daemon did not come up; running cold.",
                id="first-start-never-accepts",
            ),
            pytest.param(
                True,
                {"autostart_ok": False},
                ["connect", "run", "stop", "autostart"],
                "the daemon did not come back up; running cold.",
                id="restart-dies-before-binding",
            ),
            pytest.param(
                True,
                {"await_ok": False},
                ["connect", "run", "stop", "autostart", "await"],
                "the daemon did not come back up; running cold.",
                id="restart-never-accepts",
            ),
        ],
    )
    def test_a_start_that_fails_says_why_and_runs_cold(
        self, monkeypatch, tmp_path, capsys, stale_daemon, switches, calls, said
    ):
        """The four roads that promise "say why, then run cold": --express asked
        for the daemon, so the failure is named on stderr and the scan still
        runs (the None answer), without ever reaching the second run."""
        monkeypatch.setattr(runtime, "log_path", lambda *_: tmp_path / "express.log")
        recorder = _Recorder(
            monkeypatch,
            tmp_path,
            outcomes=[("stale", None)] if stale_daemon else [],
            **switches,
        )
        recorder.connectable = stale_daemon
        assert client.delegated_exit_code(["scan", "--express"], environ={}) is None
        assert recorder.calls == calls
        assert said in capsys.readouterr().err


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
            # The loader variables travel like any other: a cold run hands
            # every scanner subprocess the client's value, so a warm scan's
            # scanners must see it too.
            "LD_PRELOAD": "carried-like-the-cold-run",
            "LD_LIBRARY_PATH": "/opt/tool/lib",
            # The denied name.
            runtime.CHILD_ENV: "1",
        }
        carried = runtime.request_environment(environ)
        carried_names = sorted(carried)
        assert "SOME_RANDOM_VAR" in carried_names
        assert "SEMGREP_RULES" in carried_names
        assert "LD_PRELOAD" in carried_names
        assert "LD_LIBRARY_PATH" in carried_names
        assert runtime.CHILD_ENV not in carried_names
        assert len(carried_names) == len(environ) - 1

    def test_the_denylist_names_only_the_express_child_marker(self):
        assert runtime.REQUEST_ENV_DENYLIST == {runtime.CHILD_ENV}

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
        runtime.apply_request_env({runtime.CHILD_ENV: "0"}, environ)
        assert environ == {}

    def test_a_loader_variable_reaches_the_child_as_in_a_cold_run(self):
        environ = {}
        runtime.apply_request_env({"LD_PRELOAD": "libfaketime.so"}, environ)
        assert environ == {"LD_PRELOAD": "libfaketime.so"}


class TestSignalExitCode:
    """A signal recorded during a refused or broken handshake must not vanish
    into a cold run: it maps to the exit code the cold run would have died
    with. Three tiers, in this order: SIGTERM (a CI timeout reads as 143 even
    when other signals also landed), then SIGHUP (a closed terminal, 129; the
    branch guarded by ``hasattr`` for platforms without it), then SIGINT (130)."""

    def test_nothing_pending_means_no_exit(self):
        assert client._signal_exit_code([]) is None

    @needs_sighup
    def test_sighup_maps_to_129(self):
        import signal as signal_module

        assert client._signal_exit_code([int(signal_module.SIGHUP)]) == 129

    @needs_sighup
    def test_sighup_outranks_sigint(self):
        import signal as signal_module

        pending = [int(signal_module.SIGINT), int(signal_module.SIGHUP)]
        assert client._signal_exit_code(pending) == 129

    @needs_sighup
    def test_sigterm_outranks_sighup(self):
        import signal as signal_module

        pending = [int(signal_module.SIGHUP), int(signal_module.SIGTERM)]
        assert client._signal_exit_code(pending) == 143

    def test_sigint_maps_to_130(self):
        import signal as signal_module

        assert client._signal_exit_code([int(signal_module.SIGINT)]) == 130

    def test_sigterm_maps_to_143_and_outranks_sigint(self):
        import signal as signal_module

        pending = [int(signal_module.SIGINT), int(signal_module.SIGTERM)]
        assert client._signal_exit_code(pending) == 143


class TestSpawnDaemonProcess:
    """``ash express start``'s launch is the python-child bootstrap, started by
    the one spawn the sandbox choke point exempts."""

    def _spawn(self, monkeypatch, tmp_path, environ):
        import os

        from automated_security_helper.express import spawn

        seen = {}

        def fake_start(argv, *, env, cwd, log_fd, keep_fd):
            seen.update(argv=list(argv), env=dict(env), cwd=cwd, keep_fd=keep_fd)

        def fake_ready(fd):
            os.close(fd)
            return True

        monkeypatch.setattr(spawn, "start_detached", fake_start)
        monkeypatch.setattr(runtime, "runtime_dir", lambda *_: tmp_path)
        monkeypatch.setattr(runtime, "log_path", lambda *_: tmp_path / "express.log")
        monkeypatch.setattr(client, "_await_readiness", fake_ready)
        assert client.spawn_daemon_process(environ) is True
        return seen

    def test_the_bootstrap_is_the_python_child_argv_not_a_raw_list(
        self, monkeypatch, tmp_path
    ):
        import sys

        from automated_security_helper.utils.python_child import (
            DROP_WORKING_DIRECTORY,
        )

        seen = self._spawn(monkeypatch, tmp_path, {runtime.IDLE_ENV: "120"})
        argv = seen["argv"]
        assert argv[0] == sys.executable
        assert ("-P" in argv) is (sys.version_info >= (3, 11))
        code = argv[argv.index("-c") + 1]
        # The cwd entry is dropped before anything is imported, and the daemon
        # bootstrap runs behind it.
        assert code.startswith(DROP_WORKING_DIRECTORY)
        assert "express.daemon import serve" in code
        # No option that changes which site set the daemon sees: -s, -I or -E
        # would make a spawned daemon's package listing differ from its
        # client's. (-P only drops the cwd entry, which the fingerprint never
        # reads.)
        # A default client (no import flags of its own) passes none; the
        # propagation test below covers a client that has them.
        flags = argv[1 : argv.index("-c")]
        if not (
            sys.flags.no_user_site or sys.flags.ignore_environment or sys.flags.isolated
        ):
            assert not {"-s", "-I", "-E", "-S"} & set(flags), flags
        assert argv[-2] == "120.0"
        assert argv[-1] == str(seen["keep_fd"])
        assert seen["cwd"] == str(tmp_path)

    @pytest.mark.parametrize(
        ("no_user_site", "ignore_environment", "isolated", "expected"),
        [
            (0, 0, 0, []),
            (1, 0, 0, ["-s"]),
            (0, 1, 0, ["-E"]),
            (1, 1, 0, ["-s", "-E"]),
            (1, 1, 1, ["-I"]),
        ],
    )
    def test_a_clients_import_flags_are_handed_to_the_spawned_daemon(
        self,
        monkeypatch,
        tmp_path,
        no_user_site,
        ignore_environment,
        isolated,
        expected,
    ):
        """A client started with -s (a console script whose shebang says
        ``python -sP``) must get a daemon with -s too, or the daemon imports
        user-site packages the client never sees: the same scan, different
        findings, warm against cold. The flags are also in the socket key, so
        a default client reaches a different daemon altogether."""
        real = runtime.sys.flags

        class _Flags:
            # sys.flags is process-global: every flag but the three under
            # test reads through to the real one, so pytest's own reads of
            # it keep working while the patch is in place.
            def __init__(self, **overrides):
                self.__dict__.update(overrides)

            def __getattr__(self, name):
                return getattr(real, name)

        monkeypatch.setattr(
            runtime.sys,
            "flags",
            _Flags(
                no_user_site=no_user_site,
                ignore_environment=ignore_environment,
                isolated=isolated,
            ),
        )
        seen = self._spawn(monkeypatch, tmp_path, {})
        argv = seen["argv"]
        assert argv[1 : 1 + len(expected)] == expected
        assert argv[1 + len(expected)] in ("-P", "-c")

    def test_the_interpreter_shaping_variables_reach_the_new_interpreter(
        self, monkeypatch, tmp_path
    ):
        """On a layout that imports ASH only through PYTHONPATH the fresh
        interpreter fails its first import unless it inherits the variable."""
        seen = self._spawn(
            monkeypatch,
            tmp_path,
            {
                "PYTHONPATH": "/work/ash-checkout",
                "PYTHONHOME": "/opt/py",
                "PYTHONUSERBASE": "/work/user-base",
                "PYTHONNOUSERSITE": "1",
                "VIRTUAL_ENV": "/work/venv",
                "AWS_PROFILE": "prod",
                "GIT_INDEX_FILE": ".git/index.hook",
            },
        )
        # By names and the one named value, never the mapping itself: a failed
        # assertion prints its operands (tests/utils/env_assertions.py).
        assert sorted(seen["env"]) == [
            "PYTHONHOME",
            "PYTHONNOUSERSITE",
            "PYTHONPATH",
            "PYTHONUSERBASE",
            "VIRTUAL_ENV",
        ]
        spawned_path = seen["env"].get("PYTHONPATH")
        # PYTHONPATH is absolutized, which on a drive-lettered platform adds
        # the drive; the expectation is spelled the same way.
        assert spawned_path == os_module.path.abspath("/work/ash-checkout")


class TestControlRequestTimeout:
    def test_the_timeout_re_times_the_socket_after_the_connect(self, monkeypatch):
        timeouts = []

        class _Sock:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def settimeout(self, value):
                timeouts.append(value)

            def sendall(self, _data):
                pass

        monkeypatch.setattr(client, "_connect", lambda _p: _Sock())
        monkeypatch.setattr(runtime, "send_frame", lambda *_: None)
        monkeypatch.setattr(
            runtime.FrameReader, "read_frame", lambda self: {"ok": True}
        )
        client.control_request("x", {"op": "status"})
        assert timeouts == [], "no timeout asked: the connect's stays"
        client.control_request("x", {"op": "status"}, timeout=30.0)
        assert timeouts == [30.0]


class TestProgrammingErrorsAreNamed:
    def test_an_attribute_error_is_reported_as_a_bug_even_without_express(
        self, monkeypatch, capsys
    ):
        def broken(*_a, **_k):
            raise AttributeError("module 'os' has no attribute 'getuid'")

        monkeypatch.setattr(client, "_delegated_exit_code", broken)
        assert client.delegated_exit_code(["scan"], environ={}) is None
        err = capsys.readouterr().err
        assert "internal error (AttributeError" in err
        assert "bug in ASH express mode" in err

    def test_a_host_condition_stays_quiet_without_express(self, monkeypatch, capsys):
        def refused(*_a, **_k):
            raise OSError("connection refused")

        monkeypatch.setattr(client, "_delegated_exit_code", refused)
        assert client.delegated_exit_code(["scan"], environ={}) is None
        assert capsys.readouterr().err == ""


class TestAutostartBacksOffAfterARetirement:
    def test_a_fresh_retirement_marker_stops_the_respawn_and_names_the_cause(
        self, monkeypatch, tmp_path, capsys
    ):
        path = tmp_path / "d.sock"
        monkeypatch.setattr(runtime, "express_supported", lambda: True)
        monkeypatch.setattr(runtime, "socket_path", lambda *_: path)
        monkeypatch.setattr(client, "_connect", lambda _p: None)
        # raising=False: os.fork does not exist on Windows, where the
        # assertion still holds (nothing is spawned either).
        monkeypatch.setattr(
            os_module,
            "fork",
            lambda: pytest.fail("no daemon may be forked"),
            raising=False,
        )
        runtime.mark_retired_for_threads(path)
        assert client.delegated_exit_code(["scan", "--express"], environ={}) is None
        assert "extra threads" in capsys.readouterr().err

    def test_an_old_marker_no_longer_blocks(self, tmp_path):
        path = tmp_path / "d.sock"
        runtime.mark_retired_for_threads(path)
        assert runtime.recent_retirement(path) == "threads"
        import time

        later = time.time() + runtime.RETIRE_BACKOFF_SECONDS + 1
        assert runtime.recent_retirement(path, now=later) is None
        runtime.clear_retirement(path)
        assert runtime.recent_retirement(path) is None


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
            "PYTHONPATH": "/work/plugins",  # decides which ASH the daemon imports
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
            # The interpreter-shaping set is KEPT: it decides which ASH tree and
            # which site set the daemon's own interpreter resolves, and the
            # fingerprint covers it.
            "PYTHONPATH": os_module.path.abspath("/work/plugins"),
            "VIRTUAL_ENV": "/some/venv",
        }
