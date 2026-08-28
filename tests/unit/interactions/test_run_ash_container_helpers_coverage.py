# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Behaviour of run_ash_container's module-level helpers.

Why this file exists
--------------------
``run_ash_container.py`` splits its work into small helpers -- revision
discovery, Dockerfile location, command assembly, process streaming -- and the
existing suite covers the paths a healthy local checkout takes. What was
untested is everything the helpers do when the environment is *not* a full clone:
a pip-installed package resolving its own git revision, a Dockerfile that has to
be found by walking upward, a build that fails, a child process that is
interrupted.

None of these start a container. ``_build_image`` and ``_build_custom_image``
are exercised with ``run_cmd_direct`` replaced by a recorder, so the assertion is
on the command ASH would run. ``run_cmd_direct`` itself is exercised against a
real short-lived Python child, because its contract is about threads, pipes and
return codes, and a double for the process would not exercise any of that.

Doubles used here
-----------------
``_StubProcess`` and ``_StubPipe`` implement only the members
``run_cmd_direct`` touches. That is deliberate: a bare ``Mock`` would fabricate
any attribute, so a call to a Popen method that does not exist would pass. These
raise ``AttributeError`` instead.

Known gap
---------
``_assemble_run_command`` appends ``-t`` only when ``sys.stdout.isatty()``, which
is false under pytest's capture. Nothing here forces that branch, because faking
the tty would mean patching ``sys.stdout`` out from under the capture fixture and
the assertion would then be about the patch rather than about the command.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from subprocess import CalledProcessError
from types import ModuleType, SimpleNamespace
from typing import Any, Dict, List

import pytest

from automated_security_helper.core.constants import ASH_REPO_LATEST_REVISION
from automated_security_helper.core.enums import (
    ExecutionPhase,
    ExecutionStrategy,
    ExportFormat,
)
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.interactions.run_ash_container import (
    _assemble_run_command,
    _build_custom_image,
    _build_image,
    _execute_container,
    _find_dockerfile,
    _find_runner,
    _validate_ash_revision,
    get_ash_revision,
    run_cmd_direct,
    validate_path,
)
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process


# ---------------------------------------------------------------------------
# _validate_ash_revision
# ---------------------------------------------------------------------------


class TestValidateAshRevision:
    def test_empty_revision_is_rejected(self):
        """An empty build-arg would expand to nothing; it is not a revision."""
        assert _validate_ash_revision("") is False

    def test_none_is_rejected(self):
        assert _validate_ash_revision(None) is False


# ---------------------------------------------------------------------------
# get_ash_revision -- the pip-installed branch
# ---------------------------------------------------------------------------

# The eight paths get_ash_revision looks for to decide "this is a full clone".
_REPO_ROOT_MARKERS = frozenset(
    {
        ".github",
        ".gitignore",
        ".dockerignore",
        "Dockerfile",
        "pyproject.toml",
        "NOTICE",
        "docs",
        "tests",
    }
)


@pytest.fixture
def pip_installed_ash(monkeypatch, tmp_path):
    """Make ``get_ash_revision`` take the pip-installed branch.

    The function decides between LOCAL and a git revision by probing eight
    marker paths beside the package. In this worktree they all exist, so the
    function returns LOCAL before reaching any of the dist-info handling. This
    reports those eight -- and only those eight -- as absent, and points
    ``import_module`` at a package directory the test owns.

    Returns the ``direct_url.json`` path the function will look for. The test
    decides whether it exists and what it contains.
    """
    real_exists = Path.exists

    def fake_exists(self, *args, **kwargs):
        if self.name in _REPO_ROOT_MARKERS:
            return False
        return real_exists(self, *args, **kwargs)

    monkeypatch.setattr(Path, "exists", fake_exists)

    package_dir = tmp_path / "automated_security_helper"
    package_dir.mkdir()
    module = ModuleType("automated_security_helper")
    module.__path__ = [package_dir.as_posix()]
    module.__version__ = "9.9.9"
    monkeypatch.setattr(rac, "import_module", lambda name: module)

    dist_info = tmp_path / "automated_security_helper-9.9.9.dist-info"
    dist_info.mkdir()
    return dist_info / "direct_url.json"


class TestGetAshRevisionFromDirectUrl:
    def test_a_local_file_url_still_builds_from_local_source(self, pip_installed_ash):
        """pip install of a local path is a local build, not a git checkout."""
        pip_installed_ash.write_text(
            json.dumps({"url": "file://" + pip_installed_ash.parent.as_posix()}),
            encoding="utf-8",
        )
        assert get_ash_revision() == "LOCAL"

    def test_requested_revision_wins_over_commit_id(self, pip_installed_ash):
        """The tag the operator asked for is more useful than its resolved sha."""
        pip_installed_ash.write_text(
            json.dumps(
                {
                    "url": "git+https://example.invalid/ash.git",
                    "vcs_info": {
                        "vcs": "git",
                        "requested_revision": "v9.8.7",
                        "commit_id": "0123456789abcdef",
                    },
                }
            ),
            encoding="utf-8",
        )
        assert get_ash_revision() == "v9.8.7"

    def test_commit_id_is_used_when_no_revision_was_requested(self, pip_installed_ash):
        pip_installed_ash.write_text(
            json.dumps(
                {
                    "url": "git+https://example.invalid/ash.git",
                    "vcs_info": {"vcs": "git", "commit_id": "0123456789abcdef"},
                }
            ),
            encoding="utf-8",
        )
        assert get_ash_revision() == "0123456789abcdef"

    def test_an_empty_vcs_info_falls_back_to_the_latest_revision(
        self, pip_installed_ash
    ):
        pip_installed_ash.write_text(
            json.dumps({"url": "git+https://example.invalid/ash.git", "vcs_info": {}}),
            encoding="utf-8",
        )
        assert get_ash_revision() == ASH_REPO_LATEST_REVISION

    def test_a_url_without_vcs_info_falls_back_to_the_latest_revision(
        self, pip_installed_ash
    ):
        """An sdist or wheel URL carries no revision, so there is nothing to pin."""
        pip_installed_ash.write_text(
            json.dumps({"url": "https://example.invalid/ash-1.0.0.tar.gz"}),
            encoding="utf-8",
        )
        assert get_ash_revision() == ASH_REPO_LATEST_REVISION

    def test_unparseable_direct_url_json_falls_back_rather_than_raising(
        self, pip_installed_ash
    ):
        """A corrupt dist-info must not stop a container build."""
        pip_installed_ash.write_text("{ this is not json", encoding="utf-8")
        assert get_ash_revision() == ASH_REPO_LATEST_REVISION

    def test_a_json_document_that_is_not_an_object_yields_no_revision(
        self, pip_installed_ash
    ):
        """Well-formed JSON of the wrong shape leaves the revision unresolved."""
        pip_installed_ash.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
        assert get_ash_revision() is None

    def test_no_direct_url_json_falls_back_to_the_latest_revision(
        self, pip_installed_ash
    ):
        """A plain `pip install ash` from an index has no direct_url.json."""
        assert not pip_installed_ash.exists()
        assert get_ash_revision() == ASH_REPO_LATEST_REVISION


# ---------------------------------------------------------------------------
# validate_path
# ---------------------------------------------------------------------------


class TestValidatePath:
    def test_an_existing_path_is_returned_resolved(self, tmp_path):
        assert validate_path(tmp_path) == tmp_path.resolve()

    def test_a_string_path_is_accepted(self, tmp_path):
        assert validate_path(str(tmp_path)) == tmp_path.resolve()

    def test_a_missing_path_raises_value_error(self, tmp_path):
        missing = tmp_path / "not-here"
        with pytest.raises(ValueError, match="Path does not exist"):
            validate_path(missing)


# ---------------------------------------------------------------------------
# run_cmd_direct
# ---------------------------------------------------------------------------


class _StubPipe:
    """A readable pipe for run_cmd_direct's reader threads."""

    def __init__(self, lines=(), raises: BaseException | None = None):
        self._lines = list(lines)
        self._raises = raises

    def readline(self) -> str:
        if self._raises is not None:
            raise self._raises
        return self._lines.pop(0) if self._lines else ""


class _StubProcess:
    """Stands in for the Popen that ``create_process_with_pipes`` returns.

    Implements only what ``run_cmd_direct`` touches. Anything else raises
    AttributeError, which is the point -- a bare Mock would invent it.
    """

    def __init__(
        self,
        *,
        returncode: int | None = 0,
        stdout_lines=(),
        stderr_lines=(),
        stdout_raises: BaseException | None = None,
        poll_raises: BaseException | None = None,
        wait_raises: BaseException | None = None,
    ):
        self.stdout = _StubPipe(stdout_lines, raises=stdout_raises)
        self.stderr = _StubPipe(stderr_lines)
        self.returncode = returncode
        self._poll_raises = poll_raises
        self._wait_raises = wait_raises
        self.terminated = False
        self.killed = False
        self.wait_timeouts: List[Any] = []

    def poll(self):
        if self._poll_raises is not None:
            raise self._poll_raises
        return self.returncode

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        self.wait_timeouts.append(timeout)
        if self._wait_raises is not None and len(self.wait_timeouts) == 1:
            raise self._wait_raises
        return self.returncode


@pytest.fixture
def stub_process(monkeypatch):
    """Install a _StubProcess as the process run_cmd_direct will drive."""

    def install(process: _StubProcess) -> _StubProcess:
        monkeypatch.setattr(
            subprocess_utils,
            "create_process_with_pipes",
            lambda **kwargs: process,
        )
        return process

    return install


_CHILD_WRITES_BOTH_STREAMS = (
    "import sys\n"
    "sys.stdout.write('child-stdout-marker\\n')\n"
    "sys.stderr.write('child-stderr-marker\\n')\n"
)


class TestRunCmdDirectAgainstARealChild:
    def test_both_streams_are_captured_and_echoed(self, capfd):
        result = run_cmd_direct(
            [sys.executable, "-c", _CHILD_WRITES_BOTH_STREAMS], debug=True
        )
        assert result.returncode == 0
        assert "child-stdout-marker" in result.stdout
        assert "child-stderr-marker" in result.stderr
        captured = capfd.readouterr()
        assert "child-stdout-marker" in captured.out
        assert "child-stderr-marker" in captured.err

    def test_none_values_are_dropped_from_the_command(self):
        result = run_cmd_direct(
            [sys.executable, None, "-c", "print('after-none')"], debug=False
        )
        assert result.returncode == 0
        assert "after-none" in result.stdout
        assert None not in result.args

    def test_a_nonzero_exit_raises_when_checked(self):
        with pytest.raises(CalledProcessError) as excinfo:
            run_cmd_direct([sys.executable, "-c", "import sys; sys.exit(7)"])
        assert excinfo.value.returncode == 7

    def test_a_nonzero_exit_is_returned_when_not_checked(self):
        result = run_cmd_direct(
            [sys.executable, "-c", "import sys; sys.exit(7)"], check=False
        )
        assert result.returncode == 7


class TestRunCmdDirectInterruption:
    def test_ctrl_c_terminates_then_escalates_to_kill(self, stub_process, capfd):
        """A process that ignores SIGTERM must still be killed, not waited on."""
        process = stub_process(
            _StubProcess(
                returncode=None,
                poll_raises=KeyboardInterrupt(),
                wait_raises=TimeoutError("did not exit"),
            )
        )
        result = run_cmd_direct(["ignored"], check=False)
        assert process.terminated is True
        assert process.killed is True
        assert process.wait_timeouts == [5, None]
        assert result.returncode == -1
        assert "Command interrupted by user" in capfd.readouterr().err

    def test_ctrl_c_does_not_kill_a_process_that_exits_on_terminate(self, stub_process):
        process = stub_process(
            _StubProcess(returncode=0, poll_raises=KeyboardInterrupt())
        )
        run_cmd_direct(["ignored"], check=False)
        assert process.terminated is True
        assert process.killed is False


class TestRunCmdDirectPipeFailure:
    def test_a_reader_error_is_reported_and_does_not_abort_the_command(
        self, stub_process, capfd
    ):
        """A broken pipe must not lose the process's exit status."""
        stub_process(
            _StubProcess(
                returncode=0,
                stdout_raises=RuntimeError("pipe went away"),
                stderr_lines=["still-readable\n"],
            )
        )
        result = run_cmd_direct(["ignored"])
        assert result.returncode == 0
        assert result.stdout == ""
        assert "still-readable" in result.stderr
        assert "Error reading stdout: pipe went away" in capfd.readouterr().err


# ---------------------------------------------------------------------------
# _find_runner
# ---------------------------------------------------------------------------


class TestFindRunner:
    def test_a_lookup_failure_yields_none_rather_than_propagating(self, monkeypatch):
        """Runner discovery tries four names; one raising must not end the search."""

        def explode(name):
            raise OSError("PATH is unreadable")

        monkeypatch.setattr(subprocess_utils, "find_executable", explode)
        assert _find_runner("finch") is None


# ---------------------------------------------------------------------------
# _find_dockerfile
# ---------------------------------------------------------------------------


class TestFindDockerfileLocal:
    def test_the_dockerfile_is_found_by_walking_up_to_the_repo_root(
        self, monkeypatch, tmp_path
    ):
        """Running `ash` from a subdirectory of a clone still finds the Dockerfile."""
        repo = tmp_path / "repo"
        nested = repo / "packages" / "inner"
        nested.mkdir(parents=True)
        (repo / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        (repo / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
        monkeypatch.chdir(nested)

        assert _find_dockerfile("LOCAL") == repo.resolve() / "Dockerfile"

    def test_a_dockerfile_without_a_pyproject_is_not_treated_as_the_repo_root(
        self, monkeypatch, tmp_path
    ):
        """Both markers are required; a stray Dockerfile is not an ASH checkout."""
        outer = tmp_path / "outer"
        nested = outer / "inner"
        nested.mkdir(parents=True)
        (outer / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        monkeypatch.chdir(nested)

        with pytest.raises(FileNotFoundError):
            _find_dockerfile("LOCAL")

    def test_a_dockerfile_in_the_cwd_is_used_directly(self, monkeypatch, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)

        assert _find_dockerfile("LOCAL") == tmp_path / "Dockerfile"


class TestFindDockerfileNonLocal:
    def test_a_clone_in_the_cwd_wins_over_the_packaged_asset(
        self, monkeypatch, tmp_path
    ):
        """A revision was requested, but a local clone builds what the user has."""
        (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(rac, "ASH_ASSETS_DIR", tmp_path / "unused-assets")

        assert _find_dockerfile("v1.2.3") == tmp_path / "Dockerfile"

    def test_the_packaged_asset_is_used_when_the_cwd_is_not_a_clone(
        self, monkeypatch, tmp_path
    ):
        assets = tmp_path / "assets"
        assets.mkdir()
        (assets / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(rac, "ASH_ASSETS_DIR", assets)

        assert _find_dockerfile("v1.2.3") == assets / "Dockerfile"

    def test_a_missing_dockerfile_raises_file_not_found(self, monkeypatch, tmp_path):
        empty_assets = tmp_path / "assets"
        empty_assets.mkdir()
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(rac, "ASH_ASSETS_DIR", empty_assets)

        with pytest.raises(FileNotFoundError, match="Dockerfile not found"):
            _find_dockerfile("v1.2.3")


# ---------------------------------------------------------------------------
# _build_image / _build_custom_image
# ---------------------------------------------------------------------------


@pytest.fixture
def recorded_commands(monkeypatch):
    """Capture the command lists run_cmd_direct would have executed."""
    calls: List[List[str]] = []

    def fake_run_cmd_direct(cmd_list, check=True, debug=False, shell=False):
        recorded = [str(item) for item in cmd_list if item is not None]
        calls.append(recorded)
        return create_completed_process(args=recorded, returncode=0)

    monkeypatch.setattr(rac, "run_cmd_direct", fake_run_cmd_direct)
    return calls


def _build_image_kwargs(dockerfile: Path, **overrides: Any) -> Dict[str, Any]:
    kwargs: Dict[str, Any] = {
        "oci_command_prefix": [],
        "resolved_oci_runner": "docker",
        "dockerfile_path": dockerfile,
        "image_name": "ash:test",
        "build_target": "non-root",
        "container_uid": "1000",
        "container_gid": "1000",
        "resolved_revision": "LOCAL",
        "offline": False,
        "offline_semgrep_rulesets": "p/ci",
        "force": False,
        "quiet": False,
        "custom_build_arg": [],
        "debug": False,
    }
    kwargs.update(overrides)
    return kwargs


class TestBuildImage:
    @pytest.fixture
    def dockerfile(self, tmp_path):
        path = tmp_path / "Dockerfile"
        path.write_text("FROM scratch\n", encoding="utf-8")
        return path

    def test_the_gha_cache_switches_the_build_to_buildx_with_load(
        self, monkeypatch, recorded_commands, dockerfile, capfd
    ):
        """type=gha needs buildx, and buildx needs --load or the image is not kept."""
        monkeypatch.setenv("ACTIONS_RUNTIME_TOKEN", "token")
        monkeypatch.setenv("ACTIONS_CACHE_URL", "https://example.invalid/cache")
        monkeypatch.delenv("ASH_DISABLE_GHA_BUILD_CACHE", raising=False)

        _build_image(**_build_image_kwargs(dockerfile, debug=True))

        cmd = recorded_commands[0]
        assert cmd[:4] == ["docker", "buildx", "build", "--load"]
        assert "--cache-from" in cmd
        assert "type=gha,scope=ash-non-root" in cmd
        assert "Running build command:" in capfd.readouterr().out

    def test_without_the_gha_cache_a_plain_build_is_used(
        self, monkeypatch, recorded_commands, dockerfile
    ):
        monkeypatch.delenv("ACTIONS_RUNTIME_TOKEN", raising=False)

        _build_image(**_build_image_kwargs(dockerfile))

        cmd = recorded_commands[0]
        assert cmd[:2] == ["docker", "build"]
        assert "buildx" not in cmd
        assert "--cache-from" not in cmd

    def test_force_adds_no_cache_and_quiet_adds_q(
        self, monkeypatch, recorded_commands, dockerfile
    ):
        monkeypatch.setenv("ACTIONS_RUNTIME_TOKEN", "token")
        monkeypatch.setenv("ACTIONS_CACHE_URL", "https://example.invalid/cache")

        _build_image(**_build_image_kwargs(dockerfile, force=True, quiet=True))

        cmd = recorded_commands[0]
        assert "--no-cache" in cmd
        assert "-q" in cmd
        # force means rebuild from scratch, so reading a layer cache is refused.
        assert "--cache-from" not in cmd

    def test_offline_and_semgrep_rulesets_reach_the_build_args(
        self, monkeypatch, recorded_commands, dockerfile
    ):
        monkeypatch.delenv("ACTIONS_RUNTIME_TOKEN", raising=False)

        _build_image(
            **_build_image_kwargs(
                dockerfile, offline=True, offline_semgrep_rulesets="p/python"
            )
        )

        cmd = recorded_commands[0]
        assert "OFFLINE=YES" in cmd
        assert "OFFLINE_SEMGREP_RULESETS=p/python" in cmd
        assert "INSTALL_ASH_REVISION=LOCAL" in cmd

    def test_the_build_context_is_the_dockerfile_directory(
        self, monkeypatch, recorded_commands, dockerfile
    ):
        monkeypatch.delenv("ACTIONS_RUNTIME_TOKEN", raising=False)

        _build_image(**_build_image_kwargs(dockerfile))

        assert recorded_commands[0][-1] == dockerfile.parent.as_posix()

    def test_debug_reports_the_return_code(
        self, monkeypatch, recorded_commands, dockerfile, capfd
    ):
        monkeypatch.delenv("ACTIONS_RUNTIME_TOKEN", raising=False)

        _build_image(**_build_image_kwargs(dockerfile, debug=True))

        assert "Build completed with return code: 0" in capfd.readouterr().out


class TestBuildCustomImage:
    def test_a_missing_containerfile_raises_before_any_command_runs(
        self, recorded_commands, tmp_path
    ):
        with pytest.raises(FileNotFoundError, match="Custom containerfile not found"):
            _build_custom_image(
                oci_command_prefix=[],
                resolved_oci_runner="docker",
                base_image_name="ash:test",
                custom_containerfile=(tmp_path / "Containerfile").as_posix(),
                quiet=False,
                debug=False,
            )
        assert recorded_commands == []

    def test_the_base_image_is_passed_as_a_build_arg(
        self, recorded_commands, tmp_path, capfd
    ):
        containerfile = tmp_path / "Containerfile"
        containerfile.write_text("ARG ASH_BASE_IMAGE\n", encoding="utf-8")

        image = _build_custom_image(
            oci_command_prefix=["sudo"],
            resolved_oci_runner="docker",
            base_image_name="ash:ci",
            custom_containerfile=containerfile.as_posix(),
            quiet=True,
            debug=True,
        )

        assert image == "automated-security-helper:custom"
        cmd = recorded_commands[0]
        assert cmd[:3] == ["sudo", "docker", "build"]
        assert "ASH_BASE_IMAGE=ash:ci" in cmd
        assert "-q" in cmd
        assert cmd[-1] == containerfile.parent.as_posix()
        assert "Custom build completed with return code: 0" in capfd.readouterr().out

    def test_quiet_off_omits_the_q_flag(self, recorded_commands, tmp_path):
        containerfile = tmp_path / "Containerfile"
        containerfile.write_text("ARG ASH_BASE_IMAGE\n", encoding="utf-8")

        _build_custom_image(
            oci_command_prefix=[],
            resolved_oci_runner="docker",
            base_image_name="ash:ci",
            custom_containerfile=containerfile.as_posix(),
            quiet=False,
            debug=False,
        )

        assert "-q" not in recorded_commands[0]


# ---------------------------------------------------------------------------
# _assemble_run_command -- flag passthrough
# ---------------------------------------------------------------------------


def _run_command(source_dir: Path, output_dir: Path, **overrides: Any) -> List[str]:
    kwargs: Dict[str, Any] = {
        "oci_command_prefix": [],
        "resolved_oci_runner": "docker",
        "image_name": "ash:test",
        "source_dir": source_dir,
        "output_dir": output_dir,
        "offline": False,
        "debug": False,
        "color": False,
        "quiet": False,
        "progress": True,
        "verbose": False,
        "simple": False,
        "python_based_plugins_only": False,
        "cleanup": False,
        "inspect": False,
        "fail_on_findings": None,
        "phases": [ExecutionPhase.SCAN],
        "scanners": [],
        "exclude_scanners": [],
        "output_formats": [],
        "config": None,
        "config_overrides": [],
        "existing_results": None,
        "ash_plugin_modules": [],
        "strategy": ExecutionStrategy.PARALLEL,
        "ctx": None,
    }
    kwargs.update(overrides)
    return _assemble_run_command(**kwargs)


class TestAssembleRunCommandNetwork:
    def test_a_named_network_is_passed_through(self, tmp_path):
        cmd = _run_command(tmp_path, tmp_path / "out", container_network="ash-net")
        assert "--network=ash-net" in cmd

    def test_bridge_is_the_runtime_default_and_is_not_passed(self, tmp_path):
        cmd = _run_command(tmp_path, tmp_path / "out", container_network="bridge")
        assert not any(arg.startswith("--network=") for arg in cmd)

    def test_offline_forces_none_even_when_a_network_was_named(self, tmp_path):
        cmd = _run_command(
            tmp_path, tmp_path / "out", offline=True, container_network="ash-net"
        )
        assert "--network=none" in cmd
        assert "--network=ash-net" not in cmd


class TestAssembleRunCommandTerminalSize:
    def test_an_undetectable_terminal_size_is_skipped_rather_than_fatal(
        self, monkeypatch, tmp_path
    ):
        def explode(*args, **kwargs):
            raise OSError("no tty")

        # Replace the module reference rather than mutating the real shutil:
        # pytest's own terminal writer calls shutil.get_terminal_size while
        # reporting, so patching the shared module crashes the run itself.
        monkeypatch.setattr(rac, "shutil", SimpleNamespace(get_terminal_size=explode))

        cmd = _run_command(tmp_path, tmp_path / "out")

        assert not any(arg.startswith("COLUMNS=") for arg in cmd)
        assert "ash" in cmd


class TestAssembleRunCommandFlagPassthrough:
    def test_extra_context_args_are_forwarded(self, tmp_path):
        ctx = SimpleNamespace(args=["--unrecognised-passthrough"])
        cmd = _run_command(tmp_path, tmp_path / "out", ctx=ctx)
        assert "--unrecognised-passthrough" in cmd

    def test_every_boolean_flag_reaches_the_in_container_invocation(self, tmp_path):
        cmd = _run_command(
            tmp_path,
            tmp_path / "out",
            quiet=True,
            progress=False,
            color=False,
            debug=True,
            verbose=True,
            simple=True,
            python_based_plugins_only=True,
            cleanup=True,
            inspect=True,
            fail_on_findings=True,
        )
        for flag in (
            "--quiet",
            "--no-progress",
            "--no-color",
            "--debug",
            "--verbose",
            "--simple",
            "--python-based-plugins-only",
            "--cleanup",
            "--inspect",
            "--fail-on-findings",
        ):
            assert flag in cmd, flag

    def test_fail_on_findings_false_becomes_the_negative_flag(self, tmp_path):
        """None means "unset"; False is an explicit opt-out and must be sent."""
        cmd = _run_command(tmp_path, tmp_path / "out", fail_on_findings=False)
        assert "--no-fail-on-findings" in cmd
        assert "--fail-on-findings" not in cmd

    def test_fail_on_findings_unset_sends_neither_flag(self, tmp_path):
        cmd = _run_command(tmp_path, tmp_path / "out", fail_on_findings=None)
        assert "--fail-on-findings" not in cmd
        assert "--no-fail-on-findings" not in cmd

    def test_list_valued_options_are_repeated_once_per_value(self, tmp_path):
        cmd = _run_command(
            tmp_path,
            tmp_path / "out",
            scanners=["bandit", "semgrep"],
            exclude_scanners=["checkov"],
            output_formats=[ExportFormat.HTML, ExportFormat.CSV],
            config_overrides=["a=1", "b=2"],
            ash_plugin_modules=["my_plugin"],
        )
        assert cmd.count("--scanners") == 2
        assert cmd.count("--exclude-scanners") == 1
        assert cmd.count("--output-formats") == 2
        assert cmd.count("--config-overrides") == 2
        assert cmd.count("--ash-plugin-modules") == 1
        assert "bandit" in cmd and "semgrep" in cmd
        assert "checkov" in cmd
        assert "my_plugin" in cmd

    def test_config_and_existing_results_are_forwarded(self, tmp_path):
        cmd = _run_command(
            tmp_path,
            tmp_path / "out",
            config="ash.yaml",
            existing_results="prior.json",
        )
        assert cmd[cmd.index("--config") + 1] == "ash.yaml"
        assert cmd[cmd.index("--existing-results") + 1] == "prior.json"

    def test_the_summary_is_always_suppressed_inside_the_container(self, tmp_path):
        """The host prints the summary; a second copy from inside is noise."""
        cmd = _run_command(tmp_path, tmp_path / "out")
        assert cmd[-1] == "--no-show-summary"


# ---------------------------------------------------------------------------
# _execute_container
# ---------------------------------------------------------------------------


class TestExecuteContainer:
    def test_a_successful_run_returns_the_completed_process(self, monkeypatch, capfd):
        expected = create_completed_process(args=["docker"], returncode=0)
        monkeypatch.setattr(rac, "run_cmd_direct", lambda cmd, debug=False: expected)

        result = _execute_container(["docker", "run"], debug=True)

        assert result is expected
        out = capfd.readouterr().out
        assert "Running container command: docker run" in out
        assert "Container execution completed with return code: 0" in out

    def test_a_failed_run_returns_the_error_rather_than_raising(
        self, monkeypatch, capfd
    ):
        """The caller inspects returncode; raising here would lose the stderr."""
        failure = CalledProcessError(
            2, ["docker", "run"], output="out", stderr="scan failed"
        )

        def explode(cmd, debug=False):
            raise failure

        monkeypatch.setattr(rac, "run_cmd_direct", explode)

        result = _execute_container(["docker", "run"], debug=True)

        assert result is failure
        assert "Container execution failed with error:" in capfd.readouterr().out

    def test_without_debug_nothing_extra_is_printed(self, monkeypatch, capfd):
        expected = create_completed_process(args=["docker"], returncode=0)
        monkeypatch.setattr(rac, "run_cmd_direct", lambda cmd, debug=False: expected)

        _execute_container(["docker", "run"], debug=False)

        assert "Running container command" not in capfd.readouterr().out
