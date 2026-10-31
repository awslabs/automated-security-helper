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
come from the ASH tree while the working directory holds another one, a build
that fails, a child process that is interrupted.

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

import itertools
import json
import os
import signal
import sys
from pathlib import Path
from subprocess import CalledProcessError, TimeoutExpired
from types import ModuleType, SimpleNamespace
from typing import Any, Dict, List
from unittest.mock import patch

import pytest

from automated_security_helper.core.enums import (
    AshLogLevel,
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
from automated_security_helper.utils.subprocess_utils import (
    INTERRUPT_GRACE_SECONDS,
    INTERRUPT_WAIT_SLICE_SECONDS,
    create_completed_process,
)
from tests.utils.windows_console import as_windows


# ---------------------------------------------------------------------------
# _validate_ash_revision
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestValidateAshRevision:
    def test_empty_revision_is_rejected(self):
        """An empty build-arg would expand to nothing; it is not a revision."""
        assert _validate_ash_revision("") is False

    def test_none_is_rejected(self):
        assert _validate_ash_revision(None) is False

    @pytest.mark.parametrize(
        "value",
        [
            "0123456789abcdef0123456789abcdef01234567\n",
            "v3.7.0\n",
            (
                "0123456789abcdef0123456789abcdef01234567\n"
                "89abcdef0123456789abcdef0123456789abcdef"
            ),
        ],
        ids=["commit-id-and-newline", "tag-and-newline", "two-commit-ids"],
    )
    def test_a_line_break_is_rejected_wherever_it_is(self, value):
        """`$` in re.match also matches before a final newline, so a revision with
        one passed and reached the image build as a build argument."""
        assert _validate_ash_revision(value) is False


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


# What the fixture below says the build recorded in assets/ASH_INSTALLED_REVISION.
# The real file holds the branch of the checkout the suite runs in, which is "HEAD"
# on a detached CI checkout, and get_ash_revision treats that value as no record.
RECORDED_BRANCH = "main"


@pytest.fixture
def pip_installed_ash(monkeypatch, tmp_path):
    """Make ``get_ash_revision`` take the pip-installed branch.

    The function decides between LOCAL and a git revision by probing eight
    marker paths beside the package. In this worktree they all exist, so the
    function returns LOCAL before reaching any of the dist-info handling. This
    reports those eight -- and only those eight -- as absent, points
    ``import_module`` at a package directory the test owns, and records
    RECORDED_BRANCH as the revision the build wrote.

    Returns the ``direct_url.json`` path the function will look for. The test
    decides whether it exists and what it contains.
    """
    monkeypatch.setattr(rac, "ASH_REPO_LATEST_REVISION", RECORDED_BRANCH)
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


@pytest.mark.unit
class TestGetAshRevisionFromDirectUrl:
    def test_a_local_ash_source_directory_builds_from_local_source(
        self, pip_installed_ash, tmp_path
    ):
        """pip install of an ASH source directory is a local build, not a git checkout."""
        tree = tmp_path / "ash-src"
        tree.mkdir()
        (tree / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        (tree / "pyproject.toml").write_text(
            '[project]\nname = "automated-security-helper"\n', encoding="utf-8"
        )
        pip_installed_ash.write_text(
            json.dumps({"url": tree.as_uri(), "dir_info": {}}), encoding="utf-8"
        )
        assert get_ash_revision() == "LOCAL"

    def test_a_local_path_that_is_not_an_ash_tree_is_not_local(self, pip_installed_ash):
        """Here the dist-info's own directory: no Dockerfile, no pyproject.toml.

        It is not LOCAL. test_container_image_revision.py has the cases in full.
        """
        pip_installed_ash.write_text(
            json.dumps(
                {"url": "file://" + pip_installed_ash.parent.as_posix(), "dir_info": {}}
            ),
            encoding="utf-8",
        )
        assert get_ash_revision() == RECORDED_BRANCH

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
        assert get_ash_revision() == RECORDED_BRANCH

    def test_a_url_without_vcs_info_falls_back_to_the_latest_revision(
        self, pip_installed_ash
    ):
        """An sdist or wheel URL carries no revision, so there is nothing to pin."""
        pip_installed_ash.write_text(
            json.dumps({"url": "https://example.invalid/ash-1.0.0.tar.gz"}),
            encoding="utf-8",
        )
        assert get_ash_revision() == RECORDED_BRANCH

    def test_unparseable_direct_url_json_falls_back_rather_than_raising(
        self, pip_installed_ash
    ):
        """A corrupt dist-info must not stop a container build."""
        pip_installed_ash.write_text("{ this is not json", encoding="utf-8")
        assert get_ash_revision() == RECORDED_BRANCH

    def test_a_json_document_that_is_not_an_object_builds_the_release_tag(
        self, pip_installed_ash
    ):
        """Well-formed JSON of the wrong shape records nothing, so the version's tag.

        The revision is never None, so no build passes INSTALL_ASH_REVISION=None.
        test_container_image_revision.py has the rest.
        """
        pip_installed_ash.write_text(json.dumps([1, 2, 3]), encoding="utf-8")
        assert get_ash_revision() == "v9.9.9"

    def test_no_direct_url_json_falls_back_to_the_latest_revision(
        self, pip_installed_ash
    ):
        """A plain `pip install ash` from an index has no direct_url.json."""
        assert not pip_installed_ash.exists()
        assert get_ash_revision() == RECORDED_BRANCH

    @pytest.mark.parametrize(
        "direct_url",
        [
            {
                "url": "git+https://example.invalid/ash.git",
                "vcs_info": {"vcs": "git", "requested_revision": "v9.8.7"},
            },
            {"url": "https://example.invalid/ash-1.0.0.tar.gz"},
            "{ this is not json",
        ],
        ids=["revision", "no vcs_info", "unparseable"],
    )
    def test_quiet_resolves_the_same_revision_without_logging(
        self, pip_installed_ash, direct_url, capsys
    ):
        """For the read-back error, which names the revision after the build logged it."""
        pip_installed_ash.write_text(
            direct_url if isinstance(direct_url, str) else json.dumps(direct_url),
            encoding="utf-8",
        )
        expected = get_ash_revision()
        capsys.readouterr()

        with patch.object(rac, "ASH_LOGGER") as logger:
            assert get_ash_revision(quiet=True) == expected

        assert logger.method_calls == []
        assert capsys.readouterr().out == ""


# ---------------------------------------------------------------------------
# validate_path
# ---------------------------------------------------------------------------


@pytest.mark.unit
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


#: Stand-in pids above 2**30 sit past the kernel's pid space, so a signal or
#: waitid aimed at one can only fail: no stray kill can reach a real process.
_STUB_PIDS = itertools.count(2**30 + 101)


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
        self.pid = next(_STUB_PIDS)
        self._poll_raises = poll_raises
        self._wait_raises = wait_raises
        self.terminated = False
        self.killed = False
        self.signals: List[int] = []
        self.wait_timeouts: List[Any] = []

    def poll(self):
        if self._poll_raises is not None:
            raise self._poll_raises
        return self.returncode

    def send_signal(self, signum):
        self.signals.append(signum)

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


@pytest.mark.integration
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

    def test_the_child_is_started_with_the_environment_given(self):
        """How the container run's ID reaches the runner without its command line."""
        result = run_cmd_direct(
            [
                sys.executable,
                "-c",
                "import os; print(os.environ.get('ASH_TEST_RUN_ENV', 'absent'))",
            ],
            env={**os.environ, "ASH_TEST_RUN_ENV": "given"},
        )
        assert result.stdout.strip() == "given"


@pytest.mark.skipif(os.name == "nt", reason="the runtime is sent SIGINT on POSIX")
@pytest.mark.unit
class TestRunCmdDirectInterruption:
    """Ctrl-C is passed on to the runtime, which gets the grace to stop, and re-raised.

    The runtime is not sent SIGTERM, which would kill it before it could pass the
    interrupt to the container and leave a -15 status (exit 241). Container mode
    exits 130, as an interrupted local scan does.
    """

    @pytest.fixture(autouse=True)
    def not_the_terminals_foreground(self, monkeypatch):
        """Off a terminal, as under pytest: the runtime did not get the Ctrl-C itself."""
        monkeypatch.setattr(
            os, "tcgetpgrp", lambda fd: (_ for _ in ()).throw(OSError("not a tty"))
        )

    def test_ctrl_c_forwards_the_interrupt_then_escalates_to_kill(self, stub_process):
        """A runtime that does not stop within the grace is killed, not waited on."""
        process = stub_process(
            _StubProcess(
                returncode=None,
                poll_raises=KeyboardInterrupt(),
                wait_raises=TimeoutError("did not exit"),
            )
        )

        with pytest.raises(KeyboardInterrupt):
            run_cmd_direct(["ignored"], check=False)

        assert process.signals == [signal.SIGINT]
        assert process.terminated is False
        assert process.killed is True
        assert process.wait_timeouts == [5, _REAP]

    def test_ctrl_c_does_not_kill_a_runtime_that_stops_on_the_interrupt(
        self, stub_process
    ):
        process = stub_process(
            _StubProcess(returncode=130, poll_raises=KeyboardInterrupt())
        )

        with pytest.raises(KeyboardInterrupt):
            run_cmd_direct(["ignored"], check=False)

        assert process.signals == [signal.SIGINT]
        assert process.killed is False
        assert process.wait_timeouts == [5]

    def test_a_second_ctrl_c_during_the_grace_kills_at_once(self, stub_process):
        """The operator pressed Ctrl-C again: stop waiting for the runtime."""
        process = stub_process(
            _StubProcess(
                returncode=None,
                poll_raises=KeyboardInterrupt(),
                wait_raises=KeyboardInterrupt(),
            )
        )

        with pytest.raises(KeyboardInterrupt):
            run_cmd_direct(["ignored"], check=False)

        assert process.killed is True
        assert process.wait_timeouts == [5, _REAP]

    def test_a_terminals_ctrl_c_is_not_sent_to_the_runtime_twice(
        self, stub_process, monkeypatch
    ):
        """In the terminal's foreground group, the runtime got the same SIGINT."""
        monkeypatch.setattr(sys, "stdin", SimpleNamespace(fileno=lambda: 0))
        monkeypatch.setattr(os, "tcgetpgrp", lambda fd: os.getpgrp())
        process = stub_process(
            _StubProcess(returncode=130, poll_raises=KeyboardInterrupt())
        )

        with pytest.raises(KeyboardInterrupt):
            run_cmd_direct(["ignored"], check=False)

        assert process.signals == []
        assert process.wait_timeouts == [5]


class _StillRunning(_StubProcess):
    """A runtime that outlives every timed wait, as Popen.wait reports it."""

    def wait(self, timeout=None):
        self.wait_timeouts.append(timeout)
        if timeout is not None:
            raise TimeoutExpired("runtime", timeout)
        return self.returncode


#: The waits on Windows: the grace in slices, so a second Ctrl-C lands between them.
_SLICES = [INTERRUPT_WAIT_SLICE_SECONDS] * round(
    INTERRUPT_GRACE_SECONDS / INTERRUPT_WAIT_SLICE_SECONDS
)

#: The wait after a kill: bounded, so a runtime SIGKILL did not end (in
#: uninterruptible sleep, say) is not waited for without end.
_REAP = subprocess_utils._REAP_SECONDS


@pytest.mark.unit
def test_the_wait_after_a_kill_is_a_number_not_unbounded():
    """The expectations above read ``_REAP`` from the product, so a product that
    went back to waiting without end (None) would still satisfy all of them."""
    assert isinstance(_REAP, (int, float)) and 0 < _REAP <= 30, _REAP


@pytest.mark.unit
class TestRunCmdDirectInterruptionOnWindows:
    """On Windows the runtime shares ASH's console, so a Ctrl-C there reached it too.

    Pinned here, at the caller, as well as in subprocess_utils: a run_cmd_direct that
    stopped the runtime itself rather than through the helper fails these. The
    platform and the console are stood in for (tests/utils/windows_console.py); the
    windows-latest CI leg is the real check.
    """

    def test_with_a_console_the_runtime_is_not_terminated_before_the_grace(
        self, stub_process, monkeypatch
    ):
        """terminate() at once cut short the runtime's own handling of the Ctrl-C."""
        as_windows(monkeypatch, console=True)
        process = stub_process(
            _StillRunning(returncode=None, poll_raises=KeyboardInterrupt())
        )

        with pytest.raises(KeyboardInterrupt):
            run_cmd_direct(["ignored"], check=False)

        assert process.terminated is False
        assert process.signals == []
        assert process.wait_timeouts == _SLICES + [_REAP]
        assert process.killed is True, "a runtime still running after the grace"

    def test_with_a_console_a_runtime_that_stops_in_the_grace_is_not_killed(
        self, stub_process, monkeypatch
    ):
        as_windows(monkeypatch, console=True)
        process = stub_process(
            _StubProcess(returncode=130, poll_raises=KeyboardInterrupt())
        )

        with pytest.raises(KeyboardInterrupt):
            run_cmd_direct(["ignored"], check=False)

        assert process.terminated is False
        assert process.killed is False
        assert process.wait_timeouts == _SLICES[:1]

    def test_with_a_console_a_second_ctrl_c_kills_at_once(
        self, stub_process, monkeypatch
    ):
        as_windows(monkeypatch, console=True)
        process = stub_process(
            _StubProcess(
                returncode=None,
                poll_raises=KeyboardInterrupt(),
                wait_raises=KeyboardInterrupt(),
            )
        )

        with pytest.raises(KeyboardInterrupt):
            run_cmd_direct(["ignored"], check=False)

        assert process.terminated is False
        assert process.killed is True
        assert process.wait_timeouts == _SLICES[:1] + [_REAP]

    def test_without_a_console_the_runtime_is_terminated(
        self, stub_process, monkeypatch
    ):
        """Nothing passed the Ctrl-C to the runtime, so ASH stops it."""
        as_windows(monkeypatch, console=False)
        process = stub_process(
            _StubProcess(returncode=1, poll_raises=KeyboardInterrupt())
        )

        with pytest.raises(KeyboardInterrupt):
            run_cmd_direct(["ignored"], check=False)

        assert process.terminated is True
        assert process.signals == []
        assert process.wait_timeouts == _SLICES[:1]


@pytest.mark.unit
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


@pytest.mark.unit
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


#: The source tree this suite imports ASH from. A LOCAL revision builds the
#: Dockerfile at its root, wherever ``ash`` is started from.
_ASH_SOURCE_ROOT = Path(rac.__file__).resolve().parents[2]
_ASH_SOURCE_DOCKERFILE = _ASH_SOURCE_ROOT / "Dockerfile"


def _lookup(revision: str) -> Any:
    """The Dockerfile ``_find_dockerfile`` picks (resolved), or the refusal it raises.

    Returning the refusal rather than letting it propagate keeps the comparison in
    the test's own assertion, so a run that refuses where a path was required fails
    on that assertion and shows what it got.
    """
    try:
        return Path(_find_dockerfile(revision)).resolve()
    except FileNotFoundError as error:
        return error


@pytest.mark.unit
class TestFindDockerfileLocal:
    """A LOCAL revision builds the Dockerfile of the ASH tree it was installed from.

    The scanned project, or any directory above the working directory, may hold a
    Dockerfile and a pyproject.toml of its own. Neither is ever built.
    """

    def test_a_project_root_above_the_cwd_does_not_supply_the_dockerfile(
        self, monkeypatch, tmp_path
    ):
        """Running `ash` from a subdirectory of another project builds ASH's Dockerfile."""
        repo = tmp_path / "repo"
        nested = repo / "packages" / "inner"
        nested.mkdir(parents=True)
        (repo / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        (repo / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
        monkeypatch.chdir(nested)

        assert _lookup("LOCAL") == _ASH_SOURCE_DOCKERFILE

    def test_a_stray_dockerfile_above_the_cwd_does_not_supply_the_dockerfile(
        self, monkeypatch, tmp_path
    ):
        """A Dockerfile above the working directory is neither built nor a reason to refuse."""
        outer = tmp_path / "outer"
        nested = outer / "inner"
        nested.mkdir(parents=True)
        (outer / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        monkeypatch.chdir(nested)

        assert _lookup("LOCAL") == _ASH_SOURCE_DOCKERFILE

    def test_a_dockerfile_in_the_cwd_does_not_supply_the_dockerfile(
        self, monkeypatch, tmp_path
    ):
        (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)

        assert _lookup("LOCAL") == _ASH_SOURCE_DOCKERFILE

    def test_the_ash_checkout_root_supplies_its_own_dockerfile(self, monkeypatch):
        """The developer flow: an editable install run from the root of its checkout."""
        assert _ASH_SOURCE_DOCKERFILE.is_file()
        monkeypatch.chdir(_ASH_SOURCE_ROOT)

        assert _lookup("LOCAL") == _ASH_SOURCE_DOCKERFILE

    def test_a_subdirectory_of_the_ash_checkout_supplies_its_dockerfile(
        self, monkeypatch
    ):
        """The developer flow from below the checkout root still builds the checkout."""
        assert _ASH_SOURCE_DOCKERFILE.is_file()
        monkeypatch.chdir(_ASH_SOURCE_ROOT / "automated_security_helper")

        assert _lookup("LOCAL") == _ASH_SOURCE_DOCKERFILE


@pytest.mark.unit
class TestFindDockerfileLocalFromTheInstallRecord:
    """A LOCAL revision for a package that does not run from a clone.

    ``pip install <dir>`` and ``uvx --from <dir>`` leave no clone beside the
    package; the installer records the directory in ``direct_url.json`` instead.
    That directory is the one ASH source tree there is to build, so it needs a
    Dockerfile and a pyproject.toml whose [project] name is
    ``automated-security-helper`` (in any PEP 503 spelling). Anything else -- an
    install from a wheel file, a recorded directory with no Dockerfile or with
    another project's pyproject.toml, no record at all -- is refused rather than
    resolved from the working directory.
    """

    def test_a_recorded_source_directory_supplies_the_dockerfile(
        self, pip_installed_ash, monkeypatch, tmp_path
    ):
        tree = tmp_path / "ash-source"
        tree.mkdir()
        (tree / "Dockerfile").write_text("FROM scratch AS non-root\n", encoding="utf-8")
        (tree / "pyproject.toml").write_text(
            '[project]\nname = "automated-security-helper"\n', encoding="utf-8"
        )
        pip_installed_ash.write_text(
            json.dumps({"url": tree.as_uri(), "dir_info": {}}), encoding="utf-8"
        )
        project = tmp_path / "project"
        project.mkdir()
        (project / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        (project / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
        monkeypatch.chdir(project)

        assert _lookup("LOCAL") == (tree / "Dockerfile").resolve()

    @pytest.mark.parametrize(
        "record",
        [
            pytest.param(
                lambda tmp: {
                    "url": (tmp / "ash-3.7.1-py3-none-any.whl").as_uri(),
                    "archive_info": {},
                },
                id="installed-from-a-wheel-file",
            ),
            pytest.param(
                lambda tmp: {"url": (tmp / "emptied").as_uri(), "dir_info": {}},
                id="recorded-directory-without-a-dockerfile",
            ),
            pytest.param(None, id="no-install-record"),
        ],
    )
    def test_no_recorded_source_tree_is_refused_with_what_to_do(
        self, record, pip_installed_ash, monkeypatch, tmp_path
    ):
        (tmp_path / "emptied").mkdir()
        if record is not None:
            pip_installed_ash.write_text(json.dumps(record(tmp_path)), encoding="utf-8")
        project = tmp_path / "project"
        project.mkdir()
        (project / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        monkeypatch.chdir(project)

        with pytest.raises(FileNotFoundError) as refused:
            _find_dockerfile("LOCAL")

        message = str(refused.value)
        assert "--ash-revision-to-install" in message
        assert "--no-build" in message
        assert project.as_posix() not in message


@pytest.mark.unit
class TestFindDockerfileNonLocal:
    def test_a_project_dockerfile_in_the_cwd_does_not_replace_the_packaged_one(
        self, monkeypatch, tmp_path
    ):
        """A pinned revision builds the packaged Dockerfile, not the scanned project's."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        (project / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
        assets = tmp_path / "assets"
        assets.mkdir()
        (assets / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        monkeypatch.chdir(project)
        monkeypatch.setattr(rac, "ASH_ASSETS_DIR", assets)

        assert _lookup("v1.2.3") == (assets / "Dockerfile").resolve()

    def test_a_missing_packaged_dockerfile_is_refused_with_one_in_the_cwd(
        self, monkeypatch, tmp_path
    ):
        """No packaged Dockerfile means no build, not a build of the working directory's."""
        (tmp_path / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text("[project]\n", encoding="utf-8")
        empty_assets = tmp_path / "assets"
        empty_assets.mkdir()
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(rac, "ASH_ASSETS_DIR", empty_assets)

        with pytest.raises(FileNotFoundError, match="Dockerfile not found"):
            _find_dockerfile("v1.2.3")

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

    def fake_run_cmd_direct(cmd_list, check=True, debug=False, shell=False, env=None):
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


@pytest.mark.unit
class TestBuildImage:
    @pytest.fixture
    def dockerfile(self, tmp_path):
        path = tmp_path / "Dockerfile"
        path.write_text("FROM scratch\n", encoding="utf-8")
        return path

    @pytest.fixture(autouse=True)
    def _no_inherited_base_image_override(self, monkeypatch):
        """ASH_BASE_IMAGE_OVERRIDE is read from the environment, so clear it.

        CI sets it on the base-image fallback path, and a developer may well have it exported
        after debugging that path. Left inherited, every assertion in this class about what is
        and is not in the build argv would depend on the machine running it.
        """
        monkeypatch.delenv("ASH_BASE_IMAGE_OVERRIDE", raising=False)

    def test_the_gha_cache_switches_the_build_to_buildx_with_load(
        self, monkeypatch, recorded_commands, dockerfile, capfd
    ):
        """type=gha needs buildx, and buildx needs --load or the image is not kept."""
        monkeypatch.setenv("ACTIONS_RUNTIME_TOKEN", "token")
        monkeypatch.setenv("ACTIONS_CACHE_URL", "https://example.invalid/cache")
        # ACTIONS_RESULTS_URL selects cache service v2 and adds ``version=2`` to the
        # cache argument, so a runner that exports it would change the strings below.
        monkeypatch.delenv("ACTIONS_RESULTS_URL", raising=False)
        monkeypatch.delenv("ASH_DISABLE_GHA_BUILD_CACHE", raising=False)
        # The gate probes the runner for buildx, which would otherwise shell out
        # and make this test depend on the machine running it.
        monkeypatch.setattr(rac, "_runner_supports_buildx", lambda runner: True)
        # Pin the architecture, which is part of the cache scope, so the expected
        # string does not change on arm runners.
        monkeypatch.setattr(rac.platform, "machine", lambda: "x86_64")

        # build_target is "ci" rather than this module's "non-root" default because
        # it is the stage this repository's Actions legs ask for with
        # --build-target ci, and the cache requires ACTIONS_RUNTIME_TOKEN, which only
        # exists inside Actions.
        _build_image(**_build_image_kwargs(dockerfile, build_target="ci", debug=True))

        cmd = recorded_commands[0]
        assert cmd[:4] == ["docker", "buildx", "build", "--load"]
        assert "--cache-from" in cmd
        assert "type=gha,scope=ash-ci-x86_64-online" in cmd
        # The export direction must stay fail-soft and bounded: a transient cache
        # 400 must not fail the build, and mode=max would push a multi-GB image
        # into a 10 GB per-repository quota that other workflows share.
        assert "type=gha,mode=min,ignore-error=true,scope=ash-ci-x86_64-online" in cmd
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

    def test_custom_build_args_reach_the_build(
        self, monkeypatch, recorded_commands, dockerfile
    ):
        """``--custom-build-arg`` was accepted, threaded three layers down, and dropped.

        The value arrived in this function's signature from cli/image.py and cli/scan.py via
        run_ash_scan and was then never appended to the command, so
        ``ash build-image --custom-build-arg FOO=bar`` built an image with no FOO. Nothing
        failed and nothing was logged; the arg simply had no effect.
        """
        monkeypatch.delenv("ACTIONS_RUNTIME_TOKEN", raising=False)

        _build_image(
            **_build_image_kwargs(
                dockerfile, custom_build_arg=["FOO=bar", "BAZ=qux with space"]
            )
        )

        cmd = recorded_commands[0]
        assert "FOO=bar" in cmd, (
            f"--custom-build-arg FOO=bar never reached the build command: {cmd}"
        )
        assert "BAZ=qux with space" in cmd, (
            "each value must be passed as one argv element rather than split on whitespace, "
            f"or a build-arg with a space in its value becomes two broken ones: {cmd}"
        )
        # One --build-arg per value, paired with it.
        for value in ("FOO=bar", "BAZ=qux with space"):
            assert cmd[cmd.index(value) - 1] == "--build-arg", (
                f"{value!r} must be preceded by its own --build-arg: {cmd}"
            )

    def test_the_base_image_override_redirects_the_from_reference(
        self, monkeypatch, recorded_commands, dockerfile
    ):
        """The base-image pre-pull's fallback reaches the build through this read.

        ``.github/actions/prepull-base-image`` sets ASH_BASE_IMAGE_OVERRIDE to a digest-pinned
        reference when ECR Public refuses the base image and Docker Hub serves it. It has to
        arrive as a build-arg rather than as a local tag under the ECR name: BuildKit's OCI
        worker keeps no image store, so nerdctl, finch and ``docker buildx`` on a
        docker-container driver resolve ``FROM`` against the registry and never look locally.
        Measured -- a build with the tag present still died at ``FROM`` asking the refusing
        registry.
        """
        monkeypatch.delenv("ACTIONS_RUNTIME_TOKEN", raising=False)
        pinned = "docker.io/library/python@sha256:" + "a" * 64
        monkeypatch.setenv("ASH_BASE_IMAGE_OVERRIDE", pinned)

        _build_image(**_build_image_kwargs(dockerfile))

        cmd = recorded_commands[0]
        assert f"BASE_IMAGE={pinned}" in cmd, (
            f"the override must reach the build as a build-arg: {cmd}"
        )
        assert cmd[cmd.index(f"BASE_IMAGE={pinned}") - 1] == "--build-arg", cmd

    def test_no_base_image_build_arg_when_the_override_is_unset(
        self, monkeypatch, recorded_commands, dockerfile
    ):
        """The primary path's argv must be exactly what it was before this existed.

        ECR Public answers on nearly every run, and on those runs the Dockerfile's own
        ``ARG BASE_IMAGE`` default is the correct reference. Emitting a redirect anyway would
        put a ``--build-arg BASE_IMAGE=`` on every container build in the repository and make
        the Dockerfile's default unreachable.
        """
        monkeypatch.delenv("ACTIONS_RUNTIME_TOKEN", raising=False)

        _build_image(**_build_image_kwargs(dockerfile))

        cmd = recorded_commands[0]
        assert not any(arg.startswith("BASE_IMAGE=") for arg in cmd), (
            f"nothing should redirect FROM when no registry fallback happened: {cmd}"
        )

    def test_an_empty_or_blank_override_is_ignored(
        self, monkeypatch, recorded_commands, dockerfile
    ):
        """Writing an empty value to GITHUB_ENV is how a composite action unsets a variable.

        run-scan-test already does exactly that to clear the Actions cache credentials after
        the build, so an empty ASH_BASE_IMAGE_OVERRIDE is a reachable state rather than a
        hypothetical one. ``--build-arg BASE_IMAGE=`` would make ``FROM ${BASE_IMAGE}`` empty
        and fail the build with a Dockerfile parse error, three steps from the cause.
        """
        monkeypatch.delenv("ACTIONS_RUNTIME_TOKEN", raising=False)
        monkeypatch.setenv("ASH_BASE_IMAGE_OVERRIDE", "   ")

        _build_image(**_build_image_kwargs(dockerfile))

        cmd = recorded_commands[0]
        assert not any(arg.startswith("BASE_IMAGE=") for arg in cmd), (
            f"a blank override must be treated as unset, not passed through: {cmd}"
        )

    def test_an_explicit_custom_build_arg_outranks_the_override(
        self, monkeypatch, recorded_commands, dockerfile
    ):
        """A caller who names BASE_IMAGE themselves means it.

        A duplicate ``--build-arg`` is last-wins -- measured on docker 25.0.16 -- so the
        override is emitted first and the caller's own value lands after it. Asserted on
        position rather than presence, because both are present and only the order decides
        which one the build uses.
        """
        monkeypatch.delenv("ACTIONS_RUNTIME_TOKEN", raising=False)
        monkeypatch.setenv(
            "ASH_BASE_IMAGE_OVERRIDE", "docker.io/library/python:from-ci"
        )
        chosen = "BASE_IMAGE=my.registry.invalid/python:mine"

        _build_image(**_build_image_kwargs(dockerfile, custom_build_arg=[chosen]))

        cmd = recorded_commands[0]
        assert cmd.index(chosen) > cmd.index(
            "BASE_IMAGE=docker.io/library/python:from-ci"
        ), (
            "the caller's explicit value has to come last, or the CI fallback silently "
            f"overrides an intentional choice: {cmd}"
        )


@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.unit
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


@pytest.mark.unit
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

    def test_config_is_forwarded(self, tmp_path, monkeypatch):
        """The file is mounted read-only and the inner scan is given its path there.

        See test_container_config_reaches_the_scan.py.
        """
        operator = tmp_path / "operator"
        operator.mkdir()
        (operator / "ash.yaml").write_text("project_name: p\n", encoding="utf-8")
        monkeypatch.chdir(operator)
        source = tmp_path / "src"
        source.mkdir()

        cmd = _run_command(source, tmp_path / "out", config="ash.yaml")

        assert cmd[cmd.index("--config") + 1] == "/ash-config/ash.yaml"
        assert (
            f"type=bind,source={(operator / 'ash.yaml').resolve()},"
            "destination=/ash-config/ash.yaml,readonly"
        ) in cmd

    def test_config_is_forwarded_at_its_container_path(self, tmp_path):
        """An in-source config is read through the /src mount, so the inner
        scan is given its path there, not the host path, which names nothing
        inside the container."""
        config = tmp_path / "ash.yaml"
        config.write_text("project_name: t\n", encoding="utf-8")
        cmd = _run_command(tmp_path, tmp_path / "out", config=str(config))
        assert cmd[cmd.index("--config") + 1] == "/src/ash.yaml"

    def test_existing_results_becomes_the_declared_flag(self, tmp_path):
        """Inverted assertion.

        This previously asserted that ``--existing-results <path>`` reaches the
        container. No such option is declared anywhere on the CLI, and the container
        entrypoint is that same CLI, so the flag is a usage error inside -- exit 2, which
        the host's read-back cannot tell from a dirty scan. The path was wrong there
        regardless: it is a host path, and the output directory is mounted at /out.

        ``--use-existing`` is the declared option. It resolves
        ash_aggregated_results.json from the inner ``--output-dir``, which is the same
        file through the mount, so the host's own resolution is reproduced rather than
        re-sent as an unreachable path.
        """
        out = tmp_path / "out"
        cmd = _run_command(
            tmp_path,
            out,
            existing_results=(out / "ash_aggregated_results.json").as_posix(),
        )
        assert "--use-existing" in cmd
        assert "--existing-results" not in cmd

    def test_an_unset_existing_results_sends_neither_flag(self, tmp_path):
        cmd = _run_command(tmp_path, tmp_path / "out", existing_results=None)
        assert "--use-existing" not in cmd
        assert "--existing-results" not in cmd

    def test_an_empty_existing_results_sends_neither_flag(self, tmp_path):
        """Surrounding contract: the condition the host's cleanup exemption has to match.

        ``if existing_results:`` means an empty string asks the inner scan to read nothing.
        ``_discard_prior_run_artifacts`` tests the same way, so a caller passing "" cannot
        get the cleanup skipped here and the read skipped there -- which would leave a
        previous run's results file to be read back as this invocation's own. The
        discriminating test for that pair lives on the host side, in
        ``test_stale_results_provenance``; this one pins the half it has to agree with.
        """
        cmd = _run_command(tmp_path, tmp_path / "out", existing_results="")
        assert "--use-existing" not in cmd
        assert "--existing-results" not in cmd

    def test_an_existing_results_path_the_container_cannot_reach_is_reported(
        self, tmp_path, monkeypatch
    ):
        """The translation is exact only for the output directory's own results file.

        ``run_ash_scan`` is importable, so a caller can pass any path. The container has
        one output mount and ``--use-existing`` always reads that directory, so a path
        elsewhere is silently substituted -- which is worth a warning rather than a
        quiet swap.
        """
        warnings: List[str] = []
        monkeypatch.setattr(
            rac,
            "ASH_LOGGER",
            SimpleNamespace(
                warning=lambda msg, *a, **k: warnings.append(str(msg)),
                debug=lambda *a, **k: None,
                info=lambda *a, **k: None,
            ),
        )

        cmd = _run_command(
            tmp_path,
            tmp_path / "out",
            existing_results=(tmp_path / "elsewhere" / "old.json").as_posix(),
        )

        assert "--use-existing" in cmd
        assert any("old.json" in message for message in warnings), warnings

    def test_the_summary_is_always_suppressed_inside_the_container(self, tmp_path):
        """The host prints the summary; a second copy from inside is noise."""
        cmd = _run_command(tmp_path, tmp_path / "out")
        assert cmd[-1] == "--no-show-summary"


# ---------------------------------------------------------------------------
# The assembled argv against the CLI that will actually parse it
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestTheInnerArgvIsAcceptedByTheInnerCli:
    """Every flag in the container argv has to exist on the CLI that receives it.

    This closes a class rather than an instance. ``--existing-results`` was emitted here
    for as long as the file has existed and is declared nowhere; the in-container CLI
    rejects an unknown option with a usage error, and the real ``ash`` group exits
    ASH_EXIT_USAGE_ERROR for it, a code apart from 2, ASH's code for actionable
    findings, so the host's read-back tells the rejected invocation from a dirty scan.

    Asserting a flag is ``in cmd`` cannot catch that: presence in the list it was written
    into is guaranteed by the writing. The question is whether the receiving parser
    accepts it, so the assertion is on the parse, and on the value the flag resolves to.
    The real ``click`` command is built from the real ``typer`` app to answer it.
    """

    def _inner_argv(self, tmp_path, **overrides) -> List[str]:
        cmd = _run_command(tmp_path, tmp_path / "out", **overrides)
        return cmd[cmd.index("ash") + 1 :]

    def _parse(self, argv: List[str]):
        import typer.main

        from automated_security_helper.cli.scan import run_ash_scan_cli_command

        app = typer.Typer()
        app.command()(run_ash_scan_cli_command)
        return typer.main.get_command(app).make_context("ash", list(argv))

    def test_every_flag_a_fully_populated_invocation_emits_is_declared(self, tmp_path):
        out = tmp_path / "out"
        argv = self._inner_argv(
            tmp_path,
            quiet=True,
            progress=False,
            color=False,
            debug=True,
            verbose=True,
            simple=True,
            python_based_plugins_only=True,
            cleanup=True,
            inspect=True,
            fail_on_findings=False,
            fail_on_incomplete_scanners=True,
            phases=[ExecutionPhase.SCAN],
            scanners=["bandit"],
            exclude_scanners=["checkov"],
            output_formats=[ExportFormat.HTML],
            config="ash.yaml",
            config_overrides=["a=1"],
            existing_results=(out / "ash_aggregated_results.json").as_posix(),
            ash_plugin_modules=["m"],
            strategy=ExecutionStrategy.PARALLEL,
            shard_index=0,
            shard_count=2,
            ignore_suppressions=True,
            log_level=AshLogLevel.ERROR,
        )

        with self._parse(argv) as ctx:
            # The value, not the flag's presence: the defect this replaces was a flag
            # that was present and meant nothing.
            assert ctx.params["use_existing"] is True
            assert ctx.params["fail_on_findings"] is False
            assert ctx.params["fail_on_incomplete_scanners"] is True
            assert ctx.params["ignore_suppressions"] is True
            assert ctx.params["log_level"] == AshLogLevel.ERROR

    def test_the_undeclared_flag_this_replaced_is_still_rejected(self):
        """Guards the premise, and records why the rejection was invisible.

        If --existing-results were ever declared, emitting --use-existing instead would
        be a silent behavior change rather than a fix. The exit code is asserted because
        it is the reason nobody noticed: click's usage error exits 2, and 2 is also ASH's
        code for actionable findings. This parses with a bare command, not the ``ash``
        group, so it sees click's own code; ``ash`` maps it to ASH_EXIT_USAGE_ERROR.
        """
        from typer.exceptions import TyperException

        with pytest.raises(TyperException) as refusal:
            self._parse(["--existing-results", "/host/path/results.json"])

        assert "--existing-results" in str(refusal.value)
        assert refusal.value.exit_code == 2


# ---------------------------------------------------------------------------
# _execute_container
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestExecuteContainer:
    def test_a_successful_run_returns_the_completed_process(self, monkeypatch, capfd):
        expected = create_completed_process(args=["docker"], returncode=0)
        monkeypatch.setattr(
            rac, "run_cmd_direct", lambda cmd, debug=False, env=None: expected
        )

        result = _execute_container(["docker", "run"], debug=True)

        assert result is expected
        out = capfd.readouterr().out
        assert "Running container command: docker run" in out
        assert "Container execution completed with return code: 0" in out

    def test_a_failed_run_returns_the_error_rather_than_raising(
        self, monkeypatch, capfd
    ):
        """The caller inspects returncode; raising here would lose the stderr."""
        command = [
            "docker",
            "run",
            "img",
            "ash",
            "--config-overrides",
            "project_name=hunter2",
        ]
        failure = CalledProcessError(2, command, output="out", stderr="scan failed")

        def explode(cmd, debug=False, env=None):
            raise failure

        monkeypatch.setattr(rac, "run_cmd_direct", explode)

        result = _execute_container(command, debug=True)

        assert result is failure
        out = capfd.readouterr().out
        # The line names the status and the command in its shown form, each
        # override value as its key, never the raw argv.
        assert "hunter2" not in out, out
        (failure_line,) = [
            line for line in out.splitlines() if "Container execution failed" in line
        ]
        assert "code 2" in failure_line, failure_line
        assert "project_name" in failure_line, failure_line

    def test_without_debug_nothing_extra_is_printed(self, monkeypatch, capfd):
        expected = create_completed_process(args=["docker"], returncode=0)
        monkeypatch.setattr(
            rac, "run_cmd_direct", lambda cmd, debug=False, env=None: expected
        )

        _execute_container(["docker", "run"], debug=False)

        assert "Running container command" not in capfd.readouterr().out
