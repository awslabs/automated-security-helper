# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A failed container build must not continue to the run phase.

This guarantee used to be tested against the root ``ash`` bash script, in
tests/unit/test_ash_bash_entrypoint_build_failure.py. That script is gone --
``run_ash_container.py`` does the build and run it used to drive -- so the test
moved here rather than going away with it. The failure it guards is unchanged and
was observed in the wild:

1. In CI the run step cannot find the image locally, tries to pull it from
   docker.io and quay.io, and fails with "reading manifest ci in docker.io/..."
   and exit 125 -- a registry error that says nothing about the build that
   actually broke. Observed 2026-08-20, when a transient
   "curl: (35) Recv failure: Connection reset by peer" fetching grype's installer
   killed the build at ``RUN grype --version``.
2. Locally, where an image from an earlier build usually does exist, the run
   succeeds against the stale image and the whole thing exits 0. A failed build
   then reports success, having scanned with an out-of-date toolchain.

The Python path fails closed for a reason worth stating, because it is not
visible at the call site: ``_build_image`` never inspects the return code
itself. It relies on ``run_cmd_direct`` defaulting to ``check=True``, which
raises CalledProcessError, which ``run_ash_container`` catches and returns.
Flipping that default to False would reintroduce the bug silently, and these
tests are what would catch it.

The old bash tests carried a ``skipif(not ASH_SCRIPT.is_file())`` guard, so
deleting the script would have turned them green-by-skipping rather than red.
Nothing here can skip.
"""

from subprocess import CalledProcessError

import pytest

from automated_security_helper.interactions import run_ash_container as rac


@pytest.fixture
def recorded_runner(monkeypatch):
    """Replace the OCI runner with one that fails the build and records calls.

    Mirrors the fake runner the bash tests used: fail on ``build``, record
    anything else, so a test can tell whether the run step was reached.
    """
    calls = []

    def fake_run_cmd_direct(cmd_list, check=True, debug=False, shell=False):
        argv = [str(a) for a in cmd_list]
        calls.append(argv)
        if "build" in argv:
            if check:
                raise CalledProcessError(
                    1,
                    argv,
                    output="",
                    stderr='Error: building at STEP "RUN grype --version": exit status 127',
                )
            return rac.create_completed_process(
                args=argv, returncode=1, stdout="", stderr="build failed"
            )
        return rac.create_completed_process(
            args=argv, returncode=0, stdout="", stderr=""
        )

    monkeypatch.setattr(rac, "run_cmd_direct", fake_run_cmd_direct)
    monkeypatch.setattr(rac, "_resolve_oci_runner", lambda oci_runner: "fake-runner")
    return calls


def _run(tmp_path):
    source_dir = tmp_path / "src"
    source_dir.mkdir(exist_ok=True)
    return rac.run_ash_container(
        source_dir=str(source_dir),
        output_dir=str(tmp_path / "out"),
        build=True,
        run=True,
    )


class TestFailedBuildStopsTheRun:
    def test_it_reports_a_non_zero_return_code(self, recorded_runner, tmp_path):
        """The headline bug: a failed build used to report success."""
        result = _run(tmp_path)
        assert result.returncode != 0, (
            "a failed container build must not report success; exiting 0 here "
            "means a stale local image would be scanned and the failure hidden"
        )

    def test_it_never_reaches_the_run_step(self, recorded_runner, tmp_path):
        """Reaching the run step is what turns a build error into a registry error."""
        _run(tmp_path)
        ran = [argv for argv in recorded_runner if "run" in argv]
        assert ran == [], f"the run phase was reached after a failed build: {ran}"

    def test_the_build_was_actually_attempted(self, recorded_runner, tmp_path):
        """Positive control.

        Without this, a change that stopped calling the runner at all would
        satisfy both tests above for the wrong reason.
        """
        _run(tmp_path)
        assert any("build" in argv for argv in recorded_runner), (
            "no build was attempted, so the two assertions about what happens "
            "after a failed build are vacuous"
        )

    def test_the_underlying_runner_error_is_preserved(self, recorded_runner, tmp_path):
        """The message has to survive, or the next reader debugs the registry."""
        result = _run(tmp_path)
        combined = (result.stdout or "") + (result.stderr or "")
        assert "RUN grype --version" in combined

    def test_a_run_is_observable_when_the_build_succeeds(self, monkeypatch, tmp_path):
        """Control for test_it_never_reaches_the_run_step.

        That test asserts no ``run`` was recorded. If a ``run`` were never
        recorded under any conditions -- a renamed subcommand, a recorder that
        watches the wrong call -- it would pass for every input and guard
        nothing. Here the build succeeds, so a ``run`` must appear.
        """
        calls = []

        def succeeding(cmd_list, check=True, debug=False, shell=False):
            argv = [str(a) for a in cmd_list]
            calls.append(argv)
            return rac.create_completed_process(
                args=argv, returncode=0, stdout="", stderr=""
            )

        monkeypatch.setattr(rac, "run_cmd_direct", succeeding)
        monkeypatch.setattr(
            rac, "_resolve_oci_runner", lambda oci_runner: "fake-runner"
        )
        _run(tmp_path)
        assert any("run" in argv for argv in calls), (
            "no run was recorded even on a successful build, so asserting the "
            "run phase was skipped after a failed build proves nothing"
        )


class TestCheckDefaultIsWhatMakesThisWork:
    """``_build_image`` does not test the return code itself.

    It passes no ``check`` argument, so the raise depends entirely on the
    default. Pin the default, because flipping it would break the guarantee above
    without touching either function.
    """

    def test_run_cmd_direct_checks_by_default(self):
        import inspect

        default = inspect.signature(rac.run_cmd_direct).parameters["check"].default
        assert default is True, (
            "run_cmd_direct(check=...) defaults to False, so a failed container "
            "build no longer raises and _build_image falls through to the run"
        )

    def test_build_image_does_not_pass_check_itself(self):
        """Documents why the test above is load-bearing rather than trivia."""
        import inspect

        source = inspect.getsource(rac._build_image)
        assert "run_cmd_direct(" in source
        assert "check=" not in source
