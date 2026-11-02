# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``OCI_RUNNER`` is read as the environment's value by the real commands.

``oci_runner_for_this_run`` takes ``from_environment``, which each command works out
from where click took its ``--oci-runner`` value (``cli/params.py``). The unit tests of
the function give that bit directly, and the tests that call a command function with a
``MagicMock`` context always see False, so a wrong parameter name or a source that
never compares equal would make every environment value count as typed, and a
relative ``OCI_RUNNER`` would be run from the working directory with no test failing.

These run the commands through the click parser, with ``OCI_RUNNER`` in the
environment, and watch what the command hands ``run_ash_scan``:

* ``ash scan --mode container`` and ``ash build-image`` refuse a relative
  ``OCI_RUNNER`` with exit 3, name the variable, and start nothing;
* the same relative path typed after ``--oci-runner`` is read against the working
  directory and handed on;
* ``ash scan`` in its default local mode never reads the variable: no refusal, and
  no warning about it.
"""

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

#: The refusal's exit code, the one ./ash and Invoke-ASH refuse the same input with.
REFUSED = 3


@pytest.fixture(autouse=True)
def _a_clean_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A working directory of its own, and none of the variables the commands read."""
    monkeypatch.chdir(tmp_path)
    for name in ("OCI_RUNNER", "OCI_RUNNER_WRAPPER", "ASH_MODE"):
        monkeypatch.delenv(name, raising=False)
    (tmp_path / "source").mkdir()


@pytest.fixture
def scan_reads_the_runner(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    """``ash scan``'s reader of the runner value, recording its calls and returning
    the value as it got it, so a test sees whether the command read it at all."""
    reader = MagicMock(side_effect=lambda value, from_environment: value)
    monkeypatch.setattr(
        "automated_security_helper.cli.scan.oci_runner_for_this_run", reader
    )
    return reader


def _scan(*arguments: str, **environment: str):
    """``ash scan`` through the parser with ``run_ash_scan`` stubbed: (result, stub)."""
    with patch("automated_security_helper.cli.scan.run_ash_scan") as run:
        result = CliRunner().invoke(
            app,
            [
                "scan",
                "--source-dir",
                "source",
                "--output-dir",
                "output",
                *arguments,
            ],
            env=environment,
        )
    return result, run


def _build_image(*arguments: str, **environment: str):
    """``ash build-image --no-run`` through the parser: (result, stub)."""
    with patch("automated_security_helper.cli.image.run_ash_scan") as run:
        result = CliRunner().invoke(
            app, ["build-image", "--no-run", *arguments], env=environment
        )
    return result, run


def _handed_on(run: MagicMock) -> str:
    run.assert_called_once()
    return run.call_args.kwargs["oci_runner"]


def test_scan_in_container_mode_refuses_a_relative_oci_runner_from_the_environment():
    result, run = _scan("--mode", "container", OCI_RUNNER="bin/docker")

    assert result.exit_code == REFUSED, result.output
    assert "OCI_RUNNER" in result.output, result.output
    assert repr("bin/docker") in result.output, result.output
    run.assert_not_called()


def test_scan_in_container_mode_reads_a_typed_relative_path_from_the_cwd():
    result, run = _scan("--mode", "container", "--oci-runner", "bin/docker")

    assert result.exit_code == 0, result.output
    assert _handed_on(run) == os.path.abspath(os.path.join("bin", "docker"))


def test_scan_in_container_mode_hands_on_a_command_name_from_the_environment():
    result, run = _scan("--mode", "container", OCI_RUNNER="podman")

    assert result.exit_code == 0, result.output
    assert _handed_on(run) == "podman"


def test_scan_in_nix_mode_refuses_a_relative_oci_runner_from_the_environment():
    # Nix mode removes the containers an earlier container run left, with the runner.
    result, run = _scan("--mode", "nix", OCI_RUNNER="bin/docker")

    assert result.exit_code == REFUSED, result.output
    assert "OCI_RUNNER" in result.output, result.output
    run.assert_not_called()


def test_a_workspace_dry_run_refuses_what_the_run_refuses():
    """The refusal comes before the workspace block, so the dry run names the same
    first problem as the real run instead of exiting 0 on it."""
    result, run = _scan(
        "--mode",
        "container",
        "--workspace",
        "auto",
        "--dry-run",
        OCI_RUNNER="bin/docker",
    )

    assert result.exit_code == REFUSED, result.output
    assert "OCI_RUNNER" in result.output, result.output
    run.assert_not_called()


@pytest.mark.parametrize("mode", ["container", "nix"])
def test_scan_refuses_a_relative_oci_runner_wrapper_in_a_mode_that_uses_it(mode):
    # Nix mode runs the wrapper only to sweep containers an earlier run left, which
    # is skipped when there are none: the refusal does not wait for one.
    result, run = _scan("--mode", mode, OCI_RUNNER_WRAPPER="bin/sudo")

    assert result.exit_code == REFUSED, result.output
    assert "OCI_RUNNER_WRAPPER" in result.output, result.output
    assert repr("bin/sudo") in result.output, result.output
    run.assert_not_called()


def test_scan_in_local_mode_never_reads_oci_runner_wrapper():
    result, run = _scan(OCI_RUNNER_WRAPPER="bin/sudo")

    assert result.exit_code == 0, result.output
    run.assert_called_once()
    assert "OCI_RUNNER_WRAPPER" not in result.output, result.output


def test_build_image_refuses_a_relative_oci_runner_wrapper():
    result, run = _build_image(OCI_RUNNER_WRAPPER="bin/sudo")

    assert result.exit_code == REFUSED, result.output
    assert "OCI_RUNNER_WRAPPER" in result.output, result.output
    run.assert_not_called()


def test_scan_in_local_mode_never_reads_oci_runner(scan_reads_the_runner):
    result, run = _scan(OCI_RUNNER="bin/docker")

    assert result.exit_code == 0, result.output
    run.assert_called_once()
    assert "OCI_RUNNER" not in result.output, result.output
    scan_reads_the_runner.assert_not_called()


def test_scan_in_local_mode_never_reads_a_tilde_oci_runner_with_no_home(
    scan_reads_the_runner, monkeypatch
):
    monkeypatch.setenv("HOME", "")
    result, run = _scan(OCI_RUNNER="~/bin/docker")

    assert result.exit_code == 0, result.output
    run.assert_called_once()
    assert "OCI_RUNNER" not in result.output, result.output
    scan_reads_the_runner.assert_not_called()


def test_scan_in_container_mode_reads_oci_runner_as_from_the_environment(
    scan_reads_the_runner,
):
    """The control for the two above: the same command in container mode does read
    the value, and works out from click that it came from the environment."""
    result, run = _scan("--mode", "container", OCI_RUNNER="podman")

    assert result.exit_code == 0, result.output
    run.assert_called_once()
    scan_reads_the_runner.assert_called_once_with("podman", from_environment=True)


def test_build_image_refuses_a_relative_oci_runner_from_the_environment():
    result, run = _build_image(OCI_RUNNER="bin/docker")

    assert result.exit_code == REFUSED, result.output
    assert "OCI_RUNNER" in result.output, result.output
    assert repr("bin/docker") in result.output, result.output
    run.assert_not_called()


def test_build_image_reads_the_same_path_typed_against_the_working_directory():
    result, run = _build_image("--oci-runner", "bin/docker")

    assert result.exit_code == 0, result.output
    assert _handed_on(run) == os.path.abspath(os.path.join("bin", "docker"))


def test_build_image_hands_on_a_command_name_from_the_environment():
    result, run = _build_image(OCI_RUNNER="podman")

    assert result.exit_code == 0, result.output
    assert _handed_on(run) == "podman"
