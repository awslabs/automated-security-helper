# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A failed image build names its command the way the run's own text does.

A failed build's error text quotes the full build command. That command can
carry a value the operator's configuration chain reads from the environment:
``--custom-build-arg`` takes the operator's shell-expanded text, so the same
value a run would hide can sit in the build argv. The error print, and the
``--debug`` echo of the build command, show the command with each
``--config-overrides`` value as its key and the chain's environment values
hidden, exactly as the run's own command text is shown. The build's own
output is not covered by this: it streams to the terminal as the build runs.
"""

from __future__ import annotations

from pathlib import Path
from subprocess import CalledProcessError
from typing import List

import pytest

from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.utils import subprocess_utils

#: A value the configuration chain reads from the environment. Nothing
#: secret: a recognizable marker whose absence from printed text is asserted.
PLANTED = "ash-planted-value-5f2e-0123456789"


def test_the_failure_text_hides_a_carried_value_in_the_argv():
    error = CalledProcessError(
        2, ["docker", "build", "--build-arg", f"TOKEN={PLANTED}", "/ctx"]
    )
    text = rac._shown_build_failure(error, (PLANTED,))
    assert PLANTED not in text, text
    assert "returned non-zero exit status 2" in text, text
    assert "docker" in text, text


def test_the_failure_text_hides_a_carried_value_in_any_other_error():
    text = rac._shown_build_failure(RuntimeError(f"disk full at {PLANTED}"), (PLANTED,))
    assert PLANTED not in text, text
    assert "disk full" in text, text


def test_the_failure_text_shows_an_override_value_as_its_key_with_no_carrier():
    """``shown_arguments`` alone, with nothing carried: a --config-overrides
    value in the failed command's argv prints as its key."""
    error = CalledProcessError(
        1, ["ash", "--config-overrides", f"reporters.token={PLANTED}"]
    )
    text = rac._shown_build_failure(error, ())
    assert PLANTED not in text, text
    assert "reporters.token" in text, text


def test_the_debug_command_text_hides_a_value_the_spawn_carries():
    """The ``--debug`` echo of the build command reads the spawn's carrier,
    which the build phase sets around its builds."""
    with subprocess_utils._spawn_values((PLANTED,)):
        text = rac._shown_command_text(
            ["docker", "build", "--build-arg", f"TOKEN={PLANTED}", "/ctx"]
        )
    assert PLANTED not in text, text
    assert "docker build" in text, text


@pytest.fixture
def failing_build(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> List[List[str]]:
    """run_ash_container wired so its build command fails, recording argv."""
    commands: List[List[str]] = []

    def failing_run(cmd_list, check=True, debug=False, shell=False):
        argv = [str(item) for item in cmd_list if item is not None]
        commands.append(argv)
        raise CalledProcessError(1, argv)

    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "Dockerfile").write_text("FROM scratch AS non-root\n", encoding="utf-8")
    monkeypatch.setattr(rac, "ASH_ASSETS_DIR", assets)
    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.setattr(
        rac, "_find_runner", lambda _name: "/nonexistent/ash-test/docker"
    )
    monkeypatch.setattr(rac, "_runner_supports_buildx", lambda _runner: False)
    monkeypatch.setattr(rac, "run_cmd_direct", failing_run)
    for name in ("ASH_BASE_IMAGE_OVERRIDE", "ASH_BASE_OCI_LAYOUT", "ASH_CONFIG"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ASH_PROBE_PLANTED", PLANTED)
    (tmp_path / "src").mkdir()
    # The chain reads the variable; the file sits outside the scanned tree,
    # so a local scan counts it the operator's own and the value is carried.
    (tmp_path / "own.yaml").write_text(
        "project_name: ${ASH_PROBE_PLANTED}\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    return commands


def test_a_failed_build_does_not_print_a_value_the_chain_reads(failing_build, capsys):
    """The planted control first: the value really is in the failed build's
    argv, through the operator's own --custom-build-arg text. The error
    print still holds no copy of it."""
    result = rac.run_ash_container(
        source_dir="src",
        output_dir="out",
        ash_revision_to_install="v3.7.0",
        config="own.yaml",
        custom_build_arg=[f"TOKEN={PLANTED}"],
        build=True,
        run=True,
    )

    assert not rac.container_was_started(result)
    build_argv = [argv for argv in failing_build if "build" in argv]
    assert build_argv and any(
        PLANTED in argument for argv in build_argv for argument in argv
    ), failing_build
    shown = capsys.readouterr()
    text = shown.out + shown.err
    assert "Error building ASH image" in text, text
    assert PLANTED not in text, text


def test_a_failed_build_alone_prints_no_raw_argv_quote(failing_build, capsys):
    """``--no-run`` builds too: the chain is readable, so its values are
    carried; a chain the run-phase check would refuse builds as before,
    with nothing carried."""
    result = rac.run_ash_container(
        source_dir="src",
        output_dir="out",
        ash_revision_to_install="v3.7.0",
        config="own.yaml",
        custom_build_arg=[f"TOKEN={PLANTED}"],
        build=True,
        run=False,
    )

    assert not rac.container_was_started(result)
    shown = capsys.readouterr()
    text = shown.out + shown.err
    assert "Error building ASH image" in text, text
    assert PLANTED not in text, text


#: A literal the operator typed, never read from the environment, so the
#: value hiding has no claim on it: the over-masking control.
LITERAL = "ash-literal-value-7c3b-0123456789"


def _wire_echoing_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, exit_code: int
) -> None:
    """run_ash_container wired to a real spawn of an echoing build runtime.

    The stand-in quotes every argument it received back on stdout and on
    stderr and exits with ``exit_code``, running nothing else: the captured
    output then holds whatever values rode --build-arg, which is what the
    --debug dump of a failed build repeats."""
    runtime = tmp_path / "echoing-runtime"
    runtime.write_text(
        f'#!/bin/sh\necho "ECHO-OUT $@"\necho "ECHO-ERR $@" 1>&2\nexit {exit_code}\n',
        encoding="utf-8",
    )
    runtime.chmod(0o755)

    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "Dockerfile").write_text("FROM scratch AS non-root\n", encoding="utf-8")
    monkeypatch.setattr(rac, "ASH_ASSETS_DIR", assets)
    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.setattr(rac, "_find_runner", lambda _name: str(runtime))
    monkeypatch.setattr(rac, "_runner_supports_buildx", lambda _runner: False)
    for name in ("ASH_BASE_IMAGE_OVERRIDE", "ASH_BASE_OCI_LAYOUT", "ASH_CONFIG"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("ASH_PROBE_PLANTED", PLANTED)
    (tmp_path / "src").mkdir()
    (tmp_path / "own.yaml").write_text(
        "project_name: ${ASH_PROBE_PLANTED}\n", encoding="utf-8"
    )
    (tmp_path / "plain.yaml").write_text("project_name: demo\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)


@pytest.fixture
def echoing_build(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The echoing build runtime, failing: it exits 1."""
    _wire_echoing_build(tmp_path, monkeypatch, 1)


@pytest.fixture
def echoing_build_that_succeeds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The echoing build runtime, succeeding: it exits 0."""
    _wire_echoing_build(tmp_path, monkeypatch, 0)


def _dump_section(stdout_text: str) -> str:
    """The --debug dump of the failed build's captured output: everything on
    the console's stdout from the first "Build stdout:" label on. The dump is
    the handler's own print, after the spawn ended, so nothing follows it on
    stdout; the live stream of the build's output as it ran is a different
    surface and stays out of this slice."""
    index = stdout_text.find("Build stdout:")
    assert index != -1, stdout_text
    return stdout_text[index:]


def test_the_debug_dump_of_a_failed_build_hides_a_carried_value(echoing_build, capsys):
    """The build runtime quotes the carried --build-arg value back in its
    output; the --debug dump of that captured output hides it."""
    result = rac.run_ash_container(
        source_dir="src",
        output_dir="out",
        ash_revision_to_install="v3.7.0",
        config="own.yaml",
        custom_build_arg=[f"TOKEN={PLANTED}"],
        build=True,
        run=False,
        debug=True,
    )

    assert not rac.container_was_started(result)
    shown = capsys.readouterr()
    # The control: the runtime's echoed output really came back, so an
    # empty capture cannot pass this cell.
    assert "ECHO-OUT" in shown.out, shown.out
    dump = _dump_section(shown.out)
    assert "Build stderr:" in dump, dump
    assert PLANTED not in dump, dump


def test_the_debug_dump_keeps_the_operators_own_literal(echoing_build, capsys):
    """The over-masking control: a literal the operator typed is not a
    carried value, and the dump keeps it readable."""
    result = rac.run_ash_container(
        source_dir="src",
        output_dir="out",
        ash_revision_to_install="v3.7.0",
        config="plain.yaml",
        custom_build_arg=[f"TOKEN={LITERAL}"],
        build=True,
        run=False,
        debug=True,
    )

    assert not rac.container_was_started(result)
    shown = capsys.readouterr()
    dump = _dump_section(shown.out)
    assert "Build stderr:" in dump, dump
    assert LITERAL in dump, dump


def test_the_streamed_build_output_hides_a_carried_value(echoing_build, capsys):
    """The live stream, without --debug: the build runtime quotes the
    carried value back and its output streams to the console as it runs,
    so each streamed line hides the carried values."""
    result = rac.run_ash_container(
        source_dir="src",
        output_dir="out",
        ash_revision_to_install="v3.7.0",
        config="own.yaml",
        custom_build_arg=[f"TOKEN={PLANTED}"],
        build=True,
        run=False,
        debug=False,
    )

    assert not rac.container_was_started(result)
    shown = capsys.readouterr()
    text = shown.out + shown.err
    # The controls: the stream really carried the echoed output on both
    # pipes, and no --debug dump printed.
    assert "ECHO-OUT" in text and "ECHO-ERR" in text, text
    assert "Build stdout:" not in text, text
    assert PLANTED not in text, text


def test_the_streamed_build_output_keeps_the_operators_own_literal(
    echoing_build, capsys
):
    """The over-masking control for the stream: a literal the operator
    typed is not a carried value, and the streamed lines keep it."""
    result = rac.run_ash_container(
        source_dir="src",
        output_dir="out",
        ash_revision_to_install="v3.7.0",
        config="plain.yaml",
        custom_build_arg=[f"TOKEN={LITERAL}"],
        build=True,
        run=False,
        debug=False,
    )

    assert not rac.container_was_started(result)
    shown = capsys.readouterr()
    text = shown.out + shown.err
    assert "ECHO-OUT" in text and "ECHO-ERR" in text, text
    assert LITERAL in text, text


def test_a_build_that_succeeds_streams_no_carried_value(
    echoing_build_that_succeeds, capsys
):
    """The success path: the stream hides a carried value whether or not the
    build fails. The runtime quotes the value back and exits 0, so there is no
    failure text or dump to cover for it; only the streamed lines can show it."""
    rac.run_ash_container(
        source_dir="src",
        output_dir="out",
        ash_revision_to_install="v3.7.0",
        config="own.yaml",
        custom_build_arg=[f"TOKEN={PLANTED}"],
        build=True,
        run=False,
        debug=False,
    )

    shown = capsys.readouterr()
    text = shown.out + shown.err
    # The controls: the stream really carried the echoed output on both pipes,
    # and the build did not fail.
    assert "ECHO-OUT" in text and "ECHO-ERR" in text, text
    assert "Error building ASH image" not in text, text
    assert PLANTED not in text, text
