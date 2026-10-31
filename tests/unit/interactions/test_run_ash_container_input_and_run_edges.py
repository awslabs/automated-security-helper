# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Edges of run_ash_container's input checks, image build and run phase.

* A direct_url.json whose url or revision is not a string falls back, and
  ``quiet`` silences every line of the revision resolution.
* A source path that cannot be looked at is a ValueError, not a traceback.
* A carried value holding a line break is hidden line by line in the stream.
* The runtime's carriage returns reach the captured output untranslated, and a
  reader still running after the join is said.
* The buildx probe runs through OCI_RUNNER_WRAPPER as the build does.
* An id of more digits than int() takes is still read as zero or not.
* A custom Containerfile's non-root stage is found past a byte order mark and
  across a line continuation, and --force reaches the custom build.
* The output directory is refused over the source, and the env-file directory
  inside it, by the directories' identity, not only by their spelled paths.
* The default output directory is made under the run's own guard, and a linked
  output directory is refused right before it is made.
* --config under an unsearchable directory, and a symlink loop in a mounted path,
  are refusals with exit 3, not tracebacks.
* ASH_OUTER_RUN_ID, which the run command sets, is never passed from a config.
* A SIGTERM handler installed outside Python leaves the run's guard off.

Nothing here starts a process: every runtime is a function or an in-memory pipe.
"""

from __future__ import annotations

import io
import json
import logging
import os
import signal
import sys
import tempfile
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.inner_run_outcome import OUTER_RUN_ID_ENV
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.subprocess_utils import create_completed_process

pytestmark = pytest.mark.unit


class _Records(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: List[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def messages(self, level: int) -> List[str]:
        return [r.getMessage() for r in self.records if r.levelno == level]


@pytest.fixture
def logged():
    handler = _Records()
    previous = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield handler
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(previous)


# ---------------------------------------------------------------------------
# get_ash_revision
# ---------------------------------------------------------------------------


@pytest.fixture
def installed_record(tmp_path, monkeypatch):
    """An ASH installed outside a checkout, whose direct_url.json the test writes."""
    record = tmp_path / "direct_url.json"
    monkeypatch.setattr(rac, "_is_checkout", lambda path: False)
    monkeypatch.setattr(rac, "_direct_url_json_path", lambda: record)
    monkeypatch.setattr(rac, "_is_file", lambda path: True)
    monkeypatch.setattr(rac, "_source_tree_in", lambda document: False)
    return record


def test_a_direct_url_whose_url_is_not_a_string_falls_back(installed_record, logged):
    installed_record.write_text(json.dumps({"url": 5}), encoding="utf-8")

    rac.get_ash_revision()

    assert any(
        "Failed to read direct_url.json" in m for m in logged.messages(logging.WARNING)
    )


def test_a_direct_url_whose_revision_is_not_a_string_falls_back(
    installed_record, logged
):
    installed_record.write_text(
        json.dumps({"url": "https://example.invalid/r", "vcs_info": {"commit_id": 7}}),
        encoding="utf-8",
    )

    revision = rac.get_ash_revision()

    assert revision is None or isinstance(revision, str)
    assert any(
        "Failed to read direct_url.json" in m for m in logged.messages(logging.WARNING)
    ), logged.messages(logging.WARNING)


def test_quiet_silences_the_local_path_line(installed_record, logged):
    installed_record.write_text(
        json.dumps({"url": "file:///nowhere/ash-source"}), encoding="utf-8"
    )

    rac.get_ash_revision(quiet=True)

    assert not any("local path" in m for m in logged.messages(logging.INFO))


# ---------------------------------------------------------------------------
# validate_path
# ---------------------------------------------------------------------------


def test_a_path_that_cannot_be_looked_at_is_refused(tmp_path, monkeypatch):
    unsearchable = (tmp_path / "under" / "unsearchable").resolve()
    original = Path.exists

    def exists(self, *args, **kwargs):
        # Only the path under test is unsearchable; every other exists() (the
        # fixtures' own) answers as before.
        if self == unsearchable:
            raise PermissionError(13, "Permission denied", str(self))
        return original(self, *args, **kwargs)

    monkeypatch.setattr(Path, "exists", exists)

    with pytest.raises(ValueError):
        rac.validate_path(unsearchable)


# ---------------------------------------------------------------------------
# The streamed output
# ---------------------------------------------------------------------------


def test_a_value_holding_a_line_break_is_hidden_line_by_line():
    value = "first line of the value\nsecond line of the value"

    shown = rac._streamed_line("echo: second line of the value", (value,))

    assert "second line of the value" not in shown


def test_the_captured_output_hides_a_value_line_by_line_too(monkeypatch):
    """What the console hides, the result kept for the caller hides as well."""
    value = "first line of the value\nsecond line of the value"
    completed = create_completed_process(
        args=["runtime"],
        returncode=0,
        stdout="echo: second line of the value\n",
        stderr="",
    )
    monkeypatch.setattr(
        rac, "run_cmd_direct", lambda cmd, debug=False, env=None: completed
    )

    with subprocess_utils._spawn_values((value,)):
        result = rac._execute_container(["runtime", "run", "img"], debug=False)

    assert "second line of the value" not in result.stdout


def test_short_and_blank_lines_of_a_value_are_not_hidden_on_their_own():
    value = "{\n  \n  a-long-enough-line\n}"

    assert rac._value_lines((value,)) == (value, "a-long-enough-line")
    assert rac._value_lines(rac._value_lines((value,))) == rac._value_lines((value,))


_PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n"
    "-----END PRIVATE KEY-----"
)


def test_a_pem_values_armor_lines_are_not_hidden_on_their_own():
    """A report that describes a private key quotes the armor header; hiding
    those lines anywhere in the stream blanked every such description. The key's
    body is still hidden, line by line and whole."""
    lines = rac._value_lines((_PEM,))

    assert "-----BEGIN PRIVATE KEY-----" not in lines
    assert "-----END PRIVATE KEY-----" not in lines
    assert "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7" in lines
    assert _PEM in lines
    shown = rac._streamed_line(
        "a finding: -----BEGIN PRIVATE KEY----- in a file", (_PEM,)
    )
    assert "BEGIN PRIVATE KEY" in shown


def test_a_json_values_generic_key_lines_are_not_hidden_on_their_own():
    value = (
        "{\n"
        '  "type": "service_account",\n'
        '  "private_key_id": "0123456789abcdef0123456789abcdef01234567",\n'
        '  "client_email": "svc@project.iam.gserviceaccount.com"\n'
        "}"
    )

    lines = rac._value_lines((value,))

    assert '"type": "service_account",' not in lines
    assert '"private_key_id": "0123456789abcdef0123456789abcdef01234567",' in lines
    assert '"client_email": "svc@project.iam.gserviceaccount.com"' in lines


class _TextPipe:
    """A child's pipe as Popen opens it in text mode: universal newlines."""

    def __init__(self, data: bytes) -> None:
        self._wrapper = io.TextIOWrapper(io.BytesIO(data), encoding="utf-8")

    def readline(self) -> str:
        return self._wrapper.readline()

    def reconfigure(self, **kwargs) -> None:
        self._wrapper.reconfigure(**kwargs)


class _ExitedRuntime:
    def __init__(self, stdout: bytes = b"", stderr: bytes = b"") -> None:
        self.stdout = _TextPipe(stdout)
        self.stderr = _TextPipe(stderr)
        self.returncode = 0
        self.pid = os.getpid()

    def poll(self):
        return self.returncode


def test_carriage_returns_reach_the_captured_output_untranslated(monkeypatch):
    runtime = _ExitedRuntime(stdout=b"10%\r20%\r100%\n")
    monkeypatch.setattr(
        subprocess_utils, "create_process_with_pipes", lambda **kw: runtime
    )

    result = rac.run_cmd_direct(["runtime", "run", "scan"])

    assert result.stdout == "10%\r20%\r100%\n"


class _StuckReader:
    ident = 1

    def start(self) -> None:
        pass

    def join(self, timeout=None) -> None:
        pass

    def is_alive(self) -> bool:
        return True


def test_a_reader_still_running_after_the_join_is_said(monkeypatch, logged):
    runtime = _ExitedRuntime()
    monkeypatch.setattr(
        subprocess_utils, "create_process_with_pipes", lambda **kw: runtime
    )
    monkeypatch.setattr(rac, "ash_thread", lambda *args, **kwargs: _StuckReader())

    rac.run_cmd_direct(["runtime", "run", "scan"])

    # Once, although both readers (stdout and stderr) are still alive.
    said = [m for m in logged.messages(logging.WARNING) if "incomplete" in m]
    assert len(said) == 1, said


# ---------------------------------------------------------------------------
# The image build
# ---------------------------------------------------------------------------


def test_the_buildx_probe_runs_through_the_wrapper(monkeypatch):
    monkeypatch.setenv("OCI_RUNNER_WRAPPER", "sudo -E")
    monkeypatch.setattr(rac, "_BUILDX_SUPPORT_CACHE", {})
    probes: List[List[str]] = []

    def run_command(cmd, **kwargs):
        probes.append([str(c) for c in cmd])
        return create_completed_process(
            args=probes[-1], returncode=0, stdout="", stderr=""
        )

    monkeypatch.setattr(subprocess_utils, "run_command", run_command)

    assert rac._runner_supports_buildx("/usr/bin/docker") is True
    assert probes == [["sudo", "-E", "/usr/bin/docker", "buildx", "version"]]


def test_the_buildx_answer_is_kept_per_word_list_not_per_joined_text(monkeypatch):
    """A runner path holding a space and a wrapper word holding one join to the
    same text as a wrapper of two words and a shorter path; they are different
    commands and are probed apart."""
    monkeypatch.setattr(rac, "_BUILDX_SUPPORT_CACHE", {})
    probes: List[List[str]] = []

    def run_command(cmd, **kwargs):
        probes.append([str(c) for c in cmd])
        return create_completed_process(
            args=probes[-1], returncode=0, stdout="", stderr=""
        )

    monkeypatch.setattr(subprocess_utils, "run_command", run_command)
    monkeypatch.setattr(rac, "_get_oci_wrapper_prefix", lambda: ["sudo"])
    assert rac._runner_supports_buildx("/opt/my docker/docker") is True
    monkeypatch.setattr(rac, "_get_oci_wrapper_prefix", lambda: ["sudo", "/opt/my"])
    assert rac._runner_supports_buildx("docker/docker") is True

    assert len(probes) == 2, probes


def test_an_id_of_many_digits_is_read_without_int():
    assert rac._non_root_stage_uid_refusal("non-root", "0" * 5000, "1000") is not None
    assert rac._non_root_stage_uid_refusal("non-root", "1" * 5000, "1000") is None


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(
            chr(0xFEFF) + "FROM base AS non-root\nRUN true\n", id="byte-order-mark"
        ),
        pytest.param("FROM base \\\n    AS non-root\nRUN true\n", id="continuation"),
        pytest.param(
            "FROM base \\  \t\n    AS non-root\nRUN true\n",
            id="blanks-after-the-backslash",
        ),
        pytest.param(
            "FROM base \\\n# the stage that runs unprivileged\n    AS non-root\nRUN true\n",
            id="comment-inside-the-continuation",
        ),
    ],
)
def test_the_non_root_stage_is_found_past_a_bom_and_a_continuation(tmp_path, text):
    containerfile = tmp_path / "Containerfile"
    containerfile.write_text(text, encoding="utf-8")

    assert (
        rac._custom_containerfile_stage_refusal("non-root", str(containerfile)) is None
    )


def test_force_reaches_the_custom_build(tmp_path, monkeypatch):
    containerfile = tmp_path / "Containerfile"
    containerfile.write_text("FROM base\n", encoding="utf-8")
    commands: List[List[str]] = []

    def record(cmd_list, check=True, debug=False, shell=False, env=None):
        commands.append([str(item) for item in cmd_list])
        return create_completed_process(
            args=commands[-1], returncode=0, stdout="", stderr=""
        )

    monkeypatch.setattr(rac, "run_cmd_direct", record)

    rac._build_custom_image(
        oci_command_prefix=[],
        resolved_oci_runner="/nonexistent/docker",
        base_image_name="automated-security-helper:ci",
        custom_containerfile=str(containerfile),
        quiet=False,
        debug=False,
        force=True,
    )

    assert "--no-cache" in commands[0]


# ---------------------------------------------------------------------------
# The output directory and the env-file directory, by identity
# ---------------------------------------------------------------------------


def test_an_output_directory_that_is_the_source_under_another_spelling_is_refused(
    tmp_path, monkeypatch
):
    """A case-insensitive volume resolves two spellings to two paths and one
    directory: the spelled comparison misses it, the identity comparison does not."""
    source = tmp_path / "project"
    source.mkdir()
    original = Path.resolve
    resolved_paths: List[Path] = []

    def resolve(self, strict=False):
        # The refusal resolves the source first, then the output: the output is
        # the same directory, answered under another spelling.
        resolved = original(self, strict=strict)
        resolved_paths.append(self)
        if len(resolved_paths) == 2:
            return Path(str(resolved) + "-other-spelling")
        return resolved

    monkeypatch.setattr(Path, "resolve", resolve)

    with pytest.raises(rac.ContainerInputError):
        rac._refuse_output_over_the_source(source, str(source))
    assert len(resolved_paths) == 2


def test_a_volume_without_inodes_tells_no_directory_identity(tmp_path, monkeypatch):
    """Where every entry reports st_ino 0, two different directories compare
    equal by samestat; the identity comparison then says nothing."""
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    original = os.stat

    def without_inodes(path, *args, **kwargs):
        status = original(path, *args, **kwargs)
        return os.stat_result((status.st_mode, 0, status.st_dev, *tuple(status)[3:]))

    monkeypatch.setattr(os, "stat", without_inodes)

    assert rac._is_at_or_above(first, second) is False
    assert rac._is_at_or_above(first, first) is False


def test_an_env_file_directory_reaching_the_source_under_another_name_is_refused(
    tmp_path, monkeypatch
):
    source = tmp_path / "project"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    temp = source / "tmpd"
    temp.mkdir()
    monkeypatch.setenv("TMPDIR", str(temp))
    monkeypatch.setattr(tempfile, "tempdir", None)
    monkeypatch.setenv("ASH_STATE_DIR", str(tmp_path / "state"))
    original = rac._real_path

    def real_path(path):
        real = original(path)
        if Path(path) in (source, output):
            return Path(str(real) + "-other-name")
        return real

    monkeypatch.setattr(rac, "_real_path", real_path)

    try:
        with pytest.raises(rac.ContainerInputError):
            rac._write_env_file(["X"], {"X": "1"}, "docker", source, output)
    finally:
        monkeypatch.setattr(tempfile, "tempdir", None)
    assert list(temp.iterdir()) == []


# ---------------------------------------------------------------------------
# The run phase
# ---------------------------------------------------------------------------


@pytest.fixture
def commands(monkeypatch, tmp_path) -> List[List[str]]:
    seen: List[List[str]] = []

    def record(cmd_list, check=True, debug=False, shell=False, env=None):
        cmd = [str(item) for item in cmd_list if item is not None]
        seen.append(cmd)
        return create_completed_process(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.setattr(
        rac, "_find_runner", lambda _name: "/nonexistent/ash-test/docker"
    )
    monkeypatch.setattr(rac, "_runner_supports_buildx", lambda _runner: False)
    monkeypatch.setattr(rac, "run_cmd_direct", record)
    # The check ahead of the build is taken as already passed: these cases are
    # about what the run phase does with a path that changed after it.
    monkeypatch.setattr(rac, "_require_mountable_inputs", lambda *a, **k: None)
    for name in ("CI", "ASH_IMAGE_NAME", "ASH_CONFIG", "OCI_RUNNER_WRAPPER"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    return seen


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need a privilege")
def test_a_link_that_appeared_after_the_check_is_refused_before_the_run(
    tmp_path, commands
):
    source = tmp_path / "project"
    source.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (source / ".ash").symlink_to(elsewhere, target_is_directory=True)

    result = rac.run_ash_container(
        source_dir=str(source),
        output_dir=str(source / ".ash" / "ash_output"),
        build=False,
        run=True,
    )

    assert result.returncode == 3, result.stderr
    assert commands == []
    assert list(elsewhere.iterdir()) == []


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need a privilege")
def test_the_link_re_read_judges_the_source_under_its_given_name(tmp_path, commands):
    """The source is named through a link above it and the output through that
    same name: only the given name shows that the ``.ash`` on the way is a link,
    and the resolved source does not."""
    work = tmp_path / "work"
    (work / "project").mkdir(parents=True)
    named = tmp_path / "work-link"
    named.symlink_to(work, target_is_directory=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (work / "project" / ".ash").symlink_to(elsewhere, target_is_directory=True)

    result = rac.run_ash_container(
        source_dir=str(named / "project"),
        output_dir=str(named / "project" / ".ash" / "ash_output"),
        build=False,
        run=True,
    )

    assert result.returncode == 3, result.stderr
    assert commands == []
    assert list(elsewhere.iterdir()) == []


def test_a_default_output_directory_that_cannot_be_made_is_a_run_not_started(
    tmp_path, commands
):
    source = tmp_path / "project"
    source.mkdir()
    (source / "ash_output").write_text("a file where the directory goes")

    result = rac.run_ash_container(
        source_dir=str(source), output_dir="", build=False, run=True
    )

    assert result.returncode == 1
    assert not rac.container_was_started(result)
    assert commands == []


# ---------------------------------------------------------------------------
# The refusals ahead of the run
# ---------------------------------------------------------------------------


def test_a_config_under_an_unsearchable_directory_is_refused(tmp_path, monkeypatch):
    def is_file(self):
        raise PermissionError(13, "Permission denied", str(self))

    monkeypatch.setattr(Path, "is_file", is_file)

    refusal = rac._unreadable_config(str(tmp_path / "locked" / "ash.yaml"))

    assert isinstance(refusal, str)


def test_a_symlink_loop_in_a_mounted_path_is_a_refusal(tmp_path, monkeypatch):
    def loop(*args, **kwargs):
        raise RuntimeError("Symlink loop from '/looped/path'")

    monkeypatch.setattr(rac, "_require_mountable_inputs", loop)
    monkeypatch.delenv("ASH_CONFIG", raising=False)

    refusal = rac.container_input_refusal(str(tmp_path), str(tmp_path / "out"), None)

    assert isinstance(refusal, str)
    assert "Symlink loop" in refusal


def test_another_runtime_error_in_the_mount_check_keeps_its_traceback(
    tmp_path, monkeypatch
):
    """RecursionError is a RuntimeError; a bug is not a refusal."""

    def deep(*args, **kwargs):
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(rac, "_require_mountable_inputs", deep)
    monkeypatch.delenv("ASH_CONFIG", raising=False)

    with pytest.raises(RecursionError):
        rac.container_input_refusal(str(tmp_path), str(tmp_path / "out"), None)


def test_the_outer_run_id_is_never_passed_from_a_config():
    assert OUTER_RUN_ID_ENV in rac.CONTAINER_ENV_NOT_PASSED


# ---------------------------------------------------------------------------
# The SIGTERM guard
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="SIGTERM handlers are POSIX")
def test_a_handler_installed_outside_python_leaves_the_guard_off(tmp_path, monkeypatch):
    kept = signal.getsignal(signal.SIGTERM)
    monkeypatch.setattr(signal, "getsignal", lambda signum: None)
    installed: List[object] = []
    real_signal = signal.signal
    monkeypatch.setattr(
        signal, "signal", lambda signum, handler: installed.append(handler)
    )
    try:
        with rac._termination_raises(tmp_path):
            pass
    finally:
        monkeypatch.undo()
        real_signal(signal.SIGTERM, kept)

    assert installed == []
