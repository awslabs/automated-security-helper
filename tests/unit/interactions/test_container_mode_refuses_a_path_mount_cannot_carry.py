# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Container mode refuses a path ``--mount`` cannot carry, with exit 3.

Container mode bind-mounts the directory to scan at ``/src`` and the output
directory at ``/out`` with ``--mount type=bind,source=<path>,destination=...``. The
runtimes read that value as comma-separated fields (CSV): a comma starts a field of
its own, a double quote starts CSV quoting, and a line break ends the argument for a
runner that reads it a line at a time. So a source or output directory whose path
holds a comma, a double quote, a newline or a carriage return is refused before any
runtime call, by ``ash scan --mode container`` and by ``run_ash_container`` called
directly, as ``./ash`` refuses it. The path is shown escaped, so the refusal holds
no raw line break. A path holding a NUL byte, which only a caller of the API can
pass, is refused the same way.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict

import pytest

from automated_security_helper.core.enums import RunMode
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32", reason="these names are POSIX file names"
    ),
]

REFUSED = "cannot be handed to the container runner"

#: A character --mount cannot carry, as it appears in a directory name.
HELD = [
    pytest.param(",src=etc", id="comma"),
    pytest.param('"q', id="double-quote"),
    pytest.param("\nq", id="newline"),
    pytest.param("\rq", id="carriage-return"),
]


class _Reached(Exception):
    """Raised in place of the container runtime call."""


def _refusal_of(label: str, path: Path) -> str:
    """The refusal ``_require_mountable`` gives ``path``, as it shows the path.

    Taken from the function rather than spelled here, so a cell does not depend on
    the escape it uses for a line break (``\\n`` as ``repr`` shows it, ``\\x0a`` as
    ``./ash`` does); the cells require only that the message is shown whole and
    holds no raw line break.
    """
    with pytest.raises(rac.UnmountablePathError) as refused:
        rac._require_mountable(label, path.resolve())
    return str(refused.value)


def _scan(tmp_path: Path, monkeypatch, source_name: str, output_name: str) -> str:
    def container_mode(opts, logger, **kwargs):
        raise _Reached

    monkeypatch.setattr(ras, "_run_container_mode", container_mode)
    source = tmp_path / source_name
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    try:
        ras.run_ash_scan(
            source_dir=source,
            output_dir=tmp_path / output_name,
            mode=RunMode.container,
            progress=False,
        )
    except _Reached:
        return "reached"
    except SystemExit as stop:
        return f"exit {stop.code}"
    return "returned"


@pytest.mark.parametrize("held", HELD)
@pytest.mark.parametrize("where", ["source", "output"])
def test_ash_scan_refuses_it_with_3_before_the_runtime(
    tmp_path, monkeypatch, capsys, where, held
):
    source_name = f"s{held}" if where == "source" else "src"
    output_name = f"o{held}" if where == "output" else "out"

    outcome = _scan(tmp_path, monkeypatch, source_name, output_name)

    assert outcome == "exit 3", outcome
    shown = capsys.readouterr()
    text = shown.out + shown.err
    label = "source directory" if where == "source" else "output directory"
    assert f"The {label} " in text and REFUSED in text, text
    refused = tmp_path / (source_name if where == "source" else output_name)
    message = _refusal_of(label, refused)
    assert message in text, text
    assert "\n" not in message and "\r" not in message, repr(message)
    assert "\r" not in text, repr(text)
    assert not (tmp_path / output_name).exists(), "the refused run made its output"


def test_ash_scan_refuses_a_nul_in_the_output_dir_with_3(tmp_path, monkeypatch, capsys):
    """Only a caller of the API can pass one; refused with 3, not raised."""
    outcome = _scan(tmp_path, monkeypatch, "src", "o\0x")

    assert outcome == "exit 3", outcome
    shown = capsys.readouterr()
    text = shown.out + shown.err
    assert "The output directory " in text and REFUSED in text, text
    assert "NUL" in text and "\0" not in text, repr(text)


def test_control_ash_scan_with_plain_names_reaches_the_runtime(tmp_path, monkeypatch):
    assert _scan(tmp_path, monkeypatch, "src", "out") == "reached"


@pytest.fixture
def runtime(monkeypatch, tmp_path) -> Dict[str, Any]:
    """Recorders in place of the build and the run, as a direct caller meets them."""
    monkeypatch.chdir(tmp_path)
    seen: Dict[str, Any] = {"executed": 0}

    def fake_execute(cmd, debug=False, env=None):
        seen["executed"] += 1
        return create_completed_process(args=list(cmd), returncode=0)

    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.setattr(rac, "_find_runner", lambda _name: "/usr/bin/docker")
    monkeypatch.setattr(rac, "get_ash_revision", lambda quiet=False: "LOCAL")
    monkeypatch.setattr(rac, "_execute_container", fake_execute)
    for name in ("CI", "IsCI", "ISCI", "CODEBUILD_BUILD_ID", "ASH_IMAGE_NAME"):
        monkeypatch.delenv(name, raising=False)
    return seen


@pytest.mark.parametrize("held", HELD)
@pytest.mark.parametrize("where", ["source", "output"])
def test_run_ash_container_refuses_it_with_3_before_the_runtime(
    runtime, tmp_path, where, held
):
    source = tmp_path / (f"s{held}" if where == "source" else "src")
    source.mkdir()
    output = tmp_path / (f"o{held}" if where == "output" else "out")

    result = rac.run_ash_container(
        source_dir=source, output_dir=output, build=False, run=True
    )

    assert result.returncode == 3, result
    assert REFUSED in result.stderr, result.stderr
    assert runtime["executed"] == 0
    assert not rac.container_was_started(result)
    assert not output.exists(), "the refused run made its output directory"


def test_control_run_ash_container_with_plain_names_runs(runtime, tmp_path):
    (tmp_path / "src").mkdir()

    result = rac.run_ash_container(
        source_dir=tmp_path / "src", output_dir=tmp_path / "out", build=False, run=True
    )

    assert result.returncode == 0
    assert runtime["executed"] == 1


@pytest.fixture
def builds(runtime, monkeypatch, tmp_path) -> list:
    """A recorder in place of the image build, which the default build=True runs."""
    built: list = []
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM scratch\n", encoding="utf-8")
    monkeypatch.setattr(rac, "_find_dockerfile", lambda _revision: dockerfile)
    monkeypatch.setattr(rac, "_build_image", lambda **kwargs: built.append(kwargs))
    return built


@pytest.mark.parametrize("held", HELD)
@pytest.mark.parametrize("where", ["source", "output"])
def test_run_ash_container_refuses_it_before_building_the_image(
    builds, runtime, tmp_path, where, held
):
    source = tmp_path / (f"s{held}" if where == "source" else "src")
    source.mkdir()
    output = tmp_path / (f"o{held}" if where == "output" else "out")

    result = rac.run_ash_container(source_dir=source, output_dir=output, run=True)

    assert result.returncode == 3, result
    assert REFUSED in result.stderr, result.stderr
    assert builds == [], "the refused run built the image first"
    assert runtime["executed"] == 0
    assert not output.exists(), "the refused run made its output directory"


def test_control_run_ash_container_with_plain_names_builds_then_runs(
    builds, runtime, tmp_path
):
    (tmp_path / "src").mkdir()

    result = rac.run_ash_container(
        source_dir=tmp_path / "src", output_dir=tmp_path / "out", run=True
    )

    assert result.returncode == 0, result
    assert len(builds) == 1
    assert runtime["executed"] == 1


@pytest.mark.parametrize("where", ["source", "output"])
def test_run_ash_container_refuses_a_nul_with_3(builds, runtime, tmp_path, where):
    """No path holds a NUL byte, and no argument can carry one. A caller of the API
    can still pass one; it is refused with 3, as a path the runner cannot be
    handed, rather than raised out of resolving the path."""
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"

    result = rac.run_ash_container(
        source_dir=f"{source}\0x" if where == "source" else source,
        output_dir=f"{output}\0x" if where == "output" else output,
        run=True,
    )

    assert result.returncode == 3, result
    assert REFUSED in result.stderr and "NUL" in result.stderr, result.stderr
    assert "\0" not in result.stderr, repr(result.stderr)
    assert builds == []
    assert runtime["executed"] == 0
    assert not output.exists(), "the refused run made its output directory"


@pytest.mark.parametrize("held", HELD)
def test_the_run_command_is_not_built_for_it(tmp_path, held):
    """Checked where the mounts are written too, for a caller that reaches it."""
    from tests.unit.interactions.test_run_ash_container_helpers_coverage import (
        _run_command,
    )

    with pytest.raises(rac.UnmountablePathError, match=REFUSED):
        _run_command(tmp_path / "src", tmp_path / f"o{held}")


def test_the_refusal_names_the_directory_as_the_operator_gave_it(tmp_path):
    """The check runs on the resolved path, which is what the mount uses; the
    refusal names the directory as the operator gave it, since that is the
    spelling they can act on, with the resolved path beside it, which is
    where a link carried the refused character in."""
    target = tmp_path / "holds,comma"
    target.mkdir()
    given = tmp_path / "plain"
    given.symlink_to(target)

    with pytest.raises(rac.UnmountablePathError, match=REFUSED) as refused:
        rac._require_mountable_directories(given.as_posix(), tmp_path / "out")

    message = str(refused.value)
    assert f"{given.as_posix()!r} ({str(given.resolve())!r})" in message, message


def test_the_refusal_shows_one_spelling_when_nothing_resolved_away(tmp_path):
    """The control beside the cell above: a directory named by its resolved
    path is shown once, not echoed twice."""
    given = (tmp_path / "holds,comma").resolve()

    with pytest.raises(rac.UnmountablePathError, match=REFUSED) as refused:
        rac._require_mountable_directories(given, tmp_path.resolve() / "out")

    message = str(refused.value)
    assert f"The source directory {str(given)!r} cannot" in message, message


def test_an_environment_chosen_directory_prints_raw_in_neither_spelling(
    tmp_path, monkeypatch
):
    """The two-spelling refusal with an environment-chosen directory: the
    value an ASH-prefixed variable carried is hidden in the operator's
    spelling and in the resolved path alike, and the leaf names stay
    readable."""
    base = (tmp_path / "chosen-base").resolve()
    (base / "holds,comma").mkdir(parents=True)
    given = base / "plain"
    given.symlink_to(base / "holds,comma")
    monkeypatch.setenv("ASH_ZZ_PROBE_DIR", str(base))

    with pytest.raises(rac.UnmountablePathError, match=REFUSED) as refused:
        rac._require_mountable_directories(given.as_posix(), tmp_path / "out")

    message = str(refused.value)
    assert str(base) not in message, message
    assert "plain" in message and "holds,comma" in message, message
