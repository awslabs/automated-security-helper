# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan run on this host refuses a directory whose path is not UTF-8, before it writes.

The scan writes the scanned directory's absolute path into the results file and the
SARIF (the working directory, the scanner's --target argument, additional_reports), and
both are UTF-8. A path that is not UTF-8 arrives as a str with surrogate escapes, which
neither can hold. Unrefused (measured), a local scan of a directory named
caf\\xe9 would run its scanners and write its working files, then exit 1 with "Error
serializing to JSON: UnicodeEncodeError ... '\\udce9'", and leave no results file and no
reports. Such a scan exits 1 at the start, says why, and says to rename the
directory. Nothing is written, and the previous run's results stay as they were. A
report over existing results (--use-existing) on the host is not refused: it writes its
reports from the stored results, and was measured to work for such a directory.

Container mode does not get around it, so the message does not offer it. Container
mode bind-mounts the directory at /src and the output directory at /out, and the
runtime takes a mount's path as UTF-8 text. Measured with docker 25: the daemon gets the
byte as U+FFFD, refuses the mount and the scan would exit 125; with a directory of that
other name beside it, it mounts that one instead. So container mode refuses either
mount whose path is not UTF-8 with exit 3, as for any path the runtime cannot take,
before any runtime call, a report over existing results included; --no-run, which
mounts nothing, is not refused.

Only some filesystems can hold such a name. Windows cannot decode one, and APFS refuses
it, so there the tests skip, with the reason.
"""

from __future__ import annotations

import io
import os
import subprocess  # nosec B404 - the CLI under test runs as a child process
import sys
from pathlib import Path
from typing import Dict, Optional

import pytest
import rich
from rich.console import Console

import automated_security_helper
from automated_security_helper.core.enums import RunMode
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.interactions.run_ash_scan import run_ash_scan
from tests.utils.helpers import checkout_env

#: The checkout under test, which a child process is pointed at.
_CHECKOUT = Path(automated_security_helper.__file__).resolve().parents[1]


class _Reached(Exception):
    """Raised by a stand-in for the step after the refusal: the scan went on."""


def _not_utf8_dir(parent: Path, name: bytes = b"caf\xe9") -> Path:
    try:
        odd = parent / os.fsdecode(name)
        odd.mkdir()
    except (UnicodeDecodeError, OSError) as error:
        pytest.skip(f"this filesystem cannot hold a name that is not UTF-8: {error}")
    return odd


def _entries(top: Path) -> Dict[bytes, Optional[bytes]]:
    """Every entry below *top*, by its path as bytes: a file's content, None for a directory."""
    found: Dict[bytes, Optional[bytes]] = {}
    for directory, subdirectories, files in os.walk(os.fsencode(top)):
        for name in subdirectories:
            found[os.path.join(directory, name)] = None
        for name in files:
            with open(os.path.join(directory, name), "rb") as handle:
                found[os.path.join(directory, name)] = handle.read()
    return found


def _with_a_previous_run(root: Path) -> Path:
    """*root*'s default output directory, holding an earlier run's results."""
    output = root / ".ash" / "ash_output"
    (output / "reports").mkdir(parents=True)
    (output / "ash_aggregated_results.json").write_text('{"previous": true}\n')
    (output / "reports" / "ash.sarif").write_text('{"previous": true}\n')
    (output / "ash.log").write_text("the previous run's log\n")
    (root / "app.py").write_text('password = "hunter2hunter2hunter2"\n')
    return output


def _has_a_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(character) <= 0xDFFF for character in text)


@pytest.fixture
def console(monkeypatch) -> Console:
    """The console ASH prints to, recording, wide enough that no path is folded."""
    recording = Console(record=True, width=1000, color_system=None, file=io.StringIO())
    monkeypatch.setattr(rich, "_console", recording)
    return recording


@pytest.fixture
def no_nix_shell(monkeypatch):
    """Nix mode's shell, which none of these scans may start."""

    def started(**kwargs):
        raise AssertionError("nix mode started its shell")

    monkeypatch.setattr(ras, "run_ash_nix", started)
    monkeypatch.setattr(ras, "nix_preflight", lambda: None)


@pytest.mark.parametrize("mode", [RunMode.local, RunMode.precommit, RunMode.nix])
@pytest.mark.unit
def test_a_scan_here_of_a_directory_that_is_not_utf8_is_refused_before_it_writes(
    tmp_path, monkeypatch, console, no_nix_shell, mode
):
    root = _not_utf8_dir(tmp_path)
    output = _with_a_previous_run(root)
    monkeypatch.chdir(tmp_path)
    before = _entries(tmp_path)

    with pytest.raises(SystemExit) as stopped:
        run_ash_scan(
            source_dir=root,
            output_dir=output,
            mode=mode,
            scanners=["detect-secrets"],
            python_based_plugins_only=True,
            progress=False,
        )
    text = console.export_text()

    assert stopped.value.code == 1, ascii(text)
    # Nothing written, and the previous run's results, log and reports untouched.
    assert _entries(tmp_path) == before
    assert "not UTF-8" in text, ascii(text)
    # The directory is named, with its byte that is not UTF-8 written as an escape.
    assert f"{tmp_path}{os.sep}caf\\udce9" in text, ascii(text)
    assert not _has_a_surrogate(text), ascii(text)
    assert "Rename the directory" in text, ascii(text)
    # Container mode cannot mount it either, so it is not offered as a way out.
    assert "Container mode cannot mount such a directory either" in text, ascii(text)
    assert "--mode container" not in text, ascii(text)


@pytest.mark.unit
def test_the_directory_is_shown_not_obeyed(tmp_path, monkeypatch, console):
    """The name is the operator's directory's: its controls, markup and CI commands
    are written out, not obeyed."""
    root = _not_utf8_dir(tmp_path, b"caf\xe9\x1b[31m[red]x\n::error::injected")
    output = _with_a_previous_run(root)
    monkeypatch.chdir(tmp_path)

    with pytest.raises(SystemExit) as stopped:
        run_ash_scan(
            source_dir=root,
            output_dir=output,
            mode=RunMode.local,
            scanners=["detect-secrets"],
            python_based_plugins_only=True,
            progress=False,
        )
    text = console.export_text()

    assert stopped.value.code == 1, ascii(text)
    assert "caf\\udce9\\x1b[31m[red]x\\x0a::error::injected" in text, ascii(text)
    assert "\x1b" not in text, ascii(text)
    assert not any(line.lstrip().startswith("::") for line in text.splitlines()), ascii(
        text
    )
    assert not _has_a_surrogate(text), ascii(text)


@pytest.mark.integration
def test_ash_scan_refuses_it_with_the_message_on_a_strict_stdout(tmp_path):
    """Through the CLI, in a child process whose stdout cannot encode a surrogate:
    the message is printed whole, and nothing is written."""
    root = _not_utf8_dir(tmp_path)
    _with_a_previous_run(root)
    home = tmp_path / "home"
    home.mkdir()
    before = _entries(root)
    env = {
        **os.environ,
        "HOME": str(home),
        "USERPROFILE": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_DATA_HOME": str(home / ".local" / "share"),
        "XDG_STATE_HOME": str(home / ".local" / "state"),
        "PYTHONPATH": str(_CHECKOUT),
        "PYTHONIOENCODING": "utf-8:strict",
        # Wide, so that the path is printed on one line.
        "COLUMNS": "1000",
        "TERMINAL_WIDTH": "1000",
    }

    child = subprocess.run(  # nosec B603 - fixed interpreter and arguments
        [
            sys.executable,
            "-m",
            "automated_security_helper.cli.main",
            "scan",
            "--mode",
            "local",
            "--source-dir",
            str(root),
            "--scanners",
            "detect-secrets",
            "--python-only",
            "--no-progress",
        ],
        cwd=tmp_path,
        env=checkout_env(env),
        capture_output=True,
        timeout=600,
    )
    stdout = child.stdout.decode("utf-8")

    assert child.returncode == 1, (stdout, child.stderr.decode("utf-8", "replace"))
    assert "caf\\udce9" in stdout and "not UTF-8" in stdout, stdout
    assert "Container mode cannot mount" in stdout, stdout
    assert b"UnicodeEncodeError" not in child.stderr, child.stderr
    assert _entries(root) == before


@pytest.fixture
def no_container_run(monkeypatch):
    """Container mode's runtime call, which none of the refused scans may reach."""

    def container_mode(opts, logger, **kwargs):
        raise _Reached

    monkeypatch.setattr(ras, "_run_container_mode", container_mode)


@pytest.mark.parametrize(
    "odd, existing",
    [("source", False), ("output", False), ("source", True), ("output", True)],
    ids=["source", "output", "source-existing", "output-existing"],
)
@pytest.mark.unit
def test_container_mode_refuses_a_mount_whose_path_is_not_utf8(
    tmp_path, monkeypatch, console, no_container_run, odd, existing
):
    """Before any runtime call, whichever of the two mounts is not UTF-8, and with
    --use-existing too, since that run mounts both."""
    plain = tmp_path / "plain"
    plain.mkdir()
    root = _not_utf8_dir(tmp_path) if odd == "source" else plain
    output = (
        _with_a_previous_run(_not_utf8_dir(tmp_path))
        if odd == "output"
        else _with_a_previous_run(plain)
    )
    monkeypatch.chdir(tmp_path)
    before = _entries(tmp_path)

    with pytest.raises(SystemExit) as stopped:
        run_ash_scan(
            source_dir=root,
            output_dir=output,
            mode=RunMode.container,
            existing_results=(
                str(output / "ash_aggregated_results.json") if existing else None
            ),
            progress=False,
        )
    text = console.export_text()

    # 3, as for every path the container runtime cannot take (a comma, a quote, a
    # line break) and as ./ash refuses it; the host-mode refusal above is 1.
    assert stopped.value.code == 3, ascii(text)
    assert "ERROR (3)" in text, ascii(text)
    assert _entries(tmp_path) == before
    named = "The directory to scan" if odd == "source" else "The output directory"
    assert named in text and "caf\\udce9" in text, ascii(text)
    assert "bind-mounts it" in text, ascii(text)
    way_out = "Rename the directory" if odd == "source" else "Choose an --output-dir"
    assert way_out in text, ascii(text)
    assert not _has_a_surrogate(text), ascii(text)


@pytest.mark.unit
def test_container_mode_names_the_directory_to_scan_first(
    tmp_path, monkeypatch, console, no_container_run
):
    """With no --output-dir the output directory is below the directory to scan, so
    renaming that one clears both."""
    root = _not_utf8_dir(tmp_path)
    monkeypatch.chdir(tmp_path)

    with pytest.raises(SystemExit):
        run_ash_scan(
            source_dir=root,
            output_dir=root / ".ash" / "ash_output",
            mode=RunMode.container,
            progress=False,
        )
    text = console.export_text()

    assert "The directory to scan" in text, ascii(text)
    assert "The output directory" not in text, ascii(text)


@pytest.mark.unit
def test_container_mode_with_no_run_is_not_refused(
    tmp_path, monkeypatch, console, no_container_run
):
    """--no-run builds an image and mounts nothing."""
    root = _not_utf8_dir(tmp_path)
    monkeypatch.chdir(tmp_path)

    with pytest.raises(_Reached):
        run_ash_scan(
            source_dir=root,
            output_dir=root / ".ash" / "ash_output",
            mode=RunMode.container,
            run=False,
            progress=False,
        )
    assert "not UTF-8" not in console.export_text()


#: A container runtime stand-in that records each call and exits 0.
_RECORDING_RUNTIME = """\
import json, os, sys
with open(os.environ["ASH_TEST_RUNTIME_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps(sys.argv[1:]) + "\\n")
"""

_GUARD = '#!/bin/sh\necho "$(basename "$0") $*" >> "{log}"\nexit 97\n'


@pytest.mark.parametrize("odd", ["source", "output"])
@pytest.mark.integration
def test_ash_scan_container_mode_refuses_it_before_any_runtime_call(tmp_path, odd):
    """Through the CLI, on a stdout that cannot encode a surrogate, with a runtime
    stand-in that records any call and guards that fail on a real runtime's name."""
    home = tmp_path / "home"
    bin_dir = home / "bin"
    bin_dir.mkdir(parents=True)
    runtime = bin_dir / "ash-test-runtime"
    runtime.write_text(f"#!{sys.executable}\n{_RECORDING_RUNTIME}", encoding="utf-8")
    runtime.chmod(0o755)
    for name in ("docker", "finch", "nerdctl", "podman"):
        guard = bin_dir / name
        guard.write_text(_GUARD.format(log=home / "guards.log"), encoding="utf-8")
        guard.chmod(0o755)
    plain = tmp_path / "plain"
    plain.mkdir()
    (plain / "app.py").write_text("x = 1\n")
    root = plain
    extra = []
    if odd == "source":
        root = _not_utf8_dir(tmp_path)
        (root / "app.py").write_text("x = 1\n")
    else:
        extra = ["--output-dir", str(_not_utf8_dir(tmp_path) / "out")]
    before = _entries(tmp_path)
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("ASH_")
        and key not in ("CI", "OCI_RUNNER", "OCI_RUNNER_WRAPPER")
    }
    env.update(
        HOME=str(home),
        USERPROFILE=str(home),
        PATH=os.pathsep.join([str(bin_dir), env.get("PATH", "")]),
        PYTHONPATH=str(_CHECKOUT),
        PYTHONIOENCODING="utf-8:strict",
        COLUMNS="1000",
        TERMINAL_WIDTH="1000",
        ASH_TEST_RUNTIME_LOG=str(home / "runtime.log"),
    )

    child = subprocess.run(  # nosec B603 - fixed interpreter and arguments
        [
            sys.executable,
            "-m",
            "automated_security_helper.cli.main",
            "scan",
            "--mode",
            "container",
            "--no-build",
            "--oci-runner",
            "ash-test-runtime",
            "--source-dir",
            str(root),
            *extra,
            "--no-progress",
            "--no-color",
        ],
        cwd=tmp_path,
        env=checkout_env(env),
        capture_output=True,
        timeout=600,
    )
    stdout = child.stdout.decode("utf-8")
    stderr = child.stderr.decode("utf-8")

    assert child.returncode == 3, (stdout, stderr)
    assert not (home / "runtime.log").exists(), (home / "runtime.log").read_text()
    assert not (home / "guards.log").exists()
    assert "caf\\udce9" in stdout and "bind-mounts it" in stdout, stdout
    assert "Traceback" not in stderr, stderr
    assert {
        path: content
        for path, content in _entries(tmp_path).items()
        if not path.startswith(os.fsencode(home))
    } == {
        path: content
        for path, content in before.items()
        if not path.startswith(os.fsencode(home))
    }


@pytest.mark.unit
def test_a_report_over_existing_results_is_not_refused(tmp_path, monkeypatch, console):
    """It writes its reports from the stored results, not from the directory's path."""
    root = _not_utf8_dir(tmp_path)
    output = _with_a_previous_run(root)
    monkeypatch.chdir(tmp_path)

    def local_mode(opts, logger):
        raise _Reached

    monkeypatch.setattr(ras, "_run_local_mode", local_mode)
    with pytest.raises(_Reached):
        run_ash_scan(
            source_dir=root,
            output_dir=output,
            mode=RunMode.local,
            existing_results=str(output / "ash_aggregated_results.json"),
            progress=False,
        )
    assert "not UTF-8" not in console.export_text()
