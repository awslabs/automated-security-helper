# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Nix mode refuses a --config that names no usable file before clearing output.

``_outer_mode_config_load`` documents that a config file that is missing or
not a regular file is refused with exit 3 for container and nix mode alike,
before the previous run's output is cleared, in the words a local scan uses.
For container mode the input handoff (``container_input_refusal``) owns the
missing-file case. Nix mode has no such check, so the host's load raised the
OSError a missing file raises, the pre-run gate returned None, and
``_run_nix_mode`` cleared the previous run's reports before the shell's ASH
refused the config.

The cells run the production entry (``run_ash_scan``) with the Nix launcher
replaced by a fake, so no Nix shell is ever started.
"""

from __future__ import annotations

import errno
import os
import re
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.core.enums import RunMode
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.interactions.run_ash_scan import (
    ScanRefusedExit,
    run_ash_scan,
)

pytestmark = pytest.mark.unit

PRIOR = "reports/ash.sarif"

_NEEDS_PERMISSION_BITS = pytest.mark.skipif(
    os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="a privileged user reads through permission bits",
)


def _plant_prior_run(out):
    artifact = out / PRIOR
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text('{"runs": []}\n', encoding="utf-8")
    return artifact


def _flat(text: str) -> str:
    return re.sub(r"\s+", " ", text)


def _scan(tmp_path, monkeypatch, config, ash_config=None, discovered=None):
    """``config`` is the ``--config`` path, or None for a scan that names none;
    ``discovered``, when given, is called with the ``.ash.yaml`` path in the
    source directory to write the file discovery will select."""
    if ash_config is None:
        monkeypatch.delenv("ASH_CONFIG", raising=False)
    else:
        monkeypatch.setenv("ASH_CONFIG", str(ash_config))
    src = tmp_path / "src"
    src.mkdir()
    (src / "app.py").write_text("x = 1\n", encoding="utf-8")
    if discovered is not None:
        discovered(src / ".ash.yaml")
    out = tmp_path / "out"
    artifact = _plant_prior_run(out)
    launcher = MagicMock()
    with (
        patch(
            "automated_security_helper.interactions.run_ash_scan.run_ash_nix", launcher
        ),
        patch(
            "automated_security_helper.interactions.run_ash_scan.nix_preflight",
            lambda: None,
        ),
    ):
        with pytest.raises(ScanRefusedExit) as refused:
            run_ash_scan(
                source_dir=src,
                output_dir=out,
                config=str(config) if config is not None else None,
                mode=RunMode.nix,
                progress=False,
                show_summary=False,
            )
    return refused.value, launcher, artifact


def _kept(refused, launcher, artifact):
    assert refused.code == 3
    assert launcher.call_count == 0
    assert artifact.exists(), "the previous run's output was cleared before the refusal"


def test_a_missing_config_is_refused_and_the_prior_run_is_kept(
    tmp_path, monkeypatch, capsys
):
    missing = tmp_path / "ops" / "never-written.yaml"

    refused, launcher, artifact = _scan(tmp_path, monkeypatch, missing)

    _kept(refused, launcher, artifact)
    assert "never-written.yaml" in capsys.readouterr().out


def test_a_directory_named_as_the_config_is_refused_and_the_prior_run_is_kept(
    tmp_path, monkeypatch, capsys
):
    directory = tmp_path / "a-directory.yaml"
    directory.mkdir()

    refused, launcher, artifact = _scan(tmp_path, monkeypatch, directory)

    _kept(refused, launcher, artifact)
    assert "a-directory.yaml" in capsys.readouterr().out
    assert launcher.call_count == 0
    assert artifact.exists(), "the previous run's output was cleared before the refusal"


@pytest.mark.skipif(
    os.name != "posix" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs POSIX permission bits that bind the current user",
)
def test_an_unreadable_config_is_refused_and_the_prior_run_is_kept(
    tmp_path, monkeypatch, request, capsys
):
    unreadable = tmp_path / "locked.yaml"
    unreadable.write_text("project_name: locked\n", encoding="utf-8")
    unreadable.chmod(0)
    request.addfinalizer(lambda: unreadable.chmod(0o600))
    if os.access(unreadable, os.R_OK):
        pytest.skip("this process can read a mode-0 file")

    refused, launcher, artifact = _scan(tmp_path, monkeypatch, unreadable)

    assert refused.code == 3
    out = capsys.readouterr().out
    assert "Config file cannot be read" in out
    assert "locked.yaml" in out
    assert launcher.call_count == 0
    assert artifact.exists(), "the previous run's output was cleared before the refusal"


def test_a_directory_from_ash_config_is_refused_in_ash_configs_words(
    tmp_path, monkeypatch, capsys
):
    """The words a local scan uses for an ASH_CONFIG that names an existing
    non-file: the path is named as ASH_CONFIG's, and is not called missing."""
    directory = tmp_path / "a-directory.yaml"
    directory.mkdir()

    refused, launcher, artifact = _scan(
        tmp_path, monkeypatch, directory, ash_config=directory
    )

    _kept(refused, launcher, artifact)
    flat = _flat(capsys.readouterr().out)
    assert "ASH_CONFIG names" in flat, flat
    assert "does not exist" not in flat, flat
    assert "Config file not found" not in flat, flat


def test_a_directory_from_config_is_named_for_what_it_is(tmp_path, monkeypatch, capsys):
    """A directory exists, so it is not "not found"; nix mode words it as the
    local scan does, and the nix-only sentence that hedged "(or ASH_CONFIG)" is
    not a second wording."""
    directory = tmp_path / "a-directory.yaml"
    directory.mkdir()

    refused, launcher, artifact = _scan(tmp_path, monkeypatch, directory)

    _kept(refused, launcher, artifact)
    flat = _flat(capsys.readouterr().out)
    assert "is not a regular file" in flat, flat
    assert "not found" not in flat, flat
    assert "--config (or ASH_CONFIG) has to name" not in flat, flat


@pytest.mark.parametrize("kind", ["directory", "fifo", "loop", "deep"])
def test_the_local_scan_and_the_nix_gate_word_a_non_file_config_alike(
    tmp_path, monkeypatch, kind
):
    """One classification serves both: the words the nix gate prints for a
    path that is not a regular file, or a file nested past the interpreter's
    recursion limit, are the words the local scan prints."""
    if kind == "fifo" and not hasattr(os, "mkfifo"):
        pytest.skip("needs named pipes")
    named = tmp_path / "named.yaml"
    if kind == "directory":
        named.mkdir()
    elif kind == "fifo":
        os.mkfifo(named)
    elif kind == "deep":
        named.write_text("[" * 100_000 + "]" * 100_000, encoding="utf-8")
    else:
        named.symlink_to(named)

    refused, _launcher, _artifact = _scan(tmp_path, monkeypatch, named)

    local_src = tmp_path / "local-src"
    local_src.mkdir()
    with pytest.raises(ScanRefusedExit) as local_refused:
        run_ash_scan(
            source_dir=local_src,
            output_dir=tmp_path / "local-out",
            config=str(named),
            mode=RunMode.local,
            progress=False,
            show_summary=False,
        )

    assert refused.code == 3 and local_refused.value.code == 3
    assert refused.message == local_refused.value.message, (
        refused.message,
        local_refused.value.message,
    )
    if kind == "deep":
        assert "could not be parsed" in refused.message, refused.message
        assert named.name in refused.message, refused.message
    else:
        assert str(named) in refused.message


def test_a_symlink_loop_is_worded_alike_when_resolve_raises_as_it_did_before_3_13(
    tmp_path, monkeypatch
):
    """Before Python 3.13, ``Path.resolve()`` raises RuntimeError for a path
    that is a symbolic link loop; 3.13 and later answer without raising and
    the load fails on the open instead. The same cell with ``resolve``
    raising what 3.10-3.12 raise, so the interpreter running the suite does
    not decide which of the two the gate meets. Like ``_stat_denied_for``, it
    raises for the named path alone."""
    from pathlib import Path

    named = tmp_path / "named.yaml"
    named.symlink_to(named)
    real_resolve = Path.resolve

    def resolve(self, *args, **kwargs):
        if os.fspath(self) == os.fspath(named):
            raise RuntimeError(f"Symlink loop from {os.fspath(self)!r}")
        return real_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", resolve)

    refused, launcher, artifact = _scan(tmp_path, monkeypatch, named)

    _kept(refused, launcher, artifact)
    assert f"Config file is a symbolic link loop: {named.as_posix()}" in (
        refused.message
    ), refused.message
    assert "Config path is a symbolic link loop" not in refused.message


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
def test_a_fifo_from_ash_config_is_refused_in_ash_configs_words(
    tmp_path, monkeypatch, capsys
):
    fifo = tmp_path / "pipe.yaml"
    os.mkfifo(fifo)

    refused, launcher, artifact = _scan(tmp_path, monkeypatch, fifo, ash_config=fifo)

    _kept(refused, launcher, artifact)
    flat = _flat(capsys.readouterr().out)
    assert "ASH_CONFIG names" in flat, flat
    assert "does not exist" not in flat, flat


def test_a_symlink_loop_is_named_as_a_loop_not_as_missing(
    tmp_path, monkeypatch, capsys
):
    loop = tmp_path / "loop.yaml"
    loop.symlink_to(loop)

    refused, launcher, artifact = _scan(tmp_path, monkeypatch, loop)

    _kept(refused, launcher, artifact)
    flat = _flat(capsys.readouterr().out)
    assert "symbolic link loop" in flat, flat
    assert "not found" not in flat, flat


def test_a_symlink_loop_from_ash_config_is_named_in_ash_configs_words(
    tmp_path, monkeypatch, capsys
):
    loop = tmp_path / "loop.yaml"
    loop.symlink_to(loop)

    refused, launcher, artifact = _scan(tmp_path, monkeypatch, loop, ash_config=loop)

    _kept(refused, launcher, artifact)
    flat = _flat(capsys.readouterr().out)
    assert "ASH_CONFIG names" in flat and "symbolic link loop" in flat, flat


def _stat_denied_for(monkeypatch, target):
    """os.stat answers EACCES for *target* alone, as it does for a path under a
    directory this user cannot search; every other path is stat'ed for real.
    Works for a privileged user too."""
    real_stat = os.stat
    wanted = os.fspath(target)

    def stat(path, *args, **kwargs):
        if os.fspath(path) == wanted:
            raise PermissionError(errno.EACCES, "Permission denied")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", stat)


def test_a_config_whose_stat_is_denied_is_refused_not_crashed(
    tmp_path, monkeypatch, capsys
):
    """Before Python 3.14, ``Path.is_file()`` raises the stat's PermissionError
    for a path under an unsearchable directory, and the gate called it inside
    its own except handler: the second error escaped the entry uncaught where
    a local scan refuses with exit 3."""
    named = tmp_path / "private" / "ash.yaml"
    _stat_denied_for(monkeypatch, named)

    refused, launcher, artifact = _scan(tmp_path, monkeypatch, named)

    _kept(refused, launcher, artifact)
    flat = _flat(capsys.readouterr().out)
    assert "cannot be read (EACCES)" in flat, flat
    assert "not found" not in flat, flat


def test_a_denied_config_is_refused_even_when_is_file_raises_as_it_did_before_3_14(
    tmp_path, monkeypatch, capsys
):
    """The same cell with ``Path.is_file`` raising what 3.10-3.13 raise, so the
    interpreter running the suite does not decide whether it can fail. Like
    ``_stat_denied_for``, it raises for the named path alone."""
    from pathlib import Path

    named = tmp_path / "private" / "ash.yaml"
    _stat_denied_for(monkeypatch, named)
    real_is_file = Path.is_file

    def is_file(self, *args, **kwargs):
        if os.fspath(self) == os.fspath(named):
            raise PermissionError(errno.EACCES, "Permission denied", str(self))
        return real_is_file(self, *args, **kwargs)

    monkeypatch.setattr(Path, "is_file", is_file)

    refused, launcher, artifact = _scan(tmp_path, monkeypatch, named)

    _kept(refused, launcher, artifact)
    assert "cannot be read (EACCES)" in _flat(capsys.readouterr().out)


def test_a_denied_config_from_ash_config_is_refused_in_ash_configs_words(
    tmp_path, monkeypatch, capsys
):
    named = tmp_path / "private" / "ash.yaml"
    _stat_denied_for(monkeypatch, named)

    refused, launcher, artifact = _scan(tmp_path, monkeypatch, named, ash_config=named)

    _kept(refused, launcher, artifact)
    flat = _flat(capsys.readouterr().out)
    assert "ASH_CONFIG names" in flat and "cannot be read (EACCES)" in flat, flat


@_NEEDS_PERMISSION_BITS
def test_a_config_under_a_directory_this_user_cannot_search_is_refused(
    tmp_path, monkeypatch, capsys
):
    locked = tmp_path / "locked"
    locked.mkdir()
    named = locked / "ash.yaml"
    named.write_text("project_name: locked-one\n", encoding="utf-8")
    locked.chmod(0)
    try:
        refused, launcher, artifact = _scan(tmp_path, monkeypatch, named)
    finally:
        locked.chmod(0o755)

    _kept(refused, launcher, artifact)
    assert "cannot be read (EACCES)" in _flat(capsys.readouterr().out)


def test_a_file_the_process_cannot_read_is_refused_by_the_access_check(
    tmp_path, monkeypatch, capsys
):
    """A regular file whose load failed some other way, which this process has
    no right to read, is refused as unreadable by the access check; the same
    failure on a readable file is left to the shell's scan."""
    named = tmp_path / "ash.yaml"
    named.write_text("project_name: t\n", encoding="utf-8")

    def load_that_cannot_open(_opts, for_run=False, **_kwargs):
        raise PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(ras, "_loaded_config_file", load_that_cannot_open)
    real_access = os.access
    monkeypatch.setattr(
        os,
        "access",
        lambda path, mode, *a, **k: (
            False if os.fspath(path) == str(named) else real_access(path, mode, *a, **k)
        ),
    )

    refused, launcher, artifact = _scan(tmp_path, monkeypatch, named)

    _kept(refused, launcher, artifact)
    flat = _flat(capsys.readouterr().out)
    assert "Config file cannot be read:" in flat and str(named) in flat, flat


def test_a_readable_file_whose_load_failed_some_other_way_is_left_to_the_shell(
    tmp_path, monkeypatch
):
    named = tmp_path / "ash.yaml"
    named.write_text("project_name: t\n", encoding="utf-8")

    def load_that_fails(_opts, for_run=False, **_kwargs):
        raise OSError("some other failure")

    monkeypatch.setattr(ras, "_loaded_config_file", load_that_fails)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    opts = ras.ScanOptions(
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
        config=str(named),
        mode=RunMode.nix,
    )

    assert ras._outer_mode_config_load(opts).refusal is None


def _write_unreadable(path, request):
    path.write_text("project_name: locked\n", encoding="utf-8")
    path.chmod(0)
    request.addfinalizer(lambda: path.chmod(0o600))
    if os.access(path, os.R_OK):
        pytest.skip("this process can read a mode-0 file")


@_NEEDS_PERMISSION_BITS
def test_an_unreadable_discovered_config_is_refused_and_the_prior_run_is_kept(
    tmp_path, monkeypatch, request, capsys
):
    """No ``--config`` and no ``ASH_CONFIG``: discovery selects ``src/.ash.yaml``,
    which this process cannot read. The gate deferred that OSError to
    ``_unusable_nix_config``, which judges ``--config`` alone, so the file passed
    the gate, the previous run's output was cleared and the shell started."""
    refused, launcher, artifact = _scan(
        tmp_path,
        monkeypatch,
        None,
        discovered=lambda path: _write_unreadable(path, request),
    )

    _kept(refused, launcher, artifact)
    flat = _flat(capsys.readouterr().out)
    assert "could not read" in flat, flat
    assert ".ash.yaml" in flat, flat


@_NEEDS_PERMISSION_BITS
def test_an_unreadable_discovered_config_is_worded_as_the_local_scan_words_it(
    tmp_path, monkeypatch, request
):
    """The nix gate's refusal of the discovered file is the local scan's refusal
    of the same file, word for word (resolve_config's OSError handler)."""
    refused, _launcher, _artifact = _scan(
        tmp_path,
        monkeypatch,
        None,
        discovered=lambda path: _write_unreadable(path, request),
    )

    with pytest.raises(ScanRefusedExit) as local_refused:
        run_ash_scan(
            source_dir=tmp_path / "src",
            output_dir=tmp_path / "local-out",
            mode=RunMode.local,
            progress=False,
            show_summary=False,
        )

    assert refused.code == 3 and local_refused.value.code == 3
    assert refused.message == local_refused.value.message, (
        refused.message,
        local_refused.value.message,
    )
    assert str(tmp_path / "src" / ".ash.yaml") in refused.message, refused.message


def test_a_discovered_file_whose_load_failed_some_other_way_is_left_to_the_shell(
    tmp_path, monkeypatch
):
    """An OSError that does not name the discovered file (the checkout walk's,
    say) keeps the deferral: only the open of the selected file is worded."""
    src = tmp_path / "src"
    src.mkdir()
    (src / ".ash.yaml").write_text("project_name: t\n", encoding="utf-8")

    def load_that_fails(_opts, for_run=False, **_kwargs):
        raise OSError("some other failure")

    monkeypatch.setattr(ras, "_loaded_config_file", load_that_fails)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    opts = ras.ScanOptions(
        source_dir=src,
        output_dir=tmp_path / "out",
        mode=RunMode.nix,
    )

    assert ras._outer_mode_config_load(opts).refusal is None
