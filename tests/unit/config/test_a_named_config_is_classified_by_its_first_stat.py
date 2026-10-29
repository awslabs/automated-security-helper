# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Each site that classifies a named config path answers its first stat.

Three sites refuse a named config path that is a symbolic link loop or that
the stat is denied for, instead of treating it as missing: the scan's
``--config`` pre-check, ``resolve_config``, and the ASH_CONFIG lookup. A
site that stats a second time to classify reads a different answer whenever
the path changes in between (a permission or mount change, a link replaced):
a path whose first stat was denied but whose second passed was reported as not
found, and a loop whose second stat said missing was reported as missing. A
stat stand-in stages both orders deterministically.

The scan reads the named file once before its pre-check (the fail_on_findings
lookup, through the loader), so for that site the stand-in counts only the
stats the pre-check itself makes: the stats made while ``_run_local_mode`` is
running and the resolution it starts is not.

When ASH_CONFIG gave ``--config`` its value, the pre-check refuses in
ASH_CONFIG's words. It used to get them by calling get_default_config, whose
lookup stats the path again, so the second answer named the path: a denied or
looping path whose second stat said missing was reported as "does not exist",
and so was a directory. The ASH_CONFIG lookup itself asked ``is_file()`` after
its own stat had answered, so a file that stat found was refused as "not a
file" (Python 3.14) or raised the second stat's PermissionError (earlier).
"""

from __future__ import annotations

import errno
import os
import stat as stat_module
import sys

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit


def _running(function: str, module: str) -> bool:
    frame = sys._getframe(2)
    while frame is not None:
        code = frame.f_code
        if code.co_name == function and code.co_filename.endswith(module):
            return True
        frame = frame.f_back
    return False


def _every_stat() -> bool:
    return True


def _the_scan_pre_checks_stats() -> bool:
    return _running("_run_local_mode", "run_ash_scan.py") and not _running(
        "_resolve_config", "resolve_config.py"
    )


def _denied_then_passes(named, real_stat, counted):
    seen: list = []

    def stat(path, *args, **kwargs):
        if os.fspath(path) == str(named) and counted():
            seen.append(True)
            if len(seen) == 1:
                raise PermissionError(errno.EACCES, "Permission denied", str(named))
        return real_stat(path, *args, **kwargs)

    return stat, seen


def _loop_then_missing(named, real_stat, counted):
    seen: list = []

    def stat(path, *args, **kwargs):
        if os.fspath(path) == str(named) and counted():
            seen.append(True)
            if len(seen) == 1:
                raise OSError(
                    errno.ELOOP, "Too many levels of symbolic links", str(named)
                )
            raise FileNotFoundError(errno.ENOENT, "No such file", str(named))
        return real_stat(path, *args, **kwargs)

    return stat, seen


SHAPES = {
    "denied-then-passes": (_denied_then_passes, "cannot be read (EACCES)"),
    "loop-then-missing": (_loop_then_missing, "symbolic link loop"),
}


def _refused_by_resolve_config(tmp_path, named):
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    src = tmp_path / "src"
    src.mkdir()
    try:
        resolve_config(config_path=named, source_dir=src, fallback_to_default=True)
    except ASHConfigValidationError as refused:
        return str(refused)
    return "no refusal: the default configuration was used"


def _refused_by_ash_config(tmp_path, named, monkeypatch):
    from automated_security_helper.config.default_config import get_default_config

    monkeypatch.setenv("ASH_CONFIG", str(named))
    try:
        get_default_config()
    except Exception as refused:  # noqa: BLE001 -- the cell reads any refusal's text
        return str(refused)
    return "no refusal: the default configuration was used"


def _refused_by_the_scan(tmp_path, named, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()

    def stop(self, *args, **kwargs):
        raise SystemExit(0)

    monkeypatch.setattr(
        "automated_security_helper.core.orchestrator.ASHScanOrchestrator.execute_scan",
        stop,
    )
    monkeypatch.chdir(src)
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--mode",
            "local",
            "--no-progress",
            "--source-dir",
            str(src),
            "--output-dir",
            str(tmp_path / "out"),
            "--config",
            str(named),
        ],
    )
    flat = " ".join(result.output.split())
    assert result.exit_code == 3, (result.exit_code, flat[-1500:])
    return flat


SITES = {
    "resolve-config": (
        lambda tmp_path, named, monkeypatch: _refused_by_resolve_config(
            tmp_path, named
        ),
        _every_stat,
    ),
    "ash-config": (_refused_by_ash_config, _every_stat),
    "scan-pre-check": (_refused_by_the_scan, _the_scan_pre_checks_stats),
}


@pytest.mark.parametrize("shape", sorted(SHAPES))
@pytest.mark.parametrize("site", sorted(SITES))
def test_a_named_config_is_classified_by_its_first_stat(
    tmp_path, monkeypatch, site, shape
):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    named = tmp_path / "named.yaml"
    named.write_text("project_name: operator-choice\n", encoding="utf-8")
    staged, reason = SHAPES[shape]
    refused_by, counted = SITES[site]
    stat, seen = staged(named, os.stat, counted)
    monkeypatch.setattr(os, "stat", stat)

    text = refused_by(tmp_path, named, monkeypatch)

    assert seen, "control: the named path was never stat'ed; the cell measured nothing"
    assert reason in text, text[-1500:]
    assert "not found" not in text and "does not exist" not in text, text[-1500:]


def _denied_then_missing(named, real_stat, counted):
    seen: list = []

    def stat(path, *args, **kwargs):
        if os.fspath(path) == str(named) and counted():
            seen.append(True)
            if len(seen) == 1:
                raise PermissionError(errno.EACCES, "Permission denied", str(named))
            raise FileNotFoundError(errno.ENOENT, "No such file", str(named))
        return real_stat(path, *args, **kwargs)

    return stat, seen


def _a_directory_then_missing(named, real_stat, counted):
    seen: list = []
    a_directory = os.stat_result(
        (stat_module.S_IFDIR | 0o755, 0, 0, 2, 0, 0, 0, 0, 0, 0)
    )

    def stat(path, *args, **kwargs):
        if os.fspath(path) == str(named) and counted():
            seen.append(True)
            if len(seen) == 1:
                return a_directory
            raise FileNotFoundError(errno.ENOENT, "No such file", str(named))
        return real_stat(path, *args, **kwargs)

    return stat, seen


ASH_CONFIG_SHAPES = {
    "denied-then-missing": (_denied_then_missing, "which cannot be read (EACCES)"),
    "loop-then-missing": (_loop_then_missing, "which is a symbolic link loop"),
    "a-directory-then-missing": (
        _a_directory_then_missing,
        "ASH_CONFIG names it, and it is not a file",
    ),
}


@pytest.mark.parametrize("shape", sorted(ASH_CONFIG_SHAPES))
def test_a_config_ash_config_gave_is_refused_by_the_pre_checks_own_stat(
    tmp_path, monkeypatch, shape
):
    named = tmp_path / "named.yaml"
    named.write_text("project_name: operator-choice\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(named))
    staged, reason = ASH_CONFIG_SHAPES[shape]
    stat, seen = staged(named, os.stat, _the_scan_pre_checks_stats)
    monkeypatch.setattr(os, "stat", stat)

    text = _refused_by_the_scan(tmp_path, named, monkeypatch)

    assert seen, "control: the named path was never stat'ed; the cell measured nothing"
    assert "ASH_CONFIG names" in text, text[-1500:]
    assert reason in text, text[-1500:]
    assert "not found" not in text and "does not exist" not in text, text[-1500:]


def _passes_then_denied(named, real_stat, counted):
    seen: list = []

    def stat(path, *args, **kwargs):
        if os.fspath(path) == str(named) and counted():
            seen.append(True)
            if len(seen) == 2:
                raise PermissionError(errno.EACCES, "Permission denied", str(named))
        return real_stat(path, *args, **kwargs)

    return stat, seen


def test_the_ash_config_lookup_loads_the_file_its_stat_found(tmp_path, monkeypatch):
    from automated_security_helper.config.default_config import get_default_config

    named = tmp_path / "named.yaml"
    named.write_text("project_name: operator-choice\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(named))
    stat, seen = _passes_then_denied(named, os.stat, _every_stat)
    monkeypatch.setattr(os, "stat", stat)

    config = get_default_config()

    assert seen, "control: the named path was never stat'ed; the cell measured nothing"
    assert config.project_name == "operator-choice"
