# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An ASH_CONFIG that names a file that does not exist is refused, never skipped.

ASH_CONFIG is the operator's choice of configuration: the file a scan starts
from, and the environment spelling of ``--config``. Were naming a file that is
not there to leave every run on the built-in defaults, which drop the file's
suppressions and settings, the run would report success: the scan would exit 0,
``ash config validate`` would call a valid ``--config`` file valid although a
scan with the same environment would not use it, and ``ash report`` would exit 1
for a reason that had nothing to do with the configuration.

Each refuses with exit 3. The message names ASH_CONFIG and the path, in the
words a scan uses (``default_config.get_default_config``). ``ash report`` refuses
a ``--config`` that does not exist the same way, as the config commands do. An
empty ASH_CONFIG counts as unset, and one of only whitespace is refused.
"""

from __future__ import annotations

from pathlib import Path

import os

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

#: The scan's refusal, from get_default_config.
NOT_THERE = "which does not exist"


@pytest.fixture
def missing(tmp_path, monkeypatch) -> Path:
    path = tmp_path / "no-such-config.yaml"
    monkeypatch.setenv("ASH_CONFIG", str(path))
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)
    return path


def _valid(tmp_path: Path) -> Path:
    config = tmp_path / "project" / ".ash.yaml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text("project_name: valid\n", encoding="utf-8")
    return config


def _flat(text: str) -> str:
    return " ".join(text.split())


def test_get_default_config_refuses_it(missing):
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.core.exceptions import ASHConfigFileNotFoundError

    with pytest.raises(ASHConfigFileNotFoundError) as raised:
        get_default_config()

    assert f"ASH_CONFIG names {missing}, {NOT_THERE}" in str(raised.value)
    assert raised.value.ash_config_file == missing


def test_a_path_under_a_regular_file_does_not_exist(tmp_path, monkeypatch):
    """ASH_CONFIG naming a path whose parent is a regular file is a missing
    file like a plain absent one, not an unreadable path: nothing can ever
    exist under a file, so the refusal says "does not exist" instead of
    naming the errno's code."""
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.core.exceptions import ASHConfigFileNotFoundError

    plain = tmp_path / "plain.yaml"
    plain.write_text("project_name: p\n", encoding="utf-8")
    under = plain / "config.yaml"
    monkeypatch.setenv("ASH_CONFIG", str(under))

    with pytest.raises(ASHConfigFileNotFoundError) as raised:
        get_default_config()

    assert f"ASH_CONFIG names {under}, {NOT_THERE}" in str(raised.value)
    assert raised.value.ash_config_file == under


def test_the_scan_s_load_refuses_it(missing, tmp_path):
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    (tmp_path / "src").mkdir()
    with pytest.raises(ASHConfigValidationError, match=NOT_THERE):
        resolve_config(source_dir=tmp_path / "src")


def test_a_scan_exits_3_without_scanning(missing, tmp_path, monkeypatch):
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    def ran(*_args, **_kwargs):
        raise AssertionError("the scan ran, on the built-in defaults")

    monkeypatch.setattr(ASHScanOrchestrator, "execute_scan", ran)
    (tmp_path / "src").mkdir()

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--source-dir",
            str(tmp_path / "src"),
            "--output-dir",
            str(tmp_path / "out"),
            "--mode",
            "local",
        ],
    )

    assert result.exit_code == 3, result.output
    assert NOT_THERE in _flat(result.output), result.output


_NEEDS_PERMISSION_BITS = pytest.mark.skipif(
    os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="a privileged user reads through permission bits",
)


@_NEEDS_PERMISSION_BITS
def test_an_unreadable_ash_config_exits_3_naming_the_errno(tmp_path, monkeypatch):
    """ASH_CONFIG naming a file whose directory denies the stat: the scan
    refuses it by the reason, with exit 3 and no traceback, the way a missing
    file is refused. The raw stat error crashed the scan with a traceback
    where exists() propagates it, and where exists() swallows it the refusal
    misnamed the file as missing. The direct get_default_config cell pins the
    classification; this one pins the scan route reaching it."""
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    def ran(*_args, **_kwargs):
        raise AssertionError("the scan ran, on the built-in defaults")

    monkeypatch.setattr(ASHScanOrchestrator, "execute_scan", ran)
    locked = tmp_path / "locked"
    locked.mkdir()
    named = locked / "named.yaml"
    named.write_text("project_name: locked-one\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(named))
    (tmp_path / "src").mkdir()
    locked.chmod(0)
    try:
        result = CliRunner().invoke(
            app,
            [
                "scan",
                "--source-dir",
                str(tmp_path / "src"),
                "--output-dir",
                str(tmp_path / "out"),
                "--mode",
                "local",
            ],
        )
    finally:
        locked.chmod(0o755)
    flat = _flat(result.output)
    assert result.exit_code == 3, (result.exit_code, result.output[-800:])
    assert "cannot be read (EACCES)" in flat, result.output[-800:]
    # ASH_CONFIG's own words, not the scan's "Config file" classification: the
    # scan hands a value that came from ASH_CONFIG back to get_default_config,
    # whose refusal names the variable, and without this line the cell stays
    # green when that hand-off is gone.
    assert "ASH_CONFIG names" in flat, result.output[-800:]
    assert "does not exist" not in flat, result.output[-800:]
    assert "Traceback" not in result.output, result.output[-800:]


def test_a_looped_ash_config_exits_3_naming_the_loop(tmp_path, monkeypatch):
    """ASH_CONFIG naming a symbolic link loop on the same scan route: the
    classification's loop arm reaches the scan command too, as the loop cell
    for get_default_config pins it directly."""
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    def ran(*_args, **_kwargs):
        raise AssertionError("the scan ran, on the built-in defaults")

    monkeypatch.setattr(ASHScanOrchestrator, "execute_scan", ran)
    loop = tmp_path / "loop.yaml"
    loop.symlink_to(loop)
    monkeypatch.setenv("ASH_CONFIG", str(loop))
    (tmp_path / "src").mkdir()

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--source-dir",
            str(tmp_path / "src"),
            "--output-dir",
            str(tmp_path / "out"),
            "--mode",
            "local",
        ],
    )

    flat = _flat(result.output)
    assert result.exit_code == 3, (result.exit_code, result.output[-800:])
    assert "symbolic link loop" in flat, result.output[-800:]
    assert "ASH_CONFIG names" in flat, result.output[-800:]
    assert "does not exist" not in flat, result.output[-800:]
    assert "Traceback" not in result.output, result.output[-800:]


@pytest.mark.parametrize("command", ["validate", "get"])
def test_a_check_of_another_file_refuses_it_too(missing, tmp_path, command):
    """A scan of the named file under this environment refuses the run, so the
    check of that file does too, and names ASH_CONFIG."""
    config = _valid(tmp_path)

    result = CliRunner().invoke(app, ["config", command, "--config", str(config)])

    assert result.exit_code == 3, result.output
    flat = _flat(result.output)
    assert NOT_THERE in flat and "ASH_CONFIG" in flat, result.output


#: Each ASH_CONFIG a scan refuses, and the words it refuses it with.
_REFUSED_ASH_CONFIG = {
    "missing": NOT_THERE,
    "whitespace": "only whitespace",
    "dangling": NOT_THERE,
}


def _command(command: str, config: Path, tmp_path: Path) -> list:
    if command == "report":
        return [
            "report",
            "--output-dir",
            str(tmp_path / "out"),
            "--config",
            str(config),
        ]
    return ["config", command, "--config", str(config)]


@pytest.mark.parametrize(
    "command", ["validate", "get", "validate-plugin-dependencies", "report"]
)
@pytest.mark.parametrize("kind", sorted(_REFUSED_ASH_CONFIG))
@pytest.mark.parametrize("where", ["inside", "outside"])
def test_a_check_of_another_file_refuses_it_wherever_that_file_is(
    missing, tmp_path, monkeypatch, where, kind, command
):
    """Whether the named file is inside the working directory or not. Outside it,
    the file is not the tree's, and get, validate-plugin-dependencies and report
    still read ASH_CONFIG and refuse one that names no file, holds only
    whitespace or is a link to nothing."""
    config = _valid(tmp_path)
    if where == "outside":
        work = tmp_path / "work"
        work.mkdir()
        monkeypatch.chdir(work)
    if kind == "whitespace":
        monkeypatch.setenv("ASH_CONFIG", "  ")
    elif kind == "dangling":
        link = tmp_path / "dangling.yaml"
        link.symlink_to(tmp_path / "gone.yaml")
        monkeypatch.setenv("ASH_CONFIG", str(link))

    result = CliRunner().invoke(app, _command(command, config, tmp_path))

    assert result.exit_code == 3, result.output
    flat = _flat(result.output)
    assert _REFUSED_ASH_CONFIG[kind] in flat and "ASH_CONFIG" in flat, result.output


def test_report_refuses_it(missing, tmp_path):
    result = CliRunner().invoke(app, ["report", "--output-dir", str(tmp_path / "out")])

    assert result.exit_code == 3, result.output
    assert f"ASH_CONFIG names {missing}, {NOT_THERE}" in _flat(result.output)


def test_report_refuses_a_config_option_that_does_not_exist(
    missing, tmp_path, monkeypatch
):
    monkeypatch.delenv("ASH_CONFIG")
    named = tmp_path / "named-but-missing.yaml"

    result = CliRunner().invoke(
        app, ["report", "--output-dir", str(tmp_path / "out"), "--config", str(named)]
    )

    assert result.exit_code == 3, result.output
    flat = _flat(result.output)
    assert f"Invalid configuration: Configuration file not found: {named}" in flat


def test_only_whitespace_is_refused(missing, monkeypatch):
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    monkeypatch.setenv("ASH_CONFIG", "  ")

    with pytest.raises(ASHConfigSourceError, match="only whitespace"):
        get_default_config()


def test_control_empty_is_unset_and_an_existing_file_loads(
    missing, tmp_path, monkeypatch
):
    from automated_security_helper.config.default_config import get_default_config

    monkeypatch.setenv("ASH_CONFIG", "")
    assert get_default_config().project_name == "ash-scan"

    monkeypatch.setenv("ASH_CONFIG", str(_valid(tmp_path)))
    assert get_default_config().project_name == "valid"
