# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No command that takes --config-overrides shows an override's value.

A value can be a credential, and a command's output, its log and the files it
leaves in its output directory leave the host in CI. Each command that applies
--config-overrides is given an override it cannot apply, holding a value made
up when the cell runs. The value is not on stdout or stderr, not in a log
record at any level, and not in the output directory, and the refusal still
names the key. A scan's config resolution, given an override it applies, logs
no record holding the value either.
"""

from __future__ import annotations

import logging
import secrets
from pathlib import Path
from typing import Iterator, List

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.config.resolve_config import resolve_config


@pytest.fixture
def planted() -> str:
    """A value made up for this run, which no text in ASH can hold."""
    return f"planted-{secrets.token_hex(6)}"


class _Keep(logging.Handler):
    def __init__(self, sink: List[str]) -> None:
        super().__init__(level=1)
        self.sink = sink
        self.setFormatter(logging.Formatter("%(name)s %(levelname)s %(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        # format() appends the traceback, chained causes included.
        self.sink.append(self.format(record))


@pytest.fixture
def logged() -> Iterator[List[str]]:
    """Every record at every level, from the root and every logger that does not
    propagate."""
    sink: List[str] = []
    handler = _Keep(sink)
    loggers = [logging.getLogger()] + [
        logger
        for logger in logging.Logger.manager.loggerDict.values()
        if isinstance(logger, logging.Logger) and not logger.propagate
    ]
    if logging.getLogger("ash") not in loggers:
        loggers.append(logging.getLogger("ash"))
    # Every level reaches the handler, as it reaches a scan's log file.
    levels = [(logger, logger.level) for logger in loggers]
    for logger in loggers:
        logger.addHandler(handler)
        logger.setLevel(1)
    try:
        yield sink
    finally:
        for logger, level in levels:
            logger.removeHandler(handler)
            logger.setLevel(level)


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    config = tmp_path / "ash-config.yaml"
    config.write_text("project_name: demo\n", encoding="utf-8")
    return {
        "source": source,
        "config": config,
        "output": tmp_path / "out",
    }


def _command(name: str, project: dict) -> List[str]:
    config = ["--config", str(project["config"])]
    return {
        "scan": [
            "scan",
            "--source-dir",
            str(project["source"]),
            "--output-dir",
            str(project["output"]),
            *config,
        ],
        "report": ["report", "--output-dir", str(project["output"]), *config],
        "config get": ["config", "get", *config],
        "config validate": ["config", "validate", *config],
        "config validate-plugin-dependencies": [
            "config",
            "validate-plugin-dependencies",
            *config,
        ],
        "plugin list": ["plugin", "list", *config],
        "dependencies install": ["dependencies", "install", *config],
    }[name]


COMMANDS = [
    "scan",
    "report",
    "config get",
    "config validate",
    "config validate-plugin-dependencies",
    "plugin list",
    "dependencies install",
]

# An override each command refuses, and the key its refusal names ("" for one
# with no key).
OVERRIDES = [
    pytest.param(
        "global_settings.not_a_field={value}",
        "global_settings.not_a_field",
        id="a-key-the-config-refuses",
    ),
    pytest.param(
        "global_settings.severity_threshold={value}",
        "global_settings.severity_threshold",
        id="a-value-the-config-refuses",
    ),
    pytest.param("={value}", "", id="no-key"),
    pytest.param(
        " global_settings.severity_threshold={value}",
        " global_settings.severity_threshold",
        id="a-space-in-the-key",
    ),
]


def _files_holding(directory: Path, planted: str) -> List[str]:
    if not directory.exists():
        return []
    return [
        str(path)
        for path in directory.rglob("*")
        if path.is_file() and planted.encode() in path.read_bytes()
    ]


@pytest.mark.parametrize("command", COMMANDS)
@pytest.mark.parametrize(("override", "key"), OVERRIDES)
def test_a_refused_override_is_named_by_its_key(
    project, planted, logged, command, override, key
):
    args = [*_command(command, project), "--config-overrides"]
    args.append(override.format(value=planted))

    result = CliRunner().invoke(app, args)

    assert result.exit_code != 0, result.output
    assert planted not in result.stdout, result.stdout
    assert planted not in result.stderr, result.stderr
    if result.exception is not None and not isinstance(result.exception, SystemExit):
        assert planted not in str(result.exception), result.exception
    assert [record for record in logged if planted in record] == []
    assert _files_holding(project["output"], planted) == []
    assert key in result.output, result.output


def test_config_resolution_logs_no_value_it_applies(project, planted, logged):
    config = resolve_config(
        project["config"],
        source_dir=project["source"],
        config_overrides=[
            f"project_name={planted}",
            f'global_settings.ignore_paths+=[{{"path": "x/**", "reason": "{planted}"}}]',
        ],
    )

    assert config.project_name == planted
    assert [record for record in logged if planted in record] == []
