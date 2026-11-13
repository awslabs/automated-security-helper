# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ash config update --set` refuses a top-level key the configuration does not declare.

The configuration model ignores a top-level key it does not declare, so such a
--set would change nothing the configuration reads. The command refuses it as
it refuses an unknown key inside a section: exit 3, the file's bytes unchanged,
and one line that names the key.

No refusal and no success line shows a --set's value, which can be a
credential: not on stdout, not on stderr, and not in a log record at any
level. The value each cell sets is made up when it runs. A successful update
prints the updated file, so the value appears on stdout only as often as the
file holds it.

Only a --set is refused. A file that already holds such a key still loads, and
an update of another key keeps it.

The file needs nothing but the CLI app, the configuration model and the "ash"
logger, so the same cells can run on any tree that has them.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from pathlib import Path
from typing import Iterator, List

import pytest
import yaml
from typer.testing import CliRunner

from automated_security_helper.cli.config import config_app
from automated_security_helper.config.ash_config import AshConfig

pytestmark = pytest.mark.unit

# The CLI's exit code for an invalid configuration.
INVALID_CONFIG_EXIT_CODE = 3

# A key the model does not declare, which the file already holds.
STARTING_CONFIG = (
    "project_name: demo\n"
    "fail_on_findings: true\n"
    "from_a_newer_version: 1\n"
    "scanners:\n"
    "  bandit:\n"
    "    enabled: true\n"
)


@pytest.fixture
def config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    path = tmp_path / ".ash" / ".ash.yaml"
    path.parent.mkdir()
    path.write_text(STARTING_CONFIG, encoding="utf-8")
    return path


@pytest.fixture
def planted() -> str:
    """A value made up for this run, which no text in ASH can hold."""
    return f"planted-{secrets.token_hex(6)}"


class _KeepMessages(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=1)
        self.messages: List[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


@pytest.fixture
def log_messages() -> Iterator[List[str]]:
    """Every message the "ash" logger handles while a cell runs, at any level."""
    handler = _KeepMessages()
    logger = logging.getLogger("ash")
    logger.addHandler(handler)
    try:
        yield handler.messages
    finally:
        logger.removeHandler(handler)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _update(config_file: Path, assignment: str):
    return CliRunner().invoke(
        config_app, ["update", str(config_file), "--set", assignment]
    )


def _assert_not_shown(result, planted: str, log_messages: List[str]) -> None:
    assert planted not in result.stdout, result.stdout
    assert planted not in result.stderr, result.stderr
    assert [message for message in log_messages if planted in message] == []


def _assert_refused(
    result, config_file: Path, before: str, planted: str, log_messages: List[str]
) -> None:
    assert result.exit_code == INVALID_CONFIG_EXIT_CODE, result.output
    assert _sha256(config_file) == before, "the file was written"
    _assert_not_shown(result, planted, log_messages)
    assert len(result.output.splitlines()) == 1, result.output


@pytest.mark.parametrize(
    ("assignment", "key"),
    [
        pytest.param("not_a_field={value}", "not_a_field", id="unknown-key"),
        pytest.param(
            "fail_on_findingz={value}", "fail_on_findingz", id="misspelled-field"
        ),
        pytest.param(
            "from_a_newer_version={value}",
            "from_a_newer_version",
            id="a-key-the-file-holds",
        ),
        pytest.param(
            "not-a-section.inner={value}", "not-a-section", id="under-an-unknown-key"
        ),
        pytest.param("not_a_field+=[{value}]", "not_a_field", id="append"),
    ],
)
def test_a_set_of_an_unknown_top_level_key_is_refused(
    config_file, planted, log_messages, assignment, key
):
    before = _sha256(config_file)

    result = _update(config_file, assignment.format(value=planted))

    _assert_refused(result, config_file, before, planted, log_messages)
    assert key in result.output, result.output


@pytest.mark.parametrize(
    ("assignment", "key"),
    [
        pytest.param(
            "global_settings.not_a_field={value}", "not_a_field", id="global-settings"
        ),
        pytest.param(
            "scanners.bandit.not_a_field={value}", "not_a_field", id="plugin-section"
        ),
    ],
)
def test_a_set_of_an_unknown_key_inside_a_section_is_refused(
    config_file, planted, log_messages, assignment, key
):
    """The refusal the top-level one matches."""
    before = _sha256(config_file)

    result = _update(config_file, assignment.format(value=planted))

    _assert_refused(result, config_file, before, planted, log_messages)
    assert key in result.output, result.output


@pytest.mark.parametrize(
    "assignment",
    [
        pytest.param("={value}", id="no-key"),
        pytest.param(
            " global_settings.severity_threshold={value}", id="a-space-in-the-key"
        ),
        pytest.param(
            "global_settings.ignore_paths="
            + "[" * 100_000
            + '"{value}"'
            + "]" * 100_000,
            id="a-value-nested-too-deep-to-parse",
        ),
    ],
)
def test_a_set_that_cannot_be_applied_does_not_show_its_value(
    config_file, planted, log_messages, assignment
):
    before = _sha256(config_file)

    result = _update(config_file, assignment.replace("{value}", planted))

    _assert_refused(result, config_file, before, planted, log_messages)


@pytest.mark.parametrize(
    ("assignment", "key"),
    [
        pytest.param("project_name={value}", "project_name", id="set"),
        pytest.param(
            'global_settings.ignore_paths+=[{{"path": "dist/**", "reason": "{value}"}}]',
            "global_settings.ignore_paths",
            id="append",
        ),
    ],
)
def test_the_success_line_names_the_key_and_not_the_value(
    config_file, planted, log_messages, assignment, key
):
    result = _update(config_file, assignment.format(value=planted))

    assert result.exit_code == 0, result.output
    written = config_file.read_text(encoding="utf-8")
    assert planted in written
    # The printed file is the only place stdout holds the value.
    assert result.stdout.count(planted) == written.count(planted), result.stdout
    assert planted not in result.stderr, result.stderr
    assert [message for message in log_messages if planted in message] == []
    assert any(key in message for message in log_messages), log_messages


@pytest.mark.parametrize(
    ("assignment", "check"),
    [
        pytest.param(
            "fail_on_findings=false",
            lambda config: config.fail_on_findings is False,
            id="field-name",
        ),
        pytest.param(
            "fail-on-findings=false",
            lambda config: config.fail_on_findings is False,
            id="field-name-with-dashes",
        ),
        pytest.param(
            "mcp-resource-management.max_concurrent_scans=7",
            lambda config: config.mcp_resource_management.max_concurrent_scans == 7,
            id="alias",
        ),
        pytest.param(
            "mcp_resource_management.max_concurrent_scans=7",
            lambda config: config.mcp_resource_management.max_concurrent_scans == 7,
            id="field-name-of-an-aliased-field",
        ),
    ],
)
def test_a_set_of_a_declared_top_level_key_still_updates(
    config_file, assignment, check
):
    result = _update(config_file, assignment)

    assert result.exit_code == 0, result.output
    assert check(AshConfig.from_file(config_path=config_file))


class TestAFileHoldingAnUnknownTopLevelKey:
    def test_it_loads(self, config_file):
        config = AshConfig.from_file(config_path=config_file)

        assert config.project_name == "demo"

    def test_an_update_of_another_key_keeps_it(self, config_file):
        result = _update(config_file, "fail_on_findings=false")

        assert result.exit_code == 0, result.output
        data = yaml.safe_load(config_file.read_text(encoding="utf-8"))
        assert data["from_a_newer_version"] == 1
        assert data["fail_on_findings"] is False
