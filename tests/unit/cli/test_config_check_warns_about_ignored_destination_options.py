# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash config lint`` and ``ash config validate`` warn, naming the plugin and
the key, about an off-host reporter's destination or retry option a repository
file writes, which a scan, ``ash report`` and ``ash merge`` ignore.

Those commands take an off-host reporter's destination and retry options, and
its ``enabled``, from the trusted base and ``--config-overrides``
(``config/reporter_trust.py``), and log what a repository file wrote for them.
The config check warned only about the two options its own operator-only table
names, so a repository's ``.ash/.ash.yaml`` that set the Security Hub retry
count passed ``lint`` and ``validate`` clean and was ignored by every scan. The
check now judges the destination table too, with the warning it already gives
for an ignored operator-only option. A file outside the tree, and a value an
override supplies in the file's place, warn nothing: those are the operator's.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.config import config_app

pytestmark = pytest.mark.unit

IGNORED = (
    "reporters.aws-security-hub.options.max_retries is set in a config file "
    "inside the scanned tree, and a scan ignores that value"
)


def _repository_config(project: Path, body: str) -> Path:
    path = project / ".ash" / ".ash.yaml"
    path.parent.mkdir(parents=True)
    path.write_text(body, encoding="utf-8")
    return path


RETRY_IN_THE_FILE = (
    "project_name: demo\n"
    "reporters:\n"
    "  aws-security-hub:\n"
    "    enabled: true\n"
    "    options:\n"
    "      aws_region: us-east-1\n"
    "      max_retries: 3\n"
)

NO_RETRY_IN_THE_FILE = (
    "project_name: demo\n"
    "reporters:\n"
    "  aws-security-hub:\n"
    "    options:\n"
    "      aws_profile: ops\n"
)


def _run(command: str, config: Path, *more: str):
    return CliRunner().invoke(
        config_app,
        [command, "--config", str(config), *more],
        env={"COLUMNS": "300", "NO_COLOR": "1"},
    )


@pytest.mark.parametrize("command", ["lint", "validate"])
def test_a_repository_file_retry_option_is_warned_as_ignored(
    tmp_path, monkeypatch, command
):
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(project)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config = _repository_config(project, RETRY_IN_THE_FILE)

    result = _run(command, config)

    assert result.exit_code == 0, result.output
    assert IGNORED in " ".join(result.output.split()), result.output
    # The region and the enabled switch are the scan's to ignore too: each
    # place is named, once.
    flat = " ".join(result.output.split())
    assert (
        "reporters.aws-security-hub.options.aws_region is set in a config file" in flat
    )
    assert "reporters.aws-security-hub.enabled is set in a config file" in flat
    assert flat.count("options.max_retries is set in a config file") == 1


def test_validate_does_not_warn_when_the_operator_supplies_the_option(
    tmp_path, monkeypatch
):
    """The control: the file carries no retry option and the override does."""
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(project)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config = _repository_config(project, NO_RETRY_IN_THE_FILE)

    result = _run(
        "validate",
        config,
        "--config-overrides",
        "reporters.aws-security-hub.options.max_retries=3",
    )

    assert result.exit_code == 0, result.output
    assert "max_retries" not in result.output, result.output
    # The profile the file wrote is a destination option, so that one is named.
    assert "reporters.aws-security-hub.options.aws_profile is set in a config file" in (
        " ".join(result.output.split())
    )


@pytest.mark.parametrize(
    "overrides, named",
    [
        # Overrides apply in order: the last one naming the place is the value
        # a scan sees. Last equal to the file's: nothing to warn about.
        (
            (
                "reporters.aws-security-hub.options.max_retries=9",
                "reporters.aws-security-hub.options.max_retries=3",
            ),
            False,
        ),
        # Last different from the file's: the file's value is not kept.
        (
            (
                "reporters.aws-security-hub.options.max_retries=3",
                "reporters.aws-security-hub.options.max_retries=9",
            ),
            True,
        ),
    ],
    ids=["last-equal", "last-differs"],
)
def test_the_last_override_naming_a_place_decides(
    tmp_path, monkeypatch, overrides, named
):
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(project)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config = _repository_config(project, RETRY_IN_THE_FILE)
    arguments = []
    for override in overrides:
        arguments += ["--config-overrides", override]

    result = _run("validate", config, *arguments)

    assert result.exit_code == 0, result.output
    flat = " ".join(result.output.split())
    assert ("options.max_retries is set in a config file" in flat) is named, flat


@pytest.mark.parametrize("command", ["lint", "validate"])
def test_a_file_outside_the_tree_is_the_operators_and_warns_nothing(
    tmp_path, monkeypatch, command
):
    project = tmp_path / "project"
    project.mkdir()
    operator_dir = tmp_path / "operator"
    operator_dir.mkdir()
    monkeypatch.chdir(project)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config = operator_dir / "ash.yaml"
    config.write_text(RETRY_IN_THE_FILE, encoding="utf-8")

    result = _run(command, config, "--source-dir", str(project))

    assert result.exit_code == 0, result.output
    assert "is set in a config file inside the scanned tree" not in result.output, (
        result.output
    )
