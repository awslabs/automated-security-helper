# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An operator config that does not validate names `ashx config lint`.

#780 loads the operator's own config file as the trusted base whenever the config
a scan selected is inside the scanned tree (workspace and MCP scans). When that
file does not validate, the scan stops with a message whose last sentence is the
operator's next step, the same one _resolve_config gives for the config it
selected. That step has to name the command v4 ships: `ashx`. The deprecated `ash`
alias still works on most hosts, but on Windows under Git for Windows or MSYS2
`ash` is the Almquist shell.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.cli.deprecations import CANONICAL_CLI_NAME
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import ASHConfigValidationError


def _resolve(tmp_path: Path, operator_text: str, selected_text: str):
    source = tmp_path / "repo"
    (source / ".ash").mkdir(parents=True)
    selected = source / ".ash" / ".ash.yaml"
    selected.write_text(selected_text)
    operator = tmp_path / "operator.yaml"
    operator.write_text(operator_text)
    return resolve_config(
        config_path=selected,
        source_dir=source,
        trusted_config_path=operator,
    )


def test_an_invalid_operator_config_names_the_canonical_config_lint(tmp_path):
    with pytest.raises(ASHConfigValidationError) as raised:
        _resolve(
            tmp_path,
            operator_text="project_name: operator\nfail_on_findings: notabool\n",
            selected_text="project_name: scanned\n",
        )
    message = str(raised.value)
    assert "operator.yaml" in message
    assert f"Run '{CANONICAL_CLI_NAME} config lint'" in message
    assert "'ash config lint'" not in message


def test_the_selected_config_names_the_same_command(tmp_path):
    # The message the operator file's now matches, so both stay pinned together.
    with pytest.raises(ASHConfigValidationError) as raised:
        _resolve(
            tmp_path,
            operator_text="project_name: operator\n",
            selected_text="project_name: scanned\nfail_on_findings: notabool\n",
        )
    assert f"Run '{CANONICAL_CLI_NAME} config lint'" in str(raised.value)
