# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The workspace execution loader loads every chain the scan's own load takes.

``resolve_workspace_execution_config`` answers only the two workspace knobs,
but it loads the whole config file. Loading it without the scan's confinement
and ownership refused, with exit 3, chains the scan itself takes: a repository
file's write for an operator-only option, which the confine strips as the file
is read, and an operator pointer the ownership fold lands on the operator's
own key. Each cell first proves the scan's own load takes the chain, so only
the workspace loader's behavior can fail it.
"""

import pytest
import yaml

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import (
    ASHConfigSourceError,
    ASHConfigValidationError,
)
from automated_security_helper.interactions import run_ash_scan
from tests.utils.helpers import mark_git_checkout

_REFUSED = (ASHConfigSourceError, ASHConfigValidationError)


def _write(path, document):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def _workspace(tmp_path, document):
    ws = tmp_path / "ws"
    mark_git_checkout(ws)
    _write(ws / ".ash" / ".ash.yaml", document)
    return ws


def test_a_repositorys_operator_only_write_does_not_refuse_the_workspace_run(
    tmp_path, monkeypatch
):
    """What the repository writes for an operator-only option never makes its
    configuration unloadable: the scan's own load strips it as the file is
    read, and the workspace loader loads the same way."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    ws = _workspace(
        tmp_path,
        {
            "scanners": {
                "detect-secrets": {
                    "options": {"max_worker_output_mib": "zz-not-a-number"}
                }
            }
        },
    )
    try:
        resolve_config(source_dir=ws)
    except _REFUSED as error:
        raise RuntimeError(
            "the scan's own load refuses, so the cell shows nothing: "
            + type(error).__name__
        )
    answer = run_ash_scan.resolve_workspace_execution_config(ws)
    assert answer.model_dump() == {
        "max_parallel_projects": None,
        "project_timeout": None,
    }


def test_an_operator_config_beside_a_twin_loads_for_the_workspace_as_for_the_scan(
    tmp_path, monkeypatch
):
    """The operator's --config extends its own section file and the workspace
    root's file, which writes a case-variant twin, and patches under a third
    spelling. The scan's own load, with ownership, takes it; so does the
    workspace loader.

    The root extends the repository's file first. ``extends`` joins the two
    spellings into one section under the spelling of the file extended last
    (config_sources.py module docstring, the plugin-section rule), so the
    joined key is the operator's own and the patch folds onto it. Extended the
    other way the joined key is the repository's spelling, which the operator's
    files never wrote, and the scan refuses the patch as a path that does not
    fit the document
    (test_a_repository_twin_neither_blocks_nor_captures_the_operators_patch).
    """
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    ws = _workspace(
        tmp_path,
        {
            "reporters": {
                "AwsSecurityHub": {
                    "enabled": True,
                    "options": {"aws_region": "repo-r0"},
                }
            }
        },
    )
    own = _write(
        tmp_path / "own.yaml",
        {
            "reporters": {
                "aws-security-hub": {
                    "enabled": True,
                    "options": {"aws_region": "us-east-1"},
                }
            }
        },
    )
    root = _write(
        tmp_path / "operator.yaml",
        {
            "extends": [(ws / ".ash" / ".ash.yaml").as_posix(), own.as_posix()],
            "patch": [
                {
                    "op": "replace",
                    "path": "/reporters/AWS_Security_Hub/options/aws_region",
                    "value": "us-west-2",
                }
            ],
            "workspace": {"max_parallel_projects": 3},
        },
    )
    try:
        resolve_config(config_path=root, source_dir=ws)
    except _REFUSED as error:
        raise RuntimeError(
            "the scan's own load refuses, so the cell shows nothing: "
            + type(error).__name__
        )
    answer = run_ash_scan.resolve_workspace_execution_config(ws, str(root))
    assert answer.max_parallel_projects == 3


def test_control_the_workspace_knobs_are_still_the_roots_choice(tmp_path, monkeypatch):
    """The confine strips no workspace knob: the root file's own values answer."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    ws = _workspace(tmp_path, {"workspace": {"max_parallel_projects": 7}})
    answer = run_ash_scan.resolve_workspace_execution_config(ws)
    assert answer.model_dump() == {"max_parallel_projects": 7, "project_timeout": None}


def test_control_a_config_the_scan_refuses_still_refuses_the_workspace_run(
    tmp_path, monkeypatch
):
    """The loader stays as strict as the scan: a config the scan's own load
    refuses (an unknown workspace knob; extra is forbidden) refuses here too."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    ws = _workspace(tmp_path, {"workspace": {"zz_not_a_knob": 1}})
    with pytest.raises(_REFUSED):
        resolve_config(source_dir=ws)
    with pytest.raises(_REFUSED):
        run_ash_scan.resolve_workspace_execution_config(ws)
