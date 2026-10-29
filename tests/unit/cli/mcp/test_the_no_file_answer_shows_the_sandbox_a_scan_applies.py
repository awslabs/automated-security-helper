# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The no-file get_config answer's sandbox section is the scan's.

The tool documents its answer as the configuration a scan of the searched
directory would use, sandbox section included. A chain file inside that
directory is restrict-only for such a scan: the scan drops the grants it
writes (extra read paths, network scanners) with a warning. The answer has
to drop them the same way -- an agent reading a grant the scan never
applies would act on access the scan does not have. The oracle in each
cell is the scan's own resolution of the same directory, so the cells pin
agreement with the scan rather than a copied expectation.
"""

from pathlib import Path

import pytest

from automated_security_helper.cli.mcp.sandbox import ASH_MCP_ALLOWED_ROOTS_ENV
from automated_security_helper.cli.mcp_tools import mcp_get_config
from automated_security_helper.config.resolve_config import resolve_config

pytestmark = pytest.mark.unit


def _searched_tree(tmp_path: Path, monkeypatch) -> Path:
    """A directory the server may scan, wherever the test's tmp root sits."""
    monkeypatch.setenv(ASH_MCP_ALLOWED_ROOTS_ENV, str(tmp_path))
    src = tmp_path / "src"
    src.mkdir()
    return src


_GRANTS = "sandbox:\n  mode: bwrap\n  extra_read_paths:\n    - /opt/outside-grant\n"


def test_an_in_tree_chain_files_grants_are_dropped_from_the_answer(
    tmp_path, monkeypatch
):
    src = _searched_tree(tmp_path, monkeypatch)
    chain = src / "ash-env.yaml"
    chain.write_text(_GRANTS, encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(chain))

    answer = mcp_get_config(search_dir=str(src))
    applied = resolve_config(source_dir=src).sandbox.model_dump()

    # Premise: a scan of the searched directory does drop the in-tree file's
    # grant. If this line ever fails, the confinement rule changed and the
    # cell needs re-pinning, not the answer.
    assert applied["extra_read_paths"] == [], applied
    assert answer["sandbox"] == applied, answer["sandbox"]


def test_an_operator_chain_files_grants_stay_in_the_answer(tmp_path, monkeypatch):
    """Control: a chain file outside the searched tree is the operator's, and
    a scan applies its grants, so the answer keeps them too."""
    src = _searched_tree(tmp_path, monkeypatch)
    chain = tmp_path / "ops" / "ash-env.yaml"
    chain.parent.mkdir()
    chain.write_text(_GRANTS, encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(chain))

    answer = mcp_get_config(search_dir=str(src))
    applied = resolve_config(source_dir=src).sandbox.model_dump()

    assert applied["extra_read_paths"] == ["/opt/outside-grant"], applied
    assert answer["sandbox"] == applied, answer["sandbox"]
