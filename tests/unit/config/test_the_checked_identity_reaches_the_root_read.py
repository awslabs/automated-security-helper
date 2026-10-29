# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The identity a caller took when it checked a config path reaches the read.

``mcp_get_config`` hands the identity of the checked file to ``resolve_config``
as ``expect``, and each layer below it hands it on to the next until the root
read in ``config_sources.resolve_config_document``. A layer that dropped the
argument would read whichever file the name leads to by then, and no cell that
swaps the file from inside the check would notice: the early refusal in the tool
answers first. So each layer is called here with an identity that is no longer the
file's, and must refuse the read.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable, Dict

import pytest

from automated_security_helper.cli.mcp import sandbox
from automated_security_helper.cli.mcp_tools import mcp_get_config
from automated_security_helper.config import config_sources, resolve_config
from automated_security_helper.config.config_sources import (
    ConfigFileChangedError,
    FileIdentity,
)

pytestmark = pytest.mark.unit

CANARY = "replaced-file-canary-2e68"

#: Each layer from the tool's call down to the root read, called with a config
#: path and the identity to hold the read to.
LAYERS: Dict[str, Callable[[Path, FileIdentity], Any]] = {
    "resolve_config_document": lambda path, stale: (
        config_sources.resolve_config_document(
            path, confine_to=path.parent, expect=stale
        )
    ),
    "resolve_config_source": lambda path, stale: resolve_config.resolve_config_source(
        path, source_dir=path.parent, expect=stale
    ),
    "load_config_file": lambda path, stale: resolve_config.load_config_file(
        path, source_dir=path.parent, expect=stale
    ),
    # The branch that names the confinement directory itself.
    "load_config_file_confined": lambda path, stale: resolve_config.load_config_file(
        path, confine_to=path.parent, expect=stale
    ),
    "load_config_file_for_run": lambda path, stale: (
        resolve_config.load_config_file_for_run(
            path, source_dir=path.parent, expect=stale
        )
    ),
    "resolve_config": lambda path, stale: resolve_config.resolve_config(
        config_path=path,
        source_dir=path.parent,
        fallback_to_default=False,
        expect=stale,
    ),
}


def _a_file_and_an_identity_that_is_no_longer_its(tmp_path: Path):
    config = tmp_path / "ash-config.yaml"
    config.write_text(f"project_name: {CANARY}\n", encoding="utf-8")
    checked = config_sources.file_identity(config)
    assert checked is not None
    # The identity of a file that is not the one at the name.
    return config, (checked[0], checked[1] + 1)


@pytest.mark.parametrize("layer", sorted(LAYERS))
def test_each_layer_refuses_a_read_held_to_another_file(layer, tmp_path) -> None:
    config, stale = _a_file_and_an_identity_that_is_no_longer_its(tmp_path)

    with pytest.raises(ConfigFileChangedError):
        LAYERS[layer](config, stale)


@pytest.mark.parametrize("layer", sorted(LAYERS))
def test_control_each_layer_reads_a_file_held_to_its_own_identity(
    layer, tmp_path
) -> None:
    config, _stale = _a_file_and_an_identity_that_is_no_longer_its(tmp_path)

    LAYERS[layer](config, config_sources.file_identity(config))


def test_the_tool_holds_the_resolved_read_to_the_file_its_check_returned(
    tmp_path, monkeypatch
) -> None:
    """The file changes after the check returned, inside the next question the
    tool asks (whose config this is), so only the identity handed to
    ``resolve_config`` can refuse it."""
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config = tmp_path / "ash-config.yaml"
    config.write_text("project_name: checked\n", encoding="utf-8")
    other = tmp_path / "other.yaml"
    other.write_text(f"project_name: {CANARY}\n", encoding="utf-8")
    changed = []

    def untrusted_after_the_file_changed(*_args: Any, **_kwargs: Any) -> bool:
        if not changed:
            os.replace(other, config)
            changed.append(True)
        return False

    monkeypatch.setattr(
        sandbox, "client_named_config_is_untrusted", untrusted_after_the_file_changed
    )

    response = mcp_get_config(config_path=str(config))

    assert changed == [True], "the file did not change where the cell expects it"
    assert response.get("success") is False, response
    text = json.dumps(response, default=str)
    assert "changed after it was checked" in text, response
    assert CANARY not in text, response
