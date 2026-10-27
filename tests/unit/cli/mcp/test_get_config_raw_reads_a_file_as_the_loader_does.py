# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""get_config(raw=True) reads a file as the loader reads it.

Why this file exists
--------------------
The raw read parses a config file without reading the environment
(``_config_as_written``). Its JSON branch decoded the bytes as ``utf-8``, so a
file that starts with a byte order mark failed to parse raw while the resolved
read, which decodes ``utf-8-sig``, loaded it.

The YAML branch gives the parser a stream named for the file, as the config
modules do (``config_sources.named_text_stream``), so the parser's marks carry
the file's name. Nothing a client can read depends on that: a parse failure is
answered with the kind of error and its line and column
(``config_sources.parse_error_kind``) and never in the parser's words, so no
cell here can tell the two apart through ``get_config``, and the one control
below holds only that a YAML file that parses is returned.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.cli.mcp_tools import _config_as_written, mcp_get_config


@pytest.fixture(autouse=True)
def _environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASH_MCP_TRANSPORT", raising=False)


def test_control_a_yaml_file_that_parses_is_returned(tmp_path: Path) -> None:
    target = tmp_path / "config.yaml"
    target.write_text("project_name: parsed\n", encoding="utf-8")

    assert _config_as_written(target) == {"project_name": "parsed"}


def test_a_json_file_with_a_byte_order_mark_loads_raw(tmp_path: Path) -> None:
    target = tmp_path / "config.json"
    target.write_bytes(b"\xef\xbb\xbf" + b'{"project_name": "with-mark"}\n')

    result = mcp_get_config(config_path=str(target), raw=True)

    assert result == {"project_name": "with-mark"}, result


def test_control_a_json_file_without_a_byte_order_mark_loads_raw(
    tmp_path: Path,
) -> None:
    target = tmp_path / "config.json"
    target.write_bytes(b'{"project_name": "plain"}\n')

    result = mcp_get_config(config_path=str(target), raw=True)

    assert result == {"project_name": "plain"}, result
