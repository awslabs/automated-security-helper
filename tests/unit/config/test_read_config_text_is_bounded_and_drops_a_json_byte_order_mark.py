# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``read_config_text`` reads through the bounded reader and drops a JSON BOM.

Without an identity to hold the read to, ``read_config_text`` fell back to a
plain blocking ``open()`` and an unbounded ``read()``, so the config validator,
the linter, MCP profile loading and the literal re-resolution read whole files
with no ``ASH_CONFIG_MAX_FILE_BYTES`` bound. And it decoded a JSON file as
plain UTF-8, keeping a leading byte order mark that ``json.loads`` refuses,
while ``read_config_file`` decodes the same file as utf-8-sig: a JSON config
with a mark loaded there and was refused by every scan load.

Red at the base: the oversize file was read whole; the JSON file with a mark
was refused as unparseable by ``load_config_document``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.config import config_sources
from automated_security_helper.config.config_sources import (
    load_config_document,
    read_config_text,
)
from automated_security_helper.core.exceptions import ASHConfigSourceError

pytestmark = pytest.mark.unit


def test_a_text_read_without_an_identity_is_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(config_sources, "ASH_CONFIG_MAX_FILE_BYTES", 64)
    config_path = tmp_path / ".ash.yaml"
    config_path.write_text("fail_on_findings: false\n" * 20, encoding="utf-8")

    with pytest.raises(ASHConfigSourceError, match="is larger than 64 bytes"):
        read_config_text(config_path)


def test_a_small_text_still_reads_whole(tmp_path: Path) -> None:
    """The control."""
    config_path = tmp_path / ".ash.yaml"
    config_path.write_text("fail_on_findings: false\n", encoding="utf-8")

    assert read_config_text(config_path) == "fail_on_findings: false\n"


def test_a_json_config_with_a_byte_order_mark_loads(tmp_path: Path) -> None:
    config_path = tmp_path / ".ash.json"
    config_path.write_bytes(b"\xef\xbb\xbf" + b'{"fail_on_findings": false}\n')

    assert not read_config_text(config_path).startswith(chr(0xFEFF))
    assert load_config_document(config_path) == {"fail_on_findings": False}
