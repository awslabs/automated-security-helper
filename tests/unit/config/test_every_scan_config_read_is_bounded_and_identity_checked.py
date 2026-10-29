# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The reader every scan's load uses is bounded and identity-checked.

``load_config_file_for_run`` reads each chain file through its own reader
(``read_once``), which must read the way the stock reader does: through
``read_config_bytes``, so the ``ASH_CONFIG_MAX_FILE_BYTES`` bound and the
non-blocking open bind, and with the ``FileIdentity`` the chain walk vetted,
so a file swapped in between the walk's check and the open is refused rather
than read. Both are exercised through the module's own seams (the module
attributes the walk and the reader look up at call time); no real swap race
is run.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest
import yaml

from automated_security_helper.config import config_sources
from automated_security_helper.config.resolve_config import load_config_file_for_run
from automated_security_helper.core.exceptions import ASHConfigSourceError


def _write(path: Path, document: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def test_the_every_scan_read_honors_the_size_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A chain file longer than ASH_CONFIG_MAX_FILE_BYTES is refused, not read whole."""
    config = _write(
        tmp_path / "ash.yaml",
        {"project_name": "bounded", "padding": "x" * 4096},
    )
    assert config.stat().st_size > 256
    monkeypatch.setattr(config_sources, "ASH_CONFIG_MAX_FILE_BYTES", 256)

    with pytest.raises(ASHConfigSourceError, match="is larger than 256 bytes"):
        load_config_file_for_run(config)

    # Control: the same bound admits a file inside it.
    small = _write(tmp_path / "small" / "ash.yaml", {"project_name": "bounded"})
    assert small.stat().st_size <= 256
    _document, loaded = load_config_file_for_run(small)
    assert loaded.project_name == "bounded"


def test_a_file_swapped_after_the_walks_check_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The read refuses a file whose identity is not the one the walk vetted.

    The walk takes the root's identity through ``config_sources.file_identity``;
    pinning that seam to another file's identity stands in for a swap between
    the check and the open, with no real race. The reader must hand the vetted
    identity to ``read_config_bytes``, which refuses the mismatch.
    """
    config = _write(tmp_path / "ash.yaml", {"project_name": "vetted"})
    other = _write(tmp_path / "other.yaml", {"project_name": "swapped-in"})
    vetted_elsewhere = config_sources.file_identity(other)
    assert vetted_elsewhere is not None
    monkeypatch.setattr(config_sources, "file_identity", lambda _path: vetted_elsewhere)

    with pytest.raises(OSError, match="changed after it was checked"):
        load_config_file_for_run(config)

    # Control: with the real identity the same file loads.
    monkeypatch.undo()
    _document, loaded = load_config_file_for_run(config)
    assert loaded.project_name == "vetted"
