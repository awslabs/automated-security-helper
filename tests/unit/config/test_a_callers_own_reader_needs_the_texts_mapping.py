# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A caller's own reader needs the texts mapping; a patched global is not a caller.

``resolve_config_document`` fails closed when a caller supplies its own reader
without the ``texts`` mapping: with no text cache the resolution records no
environment reference the chain read, so values would be resolved into the data
and never redacted. The check measures caller intent through a ``None``
sentinel default, so a test idiom that patches the module's
``read_config_file`` to record which files a resolution reads does not turn a
default call into "a caller's own reader" -- the sentinel resolves to the
call-time global, and the recording wrapper is picked up and records.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, List
from unittest.mock import patch

import pytest

from automated_security_helper.config import config_sources
from automated_security_helper.config.config_sources import resolve_config_document


def _config(tmp_path: Path) -> Path:
    path = tmp_path / "ash.yaml"
    path.write_text("project_name: pinned\n")
    return path


def test_a_callers_own_reader_without_texts_is_refused(tmp_path: Path) -> None:
    """The fail-closed contract: an own reader with no texts mapping raises."""

    def own_reader(path: Path) -> Any:  # pragma: no cover - the check precedes reads
        raise AssertionError("the texts check precedes any read")

    with pytest.raises(TypeError, match="own reader needs the `texts` mapping"):
        resolve_config_document(_config(tmp_path), reader=own_reader)


def test_a_patched_global_is_not_a_callers_reader(tmp_path: Path) -> None:
    """A default call under a patched ``read_config_file`` resolves (no raise).

    The stock chain read keeps each file's text itself and never calls the
    ``read_config_file`` callable, so the wrapper sees nothing here by design;
    the recording idiom's seam is ``read_config_bytes`` (the next test).
    """
    config = _config(tmp_path)
    real = config_sources.read_config_file

    def recording(path: Path, *args: Any, **kwargs: Any) -> Any:
        return real(path, *args, **kwargs)

    with patch.object(config_sources, "read_config_file", recording):
        document = resolve_config_document(config)

    assert document.chain, "the default call resolved under the patch"


def test_the_recording_idiom_sees_every_read_at_the_bytes(tmp_path: Path) -> None:
    """A wrapper on ``read_config_bytes`` records the stock chain read."""
    config = _config(tmp_path)
    read: List[Path] = []
    real = config_sources.read_config_bytes

    def recording(path: Path, *args: Any, **kwargs: Any) -> Any:
        read.append(Path(path).resolve())
        return real(path, *args, **kwargs)

    with patch.object(config_sources, "read_config_bytes", recording):
        document = resolve_config_document(config)

    assert [p.name for p in read] == ["ash.yaml"], "the wrapper saw the read"
    assert document.chain, "the default call resolved under the patch"
