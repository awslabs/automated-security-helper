# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""syrupy extensions that normalize before they serialize.

Two shapes, both bound to one :class:`SnapshotNormalizer` per test by the fixtures in
tests/snapshot/conftest.py:

- :class:`NormalizingAmberExtension` stores structured data (dicts, lists, strings) in
  one ``.ambr`` file per test module. Use it for payloads: MCP results, error dicts,
  parsed JSON.
- :class:`NormalizingTextFileExtension` stores one rendered document per file, with the
  document's own extension (``.md``, ``.html``, ``.sarif``), so the diff a reviewer sees
  is the diff of the file a user would open. Use it for anything ASH prints or writes
  as text.
"""

from __future__ import annotations

from typing import Any, ClassVar

from syrupy.extensions.amber import AmberSnapshotExtension
from syrupy.extensions.single_file import SingleFileSnapshotExtension, WriteMode

from tests.snapshot.support.normalize import SnapshotNormalizer


class NormalizingAmberExtension(AmberSnapshotExtension):
    normalizer: ClassVar[SnapshotNormalizer]

    def serialize(self, data: Any, **kwargs: Any) -> str:
        return super().serialize(self.normalizer.data(data), **kwargs)


class NormalizingTextFileExtension(SingleFileSnapshotExtension):
    _write_mode = WriteMode.TEXT
    normalizer: ClassVar[SnapshotNormalizer]
    file_extension = "txt"

    def serialize(self, data: Any, **kwargs: Any) -> str:
        if not isinstance(data, str):
            raise TypeError(
                f"text_snapshot takes the rendered str, got {type(data).__name__}; "
                "use the `snapshot` fixture for structured data"
            )
        text = self.normalizer.text(data)
        # One trailing newline, always: editors and git disagree about the last line.
        return text.rstrip("\n") + "\n"


def bind(base: type, normalizer: SnapshotNormalizer, **attrs: Any) -> type:
    """A subclass of ``base`` carrying ``normalizer``; syrupy instantiates extensions itself."""
    return type(base.__name__, (base,), {"normalizer": normalizer, **attrs})
