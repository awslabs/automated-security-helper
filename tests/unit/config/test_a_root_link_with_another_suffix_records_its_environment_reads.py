# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A root config that is a link to a file with another suffix records what it read.

The root is parsed in the format of the path the caller named, but the
as-written view the environment record is paired from, and the remote-caller
environment check of the held text, read the same text in the format of the
RESOLVED target. For a ``.ash.yaml`` link to a ``.json`` file holding YAML
text with a plain ``${VAR}`` scalar, the parse read the variable while the
as-written view, parsed as JSON, failed and recorded nothing: the value reached
the record with no reference. Both now read the text in the format it was
parsed under.

Red at the base: ``environment_references`` was empty for the linked root.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.config.config_sources import resolve_config_document

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        os.name == "nt",
        reason="creating a symlink needs a privilege or Developer Mode there",
    ),
]


def test_the_linked_roots_environment_read_is_recorded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ASH_U35_LEVEL", "HIGH")
    # YAML block text behind a .json name: parsed as YAML under the link's own
    # suffix, and not JSON at all.
    target = tmp_path / "settings.json"
    target.write_text(
        "global_settings:\n  severity_threshold: ${ASH_U35_LEVEL}\n",
        encoding="utf-8",
    )
    link = tmp_path / ".ash.yaml"
    link.symlink_to(target)

    document = resolve_config_document(link)

    assert document.data["global_settings"]["severity_threshold"] == "HIGH"
    recorded = [
        (reference.path, reference.written, reference.value)
        for reference in document.environment_references
    ]
    assert recorded == [
        (("global_settings", "severity_threshold"), "${ASH_U35_LEVEL}", "HIGH")
    ], recorded


def test_a_plain_root_records_as_before(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: a root parsed under its own suffix."""
    monkeypatch.setenv("ASH_U35_LEVEL", "HIGH")
    root = tmp_path / ".ash.yaml"
    root.write_text("global_settings:\n  severity_threshold: ${ASH_U35_LEVEL}\n")

    document = resolve_config_document(root)

    assert [r.written for r in document.environment_references] == ["${ASH_U35_LEVEL}"]
