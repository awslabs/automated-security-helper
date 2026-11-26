# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A requested sandbox refuses an image scan, with the reason, before any tool.

The sandbox's read scope is built from the source tree, the output directory
and the scan target; an image's inputs (a saved archive or layout anywhere on
the host, an engine socket, the network for a ref) live outside every one of
them. Rather than starting a tool that fails partway on an unreadable payload,
the scope builder refuses the combination outright, and the executor grades
the refusal as it grades every non-availability refusal. A filesystem asset
changes nothing.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from automated_security_helper.core.asset import Asset, ImageLocator
from automated_security_helper.utils.sandbox.scope import (
    SandboxUnavailable,
    scanner_sandbox_scope,
)

pytestmark = pytest.mark.unit

REF = "registry.example.com/team/app:1.2.3"


def _context(tmp_path, asset, mode: str = "auto"):
    from automated_security_helper.config.ash_config import SandboxConfig

    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    output = tmp_path / "out"
    output.mkdir(exist_ok=True)
    return SimpleNamespace(
        source_dir=source,
        output_dir=output,
        work_dir=output / "work",
        asset=asset,
        config=SimpleNamespace(sandbox=SandboxConfig(mode=mode)),
    )


class _Scanner:
    config = None


def test_an_image_asset_refuses_a_requested_sandbox(tmp_path):
    context = _context(tmp_path, Asset.for_image(ImageLocator(ref=REF)))
    with pytest.raises(SandboxUnavailable) as raised:
        scanner_sandbox_scope(_Scanner, context, None)
    text = str(raised.value)
    assert "container-image scan" in text
    assert "without the sandbox" in text


def test_no_sandbox_requested_is_no_scope_whatever_the_asset(tmp_path):
    context = _context(tmp_path, Asset.for_image(ImageLocator(ref=REF)), mode="off")
    assert scanner_sandbox_scope(_Scanner, context, None) is None
