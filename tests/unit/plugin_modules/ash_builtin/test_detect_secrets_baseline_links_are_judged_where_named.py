# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A detect-secrets baseline is judged by the path that named it, not by its target.

The scanner resolved each baseline candidate with ``os.path.realpath`` and then
judged that resolved path everywhere: ``_baseline_refusal`` saw it as the path
"named", and ``_untrusted_baseline_reason`` handed it to
``scanned_checkout_reason``. So an in-tree ``.secrets.baseline`` that was a
symlink to a file outside the tree was read, and its settings, the verification
filter included, were judged by where the target sat: outside the scanned tree,
so the operator's.

Now the chosen baseline keeps the path as named (anchored to the source
directory, no link resolved) beside the resolved path the file is read through.
A baseline found in the tree whose target is outside the scanned directory is
not read at all; a baseline the operator names is read and judged by the name
the operator gave.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
    DetectSecretsScannerConfigOptions,
)

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("no_tool_probes")]

VERIFICATION_FILTER = (
    "detect_secrets.filters.common.is_ignored_due_to_verification_policies"
)


def _baseline_text() -> str:
    return json.dumps(
        {
            "version": "1.5.0",
            "plugins_used": [{"name": "AWSKeyDetector"}],
            "filters_used": [{"path": VERIFICATION_FILTER, "min_level": 2}],
            "results": {},
            "generated_at": "2026-01-01T00:00:00Z",
        }
    )


def _context(tmp_path: Path) -> PluginContext:
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    context.source_dir.mkdir(parents=True, exist_ok=True)
    context.output_dir.mkdir(parents=True, exist_ok=True)
    return context


def _link_in_tree_to_outside(tmp_path: Path, context: PluginContext) -> Path:
    """``<source>/.secrets.baseline`` as a symlink to a baseline outside the tree."""
    outside = tmp_path / "elsewhere" / "team.baseline"
    outside.parent.mkdir(parents=True)
    outside.write_text(_baseline_text(), encoding="utf-8")
    link = context.source_dir / ".secrets.baseline"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"symlinks unavailable on this platform: {exc}")
    return outside


def test_an_in_tree_baseline_that_links_out_of_the_tree_is_not_read(
    tmp_path, monkeypatch, caplog
):
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    _link_in_tree_to_outside(tmp_path, context)

    with caplog.at_level(logging.WARNING):
        scanner = DetectSecretsScanner(
            context=context, config=DetectSecretsScannerConfig()
        )

    assert not scanner._baseline_in_use()
    assert scanner._baseline_document is None
    assert any(
        "a link to a file outside the scanned directory" in record.message
        for record in caplog.records
    ), [record.message for record in caplog.records]
    # The scan still has detectors: the full default set, not the link's one.
    assert len(scanner.config.options.scan_settings.plugins_used) > 10
    # The link's settings are not the scan's: the verification filter it names
    # was not loaded.
    assert not any(
        item.path == VERIFICATION_FILTER
        for item in scanner.config.options.scan_settings.filters_used
    )


def test_an_operator_named_in_tree_link_is_judged_where_it_is_named(
    tmp_path, monkeypatch
):
    """The operator may name the link; its settings are still the repository's,
    because the file named sits inside the scanned directory."""
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    outside = _link_in_tree_to_outside(tmp_path, context)
    scanner = DetectSecretsScanner(
        context=context,
        config=DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(baseline_file=".secrets.baseline")
        ),
    )

    assert scanner._baseline_in_use()
    assert scanner._baseline_named == context.source_dir / ".secrets.baseline"
    assert scanner._baseline_real == Path(os.path.realpath(outside))
    reason = scanner._untrusted_baseline_reason(None)
    assert reason is not None and "inside the scanned directory" in reason, reason


def test_a_regular_in_tree_baseline_is_named_where_it_sits(tmp_path, monkeypatch):
    """Control: a baseline that is no link is used, and named by its own path."""
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    (context.source_dir / ".secrets.baseline").write_text(
        _baseline_text(), encoding="utf-8"
    )
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())

    assert scanner._baseline_in_use()
    assert scanner._baseline_named == context.source_dir / ".secrets.baseline"
    assert [p.name for p in scanner.config.options.scan_settings.plugins_used] == [
        "AWSKeyDetector"
    ]
    reason = scanner._untrusted_baseline_reason(None)
    assert reason is not None and "inside the scanned directory" in reason, reason


def test_a_client_delivered_link_is_refused_by_its_name(tmp_path, monkeypatch):
    """An MCP client's delivered tree is known by its path. A ``.secrets.baseline``
    in it that links out of the tree was tested by its resolved path only, which
    is not under the delivered tree, so the client's choice of what to hide was
    read. The name the client delivered is what is tested."""
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    _link_in_tree_to_outside(tmp_path, context)
    from automated_security_helper.cli.mcp import sandbox

    delivered = os.path.normpath(str(context.source_dir / ".secrets.baseline"))

    def client_supplied(config_path):
        return os.path.normpath(str(config_path)) == delivered

    monkeypatch.setattr(sandbox, "config_is_client_supplied", client_supplied)
    scanner = DetectSecretsScanner(
        context=context,
        config=DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(baseline_file=".secrets.baseline")
        ),
    )

    assert scanner._baseline_trust_refused is True
    assert not scanner._baseline_in_use()
