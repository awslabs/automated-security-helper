# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The converted target's scan set holds every file the converters wrote.

The converted target is ``work_dir``, the converters' output, which the scanner
enumerates itself. It did so with ``glob("**/*.*")``, which takes only names
holding a dot, so an archive member named ``id_rsa``, ``credentials`` or
``config``, or a ``.gz`` member decompressed to a dotless name, was never handed
to detect-secrets while every ``settings.py`` beside it was. The scan is driven
in-process: ``_scan_in_worker`` is replaced by a recorder, so the paths the
worker would have been given are what the test reads.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
)

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("no_tool_probes")]


def _context(tmp_path: Path) -> PluginContext:
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    context.source_dir.mkdir(parents=True)
    context.work_dir.mkdir(parents=True)
    return context


def _write(root: Path, name: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("value = 1\n", encoding="utf-8")
    return path


def _record_worker(scanner, monkeypatch) -> dict:
    seen: dict = {}

    def recorded(self, **kwargs):
        seen.update(kwargs)
        return None

    monkeypatch.setattr(type(scanner), "_scan_in_worker", recorded)
    return seen


def test_dotless_converted_files_are_handed_to_detect_secrets(tmp_path, monkeypatch):
    context = _context(tmp_path)
    work = Path(context.work_dir)
    for name in (
        "bundle_zip/id_rsa",
        "bundle_zip/.aws/credentials",
        "bundle_zip/config",
        "bundle_zip/notes",
        "bundle_zip/settings.py",
    ):
        _write(work, name)
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())
    seen = _record_worker(scanner, monkeypatch)

    scanner.scan(target=work, target_type="converted")

    assert seen, "the worker was not reached"
    handed = sorted(
        Path(path).resolve().relative_to(work.resolve()).as_posix()
        for path in seen["scan_paths"]
    )
    assert handed == [
        "bundle_zip/.aws/credentials",
        "bundle_zip/config",
        "bundle_zip/id_rsa",
        "bundle_zip/notes",
        "bundle_zip/settings.py",
    ]


def test_directories_with_a_dot_in_their_name_are_not_scan_paths(tmp_path, monkeypatch):
    """Control for the enumeration: a directory is never a file to scan, however
    it is named, and the files below it are."""
    context = _context(tmp_path)
    work = Path(context.work_dir)
    _write(work, "archive.tar/inner")
    (work / "empty.d").mkdir()
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())
    seen = _record_worker(scanner, monkeypatch)

    scanner.scan(target=work, target_type="converted")

    handed = sorted(
        Path(path).resolve().relative_to(work.resolve()).as_posix()
        for path in seen["scan_paths"]
    )
    assert handed == ["archive.tar/inner"]
