# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scanners' dependency validation reads the ``--binary-path`` record.

``ash dependencies install --binary-path <scanner>=<path>`` records the forced
path "for dependency validation"; this is the validation that reads it. The file
is judged afresh -- a regular, executable, non-symlink file whose bytes hash to
the recorded SHA-256 -- and never executed; no record, or one whose file went
stale, falls through to the PATH probe unchanged.
"""

from __future__ import annotations

import hashlib
from typing import ClassVar, Literal

import pytest

from automated_security_helper.base import scanner_plugin as scanner_plugin_module
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.utils.install_providers import (
    ForcedBinary,
    record_forced_binaries,
)

pytestmark = pytest.mark.unit


class StubConfig(ScannerPluginConfigBase):
    name: Literal["stub"] = "stub"


@pytest.fixture
def own_home(tmp_path, monkeypatch):
    """A home of the test's own, so the record and receipts stay out of the real one."""
    home = tmp_path / "record-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    return home


@pytest.fixture
def off_path(monkeypatch):
    """The scanner's command is nowhere on PATH, so only the record can satisfy it."""
    monkeypatch.setattr(
        scanner_plugin_module, "find_executable", lambda *_a, **_k: None
    )


@pytest.fixture
def scanner(tmp_path):
    """A concrete scanner that keeps the BASE dependency check (no override)."""
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    work_dir = output_dir / ASH_WORK_DIR_NAME
    work_dir.mkdir()
    context = PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=AshConfig(project_name="test"),
    )

    class BaseValidatedScanner(ScannerPluginBase):
        offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

        def model_post_init(self, context):
            self.command = "stub-tool"
            self.tool_type = ScannerToolType.SAST
            super().model_post_init(context)

        def _execute_scan(self, target, target_type, global_ignore_paths):
            raise NotImplementedError

    return BaseValidatedScanner(config=StubConfig(), context=context)


def _forced_file(tmp_path):
    marker = tmp_path / "FORCED-BINARY-WAS-RUN"
    tools = tmp_path / "tools"
    tools.mkdir(exist_ok=True)
    binary = tools / "stub-tool"
    binary.write_text(f"#!/bin/sh\ntouch {marker}\n")
    binary.chmod(0o755)
    return binary, marker


def _record(binary):
    record_forced_binaries(
        [
            ForcedBinary(
                scanner_key="stub",
                path=binary,
                sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
            )
        ]
    )


def test_a_recorded_forced_binary_satisfies_the_check_off_path(
    tmp_path, own_home, off_path, scanner
):
    binary, marker = _forced_file(tmp_path)
    assert scanner.validate_plugin_dependencies() is False  # control: no record yet

    _record(binary)

    assert scanner.validate_plugin_dependencies() is True
    assert not marker.exists(), "the forced binary was executed"


def test_a_stale_record_falls_through_to_the_path_probe(
    tmp_path, own_home, off_path, scanner
):
    binary, marker = _forced_file(tmp_path)
    _record(binary)
    # Same path, same mode, other content: no longer the validated binary.
    binary.write_text("#!/bin/sh\necho replaced\n")
    binary.chmod(0o755)

    assert scanner.validate_plugin_dependencies() is False
    assert not marker.exists()
