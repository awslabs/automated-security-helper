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
from tests.utils.stand_ins import write_stand_in

pytestmark = pytest.mark.unit


def _marker_program(directory, name, marker):
    """A program named ``name`` that creates ``marker`` if it is ever started.

    In the form the host starts (``tests/utils/stand_ins.py``): the script on POSIX,
    a ``<name>.bat`` launcher for it on Windows, where a shebang script is no
    program and so no binary to force. The path returned is the file a start names.
    """
    directory.mkdir(exist_ok=True)
    source = f"open({str(marker)!r}, 'w').close()\n"
    return write_stand_in(directory, name, source).files[-1]


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
    return _marker_program(tmp_path / "tools", "stub-tool", marker), marker


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


def test_an_overriding_scanner_reads_the_record_before_any_lookup(
    tmp_path, own_home, monkeypatch, scanner
):
    """checkov overrides ``validate_plugin_dependencies`` without chaining, the
    shape most scanners share -- the record read must still run first.

    ``__pydantic_init_subclass__`` wraps every override with the record read, so
    the promise "the forced path is resolved before any PATH or uv lookup" holds
    for the overriding scanners too. The witness: checkov's own validation body is
    replaced with one that raises, so ANY route into its PATH/uv probing fails
    this test; with the record present the wrapped entry point answers True
    without reaching it, and without a record the scanner's own route still runs.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        checkov_scanner,
    )

    binary = _marker_program(
        tmp_path / "tools-checkov", "checkov", tmp_path / "CHECKOV-WAS-RUN"
    )
    record_forced_binaries(
        [
            ForcedBinary(
                scanner_key="checkov",
                path=binary,
                sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
            )
        ]
    )

    checkov = checkov_scanner.CheckovScanner(
        config=checkov_scanner.CheckovScannerConfig(), context=scanner.context
    )

    def own_route_reached(self):
        raise AssertionError("checkov's PATH/uv probing ran before the record read")

    # The wrapper closed over the original override at class creation, so the
    # trap is planted where the wrapper calls back into the scanner's own route:
    # the first thing checkov's override does.
    monkeypatch.setattr(
        checkov_scanner.CheckovScanner,
        "resolve_deferred_tool_version",
        own_route_reached,
    )

    assert checkov.validate_plugin_dependencies() is True

    # Control: with no record for checkov, the scanner's own route is reached.
    record_forced_binaries([], erase=["checkov"])
    with pytest.raises(AssertionError, match="before the record read"):
        checkov.validate_plugin_dependencies()


def test_a_precluded_reason_keeps_the_force_out(tmp_path, own_home, off_path, scanner):
    """A scanner whose check answers more than binary presence names the gate in
    ``_forced_binary_precluded_reason`` and the force never outvotes it (npm-audit
    offline is the measured fail-open: ``npm audit --offline`` prints a clean
    audit, so a bypass is a silent false clean)."""
    binary, marker = _forced_file(tmp_path)
    _record(binary)

    class GatedScanner(type(scanner)):
        def _forced_binary_precluded_reason(self):
            return "a semantic gate the force may not outvote"

        def validate_plugin_dependencies(self) -> bool:
            return False  # its own route refuses in this harness

    gated = GatedScanner(config=StubConfig(), context=scanner.context)
    assert gated.validate_plugin_dependencies() is False
    assert not marker.exists()


def test_the_record_is_read_under_the_name_the_installer_writes(
    tmp_path, own_home, off_path, scanner
):
    """The installer keys a record by the config's name, falling back to the
    plugin class name when the config carries none (``ash dependencies install``
    builds ``plugin_name = config.name or plugin_class.__name__``). The reader
    makes the same fallback, so a record written under the class name is found
    rather than looked up under the empty string."""
    binary, _marker = _forced_file(tmp_path)
    record_forced_binaries(
        [
            ForcedBinary(
                scanner_key=type(scanner).__name__,
                path=binary,
                sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
            )
        ]
    )
    object.__setattr__(scanner.config, "name", None)

    assert scanner._forced_binary_satisfies() is True
