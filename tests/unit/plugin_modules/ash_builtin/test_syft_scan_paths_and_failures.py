# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the syft scanner passes, warns about and raises, per target.

- A blank ``config_file`` was joined to the source directory, which exists, and
  judged a configured file (refused, with no refusal line to point at).
- The missing-config and refused-config warnings were given on every ``scan()``,
  since ``_process_config_options`` runs again on each; once is enough.
- ``--base-path`` was the source directory for every target, so a converted
  target under an output directory outside the source tree had its paths spelled
  from a directory the scan is not under.
- A results file that is not CycloneDX was returned as the raw dict, which the
  executor cannot grade; it raises, naming the validation error count only.
- The catch-all error was not redacted, and a scan that raised left the previous
  target's end time in place.
- ``python -m`` on the module constructed the scanner with arguments it does not
  take; ``_demo_main`` builds the context the executor would.
- The tool lines were not reset per target, and an empty target kept the previous
  target's start time.

The blank-config and warned-once tests read the argv and the warnings of real
``scan()`` runs, not the arguments at construction or direct option re-reads: a
fix that dropped ``--config`` altogether, or a warning that repeated per scan,
would otherwise have passed them.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
    SyftScanner,
    SyftScannerConfig,
    SyftScannerConfigOptions,
    _demo_main,
)

pytestmark = pytest.mark.unit

MINIMAL_SBOM = {"bomFormat": "CycloneDX", "specVersion": "1.6"}


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    monkeypatch.setenv("ASH_OFFLINE", "YES")


def _context(tmp_path: Path, output: Path | None = None) -> PluginContext:
    output = output or tmp_path / "out"
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=output,
        work_dir=output / "converted",
        config=get_default_config(),
    )
    for path in (context.source_dir, context.output_dir, context.work_dir):
        path.mkdir(parents=True, exist_ok=True)
    (context.source_dir / "requirements.txt").write_text("requests==2.19.0\n")
    (context.work_dir / "requirements.txt").write_text("requests==2.19.0\n")
    return context


def _scanner(context: PluginContext, **options) -> SyftScanner:
    scanner = SyftScanner(
        context=context,
        config=SyftScannerConfig(options=SyftScannerConfigOptions(**options)),
    )
    scanner.dependencies_satisfied = True
    return scanner


def _scan_with(
    scanner: SyftScanner,
    response: dict,
    document: dict | None,
    *,
    target: Path | None = None,
    target_type: str = "source",
    commands: list | None = None,
):
    def run(command, **kwargs):
        if commands is not None:
            commands.append([str(part) for part in command])
        if document is not None:
            (value,) = [a for a in command if str(a).startswith("cyclonedx-json=")]
            destination = Path(str(value).split("=", 1)[1])
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(json.dumps(document))
        return response

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_run_subprocess", side_effect=run),
    ):
        return scanner.scan(
            target=target if target is not None else Path(scanner.context.source_dir),
            target_type=target_type,
        )


def _flag_value(command: list[str], flag: str) -> str:
    for index, token in enumerate(command):
        if token.startswith(f"{flag}="):
            return token.split("=", 1)[1]
        if token == flag and index + 1 < len(command):
            return command[index + 1]
    raise AssertionError(f"{flag} not in {command}")


# --- the configured path ------------------------------------------------------------


def test_a_blank_config_file_names_no_file(tmp_path, caplog):
    """Read from the argv syft gets: a fix that dropped ``--config`` altogether
    would pass a check of what is absent, and syft would then read a .syft.yaml
    from the scanned source. One ``--config``, naming a file outside the source."""
    with caplog.at_level(logging.WARNING):
        scanner = _scanner(_context(tmp_path), config_file="  ")

    assert "Configured syft config file" not in caplog.text
    commands: list[list[str]] = []
    _scan_with(scanner, {"returncode": 0}, MINIMAL_SBOM, commands=commands)
    (command,) = commands
    assert command.count("--config") == 1, command
    named = Path(_flag_value(command, "--config")).resolve()
    assert not named.is_relative_to(Path(scanner.context.source_dir).resolve())


def test_a_missing_config_file_is_warned_about_once(tmp_path, caplog):
    """``scan()`` runs ``_process_config_options`` again for every target, so the
    real path is two scans, source then converted, and one line between them."""
    missing = tmp_path / "operator" / "syft.yaml"
    context = _context(tmp_path)

    with caplog.at_level(logging.WARNING):
        scanner = _scanner(context, config_file=str(missing))
        _scan_with(scanner, {"returncode": 0}, MINIMAL_SBOM)
        _scan_with(
            scanner,
            {"returncode": 0},
            MINIMAL_SBOM,
            target=Path(context.work_dir),
            target_type="converted",
        )

    given = [m for m in caplog.messages if "does not exist" in m]
    assert len(given) == 1, caplog.messages


# --- the base path --------------------------------------------------------------------


def test_the_base_path_is_the_source_directory_for_a_target_inside_it(tmp_path):
    context = _context(tmp_path)
    scanner = _scanner(context)
    source = Path(os.path.abspath(context.source_dir))

    assert scanner._base_path(Path(context.source_dir)) == source
    assert scanner._base_path(Path(context.source_dir) / "sub") == source


@pytest.mark.parametrize("name", ["elsewhere", "src-other"])
def test_the_base_path_is_the_target_for_a_target_outside_the_source(tmp_path, name):
    """``src-other`` is outside the tree but string-prefixed by ``src``, the case a
    ``startswith`` containment check gets wrong."""
    context = _context(tmp_path)
    scanner = _scanner(context)
    outside = tmp_path / name

    assert scanner._base_path(outside) == Path(os.path.abspath(outside))


def test_a_converted_target_outside_the_source_tree_is_its_own_base_path(tmp_path):
    """``--output-dir`` outside the repository: the converted target lives there,
    and syft would otherwise spell its paths from the source directory."""
    context = _context(tmp_path, output=tmp_path / "elsewhere-out")
    scanner = _scanner(context)
    commands: list[list[str]] = []

    _scan_with(
        scanner,
        {"returncode": 0},
        MINIMAL_SBOM,
        target=Path(context.work_dir),
        target_type="converted",
        commands=commands,
    )

    (command,) = commands
    assert (
        _flag_value(command, "--base-path")
        == Path(os.path.abspath(context.work_dir)).as_posix()
    )


def test_control_the_source_target_keeps_the_source_directory_as_base_path(tmp_path):
    context = _context(tmp_path)
    scanner = _scanner(context)
    commands: list[list[str]] = []

    _scan_with(scanner, {"returncode": 0}, MINIMAL_SBOM, commands=commands)

    (command,) = commands
    assert (
        _flag_value(command, "--base-path")
        == Path(os.path.abspath(context.source_dir)).as_posix()
    )


# --- failures -------------------------------------------------------------------------


def test_a_results_file_that_is_not_cyclonedx_raises_instead_of_returning_it(tmp_path):
    scanner = _scanner(_context(tmp_path))
    document = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": "nope"}

    with pytest.raises(ScannerError) as raised:
        _scan_with(scanner, {"returncode": 0}, document)

    message = str(raised.value)
    assert "CycloneDX" in message
    assert "validation error" in message
    assert "nope" not in message


def test_the_catch_all_error_is_redacted_and_records_this_runs_end_time(tmp_path):
    scanner = _scanner(_context(tmp_path))
    scanner.end_time = None

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_values_to_redact", return_value=("zz-secret-value",)),
        patch.object(
            scanner,
            "_resolve_arguments",
            side_effect=RuntimeError("cannot read zz-secret-value here"),
        ),
    ):
        with pytest.raises(ScannerError) as raised:
            scanner.scan(target=Path(scanner.context.source_dir), target_type="source")

    assert "scan failed" in str(raised.value)
    assert "zz-secret-value" not in str(raised.value)
    assert scanner.end_time is not None


# --- per-target state -----------------------------------------------------------------


def test_the_tool_lines_are_reset_per_target(tmp_path):
    scanner = _scanner(_context(tmp_path))
    scanner.errors = ["stderr of the previous target"]
    scanner.output = ["stdout of the previous target"]

    _scan_with(scanner, {"returncode": 0}, MINIMAL_SBOM)

    assert scanner.errors == []
    assert scanner.output == []


def test_an_empty_target_does_not_keep_the_previous_targets_start_time(tmp_path):
    scanner = _scanner(_context(tmp_path))
    scanner.start_time = datetime.now(timezone.utc)
    empty = tmp_path / "empty"
    empty.mkdir()

    with patch.object(scanner, "_post_scan"):
        assert scanner.scan(target=empty, target_type="converted") is True

    assert scanner.start_time is None


# --- python -m ------------------------------------------------------------------------


def test_the_module_entry_point_builds_the_executors_context_and_writes_the_result(
    tmp_path, monkeypatch
):
    """The context the stubbed ``scan`` saw is the one the executor would build:
    the source and output directories as given, and the work directory derived
    from the output directory. A result that is not a report is written as JSON,
    the function's documented shape."""
    source = tmp_path / "src"
    source.mkdir()
    (source / "requirements.txt").write_text("requests==2.19.0\n")
    output = tmp_path / "out"
    seen: dict = {}

    def scan(self, **kwargs):
        seen["context"] = self.context
        seen["kwargs"] = kwargs
        return True

    monkeypatch.setattr(SyftScanner, "scan", scan)

    written = _demo_main(source, output)

    context = seen["context"]
    assert os.path.realpath(context.source_dir) == os.path.realpath(source)
    assert os.path.realpath(context.output_dir) == os.path.realpath(output)
    assert os.path.realpath(context.work_dir) == os.path.realpath(
        output / ASH_WORK_DIR_NAME
    )
    assert seen["kwargs"] == {"target": source, "target_type": "source"}
    assert written == output / "syft.cdx.json"
    assert json.loads(written.read_text()) is True
