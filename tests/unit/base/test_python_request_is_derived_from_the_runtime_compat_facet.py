# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``UVToolMixin._get_tool_python_request`` derives from the register's rows.

It used to return None unless a scanner overrode it with a per-scanner constant
(GuardDog's ``GUARDDOG_PYTHON_REQUEST``). Every consumer already reads that one
hook (the stored install command, the runner calls, the version probes, the
``ash dependencies install`` route), so deriving the default re-points all of
them at the facet rows at once. These tests pin the derivation itself on a
minimal class, then the two scanners that moved onto it.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.uv_tool_mixin import UVToolMixin
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_guarddog_plugins import (
    guarddog_scanner,
)
from automated_security_helper.plugin_modules.ash_guarddog_plugins.guarddog_scanner import (
    GuardDogScanner,
    GuardDogScannerConfig,
    GuardDogScannerConfigOptions,
)

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()


def _row(**changes) -> opsf.RuntimeCompatRow:
    base = {
        "runtime": opsf.RuntimeName.PYTHON,
        "tool_versions": "",
        "runtime_request": ">=3.10,<3.14",
        "resolution": opsf.CompatResolution.PIN,
        "reason": "a wheel gap; measured",
    }
    return opsf.RuntimeCompatRow(**{**base, **changes})


def _declaring(rows: tuple[opsf.RuntimeCompatRow, ...], constraint: str | None):
    """An instance of a class whose register row carries *rows*."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.zizmor_scanner import (
        ZizmorScanner,
    )

    facets = ZizmorScanner.operational_facets.model_copy(
        update={"runtime_compat": opsf.RuntimeCompatFacet(rows=rows)}
    )

    class Declaring:
        operational_facets = facets

        def _get_tool_version_constraint(self):
            return constraint

    return Declaring()


def _derive(instance) -> str | None:
    return UVToolMixin._get_tool_python_request(instance)


def test_a_scanner_without_a_register_row_derives_no_request() -> None:
    """A third-party plugin predating the register behaves as it always did."""

    class ThirdParty:
        def _get_tool_version_constraint(self):
            return None

    assert _derive(ThirdParty()) is None


def test_a_row_less_register_derives_no_request() -> None:
    assert _derive(_declaring((), None)) is None


def test_a_pin_row_derives_its_request() -> None:
    assert _derive(_declaring((_row(),), None)) == ">=3.10,<3.14"


def test_two_applicable_pin_rows_derive_one_combined_request() -> None:
    rows = (_row(), _row(runtime_request="!=3.12.*", reason="another gap"))
    assert _derive(_declaring(rows, None)) == ">=3.10,<3.14,!=3.12.*"


def test_an_exact_tool_pin_outside_the_row_range_drops_the_request() -> None:
    rows = (_row(tool_versions="<3.5"),)
    assert _derive(_declaring(rows, "==3.4.11")) == ">=3.10,<3.14"
    assert _derive(_declaring(rows, "==3.6.0")) is None


def test_a_polyfill_row_derives_no_interpreter_request() -> None:
    polyfill = _row(
        runtime_request=">=3.15",
        resolution=opsf.CompatResolution.POLYFILL,
        polyfill="checkov_json_array_hook",
        pin_insufficient="no older interpreter is installable",
    )
    assert _derive(_declaring((polyfill,), None)) is None


def test_a_plugin_override_still_answers_for_the_hooks_consumers() -> None:
    """The hook keeps its name and signature: an out-of-tree override wins."""

    class Overriding:
        def _get_tool_python_request(self):
            return ">=3.9"

    assert UVToolMixin._uv_python_kwargs(Overriding()) == {"python_request": ">=3.9"}


def _guarddog(tmp_path) -> GuardDogScanner:
    repo = tmp_path / "src"
    repo.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    return GuardDogScanner(
        context=PluginContext(
            source_dir=repo,
            output_dir=output,
            work_dir=output / "converted",
            config=AshConfig(),
        ),
        config=GuardDogScannerConfig(
            enabled=True, options=GuardDogScannerConfigOptions()
        ),
    )


def test_guarddog_derives_its_interpreter_request_from_its_compat_row(tmp_path) -> None:
    scanner = _guarddog(tmp_path)
    (row,) = GuardDogScanner.operational_facets.runtime_compat.rows
    assert scanner._get_tool_python_request() == row.runtime_request == ">=3.10,<3.14"
    assert scanner._uv_python_kwargs() == {"python_request": ">=3.10,<3.14"}


def test_guarddog_row_is_open_ended_because_its_upstream_gap_is_unsolved() -> None:
    """yara-python publishes no cp314 wheel and no upstream issue exists to
    cite, so the row is open-ended: a recheck_note stands in the issue URL's
    place, and the row records the default tool constraint it was written
    against, which the consistency gate's re-check compares at a guarddog
    bump. The interpreter pin stays the resolution."""
    (row,) = GuardDogScanner.operational_facets.runtime_compat.rows
    assert row.open_ended
    assert row.upstream_issue is None
    assert row.recheck_note is not None and row.recheck_note.strip()
    assert (
        row.recorded_default_constraint
        == guarddog_scanner.GUARDDOG_DEFAULT_VERSION_CONSTRAINT
    )
    assert row.resolution is opsf.CompatResolution.PIN


def test_the_stored_install_command_carries_the_derived_python_request(
    tmp_path,
) -> None:
    (command,) = _guarddog(tmp_path).uv_tool_install_commands
    parts = command.split()
    assert parts[:5] == ["uv", "tool", "install", "--python", ">=3.10,<3.14"]


def test_no_per_scanner_constant_or_override_is_left() -> None:
    assert not hasattr(guarddog_scanner, "GUARDDOG_PYTHON_REQUEST")
    assert "_get_tool_python_request" not in vars(GuardDogScanner)
