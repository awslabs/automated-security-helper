# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan entry redacts its error message with the values it was registered with.

The runner's failure arms each redacted their own text before closing the
entry, so an arm that forgot the parameter recorded the raw text: the
registry applied whatever error_message it was given, and a closing built
from a bare exception's text put a value the run's configuration read from
the environment into the entry a client polls. The redaction set is now
attached to the entry at registration, and the registry redacts every
error message it applies -- finish_scan and update_scan_status both --
so a forgetful arm is backstopped at the one sink they share.

The attached values are what must not be shown, so they are no part of the
entry's dictionary: ``to_dict`` is an explicit allowlist, and these cells
hold it to that.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)

pytestmark = pytest.mark.unit

SECRET = "a-value-read-from-the-environment"


@pytest.fixture
def registered(tmp_path: Path):
    """A registry and a scan registered with one environment value attached."""
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(tmp_path),
        output_directory=str(tmp_path / ".ash" / "ash_output"),
        environment_values=(SECRET,),
    )
    return registry, scan_id


def test_finish_scan_hides_a_registered_environment_value(registered):
    registry, scan_id = registered
    registry.finish_scan(
        scan_id, MCScanStatus.FAILED, error_message=f"the run broke: {SECRET}"
    )
    entry = registry.get_scan(scan_id)
    message = entry.error_message or ""
    assert "the run broke: " in message, message
    assert SECRET not in message, message


def test_update_scan_status_hides_a_registered_environment_value(registered):
    registry, scan_id = registered
    registry.update_scan_status(
        scan_id, MCScanStatus.FAILED, error_message=f"gave up at {SECRET} today"
    )
    entry = registry.get_scan(scan_id)
    message = entry.error_message or ""
    assert "gave up at " in message, message
    assert SECRET not in message, message


def test_the_entrys_dictionary_carries_no_registered_value(registered):
    """The attached values exist to be hidden, so no listing shows them: not
    as a field of their own, and not inside any field's text."""
    registry, scan_id = registered
    registry.finish_scan(
        scan_id, MCScanStatus.FAILED, error_message=f"the run broke: {SECRET}"
    )
    for shown in (registry.get_scan(scan_id).to_dict(), *registry.list_scans()):
        assert "environment_values" not in shown, sorted(shown)
        assert SECRET not in repr(shown), sorted(shown)


def test_an_entry_registered_without_values_keeps_its_message(tmp_path):
    """The control: with nothing attached, the message is applied as given --
    the backstop redacts with the registered values only, never guesses."""
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(tmp_path),
        output_directory=str(tmp_path / ".ash" / "ash_output"),
    )
    registry.finish_scan(
        scan_id, MCScanStatus.FAILED, error_message=f"the run broke: {SECRET}"
    )
    entry = registry.get_scan(scan_id)
    assert entry.error_message == f"the run broke: {SECRET}", entry.error_message
