# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scanner base decides whether a target is empty, and a directory it cannot
list is not empty.

``ScannerPluginBase.scan`` skipped a target that is missing or an empty
directory. It listed the directory with a bare ``any(target.iterdir())``, so a
directory the process could not list raised ``PermissionError`` out of
``scan()``, before the error handling that names a failed scan began. Four
scanners that override ``scan()`` (syft, ferret, snyk-code, trivy-repo) each
carried a module-level copy of the same probe, with the ``OSError`` handling the
template lacked. The probe is one base method now, ``_target_is_empty``, which
``scan()`` calls: an unlistable directory is left to the tool, which says why it
cannot read it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from tests.unit.base.scanner_support import (
    build_scanner,
    execute_writing,
    populated_target,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def unlistable(tmp_path, monkeypatch):
    """A directory whose listing is refused, without changing any real mode."""
    target = tmp_path / "locked"
    target.mkdir()
    (target / "app.py").write_text("x = 1\n")
    real_iterdir = Path.iterdir

    def _refused(self):
        if self == target:
            raise PermissionError(13, "Permission denied", str(self))
        return real_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", _refused)
    return target


def test_a_missing_target_is_empty(tmp_path):
    assert ScannerPluginBase._target_is_empty(tmp_path / "nothing-here") is True


def test_an_empty_directory_is_empty(tmp_path):
    (tmp_path / "bare").mkdir()

    assert ScannerPluginBase._target_is_empty(tmp_path / "bare") is True


def test_a_directory_with_a_file_is_not_empty(tmp_path):
    assert ScannerPluginBase._target_is_empty(populated_target(tmp_path)) is False


def test_a_file_target_is_not_empty(tmp_path):
    target = tmp_path / "one.py"
    target.write_text("x = 1\n")

    assert ScannerPluginBase._target_is_empty(target) is False


def test_a_directory_that_cannot_be_listed_is_not_empty(unlistable):
    assert ScannerPluginBase._target_is_empty(unlistable) is False


class _Reached(Exception):
    pass


def test_scan_hands_an_unlistable_directory_to_the_scanner(
    plugin_context, unlistable, monkeypatch
):
    """scan() does not raise the listing error: it goes on to its preamble, the
    step after the empty-target skip."""
    scanner = build_scanner(plugin_context, execute_scan=execute_writing(None))

    def _preamble(self, **_kwargs):
        raise _Reached

    monkeypatch.setattr(type(scanner), "_pre_scan", _preamble)

    with pytest.raises(_Reached):
        scanner.scan(target=unlistable, target_type="source")


def test_scan_skips_a_missing_target_before_its_preamble(
    plugin_context, tmp_path, monkeypatch
):
    """The control: a missing target returns before the preamble."""
    scanner = build_scanner(plugin_context, execute_scan=execute_writing(None))

    def _preamble(self, **_kwargs):
        raise _Reached

    monkeypatch.setattr(type(scanner), "_pre_scan", _preamble)

    assert scanner.scan(target=tmp_path / "nothing-here", target_type="source")
