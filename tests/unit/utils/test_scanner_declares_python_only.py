# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``scanner_declares_python_only``: what a loaded scanner class says of itself.

A Python-only run leaves out every scanner whose ``is_python_only`` is False, and a
scanner class that states ``python_only`` answers with it. A plugin that runs before
the scan phase has no scanner instance to ask, so it reads the class's statement.
"""

import importlib

import pytest

pytestmark = pytest.mark.unit


def test_grype_and_trivy_say_they_are_not_python_only() -> None:
    for module in ("grype_scanner", "trivy_scanner"):
        importlib.import_module(
            f"automated_security_helper.plugin_modules.ash_builtin.scanners.{module}"
        )
    from automated_security_helper.utils.scanner_tool_types import (
        scanner_declares_python_only,
    )

    assert scanner_declares_python_only("grype") is False
    assert scanner_declares_python_only("trivy") is False


def test_a_name_no_loaded_scanner_has_answers_none() -> None:
    from automated_security_helper.utils.scanner_tool_types import (
        scanner_declares_python_only,
    )

    assert scanner_declares_python_only("no-such-scanner") is None
    assert scanner_declares_python_only("") is None
