# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The integration marker's registered description states the tier rule.

``pytest --markers`` is where a contributor reads what a tier means. The e2e line
tests/conftest.py registers states its rule (the product run as an operator would, against
real tools); the integration line said only "component interactions", which does not say
what makes a test integration. The rule the tier contract classes by
(tests/NAMING_CONVENTIONS.md) is a process started, a socket opened, or git run on any
path, and the description names it.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.unit


def test_the_integration_marker_description_names_the_process_rule(pytestconfig):
    # pytest.ini registers the marker too, with its own text, so the ini value holds one
    # line per registration; the conftest's is the one that states the rule.
    lines = [
        line
        for line in pytestconfig.getini("markers")
        if line.startswith("integration:")
    ]
    assert lines, pytestconfig.getini("markers")
    stating = [
        line
        for line in lines
        if "process" in line and "socket" in line and "git" in line
    ]
    assert stating, lines
