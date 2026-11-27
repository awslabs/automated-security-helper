# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The image submission options delegate to the express daemon as scans do.

An image scan under express is the same scan warm: the forked child is the cold
run and parses the real command line. The client's classification can only err
toward the cold run, so each new option needs a row that it is still read as a
scan, and the lookalike control that a value spelled like another subcommand
still sends the invocation cold.
"""

from __future__ import annotations

import pytest

from automated_security_helper.express.client import is_scan_invocation

pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    "argv",
    [
        ["scan", "--image", "registry.example.com/team/app:1.2.3"],
        ["scan", "--image=registry.example.com/team/app@sha256:" + "ab" * 32],
        ["scan", "--image-archive", "/tmp/app.tar"],
        ["scan", "--image-layout", "/tmp/app-layout"],
        ["--image", "alpine:3.20"],
        ["--image-archive=/tmp/app.tar", "--output-dir", "/tmp/out"],
    ],
)
def test_an_image_submission_is_a_scan_invocation(argv):
    assert is_scan_invocation(argv)


@pytest.mark.parametrize("value", ["results", "container", "config"])
def test_a_bare_invocation_whose_image_value_spells_a_subcommand_runs_cold(value):
    assert not is_scan_invocation(["--image", value])


def test_a_scan_subcommand_keeps_an_image_value_that_spells_a_subcommand():
    assert is_scan_invocation(["scan", "--image", "results"])


def test_no_express_wins_over_an_image_option():
    assert not is_scan_invocation(["scan", "--image", "alpine:3", "--no-express"])
