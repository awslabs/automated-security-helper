# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The docs tests' own pytest configuration.

These tests also run inside a checkout whose tests/unit/conftest.py checks what
each child process starts, and admits a program a test starts on purpose only
through the ``allow_real_program`` marker. This tree registers the marker too, so
a run of the docs tests alone neither warns on it nor, under ``--strict-markers``,
fails collection; registering it twice is harmless where that conftest is loaded.
"""


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "allow_real_program(program, *, where, args=(), contained=None, reason): "
        "the test starts this program on purpose; a checkout whose test "
        "configuration checks child-process starts reads it, and here it only "
        "names the start for the reader",
    )
