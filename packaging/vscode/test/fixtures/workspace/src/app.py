# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Fixture source for the extension's diagnostics test.

Nothing here is imported or executed. It exists so the SARIF fixture next to it
points at real lines in a real file: a diagnostic whose range falls outside the
document is clamped by the editor, which would let an off-by-one in the 1-based
to 0-based line conversion pass unnoticed.

The line numbers referenced by test/fixtures/ash.sarif are load-bearing. Adding
or removing a line above one of them moves the finding and fails the suite,
which is the intended coupling -- the whole point of the assertion is that a
stated line arrives at that line.
"""

import os
import subprocess


def run_report(target):
    """The next line, 23, is the fixture's error-level finding."""
    return subprocess.check_output(f"generate-report {target}", shell=True)


def connection_string():
    """The next line, 28, is the fixture's warning-level finding."""
    return os.environ.get("DB_DSN", "postgresql://svc:hunter2@localhost/app")


def cache_directory():
    """The next line, 33, is the fixture's note-level finding."""
    return "/tmp/report-cache"
