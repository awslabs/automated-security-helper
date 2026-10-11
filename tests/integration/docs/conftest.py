# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The --docs-root option for the docs-example runner, and a header saying what ran.

Registered here, beside the tests that read it, so it exists when this directory is
named on the command line, which is how it is meant to be run:

    <code-tree>/.venv/bin/pytest <docs-tree>/tests/integration/docs \
        --run-integration --docs-root=<docs-tree>

As one word: before this option is registered, pytest reads a separate value as a test
path, and loads that tree's tests/conftest.py too, which fails on a duplicate option
when it is not the tree the tests come from.

The pages and fixtures come from <docs-tree>; ``ash`` and every python block run with
the ASH installed in the interpreter's environment.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def pytest_addoption(parser):
    parser.addoption(
        "--docs-root",
        default=None,
        help="run the examples of the docs in this checkout (default: this checkout)",
    )


def pytest_report_header(config):
    # The package a block's `ash` and python import, asked of a fresh interpreter in
    # isolated mode so the current directory cannot shadow the installed package.
    probe = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            "import os, automated_security_helper as m; print(os.path.dirname(m.__file__))",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    package = probe.stdout.strip() or f"not importable: {probe.stderr.strip()[-200:]}"
    docs_root = config.getoption("--docs-root") or Path(__file__).resolve().parents[3]
    return [
        f"docs examples: ASH package {package}",
        f"docs examples: docs root {docs_root}",
    ]
