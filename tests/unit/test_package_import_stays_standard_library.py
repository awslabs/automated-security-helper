# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Importing the package reads no version, so a standard-library-only module stays one.

The package __init__ imported utils/version_management, which on Python 3.10
imports tomli, so `python -m automated_security_helper.utils.content_databases`,
written to run on the standard library alone, depended on a third-party
package through the package import. __version__ is read on first use.
"""

from __future__ import annotations

import subprocess
import sys

import pytest

import automated_security_helper

pytestmark = pytest.mark.unit


def test_version_is_still_the_packages():
    from automated_security_helper.utils.version_management import get_version

    assert automated_security_helper.__version__ == get_version()


def test_an_unknown_attribute_is_still_an_attribute_error():
    with pytest.raises(AttributeError):
        automated_security_helper.no_such_name  # noqa: B018


def test_importing_the_package_does_not_import_the_version_reader():
    code = (
        "import sys, automated_security_helper.utils.content_databases\n"
        "print('automated_security_helper.utils.version_management' in sys.modules,"
        " any(name == 'tomli' or name.startswith('tomli.') for name in sys.modules))"
    )

    completed = subprocess.run(
        [sys.executable, "-I", "-c", code], capture_output=True, text=True, check=False
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.split() == ["False", "False"], completed.stdout
