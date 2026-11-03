# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A --results refusal names the path as the operator typed it.

The refusal built its text from the ``Path`` object, which spells the operator's
text in the host's own way: on Windows every ``/`` the operator gave came back as
``\\``, and on every host a trailing separator was dropped. The test pinning
"printed as given" went red on the Windows runners for exactly that. The text of
the argument is what is shown.
"""

from __future__ import annotations

import os

import pytest

from automated_security_helper.cli.merge import ResultsPathError, resolve_results_file

pytestmark = pytest.mark.unit


def test_a_missing_path_is_named_with_the_separator_the_operator_typed(tmp_path):
    typed = f"{tmp_path.as_posix()}/no/such/"

    with pytest.raises(ResultsPathError) as excinfo:
        resolve_results_file(typed)

    assert typed in str(excinfo.value), str(excinfo.value)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs a named pipe")
def test_a_path_that_is_neither_file_nor_directory_is_named_as_typed(tmp_path):
    (tmp_path / "pipes").mkdir()
    os.mkfifo(tmp_path / "pipes" / "a-pipe")
    typed = f"{tmp_path.as_posix()}/pipes//a-pipe"

    with pytest.raises(ResultsPathError) as excinfo:
        resolve_results_file(typed)

    assert typed in str(excinfo.value), str(excinfo.value)
