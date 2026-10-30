# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ASHConfigUnsetVariableError`` survives a copy and a pickle round trip.

``BaseException`` rebuilds an exception as ``cls(*args)``. The error's ``variable``
is required and keyword-only, so ``copy.copy``, ``copy.deepcopy`` and pickle (an
error handed back from a worker process) failed with a TypeError.
"""

from __future__ import annotations

import copy
import pickle
from pathlib import Path

import pytest

from automated_security_helper.core.exceptions import (
    ASHConfigSourceError,
    ASHConfigUnsetVariableError,
)

pytestmark = pytest.mark.unit


def _error() -> ASHConfigUnsetVariableError:
    error = ASHConfigUnsetVariableError(
        "ASH_TOKEN_VALUE is not set",
        variable="ASH_TOKEN_VALUE",
        config_file=Path("repo") / ".ash" / ".ash.yaml",
        detail="the reference is not set",
    )
    error.ash_config_file = Path("repo") / ".ash" / ".ash.yaml"
    return error


def _round_trips():
    return {
        "pickle": lambda error: pickle.loads(pickle.dumps(error)),
        "copy": copy.copy,
        "deepcopy": copy.deepcopy,
    }


@pytest.mark.parametrize("how", sorted(_round_trips()))
def test_the_error_is_rebuilt_with_everything_it_carried(how):
    original = _error()

    clone = _round_trips()[how](original)

    assert type(clone) is ASHConfigUnsetVariableError
    assert clone is not original
    assert str(clone) == "ASH_TOKEN_VALUE is not set"
    assert clone.variable == "ASH_TOKEN_VALUE"
    assert clone.config_file == original.config_file
    assert clone.detail == "the reference is not set"
    assert clone.ash_config_file == original.ash_config_file


@pytest.mark.parametrize("how", sorted(_round_trips()))
def test_a_rebuilt_error_is_still_a_config_source_error(how):
    clone = _round_trips()[how](_error())

    assert isinstance(clone, ASHConfigSourceError)
    assert isinstance(clone, ValueError)


def test_an_error_built_without_a_file_or_detail_round_trips():
    original = ASHConfigUnsetVariableError("VAR is not set", variable="VAR")

    clone = pickle.loads(pickle.dumps(original))

    assert clone.variable == "VAR"
    assert clone.config_file is None
    assert clone.detail == "VAR is not set"
