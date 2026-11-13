# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A refusal built without a chain still says when the file had changed.

When a chain refuses on a value read from the environment, the failure is
rebuilt from a second resolution that reads nothing from it
(``_environment_blind_error``), so the refusal quotes no value. The caller raises
that error ``from None``, which drops the ``ConfigFileChangedError`` the second
resolution may have been raised from. ``config_file_changed`` follows only the
cause chain and a mark, so a base swapped while the second resolution ran was
reported as a plain failure.

The error now carries the fact on a mark, as a reworded base error does, and the
mark holds no path.

Red at the base: the error returned by the helper had no mark, so once raised
``from None`` it read as a plain failure. The control, a failure that is not a
changed file, stays a plain failure at both ends.
"""

from __future__ import annotations

import errno
from pathlib import Path
from typing import Any

import pytest

from automated_security_helper.config import config_sources
from automated_security_helper.config.config_sources import (
    ConfigFileChangedError,
    config_file_changed,
)
from automated_security_helper.core.exceptions import ASHConfigSourceError

pytestmark = pytest.mark.unit


def _literal_walk_raising(cause: BaseException) -> Any:
    """A stand-in for the second resolution that fails from ``cause``."""

    def walk(*args: Any, **kwargs: Any) -> Any:
        raise ASHConfigSourceError("the base could not be read") from cause

    return walk


def _raised_as_the_caller_raises_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cause: BaseException
) -> ASHConfigSourceError:
    monkeypatch.setattr(
        config_sources, "resolve_config_document", _literal_walk_raising(cause)
    )
    blind = config_sources._environment_blind_error(
        tmp_path / ".ash.yaml", tmp_path, None, ASHConfigSourceError("refused")
    )
    with pytest.raises(ASHConfigSourceError) as caught:
        raise blind from None
    return caught.value


def test_a_base_that_changed_during_the_second_resolution_is_still_a_changed_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raised = _raised_as_the_caller_raises_it(
        tmp_path,
        monkeypatch,
        ConfigFileChangedError(errno.ESTALE, "changed after it was checked"),
    )

    assert raised.__cause__ is None, "premise: the chain was cut"
    assert config_file_changed(raised)


def test_the_mark_that_says_the_file_changed_names_no_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raised = _raised_as_the_caller_raises_it(
        tmp_path,
        monkeypatch,
        ConfigFileChangedError(errno.ESTALE, "changed after it was checked"),
    )

    assert config_file_changed(raised)
    assert str(tmp_path) not in str(raised)


def test_a_plain_failure_of_the_second_resolution_stays_a_plain_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: a stale handle the file system reports is a plain OSError
    with the same errno, and is not taken for a swap."""
    raised = _raised_as_the_caller_raises_it(
        tmp_path, monkeypatch, OSError(errno.ESTALE, "stale file handle")
    )

    assert raised.__cause__ is None, "premise: the chain was cut"
    assert not config_file_changed(raised)
