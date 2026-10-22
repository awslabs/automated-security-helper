# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which config file read marks its failure with the file's path.

The scan gate names the file that was being read when a load failed from a
note the chain walk puts on the error (``config_file_being_read``). Only the
root read carries it: a base's failures are worded by the walk itself, so a
base's read marks nothing, and a base the environment chose never has its path
put on an exception.

A caller's own reader must hand in the ``texts`` cache it fills
(``resolve_config_document`` refuses a reader without one), so the cells use
the reader shape the in-tree callers use: it reads and keeps each file's text,
parses it, and fails on the file a cell names. The failure is then the
reader's own, and the cells show what each read marked it with.

A base's failure leaves the walk wrapped in a chain error (the failure of a
base read is not one the base branch words), so the base cell reads the mark
on the error's cause, the reader's own exception.
"""

from pathlib import Path

import pytest

from automated_security_helper.config.config_sources import (
    config_file_being_read,
    parse_config_text,
    read_config_text,
    resolve_config_document,
)
from automated_security_helper.core.exceptions import ASHConfigSourceError


def _chain(tmp_path: Path):
    top = tmp_path / "top.yaml"
    base = tmp_path / "base.yaml"
    top.write_text("extends: base.yaml\n", encoding="utf-8")
    base.write_text("project_name: base\n", encoding="utf-8")
    return top, base


def _reader_failing_on(failing: Path, error: BaseException, texts: dict):
    """A caller's reader that keeps each file's text in *texts* and parses it,
    and raises *error* when it is asked for *failing*."""

    def read(path: Path):
        resolved = Path(path).resolve()
        if resolved == failing.resolve():
            raise error
        text = read_config_text(path)
        texts[resolved] = text
        return parse_config_text(path, text)

    return read


def test_a_failure_of_a_base_read_carries_no_file_note(tmp_path):
    top, base = _chain(tmp_path)
    texts: dict = {}
    failure = TypeError("the reader's own")

    with pytest.raises(ASHConfigSourceError) as raised:
        resolve_config_document(
            top,
            confine_to=tmp_path,
            reader=_reader_failing_on(base, failure, texts),
            texts=texts,
        )

    assert raised.value.__cause__ is failure, raised.value
    assert config_file_being_read(failure) is None
    assert config_file_being_read(raised.value) is None


def test_a_failure_of_the_root_read_carries_the_root_file(tmp_path):
    top, _base = _chain(tmp_path)
    texts: dict = {}

    with pytest.raises(RecursionError) as raised:
        resolve_config_document(
            top,
            confine_to=tmp_path,
            reader=_reader_failing_on(top, RecursionError(), texts),
            texts=texts,
        )

    assert config_file_being_read(raised.value) == top
