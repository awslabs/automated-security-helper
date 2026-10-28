# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The refusal for an unreadable ASH_CONFIG file says what it should say.

``default_config_document_for_tree`` reads the file ASH_CONFIG names. When the
read fails with an OSError the refusal is built around the file's described
path, so the OSError's own copy of that path is dropped
(``os_error_without_named_file``): the operator reads the file once, followed
by the errno and its text. The exit-code cells beside this one assert only that
the refusal exists; these cells pin the words, so an error text that repeats
the path, or one that adds something to it, goes red.
"""

import errno
import os

import pytest

from automated_security_helper.config.config_sources import describe_config_path
from automated_security_helper.config.default_config import (
    default_config_document_for_tree,
)
from automated_security_helper.core.exceptions import ASHConfigValidationError
from tests.utils.helpers import mark_git_checkout


def _skip_unless_permission_bits_hold():
    if os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0):
        pytest.skip("needs POSIX permission bits, which root reads past")


def _refusal_for_an_unreadable_ash_config(tmp_path, monkeypatch):
    _skip_unless_permission_bits_hold()
    src = tmp_path / "src"
    mark_git_checkout(src)
    config = tmp_path / "plain" / "operator.yaml"
    config.parent.mkdir()
    config.write_text("project_name: unreadable\n", encoding="utf-8")
    config.chmod(0)
    monkeypatch.chdir(src)
    monkeypatch.setenv("ASH_CONFIG", str(config))
    try:
        with pytest.raises(ASHConfigValidationError) as refused:
            default_config_document_for_tree(src)
    finally:
        config.chmod(0o600)
    return config, str(refused.value)


def test_an_unreadable_ash_config_is_refused_with_its_path_and_errno_once(
    tmp_path, monkeypatch
):
    config, message = _refusal_for_an_unreadable_ash_config(tmp_path, monkeypatch)
    assert message == (
        f"could not read {describe_config_path(config)}: "
        f"[Errno {errno.EACCES}] {os.strerror(errno.EACCES)}"
    ), message


def test_the_unreadable_file_is_named_once_not_twice(tmp_path, monkeypatch):
    """The OSError carries the file's path in its own text; the refusal must
    not print it a second time after the described path."""
    config, message = _refusal_for_an_unreadable_ash_config(tmp_path, monkeypatch)
    assert message.count(config.name) == 1, message
