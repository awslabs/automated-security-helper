# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""One category for one bad path, and a full disk is not a missing permission.

- ``validate_output_directory_path`` worked the category out from a second ``stat``
  of the path, while ``output_dir_refusal`` returned only the strerror of the error
  that refused it. A directory that exists, can be entered and whose disk or quota
  is full (``ENOSPC``, ``EDQUOT``) was therefore ``permission_denied``. The
  refusal now carries its kind and errno (``DirectoryRefusal``), and the category
  follows them.
- The same path met three routes with three answers: an embedded NUL or a name
  past the system's limit was ``invalid_path`` in ``source_directory_error`` and
  ``unexpected_error`` in ``validate_directory_path`` and ``safe_read_json_file``;
  a link loop on the way was ``file_not_found`` in the first two and
  ``unexpected_error`` in the third. All three now take their category from
  ``lookup_error_category``.
"""

import copy
import errno
import os
import pickle
import sys

import pytest

from automated_security_helper.core.resource_management import error_handling
from automated_security_helper.core.resource_management.error_handling import (
    ErrorCategory,
    safe_read_json_file,
    source_directory_error,
    validate_directory_path,
    validate_output_directory_path,
)
from automated_security_helper.utils import directory_refusals
from automated_security_helper.utils.directory_refusals import (
    REFUSED_CANNOT_BE_WRITTEN,
    DirectoryRefusal,
    output_dir_refusal,
)

pytestmark = pytest.mark.unit

needs_symlinks = pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)


def _write_check_fails_with(monkeypatch, code):
    """The file ``output_dir_refusal`` makes to test the directory cannot be made."""
    real_open = os.open

    def refusing(path, *args, **kwargs):
        if directory_refusals.WRITE_CHECK_PREFIX in os.fspath(path):
            raise OSError(code, os.strerror(code), os.fspath(path))
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(directory_refusals.os, "open", refusing)


@pytest.mark.parametrize(
    ("code", "category"),
    [
        pytest.param(errno.ENOSPC, ErrorCategory.RESOURCE_EXHAUSTED, id="disk-full"),
        pytest.param(
            getattr(errno, "EDQUOT", errno.ENOSPC),
            ErrorCategory.RESOURCE_EXHAUSTED,
            id="quota",
        ),
        pytest.param(errno.EACCES, ErrorCategory.PERMISSION_DENIED, id="permission"),
        pytest.param(errno.EROFS, ErrorCategory.PERMISSION_DENIED, id="read-only"),
    ],
)
def test_the_category_of_a_directory_that_cannot_be_written_follows_the_error(
    tmp_path, monkeypatch, code, category
):
    _write_check_fails_with(monkeypatch, code)

    error = validate_output_directory_path(tmp_path)

    assert error is not None
    assert error.context["error_category"] == category.value
    assert "Output directory cannot be written" in str(error)


def test_the_refusal_is_the_same_text_and_carries_its_kind_and_errno(
    tmp_path, monkeypatch
):
    _write_check_fails_with(monkeypatch, errno.ENOSPC)

    refusal = output_dir_refusal(tmp_path)

    assert isinstance(refusal, DirectoryRefusal)
    assert isinstance(refusal, str)
    assert refusal == (
        f"Output directory cannot be written: {tmp_path} ({os.strerror(errno.ENOSPC)})"
    )
    assert refusal.kind == REFUSED_CANNOT_BE_WRITTEN
    assert refusal.error_number == errno.ENOSPC


def test_a_refusal_survives_a_copy_and_a_pickle_with_its_reason(tmp_path, monkeypatch):
    _write_check_fails_with(monkeypatch, errno.ENOSPC)
    refusal = output_dir_refusal(tmp_path)

    for rebuilt in (copy.copy(refusal), copy.deepcopy(refusal)):
        assert rebuilt == refusal
        assert (rebuilt.kind, rebuilt.error_number) == (
            refusal.kind,
            refusal.error_number,
        )
    unpickled = pickle.loads(pickle.dumps(refusal))
    assert (unpickled, unpickled.kind, unpickled.error_number) == (
        refusal,
        refusal.kind,
        refusal.error_number,
    )


def test_control_a_refusal_that_is_only_text_is_judged_by_a_stat_of_the_path(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(
        error_handling,
        "output_dir_refusal",
        lambda path: f"Output directory cannot be entered: {path}",
    )

    error = validate_output_directory_path(tmp_path)

    assert error.context["error_category"] == ErrorCategory.PERMISSION_DENIED.value


def test_control_a_file_where_the_directory_should_be_is_an_invalid_path(tmp_path):
    file_path = tmp_path / "a-file"
    file_path.write_text("x", encoding="utf-8")

    error = validate_output_directory_path(file_path)

    assert error.context["error_category"] == ErrorCategory.INVALID_PATH.value


def _categories_of_the_three_routes(path):
    source = source_directory_error(path)
    directory = validate_directory_path(path)
    _, read = safe_read_json_file(path)
    return tuple(
        None if error is None else error.context["error_category"]
        for error in (source, directory, read)
    )


def test_an_embedded_nul_has_one_category_on_every_route(tmp_path):
    categories = _categories_of_the_three_routes(str(tmp_path / "pro\x00j"))

    assert categories == (ErrorCategory.INVALID_PATH.value,) * 3


def test_a_name_past_the_systems_limit_has_one_category_on_every_route(
    tmp_path, monkeypatch
):
    real_stat, real_lstat = os.stat, os.lstat

    def too_long(real):
        def lookup(path, *args, **kwargs):
            if "too-long-marker" in os.fspath(path):
                raise OSError(errno.ENAMETOOLONG, "File name too long", str(path))
            return real(path, *args, **kwargs)

        return lookup

    monkeypatch.setattr(error_handling.os, "stat", too_long(real_stat))
    monkeypatch.setattr(error_handling.os, "lstat", too_long(real_lstat))

    categories = _categories_of_the_three_routes(str(tmp_path / "too-long-marker"))

    assert categories == (ErrorCategory.INVALID_PATH.value,) * 3


@needs_symlinks
def test_a_link_loop_on_the_way_has_one_category_on_every_route(tmp_path):
    loop = tmp_path / "loop"
    loop.symlink_to(loop)

    categories = _categories_of_the_three_routes(str(loop / "inner"))

    assert categories == (ErrorCategory.FILE_NOT_FOUND.value,) * 3


def test_control_a_missing_path_has_one_category_on_every_route(tmp_path):
    categories = _categories_of_the_three_routes(str(tmp_path / "absent"))

    assert categories == (ErrorCategory.FILE_NOT_FOUND.value,) * 3


def test_control_a_missing_optional_file_is_still_no_error(tmp_path):
    assert safe_read_json_file(tmp_path / "absent.json", required=False) == (
        None,
        None,
    )


@needs_symlinks
def test_a_link_loop_on_the_way_to_an_optional_file_is_no_error_either(tmp_path):
    loop = tmp_path / "loop"
    loop.symlink_to(loop)

    assert safe_read_json_file(loop / "x.json", required=False) == (None, None)
