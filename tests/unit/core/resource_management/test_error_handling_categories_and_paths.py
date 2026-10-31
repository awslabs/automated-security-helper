# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The error-handling helpers name what went wrong, and look at nothing but the path.

Each test here is pinned against the behavior it replaced:

* ``safe_read_json_file`` reported a file that is not UTF-8, one nested past the
  decoder's limit, and one removed between its existence check and its read all
  as ``unexpected_error``; it also read through a symlink at the file name.
* Every error context in the module carried the server's working directory, read
  with ``Path.cwd()`` inside the error handlers, so a removed working directory
  made the "safe" helpers raise, and the directory reached the MCP client.
* ``safe_write_json_file`` made missing parent directories with ``mkdir`` before
  the guarded open, so under a writable root the directories were made through a
  link and the open then refused that link.
* ``validate_directory_path`` reported an existing regular file as not found, and
  a path below an unsearchable directory as unexpected.
* ``source_directory_error`` let a NUL in the path escape as ValueError and read
  a too-long name as a directory that cannot be entered.
* ``validate_output_directory_path`` labelled every refusal ``invalid_parameter``.
* ``validate_scan_parameters`` skipped an empty config path as "no config".
* ``_strings_shown`` escaped string values but not dict keys or set members.
"""

import errno
import json
import os
from types import SimpleNamespace

import pytest

from automated_security_helper.core.resource_management import error_handling
from automated_security_helper.core.resource_management.error_handling import (
    ErrorCategory,
    create_error_response,
    safe_read_json_file,
    safe_write_json_file,
    source_directory_error,
    validate_config_path,
    validate_directory_path,
    validate_output_directory_path,
    validate_scan_parameters,
)
from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.utils.sandbox.fs_guard import writable_root
from automated_security_helper.utils.terminal_text import raw_controls_on_one_line

pytestmark = pytest.mark.unit


def _symlink_or_skip(link, target):
    """Make ``link`` point at ``target``, in the argument order of the helpers of
    the same name in the sibling test files."""
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"symlinks cannot be made here: {error}")


class _OsWith:
    """The ``os`` module with some functions replaced, to stand in for one
    module's own binding of ``os``.

    ``monkeypatch.setattr(error_handling.os, "lstat", ...)`` replaces the
    function on the shared module, for the whole process while the test runs
    (pathlib, logging and pytest itself call it too). Replacing the binding a
    module reads its ``os`` through reaches that module alone.
    """

    def __init__(self, **replacements):
        self.__dict__.update(replacements)

    def __getattr__(self, name):
        return getattr(os, name)


class TestSafeReadJsonFileNamesEachFailure:
    def test_a_file_that_is_not_utf8_is_a_format_error(self, tmp_path):
        path = tmp_path / "results.json"
        path.write_bytes(b"\xff\xfe{}")

        data, error = safe_read_json_file(path)

        assert data is None
        assert error.context["error_category"] == ErrorCategory.INVALID_FORMAT.value
        assert "UTF-8" in str(error)

    def test_a_document_nested_past_the_decoder_is_a_format_error(
        self, tmp_path, monkeypatch
    ):
        path = tmp_path / "results.json"
        path.write_text("{}", encoding="utf-8")

        def too_deep(text):
            raise RecursionError("maximum recursion depth exceeded")

        monkeypatch.setattr(
            error_handling,
            "json",
            SimpleNamespace(loads=too_deep, JSONDecodeError=json.JSONDecodeError),
        )

        data, error = safe_read_json_file(path)

        assert data is None
        assert error.context["error_category"] == ErrorCategory.INVALID_FORMAT.value

    def test_a_file_removed_before_the_read_is_not_found(self, tmp_path, monkeypatch):
        path = tmp_path / "results.json"
        path.write_text("{}", encoding="utf-8")

        def gone(path_obj):
            raise FileNotFoundError(errno.ENOENT, "No such file", str(path_obj))

        monkeypatch.setattr(error_handling, "_read_regular_file_text", gone)

        data, error = safe_read_json_file(path, required=True)
        assert data is None
        assert error.context["error_category"] == ErrorCategory.FILE_NOT_FOUND.value

        assert safe_read_json_file(path, required=False) == (None, None)

    def test_a_link_at_the_file_name_is_not_followed(self, tmp_path):
        outside = tmp_path / "outside.json"
        outside.write_text('{"secret": "elsewhere"}', encoding="utf-8")
        link = tmp_path / "ASH.ScanResults.json"
        _symlink_or_skip(link, outside)

        data, error = safe_read_json_file(link)

        assert data is None
        assert error.context["error_category"] == ErrorCategory.INVALID_PATH.value
        assert "symbolic link" in str(error)

    @pytest.mark.skipif(
        not hasattr(os, "O_NOFOLLOW"), reason="the platform has no O_NOFOLLOW"
    )
    def test_a_link_swapped_in_after_the_look_is_not_followed_either(
        self, tmp_path, monkeypatch
    ):
        """The look (lstat) and the open are two calls; a scanner can replace a
        regular file with a link between them. The open is by descriptor with
        O_NOFOLLOW and the descriptor is fstat-ed, so what is read is what was
        checked. Here the look is made to report the regular file the name held,
        while the name already holds a link: the reopen by name followed it and
        returned the file outside the tree as the scan's own."""
        outside = tmp_path / "outside.json"
        outside.write_text('{"secret": "elsewhere"}', encoding="utf-8")
        link = tmp_path / "ASH.ScanResults.json"
        _symlink_or_skip(link, outside)
        regular = os.lstat(outside)
        real_lstat = os.lstat

        def looks_regular(path, *args, **kwargs):
            if str(path) == str(link):
                return regular
            return real_lstat(path, *args, **kwargs)

        monkeypatch.setattr(error_handling, "os", _OsWith(lstat=looks_regular))

        data, error = safe_read_json_file(link)

        assert data is None
        assert error is not None
        assert error.context["error_category"] == ErrorCategory.INVALID_PATH.value
        assert "symbolic link" in str(error)

    def test_a_directory_swapped_in_after_the_look_is_not_a_file(
        self, tmp_path, monkeypatch
    ):
        """The same window with a directory at the name: the descriptor opens
        (a directory can be opened read-only) and its fstat refuses it as not a
        file, where the reopen by name raised IsADirectoryError out of the
        read and the caller was told "unexpected"."""
        sample = tmp_path / "sample.json"
        sample.write_text("{}", encoding="utf-8")
        regular = os.lstat(sample)
        real_lstat = os.lstat
        directory = tmp_path / "ASH.ScanResults.json"
        directory.mkdir()

        def looks_regular(path, *args, **kwargs):
            if str(path) == str(directory):
                return regular
            return real_lstat(path, *args, **kwargs)

        monkeypatch.setattr(error_handling, "os", _OsWith(lstat=looks_regular))

        data, error = safe_read_json_file(directory)

        assert data is None
        assert error is not None
        assert error.context["error_category"] == ErrorCategory.INVALID_PATH.value
        assert "not a file" in str(error)

    def test_the_control_a_regular_file_is_read_through_the_descriptor(self, tmp_path):
        path = tmp_path / "ASH.ScanResults.json"
        path.write_text('{"status": "PASSED"}', encoding="utf-8")

        data, error = safe_read_json_file(path)

        assert error is None
        assert data == {"status": "PASSED"}

    def test_a_missing_file_error_names_the_file_and_not_the_process(self, tmp_path):
        data, error = safe_read_json_file(tmp_path / "absent.json")

        assert data is None
        assert error.context["error_category"] == ErrorCategory.FILE_NOT_FOUND.value
        assert "cwd" not in error.context


class TestSafeWriteJsonFileMakesParentsUnderTheGuard:
    def test_parents_are_not_made_through_a_link_below_a_writable_root(self, tmp_path):
        root = tmp_path / "out"
        root.mkdir()
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        _symlink_or_skip(root / "link", elsewhere)

        with writable_root(root):
            error = safe_write_json_file(root / "link" / "sub" / "state.json", {"a": 1})

        assert error is not None
        assert error.context["error_category"] == ErrorCategory.INVALID_PATH.value
        assert not (elsewhere / "sub").exists()
        assert "cwd" not in error.context

    def test_missing_parents_are_made_for_a_plain_path(self, tmp_path):
        path = tmp_path / "a" / "b" / "state.json"

        assert safe_write_json_file(path, {"a": [1, 2]}) is None
        assert json.loads(path.read_text(encoding="utf-8")) == {"a": [1, 2]}


class TestValidateDirectoryPathCategories:
    def test_a_regular_file_is_an_invalid_path_not_a_missing_one(self, tmp_path):
        file_path = tmp_path / "a-file"
        file_path.write_text("x", encoding="utf-8")

        error = validate_directory_path(file_path)

        assert error is not None
        assert error.context["error_category"] == ErrorCategory.INVALID_PATH.value
        assert "not a directory" in str(error)

    def test_a_missing_directory_is_not_found_and_names_no_cwd(self, tmp_path):
        error = validate_directory_path(tmp_path / "absent")

        assert error.context["error_category"] == ErrorCategory.FILE_NOT_FOUND.value
        assert "Directory not found or not a directory" in str(error)
        assert "cwd" not in error.context

    def test_a_path_below_an_unsearchable_directory_is_permission_denied(
        self, tmp_path, monkeypatch
    ):
        target = tmp_path / "closed" / "inner"
        real_stat = os.stat

        def refused(path, *args, **kwargs):
            if str(path).startswith(str(tmp_path / "closed")):
                raise PermissionError(errno.EACCES, "Permission denied", str(path))
            return real_stat(path, *args, **kwargs)

        monkeypatch.setattr(error_handling, "os", _OsWith(stat=refused))

        error = validate_directory_path(target)

        assert error is not None
        assert error.context["error_category"] == ErrorCategory.PERMISSION_DENIED.value

    def test_a_directory_is_valid(self, tmp_path):
        assert validate_directory_path(tmp_path) is None


class TestSourceDirectoryErrorOnPathsTheSystemRefuses:
    """The category is this surface's; the text is the one every surface shares.

    utils/directory_refusals.py (the CLI, ./ash and Invoke-ASH) words a NUL as
    "does not exist" and a name too long as "cannot be entered", and three places
    promise that source_directory_error gives the same text for the same input;
    "is not a valid path" was a fourth wording no other surface used.
    """

    def test_an_embedded_nul_is_an_invalid_path_worded_as_the_cli_words_it(self):
        from automated_security_helper.utils.directory_refusals import (
            source_dir_refusal,
        )

        error = source_directory_error("proj\x00ect")

        assert error is not None
        assert error.context["error_category"] == ErrorCategory.INVALID_PATH.value
        assert str(error) == source_dir_refusal("proj\x00ect")
        assert "does not exist" in str(error)

    def test_a_name_too_long_is_an_invalid_path_worded_as_the_cli_words_it(
        self, monkeypatch
    ):
        from automated_security_helper.utils import directory_refusals
        from automated_security_helper.utils.directory_refusals import (
            source_dir_refusal,
        )

        def too_long(path, *args, **kwargs):
            raise OSError(errno.ENAMETOOLONG, "File name too long", str(path))

        monkeypatch.setattr(error_handling, "os", _OsWith(stat=too_long))
        monkeypatch.setattr(directory_refusals, "os", _OsWith(stat=too_long))

        error = source_directory_error("x" * 5000)

        assert error.context["error_category"] == ErrorCategory.INVALID_PATH.value
        assert str(error) == source_dir_refusal("x" * 5000)
        assert "cannot be entered" in str(error)

    def test_no_text_of_this_helper_is_outside_the_shared_list(self):
        """Every problem phrase source_directory_error can produce is one the
        shared wording module lists; the fourth phrase was not."""
        import inspect

        source = inspect.getsource(source_directory_error)
        shared = inspect.getsource(
            __import__(
                "automated_security_helper.utils.directory_refusals",
                fromlist=["source_dir_refusal"],
            ).source_dir_refusal
        )
        for phrase in ("does not exist", "is not a directory", "cannot be entered"):
            assert phrase in source and phrase in shared
        assert "is not a valid path" not in source


class TestValidateOutputDirectoryPathCategories:
    def test_a_regular_file_is_an_invalid_path(self, tmp_path):
        file_path = tmp_path / "a-file"
        file_path.write_text("x", encoding="utf-8")

        error = validate_output_directory_path(file_path)

        assert error is not None
        assert error.context["error_category"] == ErrorCategory.INVALID_PATH.value

    def test_a_directory_that_cannot_be_entered_is_permission_denied(
        self, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(
            error_handling,
            "output_dir_refusal",
            lambda path: f"Output directory cannot be entered: {path}",
        )

        error = validate_output_directory_path(tmp_path)

        assert error is not None
        assert error.context["error_category"] == ErrorCategory.PERMISSION_DENIED.value

    def test_a_usable_directory_is_valid(self, tmp_path):
        assert validate_output_directory_path(tmp_path) is None


class TestAnEmptyConfigPathIsRefused:
    def test_validate_config_path_refuses_an_empty_string(self):
        error = validate_config_path("")

        assert error is not None
        assert error.context["error_category"] == ErrorCategory.INVALID_PARAMETER.value

    def test_validate_scan_parameters_does_not_skip_an_empty_config_path(
        self, tmp_path
    ):
        is_valid, errors = validate_scan_parameters(tmp_path, "MEDIUM", config_path="")

        assert is_valid is False
        assert [e.context["error_category"] for e in errors] == [
            ErrorCategory.INVALID_PARAMETER.value
        ]

    def test_no_config_path_is_still_no_config(self, tmp_path):
        is_valid, errors = validate_scan_parameters(
            tmp_path, "MEDIUM", config_path=None
        )

        assert (is_valid, errors) == (True, [])


class TestStringsShownCoversKeysAndSets:
    def test_a_dict_key_with_a_control_character_is_escaped(self):
        key = "scan\x1b[0mner"
        error = MCPResourceError("x", context={key: "value"})

        response = create_error_response(error, "op")

        assert raw_controls_on_one_line(key) in response["context"]
        assert key not in response["context"]
        assert all("\x1b" not in k for k in response["context"])

    def test_set_and_frozenset_members_are_escaped_and_the_type_kept(self):
        error = MCPResourceError(
            "x",
            context={"names": {"a\nb"}, "frozen": frozenset({"c\rd"})},
        )

        response = create_error_response(error, "op")

        assert response["context"]["names"] == {raw_controls_on_one_line("a\nb")}
        assert isinstance(response["context"]["names"], set)
        assert response["context"]["frozen"] == frozenset(
            {raw_controls_on_one_line("c\rd")}
        )
        assert isinstance(response["context"]["frozen"], frozenset)
