# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reading a ``.code-workspace`` file: the inputs that were refused for the wrong
reason, escaped as tracebacks, or read from the wrong directory.

* A byte order mark made a valid file "not valid JSON" while ASH's own JSON
  config reader drops one.
* A document nested past the recursion limit raised ``RecursionError`` out of
  ``json.loads``, a traceback and exit 1 where every unusable file is exit 4.
* The JSONC hint fired only on a comment marker, so a trailing comma, the other
  thing VS Code accepts, got the bare parser message; and a ``//`` inside a URL
  string made the message claim the file "appears to contain comments".
* A symlinked workspace file was resolved to its target, which moved the
  workspace root, and so every folder entry, to the target's directory.
* ``Path.exists()``/``is_file()`` and ``Path.glob`` either raised a bare
  ``PermissionError`` or read an unsearchable directory as empty.
"""

import json
import os

import pytest

from automated_security_helper.core.exceptions import WorkspaceDefinitionError
from automated_security_helper.workspace.workspace_file import (
    discover_workspace_file,
    load_workspace_file,
)

pytestmark = pytest.mark.unit

ONE_FOLDER = {"folders": [{"path": "api"}]}


def _symlink_or_skip(link, target, target_is_directory=False) -> None:
    try:
        link.symlink_to(target, target_is_directory=target_is_directory)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"symlink creation unavailable on this platform: {exc}")


class TestParsing:
    def test_a_byte_order_mark_is_dropped(self, tmp_path):
        path = tmp_path / "dev.code-workspace"
        path.write_text(chr(0xFEFF) + json.dumps(ONE_FOLDER), encoding="utf-8")

        definition = load_workspace_file(path)

        assert [folder.path for folder in definition.folders] == ["api"]

    def test_a_document_nested_past_the_recursion_limit_is_refused(self, tmp_path):
        path = tmp_path / "dev.code-workspace"
        path.write_text("[" * 50000 + "]" * 50000, encoding="utf-8")

        with pytest.raises(WorkspaceDefinitionError, match="not valid JSON"):
            load_workspace_file(path)

    def test_a_trailing_comma_gets_the_jsonc_hint(self, tmp_path):
        path = tmp_path / "dev.code-workspace"
        path.write_text('{"folders": [{"path": "api"},]}', encoding="utf-8")

        with pytest.raises(WorkspaceDefinitionError) as excinfo:
            load_workspace_file(path)

        assert "trailing commas" in str(excinfo.value)

    def test_a_url_in_a_string_is_not_called_a_comment(self, tmp_path):
        path = tmp_path / "dev.code-workspace"
        path.write_text(
            '{"folders": [{"path": "api", "remote": "https://example.invalid/x"}]',
            encoding="utf-8",
        )

        with pytest.raises(WorkspaceDefinitionError) as excinfo:
            load_workspace_file(path)

        assert "appears to contain comments" not in str(excinfo.value)


class TestALinkedDefinitionIsReadWhereItWasNamed:
    def test_the_root_is_the_directory_holding_the_link(self, tmp_path):
        opened = tmp_path / "opened"
        opened.mkdir()
        (opened / "api").mkdir()
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        real = elsewhere / "real.code-workspace"
        real.write_text(json.dumps(ONE_FOLDER), encoding="utf-8")
        link = opened / "dev.code-workspace"
        _symlink_or_skip(link, real)

        definition = load_workspace_file(link)

        assert definition.root == opened.resolve()
        assert definition.path == opened.resolve() / "dev.code-workspace"

    def test_discovery_returns_the_link_not_its_target(self, tmp_path):
        opened = tmp_path / "opened"
        opened.mkdir()
        real = tmp_path / "real.code-workspace"
        real.write_text(json.dumps(ONE_FOLDER), encoding="utf-8")
        _symlink_or_skip(opened / "dev.code-workspace", real)

        assert (
            discover_workspace_file(opened) == opened.resolve() / "dev.code-workspace"
        )


class TestAnUnsearchableDirectoryIsARefusal:
    def test_a_file_under_an_unsearchable_directory_is_refused_not_a_traceback(
        self, tmp_path
    ):
        locked = tmp_path / "locked"
        locked.mkdir()
        path = locked / "dev.code-workspace"
        path.write_text(json.dumps(ONE_FOLDER), encoding="utf-8")
        locked.chmod(0o000)
        try:
            if os.access(path, os.R_OK):  # pragma: no cover - root
                pytest.skip("running as a user that ignores directory permissions")
            with pytest.raises(WorkspaceDefinitionError, match="could not be examined"):
                load_workspace_file(path)
        finally:
            locked.chmod(0o755)

    def test_discovery_in_an_unlistable_directory_is_refused_not_empty(self, tmp_path):
        locked = tmp_path / "locked"
        locked.mkdir()
        (locked / "dev.code-workspace").write_text(
            json.dumps(ONE_FOLDER), encoding="utf-8"
        )
        locked.chmod(0o000)
        try:
            if os.access(locked / "dev.code-workspace", os.R_OK):  # pragma: no cover
                pytest.skip("running as a user that ignores directory permissions")
            with pytest.raises(WorkspaceDefinitionError, match="could not be listed"):
                discover_workspace_file(locked)
        finally:
            locked.chmod(0o755)
