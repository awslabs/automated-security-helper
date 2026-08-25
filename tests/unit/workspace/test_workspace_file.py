# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for parsing and discovering a ``.code-workspace`` definition.

Everything here is about refusing a definition ASH cannot act on, and about the
two blocks the parser deliberately ignores -- ``settings`` and a folder's
``name`` -- because reading either would put ASH policy in another tool's file.
"""

import json

import pytest

from automated_security_helper.core.exceptions import WorkspaceDefinitionError
from automated_security_helper.workspace.workspace_file import (
    discover_workspace_file,
    load_workspace_file,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write(root, payload, name="dev.code-workspace"):
    """Write *payload* as a workspace file and return its path."""
    path = root / name
    if isinstance(payload, str):
        path.write_text(payload, encoding="utf-8")
    else:
        path.write_text(json.dumps(payload), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Parsing a well-formed definition
# ---------------------------------------------------------------------------


def test_folders_are_read_in_file_order(tmp_path):
    path = _write(
        tmp_path,
        {"folders": [{"path": "kiro-bootstrap"}, {"path": "shared-infra"}]},
    )

    definition = load_workspace_file(path)

    assert [f.path for f in definition.folders] == ["kiro-bootstrap", "shared-infra"]
    assert definition.root == tmp_path.resolve()
    assert definition.path == path.resolve()


def test_settings_block_is_ignored(tmp_path):
    """ASH policy lives in ASH's config, never in another tool's schema."""
    path = _write(
        tmp_path,
        {
            "folders": [{"path": "api"}],
            "settings": {
                "ash.severity_threshold": "CRITICAL",
                "files.exclude": {"**/node_modules": True},
            },
        },
    )

    definition = load_workspace_file(path)

    assert [f.path for f in definition.folders] == ["api"]
    assert not hasattr(definition, "settings")


def test_folder_name_field_is_ignored(tmp_path):
    """VS Code's display name must not become ASH's attribution label."""
    path = _write(
        tmp_path,
        {"folders": [{"path": "api", "name": "The API Service"}]},
    )

    definition = load_workspace_file(path)

    assert [f.path for f in definition.folders] == ["api"]
    assert not any(
        getattr(folder, "name", None) == "The API Service"
        for folder in definition.folders
    )


def test_extra_top_level_keys_are_ignored(tmp_path):
    path = _write(
        tmp_path,
        {"folders": [{"path": "api"}], "extensions": {"recommendations": []}},
    )

    assert [f.path for f in load_workspace_file(path).folders] == ["api"]


def test_workspace_file_is_read_as_utf8(tmp_path):
    """Explicit encoding, so the parse does not depend on the host locale."""
    # Built with chr() so this test file itself stays pure ASCII.
    name = "caf" + chr(0xE9) + "-api"
    path = tmp_path / "dev.code-workspace"
    path.write_text(
        json.dumps({"folders": [{"path": name}]}, ensure_ascii=False),
        encoding="utf-8",
    )

    assert [f.path for f in load_workspace_file(path).folders] == [name]


# ---------------------------------------------------------------------------
# Malformed definitions -- every one of these is exit code 4
# ---------------------------------------------------------------------------


def test_empty_folders_list_is_rejected(tmp_path):
    path = _write(tmp_path, {"folders": []})

    with pytest.raises(WorkspaceDefinitionError, match="at least one folder"):
        load_workspace_file(path)


def test_missing_folders_key_is_rejected(tmp_path):
    path = _write(tmp_path, {"settings": {}})

    with pytest.raises(WorkspaceDefinitionError, match="folders"):
        load_workspace_file(path)


def test_invalid_json_is_rejected(tmp_path):
    path = _write(tmp_path, '{"folders": [{"path": "api"}')

    with pytest.raises(WorkspaceDefinitionError, match="not valid JSON"):
        load_workspace_file(path)


def test_json_comments_are_rejected_with_an_actionable_message(tmp_path):
    """VS Code tolerates comments; ASH does not, and says so rather than guessing."""
    path = _write(
        tmp_path,
        '{\n  // the API\n  "folders": [{"path": "api"}]\n}',
    )

    with pytest.raises(WorkspaceDefinitionError, match="comments"):
        load_workspace_file(path)


def test_top_level_array_is_rejected(tmp_path):
    path = _write(tmp_path, [{"path": "api"}])

    with pytest.raises(WorkspaceDefinitionError, match="JSON object"):
        load_workspace_file(path)


def test_folders_not_a_list_is_rejected(tmp_path):
    path = _write(tmp_path, {"folders": {"path": "api"}})

    with pytest.raises(WorkspaceDefinitionError, match="list"):
        load_workspace_file(path)


def test_folder_entry_not_an_object_is_rejected(tmp_path):
    path = _write(tmp_path, {"folders": ["api"]})

    with pytest.raises(WorkspaceDefinitionError, match="JSON object"):
        load_workspace_file(path)


def test_folder_entry_without_path_is_rejected(tmp_path):
    path = _write(tmp_path, {"folders": [{"name": "api"}]})

    with pytest.raises(WorkspaceDefinitionError, match="'path'"):
        load_workspace_file(path)


def test_folder_entry_with_non_string_path_is_rejected(tmp_path):
    path = _write(tmp_path, {"folders": [{"path": 7}]})

    with pytest.raises(WorkspaceDefinitionError, match="'path'"):
        load_workspace_file(path)


def test_folder_entry_with_blank_path_is_rejected(tmp_path):
    path = _write(tmp_path, {"folders": [{"path": "   "}]})

    with pytest.raises(WorkspaceDefinitionError, match="'path'"):
        load_workspace_file(path)


@pytest.mark.parametrize("entry", ["api\x00evil", "\x00", "\x00api"])
def test_folder_entry_containing_a_null_character_is_rejected(tmp_path, entry):
    """Caught from the raw text, before pathlib sees it.

    A null byte reaches ``os.lstat`` and raises ValueError, whose message differs
    between Python versions ("embedded null byte" on 3.10, "lstat: embedded null
    character in path" on 3.13). Letting it through would turn a malformed
    workspace file into an unhandled exception and exit 1 rather than exit 4, and
    would do it with a version-dependent message.
    """
    path = _write(tmp_path, {"folders": [{"path": entry}]})

    with pytest.raises(WorkspaceDefinitionError, match="null character"):
        load_workspace_file(path)


def test_a_null_character_rejection_does_not_quote_the_platform_error(tmp_path):
    """The message must be identical on every supported Python version."""
    path = _write(tmp_path, {"folders": [{"path": "api\x00evil"}]})

    with pytest.raises(WorkspaceDefinitionError) as excinfo:
        load_workspace_file(path)

    message = str(excinfo.value)
    assert "embedded null byte" not in message
    assert "lstat" not in message


def test_missing_workspace_file_is_rejected(tmp_path):
    with pytest.raises(WorkspaceDefinitionError, match="does not exist"):
        load_workspace_file(tmp_path / "absent.code-workspace")


def test_directory_given_instead_of_a_file_is_rejected(tmp_path):
    with pytest.raises(WorkspaceDefinitionError, match="not a file"):
        load_workspace_file(tmp_path)


def test_rejection_message_names_the_offending_file(tmp_path):
    path = _write(tmp_path, {"folders": []})

    with pytest.raises(WorkspaceDefinitionError) as excinfo:
        load_workspace_file(path)

    assert path.name in str(excinfo.value)


# ---------------------------------------------------------------------------
# Auto-discovery
# ---------------------------------------------------------------------------


def test_discovery_finds_exactly_one_candidate(tmp_path):
    path = _write(tmp_path, {"folders": [{"path": "api"}]})

    assert discover_workspace_file(tmp_path) == path.resolve()


def test_discovery_with_two_candidates_lists_both(tmp_path):
    first = _write(tmp_path, {"folders": [{"path": "api"}]}, name="a.code-workspace")
    second = _write(tmp_path, {"folders": [{"path": "web"}]}, name="b.code-workspace")

    with pytest.raises(WorkspaceDefinitionError) as excinfo:
        discover_workspace_file(tmp_path)

    message = str(excinfo.value)
    assert first.name in message
    assert second.name in message


def test_discovery_with_no_candidate_is_rejected(tmp_path):
    with pytest.raises(WorkspaceDefinitionError, match="No '\\*.code-workspace'"):
        discover_workspace_file(tmp_path)


def test_discovery_does_not_recurse_into_subdirectories(tmp_path):
    nested = tmp_path / "nested"
    nested.mkdir()
    _write(nested, {"folders": [{"path": "api"}]})

    with pytest.raises(WorkspaceDefinitionError, match="No '\\*.code-workspace'"):
        discover_workspace_file(tmp_path)


def test_discovery_ignores_directories_with_the_workspace_suffix(tmp_path):
    """A directory named ``x.code-workspace`` is not a definition."""
    (tmp_path / "decoy.code-workspace").mkdir()
    real = _write(tmp_path, {"folders": [{"path": "api"}]})

    assert discover_workspace_file(tmp_path) == real.resolve()
