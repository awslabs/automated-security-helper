# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""With no root given and the working directory deleted, the client rules still answer.

``client_file_denials``, ``apply_client_config_rules`` and
``strip_client_scanner_exclusions`` each took ``Path.cwd()`` as the scanned tree
when no root was given, so a working directory deleted while the process runs
made a delivered config's check raise ``FileNotFoundError`` instead of judging
the file. The rules now judge with no tree: a module request is judged by the
client-supplied arm alone (``refusal_reason`` with no scanned root), a sandbox or
field denial is the same denial it is with a root, and a delivered trivy ignore
file, the one thing read from the scanned tree, is not read.

Each deleted-cwd cell has a live-root control, so a cell can only fail by the two
paths diverging. The module-drop and sandbox-wording cells of a rootless load
through ``resolve_config`` are in
``test_a_deleted_working_directory_fails_closed_everywhere.py``.
"""

import os
import sys
from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.client_config_policy import (
    apply_client_config_rules,
    client_file_denials,
    rules_from,
)
from automated_security_helper.config.client_scanner_exclusions import (
    strip_client_scanner_exclusions,
)
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import (
    ASHConfigFieldDeniedError,
    ASHConfigValidationError,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()

UPLOAD = Path("/zz-delcwd-upload/config.yaml")


def _delete_cwd(tmp_path, monkeypatch):
    # os.rmdir of the process's working directory is PermissionError on
    # Windows, so every deleted-cwd cell skips there through this one helper.
    if sys.platform == "win32":
        pytest.skip("the working directory cannot be removed on Windows")
    launched = tmp_path / "launched-here"
    launched.mkdir()
    monkeypatch.chdir(launched)
    os.rmdir(launched)
    with pytest.raises(FileNotFoundError):
        Path.cwd()


_GRANT = {"sandbox": {"extra_read_paths": ["/zz-delcwd-read"]}}
_UNINSTALLED_MODULE = {"ash_plugin_modules": ["zz_delcwd_uninstalled_mod"]}


def _keys(found):
    return [denial.key for _file, denials in found for denial in denials]


def test_client_file_denials_answers_with_no_root_and_no_working_directory(
    tmp_path, monkeypatch
):
    _delete_cwd(tmp_path, monkeypatch)

    found = client_file_denials(
        {UPLOAD: {"project_name": "upload"}},
        rules_from(AshConfig()),
        all_delivered=True,
    )

    assert found == []


def test_client_file_denials_still_names_a_widening_with_no_working_directory(
    tmp_path, monkeypatch
):
    _delete_cwd(tmp_path, monkeypatch)

    found = client_file_denials(
        {UPLOAD: _GRANT}, rules_from(AshConfig()), all_delivered=True
    )

    assert _keys(found) == ["sandbox.extra_read_paths"], found


def test_control_a_live_root_names_the_same_widening(tmp_path):
    found = client_file_denials(
        {UPLOAD: _GRANT},
        rules_from(AshConfig()),
        scanned_root=tmp_path,
        all_delivered=True,
    )

    assert _keys(found) == ["sandbox.extra_read_paths"], found


def test_client_file_denials_still_judges_a_module_with_no_working_directory(
    tmp_path, monkeypatch
):
    """No tree does not mean no module judgment: a module the installed
    environment cannot import is refused whether or not a tree is known."""
    _delete_cwd(tmp_path, monkeypatch)

    found = client_file_denials(
        {UPLOAD: _UNINSTALLED_MODULE}, rules_from(AshConfig()), all_delivered=True
    )

    assert _keys(found) == ["ash_plugin_modules"], found
    reasons = [denial.reason for _file, denials in found for denial in denials]
    assert all("not importable" in reason for reason in reasons), reasons


def test_control_a_live_root_refuses_the_same_module(tmp_path):
    found = client_file_denials(
        {UPLOAD: _UNINSTALLED_MODULE},
        rules_from(AshConfig()),
        scanned_root=tmp_path,
        all_delivered=True,
    )

    assert _keys(found) == ["ash_plugin_modules"], found


def _apply(documents):
    return apply_client_config_rules(
        AshConfig(),
        documents,
        rules=rules_from(AshConfig()),
        trusted_config_path=None,
        source_dir=None,
        permit_base=None,
        all_delivered=True,
    )


def test_a_delivered_widening_is_refused_with_no_root_and_no_working_directory(
    tmp_path, monkeypatch
):
    """The refusal a live root gives, not the FileNotFoundError out of Path.cwd()."""
    _delete_cwd(tmp_path, monkeypatch)

    with pytest.raises(ASHConfigFieldDeniedError) as refused:
        _apply({UPLOAD: _GRANT})

    assert "sandbox.extra_read_paths" in str(refused.value), str(refused.value)


def test_a_delivered_config_that_asks_for_nothing_answers_with_no_working_directory(
    tmp_path, monkeypatch
):
    _delete_cwd(tmp_path, monkeypatch)

    config = _apply({UPLOAD: {"project_name": "upload"}})

    assert isinstance(config, AshConfig)


def _trivy_delivered_config():
    document = {
        "project_name": "delivered",
        "scanners": {"trivy-repo": {"options": {"ignore_file": ".trivyignore"}}},
    }
    return AshConfig.model_validate(document), {UPLOAD: document}


def _strip(config, documents, **roots):
    return strip_client_scanner_exclusions(
        config,
        documents,
        AshConfig(),
        source_dir=roots.get("source_dir"),
        scanned_root=roots.get("scanned_root"),
        is_delivered=lambda _path: True,
    )


def _ignore_file_notes(config):
    return [
        note
        for note in getattr(config, "_resolution_warnings", None) or []
        if "ignore_file" in note
    ]


def test_a_delivered_trivy_ignore_file_is_not_read_with_no_root_and_no_working_directory(
    tmp_path, monkeypatch
):
    config, documents = _trivy_delivered_config()
    _delete_cwd(tmp_path, monkeypatch)

    stripped = _strip(config, documents)

    options = stripped.get_plugin_config("scanner", "trivy-repo")["options"]
    assert not options.get("ignore_file"), options
    assert list(stripped._client_scanner_exclusions) == []
    notes = _ignore_file_notes(stripped)
    assert len(notes) == 1, notes
    assert "was not read" in notes[0] and "no scanned tree" in notes[0], notes[0]
    assert "working directory is gone" in notes[0], notes[0]


def test_control_with_a_live_root_the_same_file_is_not_called_a_missing_tree(tmp_path):
    config, documents = _trivy_delivered_config()

    stripped = _strip(config, documents, scanned_root=tmp_path)

    notes = _ignore_file_notes(stripped)
    assert len(notes) == 1, notes
    assert "no scanned tree" not in notes[0], notes[0]


def _upload_path(tmp_path):
    upload = tmp_path / "upload" / "config.yaml"
    upload.parent.mkdir()
    return upload


def test_a_client_upload_that_asks_for_nothing_loads_with_no_working_directory(
    tmp_path, monkeypatch
):
    """The whole path of a rootless client upload -- the chain read, the client
    rules, the exclusion move, the confinement -- with nothing in the file to
    refuse: the working directory is read by none of them."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    upload = _upload_path(tmp_path)
    upload.write_text("project_name: upload\n", encoding="utf-8")
    _delete_cwd(tmp_path, monkeypatch)

    config = resolve_config(
        config_path=str(upload), untrusted_config=True, fallback_to_default=False
    )

    assert config.project_name == "upload"


def test_an_override_with_a_relative_path_refuses_the_load_with_no_working_directory(
    tmp_path, monkeypatch
):
    """The operator's --config-overrides take a relative path from the working
    directory ASH runs in. With it gone the path would reach the scanners as
    written and be read from the scanned tree, so the load is refused, naming
    the override's key and never its value."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    named = tmp_path / "ash.yaml"
    named.write_text("project_name: operator\n", encoding="utf-8")
    _delete_cwd(tmp_path, monkeypatch)

    with pytest.raises(ASHConfigValidationError) as refused:
        resolve_config(
            config_path=named,
            config_overrides=["scanners.bandit.options.config_file=zz-secret.yaml"],
        )

    text = str(refused.value)
    assert "scanners.bandit.options.config_file" in text, text
    assert "zz-secret" not in text, text
    assert "working directory" in text, text


def test_an_override_with_no_path_answers_with_no_working_directory(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    named = tmp_path / "ash.yaml"
    named.write_text("project_name: operator\n", encoding="utf-8")
    _delete_cwd(tmp_path, monkeypatch)

    config = resolve_config(
        config_path=named, config_overrides=["project_name=overridden"]
    )

    assert config.project_name == "overridden"


def test_control_a_live_working_directory_anchors_the_same_override(
    tmp_path, monkeypatch
):
    from automated_security_helper.config.resolve_config import (
        _anchored_operator_overrides,
    )

    monkeypatch.chdir(tmp_path)

    anchored = _anchored_operator_overrides(
        ["scanners.bandit.options.config_file=bandit.yaml", "project_name=renamed"]
    )

    assert anchored == [
        "scanners.bandit.options.config_file="
        + os.path.join(os.path.realpath(tmp_path), "bandit.yaml"),
        "project_name=renamed",
    ]
