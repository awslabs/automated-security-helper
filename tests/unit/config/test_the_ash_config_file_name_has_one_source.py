# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The tree pre-check reads the file ASH_CONFIG names from the variable alone.

A parameter that carried the file beside the variable gave the check two
sources for one name: the display name came from the parameter while the text
the read error trims came from the variable, and a caller that passed the
parameter with the variable unset got a ``KeyError``. The variable is the one
source.
"""

from __future__ import annotations

import pytest

from automated_security_helper.config import default_config


def test_no_variable_means_no_document(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)

    assert default_config.default_config_document_for_tree(tmp_path) is None


def test_the_file_is_not_a_parameter_beside_the_variable(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    config = tmp_path / "ash.yaml"
    config.write_text("project_name: op\n", encoding="utf-8")

    with pytest.raises(TypeError):
        default_config.default_config_document_for_tree(tmp_path, named=config)


def test_the_document_is_read_from_the_file_the_variable_names(tmp_path, monkeypatch):
    config = tmp_path / "ash.yaml"
    config.write_text("project_name: from-the-variable\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(config))

    document = default_config.default_config_document_for_tree(tmp_path)

    assert document is not None
    assert document.data["project_name"] == "from-the-variable"
