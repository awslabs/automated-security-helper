# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A chain file its rule keeps from the environment is refused before it reads any.

Why this file exists
--------------------
``resolve_config_document`` takes a ``refuse_env`` rule: the files of a chain, a
root or a base, that may read nothing from the environment (for a remote MCP
caller, every file outside the operator's config roots). The rule was applied
after the file was read, and the read resolved each ``${VAR}`` reference first.
A reference to a variable that is not set therefore failed with "is not set" and
one to a variable that is set was refused, so the answer told the caller whether
the server's variable existed, and the server had read it for a file the rule
says reads nothing.

The refusal now comes from ``parse_config_text``, which every reader of the chain
parses a file's text through, before a reference is resolved. These cases pin that
it is the same refusal whether or not the variable is set, that it quotes no value,
and that a file the rule does not refuse still reports an unset variable as it did.

Covered: the stock reader and a caller's own reader (the shape of ``read_once`` in
``resolve_config``), for a YAML plain reference, a YAML ``!ENV`` tag and a TOML
string, in the root and in a base. ``read_config_file`` with its own ``refuse_env``
decided before it resolved a reference already; it is pinned here too. A caller's
reader that does not parse through ``parse_config_text`` is not covered by the read
and is refused after it, as before.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

import pytest

from automated_security_helper.config.config_sources import (
    parse_config_text,
    read_config_file,
    read_config_text,
    refuse_env_everywhere,
    resolve_config_document,
)
from automated_security_helper.core.exceptions import (
    ASHConfigEnvNotResolvedError,
    ASHConfigSourceError,
)

pytestmark = pytest.mark.unit

PROBE = "ASH_REFUSED_FILE_PROBE"
VALUE = "value-from-the-servers-environment"

#: (extension, text) of a file that reads the probe variable, with no default.
REFERENCES = {
    "yaml-plain": ("yaml", f"project_name: ${{{PROBE}}}\n"),
    "yaml-tag": ("yaml", f"project_name: !ENV ${{{PROBE}}}\n"),
    "toml": ("toml", f'project_name = "${{{PROBE}}}"\n'),
}

WHERE = ["root", "base"]

Rule = Callable[[Path], bool]


def _chain(tmp_path: Path, kind: str, where: str) -> Tuple[Path, Rule]:
    """The root of a chain whose ``where`` file reads the probe, and the rule that
    refuses exactly that file."""
    extension, text = REFERENCES[kind]
    if where == "root":
        root = tmp_path / f"ash.{extension}"
        root.write_text(text, encoding="utf-8")
        return root, lambda path: Path(path).name == root.name
    base = tmp_path / f"base.{extension}"
    base.write_text(text, encoding="utf-8")
    root = tmp_path / "ash.yaml"
    root.write_text(f"extends: {base.name}\n", encoding="utf-8")
    return root, lambda path: Path(path).name == base.name


def _callers_reader(texts: Dict[Path, str]) -> Callable[..., Any]:
    """A reader of the shape ``resolve_config.read_once`` has: it reads the text,
    keeps it, and parses it through ``parse_config_text``."""

    def read(path: Path, expect: Optional[Tuple[int, int]] = None) -> Any:
        key = Path(path).resolve()
        texts[key] = read_config_text(path, expect=expect)
        return parse_config_text(path, texts[key])

    return read


def _resolve(root: Path, rule: Optional[Rule], **kwargs: Any) -> Any:
    return resolve_config_document(
        root, confine_to=root.parent, refuse_env=rule, **kwargs
    )


def _refusal(root: Path, rule: Rule, **kwargs: Any) -> ASHConfigEnvNotResolvedError:
    with pytest.raises(ASHConfigEnvNotResolvedError) as caught:
        _resolve(root, rule, **kwargs)
    return caught.value


@pytest.mark.parametrize("where", WHERE)
@pytest.mark.parametrize("kind", REFERENCES)
def test_the_refusal_is_one_text_whether_or_not_the_variable_is_set(
    tmp_path, monkeypatch, kind, where
):
    root, rule = _chain(tmp_path, kind, where)

    monkeypatch.delenv(PROBE, raising=False)
    unset = _refusal(root, rule)
    monkeypatch.setenv(PROBE, VALUE)
    present = _refusal(root, rule)

    assert str(unset) == str(present)
    assert VALUE not in str(present)
    assert "is not set" not in str(unset)


@pytest.mark.parametrize("where", WHERE)
@pytest.mark.parametrize("kind", REFERENCES)
def test_a_callers_own_reader_is_refused_the_same_way(
    tmp_path, monkeypatch, kind, where
):
    root, rule = _chain(tmp_path, kind, where)

    monkeypatch.delenv(PROBE, raising=False)
    kept: Dict[Path, str] = {}
    unset = _refusal(root, rule, reader=_callers_reader(kept), texts=kept)
    monkeypatch.setenv(PROBE, VALUE)
    kept = {}
    present = _refusal(root, rule, reader=_callers_reader(kept), texts=kept)

    assert str(unset) == str(present)
    assert VALUE not in str(present)
    assert "is not set" not in str(unset)


@pytest.mark.parametrize("kind", REFERENCES)
def test_read_config_file_with_a_rule_refuses_before_it_resolves(
    tmp_path, monkeypatch, kind
):
    """The direct reader decided before it resolved a reference already."""
    root, _rule = _chain(tmp_path, kind, "root")

    monkeypatch.delenv(PROBE, raising=False)
    with pytest.raises(ASHConfigEnvNotResolvedError) as unset:
        read_config_file(root, refuse_env=refuse_env_everywhere)
    monkeypatch.setenv(PROBE, VALUE)
    with pytest.raises(ASHConfigEnvNotResolvedError) as present:
        read_config_file(root, refuse_env=refuse_env_everywhere)

    assert str(unset.value) == str(present.value)
    assert VALUE not in str(present.value)


@pytest.mark.parametrize("where", WHERE)
@pytest.mark.parametrize("kind", ["yaml-plain", "toml"])
def test_a_file_the_rule_does_not_refuse_still_reports_an_unset_variable(
    tmp_path, monkeypatch, kind, where
):
    root, _rule = _chain(tmp_path, kind, where)
    monkeypatch.delenv(PROBE, raising=False)

    with pytest.raises(ASHConfigSourceError) as caught:
        _resolve(root, None)

    assert not isinstance(caught.value, ASHConfigEnvNotResolvedError)
    assert "is not set" in str(caught.value)


@pytest.mark.parametrize("where", WHERE)
@pytest.mark.parametrize("kind", REFERENCES)
def test_a_file_the_rule_does_not_refuse_resolves_the_variable(
    tmp_path, monkeypatch, kind, where
):
    root, _rule = _chain(tmp_path, kind, where)
    monkeypatch.setenv(PROBE, VALUE)

    document = _resolve(root, None)

    assert document.data["project_name"] == VALUE


def test_a_rule_that_refuses_another_file_leaves_this_one_unset_variable_alone(
    tmp_path, monkeypatch
):
    root, _rule = _chain(tmp_path, "yaml-plain", "root")
    monkeypatch.delenv(PROBE, raising=False)

    with pytest.raises(ASHConfigSourceError) as caught:
        _resolve(root, lambda path: Path(path).name == "other.yaml")

    assert "is not set" in str(caught.value)


def test_a_refused_file_that_reads_nothing_is_loaded(tmp_path):
    root = tmp_path / "ash.yaml"
    root.write_text("project_name: plain\n", encoding="utf-8")

    document = _resolve(root, refuse_env_everywhere)

    assert document.data["project_name"] == "plain"


def test_the_refusal_does_not_outlive_the_walk(tmp_path, monkeypatch):
    """A text parsed after a refused walk is resolved as it always was."""
    root, rule = _chain(tmp_path, "yaml-plain", "root")
    monkeypatch.setenv(PROBE, VALUE)
    _refusal(root, rule)

    parsed = parse_config_text(root, root.read_text(encoding="utf-8"))

    assert parsed == {"project_name": VALUE}
