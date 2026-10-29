# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A repository file that uses a YAML alias is refused, not half-loaded.

A YAML anchor lets two reporter sections share one options mapping, and
``copy.deepcopy`` keeps that sharing in the copy, so the operator-only strip
that pops a confined option once per section would pop the shared mapping twice
and raise KeyError on the second section. ASH does not try to load such a file:
``_NoAliasSafeLoader`` refuses every YAML alias while the document is composed,
so no section is ever shared and the strip never meets one.

The contract is the refusal, with the alias-free spelling as the control. The
aliased file is refused as a source error that gives the parser's type and
where it stopped (``could not be parsed (ComposerError at line N, column M)``)
and quotes none of the file; the same document with the value written out in
each section loads, settles each section's operator-only write against the
trusted base, warns about it, and holds the same project name and reporters.
Two routes reach the strip, and both refuse: the repository's own named config
file, and an operator ASH_CONFIG root that extends the repository's file.

The test names say "loads like the alias-free one" from the older contract,
where an alias loaded; they are kept so a test's id stays the same across the
change of contract.
"""

import json
import logging
from pathlib import Path

import pytest

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import ASHConfigSourceError

_ALIASED = (
    "project_name: shared-options\n"
    "reporters:\n"
    "  aws-security-hub:\n"
    "    options: &shared\n"
    "      findings_scope: suppressed\n"
    "  AwsSecurityHub:\n"
    "    options: *shared\n"
)

#: The alias on the whole reporter SECTION, not its options mapping.
_ALIASED_SECTION = (
    "project_name: shared-options\n"
    "reporters:\n"
    "  aws-security-hub: &shared\n"
    "    options:\n"
    "      findings_scope: suppressed\n"
    "  AwsSecurityHub: *shared\n"
)

#: The same document with each section carrying its own mapping.
_PLAIN = (
    "project_name: shared-options\n"
    "reporters:\n"
    "  aws-security-hub:\n"
    "    options:\n"
    "      findings_scope: suppressed\n"
    "  AwsSecurityHub:\n"
    "    options:\n"
    "      findings_scope: suppressed\n"
)


def _repository_file(root: Path, body: str) -> Path:
    named = root / ".ash" / ".ash.yaml"
    named.parent.mkdir(parents=True)
    named.write_text(body, encoding="utf-8")
    return named


def _assert_refused_at_parse(refused) -> None:
    """The refusal gives the parse place and none of the file's text."""
    said = str(refused.value)
    assert "could not be parsed (ComposerError at line " in said, said
    # Not the anchor's marker, nor a value or key the file wrote.
    assert "*shared" not in said and "findings_scope" not in said, said
    assert "suppressed" not in said, said


def _reporters_and_warnings(config, caplog):
    reporters = config.model_dump(mode="json")["reporters"]
    warned = [
        record.getMessage()
        for record in caplog.records
        if "findings_scope" in record.getMessage()
    ]
    return reporters, warned


def _assert_the_alias_free_control_loads(tmp_path, caplog, name):
    """The control: the alias-free spelling of the same document loads, the
    operator-only write is settled away and warned about, and the project name
    reads back as written."""
    control_root = tmp_path / name
    control_file = _repository_file(control_root, _PLAIN)
    with caplog.at_level(logging.WARNING):
        control = resolve_config(config_path=str(control_file), source_dir=control_root)
    _, control_warned = _reporters_and_warnings(control, caplog)

    dump = json.dumps(control.model_dump(mode="json"), default=str)
    assert '"findings_scope": "suppressed"' not in dump, dump[:400]
    assert control_warned, caplog.text
    assert control.project_name == "shared-options"


def test_an_aliased_repository_file_loads_like_the_alias_free_one(
    tmp_path, monkeypatch, caplog
):
    """The repository's own config file whose two reporter sections share one
    options mapping through a YAML alias is refused at parse, and the same
    document written out in each section loads (the control)."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)

    aliased_root = tmp_path / "aliased"
    aliased_file = _repository_file(aliased_root, _ALIASED)
    with pytest.raises(ASHConfigSourceError) as refused:
        resolve_config(config_path=str(aliased_file), source_dir=aliased_root)
    _assert_refused_at_parse(refused)

    _assert_the_alias_free_control_loads(tmp_path, caplog, "plain")


def test_a_whole_section_alias_loads_like_the_alias_free_one(
    tmp_path, monkeypatch, caplog
):
    """The alias shares the whole reporter section, not just its options
    mapping. The refusal is the same: the loader refuses the alias wherever it
    stands, so no copy of the section is ever needed. The alias-free control
    loads."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)

    aliased_root = tmp_path / "aliased-section"
    aliased_file = _repository_file(aliased_root, _ALIASED_SECTION)
    with pytest.raises(ASHConfigSourceError) as refused:
        resolve_config(config_path=str(aliased_file), source_dir=aliased_root)
    _assert_refused_at_parse(refused)

    _assert_the_alias_free_control_loads(tmp_path, caplog, "plain-section")


def test_an_operator_extends_of_an_aliased_repository_file_loads(
    tmp_path, monkeypatch, caplog
):
    """The second route to the strip: an operator ASH_CONFIG root extends the
    repository file whose sections share one options mapping. The chain
    refuses the base at parse, naming it as the base the operator's file
    extends. The same chain over the alias-free file loads, and the
    repository's operator-only write is settled away."""
    aliased_root = tmp_path / "aliased-project"
    aliased_named = _repository_file(aliased_root, _ALIASED)
    aliased_operator = tmp_path / "aliased-operator.yaml"
    aliased_operator.write_text(
        f"extends:\n  - {aliased_named.as_posix()}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(aliased_operator))
    with pytest.raises(ASHConfigSourceError) as refused:
        resolve_config(source_dir=aliased_root)
    _assert_refused_at_parse(refused)

    plain_root = tmp_path / "plain-project"
    plain_named = _repository_file(plain_root, _PLAIN)
    plain_operator = tmp_path / "plain-operator.yaml"
    plain_operator.write_text(
        f"extends:\n  - {plain_named.as_posix()}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(plain_operator))
    with caplog.at_level(logging.WARNING):
        config = resolve_config(source_dir=plain_root)

    dump = json.dumps(config.model_dump(mode="json"), default=str)
    assert '"findings_scope": "suppressed"' not in dump, dump[:400]
    assert any("findings_scope" in record.getMessage() for record in caplog.records), (
        caplog.text
    )
