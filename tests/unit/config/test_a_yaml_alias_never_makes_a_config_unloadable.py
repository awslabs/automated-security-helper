# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A repository file's operator-only write never makes it unloadable.

A YAML anchor lets two reporter sections share one options mapping, and
``copy.deepcopy`` keeps that sharing in the copy, so the operator-only strip
that pops a confined option once per section used to pop the shared mapping
twice and raise KeyError on the second section. The contract is the one the
alias-free control shows: the file loads, each section's operator-only write
is settled against the trusted base and warned about, and the resolved
configuration holds the same reporters either way. Two routes reach the
strip: the repository's own named config file, and an operator ASH_CONFIG
root that extends the repository's file.
"""

import json
import logging
from pathlib import Path

from automated_security_helper.config.resolve_config import resolve_config

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


def _reporters_and_warnings(config, caplog):
    reporters = config.model_dump(mode="json")["reporters"]
    warned = [
        record.getMessage()
        for record in caplog.records
        if "findings_scope" in record.getMessage()
    ]
    return reporters, warned


def test_an_aliased_repository_file_loads_like_the_alias_free_one(
    tmp_path, monkeypatch, caplog
):
    """The repository's own config file whose two reporter sections share one
    options mapping through a YAML alias: the load succeeds, the operator-only
    write is settled away and warned about, and the resolved reporters equal
    the alias-free control's."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)

    aliased_root = tmp_path / "aliased"
    aliased_file = _repository_file(aliased_root, _ALIASED)
    with caplog.at_level(logging.WARNING):
        aliased = resolve_config(config_path=str(aliased_file), source_dir=aliased_root)
    aliased_reporters, aliased_warned = _reporters_and_warnings(aliased, caplog)
    caplog.clear()

    control_root = tmp_path / "plain"
    control_file = _repository_file(control_root, _PLAIN)
    with caplog.at_level(logging.WARNING):
        control = resolve_config(config_path=str(control_file), source_dir=control_root)
    control_reporters, control_warned = _reporters_and_warnings(control, caplog)

    # The write did not survive into the resolved configuration (the bare
    # word appears in unrelated default option names, so the probe is the
    # written pair)...
    dump = json.dumps(aliased.model_dump(mode="json"), default=str)
    assert '"findings_scope": "suppressed"' not in dump, dump[:400]
    # ...the aliased form resolves to what the alias-free form resolves to...
    assert aliased_reporters == control_reporters, (
        aliased_reporters,
        control_reporters,
    )
    # ...and both loads say what they settled.
    assert aliased_warned and control_warned, (aliased_warned, control_warned)


def test_a_whole_section_alias_loads_like_the_alias_free_one(
    tmp_path, monkeypatch, caplog
):
    """The alias shares the whole reporter section, so the un-sharing has to
    copy the section itself before its options mapping: a copy of the options
    alone still leaves both keys reading one section, whose second pop raises
    as the shared mapping's did. Same contract as the options-level cells."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)

    aliased_root = tmp_path / "aliased-section"
    aliased_file = _repository_file(aliased_root, _ALIASED_SECTION)
    with caplog.at_level(logging.WARNING):
        aliased = resolve_config(config_path=str(aliased_file), source_dir=aliased_root)
    aliased_reporters, aliased_warned = _reporters_and_warnings(aliased, caplog)
    caplog.clear()

    control_root = tmp_path / "plain-section"
    control_file = _repository_file(control_root, _PLAIN)
    with caplog.at_level(logging.WARNING):
        control = resolve_config(config_path=str(control_file), source_dir=control_root)
    control_reporters, control_warned = _reporters_and_warnings(control, caplog)

    dump = json.dumps(aliased.model_dump(mode="json"), default=str)
    assert '"findings_scope": "suppressed"' not in dump, dump[:400]
    assert aliased_reporters == control_reporters, (
        aliased_reporters,
        control_reporters,
    )
    assert aliased_warned and control_warned, (aliased_warned, control_warned)


def test_an_operator_extends_of_an_aliased_repository_file_loads(
    tmp_path, monkeypatch, caplog
):
    """The second route to the strip: an operator ASH_CONFIG root extends the
    repository file whose sections share one options mapping. The chain loads,
    and the repository's operator-only write is settled away."""
    root = tmp_path / "project"
    named = _repository_file(root, _ALIASED)
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends:\n  - {named.as_posix()}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))

    with caplog.at_level(logging.WARNING):
        config = resolve_config(source_dir=root)

    dump = json.dumps(config.model_dump(mode="json"), default=str)
    assert '"findings_scope": "suppressed"' not in dump, dump[:400]
    assert any("findings_scope" in record.getMessage() for record in caplog.records), (
        caplog.text
    )
