# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An operator's patch never reaches a repository file that uses a YAML alias.

A YAML anchor in a repository file would make two sections, or two sections'
options, ONE mapping, so a patch adding an option through one section's pointer
could land in every section the alias shares. ASH closes that at the parse:
``_NoAliasSafeLoader`` refuses every YAML alias in a config file, so a
repository file that uses one is refused before any operator patch is applied,
and the refusal gives the parser's type and where it stopped
(``could not be parsed (ComposerError at line N, column M)``) and quotes none
of the file's text. The contract is the refusal, on both operator routes: a
named ``--config`` root and an ``ASH_CONFIG`` root, each extending the
repository's file.

The control is each shape's alias-free spelling, which must load: the patch
there lands where its pointer says and nowhere else. A shape whose alias-free
spelling stopped loading would pass for the wrong reason, so the premise is
checked before the refusal is.
"""

import json
import os
from pathlib import Path

import pytest

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import (
    ASHConfigSourceError,
    ASHConfigValidationError,
)
from tests.utils.helpers import mark_git_checkout

_REFUSED = (ASHConfigSourceError, ASHConfigValidationError)

#: Each shape is (aliased text, the same document spelled without the alias).
_SHAPES = {
    "hub-twins-share-options": (
        (
            "project_name: repository\nreporters:\n"
            "  aws-security-hub:\n    enabled: true\n    options: &shared\n"
            "      aws_region: repo-r0\n"
            "  AwsSecurityHub:\n    enabled: true\n    options: *shared\n"
        ),
        (
            "project_name: repository\nreporters:\n"
            "  aws-security-hub:\n    enabled: true\n    options:\n"
            "      aws_region: repo-r0\n"
            "  AwsSecurityHub:\n    enabled: true\n    options:\n"
            "      aws_region: repo-r0\n"
        ),
    ),
    "hub-shares-with-a-plain-reporter": (
        (
            "project_name: repository\nreporters:\n"
            "  aws-security-hub:\n    enabled: true\n    options: &shared\n"
            "      aws_region: repo-r0\n"
            "  zz-sink-reporter:\n    enabled: false\n    options: *shared\n"
        ),
        (
            "project_name: repository\nreporters:\n"
            "  aws-security-hub:\n    enabled: true\n    options:\n"
            "      aws_region: repo-r0\n"
            "  zz-sink-reporter:\n    enabled: false\n    options:\n"
            "      aws_region: repo-r0\n"
        ),
    ),
    "hub-shares-empty-options-with-sarif": (
        (
            "project_name: repository\nreporters:\n"
            "  aws-security-hub:\n    enabled: true\n    options: &shared {}\n"
            "  sarif:\n    enabled: true\n    options: *shared\n"
        ),
        (
            "project_name: repository\nreporters:\n"
            "  aws-security-hub:\n    enabled: true\n    options: {}\n"
            "  sarif:\n    enabled: true\n    options: {}\n"
        ),
    ),
    "hub-shares-empty-options-with-detect-secrets": (
        (
            "project_name: repository\nreporters:\n"
            "  aws-security-hub:\n    enabled: true\n    options: &shared {}\n"
            "scanners:\n  detect-secrets:\n    options: *shared\n"
        ),
        (
            "project_name: repository\nreporters:\n"
            "  aws-security-hub:\n    enabled: true\n    options: {}\n"
            "scanners:\n  detect-secrets:\n    options: {}\n"
        ),
    ),
}

#: Operator patches, each naming exactly one section.
_WRITES = {
    "patch-operator-only-reporter-option": (
        "patch:\n  - op: add\n"
        "    path: /reporters/aws-security-hub/options/findings_scope\n"
        "    value: suppressed\n"
    ),
    "patch-plain-option": (
        "patch:\n  - op: add\n"
        "    path: /reporters/aws-security-hub/options/aws_region\n"
        "    value: us-west-2\n"
    ),
    "patch-operator-only-scanner-option": (
        "patch:\n  - op: add\n"
        "    path: /scanners/detect-secrets/options/max_worker_output_mib\n"
        "    value: 4096\n"
    ),
}

_ROUTES = ["operator-config", "operator-ash-config"]


def _norm(text: str, base: Path) -> str:
    for spelling in {str(base), os.path.realpath(base), base.as_posix()}:
        text = text.replace(spelling, "<BASE>")
    return text


def _outcome(base, route, text, patch, monkeypatch):
    """How the chain resolves: ("loaded", <plugin dump>) or the refusal."""
    checkout = base / "checkout"
    repo = checkout / "cfg" / "repo.yaml"
    repo.parent.mkdir(parents=True)
    repo.write_text(text, encoding="utf-8")
    mark_git_checkout(checkout)
    root = base / "root.yaml"
    root.write_text(
        "project_name: operator\nextends:\n  - " + repo.as_posix() + "\n" + patch,
        encoding="utf-8",
    )
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    try:
        if route == "operator-config":
            config = resolve_config(config_path=root, source_dir=checkout)
        else:
            monkeypatch.setenv("ASH_CONFIG", str(root))
            monkeypatch.chdir(checkout)
            config = resolve_config(source_dir=checkout)
    except _REFUSED as exc:
        return ("refused", type(exc).__name__, _norm(str(exc), base))
    dump = config.model_dump(mode="json")
    kinds = {"reporters": dump["reporters"], "scanners": dump["scanners"]}
    return ("loaded", _norm(json.dumps(kinds, sort_keys=True, default=str), base))


def _cells():
    cells = []
    for shape in sorted(_SHAPES):
        scanner_shape = shape == "hub-shares-empty-options-with-detect-secrets"
        for write in sorted(_WRITES):
            if (write == "patch-operator-only-scanner-option") != scanner_shape:
                continue
            for route in _ROUTES:
                cells.append(
                    pytest.param(shape, route, write, id=f"{shape}-{route}-{write}")
                )
    return cells


@pytest.mark.parametrize("shape,route,write", _cells())
def test_an_operator_patch_lands_as_in_the_alias_free_spelling(
    tmp_path, monkeypatch, shape, route, write
):
    """The operator's patch names ONE section. The alias-free spelling of the
    repository file loads and takes the patch; the spelling with the alias is
    refused at parse, before the patch is applied, in words that name the
    place the parser stopped and quote nothing of the file."""
    aliased_text, plain_text = _SHAPES[shape]
    patch = _WRITES[write]
    aliased = _outcome(tmp_path / "a", route, aliased_text, patch, monkeypatch)
    plain = _outcome(tmp_path / "p", route, plain_text, patch, monkeypatch)
    if plain[0] != "loaded":
        raise RuntimeError(
            "premise: the alias-free spelling must load; got " + repr(plain)[:700]
        )
    assert aliased[0] == "refused" and aliased[1] == "ASHConfigSourceError", (
        aliased[0],
        tuple(piece[:700] for piece in aliased[1:]),
    )
    said = aliased[2]
    assert "could not be parsed (ComposerError at line " in said, said[:700]
    # Nothing of the file: not the anchor's name, not the alias marker.
    assert "shared" not in said and "*" not in said, said[:700]
