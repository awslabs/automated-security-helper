# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A patch pointer's plugin-section segment lands on the section it names.

A patch operation can spell a plugin section differently from the document:
in case as well as in "-" vs "_". The full document's pointer walk respells a
segment directly under a plugin segment onto the key the document already
holds with the same folded name -- the fold the view walk's settle step uses
-- so the op lands on that section instead of standing beside it or refusing
the load, and the two walks reach one canonical path. A repository file's
writes keep their confinement whatever the spelling: landing on the canonical
section is exactly what lets the confine hook judge them.

``extends`` joins every spelling the plugin lookup reads for one plugin into
one section, written under the overlay's spelling (config_sources.deep_merge,
"Spellings" in its module docstring). So after a chain merges, the document
holds ONE key per plugin section, and the chain's order decides which
spelling that is: the file extended last gives it. The cases below that put a
repository file's spelling beside the operator's therefore assert what that
join produces: one key, the patched value on it and readable through
``get_plugin_config``, and the typed pointer landing only where it names that
key (or where the operator's own spelling is the one that survives).
"""

import logging
from pathlib import Path

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.operator_only_options import reporter_section
from automated_security_helper.config.plugin_section_names import folded_section_name
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.plugin_modules.ash_aws_plugins.security_hub_reporter import (
    SecurityHubReporter,
)
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()

_HUB_FOLD = folded_section_name("aws-security-hub")


def _section(config):
    return reporter_section(config, SecurityHubReporter) or {}


def _hub_spellings(config):
    reporters = config.model_dump().get("reporters") or {}
    return [
        key
        for key in reporters
        if isinstance(key, str) and folded_section_name(key) == _HUB_FOLD
    ]


def _operator_chain(tmp_path, patch_lines):
    """own.yaml writes the section; operator.yaml extends it and patches."""
    own = tmp_path / "own.yaml"
    own.write_text(
        "project_name: op\nreporters:\n  aws-security-hub:\n    enabled: true\n"
        "    options:\n      aws_region: us-east-1\n",
        encoding="utf-8",
    )
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        f"extends:\n  - {own.as_posix()}\n" + patch_lines, encoding="utf-8"
    )
    return operator


@pytest.mark.parametrize(
    "spelling", ["AWS-Security-Hub", "Aws_Security_Hub", "AWSSECURITYHUB"]
)
def test_a_case_variant_patch_lands_on_the_section(tmp_path, monkeypatch, spelling):
    """A replace whose pointer spells the section with different case lands on
    the section the document holds: the load answers, the option carries the
    patched value, and no second section stands beside the real one."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    operator = _operator_chain(
        tmp_path,
        "patch:\n"
        "  - op: replace\n"
        f"    path: /reporters/{spelling}/options/aws_region\n"
        "    value: eu-west-1\n",
    )
    plain = tmp_path / "plain"
    plain.mkdir()
    monkeypatch.chdir(plain)

    config = resolve_config(config_path=operator)

    assert _options_region(config) == "eu-west-1", _section(config)
    assert len(_hub_spellings(config)) == 1, _hub_spellings(config)


def _options_region(config):
    return (_section(config).get("options") or {}).get("aws_region")


def _canonical_region(config):
    """The region the model's plugin lookup reads for the hub reporter, by the
    name ``get_plugin_config`` is asked under, whatever spelling the document
    holds the section under."""
    section = config.get_plugin_config(
        plugin_type="reporter", plugin_name="aws-security-hub"
    )
    if hasattr(section, "model_dump"):
        section = section.model_dump()
    return ((section or {}).get("options") or {}).get("aws_region")


def test_a_whole_section_add_shows_one_section(tmp_path, monkeypatch):
    """An add of the WHOLE section under a case-variant spelling folds onto
    the section the document holds: one section afterwards, carrying the
    added values, never a twin beside the one the exact-spelling lookup would
    read the old settings from."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    operator = _operator_chain(
        tmp_path,
        "patch:\n"
        "  - op: add\n"
        "    path: /reporters/AWS-Security-Hub\n"
        "    value:\n"
        "      enabled: true\n"
        "      options:\n"
        "        aws_region: eu-west-1\n",
    )
    plain = tmp_path / "plain"
    plain.mkdir()
    monkeypatch.chdir(plain)

    config = resolve_config(config_path=operator)

    assert len(_hub_spellings(config)) == 1, _hub_spellings(config)
    assert _options_region(config) == "eu-west-1", _section(config)


def test_premise_a_split_type_word_folds_by_name_and_reduces_differently():
    """The shape the next cell turns on: the two spellings fold to one
    section name, while the plugin-name reduction -- which strips the
    Converter/Scanner/Reporter word only where it stands whole -- reads them
    as different plugins, so the shared fold identity keeps them apart."""
    from automated_security_helper.config.ash_config import (
        reduced_plugin_name,
        section_fold_key,
    )

    held, typed = "bedrock-summary-reporter", "bedrock-summary-repo_rter"
    assert folded_section_name(held) == folded_section_name(typed)
    assert reduced_plugin_name(held) != reduced_plugin_name(typed)
    assert section_fold_key(held) != section_fold_key(typed)


def test_a_split_type_word_spelling_does_not_fold(tmp_path, monkeypatch):
    """A spelling whose type word a separator splits names no plugin the
    config lookup reads. Folding it in the document while the view's settle
    kept it apart showed the patched value on the model while the off-host
    reporter ran the unpatched one. Both walks read one fold identity
    (section_fold_key), so the segment stays as typed on both sides and the
    replace at the absent key refuses the load by its own path -- the model
    cannot show a value that will not run."""
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    repository = checkout / ".ash" / ".ash.yaml"
    repository.parent.mkdir(parents=True, exist_ok=True)
    repository.write_text("project_name: repository\n", encoding="utf-8")
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        "extends:\n  - " + repository.as_posix() + "\n"
        "reporters:\n  bedrock-summary-reporter:\n    enabled: true\n"
        "    options:\n      aws_region: us-east-1\n"
        "patch:\n  - op: replace\n"
        "    path: /reporters/bedrock-summary-repo_rter/options/aws_region\n"
        "    value: us-west-2\n",
        encoding="utf-8",
    )

    with pytest.raises(ASHConfigSourceError, match="bedrock-summary-repo_rter"):
        resolve_config(config_path=operator, source_dir=checkout)


def test_the_relax_check_reads_the_folds_identity_not_the_sections_name(
    tmp_path, monkeypatch
):
    """The operator's files own a split-type-word spelling, which the fold
    identity (section_fold_key) keeps apart from the real plugin section the
    repository wrote (the premise cell above pins the two reductions apart).
    A case-variant pointer at the real section shares a fold with no owned
    key, so the restriction relaxes and the pointer folds onto the
    repository's only key. Relaxing by the folded section NAME instead reads
    the split spelling as a spelling of the section -- both reduce to the
    plugin's name -- keeps the restriction on over a section the operator
    never spelled, and the patch misses the repository's key."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    repository = checkout / ".ash" / ".ash.yaml"
    repository.parent.mkdir(parents=True, exist_ok=True)
    repository.write_text(
        "project_name: repository\nreporters:\n  bedrock-summary-reporter:\n"
        "    enabled: true\n    options:\n      aws_region: repo-r0\n",
        encoding="utf-8",
    )
    own = tmp_path / "own.yaml"
    own.write_text(
        "reporters:\n  bedrock-summary-repo_rter:\n    enabled: false\n",
        encoding="utf-8",
    )
    root = tmp_path / "operator.yaml"
    root.write_text(
        f"extends:\n  - {own.as_posix()}\n  - {repository.as_posix()}\n"
        "patch:\n  - op: replace\n"
        "    path: /reporters/Bedrock-Summary-Reporter/options/aws_region\n"
        "    value: us-west-2\n",
        encoding="utf-8",
    )

    config = resolve_config(config_path=root, source_dir=checkout)

    reporters = config.model_dump().get("reporters") or {}
    patched = reporters.get("bedrock-summary-reporter") or {}
    assert (patched.get("options") or {}).get("aws_region") == "us-west-2", reporters
    assert "Bedrock-Summary-Reporter" not in reporters, reporters


def test_an_add_at_the_swap_of_a_repository_only_key_lands_on_it(tmp_path, monkeypatch):
    """An add typed at the uniform swap of a section only the repository
    wrote: the operator's chain owns no spelling of the fold, so the segment
    resolves as it does without ownership, onto the repository's key, and
    the add writes there. Creating a second key beside the repository's --
    the typed spelling as its own section -- would put a twin in the
    document that neither walk reads."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    repository = checkout / ".ash" / ".ash.yaml"
    repository.parent.mkdir(parents=True, exist_ok=True)
    repository.write_text(
        "project_name: repository\nreporters:\n  aws-security-hub:\n"
        "    enabled: false\n    options:\n      aws_region: repo-r0\n",
        encoding="utf-8",
    )
    root = tmp_path / "operator.yaml"
    root.write_text(
        f"extends:\n  - {repository.as_posix()}\n"
        "patch:\n  - op: add\n"
        "    path: /reporters/aws_security_hub\n"
        "    value:\n      enabled: true\n"
        "      options:\n        aws_region: us-west-2\n",
        encoding="utf-8",
    )

    config = resolve_config(config_path=root, source_dir=checkout)

    reporters = config.model_dump().get("reporters") or {}
    hubs = {
        key: value
        for key, value in reporters.items()
        if "security" in key.lower().replace("-", "_") and value
    }
    assert sorted(hubs) == ["aws-security-hub"], sorted(hubs)
    section = hubs["aws-security-hub"]
    assert (section.get("options") or {}).get("aws_region") == "us-west-2", hubs


def test_control_a_repository_case_variant_patch_keeps_the_off_host_section(
    tmp_path, monkeypatch, caplog
):
    """The confinement control: a REPOSITORY file's patch spelled case-variant
    still does not reach the off-host section. Folding the pointer onto the
    canonical section must change where the op lands, never whose write it
    is."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    repository = checkout / ".ash" / ".ash.yaml"
    repository.parent.mkdir(parents=True, exist_ok=True)
    repository.write_text(
        "reporters: {}\n"
        "patch:\n"
        "  - op: add\n"
        "    path: /reporters/AWS-Security-Hub\n"
        "    value:\n"
        "      enabled: true\n"
        "      options:\n"
        "        aws_region: repo-region\n",
        encoding="utf-8",
    )
    operator = tmp_path / "operator.yaml"
    operator.write_text(f"extends:\n  - {repository.as_posix()}\n", encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        config = resolve_config(config_path=operator, source_dir=checkout)
        section = _section(config)

    assert section.get("enabled") is not True, section
    assert (section.get("options") or {}).get("aws_region") != "repo-region", section


def test_an_exact_key_wins_over_an_earlier_twin():
    """A pointer that names an existing key exactly is never folded away,
    even when a case-variant twin of the same section stands earlier in the
    document: the op lands on the key it names. (At this fold's scope the
    guard is also implied by the exactly-one-match rule -- the named key is
    in its own match set -- so this cell pins the behavior itself.)"""
    from automated_security_helper.config.config_sources import _normalize_pointer

    document = {"reporters": {"AwsSecurityHub": {}, "aws-security-hub": {}}}
    assert (
        _normalize_pointer(document, "/reporters/aws-security-hub/enabled")
        == "/reporters/aws-security-hub/enabled"
    )


@pytest.mark.parametrize("segment", ["scanners", "converters"])
def test_the_fold_covers_every_plugin_segment(segment):
    """The fold is not a reporters-only rule: a case-variant pointer under
    scanners or converters lands on the held section the same way, so an
    operator-only option under those segments is judged on the canonical
    section too."""
    from automated_security_helper.config.config_sources import _normalize_pointer

    document = {segment: {"detect-secrets": {"options": {}}}}
    assert (
        _normalize_pointer(document, "/" + segment + "/Detect-Secrets/options")
        == "/" + segment + "/detect-secrets/options"
    )


def _model_hub_sections(config):
    reporters = config.model_dump().get("reporters") or {}
    return {
        key: value
        for key, value in reporters.items()
        if isinstance(key, str)
        and folded_section_name(key) == _HUB_FOLD
        and isinstance(value, dict)
    }


def test_a_repository_case_variant_patch_on_its_own_section_stays_out(
    tmp_path, monkeypatch
):
    """The fold taken INSIDE a repository file: it holds the off-host section
    and patches it under two case variants. The patch lands on the held
    section -- one section in the model, no second key beside it -- and
    neither the model's section nor the reporter takes the repository's
    enable or region, which the confine hook leaves out. The
    committed control above writes an empty ``reporters`` mapping, so its
    pointer has nothing to fold onto; this one proves the confinement with
    the fold actually taken."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    repository = checkout / ".ash" / ".ash.yaml"
    repository.parent.mkdir(parents=True, exist_ok=True)
    repository.write_text(
        "reporters:\n  aws-security-hub:\n    enabled: false\n"
        "    options:\n      aws_region: repo-r0\n"
        "patch:\n  - op: replace\n    path: /reporters/AWS-Security-Hub/enabled\n"
        "    value: true\n"
        "  - op: replace\n    path: /reporters/AwsSecurityHub/options/aws_region\n"
        "    value: repo-region\n",
        encoding="utf-8",
    )
    operator = tmp_path / "operator.yaml"
    operator.write_text(f"extends:\n  - {repository.as_posix()}\n", encoding="utf-8")

    config = resolve_config(config_path=operator, source_dir=checkout)

    held = _model_hub_sections(config)
    # Premise: the fold landed both ops on the held section, so no second
    # key stands beside it; the confine hook then leaves the off-host
    # options the repository's ops set out of the model's section too.
    assert list(held) == ["aws-security-hub"], held
    assert ((held["aws-security-hub"].get("options") or {}).get("aws_region")) != (
        "repo-region"
    ), held
    assert held["aws-security-hub"].get("enabled") is not True, held
    ran = _section(config)
    assert ran.get("enabled") is not True, ran
    assert (ran.get("options") or {}).get("aws_region") != "repo-region", ran


def _shown_and_ran(config):
    """What the model shows for the hub section, and what the reporter runs,
    each as its (aws_region, enabled) pair."""
    from automated_security_helper.base.plugin_config import plugin_config_key
    from automated_security_helper.config.operator_only_options import (
        _reporter_section_of,
    )

    def pair(section):
        if section is None:
            plain = {}
        elif hasattr(section, "model_dump"):
            plain = section.model_dump()
        else:
            plain = dict(section)
        return (plain.get("options") or {}).get("aws_region"), plain.get("enabled")

    shown = _reporter_section_of(config, plugin_config_key(SecurityHubReporter))
    return pair(shown), pair(_section(config))


def _twin_chain(tmp_path, order, patch_lines, repository_reporters=True):
    """own.yaml writes the section, the repository's file holds a case-variant
    twin of it (or none), and the root extends both in *order* and patches."""
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    repository = checkout / ".ash" / ".ash.yaml"
    repository.parent.mkdir(parents=True, exist_ok=True)
    repository_text = "project_name: repository\n"
    if repository_reporters:
        repository_text += (
            "reporters:\n  AwsSecurityHub:\n    enabled: false\n"
            "    options:\n      aws_region: repo-r0\n"
        )
    repository.write_text(repository_text, encoding="utf-8")
    own = tmp_path / "own.yaml"
    own.write_text(
        "reporters:\n  aws-security-hub:\n    enabled: true\n"
        "    options:\n      aws_region: us-east-1\n",
        encoding="utf-8",
    )
    bases = [own, repository] if order == "own-first" else [repository, own]
    root = tmp_path / "operator.yaml"
    root.write_text(
        "extends:\n"
        + "".join(f"  - {base.as_posix()}\n" for base in bases)
        + patch_lines,
        encoding="utf-8",
    )
    return checkout, root


_TWIN_PATCHES = {
    "add-whole": (
        "patch:\n"
        "  - op: add\n"
        "    path: /reporters/AWS_Security_Hub\n"
        "    value:\n"
        "      enabled: true\n"
        "      options:\n"
        "        aws_region: us-west-2\n"
    ),
    "replace-deep": (
        "patch:\n"
        "  - op: replace\n"
        "    path: /reporters/AWS_Security_Hub/options/aws_region\n"
        "    value: us-west-2\n"
    ),
    "add-deep": (
        "patch:\n"
        "  - op: add\n"
        "    path: /reporters/AWS_Security_Hub/options/aws_region\n"
        "    value: us-west-2\n"
    ),
}


@pytest.mark.parametrize("op_name", sorted(_TWIN_PATCHES))
@pytest.mark.parametrize("order", ["own-first", "repository-first"])
def test_a_repository_twin_neither_blocks_nor_captures_the_operators_patch(
    tmp_path, monkeypatch, order, op_name
):
    """The repository's file holds a case-variant twin of the section the
    operator's own file writes, and the operator's root patches it under a
    third spelling. ``extends`` joins the two into one section under the
    spelling of the file extended last.

    Extended repository-first, that is the operator's spelling: the pointer
    folds onto it, every op lands, one key stands, and the model shows what
    the off-host reporter runs. Extended own-first it is the repository's
    spelling, which the operator's files never wrote, so the ownership the
    pointer fold resolves against cannot find it: a deep op typed in a third
    spelling is refused as not fitting the document, and the whole-section
    add lands under the typed key, where the model and the reporter view
    still agree."""
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout, root = _twin_chain(tmp_path, order, _TWIN_PATCHES[op_name])

    if order == "own-first" and op_name != "add-whole":
        with pytest.raises(ASHConfigSourceError, match="does not fit the document"):
            resolve_config(config_path=root, source_dir=checkout)
        return

    config = resolve_config(config_path=root, source_dir=checkout)

    shown, ran = _shown_and_ran(config)
    assert shown == ran == ("us-west-2", True), (shown, ran)
    assert _canonical_region(config) == "us-west-2", _model_hub_sections(config)
    if order == "repository-first":
        assert list(_model_hub_sections(config)) == ["aws-security-hub"], (
            _model_hub_sections(config)
        )


def _twin_capture_chain(tmp_path, twin_key, operator_key, patch_spelling):
    """The repository holds *twin_key*; the operator's own file writes
    *operator_key*; the root patches a deep option under *patch_spelling*."""
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    repository = checkout / ".ash" / ".ash.yaml"
    repository.parent.mkdir(parents=True, exist_ok=True)
    repository.write_text(
        f"project_name: repository\nreporters:\n  {twin_key}:\n"
        "    enabled: false\n    options:\n      aws_region: repo-r0\n",
        encoding="utf-8",
    )
    own = tmp_path / "own.yaml"
    own.write_text(
        f"reporters:\n  {operator_key}:\n    enabled: true\n"
        "    options:\n      aws_region: us-east-1\n",
        encoding="utf-8",
    )
    root = tmp_path / "operator.yaml"
    root.write_text(
        f"extends:\n  - {own.as_posix()}\n  - {repository.as_posix()}\n"
        "patch:\n"
        "  - op: replace\n"
        f"    path: /reporters/{patch_spelling}/options/aws_region\n"
        "    value: us-west-2\n",
        encoding="utf-8",
    )
    return checkout, root


@pytest.mark.parametrize(
    "twin_key, operator_key, patch_spelling",
    [
        ("AwsSecurityHub", "aws-security-hub", "AwsSecurityHub"),
        ("Aws-Security-Hub", "aws-security-hub", "Aws_Security_Hub"),
        ("aws-security-hub", "AWS-Security-Hub", "aws-security-hub"),
        ("AWS-Security-Hub", "aws-security-hub", "AWS_Security_Hub"),
    ],
    ids=[
        "exact-twin",
        "separator-swap-of-twin",
        "canonical-twin",
        "swap-of-uppercase-twin",
    ],
)
def test_a_repository_key_matching_the_typed_spelling_does_not_capture(
    tmp_path, monkeypatch, twin_key, operator_key, patch_spelling
):
    """The repository's file writes a spelling of the section that the
    operator's own file writes another way, and the repository is extended
    last, so the join leaves the repository's spelling as the section's one
    key. The operator's patch segment names that key when it is typed exactly
    as the repository wrote it (the exact twin, or the plugin's canonical
    spelling): the patch lands there, the model and the reporter view read
    the patched region, and no second key stands. Typed any other way, even
    as a "-"/"_" swap or a case variant of it, the pointer folds only onto
    keys the operator's own files wrote, finds none in the document, and the
    load is refused as a path that does not fit."""
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout, root = _twin_capture_chain(
        tmp_path, twin_key, operator_key, patch_spelling
    )

    if patch_spelling != twin_key:
        with pytest.raises(ASHConfigSourceError, match="does not fit the document"):
            resolve_config(config_path=root, source_dir=checkout)
        return

    config = resolve_config(config_path=root, source_dir=checkout)

    assert (_section(config).get("options") or {}).get("aws_region") == "us-west-2"
    hubs = _model_hub_sections(config)
    assert list(hubs) == [twin_key], hubs
    assert (hubs[twin_key].get("options") or {}).get("aws_region") == "us-west-2", hubs
    assert _canonical_region(config) == "us-west-2", hubs


def test_a_mixed_separator_repository_twin_neither_blocks_nor_joins(
    tmp_path, monkeypatch
):
    """The operator's key and the repository's twin each mix their
    separators, differently, and the repository is extended last, so the join
    leaves the twin's spelling as the one key. A third spelling typed in the
    operator's patch names neither mixed key, and the pointer folds only onto
    keys the operator's own files wrote, so the load is refused as a path
    that does not fit. The fold must not read the twin as a spelling of the
    operator's write (treating every "-" as "_" did, and made the match
    ambiguous), so the refusal is the plain one."""
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout, root = _twin_capture_chain(
        tmp_path, "aws-security_hub", "aws_security-hub", "AWS_SECURITY_HUB"
    )

    with pytest.raises(
        ASHConfigSourceError, match="does not fit the document"
    ) as refused:
        resolve_config(config_path=root, source_dir=checkout)

    assert "ambiguous" not in str(refused.value), str(refused.value)


@pytest.mark.parametrize(
    "twin_key",
    ["aws_security_hub", "aws-security-hub"],
    ids=["underscore-swap-of-operator", "dash-swap-of-operator"],
)
def test_an_apart_uniform_swap_twin_does_not_capture_the_pointer(
    tmp_path, monkeypatch, twin_key
):
    """The operator's own file writes a mixed-separator key first; the
    repository later writes one of its uniform "-"/"_" swaps. The join leaves
    the repository's spelling as the section's one key, and an exact pointer
    at that spelling names a key of the document, so the patch lands on it
    and the model reads the patched region under it."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout, root = _twin_capture_chain(
        tmp_path, twin_key, "aws_security-hub", twin_key
    )

    config = resolve_config(config_path=root, source_dir=checkout)

    hubs = _model_hub_sections(config)
    assert list(hubs) == [twin_key], hubs
    assert (hubs[twin_key].get("options") or {}).get("aws_region") == "us-west-2", hubs
    assert _canonical_region(config) == "us-west-2", hubs


def test_the_pointer_folds_onto_the_operators_key_beside_its_apart_swap():
    """Unit shape of the chain cells above: with the operator's mixed
    spelling and its uniform swap both keys of the document, the pointer at
    the swap's spelling folds onto the owned key. The swap arm of the
    ownership compare must not read a key as owned while the owned spelling
    itself stands in the document."""
    from automated_security_helper.config.config_sources import _normalize_pointer

    document = {
        "reporters": {
            "aws_security-hub": {"enabled": True},
            "aws_security_hub": {"enabled": False},
        }
    }
    owned = {"reporters": {"aws_security-hub"}}

    pointer = _normalize_pointer(
        document, "/reporters/aws_security_hub/options/aws_region", owned
    )

    assert pointer == "/reporters/aws_security-hub/options/aws_region", pointer


def test_a_twin_reached_through_the_repository_is_not_the_operators(
    tmp_path, monkeypatch
):
    """Ownership stops at a repository file: a base reached THROUGH the
    repository's file is the repository's wherever it sits, exactly as the
    operator view reads the chain. The twin that base writes is extended
    last, so the join leaves its spelling as the section's one key; the
    operator's third spelling folds only onto keys the operator's own files
    wrote, finds none, and the load is refused as a path that does not fit.
    Counting that base's keys as the operator's own would have matched the
    twin and landed the patch on the repository's section."""
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    vendor = tmp_path / "vendor.yaml"
    vendor.write_text(
        "reporters:\n  AwsSecurityHub:\n    enabled: false\n"
        "    options:\n      aws_region: repo-r0\n",
        encoding="utf-8",
    )
    repository = checkout / ".ash" / ".ash.yaml"
    repository.parent.mkdir(parents=True, exist_ok=True)
    repository.write_text(f"extends:\n  - {vendor.as_posix()}\n", encoding="utf-8")
    own = tmp_path / "own.yaml"
    own.write_text(
        "reporters:\n  aws-security-hub:\n    enabled: true\n"
        "    options:\n      aws_region: us-east-1\n",
        encoding="utf-8",
    )
    root = tmp_path / "operator.yaml"
    root.write_text(
        f"extends:\n  - {own.as_posix()}\n  - {repository.as_posix()}\n"
        "patch:\n"
        "  - op: replace\n"
        "    path: /reporters/AWS_Security_Hub/options/aws_region\n"
        "    value: us-west-2\n",
        encoding="utf-8",
    )

    with pytest.raises(ASHConfigSourceError, match="does not fit the document"):
        resolve_config(config_path=root, source_dir=checkout)


def test_an_environment_reference_follows_the_ownership_folded_patch(
    tmp_path, monkeypatch
):
    """The reference replay applies each operation at the path the chain
    read chose, with the ownership it had then. Re-normalizing against the
    replay's own copy without that ownership leaves the pointer ambiguous
    beside the repository's twin, the operation misfits the copy, and the
    whole load is refused for a chain the read itself took."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.setenv("ASH_ZZ_TWIN_REGION", "us-east-1")
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    repository = checkout / ".ash" / ".ash.yaml"
    repository.parent.mkdir(parents=True, exist_ok=True)
    repository.write_text(
        "project_name: repository\nreporters:\n  AwsSecurityHub:\n    enabled: false\n",
        encoding="utf-8",
    )
    own = tmp_path / "own.yaml"
    own.write_text(
        "reporters:\n  aws-security-hub:\n    enabled: true\n"
        "    options:\n      aws_region: !ENV ${ASH_ZZ_TWIN_REGION}\n",
        encoding="utf-8",
    )
    root = tmp_path / "operator.yaml"
    # Repository first: the join leaves the operator's spelling as the one
    # key, which the ownership fold finds for the typed variant.
    root.write_text(
        f"extends:\n  - {repository.as_posix()}\n  - {own.as_posix()}\n"
        "patch:\n"
        "  - op: add\n"
        "    path: /reporters/AWS_Security_Hub/options/zz-extra\n"
        "    value: 1\n",
        encoding="utf-8",
    )

    config = resolve_config(config_path=root, source_dir=checkout)

    assert _options_region(config) == "us-east-1", _section(config)
    assert "us-east-1" in list(config._environment_values), config._environment_values


def test_a_whole_segment_write_anchors_its_keys_for_later_ops(tmp_path, monkeypatch):
    """An operation that writes a whole plugin segment writes every section
    inside its value, so a later operation of the same file folds onto a
    key that value introduced, as it folds onto a section the file wrote in
    YAML. Recording only two-segment paths left the introduced key unowned:
    the later variant pointer matched no owned key, stayed as typed and
    refused a load whose spellings were all the operator's own."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    operator = _operator_chain(
        tmp_path,
        "patch:\n"
        "  - op: replace\n"
        "    path: /reporters\n"
        "    value:\n"
        "      AwsSecurityHub:\n"
        "        enabled: true\n"
        "        options:\n"
        "          aws_region: us-east-1\n"
        "  - op: replace\n"
        "    path: /reporters/aws_security_hub/options/aws_region\n"
        "    value: us-west-2\n",
    )
    plain = tmp_path / "plain"
    plain.mkdir()
    monkeypatch.chdir(plain)

    config = resolve_config(config_path=operator)

    assert _options_region(config) == "us-west-2", _section(config)
    assert len(_hub_spellings(config)) == 1, _hub_spellings(config)


def test_a_whole_document_write_anchors_its_keys_for_later_ops(tmp_path, monkeypatch):
    """An operation that rewrites the whole document writes every section its
    value's plugin segments hold, so a later operation of the same file folds
    onto a key the rewrite introduced, exactly as it folds onto one a
    whole-segment write introduced. Recording only pointers that start under
    a plugin segment left the rewrite's keys unowned: the later variant
    pointer matched no owned key, stayed as typed and refused a load whose
    spellings were all the operator's own."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    operator = _operator_chain(
        tmp_path,
        "patch:\n"
        "  - op: replace\n"
        '    path: ""\n'
        "    value:\n"
        "      project_name: rewritten\n"
        "      reporters:\n"
        "        AwsSecurityHub:\n"
        "          enabled: true\n"
        "          options:\n"
        "            aws_region: us-east-1\n"
        "  - op: replace\n"
        "    path: /reporters/aws_security_hub/options/aws_region\n"
        "    value: us-west-2\n",
    )
    plain = tmp_path / "plain"
    plain.mkdir()
    monkeypatch.chdir(plain)

    config = resolve_config(config_path=operator)

    assert _options_region(config) == "us-west-2", _section(config)
    assert len(_hub_spellings(config)) == 1, _hub_spellings(config)


def test_a_test_op_grants_no_ownership(tmp_path):
    """A ``test`` operation asserts and writes nothing, so it anchors no
    owned spelling: recording its path as an owned write let the next
    operation fold onto the repository's section, which only that test op
    had touched. The operator's chain owns another spelling of the section
    (the restriction is active), so the variant patch matches no owned key
    in the document, stays as typed and misfits."""
    from automated_security_helper.config.config_sources import _apply_patch
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    document = {
        "reporters": {
            "AwsSecurityHub": {"enabled": False, "options": {"aws_region": "repo-r0"}}
        }
    }
    # The operator's files wrote this spelling and a later remove of their
    # own dropped it: the merge never replaces a key with a case variant (a
    # case twin stands apart), so an owned spelling absent beside a twin is
    # a state only an operator remove produces.
    owned = {"reporters": {"aws-security-hub"}}
    ops = [
        {
            "op": "test",
            "path": "/reporters/AwsSecurityHub",
            "value": {"enabled": False, "options": {"aws_region": "repo-r0"}},
        },
        {
            "op": "replace",
            "path": "/reporters/AWS_SECURITY_HUB/options/aws_region",
            "value": "us-west-2",
        },
    ]

    with pytest.raises(ASHConfigSourceError):
        _apply_patch(document, ops, Path("operator.yaml"), owned=owned)


#: The repository writes BOTH uniform swaps of the operator's mixed key.
_BOTH_SWAPS = ("aws_security_hub", "aws-security-hub")
_MIXED_KEYS = ("aws-security_hub", "aws_security-hub")
_BOTH_SWAP_OPS = {
    "replace-deep": (
        "  - op: replace\n"
        "    path: /reporters/{spelling}/options/aws_region\n"
        "    value: us-west-2\n"
    ),
    "add-deep": (
        "  - op: add\n"
        "    path: /reporters/{spelling}/options/aws_region\n"
        "    value: us-west-2\n"
    ),
    "add-whole": (
        "  - op: add\n"
        "    path: /reporters/{spelling}\n"
        "    value:\n      enabled: true\n"
        "      options:\n        aws_region: us-west-2\n"
    ),
}


@pytest.mark.parametrize("op_name", sorted(_BOTH_SWAP_OPS))
@pytest.mark.parametrize("typed", ["joined-swap", "apart-swap", "third", "own-exact"])
@pytest.mark.parametrize("order", ["own-first", "repository-first"])
@pytest.mark.parametrize("mixed", _MIXED_KEYS)
def test_beside_both_swaps_only_the_joined_key_counts_as_the_operators(
    tmp_path, monkeypatch, mixed, order, typed, op_name
):
    """ONE repository file writes both uniform swaps of the operator's mixed
    key. The join puts all three spellings in one section under the spelling
    of the file extended last: the operator's mixed key when the repository
    is extended first, the repository's last-written swap when it is
    extended last. Whatever the typed spelling and the op, the patch loads
    and lands on that one key: the document holds no second key for it to be
    split over or to land beside, the model reads the patched region under
    the plugin's own name, and the reporter view agrees."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    joined, apart = _BOTH_SWAPS
    spelling = {
        "joined-swap": joined,
        "apart-swap": apart,
        "third": "AWS_Security_Hub",
        "own-exact": mixed,
    }[typed]
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    repository = checkout / ".ash" / ".ash.yaml"
    repository.parent.mkdir(parents=True, exist_ok=True)
    repository.write_text(
        "project_name: repository\nreporters:\n"
        + "".join(
            f"  {key}:\n    enabled: false\n    options:\n      aws_region: repo-r0\n"
            for key in _BOTH_SWAPS
        ),
        encoding="utf-8",
    )
    own = tmp_path / "own.yaml"
    own.write_text(
        f"reporters:\n  {mixed}:\n    enabled: true\n"
        "    options:\n      aws_region: us-east-1\n",
        encoding="utf-8",
    )
    bases = [own, repository] if order == "own-first" else [repository, own]
    root = tmp_path / "operator.yaml"
    root.write_text(
        f"extends:\n  - {bases[0].as_posix()}\n  - {bases[1].as_posix()}\n"
        "patch:\n" + _BOTH_SWAP_OPS[op_name].format(spelling=spelling),
        encoding="utf-8",
    )
    # The key that survives the join is the overlay's: the mixed key when the
    # operator's file is extended last, otherwise the last swap the
    # repository's file wrote.
    survivor = mixed if order == "repository-first" else apart

    config = resolve_config(config_path=root, source_dir=checkout)

    hubs = _model_hub_sections(config)
    assert list(hubs) == [survivor], hubs
    assert (hubs[survivor].get("options") or {}).get("aws_region") == "us-west-2", hubs
    assert _canonical_region(config) == "us-west-2", hubs
    assert _options_region(config) == "us-west-2", _section(config)


def _guarded_write_chain(tmp_path, own_key, twin_key, spelling, order, tested):
    """The operator guards a write with a test op under the same pointer:
    *own_key* is the operator's section (region us-east-1), *twin_key* the
    repository's (region repo-r0), and the root tests *tested* at *spelling*
    then replaces the same pointer."""
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    repository = checkout / ".ash" / ".ash.yaml"
    repository.parent.mkdir(parents=True, exist_ok=True)
    repository.write_text(
        f"project_name: repository\nreporters:\n  {twin_key}:\n"
        "    enabled: false\n    options:\n      aws_region: repo-r0\n",
        encoding="utf-8",
    )
    own = tmp_path / "own.yaml"
    own.write_text(
        f"reporters:\n  {own_key}:\n    enabled: true\n"
        "    options:\n      aws_region: us-east-1\n",
        encoding="utf-8",
    )
    bases = [own, repository] if order == "own-first" else [repository, own]
    pointer = f"/reporters/{spelling}/options/aws_region"
    root = tmp_path / "operator.yaml"
    root.write_text(
        f"extends:\n  - {bases[0].as_posix()}\n  - {bases[1].as_posix()}\n"
        "patch:\n"
        "  - op: test\n"
        f"    path: {pointer}\n"
        f"    value: {tested}\n"
        "  - op: replace\n"
        f"    path: {pointer}\n"
        "    value: us-west-2\n",
        encoding="utf-8",
    )
    return checkout, root


#: case -> (the operator's key, the repository twin, the typed segment)
_GUARDED_CASES = {
    "own-exact": ("aws-security-hub", "AwsSecurityHub", "aws-security-hub"),
    "swap-of-own": ("aws-security-hub", "AwsSecurityHub", "aws_security_hub"),
    "twin-exact": ("aws-security-hub", "AwsSecurityHub", "AwsSecurityHub"),
    "swap-of-twin": ("aws-security-hub", "AWS-Security-Hub", "AWS_Security_Hub"),
    "third": ("aws-security-hub", "AwsSecurityHub", "AWS_Security_Hub"),
}


@pytest.mark.parametrize("expected", ["operator-value", "repository-value"])
@pytest.mark.parametrize("order", ["own-first", "repository-first"])
@pytest.mark.parametrize("case", sorted(_GUARDED_CASES))
def test_a_test_op_checks_the_key_its_write_under_the_same_pointer_lands_on(
    tmp_path, monkeypatch, case, order, expected
):
    """The operator guards its write with a test op under the same pointer.
    A test op's pointer resolves with the same ownership as the write's, so
    the guard and the write aim at one key. The join leaves ONE key for the
    section, under the spelling of the file extended last, and that key holds
    the merged values: the operator's region when the operator's file is
    extended last, the repository's when the repository's is. Extended
    repository-first, any typed spelling folds onto the operator's key and
    the guard holds exactly when it tests the operator's value. Extended
    own-first, the surviving key is the repository's spelling, which the
    operator's files never wrote, so only a pointer typed exactly as that
    spelling finds it (and then tests the repository's value); any other
    spelling finds no key, and the guard, which cannot hold, refuses the
    load. Either way the write applies only when its guard held."""
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    own_key, twin_key, spelling = _GUARDED_CASES[case]
    tested = "us-east-1" if expected == "operator-value" else "repo-r0"
    checkout, root = _guarded_write_chain(
        tmp_path, own_key, twin_key, spelling, order, tested
    )
    operator_last = order == "repository-first"
    survivor = own_key if operator_last else twin_key
    held = "us-east-1" if operator_last else "repo-r0"
    guard_holds = (operator_last or spelling == twin_key) and tested == held

    if guard_holds:
        config = resolve_config(config_path=root, source_dir=checkout)
        hubs = _model_hub_sections(config)
        assert list(hubs) == [survivor], hubs
        assert (hubs[survivor].get("options") or {}).get("aws_region") == "us-west-2"
        assert _canonical_region(config) == "us-west-2", hubs
    else:
        with pytest.raises(ASHConfigSourceError):
            resolve_config(config_path=root, source_dir=checkout)


def test_a_failed_test_op_names_the_respelled_path_it_checked(tmp_path, monkeypatch):
    """Typed at the repository twin's exact spelling, with the operator's file
    extended last, the join leaves the operator's spelling as the one key and
    the test op checks it, so the value it failed against sits at the
    operator's spelling: the refusal names that path, the one it checked, not
    the typed one, which would point a reader at a key holding exactly the
    value the message says was not found."""
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout, root = _guarded_write_chain(
        tmp_path,
        "aws-security-hub",
        "AwsSecurityHub",
        "AwsSecurityHub",
        "repository-first",
        "repo-r0",
    )

    with pytest.raises(ASHConfigSourceError) as refused:
        resolve_config(config_path=root, source_dir=checkout)

    message = str(refused.value)
    assert "/reporters/aws-security-hub/options/aws_region" in message, message
    assert "repo-r0" not in message, message


@pytest.mark.parametrize("op_name", sorted(_TWIN_PATCHES))
def test_control_without_the_twin_the_same_patch_lands(tmp_path, monkeypatch, op_name):
    """The same chain with a repository file that writes no reporters: the
    operator's patch lands exactly as it does beside the twin, so the cells
    above measure the twin's effect and nothing else."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout, root = _twin_chain(
        tmp_path, "own-first", _TWIN_PATCHES[op_name], repository_reporters=False
    )

    config = resolve_config(config_path=root, source_dir=checkout)

    shown, ran = _shown_and_ran(config)
    assert shown == ran == ("us-west-2", True), (shown, ran)


def test_a_repository_root_folding_onto_its_outside_base_s_section_stays_out(
    tmp_path, monkeypatch
):
    """A repository root that extends a file outside the checkout reaches it
    THROUGH a repository file, so the base is the repository's too. Its
    case-variant patch folds onto the section that base holds; the reporter
    runs neither the base's enable nor the patched region."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    own = tmp_path / "own.yaml"
    own.write_text(
        "reporters:\n  aws-security-hub:\n    enabled: true\n"
        "    options:\n      aws_region: us-east-1\n",
        encoding="utf-8",
    )
    root = checkout / ".ash" / ".ash.yaml"
    root.parent.mkdir(parents=True, exist_ok=True)
    root.write_text(
        "project_name: repo-root\nextends:\n  - " + own.as_posix() + "\n"
        "patch:\n  - op: replace\n"
        "    path: /reporters/AWS_Security_Hub/options/aws_region\n"
        "    value: repo-region\n",
        encoding="utf-8",
    )

    config = resolve_config(
        config_path=root, source_dir=tmp_path, scanned_root=checkout
    )

    held = _model_hub_sections(config)
    assert list(held) == ["aws-security-hub"], held
    assert ((held["aws-security-hub"].get("options") or {}).get("aws_region")) != (
        "repo-region"
    ), held
    assert held["aws-security-hub"].get("enabled") is not True, held
    ran = _section(config)
    assert ran.get("enabled") is not True, ran
    assert (ran.get("options") or {}).get("aws_region") != "repo-region", ran


def _repository_only_scanners_chain(tmp_path, patch_spelling, repo_key="bandit"):
    """The repository's file alone writes the scanners section; the
    operator's root only patches it, under *patch_spelling*."""
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    repository = checkout / ".ash" / ".ash.yaml"
    repository.parent.mkdir(parents=True, exist_ok=True)
    repository.write_text(
        f"project_name: repository\nscanners:\n  {repo_key}:\n    enabled: false\n",
        encoding="utf-8",
    )
    root = tmp_path / "operator.yaml"
    root.write_text(
        f"extends:\n  - {repository.as_posix()}\n"
        "patch:\n"
        "  - op: replace\n"
        f"    path: /scanners/{patch_spelling}/enabled\n"
        "    value: true\n",
        encoding="utf-8",
    )
    return checkout, root


@pytest.mark.parametrize(
    "repo_key, patch_spelling",
    [
        ("bandit", "Bandit"),
        ("detect-secrets", "detect_secrets"),
    ],
    ids=["case-variant", "separator-swap"],
)
def test_a_variant_patch_onto_a_repository_only_section_lands(
    tmp_path, monkeypatch, repo_key, patch_spelling
):
    """The operator's own files wrote no spelling of this section, so there
    is no owned key a repository twin could capture the pointer from: the
    ownership restricts nothing, and the variant pointer folds onto the one
    key the document holds, as it does without ownership. Refusing here made
    whether a chain loads depend on the pointer's spelling of a section the
    operator never wrote, while the exact spelling landed on the same key."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout, root = _repository_only_scanners_chain(
        tmp_path, patch_spelling, repo_key=repo_key
    )

    config = resolve_config(config_path=root, source_dir=checkout)

    resolved = (
        config.get_plugin_config(plugin_type="scanner", plugin_name=repo_key) or {}
    )
    assert resolved.get("enabled") is True, resolved
    extra = getattr(config.scanners, "__pydantic_extra__", None) or {}
    assert patch_spelling not in extra, extra


def test_the_exact_spelling_onto_a_repository_only_section_applies(
    tmp_path, monkeypatch
):
    """The control: the operator's pointer spelled exactly as the repository's
    file wrote the key is unambiguous, so the ownership restricts nothing and
    the patch applies."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    checkout, root = _repository_only_scanners_chain(tmp_path, "bandit")

    config = resolve_config(config_path=root, source_dir=checkout)

    scanners = config.model_dump().get("scanners") or {}
    assert (scanners.get("bandit") or {}).get("enabled") is True, scanners


def test_the_default_tree_read_takes_the_variant_patch_beside_no_owned_twin(
    tmp_path, monkeypatch
):
    """The same shape through default_config_for_tree, the read the MCP
    server's resource limits and the exit-code repair start from: an
    ASH_CONFIG chain whose repository base alone writes the section loads,
    and the operator's variant pointer folds onto the repository's key.
    Refusing here took down every caller of the default read while a scan
    of the same tree would answer."""
    checkout, root = _repository_only_scanners_chain(
        tmp_path, "detect_secrets", repo_key="detect-secrets"
    )
    monkeypatch.setenv("ASH_CONFIG", str(root))
    from automated_security_helper.config.default_config import (
        default_config_for_tree,
    )

    config = default_config_for_tree(checkout)

    resolved = (
        config.get_plugin_config(plugin_type="scanner", plugin_name="detect-secrets")
        or {}
    )
    assert resolved.get("enabled") is True, resolved


def test_a_failed_test_ops_refusal_names_no_key_read_from_the_environment(
    tmp_path, monkeypatch
):
    """An add op's value writes a section whose key the file read from the
    environment, and a later failing test op's pointer folds onto that key:
    the refusal says where the check landed without naming the key, whose
    text only the environment holds. The fold's own-spelling branch printed
    it, because the values an operation's own value reads are tracked apart
    from the file's other reads and the hidden-value check missed them."""
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    canary = "ash-canary-7f3e-0123456789"
    monkeypatch.setenv("ASH_TEST_PATCH_NAME", canary)
    config = tmp_path / "op" / "ash.yaml"
    config.parent.mkdir()
    config.write_text(
        "project_name: demo\n"
        "patch:\n"
        "  - op: add\n"
        "    path: /reporters\n"
        "    value:\n"
        "      ${ASH_TEST_PATCH_NAME}:\n"
        "        enabled: false\n"
        "  - op: test\n"
        "    path: /reporters/Ash_Canary_7f3e_0123456789/enabled\n"
        "    value: true\n",
        encoding="utf-8",
    )
    src = tmp_path / "src"
    mark_git_checkout(src)
    monkeypatch.setenv("ASH_CONFIG", str(config))
    monkeypatch.chdir(src)
    with pytest.raises(ASHConfigSourceError) as refused:
        resolve_config(source_dir=src)
    message = str(refused.value)
    fired = "the value the test op gives" in message
    if not fired:
        raise RuntimeError(f"the test op's refusal did not fire: {message}")
    shown = canary in message
    assert not shown, "the refusal names the key read from the environment"
    # The branch's own words, not only the absence of the key: the refusal
    # still says where the check landed.
    assert "checked at the key this file's own writes landed on" in message, message


def test_a_pointer_that_is_an_environment_read_shows_its_hidden_form(
    tmp_path, monkeypatch
):
    """The failing test op's pointer is itself read from the environment: the
    whole scalar is a reference, which is the only pointer shape that reads
    one. The refusal shows the pointer's hidden form with the clause saying
    where the check landed, and never the resolved pointer or its segments,
    which only the environment supplied: the raw path's segments may hold
    the read value wherever the fold left them unchanged, so no respelling
    of it is printed."""
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    resolved_pointer = "/reporters/Ash_Canary_7f3e_0123456789/enabled"
    monkeypatch.setenv("ASH_TEST_POINTER", resolved_pointer)
    config = tmp_path / "op" / "ash.yaml"
    config.parent.mkdir()
    config.write_text(
        "project_name: demo\n"
        "patch:\n"
        "  - op: add\n"
        "    path: /reporters\n"
        "    value:\n"
        "      ash_canary_7f3e_0123456789:\n"
        "        enabled: false\n"
        "  - op: test\n"
        "    path: ${ASH_TEST_POINTER}\n"
        "    value: true\n",
        encoding="utf-8",
    )
    src = tmp_path / "src"
    mark_git_checkout(src)
    monkeypatch.setenv("ASH_CONFIG", str(config))
    monkeypatch.chdir(src)
    with pytest.raises(ASHConfigSourceError) as refused:
        resolve_config(source_dir=src)
    message = str(refused.value)
    fired = "the value the test op gives" in message
    if not fired:
        raise RuntimeError(f"the test op's refusal did not fire: {message}")
    assert "'<value>'" in message, message
    assert "checked at the key this file's own writes landed on" in message, message
    assert resolved_pointer not in message, message
    assert "Ash_Canary_7f3e_0123456789" not in message, message
    assert "ash_canary_7f3e_0123456789" not in message, message


def test_a_reference_inside_a_longer_pointer_is_literal_text(tmp_path, monkeypatch):
    """A ``${VAR}`` inside a longer pointer reads nothing from the
    environment: only a pointer that is wholly one reference reads a value,
    so this pointer is literal text. The refusal shows it as written, with
    no landed clause, since the check landed exactly where the pointer says.
    The variable is set to this file's own key spelling, so a resolution
    that DID read it would land the check on the owned key and change the
    refusal; the refusal is byte-identical with the variable unset, which is
    the no-read proof."""
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    canary = "Ash-Canary-7f3e-0123456789"
    config = tmp_path / "op" / "ash.yaml"
    config.parent.mkdir()
    config.write_text(
        "project_name: demo\n"
        "patch:\n"
        "  - op: add\n"
        "    path: /reporters\n"
        "    value:\n"
        "      ash_canary_7f3e_0123456789:\n"
        "        enabled: false\n"
        "  - op: test\n"
        "    path: /reporters/${ASH_TEST_POINTER_SEG}/enabled\n"
        "    value: true\n",
        encoding="utf-8",
    )
    src = tmp_path / "src"
    mark_git_checkout(src)
    monkeypatch.setenv("ASH_CONFIG", str(config))
    monkeypatch.chdir(src)

    monkeypatch.setenv("ASH_TEST_POINTER_SEG", canary)
    with pytest.raises(ASHConfigSourceError) as refused:
        resolve_config(source_dir=src)
    message = str(refused.value)
    fired = "the value the test op gives" in message
    if not fired:
        raise RuntimeError(f"the test op's refusal did not fire: {message}")
    assert "${ASH_TEST_POINTER_SEG}" in message, message
    assert canary not in message, message
    assert "checked at the key this file's own writes landed on" not in message, message

    monkeypatch.delenv("ASH_TEST_POINTER_SEG")
    with pytest.raises(ASHConfigSourceError) as unset:
        resolve_config(source_dir=src)
    assert str(unset.value) == message, (str(unset.value), message)
