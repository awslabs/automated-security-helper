# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A client-patched copy that repeats the trusted profile in another serialization is not a change.

``config_document_denials`` exempts a leaf whose value equals what the trusted
config has at the same place. A session's client-patched profile copy
(``repeats_trusted``) is the trusted profile written whole, so a leaf it repeats
can differ from the trusted dump only in how it is written: an entry without the
keys the model defaults, a spelling the model normalizes. Compared as text, such
a leaf read as the client's change and a policy denying the field refused the
operator's own entries in the copy. The leaf is now also compared as the model
reads it: the trusted dump with only this leaf's value placed at its pointer,
validated as a config file is. So only a value the client changed is refused, and
nothing else the copy holds (another spelling of the field, a key the model
drops, reference text in another field) can decide the leaf.

A leaf the profile read from the environment is the one place a repeat of the
trusted value is never exempt, since a client would learn from the absence of a
refusal that its guess was right. The copy holds the operator's own value there
when the load that reads it filled the profile's reference in, and that leaf is
exempt. The last section pins when a leaf counts as the operator's own.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

from automated_security_helper.config.ash_config import (
    AshConfig,
    RuntimeOverridesConfig,
)
from automated_security_helper.config.environment_record import (
    EnvironmentReference,
    fill_environment_references,
)
from automated_security_helper.config.runtime_patch import config_document_denials

pytestmark = pytest.mark.unit

#: The operator's entries as a profile file writes them: no defaulted keys.
_OPERATOR_SUPPRESSION = {
    "rule_id": "B101",
    "path": "src/vendored.py",
    "reason": "vendored",
}
_OPERATOR_IGNORE = {"path": "operator-ignored/**", "reason": "operator"}

_DENIED = ["/global_settings/suppressions", "/global_settings/ignore_paths"]


def _trusted(**top_level: Any) -> AshConfig:
    """The operator's profile; ``top_level`` adds fields the profile also sets."""
    return AshConfig.model_validate(
        {
            "project_name": "operator",
            "global_settings": {
                "suppressions": [dict(_OPERATOR_SUPPRESSION)],
                "ignore_paths": [dict(_OPERATOR_IGNORE)],
            },
            **top_level,
        }
    )


def _copy(**global_settings: Any) -> Dict[str, Any]:
    """A patched copy of the profile: project_name changed, the entries as written."""
    settings: Dict[str, Any] = {
        "suppressions": [dict(_OPERATOR_SUPPRESSION)],
        "ignore_paths": [dict(_OPERATOR_IGNORE)],
    }
    settings.update(global_settings)
    return {"project_name": "x", "global_settings": settings}


def _denied_keys_for(
    document: Dict[str, Any],
    *,
    trusted: AshConfig,
    denied: List[str],
    repeats_trusted: bool,
) -> List[str]:
    """The keys of ``document`` that an allowlist denying ``denied`` refuses, judged
    against the ``trusted`` profile."""
    allowlist = RuntimeOverridesConfig(
        enabled=True, allowed_paths=["/project_name"], denied_paths=list(denied)
    )
    return [
        denial.key
        for denial in config_document_denials(
            document,
            allowlist=allowlist,
            config=trusted,
            repeats_trusted=repeats_trusted,
        )
    ]


def _denied_keys(document: Dict[str, Any], *, repeats_trusted: bool) -> List[str]:
    return _denied_keys_for(
        document,
        trusted=_trusted(),
        denied=_DENIED,
        repeats_trusted=repeats_trusted,
    )


def test_the_trusted_dump_carries_the_defaulted_keys_the_copy_leaves_out() -> None:
    """The control: the two serializations of one entry differ as text."""
    dumped = _trusted().model_dump(mode="json", by_alias=True)
    entry = dumped["global_settings"]["ignore_paths"][0]
    assert entry != _OPERATOR_IGNORE
    assert {key: entry[key] for key in _OPERATOR_IGNORE} == _OPERATOR_IGNORE


def test_a_copy_repeating_the_profiles_entries_as_written_is_not_refused() -> None:
    assert _denied_keys(_copy(), repeats_trusted=True) == []


def test_a_copy_whose_entry_the_client_changed_is_still_refused() -> None:
    """The must-flag control: a changed value differs after validation too."""
    changed = dict(_OPERATOR_SUPPRESSION, reason="the client's reason")
    keys = _denied_keys(_copy(suppressions=[changed]), repeats_trusted=True)
    assert keys == ["global_settings.suppressions"]


def test_a_copy_with_an_entry_the_client_added_is_still_refused() -> None:
    added = [dict(_OPERATOR_IGNORE), {"path": "client/**", "reason": "the client's"}]
    keys = _denied_keys(_copy(ignore_paths=added), repeats_trusted=True)
    assert keys == ["global_settings.ignore_paths"]


def test_the_model_read_compare_applies_to_a_client_patched_copy_only() -> None:
    """Any other delivered document keeps the text compare, as before."""
    keys = _denied_keys(_copy(), repeats_trusted=False)
    assert sorted(keys) == [
        "global_settings.ignore_paths",
        "global_settings.suppressions",
    ]


def test_a_copy_the_model_refuses_gets_no_exemption() -> None:
    """An entry with a key the model does not declare cannot be read, so it is
    compared as written and refused."""
    unreadable = [dict(_OPERATOR_IGNORE, unknown_key="x")]
    keys = _denied_keys(_copy(ignore_paths=unreadable), repeats_trusted=True)
    assert "global_settings.ignore_paths" in keys


def _two_spellings() -> Dict[str, Any]:
    """A copy that writes ``global_settings`` as the profile has it and also
    ``global-settings``, with a suppression the profile does not have."""
    other = [{"rule_id": "B102", "path": "src/other.py", "reason": "a different entry"}]
    document = _copy()
    document["global-settings"] = {"suppressions": other}
    return document


def test_a_second_spelling_of_a_top_level_field_is_judged_by_its_own_value() -> None:
    """A copy that writes one field under two spellings is judged by what each
    spelling holds. The hyphen spelling holds a suppression the profile does not
    have, so it is refused, and the underscore spelling, which repeats the profile,
    is not."""
    keys = _denied_keys(_two_spellings(), repeats_trusted=True)

    assert "global-settings.suppressions" in keys, keys
    assert "global_settings.suppressions" not in keys, keys


def test_both_spellings_are_refused_without_the_exemption() -> None:
    """The control: any other delivered document gets the text compare, so both
    spellings are refused and the denial itself matches either one."""
    keys = _denied_keys(_two_spellings(), repeats_trusted=False)

    assert "global-settings.suppressions" in keys, keys
    assert "global_settings.suppressions" in keys, keys


def _hyphen_spelling_keys(*, repeats_trusted: bool) -> List[str]:
    """The denied keys of a copy that writes ``fail-on-findings`` with the other
    value, against a profile that holds ``fail_on_findings`` at its default and a
    policy that denies it."""
    default = AshConfig().fail_on_findings
    assert isinstance(default, bool)
    document = _copy()
    document["fail-on-findings"] = not default
    return _denied_keys_for(
        document,
        trusted=_trusted(fail_on_findings=default),
        denied=[*_DENIED, "/fail_on_findings"],
        repeats_trusted=repeats_trusted,
    )


def test_a_hyphen_spelling_of_a_field_the_policy_denies_is_refused() -> None:
    """The profile holds ``fail_on_findings`` at its default and the policy denies
    it. A copy that writes the field as ``fail-on-findings`` with the other value
    changes the same field under another spelling, so that key is refused."""
    keys = _hyphen_spelling_keys(repeats_trusted=True)

    assert "fail-on-findings" in keys, keys


def test_a_hyphen_spelling_of_a_denied_field_is_refused_without_the_exemption() -> None:
    """The control: any other delivered document gets the text compare, so the
    denial itself matches the hyphen spelling."""
    keys = _hyphen_spelling_keys(repeats_trusted=False)

    assert "fail-on-findings" in keys, keys


@pytest.mark.parametrize(
    "document",
    [
        pytest.param(
            dict(_copy(), fail_on_findings="${ASH_FAIL_ON_FINDINGS}"), id="boolean"
        ),
        pytest.param(
            _copy(severity_threshold="${ASH_SEVERITY_THRESHOLD}"), id="fixed-choice"
        ),
    ],
)
def test_reference_text_in_a_non_string_field_keeps_the_exemption(
    document: Dict[str, Any],
) -> None:
    """A copy that holds reference text in a boolean or a fixed-choice field is not
    a document the model can read. The suppressions and ignore paths still repeat
    the profile, and the field is not denied here, so nothing is refused. Only the
    fixed-choice shape comes from a real profile: the loader refuses a reference at
    a boolean field."""
    keys = _denied_keys(document, repeats_trusted=True)

    assert keys == [], keys


_BANDIT_DENIED = ["/scanners/bandit/options/confidence_level"]
_BANDIT_KEY = "scanners.bandit.options.confidence_level"


def _bandit_trusted() -> AshConfig:
    return AshConfig.model_validate(
        {
            "project_name": "operator",
            "scanners": {"bandit": {"options": {"confidence_level": "high"}}},
        }
    )


def _bandit_copy() -> Dict[str, Any]:
    """A copy whose bandit confidence level is not the profile's."""
    return {
        "project_name": "x",
        "scanners": {"bandit": {"options": {"confidence_level": "low"}}},
    }


def test_a_copy_whose_plugin_option_the_client_changed_is_still_refused() -> None:
    """The control for the plugin-section lookup: a changed option of a plugin
    section is refused when nothing is planted."""
    keys = _denied_keys_for(
        _bandit_copy(),
        trusted=_bandit_trusted(),
        denied=_BANDIT_DENIED,
        repeats_trusted=True,
    )

    assert _BANDIT_KEY in keys, keys


def test_a_plugin_lookup_that_raises_on_the_copy_does_not_leave_the_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The check reads a plugin section of the copy through ``get_plugin_config``.
    An error from that lookup on the copy does not leave the check, and the option
    the client changed is still refused."""
    trusted = _bandit_trusted()
    lookup = AshConfig.get_plugin_config

    def raising_on_the_copy(self: AshConfig, *args: Any, **kwargs: Any) -> Any:
        if self is trusted:
            return lookup(self, *args, **kwargs)
        raise RuntimeError("planted")

    monkeypatch.setattr(AshConfig, "get_plugin_config", raising_on_the_copy)

    keys = _denied_keys_for(
        _bandit_copy(),
        trusted=trusted,
        denied=_BANDIT_DENIED,
        repeats_trusted=True,
    )

    assert _BANDIT_KEY in keys, keys


# ---------------------------------------------------------------------------
# A leaf the profile read from the environment
# ---------------------------------------------------------------------------

#: The client's copy, and another document of the session.
_COPY = Path("/session/client-config/ash.yaml")
_ANOTHER = Path("/session/config/ash.yaml")

#: What each variable the profiles below read holds.
_ENVIRONMENT = {
    "ASH_C3_PROJECT": "operator-project",
    "ASH_C3_SEVERITY": "HIGH",
    "ASH_C3_BASE": "base-project",
    "ASH_C3_REGION": "us-west-2",
}

_PROFILE = (
    "project_name: ${ASH_C3_PROJECT}\n"
    "global_settings:\n"
    "  severity_threshold: ${ASH_C3_SEVERITY}\n"
)
_REPORTER_PROFILE = (
    "reporters:\n"
    "  aws-security-hub:\n"
    "    enabled: false\n"
    "    options:\n"
    "      aws_region: ${ASH_C3_REGION}\n"
)

#: The two leaves of ``_PROFILE`` a policy denies, as pointers and as the keys a
#: denial names.
_PROFILE_DENIED = ["/project_name", "/global_settings/severity_threshold"]
_PROFILE_KEYS = ["project_name", "global_settings.severity_threshold"]


def _load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, files: Dict[str, str]
) -> Tuple[AshConfig, List[EnvironmentReference]]:
    """The config the profile in ``files`` loads as (``.ash.yaml`` is the file
    loaded, any other is a base it extends), and the references the load read from
    the environment."""
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )

    for name, value in _ENVIRONMENT.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    for name, text in files.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    document, config = load_config_file_for_run(tmp_path / ".ash.yaml")
    return config, list(document.environment_references)


@pytest.fixture
def profile(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Tuple[AshConfig, List[EnvironmentReference]]:
    """The trusted config whose project name and severity threshold the profile
    read from the environment, and the two references it read."""
    config, references = _load(tmp_path, monkeypatch, {".ash.yaml": _PROFILE})
    assert config.project_name == "operator-project", "the control: it was read"
    assert len(references) == 2, references
    return config, references


def _profile_copy_text() -> Dict[str, Any]:
    """The client's copy of ``_PROFILE``: each reference as the text it wrote."""
    return {
        "project_name": "${ASH_C3_PROJECT}",
        "global_settings": {"severity_threshold": "${ASH_C3_SEVERITY}"},
    }


def _filled(
    references: List[EnvironmentReference],
    text: Dict[str, Any],
    path: Path = _COPY,
) -> Tuple[Dict[str, Any], List[EnvironmentReference]]:
    """``text``, a copy holding the profile's references as text, as the load that
    reads the copy fills it from ``references``, and what that fill read: each
    reference stamped as ``path``'s own."""
    placed: List[EnvironmentReference] = []
    document = fill_environment_references(text, references, placed=placed)
    return document, [reference.read_in(path) for reference in placed]


def _environment_denied_keys(
    document: Dict[str, Any],
    config: AshConfig,
    *,
    denied: List[str],
    own: List[EnvironmentReference],
    path: Path | None = _COPY,
    repeats_trusted: bool = True,
) -> List[str]:
    """The keys of ``document`` that a policy denying ``denied`` refuses, judged
    against ``config``, where ``own`` are the references the load read in the
    document that ``path`` names."""
    allowlist = RuntimeOverridesConfig(
        enabled=True, allowed_paths=["/global_settings/**"], denied_paths=list(denied)
    )
    return [
        denial.key
        for denial in config_document_denials(
            document,
            allowlist=allowlist,
            config=config,
            repeats_trusted=repeats_trusted,
            own_references=own,
            document_path=path,
        )
    ]


def test_the_operators_own_references_at_denied_leaves_are_not_refused(
    profile,
) -> None:
    """The copy holds the operator's value at two leaves a policy denies, each put
    there by the fill from the operator's own reference at that place, so neither
    leaf is refused."""
    config, references = profile
    document, own = _filled(references, _profile_copy_text())
    assert document["project_name"] == "operator-project", "the control: it was filled"

    keys = _environment_denied_keys(document, config, denied=_PROFILE_DENIED, own=own)

    assert keys == []


def test_the_value_written_out_where_the_profile_read_the_environment_is_refused(
    profile,
) -> None:
    """A copy that writes the value itself, here the right one, holds no reference
    of the operator's at those leaves. They are refused, so the absence of a
    refusal never tells a client that its guess was right."""
    config, _ = profile
    document = {
        "project_name": "operator-project",
        "global_settings": {"severity_threshold": "HIGH"},
    }

    keys = _environment_denied_keys(document, config, denied=_PROFILE_DENIED, own=[])

    assert keys == _PROFILE_KEYS


def test_a_reference_at_another_place_does_not_admit_the_leaf(profile) -> None:
    """References the load read at other places than the leaves' do not admit them:
    both leaves hold the profile's value, and both are refused."""
    config, references = profile
    document, own = _filled(references, _profile_copy_text())
    elsewhere = [replace(reference, path=("description",)) for reference in own]

    keys = _environment_denied_keys(
        document, config, denied=_PROFILE_DENIED, own=elsewhere
    )

    assert keys == _PROFILE_KEYS


def test_references_covering_one_denied_leaf_leave_the_other_refused(profile) -> None:
    """References that cover only the project name admit that leaf and leave the
    severity threshold, which the profile also read from the environment,
    refused."""
    config, references = profile
    document, own = _filled(references, _profile_copy_text())
    project_only = [r for r in own if r.path == ("project_name",)]
    assert len(project_only) == 1, own

    keys = _environment_denied_keys(
        document, config, denied=_PROFILE_DENIED, own=project_only
    )

    assert keys == ["global_settings.severity_threshold"]


@pytest.mark.parametrize(
    ("stamped_for", "document_path", "repeats_trusted"),
    [
        pytest.param(_ANOTHER, _COPY, True, id="references-of-another-document"),
        pytest.param(_COPY, None, True, id="no-document-named"),
        pytest.param(_COPY, _COPY, False, id="not-a-patched-copy"),
    ],
)
def test_a_reference_counts_only_for_the_patched_copy_it_was_read_in(
    profile, stamped_for: Path, document_path: Path | None, repeats_trusted: bool
) -> None:
    """A reference admits a leaf only when it names the document judged, the caller
    names that document, and the document is a client's patched copy. Any other
    case leaves the leaves refused."""
    config, references = profile
    document, own = _filled(references, _profile_copy_text(), path=stamped_for)

    keys = _environment_denied_keys(
        document,
        config,
        denied=_PROFILE_DENIED,
        own=own,
        path=document_path,
        repeats_trusted=repeats_trusted,
    )

    assert keys == _PROFILE_KEYS


@pytest.mark.parametrize(
    ("base", "texts", "refused"),
    [
        pytest.param(
            "project_name: ${ASH_C3_BASE}\n",
            {"${ASH_C3_BASE}", "${ASH_C3_PROJECT}"},
            True,
            id="the-base-reads-the-environment-too",
        ),
        pytest.param(
            "project_name: base-project\n",
            {"${ASH_C3_PROJECT}"},
            False,
            id="the-base-writes-a-literal",
        ),
    ],
)
def test_two_texts_read_at_one_place_never_admit_the_leaf(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    base: str,
    texts: set,
    refused: bool,
) -> None:
    """When a base and the file that extends it both read the project name, each
    from its own variable, the trusted config recorded two texts at the place, so
    the leaf is refused though the copy holds the later file's value. With a
    literal in the base there is one text, and the same copy is not refused."""
    config, references = _load(
        tmp_path,
        monkeypatch,
        {
            "base.yaml": base,
            ".ash.yaml": "extends: base.yaml\nproject_name: ${ASH_C3_PROJECT}\n",
        },
    )
    assert {reference.written for reference in references} == texts, references
    assert config.project_name == "operator-project", "the control: the later file wins"
    document, own = _filled(references, {"project_name": "${ASH_C3_PROJECT}"})
    assert document == {"project_name": "operator-project"}, "the control: filled"
    assert len(own) == 1, own

    keys = _environment_denied_keys(document, config, denied=["/project_name"], own=own)

    assert keys == (["project_name"] if refused else [])


def _reporter_copy(section: str) -> Dict[str, Any]:
    """The reporter profile's copy with its plugin section spelled ``section`` and
    the operator's region filled in."""
    return {
        "reporters": {
            section: {"enabled": False, "options": {"aws_region": "us-west-2"}}
        }
    }


_REPORTER_DENIED = ["/reporters/aws-security-hub/**"]
_REGION_POINTER_PATH = ("reporters", "aws-security-hub", "options", "aws_region")


def test_a_plugin_section_spelled_as_the_profile_spells_it_is_not_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the two cases below: the plugin section spelled as the
    profile spells it, with the profile's reference read in at that place, holds
    the operator's own value and is not refused."""
    config, references = _load(tmp_path, monkeypatch, {".ash.yaml": _REPORTER_PROFILE})
    own = [reference.read_in(_COPY) for reference in references]
    assert [reference.path for reference in own] == [_REGION_POINTER_PATH], own

    keys = _environment_denied_keys(
        _reporter_copy("aws-security-hub"),
        config,
        denied=_REPORTER_DENIED,
        own=own,
    )

    assert keys == []


def test_a_plugin_section_spelled_another_way_than_the_reference_names_it_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The copy spells the plugin section another way (the same plugin to the
    lookup, another pointer) than the references the load read in it, so those
    are not at the leaf's place. The leaf, whose value is the profile's, is
    refused."""
    config, references = _load(tmp_path, monkeypatch, {".ash.yaml": _REPORTER_PROFILE})
    own = [reference.read_in(_COPY) for reference in references]

    keys = _environment_denied_keys(
        _reporter_copy("AWS-Security-Hub"),
        config,
        denied=_REPORTER_DENIED,
        own=own,
    )

    assert keys == ["reporters.AWS-Security-Hub.options.aws_region"]


def test_references_at_the_spelling_the_copy_uses_admit_the_same_leaf(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the case above: the same copy, with the references read at
    the spelling the copy uses (where the fill puts them), is not refused. So
    the spelling alone decided that case."""
    config, references = _load(tmp_path, monkeypatch, {".ash.yaml": _REPORTER_PROFILE})
    spelled = ("reporters", "AWS-Security-Hub", "options", "aws_region")
    own = [replace(reference, path=spelled).read_in(_COPY) for reference in references]

    keys = _environment_denied_keys(
        _reporter_copy("AWS-Security-Hub"),
        config,
        denied=_REPORTER_DENIED,
        own=own,
    )

    assert keys == []
