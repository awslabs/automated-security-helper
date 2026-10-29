# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every comparison of a plugin key lowers case the same way.

``AshConfig.get_plugin_config`` gives a plugin the section whose key it reads as
the plugin's name. The runtime-patch denials, the option check of a loaded
plugin, the reporter confinement of ``ash report`` and ``ash merge``, and the
workspace policy's scanner names each decide, by a comparison of their own,
which keys are a plugin's. They have to read the same keys: a key the lookup
reads that a check does not see as the plugin's is outside that check.

The rule is ASCII case only (``plugin_section_names.ascii_lower``). ``str.lower``
lowers a non-ASCII letter whose lowercase is an ASCII letter to that letter, so
a key spelled with it is one plugin's section for a lookup that lowers with
``str.lower`` and another name for a check that lowers ASCII only. These tests
spell keys with such a letter (lowercase ``k``) and tie each check to the lookup:
a check covers a key, or the lookup does not read it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.base.plugin_config import plugin_config_key
from automated_security_helper.base.reporter_plugin import off_host_reporter_refused
from automated_security_helper.cli.merge import select_merge_reporters
from automated_security_helper.config.ash_config import (
    AshConfig,
    RuntimeOverridesConfig,
    plugin_key_lookup_names,
    plugin_section_lookup,
    reduced_plugin_name,
)
from automated_security_helper.config.ash_workspace_config import WorkspacePolicyConfig
from automated_security_helper.config.plugin_option_check import (
    refuse_unknown_plugin_options,
)
from automated_security_helper.config.reporter_trust import (
    confine_off_host_reporters_to_overrides,
)
from automated_security_helper.config.runtime_patch import (
    _denied_path_reason,
    config_document_denials,
    known_plugin_keys,
)
from automated_security_helper.config.untrusted_source import (
    MERGE_CONFIG_FILE,
    REPORT_CONFIG_FILE,
)
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporter,
)
from automated_security_helper.plugin_modules.ash_snyk_plugins.snyk_code_scanner import (
    SnykCodeScanner,
)
from automated_security_helper.workspace.execution import _enable_policy_scanners
from automated_security_helper.workspace.policy import (
    normalise_scanner_name,
    policy_for_project,
)

AshConfig.model_rebuild()

#: A non-ASCII letter whose Unicode lowercase is ASCII ``k``, written as an escape.
LOWERS_TO_K = "\N{KELVIN SIGN}"

SNYK_CODE = "snyk-code"
SNYK_CODE_WITH_IT = "sny" + LOWERS_TO_K + "-code"
BEDROCK = "bedrock-summary-reporter"
#: Without the type word, the spelling the lookup reads as the reporter's name.
BEDROCK_WITH_IT = "bedroc" + LOWERS_TO_K + "-summary"

_SECTION_TYPE = {
    "scanners": "scanner",
    "reporters": "reporter",
    "converters": "converter",
}

#: Non-ASCII letters a case-insensitive pattern reads as the ASCII letter, with
#: the ASCII letter each stands for: the one whose lowercase is ``k``, one that
#: lowers to itself, and two for ``i`` (one lowers to ``i`` and a combining mark).
_LOOKALIKES = (
    ("k", LOWERS_TO_K),
    ("s", chr(0x17F)),
    ("i", chr(0x131)),
    ("i", chr(0x130)),
)


def _reads(item_dict: dict, plugin_type: str, plugin: str):
    """The section ``get_plugin_config`` reads for ``plugin`` in ``item_dict``."""
    return plugin_section_lookup(item_dict, plugin_type, plugin, [])


def _spellings(name: str) -> list[str]:
    """ASCII respellings of ``name``, and each with a look-alike letter in it."""
    ascii_spellings = {
        name,
        name.upper(),
        name.replace("-", "_"),
        name.replace("-", ""),
        name.removesuffix("-reporter"),
        name.removesuffix("-scanner"),
    }
    spellings = set(ascii_spellings)
    for spelling in ascii_spellings:
        for letter, other in _LOOKALIKES:
            if letter not in spelling:
                continue
            spellings.add(spelling.replace(letter, other))
            spellings.update(
                spelling[:index] + other + spelling[index + 1 :]
                for index, character in enumerate(spelling)
                if character == letter
            )
    return sorted(spellings)


def _denied_keys(document: dict) -> list[str]:
    """The fields of ``document`` the default runtime-override denials refuse."""
    return [
        denial.key
        for denial in config_document_denials(
            document, allowlist=RuntimeOverridesConfig()
        )
    ]


# ---------------------------------------------------------------------------
# The rule
# ---------------------------------------------------------------------------


def test_the_lowering_of_a_plugin_key_is_ascii_only():
    # Imported here, not above: the module's other tests need none of it.
    from automated_security_helper.config.plugin_section_names import ascii_lower

    assert ascii_lower("Snyk-Code") == SNYK_CODE
    assert ascii_lower(SNYK_CODE_WITH_IT) == SNYK_CODE_WITH_IT
    # Control: this is a letter str.lower reads as ASCII, which is why the rule
    # is not str.lower.
    assert SNYK_CODE_WITH_IT.lower() == SNYK_CODE


def test_control_the_names_a_check_covers_do_not_include_the_str_lower_spelling():
    """The set the denials and checks read a key under is built from the ASCII fold."""
    assert "snykcode" not in plugin_key_lookup_names(SNYK_CODE_WITH_IT)
    assert "bedrocksummary" not in plugin_key_lookup_names(BEDROCK_WITH_IT)
    assert "snykcode" in plugin_key_lookup_names("Snyk_Code")


def test_a_section_is_read_only_under_a_key_the_checks_name():
    """For every shipped plugin and every spelling: read, then named.

    ``plugin_key_lookup_names`` is documented as every reduced name under which
    ``get_plugin_config`` finds a section. A section the lookup reads under a key
    outside that set is one every check built on the set misses.
    """
    unnamed = []
    reads = 0
    saw_the_letter = False
    for section, names in known_plugin_keys(None).items():
        plugin_type = _SECTION_TYPE[section]
        for plugin in sorted(names):
            reduced = reduced_plugin_name(plugin)
            for key in _spellings(plugin):
                saw_the_letter = saw_the_letter or LOWERS_TO_K in key
                read = _reads({key: {"enabled": True}}, plugin_type, plugin)
                if read is None:
                    continue
                reads += 1
                if key != plugin and reduced not in plugin_key_lookup_names(key):
                    unnamed.append((section, plugin, key))
    # Controls: the corpus holds the look-alike letter, and the lookup reads many
    # of its spellings, so an empty result is not an empty corpus.
    assert saw_the_letter
    assert reads > 100
    assert unnamed == []


@pytest.mark.parametrize(
    "section,plugin,spelling",
    [
        ("scanners", SNYK_CODE, "Snyk_Code"),
        ("scanners", SNYK_CODE, "SNYK-CODE"),
        ("scanners", SNYK_CODE, "snykcode"),
        ("scanners", "detect-secrets", "DetectSecrets"),
        ("reporters", BEDROCK, "BedrockSummary"),
        ("reporters", BEDROCK, "bedrock_summary"),
        ("reporters", BEDROCK, "BEDROCK-SUMMARY-REPORTER"),
        ("converters", "archive", "ARCHIVE"),
    ],
)
def test_control_an_ascii_respelling_is_still_read_and_named(section, plugin, spelling):
    """The rule narrows nothing it did not have to: ASCII case and separators."""
    assert _reads({spelling: {"enabled": True}}, _SECTION_TYPE[section], plugin)
    assert reduced_plugin_name(plugin) in plugin_key_lookup_names(spelling)
    assert reduced_plugin_name(spelling) == reduced_plugin_name(plugin)


@pytest.mark.parametrize(
    "section,plugin,spelling,denial",
    [
        pytest.param(
            "scanners",
            SNYK_CODE,
            SNYK_CODE_WITH_IT,
            "/scanners/snyk-code/**",
            id="snyk",
        ),
        pytest.param(
            "reporters", BEDROCK, BEDROCK_WITH_IT, f"/reporters/{BEDROCK}/**", id="aws"
        ),
        pytest.param("scanners", "checkov", "chec" + LOWERS_TO_K + "ov", None, id="c"),
        pytest.param("scanners", "cdk-nag", "cd" + LOWERS_TO_K + "-nag", None, id="n"),
        pytest.param(
            "reporters", "markdown", "mar" + LOWERS_TO_K + "down", None, id="m"
        ),
    ],
)
def test_a_key_with_the_letter_in_place_of_k_is_one_plugin_under_every_helper(
    section, plugin, spelling, denial
):
    """Read and covered alike: no plugin at all, or the same plugin everywhere.

    The lookup, ``reduced_plugin_name``, ``plugin_key_lookup_names`` and, where
    the plugin has one, its denial all answer the same way for the key.
    """
    read = _reads({spelling: {"enabled": True}}, _SECTION_TYPE[section], plugin)
    reduces_alike = reduced_plugin_name(spelling) == reduced_plugin_name(plugin)
    named = reduced_plugin_name(plugin) in plugin_key_lookup_names(spelling)
    assert (read is not None) == reduces_alike == named
    if denial is not None:
        reason = _denied_path_reason(
            denial, f"/{section}/{spelling}/enabled", known_plugin_keys(None)
        )
        assert (reason is not None) == (read is not None)


def test_kg_a_reporters_key_with_the_letter_is_no_bedrock_reporters_section():
    """Gap KG: through ``AshConfig.get_plugin_config`` itself, not the bare lookup.

    The key is ``bedroc`` + the letter + ``-summary``, built into a config's
    ``reporters``. The control is the ASCII spelling of the same name, which the
    lookup does read, so a ``None`` below is the key's, not a dead lookup's.
    """
    control = AshConfig.model_validate(
        {"project_name": "t", "reporters": {"bedrock-summary": {"enabled": True}}}
    )
    config = AshConfig.model_validate(
        {"project_name": "t", "reporters": {BEDROCK_WITH_IT: {"enabled": True}}}
    )

    assert control.get_plugin_config(plugin_type="reporter", plugin_name=BEDROCK)
    assert config.get_plugin_config(plugin_type="reporter", plugin_name=BEDROCK) is None


# ---------------------------------------------------------------------------
# Runtime-patch denials
# ---------------------------------------------------------------------------

DENIED_PLUGINS = [
    pytest.param("scanners", "scanner", SNYK_CODE, SNYK_CODE_WITH_IT, id="snyk-code"),
    pytest.param("reporters", "reporter", BEDROCK, BEDROCK_WITH_IT, id="bedrock"),
]


@pytest.mark.parametrize("section,plugin_type,plugin,spelling", DENIED_PLUGINS)
def test_a_delivered_section_the_lookup_reads_is_one_the_denials_cover(
    section, plugin_type, plugin, spelling
):
    written = {"enabled": True, "options": {"honor_tree_exclusions": True}}
    read = _reads({spelling: written}, plugin_type, plugin)
    denied = _denied_keys({section: {spelling: written}})
    assert read is None or denied


@pytest.mark.parametrize("section,plugin_type,plugin,spelling", DENIED_PLUGINS)
def test_a_patch_op_at_a_section_the_lookup_reads_is_one_the_denials_cover(
    section, plugin_type, plugin, spelling
):
    read = _reads({spelling: {"enabled": True}}, plugin_type, plugin)
    reason = _denied_path_reason(
        f"/{section}/{plugin}/**",
        f"/{section}/{spelling}/enabled",
        known_plugin_keys(None),
    )
    assert read is None or reason is not None


@pytest.mark.parametrize(
    "section,plugin,spelling",
    [
        ("scanners", SNYK_CODE, SNYK_CODE),
        ("scanners", SNYK_CODE, "Snyk_Code"),
        ("scanners", SNYK_CODE, "SNYK-CODE"),
        ("reporters", BEDROCK, BEDROCK),
        ("reporters", BEDROCK, "BedrockSummary"),
    ],
)
def test_control_an_ascii_spelling_is_read_and_denied(section, plugin, spelling):
    written = {"enabled": True}
    assert _reads({spelling: written}, _SECTION_TYPE[section], plugin) is not None
    assert _denied_keys({section: {spelling: written}})


# ---------------------------------------------------------------------------
# The option check of a loaded plugin
# ---------------------------------------------------------------------------


def _is_refused(config: AshConfig, plugins) -> bool:
    try:
        refuse_unknown_plugin_options(config, plugins)
    except ASHConfigValidationError:
        return True
    return False


@pytest.mark.parametrize(
    "spelling",
    [SNYK_CODE, "Snyk_Code", "snykcode", SNYK_CODE_WITH_IT, "unrelated-" + SNYK_CODE],
)
def test_an_unknown_option_is_refused_exactly_where_the_lookup_reads_the_section(
    spelling,
):
    config = AshConfig.model_validate(
        {
            "project_name": "t",
            "scanners": {spelling: {"options": {"no_such_option": True}}},
        }
    )
    read = config.get_plugin_config("scanner", plugin_config_key(SnykCodeScanner))
    assert _is_refused(config, {"scanner": [SnykCodeScanner]}) == (read is not None)


@pytest.mark.parametrize("spelling", [SNYK_CODE, "Snyk_Code", "snykcode"])
def test_control_an_unknown_option_of_an_ascii_spelling_is_refused(spelling):
    config = AshConfig.model_validate(
        {
            "project_name": "t",
            "scanners": {spelling: {"options": {"no_such_option": True}}},
        }
    )
    assert config.get_plugin_config("scanner", SNYK_CODE) is not None
    assert _is_refused(config, {"scanner": [SnykCodeScanner]})


# ---------------------------------------------------------------------------
# The reporter confinement of ash report and ash merge
# ---------------------------------------------------------------------------


def _bedrock_config(spelling: str) -> AshConfig:
    """A config with a Bedrock reporter section: on, with a profile of its own."""
    return AshConfig.model_validate(
        {
            "project_name": "t",
            "reporters": {
                spelling: {
                    "enabled": True,
                    "options": {
                        "aws_profile": "file-profile",
                        "aws_region": "us-west-2",
                    },
                }
            },
        }
    )


@pytest.fixture
def config_file(tmp_path: Path) -> Path:
    """A config file that is in no checkout of the scanned tree."""
    path = tmp_path / "elsewhere" / "ash.yaml"
    path.parent.mkdir()
    path.write_text("project_name: t\n", encoding="utf-8")
    return path


@pytest.mark.parametrize(
    "spelling", [BEDROCK, "BedrockSummary", "bedrock_summary", BEDROCK_WITH_IT]
)
def test_ash_report_does_not_run_a_reporter_the_file_spells_into_its_section(
    spelling, config_file
):
    config = _bedrock_config(spelling)
    confine_off_host_reporters_to_overrides(
        config, [config_file], [], REPORT_CONFIG_FILE
    )
    # What ash report reads: the section for the format name it was given.
    section = config.get_plugin_config(plugin_type="reporter", plugin_name=BEDROCK)
    assert off_host_reporter_refused(BedrockSummaryReporter, section) is True
    options = section.get("options") if isinstance(section, dict) else None
    assert "aws_profile" not in (options or {})


@pytest.mark.parametrize(
    "spelling", [BEDROCK, "BedrockSummary", "bedrock_summary", BEDROCK_WITH_IT]
)
def test_ash_merge_does_not_run_a_reporter_the_file_spells_into_its_section(
    spelling, config_file
):
    operator_config = _bedrock_config(spelling)
    confine_off_host_reporters_to_overrides(
        operator_config, [config_file], [], MERGE_CONFIG_FILE
    )
    _, off_host, _ = select_merge_reporters(
        [BedrockSummaryReporter], None, operator_config
    )
    assert off_host == []


# ---------------------------------------------------------------------------
# The workspace policy's scanner names
# ---------------------------------------------------------------------------


def test_the_policy_folds_scanner_names_with_the_same_lowering():
    assert normalise_scanner_name("Snyk-Code") == normalise_scanner_name(SNYK_CODE)
    assert normalise_scanner_name(SNYK_CODE_WITH_IT) != normalise_scanner_name(
        SNYK_CODE
    )


def test_a_policy_scanner_is_added_when_the_project_key_is_not_that_scanners_section():
    policy = WorkspacePolicyConfig(additional_scanners=[SNYK_CODE])
    resolved = policy_for_project(
        policy,
        project_prefix="api",
        project_threshold="MEDIUM",
        project_scanners=(SNYK_CODE_WITH_IT,),
    )
    assert resolved.policy_scanners == (SNYK_CODE,)


def test_control_a_policy_scanner_the_project_declares_is_not_added():
    policy = WorkspacePolicyConfig(additional_scanners=[SNYK_CODE])
    resolved = policy_for_project(
        policy,
        project_prefix="api",
        project_threshold="MEDIUM",
        project_scanners=("SNYK_CODE",),
    )
    assert resolved.policy_scanners == ()


def test_enabling_a_policy_scanner_gives_it_a_section_of_its_own():
    config = AshConfig.model_validate(
        {"project_name": "t", "scanners": {SNYK_CODE_WITH_IT: {"enabled": False}}}
    )
    _enable_policy_scanners(config, [SNYK_CODE])
    dumped = config.scanners.model_dump(by_alias=True)
    assert SNYK_CODE in dumped
    assert dumped[SNYK_CODE]["enabled"] is True
    assert dumped[SNYK_CODE_WITH_IT]["enabled"] is False


# ---------------------------------------------------------------------------
# A key with no ASCII letter, digit or "+" has no spelling to be read under
# ---------------------------------------------------------------------------

#: Two keys made only of characters the reduction drops, written as code points.
NO_ASCII_KEY = chr(0x4E2D) + chr(0x6587)
OTHER_NO_ASCII_KEY = chr(0x65E5) + chr(0x672C)


@pytest.mark.parametrize(
    "plugin", ["Reporter", "Scanner", "ConverterConfig", OTHER_NO_ASCII_KEY]
)
def test_a_key_with_no_ascii_letter_is_no_plugins_section(plugin):
    """A plugin whose reduced name is empty reads no section by that empty name."""
    assert reduced_plugin_name(plugin) == ""

    assert _reads({NO_ASCII_KEY: {"enabled": True}}, "reporter", plugin) is None


@pytest.mark.parametrize(
    "plugin", ["Reporter", "Scanner", "ConverterConfig", OTHER_NO_ASCII_KEY]
)
def test_a_key_that_is_the_empty_string_is_no_plugins_section(plugin):
    """The empty reduced name of these plugins must not match a section keyed
    ``""``, which is what ``scanners: {"": {...}}`` in a config file writes."""
    assert reduced_plugin_name(plugin) == ""

    assert _reads({"": {"enabled": True}}, "reporter", plugin) is None


def test_control_an_ascii_key_is_still_read_by_its_plugin():
    section = {"enabled": True}

    assert _reads({"csv": section, NO_ASCII_KEY: {}}, "reporter", "CSVReporter") is (
        section
    )
    assert _reads({"": {}, "csv": section}, "reporter", "CSVReporter") is section


def test_the_policy_keeps_names_with_no_ascii_letter_apart():
    """``normalise_scanner_name`` falls back to the name itself when the
    reduction leaves nothing, so two such names are two scanners."""
    assert normalise_scanner_name(NO_ASCII_KEY) == NO_ASCII_KEY
    assert normalise_scanner_name(NO_ASCII_KEY) != normalise_scanner_name(
        OTHER_NO_ASCII_KEY
    )
    assert normalise_scanner_name(f" {NO_ASCII_KEY} ") == NO_ASCII_KEY
    assert normalise_scanner_name(f"-{NO_ASCII_KEY}") == f"_{NO_ASCII_KEY}"
