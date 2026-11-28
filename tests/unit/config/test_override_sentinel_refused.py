"""``+=`` and ``-=`` on a list whose value means every item are refused.

Three list options hold a value that stands for every item rather than for the
items it lists: checkov's ``frameworks`` defaults to ``["all"]``, and checkov runs a
written ``frameworks: []`` as ``all`` too; detect-secrets'
``scan_settings.plugins_used`` defaults to ``[]``, which runs every detector
detect-secrets has; and a file that writes trivy-repo's ``scanners: []`` leaves the
choice of scanners to trivy. ``KEY+=[...]`` on such a value has no list to add to,
and ``KEY-=[...]`` none to take items out of, so the application that builds the
run's own configuration (``warn_unread_appends=True``) refuses both, and refuses a
removal that would leave the option holding that value. Each refusal names the
replace form, ``KEY=[...]``, which is applied as before, and so is an edit of a list
an override wrote.

The same overrides are replayed onto other bases (the trusted views, the gates),
which can hold such a value where the real document holds a list, so a replay
applies the edit as written: refusing there would end a run its own build accepted.
"""

from __future__ import annotations

import json

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import apply_config_overrides
from automated_security_helper.core.exceptions import ASHConfigValidationError

pytestmark = pytest.mark.unit

CHECKOV = "scanners.checkov.options.frameworks"
DETECT_SECRETS = "scanners.detect-secrets.options.scan_settings.plugins_used"
TRIVY_REPO = "scanners.trivy-repo.options.scanners"
#: An entry of detect-secrets' ``plugins_used``: a detector named by its class.
DETECTOR = {"name": "AWSKeyDetector"}


def _checkov_frameworks(config: AshConfig) -> list[str]:
    """The frameworks the configuration gives checkov."""
    return list(config.scanners.checkov.options.frameworks)


def _detect_secrets_detectors(config: AshConfig) -> list[str]:
    """The names of the detectors the configuration gives detect-secrets."""
    settings = config.scanners.detect_secrets.options.scan_settings
    return [plugin.name for plugin in settings.plugins_used]


def _trivy_repo_scanners(config: AshConfig) -> list[str]:
    """The scanners trivy-repo's section holds. The section is not typed, so the
    configuration keeps it as the mapping the file or the override wrote."""
    section = config.get_plugin_config("scanner", "trivy-repo")
    return list(section["options"]["scanners"])


def _trivy_repo_written_empty() -> AshConfig:
    """A configuration whose file writes trivy-repo's ``scanners: []``. The option's
    unwritten default is a list of four scanners, so only a file that writes ``[]``
    holds the value that leaves the choice to trivy."""
    return AshConfig.model_validate(
        {"scanners": {"trivy-repo": {"options": {"scanners": []}}}}
    )


def _checkov_written_empty() -> AshConfig:
    """A configuration whose file writes checkov's ``frameworks: []``, which checkov
    runs as ``all``, as it runs the default ``["all"]``."""
    return AshConfig.model_validate(
        {"scanners": {"checkov": {"options": {"frameworks": []}}}}
    )


def test_an_append_to_checkovs_every_framework_value_is_refused():
    """checkov's default ``["all"]`` already runs terraform, so the append has no
    list to add the framework to. The refusal names the replace form, and never the
    item the override gave."""
    assert _checkov_frameworks(AshConfig()) == ["all"], "control: the default"

    with pytest.raises(ASHConfigValidationError) as refused:
        apply_config_overrides(
            AshConfig(), [f'{CHECKOV}+=["terraform"]'], warn_unread_appends=True
        )

    text = str(refused.value)
    assert "which means every item" in text, text
    assert f"'{CHECKOV}=[...]'" in text, text
    assert "terraform" not in text, text


def test_a_removal_from_checkovs_every_framework_value_is_refused():
    """``all`` stands for frameworks it does not list, so there is no list to take
    an item out of."""
    with pytest.raises(ASHConfigValidationError) as refused:
        apply_config_overrides(
            AshConfig(), [f'{CHECKOV}-=["all"]'], warn_unread_appends=True
        )

    text = str(refused.value)
    assert "which means every item" in text, text
    assert f"'{CHECKOV}=[...]'" in text, text


def test_an_append_to_detect_secrets_every_plugin_value_is_refused():
    """``plugins_used: []``, the default, runs every detector detect-secrets has; an
    append would narrow the run to the detectors it names."""
    assert _detect_secrets_detectors(AshConfig()) == [], "control: the default"

    with pytest.raises(ASHConfigValidationError) as refused:
        apply_config_overrides(
            AshConfig(),
            [f"{DETECT_SECRETS}+={json.dumps([DETECTOR])}"],
            warn_unread_appends=True,
        )

    text = str(refused.value)
    assert "which means every item" in text, text
    assert f"'{DETECT_SECRETS}=[...]'" in text, text
    assert DETECTOR["name"] not in text, text


@pytest.mark.parametrize("operator", ["+=", "-="], ids=["append", "remove"])
def test_an_edit_of_trivy_repos_empty_scanners_is_refused(operator):
    """With ``scanners: []`` ASH passes trivy no ``--scanners`` and trivy chooses, so
    neither an append nor a removal has a list to act on."""
    with pytest.raises(ASHConfigValidationError) as refused:
        apply_config_overrides(
            _trivy_repo_written_empty(),
            [f'{TRIVY_REPO}{operator}["vuln"]'],
            warn_unread_appends=True,
        )

    text = str(refused.value)
    assert "which means every item" in text, text
    assert f"'{TRIVY_REPO}=[...]'" in text, text


def test_a_removal_that_would_leave_every_item_is_refused():
    """The first override gives trivy-repo ``["vuln"]``, so the removal has a list to
    take ``vuln`` out of, but what it would leave, ``[]``, hands the choice back to
    trivy, which can run the very scanner the removal took out."""
    with pytest.raises(ASHConfigValidationError) as refused:
        apply_config_overrides(
            AshConfig(),
            [f'{TRIVY_REPO}=["vuln"]', f'{TRIVY_REPO}-=["vuln"]'],
            warn_unread_appends=True,
        )

    text = str(refused.value)
    assert "would leave" in text, text
    assert "which means every item" in text, text


@pytest.mark.parametrize(
    ("base", "override", "read", "expected"),
    [
        pytest.param(
            AshConfig,
            f'{CHECKOV}=["terraform"]',
            _checkov_frameworks,
            ["terraform"],
            id="checkov",
        ),
        pytest.param(
            AshConfig,
            f"{DETECT_SECRETS}={json.dumps([DETECTOR])}",
            _detect_secrets_detectors,
            [DETECTOR["name"]],
            id="detect-secrets",
        ),
        pytest.param(
            _trivy_repo_written_empty,
            f'{TRIVY_REPO}=["vuln"]',
            _trivy_repo_scanners,
            ["vuln"],
            id="trivy-repo",
        ),
        pytest.param(
            _checkov_written_empty,
            f'{CHECKOV}=["terraform"]',
            _checkov_frameworks,
            ["terraform"],
            id="checkov-written-empty",
        ),
    ],
)
def test_a_replacement_of_a_sentinel_is_unchanged(base, override, read, expected):
    """Control: the replace form each refusal names is applied in the application
    that refuses the edit, so the refusal is of the edit and not of the option."""
    config = apply_config_overrides(base(), [override], warn_unread_appends=True)

    assert read(config) == expected


def test_an_edit_of_a_written_list_is_unchanged():
    """Control: once an override wrote ``frameworks``, it holds the frameworks it
    lists and not every item, so an append to it is applied in the run's own
    application."""
    config = apply_config_overrides(
        AshConfig(),
        [f'{CHECKOV}=["terraform"]', f'{CHECKOV}+=["kubernetes"]'],
        warn_unread_appends=True,
    )

    assert _checkov_frameworks(config) == ["terraform", "kubernetes"]


def test_a_replay_applies_a_sentinel_edit_as_written():
    """Control: an application without ``warn_unread_appends`` (a replay, a view or a
    gate) works on a base that can hold the default where the real document holds a
    list, so it refuses nothing and the append lands as it always has."""
    config = apply_config_overrides(AshConfig(), [f'{CHECKOV}+=["terraform"]'])

    assert _checkov_frameworks(config) == ["all", "terraform"]


def test_the_sentinel_table_names_the_three_options():
    """The table the refusals read: each option by its plugin segment, the plugin's
    own name and its key below the section, with the value that means every item."""
    from automated_security_helper.plugin_manifests import OVERRIDE_EDIT_SENTINELS

    table = {
        segment: {plugin: dict(row) for plugin, row in plugins.items()}
        for segment, plugins in OVERRIDE_EDIT_SENTINELS.items()
    }
    assert table == {
        "scanners": {
            "checkov": {("options", "frameworks"): ("all",)},
            "detect-secrets": {("options", "scan_settings", "plugins_used"): ()},
            "trivy-repo": {("options", "scanners"): ()},
        }
    }


def test_an_append_of_a_framework_all_leaves_out_is_accepted():
    """Control: checkov's ``all`` leaves out the frameworks that read a hosted
    service's repository settings, and checkov's own help says to name one with or
    without ``all``. Adding one to the default is an append, refused at no point."""
    config = apply_config_overrides(
        AshConfig(),
        [f'{CHECKOV}+=["github_configuration"]'],
        warn_unread_appends=True,
    )

    assert _checkov_frameworks(config) == ["all", "github_configuration"]


def test_an_append_beside_a_framework_all_leaves_out_is_still_refused():
    """Only an append whose every item is one ``all`` leaves out is let through."""
    with pytest.raises(ASHConfigValidationError, match="which means every item"):
        apply_config_overrides(
            AshConfig(),
            [f'{CHECKOV}+=["github_configuration", "terraform"]'],
            warn_unread_appends=True,
        )


def test_the_additions_table_names_checkovs_hosted_service_frameworks():
    """The items an append may still add to checkov's ``["all"]``."""
    from automated_security_helper.plugin_manifests import (
        OVERRIDE_EDIT_SENTINEL_ADDITIONS,
    )

    row = OVERRIDE_EDIT_SENTINEL_ADDITIONS["scanners"]["checkov"]
    assert dict(row) == {
        ("options", "frameworks"): frozenset(
            {"bitbucket_configuration", "github_configuration", "gitlab_configuration"}
        )
    }


@pytest.mark.parametrize(
    ("operator", "item"),
    [
        pytest.param("+=", "terraform", id="append"),
        pytest.param("+=", "github_configuration", id="append-a-framework-all-omits"),
        pytest.param("-=", "terraform", id="remove"),
    ],
)
def test_an_edit_of_checkovs_empty_frameworks_is_refused(operator, item):
    """checkov runs a written ``frameworks: []`` as ``all``, so the empty list
    stands for every framework, as the default does. An append would narrow the run
    to the framework it names, one ``all`` leaves out included, since nothing else
    is in the list, and a removal has no list to take it from."""
    assert _checkov_frameworks(_checkov_written_empty()) == [], "control: the file"

    with pytest.raises(ASHConfigValidationError) as refused:
        apply_config_overrides(
            _checkov_written_empty(),
            [f'{CHECKOV}{operator}["{item}"]'],
            warn_unread_appends=True,
        )

    text = str(refused.value)
    assert "holds [], which means every item" in text, text
    assert f"'{CHECKOV}=[...]'" in text, text
    assert item not in text, text


def test_a_removal_that_would_leave_checkovs_frameworks_empty_is_refused():
    """The first override gives checkov ``["terraform"]``. Taking it out would leave
    ``[]``, which checkov runs as ``all``, so the run would scan every framework
    where it scanned one."""
    with pytest.raises(ASHConfigValidationError) as refused:
        apply_config_overrides(
            AshConfig(),
            [f'{CHECKOV}=["terraform"]', f'{CHECKOV}-=["terraform"]'],
            warn_unread_appends=True,
        )

    text = str(refused.value)
    assert "would leave" in text, text
    assert "holding [], which means every item" in text, text


def test_a_removal_that_leaves_checkov_a_framework_is_applied():
    """Control: a removal that leaves a framework in the list is applied in the
    run's own application."""
    config = apply_config_overrides(
        AshConfig(),
        [f'{CHECKOV}=["terraform", "kubernetes"]', f'{CHECKOV}-=["terraform"]'],
        warn_unread_appends=True,
    )

    assert _checkov_frameworks(config) == ["kubernetes"]
