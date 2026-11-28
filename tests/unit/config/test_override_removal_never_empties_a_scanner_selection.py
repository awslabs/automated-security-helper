"""An edit of a scanner selection never turns it into the mode's default set.

``default_scanners.only`` and ``precommit.only_scanners`` narrow a run to the
scanners they name. Empty, each is no selection: the mode's default set runs, which
outside precommit mode is every enabled scanner. The empty value is the default,
not a list of names, so ``+=`` onto it would narrow the run to the names it adds,
and ``-=`` from it would take nothing out while the named scanner still ran. A
``-=`` that took the last name out of a list would turn a run narrowed to some
scanners into a run of the default set. The application that builds a command's
own configuration (``warn_unread_appends=True``) refuses each of them, naming the
replace form, the key that adds to the default set and ``--exclude-scanners``, as
the command line refuses an exclusion that cancels the selection it applies to.
Every other edit is applied as written, and a replay of the same overrides onto
another base (a view, a gate) applies every edit as written.

A scan whose configuration's chain holds a file of the repository takes
``default_scanners`` from the operator's own configuration, with the selection
overrides replayed onto it. That replay is the run's selection, so the edit is
judged there, with or without a config file in the repository. ``ash config
validate`` reports the refusal a scan gives for a file outside the repository, and
none for the repository's own file that a scan would not give.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import (
    apply_config_overrides,
    resolve_config,
)
from automated_security_helper.core.exceptions import ASHConfigValidationError
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit

#: The two selection lists, by override key.
SELECTIONS = [
    pytest.param("default_scanners.only", id="default-scanners-only"),
    pytest.param("precommit.only_scanners", id="precommit-only-scanners"),
]
#: The key that adds scanners to the set each selection list runs while empty.
ADDS = {
    "default_scanners.only": "default_scanners.add",
    "precommit.only_scanners": "precommit.add_scanners",
}


def _selection(key: str, overrides: list[str], own_configuration: bool) -> list[str]:
    """The list at *key* after *overrides*, each written as ``{key}{override}``."""
    config = apply_config_overrides(
        AshConfig(),
        [f"{key}{override}" for override in overrides],
        warn_unread_appends=own_configuration,
    )
    section, option = key.split(".")
    return list(getattr(getattr(config, section), option))


@pytest.mark.parametrize("key", SELECTIONS)
def test_a_removal_that_would_empty_a_scanner_selection_is_refused(key):
    """The first override narrows the run to detect-secrets. Taking that name out
    would leave the list empty, and the run would execute the mode's default
    scanners, detect-secrets among them. The run's own build refuses the removal and
    names the replace form."""
    with pytest.raises(ASHConfigValidationError) as refused:
        _selection(
            key,
            ['=["detect-secrets"]', '-=["detect-secrets"]'],
            own_configuration=True,
        )

    text = str(refused.value)
    assert "would leave" in text, text
    assert f"'{key}=[...]'" in text, text


@pytest.mark.parametrize("key", SELECTIONS)
@pytest.mark.parametrize(
    ("overrides", "own_configuration", "expected"),
    [
        pytest.param(
            ['=["bandit", "detect-secrets"]', '-=["detect-secrets"]'],
            True,
            ["bandit"],
            id="removal-leaving-a-name",
        ),
        pytest.param(
            ['=["bandit"]', '+=["checkov"]'],
            True,
            ["bandit", "checkov"],
            id="append-onto-a-written-list",
        ),
        pytest.param(
            ['=["detect-secrets"]', '-=["detect-secrets"]'],
            False,
            [],
            id="replayed-emptying-removal",
        ),
        pytest.param(
            ['+=["bandit"]'], False, ["bandit"], id="replayed-append-onto-empty"
        ),
    ],
)
def test_every_other_edit_of_a_scanner_selection_is_applied(
    key, overrides, own_configuration, expected
):
    """Control: a removal that leaves a name and an append onto a list that names
    scanners are applied in the run's own build, and a replay applies every edit as
    written, the emptying removal and the append onto the empty list included."""
    assert _selection(key, overrides, own_configuration) == expected


@pytest.mark.parametrize("key", SELECTIONS)
@pytest.mark.parametrize("operator", ["+=", "-="], ids=["append", "remove"])
def test_an_edit_of_an_empty_scanner_selection_is_refused(key, operator):
    """Empty, the list is not a list of names but the default set, so neither edit
    has a list to act on: the append would narrow the run to bandit, and the
    removal would take nothing out while bandit still ran. The run's own build
    refuses both, naming the replace form, the key that adds to the default set
    and the flag that leaves scanners out of it, never the item."""
    with pytest.raises(ASHConfigValidationError) as refused:
        _selection(key, [f'{operator}["bandit"]'], own_configuration=True)

    text = str(refused.value)
    assert "is empty" in text, text
    assert f"'{key}=[...]'" in text, text
    assert f"'{ADDS[key]}=[...]'" in text, text
    assert "--exclude-scanners" in text, text
    assert "bandit" not in text, text


def _write(path: Path, document: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def _layout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operator_only: list[str] | None,
    repository_config: dict[str, Any] | None,
) -> Path:
    """A repository to scan, as a checkout, with *repository_config* as its own
    config file when one is given. ``ASH_CONFIG`` names an operator's file outside
    every checkout that selects *operator_only*, or no file when it is None."""
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    if operator_only is not None:
        operator_file = _write(
            tmp_path / "operator" / "ash.yaml",
            {"default_scanners": {"only": operator_only}},
        )
        monkeypatch.setenv("ASH_CONFIG", str(operator_file))
    repo = tmp_path / "repo"
    mark_git_checkout(repo)
    if repository_config is not None:
        _write(repo / ".ash.yaml", repository_config)
    return repo


def _scanned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operator_only: list[str] | None,
    repository_config: dict[str, Any] | None,
    overrides: list[str],
) -> AshConfig:
    """What a scan of the repository resolves, *overrides* being the operator's
    ``--config-overrides``."""
    repo = _layout(tmp_path, monkeypatch, operator_only, repository_config)
    return resolve_config(source_dir=repo, config_overrides=overrides)


def _check_errors(checked: Path, repo: Path, overrides: list[str]) -> list[str]:
    """The errors ``ash config validate`` reports for *checked*, read for a scan
    of *repo* with *overrides*."""
    from automated_security_helper.config.config_validator import ConfigValidator

    return ConfigValidator.check_config_file(
        checked, source_dir=repo, config_overrides=overrides
    ).errors


#: The repository's own config file, which selects no scanners.
REPOSITORY_CONFIG = {"project_name": "repo"}
LAYOUTS = [
    pytest.param(REPOSITORY_CONFIG, id="repository-config"),
    pytest.param(None, id="no-repository-config"),
]
#: Edits the operator's selection allows, each with the selection it leaves.
ALLOWED_EDITS = [
    pytest.param(
        ["bandit", "checkov"],
        ['default_scanners.only-=["bandit"]'],
        ["checkov"],
        id="removal-leaving-a-name",
    ),
    pytest.param(
        ["bandit"],
        ['default_scanners.only+=["checkov"]'],
        ["bandit", "checkov"],
        id="append-onto-the-operators-list",
    ),
    pytest.param(
        ["bandit"],
        [
            'default_scanners.only+=["checkov"]',
            'default_scanners.only-=["checkov"]',
        ],
        ["bandit"],
        id="append-then-removal",
    ),
]


@pytest.mark.parametrize("repository_config", LAYOUTS)
def test_a_removal_that_would_empty_the_operators_selection_is_refused(
    tmp_path, monkeypatch, repository_config
):
    """The operator's file narrows the run to bandit. With a config file of its own
    in the repository, the scan builds its configuration from that file, which
    selects nothing, and gives the run the operator's selection with the overrides
    replayed onto it; without one, the operator's file is the configuration.
    Either way taking bandit out would leave the run's selection empty, so the
    removal is refused."""
    with pytest.raises(ASHConfigValidationError) as refused:
        _scanned(
            tmp_path,
            monkeypatch,
            ["bandit"],
            repository_config,
            ['default_scanners.only-=["bandit"]'],
        )

    text = str(refused.value)
    assert "would leave" in text, text
    assert "'default_scanners.only=[...]'" in text, text


@pytest.mark.parametrize(("operator_only", "overrides", "expected"), ALLOWED_EDITS)
def test_an_edit_the_operators_selection_allows_is_applied(
    tmp_path, monkeypatch, operator_only, overrides, expected
):
    """The repository's config file selects nothing, so the build of the file
    starts from an empty list, but the run's selection is the operator's with the
    overrides replayed onto it. Each edit there leaves the operator's list a name,
    so ``ash config validate`` of the repository's file reports nothing about it,
    and the scan refuses none and selects what the edits made of that list."""
    repo = _layout(tmp_path, monkeypatch, operator_only, REPOSITORY_CONFIG)

    errors = _check_errors(repo / ".ash.yaml", repo, overrides)
    assert not [error for error in errors if "default_scanners.only" in error], errors

    config = resolve_config(source_dir=repo, config_overrides=overrides)
    assert list(config.default_scanners.only) == expected


@pytest.mark.parametrize(
    ("operator_only", "override", "words"),
    [
        pytest.param(["bandit"], '-=["bandit"]', "would leave", id="emptying-removal"),
        pytest.param([], '+=["bandit"]', "is empty", id="append-onto-empty"),
    ],
)
def test_the_config_check_refuses_what_a_scan_using_the_file_refuses(
    tmp_path, monkeypatch, operator_only, override, words
):
    """A config file outside the repository is the selection of a scan that uses
    it, so ``ash config validate`` of it reports the refusal that scan gives."""
    repo = _layout(tmp_path, monkeypatch, None, None)
    checked = _write(
        tmp_path / "elsewhere" / "ash.yaml",
        {"default_scanners": {"only": operator_only}},
    )

    errors = _check_errors(checked, repo, [f"default_scanners.only{override}"])

    assert [error for error in errors if words in error], errors


@pytest.mark.parametrize("repository_config", LAYOUTS)
@pytest.mark.parametrize("operator", ["+=", "-="], ids=["append", "remove"])
def test_an_edit_of_an_empty_run_selection_is_refused(
    tmp_path, monkeypatch, operator, repository_config
):
    """No file the operator owns selects scanners, so the run's selection is empty
    and the run executes the mode's default set. With or without a config file in
    the repository, an append or a removal has no list of names to act on there,
    and the scan refuses it."""
    with pytest.raises(ASHConfigValidationError) as refused:
        _scanned(
            tmp_path,
            monkeypatch,
            None,
            repository_config,
            [f'default_scanners.only{operator}["bandit"]'],
        )

    assert "is empty" in str(refused.value), str(refused.value)


def test_a_removal_that_would_empty_a_repositorys_precommit_selection_is_refused(
    tmp_path, monkeypatch
):
    """Control: a run reads its precommit selection from the configuration the edit
    applies to, a repository's own config file included, so the command's own
    build refuses the emptying removal there, where the run takes default_scanners
    from the operator."""
    with pytest.raises(ASHConfigValidationError) as refused:
        _scanned(
            tmp_path,
            monkeypatch,
            None,
            {"precommit": {"only_scanners": ["bandit"]}},
            ['precommit.only_scanners-=["bandit"]'],
        )

    assert "would leave" in str(refused.value), str(refused.value)
