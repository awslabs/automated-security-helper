"""A ``key-=`` removal never passes a trust guard as a value the operator set.

``--config-overrides`` takes ``KEY=VALUE``, which writes a value, ``KEY+=VALUE``,
which adds items to the list at KEY, and ``KEY-=VALUE``, which takes items out of
it. What a removal leaves is the list the chain held less those items, so it can
be exactly what the repository's own file wrote: a removal writes nothing of the
operator's. Several modules decide something from the key of each override, and
read with the operator dropped, a removal would look like a write to each of
them:

* the operator-only options (``_set_by_override``) would keep the repository's
  ``archive_resolved_findings`` or ``max_worker_output_mib``;
* the scanner config confinement (``landings_of`` and ``_covered``) would leave
  the repository's list at the path of a removal the trusted base refused;
* the record of the paths the operator named (``parse_overrides``) would credit
  a repository path as the operator's;
* the config check's ignored-destination warning (``override_writes``) would go
  quiet about a repository value no scan keeps.

Two more readers must take a removal the way they take the append of the same
text: the plugin module confinement replays it onto the trusted list, and the
override path anchoring (``anchor_override_paths``) anchors its value as the
list entry an append adds, so the two name one entry.

A test that passes before ``-=`` exists says why in its docstring: there, a
removal keeps its ``-`` on the key, which then names no option at all.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List

import pytest
from typer.testing import CliRunner

import automated_security_helper.config.resolve_config as resolve_module
from automated_security_helper.cli.config import config_app
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.path_trust import OperatorPaths, parse_overrides
from automated_security_helper.config.resolve_config import (
    apply_config_overrides,
    resolve_config,
)
from automated_security_helper.config.tool_config_trust import (
    confine_scanner_config_files,
)
from automated_security_helper.core.exceptions import ASHConfigValidationError

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _no_override_notice_carried_between_tests(monkeypatch: pytest.MonkeyPatch):
    """The once-per-run notices of the override grammar start empty in each test.

    None of these tests asserts a notice; the set is reset so that one these
    tests give cannot hide another test's. It exists only once ``-=`` does,
    hence ``raising=False``.
    """
    monkeypatch.setattr(resolve_module, "_OVERRIDE_NOTICES_GIVEN", set(), raising=False)


def _warnings(records: List[logging.LogRecord]) -> List[str]:
    return [r.getMessage() for r in records if r.levelno >= logging.WARNING]


# --- operator_only_options._set_by_override ---------------------------------

#: An operator-only option's kind, the resolved sections of that kind, the
#: section and the option, and a removal at the mapping above the option or at
#: the option itself.
OPERATOR_ONLY_REMOVALS = [
    pytest.param(
        "reporters",
        {
            "aws-security-hub": {
                "options": {
                    "archive_resolved_findings": True,
                    "findings_scope": "repository-scope",
                }
            }
        },
        "aws-security-hub",
        "archive_resolved_findings",
        'reporters.aws-security-hub.options-=["findings_scope"]',
        id="reporter-options",
    ),
    pytest.param(
        "reporters",
        {"aws-security-hub": {"options": {"archive_resolved_findings": True}}},
        "aws-security-hub",
        "archive_resolved_findings",
        "reporters.aws-security-hub.options.archive_resolved_findings-=true",
        id="reporter-option",
    ),
    pytest.param(
        "scanners",
        {"detect-secrets": {"options": {"max_worker_output_mib": 4096}}},
        "detect-secrets",
        "max_worker_output_mib",
        'scanners.detect-secrets.options-=["max_worker_output_mib"]',
        id="scanner-options",
    ),
]


@pytest.mark.parametrize(
    ("kind", "sections", "section", "option", "removal"), OPERATOR_ONLY_REMOVALS
)
def test_a_removal_never_makes_an_operator_only_option_the_operators(
    kind: str, sections: Dict[str, Any], section: str, option: str, removal: str
) -> None:
    """A removal at the option, or at the mapping above it, sets nothing.

    Counted as a write, it would make the confinement skip the option and keep
    the value it has, which is the repository's: its
    ``archive_resolved_findings: true`` would archive findings in the operator's
    account. The same key written as a set counts, alone and after the
    removal, so the removal is told apart by its operator alone; read without
    it, the removal is that set. Passes before ``-=`` exists: the key keeps its
    ``-`` there, and ``options-`` or ``archive_resolved_findings-`` resolves to
    no key on the option's path.
    """
    from automated_security_helper.config.operator_only_options import (
        _set_by_override,
    )

    written = removal.replace("-=", "=", 1)

    assert _set_by_override(sections, section, option, [written], kind=kind)
    assert not _set_by_override(sections, section, option, [removal], kind=kind)
    assert _set_by_override(sections, section, option, [removal, written], kind=kind)


# --- tool_config_trust.landings_of and _covered -----------------------------

#: A removal of one item from opengrep's ``patterns``, which replaces every rule
#: config opengrep runs.
PATTERNS_REMOVAL = "scanners.opengrep.options.patterns-=extra-rule"


def _refuse_opengrep_on_the_trusted_base(monkeypatch: pytest.MonkeyPatch) -> None:
    """``apply_config_overrides`` refuses any set naming opengrep on the trusted
    base (its ``project_name`` is ``op``); the resolved config takes it."""
    real = resolve_module.apply_config_overrides

    def refusing(
        config: AshConfig, overrides: List[str], *args: Any, **kwargs: Any
    ) -> AshConfig:
        if config.project_name == "op" and any(
            "opengrep" in item for item in overrides
        ):
            raise ASHConfigValidationError("refused")
        return real(config, overrides, *args, **kwargs)

    monkeypatch.setattr(resolve_module, "apply_config_overrides", refusing)


def _patterns(config: AshConfig) -> List[str]:
    return list(config.scanners.opengrep.options.patterns)


def _resolved_after_the_removal(applied: bool) -> AshConfig:
    """The resolved config, holding the repository's list less the removed item:
    built by the apply from the list the repository wrote, or written that way."""
    if applied:
        return apply_config_overrides(
            AshConfig.model_validate(
                {
                    "project_name": "repo",
                    "scanners": {
                        "opengrep": {
                            "options": {"patterns": ["repo-rule", "extra-rule"]}
                        }
                    },
                }
            ),
            [PATTERNS_REMOVAL],
        )
    return AshConfig.model_validate(
        {
            "project_name": "repo",
            "scanners": {"opengrep": {"options": {"patterns": ["repo-rule"]}}},
        }
    )


@pytest.mark.parametrize("applied", [True, False], ids=["applied", "built"])
def test_a_dropped_removal_covers_no_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    ash_log: List[logging.LogRecord],
    applied: bool,
) -> None:
    """A removal the trusted base refused leaves the trusted base's list at its path.

    The operator removed one item from opengrep's ``patterns`` and the trusted
    base could not take the removal, so the resolved list holds the
    repository's own rule. Counted as a set, the dropped removal would cover its
    path and keep that rule as the operator's. The warning for the dropped
    removal says what happens instead, never that its value stays as the
    operator wrote it.

    ``applied`` builds the resolved list with the removal itself, which needs
    ``-=``; ``built`` writes that list directly and measures the confinement
    alone. Before ``-=`` exists, ``built`` already ends with the trusted list
    (the dropped key keeps its ``-``, which no path matches) and fails only on
    the warning's wording.
    """
    config = _resolved_after_the_removal(applied)
    assert _patterns(config) == ["repo-rule"]
    trusted = AshConfig.model_validate(
        {
            "project_name": "op",
            "scanners": {"opengrep": {"options": {"patterns": ["base-rule"]}}},
        }
    )
    _refuse_opengrep_on_the_trusted_base(monkeypatch)

    confine_scanner_config_files(
        config, trusted, [PATTERNS_REMOVAL], [tmp_path / ".ash.yaml"]
    )

    assert _patterns(config) == ["base-rule"]
    dropped = [
        message
        for message in _warnings(ash_log)
        if "cannot take" in message and "scanners.opengrep.options.patterns" in message
    ]
    assert len(dropped) == 1, dropped
    assert "stays as the operator wrote it" not in dropped[0], dropped[0]
    assert "where it would have removed items" in dropped[0], dropped[0]
    assert not [message for message in _warnings(ash_log) if "extra-rule" in message]


# --- path_trust.parse_overrides ---------------------------------------------

CHECKOV_CONFIG_FILE = "scanners.checkov.options.config_file"


def test_a_removal_names_no_operator_path() -> None:
    """A removal is left out of the record of the paths the operator named.

    The record matches the operator's spelling leniently (``/ops/./c.yaml``
    names ``/ops/c.yaml``), so a removal recorded as a path would credit the
    repository's ``/ops/c.yaml`` as the operator's: "not this path" read as the
    operator's trust in it. The set of the same spelling is the control the
    lenient match credits, and a set after a removal is still recorded.
    """
    assert parse_overrides([f"{CHECKOV_CONFIG_FILE}-=/ops/c.yaml"]) == []
    mixed = parse_overrides(
        [f"{CHECKOV_CONFIG_FILE}-=/ops/c.yaml", f"{CHECKOV_CONFIG_FILE}=/ops/a.yaml"]
    )
    assert mixed == [(CHECKOV_CONFIG_FILE, "/ops/a.yaml")]

    written = OperatorPaths(
        overrides=parse_overrides([f"{CHECKOV_CONFIG_FILE}=/ops/./c.yaml"])
    )
    removed = OperatorPaths(
        overrides=parse_overrides([f"{CHECKOV_CONFIG_FILE}-=/ops/./c.yaml"])
    )
    assert written.named(CHECKOV_CONFIG_FILE, "/ops/c.yaml")
    assert not removed.named(CHECKOV_CONFIG_FILE, "/ops/c.yaml")


# --- config_validator: the ignored-destination check ------------------------

#: A destination option of an off-host reporter whose value is a list.
BEDROCK_FRAMEWORKS = "reporters.bedrock-summary-reporter.options.compliance_frameworks"

FRAMEWORKS_IN_THE_FILE = (
    "project_name: demo\n"
    "reporters:\n"
    "  bedrock-summary-reporter:\n"
    "    options:\n"
    "      compliance_frameworks:\n"
    "        - SOC2\n"
)


def _validate(config: Path, override: str):
    return CliRunner().invoke(
        config_app,
        ["validate", "--config", str(config), "--config-overrides", override],
        env={"COLUMNS": "300", "NO_COLOR": "1"},
    )


def test_a_removal_does_not_decide_whether_the_files_value_stands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``ash config validate`` still warns that a scan ignores the file's list.

    A scan takes this option from the trusted base with the operator's
    overrides replayed onto it, so the repository file's ``[SOC2]`` is not kept
    whatever the override does. An override that writes the file's own value
    makes that value the operator's, and the check says nothing then (the
    control). A removal of the file's whole value writes no value: counted as
    that set, it would silence the warning about a value the scan drops. Passes
    before ``-=`` exists: the removal's key keeps its ``-`` there, and names no
    option the check compares with the file.
    """
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(project)
    config = project / ".ash.yaml"
    config.write_text(FRAMEWORKS_IN_THE_FILE, encoding="utf-8")
    ignored = (
        f"{BEDROCK_FRAMEWORKS} is set in a config file inside the scanned tree, "
        "and a scan ignores that value"
    )

    written = _validate(config, f'{BEDROCK_FRAMEWORKS}=["SOC2"]')
    removed = _validate(config, f'{BEDROCK_FRAMEWORKS}-=["SOC2"]')

    assert written.exit_code == 0, written.output
    assert ignored not in " ".join(written.output.split()), written.output
    assert removed.exit_code == 0, removed.output
    assert ignored in " ".join(removed.output.split()), removed.output


# --- plugin_module_trust.confine_plugin_modules -----------------------------

#: A stand-in package inside the scanned tree, whose ``__init__`` only defines a
#: constant. Its name is in the plugin namespace (``_ash_plugins``), so the
#: module confinement decides it, not the scan's namespace refusal.
STANDIN_MODULE = "removal_standin_ash_plugins"
INSTALLED_MODULE = "automated_security_helper.plugin_modules.ash_trivy_plugins"


@pytest.fixture
def plugin_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """A scanned tree whose ``.ash.yaml`` names the stand-in package in one
    comma-joined entry beside an installed module. The tree is on ``sys.path``,
    as a ``python -m`` launch from inside it puts it."""
    source = tmp_path / "repo"
    package = source / STANDIN_MODULE
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("STANDIN_LOADED = True\n")
    (source / ".ash.yaml").write_text(
        "project_name: scanned\n"
        "ash_plugin_modules:\n"
        f"  - {INSTALLED_MODULE},{STANDIN_MODULE}\n"
    )
    monkeypatch.syspath_prepend(str(source))
    monkeypatch.chdir(source)
    yield source
    loaded = [
        name
        for name in sys.modules
        if name == STANDIN_MODULE or name.startswith(f"{STANDIN_MODULE}.")
    ]
    for name in loaded:
        del sys.modules[name]


def test_a_removed_plugin_module_stays_removed_under_the_trusted_replay(
    plugin_tree: Path, ash_log: List[logging.LogRecord]
) -> None:
    """The removal is replayed onto the trusted list, as the append before it is.

    The operator's overrides add the stand-in and then remove it, so the
    operator names no such module, while the repository's comma-joined entry
    still names it: a removal takes out equal entries only. Replaying the
    append alone would leave the stand-in in the trusted list, and the in-tree
    package would be kept for the scan to import. With both replayed it is
    refused as any in-tree module is, and the installed module named in the
    same entry stays.
    """
    config = resolve_config(
        source_dir=plugin_tree,
        config_overrides=[
            f'ash_plugin_modules+=["{STANDIN_MODULE}"]',
            f'ash_plugin_modules-=["{STANDIN_MODULE}"]',
        ],
    )

    assert config.ash_plugin_modules == [INSTALLED_MODULE]
    assert STANDIN_MODULE not in sys.modules
    refused = [
        message
        for message in _warnings(ash_log)
        if "ash_plugin_modules" in message and STANDIN_MODULE in message
    ]
    assert len(refused) == 1, refused


# --- operator_paths.anchor_override_paths -----------------------------------


def _scanner_options(config: AshConfig, scanner: str) -> Dict[str, Any]:
    return (config.get_plugin_config("scanner", scanner) or {}).get("options") or {}


#: List options whose entries are paths an override's relative value is
#: anchored in, and how to read each list back.
LIST_PATH_OPTIONS = [
    pytest.param(
        "sandbox.extra_read_paths",
        lambda config: list(config.sandbox.extra_read_paths),
        id="sandbox-extra-read-paths",
    ),
    pytest.param(
        "scanners.cfn-guard.options.rules_paths",
        lambda config: list(
            _scanner_options(config, "cfn-guard").get("rules_paths") or []
        ),
        id="cfn-guard-rules-paths",
    ),
]


@pytest.mark.parametrize(("key", "listed"), LIST_PATH_OPTIONS)
def test_a_removal_names_the_entry_an_append_of_the_same_text_added(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    key: str,
    listed: Callable[[AshConfig], List[str]],
) -> None:
    """An append and then a removal of one relative path leave the list as it was.

    The append's relative value is taken from the working directory, so the
    list holds the anchored path, and a removal of the same text names that
    entry only when its value is anchored the same way, as an entry.
    ``extra_read_paths`` is anchored only as a list: its value anchored as the
    option's whole value stays relative and removes nothing. ``rules_paths``
    anchors a single path too, so its case pins the round trip, not the entry
    rule. The append alone is the control: its entry is the anchored path.
    """
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    workdir = tmp_path / "ci"
    rules = workdir / "rules" / "mine.guard"
    rules.parent.mkdir(parents=True)
    rules.write_text("# placeholder\n", encoding="utf-8")
    kept = tmp_path / "org" / "kept.guard"
    kept.parent.mkdir(parents=True)
    kept.write_text("# placeholder\n", encoding="utf-8")
    monkeypatch.chdir(workdir)
    start = f"{key}={json.dumps([kept.as_posix()])}"
    added = f"{key}+=rules/mine.guard"
    removed = f"{key}-=rules/mine.guard"

    appended = listed(resolve_config(source_dir=repo, config_overrides=[start, added]))
    assert len(appended) == 2, appended
    assert appended[0] == kept.as_posix(), appended
    assert Path(appended[1]).is_absolute(), appended
    assert Path(appended[1]).resolve() == rules.resolve(), appended

    after = listed(
        resolve_config(source_dir=repo, config_overrides=[start, added, removed])
    )
    assert after == [kept.as_posix()], after
