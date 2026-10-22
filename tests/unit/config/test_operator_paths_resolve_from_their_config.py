# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A relative path the operator sets is taken from where the operator set it.

An option that names a file or directory on the host (a scanner's own config file,
a baseline, a rules directory, a path the sandbox may read) can be relative. One
written in a config file is taken from that file's directory, one in an
``extends`` base from the base's directory, and one given with
``--config-overrides`` from the working directory ASH runs in
(``config/operator_paths.py``). None of them is taken from the scanned tree: the
tree is the repository being scanned, and a file there with the same name is the
repository's, not the one the operator named.

Each test puts the operator's file and a same-named decoy in the scanned tree,
and checks that the resolved option names the operator's file.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, List, NamedTuple
from unittest.mock import patch

import pytest
import yaml

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.config.tool_config_trust import (
    SCANNER_CONFIG_FILE_OPTIONS,
)
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScanner,
)
from automated_security_helper.utils.config_trust import (
    NOT_THE_OPERATORS,
    OperatorPath,
    operator_path,
    operator_paths,
)
from automated_security_helper.utils.uv_tool_runner import UVToolRunner


@pytest.fixture(autouse=True)
def _no_operator_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)


@pytest.fixture(autouse=True)
def _no_uv_probe():
    with patch.object(UVToolRunner, "is_uv_available", return_value=False):
        yield


def _write(path: Path, document: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    return path


def _touch(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# placeholder\n", encoding="utf-8")
    return path


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    return repo


def _options(config: AshConfig, scanner: str) -> Dict[str, Any]:
    return (config.get_plugin_config("scanner", scanner) or {}).get("options") or {}


def _same_file(value: Any, expected: Path) -> bool:
    """Whether ``value`` names ``expected`` wherever it is read from.

    Absolute, because a scanner joins a relative value to the source directory,
    and so does ``Path.resolve`` to the test's working directory.
    """
    if value is None or not Path(str(value)).is_absolute():
        return False
    return Path(str(value)).resolve() == expected.resolve()


class PathOption(NamedTuple):
    """One option, how a config document and an override set it, and how to read it back."""

    id: str
    document: Callable[[str], Dict[str, Any]]
    read: Callable[[AshConfig], Any]
    override: Callable[[str], str]


def _scanner_option(scanner: str, option: str) -> PathOption:
    return PathOption(
        f"{scanner}.{option}",
        lambda value: {"scanners": {scanner: {"options": {option: value}}}},
        lambda config: _options(config, scanner).get(option),
        lambda value: f"scanners.{scanner}.options.{option}={value}",
    )


class ScannerPath(NamedTuple):
    """An option a scanner hands to ``config_trust.operator_path``, and how.

    ``outside_tree`` is what the scanner passes: off for a findings config the
    operator may keep in the tree, on for a file that can make the tool load code.
    """

    scanner: str
    name: str
    option: PathOption
    outside_tree: bool

    @property
    def key(self) -> str:
        return f"scanners.{self.scanner}.options.{self.name}"


def _scanner_path(scanner: str, option: str, *, outside_tree: bool) -> ScannerPath:
    return ScannerPath(scanner, option, _scanner_option(scanner, option), outside_tree)


def _scanner_list_option(scanner: str, option: str) -> PathOption:
    """A list of paths, set with one entry and read back by its first."""
    return PathOption(
        f"{scanner}.{option}",
        lambda value: {"scanners": {scanner: {"options": {option: [value]}}}},
        lambda config: (_options(config, scanner).get(option) or [None])[0],
        lambda value: f"scanners.{scanner}.options.{option}={json.dumps([value])}",
    )


#: The path options of actionlint, cfn-guard, cfn-lint, gitleaks, zizmor, trivy
#: and trivy-repo, each as its scanner checks it. actionlint's ``shellcheck`` and
#: ``pyflakes`` are not here: a bare name there is a program looked up on PATH.
SCANNER_PATHS: List[ScannerPath] = [
    _scanner_path("actionlint", "config_file", outside_tree=False),
    ScannerPath(
        "cfn-guard",
        "rules_paths",
        _scanner_list_option("cfn-guard", "rules_paths"),
        outside_tree=False,
    ),
    _scanner_path("cfn-lint", "config_file", outside_tree=True),
    _scanner_path("gitleaks", "config_file", outside_tree=False),
    _scanner_path("gitleaks", "baseline_path", outside_tree=False),
    _scanner_path("zizmor", "config_file", outside_tree=False),
    _scanner_path("trivy", "config_file", outside_tree=True),
    _scanner_path("trivy", "ignore_file", outside_tree=True),
    _scanner_path("trivy", "secret_config_file", outside_tree=True),
    _scanner_path("trivy-repo", "config_file", outside_tree=True),
    _scanner_path("trivy-repo", "module_dir", outside_tree=True),
    _scanner_path("trivy-repo", "ignore_file", outside_tree=True),
    _scanner_path("trivy-repo", "secret_config_file", outside_tree=True),
]


PATH_OPTIONS: List[PathOption] = [
    _scanner_option("bandit", "config_file"),
    _scanner_option("grype", "config_file"),
    _scanner_option("syft", "config_file"),
    _scanner_option("checkov", "config_file"),
    _scanner_option("ferret-scan", "config_file"),
    _scanner_option("detect-secrets", "baseline_file"),
    _scanner_option("semgrep", "config"),
    _scanner_option("opengrep", "config"),
    *(path.option for path in SCANNER_PATHS),
    PathOption(
        "sandbox.extra_read_paths",
        lambda value: {"sandbox": {"extra_read_paths": [value]}},
        lambda config: (config.sandbox.extra_read_paths or [None])[0],
        lambda value: f"sandbox.extra_read_paths={json.dumps([value])}",
    ),
]


@pytest.mark.parametrize("option", PATH_OPTIONS, ids=lambda o: o.id)
def test_a_relative_path_in_the_operators_config_is_taken_from_its_directory(
    tmp_path: Path, option: PathOption
) -> None:
    repo = _repo(tmp_path)
    decoy = _touch(repo / "tools" / "named.cfg")
    operator = _write(
        tmp_path / "operator" / "ash.yaml", option.document("tools/named.cfg")
    )
    wanted = _touch(operator.parent / "tools" / "named.cfg")

    config = resolve_config(config_path=operator, source_dir=repo)

    value = option.read(config)
    assert _same_file(value, wanted), value
    assert not _same_file(value, decoy)


def test_bandit_reads_the_operators_file_and_not_the_trees_decoy(
    tmp_path: Path,
) -> None:
    """End to end: the file bandit is handed is the one next to the operator's config."""
    repo = _repo(tmp_path)
    _touch(repo / "bandit.yaml")
    operator = _write(
        tmp_path / "operator" / "ash.yaml",
        {"scanners": {"bandit": {"options": {"config_file": "bandit.yaml"}}}},
    )
    wanted = _touch(operator.parent / "bandit.yaml")
    config = resolve_config(config_path=operator, source_dir=repo)
    output = tmp_path / "out"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)

    scanner = BanditScanner(
        config=config.get_plugin_config("scanner", "bandit"),
        context=PluginContext(
            source_dir=repo,
            output_dir=output,
            work_dir=output / ASH_WORK_DIR_NAME,
            config=config,
        ),
    )

    passed = [arg.value for arg in scanner.args.extra_args if arg.key == "--configfile"]
    assert len(passed) == 1
    assert _same_file(passed[0], wanted)


def test_a_relative_path_in_an_extends_base_is_taken_from_the_bases_directory(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    _touch(repo / "bandit.yaml")
    operator_dir = tmp_path / "operator"
    _write(
        operator_dir / "shared" / "base.yaml",
        {"scanners": {"bandit": {"options": {"config_file": "bandit.yaml"}}}},
    )
    wanted = _touch(operator_dir / "shared" / "bandit.yaml")
    _touch(operator_dir / "bandit.yaml")
    operator = _write(operator_dir / "ash.yaml", {"extends": "shared/base.yaml"})

    config = resolve_config(config_path=operator, source_dir=repo)

    assert _same_file(_options(config, "bandit").get("config_file"), wanted)


def test_a_relative_path_in_a_patch_is_taken_from_its_files_directory(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    _touch(repo / "baseline.json")
    operator = _write(
        tmp_path / "operator" / "ash.yaml",
        {
            "scanners": {"detect-secrets": {"options": {}}},
            "patch": [
                {
                    "op": "add",
                    "path": "/scanners/detect-secrets/options/baseline_file",
                    "value": "baseline.json",
                }
            ],
        },
    )
    wanted = _touch(operator.parent / "baseline.json")

    config = resolve_config(config_path=operator, source_dir=repo)

    assert _same_file(_options(config, "detect-secrets").get("baseline_file"), wanted)


def test_a_relative_path_in_the_ash_config_file_is_taken_from_its_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    _touch(repo / "bandit.yaml")
    operator = _write(
        tmp_path / "operator" / "ash.yaml",
        {"scanners": {"bandit": {"options": {"config_file": "bandit.yaml"}}}},
    )
    wanted = _touch(operator.parent / "bandit.yaml")
    monkeypatch.setenv("ASH_CONFIG", str(operator))

    config = resolve_config(source_dir=repo)

    assert _same_file(_options(config, "bandit").get("config_file"), wanted)


def test_a_relative_path_in_an_override_is_taken_from_the_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    _touch(repo / "bandit.yaml")
    workdir = tmp_path / "ci"
    wanted = _touch(workdir / "bandit.yaml")
    monkeypatch.chdir(workdir)

    config = resolve_config(
        source_dir=repo,
        config_overrides=["scanners.bandit.options.config_file=bandit.yaml"],
    )

    assert _same_file(_options(config, "bandit").get("config_file"), wanted)


@pytest.mark.parametrize("option", PATH_OPTIONS, ids=lambda o: o.id)
def test_a_relative_path_option_in_an_override_is_taken_from_the_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, option: PathOption
) -> None:
    repo = _repo(tmp_path)
    decoy = _touch(repo / "tools" / "named.cfg")
    workdir = tmp_path / "ci"
    wanted = _touch(workdir / "tools" / "named.cfg")
    monkeypatch.chdir(workdir)

    config = resolve_config(
        source_dir=repo, config_overrides=[option.override("tools/named.cfg")]
    )

    value = option.read(config)
    assert _same_file(value, wanted), value
    assert not _same_file(value, decoy)


def test_a_relative_list_entry_in_an_override_is_taken_from_the_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(tmp_path)
    workdir = tmp_path / "ci"
    wanted = workdir / "certs"
    wanted.mkdir(parents=True)
    monkeypatch.chdir(workdir)

    config = resolve_config(
        source_dir=repo,
        config_overrides=[f"sandbox.extra_read_paths={json.dumps(['certs'])}"],
    )

    assert [Path(p) for p in config.sandbox.extra_read_paths] == [wanted.resolve()]


def test_a_workspace_projects_decoy_is_not_the_operators_file(tmp_path: Path) -> None:
    """The operator's --config layered over a project names its own directory's file."""
    repo = _repo(tmp_path)
    _touch(repo / "bandit.yaml")
    _write(
        repo / ".ash" / ".ash.yaml",
        {"scanners": {"bandit": {"options": {"config_file": "bandit.yaml"}}}},
    )
    operator = _write(
        tmp_path / "operator" / "ash.yaml",
        {"scanners": {"bandit": {"options": {"config_file": "bandit.yaml"}}}},
    )
    wanted = _touch(operator.parent / "bandit.yaml")

    config = resolve_config(
        config_path=repo / ".ash" / ".ash.yaml",
        source_dir=repo,
        trusted_config_path=operator,
        overlay_config_path=operator,
    )

    assert _same_file(_options(config, "bandit").get("config_file"), wanted)


def test_a_relative_path_in_an_mcp_profile_is_taken_from_the_profiles_directory(
    tmp_path: Path,
) -> None:
    """The server writes a session's copy of a profile elsewhere; the path survives."""
    from automated_security_helper.cli.mcp.profile_registry import register_profiles

    profile = _write(
        tmp_path / "profiles" / "ci.yaml",
        {"scanners": {"bandit": {"options": {"config_file": "bandit.yaml"}}}},
    )
    wanted = _touch(profile.parent / "bandit.yaml")

    registry = register_profiles([f"ci={profile}"])

    assert _same_file(registry["ci"].config.scanners.bandit.options.config_file, wanted)


@pytest.mark.parametrize("entries", ["plugins_used", "filters_used"])
def test_a_relative_detect_secrets_file_entry_is_taken_from_its_files_directory(
    tmp_path: Path, entries: str
) -> None:
    repo = _repo(tmp_path)
    _touch(repo / "plugins" / "custom.py")
    operator = _write(
        tmp_path / "operator" / "ash.yaml",
        {
            "scanners": {
                "detect-secrets": {
                    "options": {
                        "scan_settings": {
                            entries: [{"path": "file://plugins/custom.py::check"}]
                        }
                    }
                }
            }
        },
    )
    wanted = _touch(operator.parent / "plugins" / "custom.py")

    config = resolve_config(config_path=operator, source_dir=repo)

    settings = _options(config, "detect-secrets")["scan_settings"]
    path = settings[entries][0]["path"]
    file_part, _, function = path[len("file://") :].partition("::")
    assert path.startswith("file://")
    assert _same_file(file_part, wanted)
    assert function == "check"


@pytest.mark.parametrize("value", ["p/ci", "auto", "https://example.invalid/rules"])
def test_a_rules_config_that_names_no_file_there_is_left_as_written(
    tmp_path: Path, value: str
) -> None:
    """semgrep's and opengrep's config is a registry entry or a URL unless it is a path."""
    repo = _repo(tmp_path)
    operator = _write(
        tmp_path / "operator" / "ash.yaml",
        {"scanners": {"semgrep": {"options": {"config": value}}}},
    )

    config = resolve_config(config_path=operator, source_dir=repo)

    assert _options(config, "semgrep").get("config") == value


@pytest.mark.parametrize("value", ["~/tools/bandit.yaml", "/etc/ash/bandit.yaml"])
def test_a_home_relative_or_absolute_path_is_left_as_written(
    tmp_path: Path, value: str
) -> None:
    repo = _repo(tmp_path)
    operator = _write(
        tmp_path / "operator" / "ash.yaml",
        {"scanners": {"bandit": {"options": {"config_file": value}}}},
    )

    config = resolve_config(config_path=operator, source_dir=repo)

    assert _options(config, "bandit").get("config_file") == value


# --------------------------------------------------------------------------- #
# What the scanner is given: config_trust.operator_path on the anchored value
# --------------------------------------------------------------------------- #


def _chosen(config: AshConfig, path: ScannerPath, source: Path) -> OperatorPath:
    """What ``config_trust`` hands the scanner for the option, asked as it asks.

    A list (cfn-guard's ``rules_paths``) goes through ``operator_paths`` whole,
    as the scanner passes it, and its first entry is returned.
    """
    value = _options(config, path.scanner).get(path.name)
    if isinstance(value, list):
        return operator_paths(
            config, path.key, value, source, outside_tree=path.outside_tree
        )[0]
    return operator_path(
        config, path.key, value, source, outside_tree=path.outside_tree
    )


@pytest.mark.parametrize("how", ["config file", "override", "workspace"])
@pytest.mark.parametrize("path", SCANNER_PATHS, ids=lambda p: p.option.id)
def test_the_scanner_is_given_the_file_where_the_operator_set_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, path: ScannerPath, how: str
) -> None:
    """Not the same-named file in the scanned tree.

    With ``override`` the tree has a config of its own, and with ``workspace``
    the project's config sets the option too, under the operator's ``--config``.
    Either way ``set_by_operator`` compares the value with the trusted base plus
    the overrides, which are anchored as the value is.
    """
    repo = _repo(tmp_path)
    decoy = _touch(repo / "tools" / "named.cfg")
    if how == "override":
        workdir = tmp_path / "ci"
        wanted = _touch(workdir / "tools" / "named.cfg")
        monkeypatch.chdir(workdir)
        _write(repo / ".ash" / ".ash.yaml", {"project_name": "scanned"})
        config = resolve_config(
            source_dir=repo,
            config_overrides=[path.option.override("tools/named.cfg")],
        )
    else:
        operator = _write(
            tmp_path / "operator" / "ash.yaml", path.option.document("tools/named.cfg")
        )
        wanted = _touch(operator.parent / "tools" / "named.cfg")
        if how == "workspace":
            project = _write(
                repo / ".ash" / ".ash.yaml", path.option.document("tools/named.cfg")
            )
            config = resolve_config(
                config_path=project,
                source_dir=repo,
                trusted_config_path=operator,
                overlay_config_path=operator,
            )
        else:
            config = resolve_config(config_path=operator, source_dir=repo)

    chosen = _chosen(config, path, repo)

    assert chosen.path == wanted.resolve(), chosen
    assert chosen.path != decoy.resolve()


#: The options a config in the tree still sets: ``tool_config_trust`` does not
#: put the trusted base's value in their place, so the scanner judges the
#: tree's value itself.
_SET_BY_THE_TREE = [
    path
    for path in SCANNER_PATHS
    if path.name not in SCANNER_CONFIG_FILE_OPTIONS.get(path.scanner, ())
]


@pytest.mark.parametrize("operator_sets_it", [True, False])
@pytest.mark.parametrize("path", _SET_BY_THE_TREE, ids=lambda p: p.option.id)
def test_a_config_in_the_tree_is_left_as_written_and_is_not_the_operators(
    tmp_path: Path, path: ScannerPath, operator_sets_it: bool
) -> None:
    """The tree's relative value names the tree's file, whatever the operator wrote.

    With ``operator_sets_it`` the operator's file sets the same relative value,
    which is anchored at that file's directory, so the two no longer compare
    equal and the tree's value is not taken for the operator's.
    """
    repo = _repo(tmp_path)
    _touch(repo / "tools" / "named.cfg")
    project = _write(
        repo / ".ash" / ".ash.yaml", path.option.document("tools/named.cfg")
    )
    operator = None
    if operator_sets_it:
        operator = _write(
            tmp_path / "operator" / "ash.yaml", path.option.document("tools/named.cfg")
        )
        _touch(operator.parent / "tools" / "named.cfg")

    config = resolve_config(
        config_path=project, source_dir=repo, trusted_config_path=operator
    )

    assert Path(str(path.option.read(config))) == Path("tools/named.cfg")
    chosen = _chosen(config, path, repo)
    assert chosen.path is None
    assert chosen.refusal == NOT_THE_OPERATORS


def test_a_relative_rules_path_appended_by_an_override_is_taken_from_the_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``key+=entry`` adds one entry to the list, anchored as a whole list is."""
    repo = _repo(tmp_path)
    decoy = _touch(repo / "rules" / "mine.guard")
    workdir = tmp_path / "ci"
    wanted = _touch(workdir / "rules" / "mine.guard")
    monkeypatch.chdir(workdir)

    config = resolve_config(
        source_dir=repo,
        config_overrides=["scanners.cfn-guard.options.rules_paths+=rules/mine.guard"],
    )

    entries = _options(config, "cfn-guard")["rules_paths"]
    assert len(entries) == 1
    assert _same_file(entries[0], wanted), entries
    assert not _same_file(entries[0], decoy)


def test_a_relative_rules_path_a_patch_appends_is_taken_from_its_files_directory(
    tmp_path: Path,
) -> None:
    repo = _repo(tmp_path)
    _touch(repo / "rules" / "mine.guard")
    absolute = _touch(tmp_path / "shared" / "org.guard")
    operator = _write(
        tmp_path / "operator" / "ash.yaml",
        {
            "scanners": {
                "cfn-guard": {"options": {"rules_paths": [absolute.as_posix()]}}
            },
            "patch": [
                {
                    "op": "add",
                    "path": "/scanners/cfn-guard/options/rules_paths/-",
                    "value": "rules/mine.guard",
                }
            ],
        },
    )
    wanted = _touch(operator.parent / "rules" / "mine.guard")

    config = resolve_config(config_path=operator, source_dir=repo)

    entries = _options(config, "cfn-guard")["rules_paths"]
    assert len(entries) == 2
    assert entries[0] == absolute.as_posix()
    assert _same_file(entries[1], wanted), entries
