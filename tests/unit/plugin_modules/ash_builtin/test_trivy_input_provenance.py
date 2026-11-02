# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Who may choose the files trivy and trivy-repo read their inputs from.

``--config``, ``--ignorefile`` and ``--secret-config`` each name a file that can drop
findings, and a trivy.yaml can also load WASM modules. So the option is used only
when the operator set it (``utils/config_trust.set_by_operator``) and the file is
outside the scanned tree, and trivy is handed the path that was checked rather
than one rebuilt from the configured value.

The configs here come from ``resolve_config``, so provenance is recorded the way a
scan records it: a ``.ash/.ash.yaml`` in the tree, a config an MCP client delivered
(``untrusted_config``), a config file outside the tree, and ``--config-overrides``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import List
from unittest.mock import patch

import pytest
import yaml

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
    TrivyScanner,
    TrivyScannerConfig,
    TrivyScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
    TrivyRepoScannerConfig,
    TrivyRepoScannerConfigOptions,
)
from automated_security_helper.utils.content_db_shared import EMPTY_TOOL_CONFIG

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()

SCANNERS = ["trivy", "trivy-repo"]
OPTIONS = [
    ("config_file", "--config", "trivy.yaml", ""),
    ("ignore_file", "--ignorefile", ".trivyignore", ""),
    ("secret_config_file", "--secret-config", "trivy-secret.yaml", "{}\n"),
]


@pytest.fixture(autouse=True)
def _no_operator_env(monkeypatch):
    monkeypatch.delenv("TRIVY_CONFIG", raising=False)
    monkeypatch.delenv("TRIVY_IGNOREFILE", raising=False)
    monkeypatch.delenv("TRIVY_SECRET_CONFIG", raising=False)
    try:
        from automated_security_helper.config.path_trust import (
            reset_path_refusal_warnings,
        )
    except ImportError:  # a revision without config/path_trust.py
        return
    reset_path_refusal_warnings()


def _source(tmp_path: Path) -> Path:
    source = tmp_path / "repo"
    (source / ".git").mkdir(parents=True)
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    return source


def _outside(tmp_path: Path, name: str, content: str) -> Path:
    chosen = tmp_path / "outside" / name
    chosen.parent.mkdir(parents=True, exist_ok=True)
    chosen.write_text(content, encoding="utf-8")
    return chosen


def _write_config(path: Path, scanner: str, option: str, value: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump({"scanners": {scanner: {"options": {option: value}}}}),
        encoding="utf-8",
    )
    return path


def _argv(
    tmp_path: Path, source: Path, config, scanner: str, option: str, value
) -> List[str]:
    output = tmp_path / "out"
    output.mkdir(exist_ok=True)
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=config,
    )
    if scanner == "trivy":
        fs = TrivyScanner(
            context=context,
            config=TrivyScannerConfig(
                enabled=True,
                options=TrivyScannerConfigOptions(offline=False, **{option: value}),
            ),
            config_from_context=True,
        )
        final_args, _, _ = fs._execute_scan(source, "source", [])
        return [str(a) for a in final_args]
    repo = TrivyRepoScanner(
        context=context,
        config=TrivyRepoScannerConfig(
            options=TrivyRepoScannerConfigOptions(**{option: value})
        ),
        config_from_context=True,
    )
    repo.dependencies_satisfied = True
    with (
        patch.object(repo, "_pre_scan", return_value=True),
        patch.object(repo, "_run_subprocess", return_value={"returncode": 0}) as run,
    ):
        repo.scan(target=source, target_type="source")
    return [str(a) for a in run.call_args.kwargs["command"]]


def _passed(argv: List[str], flag: str) -> str:
    values = [a.split("=", 1)[1] for a in argv if a.startswith(f"{flag}=")]
    assert len(values) == 1, argv
    return values[0]


def _inside(path: Path, tree: Path) -> bool:
    return Path(os.path.realpath(path)).is_relative_to(Path(os.path.realpath(tree)))


def _is_ashs_own(passed: str, flag: str, source: Path, content: str) -> bool:
    """ASH's own file for ``flag``: for ``--config`` the empty config ASH ships
    (``EMPTY_TOOL_CONFIG``), and for the other two the file ASH writes for trivy,
    outside the tree and setting nothing.

    Where ASH writes those is ``config/tool_config_trust.empty_tool_config``'s
    choice (tests/unit/config/test_generated_tool_configs_are_outside_the_tree.py).
    """
    if flag == "--config":
        return Path(passed) == EMPTY_TOOL_CONFIG
    path = Path(passed)
    return not _inside(path, source) and path.read_text(encoding="utf-8") == content


def _real(path: Path) -> str:
    return Path(os.path.realpath(path)).as_posix()


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"symlink creation unavailable on this platform: {exc}")


def _set_home(monkeypatch, home: Path) -> None:
    # os.path.expanduser reads HOME on POSIX and USERPROFILE on Windows.
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))


# --------------------------------------------------------------------------- #
# Who set it
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("option, flag, name, content", OPTIONS)
@pytest.mark.parametrize("scanner", SCANNERS)
def test_a_value_from_the_scanned_trees_config_is_not_used(
    tmp_path, scanner, option, flag, name, content
):
    """The file is outside the tree, but the repository chose it."""
    source = _source(tmp_path)
    chosen = _outside(tmp_path, name, content)
    _write_config(source / ".ash" / ".ash.yaml", scanner, option, str(chosen))
    config = resolve_config(source_dir=source)

    passed = _passed(
        _argv(tmp_path, source, config, scanner, option, str(chosen)), flag
    )

    assert passed != _real(chosen)
    assert _is_ashs_own(passed, flag, source, content)


@pytest.mark.parametrize("option, flag, name, content", OPTIONS)
@pytest.mark.parametrize("scanner", SCANNERS)
def test_a_value_from_an_mcp_delivered_config_is_not_used(
    tmp_path, scanner, option, flag, name, content
):
    """A config an MCP client delivered is the client's, wherever it is staged.

    Where the default ``denied_paths`` cover the option, by its own entry or by
    the scanner's whole section (both trivy scanners' are always denied), the
    delivered config is refused outright, naming it, which uses the value no more
    than ignoring it would. Asked of the runtime-override check, which matches
    the entries as the delivered-config check does, globs included.
    """
    from automated_security_helper.config.ash_config import (
        AshConfig,
        RuntimeOverridesConfig,
    )
    from automated_security_helper.config.runtime_patch import (
        RuntimePatchDeniedError,
        check_runtime_ops,
    )
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    source = _source(tmp_path)
    chosen = _outside(tmp_path, name, content)
    delivered = _write_config(
        tmp_path / "upload" / "ash.yaml", scanner, option, str(chosen)
    )
    pointer = f"/scanners/{scanner}/options/{option}"
    try:
        # ``config`` is the config the ops would apply to. With no operator
        # profile named, the delivered config is judged against ASH's defaults
        # (``client_config_policy._trusted_config``), so they are asked here too.
        check_runtime_ops(
            [{"op": "add", "path": pointer, "value": str(chosen)}],
            allowlist=RuntimeOverridesConfig(enabled=True, allowed_paths=["/**"]),
            config=AshConfig(),
        )
        denied = False
    except RuntimePatchDeniedError:
        denied = True
    if denied:
        with pytest.raises(ASHConfigFieldDeniedError) as refused:
            resolve_config(
                config_path=delivered, source_dir=source, untrusted_config=True
            )
        assert f"scanners.{scanner}.options.{option}" in str(refused.value)
        return
    config = resolve_config(
        config_path=delivered, source_dir=source, untrusted_config=True
    )

    passed = _passed(
        _argv(tmp_path, source, config, scanner, option, str(chosen)), flag
    )

    assert passed != _real(chosen)


@pytest.mark.parametrize("how", ["config file outside the tree", "override"])
@pytest.mark.parametrize("option, flag, name, content", OPTIONS)
@pytest.mark.parametrize("scanner", SCANNERS)
def test_an_operator_value_outside_the_tree_is_used(
    tmp_path, scanner, option, flag, name, content, how
):
    source = _source(tmp_path)
    chosen = _outside(tmp_path, name, content)
    if how == "override":
        _write_config(source / ".ash" / ".ash.yaml", scanner, option, "")
        config = resolve_config(
            source_dir=source,
            config_overrides=[f"scanners.{scanner}.options.{option}={chosen}"],
        )
    else:
        operator = _write_config(
            tmp_path / "operator" / "ash.yaml", scanner, option, str(chosen)
        )
        config = resolve_config(config_path=operator, source_dir=source)

    passed = _passed(
        _argv(tmp_path, source, config, scanner, option, str(chosen)), flag
    )

    assert passed == _real(chosen)


@pytest.mark.parametrize(
    ("env", "option", "flag"),
    [
        ("TRIVY_CONFIG", "config_file", "--config"),
        ("TRIVY_IGNOREFILE", "ignore_file", "--ignorefile"),
        ("TRIVY_SECRET_CONFIG", "secret_config_file", "--secret-config"),
    ],
)
@pytest.mark.parametrize("scanner", SCANNERS)
def test_a_relative_path_in_the_environment_is_taken_from_the_working_directory(
    tmp_path, monkeypatch, scanner, env, option, flag
):
    """The variable is the operator's, set where ASH runs, not in the scanned tree.

    The same name at the root of the scanned tree is not the file meant.
    """
    source = _source(tmp_path)
    (source / "operator-file").write_text("{}\n", encoding="utf-8")
    workdir = tmp_path / "ci"
    workdir.mkdir()
    (workdir / "operator-file").write_text("{}\n", encoding="utf-8")
    monkeypatch.chdir(workdir)
    monkeypatch.setenv(env, "operator-file")
    config = resolve_config(source_dir=source)

    passed = _passed(_argv(tmp_path, source, config, scanner, option, None), flag)

    assert passed == _real(workdir / "operator-file")


@pytest.mark.parametrize("set_by", ["unset", "the scanned tree's config"])
@pytest.mark.parametrize("scanner", SCANNERS)
def test_trivy_config_from_the_environment_is_used_for_a_file_outside_the_tree(
    tmp_path, monkeypatch, scanner, set_by
):
    """``config_file`` unset or refused falls back to ``TRIVY_CONFIG``, the operator's
    environment, as ``ignore_file`` falls back to ``TRIVY_IGNOREFILE``."""
    source = _source(tmp_path)
    chosen = _outside(tmp_path, "trivy.yaml", "")
    monkeypatch.setenv("TRIVY_CONFIG", str(chosen))
    value = None
    if set_by != "unset":
        value = str(_outside(tmp_path, "tree-chose.yaml", ""))
        _write_config(source / ".ash" / ".ash.yaml", scanner, "config_file", value)
    config = resolve_config(source_dir=source)

    argv = _argv(tmp_path, source, config, scanner, "config_file", value)

    assert _passed(argv, "--config") == _real(chosen)


@pytest.mark.parametrize("scanner", SCANNERS)
def test_trivy_config_from_the_environment_inside_the_tree_is_not_used(
    tmp_path, monkeypatch, scanner
):
    source = _source(tmp_path)
    planted = source / "trivy.yaml"
    planted.write_text("module:\n  dir: ./planted\n", encoding="utf-8")
    monkeypatch.setenv("TRIVY_CONFIG", str(planted))
    config = resolve_config(source_dir=source)

    argv = _argv(tmp_path, source, config, scanner, "config_file", None)

    assert _passed(argv, "--config") == EMPTY_TOOL_CONFIG.as_posix()
    assert _real(planted) not in " ".join(argv)


@pytest.mark.parametrize("scanner", SCANNERS)
def test_a_relative_trivy_config_beside_the_scanned_tree_is_not_the_one_meant(
    tmp_path, monkeypatch, scanner
):
    """``../trivy.yaml`` names a file next to the working directory, not next to
    the scanned directory, which may be another part of the same checkout."""
    source = _source(tmp_path)
    beside_the_tree = tmp_path / "trivy.yaml"
    beside_the_tree.write_text("module:\n  dir: ./planted\n", encoding="utf-8")
    workdir = tmp_path / "ci" / "job"
    workdir.mkdir(parents=True)
    (workdir.parent / "trivy.yaml").write_text("{}\n", encoding="utf-8")
    monkeypatch.chdir(workdir)
    monkeypatch.setenv("TRIVY_CONFIG", "../trivy.yaml")
    config = resolve_config(source_dir=source)

    argv = _argv(tmp_path, source, config, scanner, "config_file", None)

    assert _passed(argv, "--config") == _real(workdir.parent / "trivy.yaml")
    assert _real(beside_the_tree) not in " ".join(argv)


# --------------------------------------------------------------------------- #
# The path checked is the path used
# --------------------------------------------------------------------------- #


def _spelled(tmp_path: Path, source: Path, chosen: Path, spelling: str) -> str:
    if spelling == "relative":
        return os.path.relpath(chosen, source)
    if spelling == "dotdot":
        (chosen.parent / "sub").mkdir(exist_ok=True)
        return f"{chosen.parent}/sub/../{chosen.name}"
    if spelling == "symlink":
        link = tmp_path / "links" / chosen.name
        link.parent.mkdir(exist_ok=True)
        _symlink_or_skip(link, chosen)
        return str(link)
    if spelling == "relative-dotdot-through-link":
        # source/jump -> <outside>/deep, so "jump/../<name>" is <outside>/<name> to
        # the filesystem but <source>/<name> to a lexical normalization.
        deep = chosen.parent / "deep"
        deep.mkdir(exist_ok=True)
        _symlink_or_skip(source / "jump", deep)
        return f"jump/../{chosen.name}"
    raise AssertionError(spelling)


@pytest.mark.parametrize(
    "spelling",
    ["relative", "dotdot", "symlink", "home", "relative-dotdot-through-link"],
)
@pytest.mark.parametrize("option, flag, name, content", OPTIONS)
@pytest.mark.parametrize("scanner", SCANNERS)
def test_trivy_is_handed_the_path_that_was_checked(
    tmp_path, monkeypatch, scanner, option, flag, name, content, spelling
):
    """However the operator spells an outside file, trivy gets that file, and
    never a file the spelling could be mistaken for.

    ``home`` is the case where the spellings part: the check expands ``~`` and a
    path rebuilt from the raw value does not, so ``~/trivy.yaml`` was checked as
    the operator's home and used as ``<source>/~/trivy.yaml``, a file the
    repository planted. ``relative-dotdot-through-link`` reaches the outside file
    only through ``jump``, a link in the tree, so the tree chose it and ASH's own
    file is passed instead.
    """
    source = _source(tmp_path)
    chosen = _outside(tmp_path, name, content)
    planted = source / "~" / name
    planted.parent.mkdir()
    planted.write_text("module:\n  dir: ./planted\n", encoding="utf-8")
    # What a lexical normalization of "jump/../<name>" would name.
    lexical = source / name
    lexical.write_text("module:\n  dir: ./planted\n", encoding="utf-8")
    if spelling == "home":
        _set_home(monkeypatch, chosen.parent)
        value = f"~/{name}"
    else:
        value = _spelled(tmp_path, source, chosen, spelling)
    operator = _write_config(tmp_path / "operator" / "ash.yaml", scanner, option, value)
    config = resolve_config(config_path=operator, source_dir=source)

    argv = _argv(tmp_path, source, config, scanner, option, value)

    passed = _passed(argv, flag)
    assert _real(planted) not in " ".join(argv)
    assert passed != _real(lexical)
    # Where the filesystem itself takes the spelling. On POSIX "jump/../<name>"
    # goes through the tree's link to <outside>/<name>, which the link chose;
    # Windows collapses ".." before following links, so there it is
    # <source>/<name>, inside the tree. Either way ASH's own file is passed.
    target = Path(
        os.path.realpath(source / value if spelling.startswith("relative") else chosen)
    )
    if spelling == "relative-dotdot-through-link" or _inside(target, source):
        assert _is_ashs_own(passed, flag, source, content)
    else:
        assert passed == _real(target) == _real(chosen)


@pytest.mark.parametrize("option, flag, name, content", OPTIONS)
@pytest.mark.parametrize("scanner", SCANNERS)
def test_windows_dotdot_semantics_refuse_the_in_tree_target(
    tmp_path, monkeypatch, scanner, option, flag, name, content
):
    """Windows collapses ".." before it follows a link (measured in CI on
    windows-latest), so "jump/../<name>" is <source>/<name> there. Emulated here
    by normalizing before resolving: the in-tree file is refused, not passed."""
    source = _source(tmp_path)
    chosen = _outside(tmp_path, name, content)
    lexical = source / name
    lexical.write_text("module:\n  dir: ./planted\n", encoding="utf-8")
    value = _spelled(tmp_path, source, chosen, "relative-dotdot-through-link")
    real = os.path.realpath
    monkeypatch.setattr(
        os.path, "realpath", lambda p, *a, **k: real(os.path.normpath(p), *a, **k)
    )
    operator = _write_config(tmp_path / "operator" / "ash.yaml", scanner, option, value)
    config = resolve_config(config_path=operator, source_dir=source)

    passed = _passed(_argv(tmp_path, source, config, scanner, option, value), flag)

    assert passed != _real(lexical)
    assert _is_ashs_own(passed, flag, source, content)


@pytest.mark.parametrize("option, flag, name, content", OPTIONS)
@pytest.mark.parametrize("scanner", SCANNERS)
def test_an_outside_symlink_into_the_tree_is_not_used(
    tmp_path, scanner, option, flag, name, content
):
    """The link is outside the tree; the file it names is not."""
    source = _source(tmp_path)
    planted = source / name
    planted.write_text(content, encoding="utf-8")
    link = tmp_path / "links" / name
    link.parent.mkdir()
    _symlink_or_skip(link, planted)
    operator = _write_config(
        tmp_path / "operator" / "ash.yaml", scanner, option, str(link)
    )
    config = resolve_config(config_path=operator, source_dir=source)

    argv = _argv(tmp_path, source, config, scanner, option, str(link))

    passed = _passed(argv, flag)
    assert passed not in (_real(planted), link.as_posix())
    assert _is_ashs_own(passed, flag, source, content)


@pytest.mark.parametrize("spelling", ["relative", "dotdot", "symlink", "home", "tree"])
def test_trivy_repo_is_handed_the_modules_directory_that_was_checked(
    tmp_path, monkeypatch, spelling
):
    """``module_dir`` names WASM modules trivy loads; the same rule, for a directory."""
    source = _source(tmp_path)
    chosen = tmp_path / "outside" / "modules"
    chosen.mkdir(parents=True)
    planted = source / "~" / "modules"
    planted.mkdir(parents=True)
    if spelling == "home":
        _set_home(monkeypatch, chosen.parent)
        value = "~/modules"
    elif spelling == "tree":
        value = "~/modules"
        _write_config(source / ".ash" / ".ash.yaml", "trivy-repo", "module_dir", value)
        _set_home(monkeypatch, chosen.parent)
    else:
        value = _spelled(tmp_path, source, chosen, spelling)
    if spelling == "tree":
        config = resolve_config(source_dir=source)
    else:
        operator = _write_config(
            tmp_path / "operator" / "ash.yaml", "trivy-repo", "module_dir", value
        )
        config = resolve_config(config_path=operator, source_dir=source)

    argv = _argv(tmp_path, source, config, "trivy-repo", "module_dir", value)

    passed = _passed(argv, "--module-dir")
    if spelling == "tree":
        assert passed != _real(chosen)
    else:
        assert passed == _real(chosen)
    assert _real(planted) not in " ".join(argv)


def test_builtin_trivy_is_handed_an_empty_modules_directory(tmp_path, monkeypatch):
    """trivy loads the WASM modules in ``--module-dir``, by default
    ``~/.trivy/modules``, so builtin trivy, which has no ``module_dir`` option, is
    handed an empty directory outside the scanned tree, as trivy-repo is when its
    option is unset."""
    source = _source(tmp_path)
    home = tmp_path / "home"
    (home / ".trivy" / "modules").mkdir(parents=True)
    (home / ".trivy" / "modules" / "planted.wasm").write_bytes(b"\0asm")
    _set_home(monkeypatch, home)
    config = resolve_config(source_dir=source)

    argv = _argv(tmp_path, source, config, "trivy", "config_file", None)

    passed = Path(_passed(argv, "--module-dir"))
    assert passed.is_dir(), argv
    assert list(passed.iterdir()) == []
    assert not _inside(passed, source)
    assert not _inside(passed, home)
