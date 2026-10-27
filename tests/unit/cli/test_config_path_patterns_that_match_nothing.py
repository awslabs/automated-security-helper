# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash config validate`` and ``ash config lint`` name a path pattern that
matches nothing, and say what to write instead.

ASH matches an ignore or suppression path against paths relative to the scan
root, which never start with ``./``, and case-sensitively. So:

- a pattern that starts with ``./`` matches no path; the advice is the pattern
  without it (``Use 'src/'``), spelled as the directory advice spells a directory;
- a bare ``.``, ``./``, ``.\\`` or an empty pattern matches no path; the advice is
  to name the paths to ignore;
- a pattern whose leading names match a path in the tree only by case
  (``tests/**`` against ``Tests/``) is named with the tree's spelling.

Each is a warning: validate still exits 0 (a scan accepts the config) and lint
keeps its exit code, which a warning leaves at 0. Lint reports each piece of
advice once, at the path's place in the file. A pattern read from the
environment is named as ``<value>`` and the advice does not quote it.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

import pytest
from typer.testing import CliRunner

VALIDATED = "Configuration is valid! A scan accepts it."

PREFIX = "starts with './' and matches no path"
BARE = "matches no path. Name the paths"
CASE = "only by case; patterns match case-sensitively"


def _tree(tmp_path: Path, config: str, files: Dict[str, str]) -> Path:
    tree = tmp_path / "source"
    tree.mkdir()
    for name, text in files.items():
        (tree / name).parent.mkdir(parents=True, exist_ok=True)
        (tree / name).write_text(text, encoding="utf-8")
    (tree / "ash.yaml").write_text(config, encoding="utf-8")
    return tree


def _run(
    command: str, tree: Path, monkeypatch: pytest.MonkeyPatch
) -> "tuple[int, str]":
    from automated_security_helper.cli.config import config_app

    monkeypatch.chdir(tree)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    args = ["--config", "ash.yaml"]
    if command == "lint":
        args.append("--no-color")
    result = CliRunner().invoke(config_app, [command, *args])
    return result.exit_code, result.output


def _ignore(path: str) -> str:
    return (
        "project_name: demo\nglobal_settings:\n  ignore_paths:\n"
        f"    - path: {path}\n      reason: probe\n"
    )


def _suppression(path: str) -> str:
    return (
        "project_name: demo\nglobal_settings:\n  suppressions:\n"
        f"    - rule_id: R1\n      path: {path}\n      reason: probe\n"
    )


FILES = {"src/app.py": "x = 1\n", "app.py": "y = 2\n", "Tests/test_a.py": "z = 3\n"}


def _flat(text: str) -> str:
    """The output with its line wrapping removed."""
    return " ".join(text.split())


CASES = [
    pytest.param(
        _ignore("./src"),
        [
            f"Path './src' {PREFIX}. Use 'src/' to ignore every file inside the directory."
        ],
        id="dot-slash-directory",
    ),
    pytest.param(
        _ignore("./app.py"),
        [f"Path './app.py' {PREFIX}. Use 'app.py' to ignore it."],
        id="dot-slash-file",
    ),
    pytest.param(
        _suppression("./src/app.py"),
        [f"Path './src/app.py' {PREFIX}. Use 'src/app.py' to suppress its findings."],
        id="dot-slash-suppression",
    ),
    pytest.param(
        _ignore("./"),
        [f"Path './' {BARE} to ignore instead"],
        id="bare-dot-slash",
    ),
    pytest.param(_ignore("."), [f"Path '.' {BARE} to ignore instead"], id="bare-dot"),
    pytest.param(
        _ignore("'.\\'"),
        [f"Path '.\\' {BARE} to ignore instead"],
        id="bare-dot-backslash",
    ),
    pytest.param(_ignore("''"), [f"Path '' {BARE} to ignore instead"], id="empty"),
    pytest.param(
        _suppression("."),
        [f"Path '.' {BARE} whose findings to suppress instead"],
        id="bare-dot-suppression",
    ),
    pytest.param(
        _ignore("tests/**"),
        [f"Path 'tests/**' matches 'Tests/' {CASE}."],
        id="case-only",
    ),
    pytest.param(
        _suppression("tests/test_a.py"),
        [f"Path 'tests/test_a.py' matches 'Tests/test_a.py' {CASE}."],
        id="case-only-suppression",
    ),
]

CONTROLS = [
    pytest.param(_ignore("src/**"), id="control-a-glob"),
    pytest.param(_ignore("Tests/**"), id="control-case-matches"),
    pytest.param(_ignore("src/"), id="control-a-directory-with-its-slash"),
    pytest.param(_suppression("src/app.py"), id="control-a-file"),
]


@pytest.mark.parametrize("command", ["validate", "lint"])
@pytest.mark.parametrize(("config", "shown"), CASES)
def test_a_pattern_that_matches_nothing_is_named_with_advice(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    config: str,
    shown: List[str],
) -> None:
    tree = _tree(tmp_path, config, FILES)
    code, output = _run(command, tree, monkeypatch)

    # A warning: a scan accepts the config.
    assert code == 0, output
    for text in shown:
        assert text in _flat(output), (text, output)
    if command == "validate":
        assert VALIDATED in output, output
    else:
        # Once, as a warning at the path's place in the file.
        for text in shown:
            assert _flat(output).count(text) == 1, (text, output)
        assert "❌" not in output, output
        assert "Warnings: 1" in output, output
        assert "at 'global_settings." in _flat(output), output
    # One piece of advice, not the directory advice as well.
    assert "points to a directory" not in output, output


def test_lint_reports_the_directory_advice_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tree = _tree(tmp_path, _ignore("src"), FILES)
    code, output = _run("lint", tree, monkeypatch)

    shown = (
        "Path 'src' points to a directory but matches no file in it. "
        "Use 'src/' to ignore every file inside the directory. "
        "at 'global_settings.ignore_paths[0].path'"
    )
    assert code == 0, output
    assert _flat(output).count("Path 'src' points to a directory") == 1, output
    assert shown in _flat(output), output
    assert "❌" not in output, output


@pytest.mark.parametrize(
    ("base_path", "shown"),
    [
        pytest.param(
            "./src",
            f"Path './src' {PREFIX}. Use 'src/' to ignore every file inside the directory.",
            id="dot-slash",
        ),
        pytest.param(
            "src",
            "Path 'src' points to a directory but matches no file in it.",
            id="directory",
        ),
    ],
)
def test_lint_warns_of_a_pattern_the_extends_chain_adds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, base_path: str, shown: str
) -> None:
    # The file names no path; its base does. Lint reports validate's advice for
    # it once, as a warning, and exits 0.
    tree = _tree(tmp_path, "extends: base.yaml\nproject_name: demo\n", FILES)
    (tree / "base.yaml").write_text(_ignore(base_path), encoding="utf-8")
    code, output = _run("lint", tree, monkeypatch)

    assert code == 0, output
    assert _flat(output).count(shown) == 1, output
    assert "❌" not in output, output
    assert "Warnings: 1" in output, output


@pytest.mark.parametrize("command", ["validate", "lint"])
@pytest.mark.parametrize("config", CONTROLS)
def test_control_a_pattern_that_matches_is_not_named(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command: str, config: str
) -> None:
    tree = _tree(tmp_path, config, FILES)
    code, output = _run(command, tree, monkeypatch)

    assert code == 0, output
    for text in (PREFIX, BARE, CASE, "points to a directory"):
        assert text not in _flat(output), (text, output)


@pytest.mark.parametrize("command", ["validate", "lint"])
@pytest.mark.parametrize(
    ("value", "shown"),
    [
        pytest.param(
            "./src", f"Path '<value>' {PREFIX}. Remove the leading './'.", id="prefix"
        ),
        pytest.param(".", f"Path '<value>' {BARE} to ignore instead", id="bare"),
        pytest.param(
            "tests/**",
            f"Path '<value>' matches a path in the scanned tree {CASE}.",
            id="case",
        ),
    ],
)
def test_a_pattern_read_from_the_environment_is_not_quoted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    value: str,
    shown: str,
) -> None:
    monkeypatch.setenv("ASH_PROBE_PATTERN", value)
    tree = _tree(tmp_path, _ignore("!ENV ${ASH_PROBE_PATTERN}"), FILES)
    code, output = _run(command, tree, monkeypatch)

    assert code == 0, output
    assert shown in _flat(output), output
    # Neither the pattern nor the tree's spelling of it.
    for text in ("./src", "'src", "tests/**", "Tests/"):
        assert text not in output, (text, output)
