# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""scripts/e2e/prev_tree.py: the N-1 source tree an e2e upgrade leg builds from.

The Chocolatey upgrade leg only tests an upgrade if N-1 differs from N in both code and
version. These tests build small git repositories and hold the helper to that: the
version goes down, a tree equal to HEAD falls back to HEAD's parent, and every case
where no real upgrade exists is refused rather than quietly producing a no-op.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "e2e" / "prev_tree.py"


def _load():
    spec = importlib.util.spec_from_file_location("ash_e2e_prev_tree", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


pt = _load()


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def _commit(repo: Path, files: dict, message: str) -> str:
    for name, content in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
    _git(repo, "add", "-A")
    _git(
        repo,
        "-c",
        "user.name=e2e",
        "-c",
        "user.email=e2e@example.invalid",
        "commit",
        "-q",
        "-m",
        message,
    )
    return _git(repo, "rev-parse", "HEAD")


def _pyproject(version: str, eol: str = "\n") -> str:
    lines = [
        "[project]",
        'name = "automated-security-helper"',
        f'version = "{version}"',
        "",
        "[tool.commitizen]",
        f'version = "{version}"',
        "",
    ]
    return eol.join(lines)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "core.autocrlf", "false")
    return root


@pytest.mark.parametrize(
    "version, lowered",
    [
        ("3.7.0", "3.6.0"),
        ("3.7.1", "3.7.0"),
        ("3.10.0", "3.9.0"),
        ("3.0.0", "2.0.0"),
        ("4.0.0.2", "4.0.0.1"),
        ("1", "0"),
    ],
)
def test_lower_version_decrements_the_last_nonzero_component(version, lowered):
    assert pt.lower_version(version) == lowered
    assert pt.sorts_below(lowered, version)


@pytest.mark.parametrize("version", ["0.0.0", "3.7.0rc1", "3.7.0+local", "1!3.7.0", ""])
def test_lower_version_refuses_what_it_cannot_order(version):
    with pytest.raises(pt.DerivationError):
        pt.lower_version(version)


def test_sorts_below_compares_integers_not_strings():
    assert pt.sorts_below("3.9.0", "3.10.0")
    assert not pt.sorts_below("3.10.0", "3.9.0")
    assert not pt.sorts_below("3.7.0", "3.7.0")
    assert not pt.sorts_below("3.7", "3.7.0")


def test_derives_from_the_named_ref_and_lowers_only_the_project_version(repo, tmp_path):
    prev = _commit(
        repo, {"pyproject.toml": _pyproject("3.7.0"), "a.py": "old\n"}, "prev"
    )
    _git(repo, "branch", "base")
    _commit(repo, {"a.py": "new\n"}, "head")

    result = pt.derive(repo, "base", tmp_path / "out")

    assert result["prev_ref"] == "base"
    assert result["prev_sha"] == prev
    assert result["head_version"] == "3.7.0"
    assert result["prev_base_version"] == "3.7.0"
    assert result["prev_version"] == "3.6.0"
    src = Path(result["src"])
    assert (src / "a.py").read_text(encoding="utf-8") == "old\n"
    text = (src / "pyproject.toml").read_text(encoding="utf-8")
    # [project]'s line moved; commitizen's did not.
    assert text.count('version = "3.6.0"') == 1
    assert text.count('version = "3.7.0"') == 1
    assert text.index('version = "3.6.0"') < text.index("[tool.commitizen]")
    # The checkout is untouched.
    assert 'version = "3.7.0"' in (repo / "pyproject.toml").read_text(encoding="utf-8")
    assert not (tmp_path / "out" / "prev.zip").exists()


def test_a_ref_with_heads_tree_falls_back_to_heads_parent(repo, tmp_path):
    parent = _commit(
        repo, {"pyproject.toml": _pyproject("3.7.0"), "a.py": "old\n"}, "one"
    )
    _commit(repo, {"a.py": "new\n"}, "two")
    _git(repo, "branch", "base")  # base == HEAD, as on a push to the base branch

    result = pt.derive(repo, "base", tmp_path / "out")

    assert result["prev_ref"] == "HEAD^"
    assert result["prev_sha"] == parent
    assert (Path(result["src"]) / "a.py").read_text(encoding="utf-8") == "old\n"


def test_no_parent_to_fall_back_to_is_refused(repo, tmp_path):
    _commit(repo, {"pyproject.toml": _pyproject("3.7.0")}, "only")
    _git(repo, "branch", "base")
    with pytest.raises(pt.DerivationError, match="no parent"):
        pt.derive(repo, "base", tmp_path / "out")


def test_a_parent_with_heads_tree_too_is_refused(repo, tmp_path):
    _commit(repo, {"pyproject.toml": _pyproject("3.7.0")}, "one")
    _git(
        repo,
        "-c",
        "user.name=e2e",
        "-c",
        "user.email=e2e@example.invalid",
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "empty",
    )
    _git(repo, "branch", "base")
    with pytest.raises(pt.DerivationError, match="no code change"):
        pt.derive(repo, "base", tmp_path / "out")


def test_an_unknown_ref_is_refused(repo, tmp_path):
    _commit(repo, {"pyproject.toml": _pyproject("3.7.0")}, "one")
    with pytest.raises(pt.DerivationError, match="does not name a commit"):
        pt.derive(repo, "no-such-ref", tmp_path / "out")


def test_an_n_minus_1_that_does_not_sort_below_head_is_refused(repo, tmp_path):
    # The base is a newer release line than HEAD: lowering 4.0.0 gives 3.0.0, which is
    # not below HEAD's 2.0.0, so the "upgrade" would be a downgrade.
    _commit(repo, {"pyproject.toml": _pyproject("4.0.0")}, "newer")
    _git(repo, "branch", "base")
    _commit(repo, {"pyproject.toml": _pyproject("2.0.0")}, "head")
    with pytest.raises(pt.DerivationError, match="does not sort below"):
        pt.derive(repo, "base", tmp_path / "out")


def test_crlf_line_endings_survive_the_version_edit(repo, tmp_path):
    _commit(repo, {"pyproject.toml": _pyproject("3.7.0", eol="\r\n")}, "one")
    _git(repo, "branch", "base")
    _commit(repo, {"b.py": "x\n"}, "two")

    result = pt.derive(repo, "base", tmp_path / "out")

    raw = (Path(result["src"]) / "pyproject.toml").read_bytes()
    assert b'version = "3.6.0"\r\n' in raw
    assert b'version = "3.7.0"\r\n' in raw
    assert b"\n" not in raw.replace(b"\r\n", b"")


def test_main_prints_json_on_stdout_and_exits_1_on_refusal(repo, tmp_path, capsys):
    _commit(repo, {"pyproject.toml": _pyproject("3.7.0")}, "one")
    _git(repo, "branch", "base")
    _commit(repo, {"b.py": "x\n"}, "two")

    assert (
        pt.main(
            ["--repo", str(repo), "--prev-ref", "base", "--out", str(tmp_path / "o")]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["prev_version"] == "3.6.0"

    assert (
        pt.main(
            ["--repo", str(repo), "--prev-ref", "nope", "--out", str(tmp_path / "p")]
        )
        == 1
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "FAIL:" in captured.err
