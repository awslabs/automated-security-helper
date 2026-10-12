# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash merge`` takes its config from the operator alone, and refuses one it cannot use.

An unusable ``--config``. Missing, unreadable, a directory, a dangling link, not
YAML, or YAML that does not validate: each refuses the merge with exit code 3,
before anything is written, and the file is read at most once. The refusal
quotes the path the operator gave, with its control characters escaped, so a
name holding a newline or a terminal escape cannot start a line of its own or
restyle the output.

An unset environment reference. A YAML, TOML or pyproject config whose
``${VAR}`` names an unset variable with no default is handled by ``ash merge
--config`` as ``ash scan --config`` handles it; each case runs both and compares.

Every merge runs in a child process, so the only plugin modules registered are the
ones that merge imports. The child has no AWS credentials, a refusing proxy and
its own HOME.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

import pytest

from tests.unit.cli.test_merge import build_shards, write_shards
from tests.utils.isolated_tool_env import (
    install_refusing_installers,
    isolated_tool_env,
    without_inherited_aws,
)

REPO_ROOT = Path(__file__).resolve().parents[3]
INVALID_CONFIG_EXIT = 3
RESULTS_FILE_NAME = "ash_aggregated_results.json"
#: Inside the plugin namespace, installed outside every tree the merge looks at;
#: importing it writes a file, so the test sees whether the merge imported it.
MARKER_PACKAGE = "zzmergemarker_ash_plugins"
_MARKER_ENV = "ASH_TEST_MERGE_MARKER_FILE"
#: Never set while these tests run.
UNSET_VARIABLE = "ASH_TEST_UNSET_VARIABLE"
#: A directory name holding an escape sequence and a newline.
CONTROL_NAME = "op\x1b[31mred\nnext"

_CHILD = r"""
import json
import os
import sys

spec = json.loads(sys.argv[1])
opens = []
watched = spec.get("watch")
if watched:
    watched = os.path.realpath(watched)

    def _audit(event, args):
        if event == "open" and args and isinstance(args[0], str):
            if os.path.realpath(args[0]) == watched:
                opens.append(1)

    sys.addaudithook(_audit)

code = None
try:
    if spec["command"] == "merge":
        from automated_security_helper.cli.main import app

        app(["merge"] + spec["args"], prog_name="ash")
    else:
        from automated_security_helper.cli.entrypoint import main

        sys.argv = ["ash"] + spec["args"]
        main()
except SystemExit as exit_:
    code = exit_.code
sys.stdout.flush()
print("\nMERGE-CHILD " + json.dumps({"exit_code": code or 0, "opens": len(opens)}))
"""


class _Child:
    """One merge or scan in a fresh interpreter, with the marker package installed."""

    def __init__(self, tmp_path: Path):
        self.root = tmp_path
        self.site = tmp_path / "site"
        (self.site / MARKER_PACKAGE).mkdir(parents=True)
        (self.site / MARKER_PACKAGE / "__init__.py").write_text(
            "import os, pathlib\n"
            f"pathlib.Path(os.environ[{_MARKER_ENV!r}]).write_text('imported')\n",
            encoding="utf-8",
        )
        self.marker = tmp_path / "marker"
        self.home = tmp_path / "home"
        self.home.mkdir()
        self.stubs = tmp_path / "stubs"
        install_refusing_installers(self.stubs)
        # The merge's working directory, which it treats as the scanned tree.
        self.workdir = tmp_path / "cwd"
        self.workdir.mkdir()
        self.operator = tmp_path / "operator"
        self.operator.mkdir()
        self.output_dir = tmp_path / "merged"

    def shards(self, modules: Optional[List[str]] = None) -> List[str]:
        shards = build_shards(3)
        for shard in shards:
            shard.ash_config.ash_plugin_modules = list(modules or [])
        return write_shards(self.root / "artifacts", shards)

    def env(self) -> Dict[str, str]:
        env = without_inherited_aws(
            {
                key: value
                for key, value in os.environ.items()
                if not key.startswith("ASH_")
            }
        )
        env.update(isolated_tool_env(self.root / "tool-env"))
        env.update(
            {
                "PYTHONPATH": os.pathsep.join([str(self.site), str(REPO_ROOT)]),
                "HOME": str(self.home),
                "USERPROFILE": str(self.home),
                "PATH": os.pathsep.join(
                    [str(self.stubs), str(Path(sys.executable).parent)]
                    + ([] if sys.platform == "win32" else ["/usr/bin", "/bin"])
                    + ([env["PATH"]] if sys.platform == "win32" else [])
                ),
                _MARKER_ENV: str(self.marker),
                "PYTHONIOENCODING": "utf-8",
            }
        )
        return env

    def run(self, command: str, args: List[str], watch: Optional[Path] = None):
        spec = {
            "command": command,
            "args": args,
            "watch": str(watch) if watch else None,
        }
        completed = subprocess.run(
            [sys.executable, "-c", _CHILD, json.dumps(spec)],
            cwd=self.workdir,
            env=self.env(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="backslashreplace",
            timeout=600,
        )
        lines = completed.stdout.rsplit("\nMERGE-CHILD ", 1)
        assert len(lines) == 2, (completed.stdout[-3000:], completed.stderr[-3000:])
        report = json.loads(lines[1].strip())
        report["output"] = lines[0] + completed.stderr
        return report

    def merge(self, shard_paths: List[str], *args: str, watch: Optional[Path] = None):
        argv = ["--output-dir", str(self.output_dir)]
        for path in shard_paths:
            argv += ["--results", path]
        return self.run("merge", argv + list(args), watch=watch)

    def merged(self) -> bool:
        return (self.output_dir / RESULTS_FILE_NAME).exists()

    def imported(self) -> bool:
        return self.marker.exists()


def _flat(text: str) -> str:
    """``text`` without the line breaks and padding the console wraps it with."""
    return "".join(text.split())


# --------------------------------------------------------------------- unusable config


def _missing(directory: Path) -> Path:
    return directory / "absent.yaml"


def _unreadable(directory: Path) -> Path:
    path = directory / "unreadable.yaml"
    path.write_text("project_name: operator\n", encoding="utf-8")
    path.chmod(0)
    return path


def _a_directory(directory: Path) -> Path:
    path = directory / "a-directory.yaml"
    path.mkdir()
    return path


def _dangling(directory: Path) -> Path:
    path = directory / "dangling.yaml"
    path.symlink_to(directory / "nothing-here.yaml")
    return path


def _not_yaml(directory: Path) -> Path:
    path = directory / "not-yaml.yaml"
    path.write_text("project_name: [unclosed\n", encoding="utf-8")
    return path


def _invalid(directory: Path) -> Path:
    path = directory / "invalid.yaml"
    path.write_text("project_name: operator\nglobal_settings: 5\n", encoding="utf-8")
    return path


UNUSABLE = {
    "missing": _missing,
    "unreadable": _unreadable,
    "directory": _a_directory,
    "dangling-link": _dangling,
    "not-yaml": _not_yaml,
    "invalid": _invalid,
}


def _needs(case: str) -> None:
    if case == "dangling-link" and sys.platform == "win32":
        pytest.skip("creating symlinks needs privileges on Windows")


def _still_readable(path: Path) -> bool:
    """Whether permission bits stop this process reading ``path``: not as root."""
    try:
        with open(path, "rb"):
            return True
    except OSError:
        return False


def _assert_refused(child: _Child, result: dict, before: List[str]) -> None:
    assert result["exit_code"] == INVALID_CONFIG_EXIT, result["output"]
    assert "Invalid configuration" in result["output"], result["output"]
    assert not child.output_dir.exists(), result["output"]
    assert sorted(p.name for p in child.workdir.iterdir()) == before
    assert "Traceback" not in result["output"], result["output"]


@pytest.mark.parametrize("case", sorted(UNUSABLE))
def test_an_unusable_operator_config_refuses_the_merge(case, tmp_path):
    """Exit 3, nothing written, the file read at most once."""
    _needs(case)
    child = _Child(tmp_path)
    shard_paths = child.shards()
    config = UNUSABLE[case](child.operator)
    before = sorted(p.name for p in child.workdir.iterdir())

    result = child.merge(shard_paths, "--config", str(config), watch=config)

    assert result["opens"] <= 1, result
    if case == "unreadable" and _still_readable(config):
        # Root, or Windows, where the bits do not stop a read: a usable file.
        assert result["exit_code"] != INVALID_CONFIG_EXIT, result["output"]
        assert child.merged(), result["output"]
        return
    _assert_refused(child, result, before)


@pytest.mark.skipif(
    sys.platform == "win32", reason="a Windows file name cannot hold control characters"
)
@pytest.mark.parametrize("case", sorted(UNUSABLE))
def test_the_refusal_escapes_control_characters_in_the_path(case, tmp_path):
    """The path the operator gave is quoted with its controls escaped."""
    _needs(case)
    child = _Child(tmp_path)
    shard_paths = child.shards()
    directory = child.operator / CONTROL_NAME
    directory.mkdir()
    config = UNUSABLE[case](directory)
    before = sorted(p.name for p in child.workdir.iterdir())

    result = child.merge(shard_paths, "--config", str(config), watch=config)

    if case == "unreadable" and _still_readable(config):
        # Root, where the bits do not stop a read: a usable file, so no refusal.
        assert result["exit_code"] != INVALID_CONFIG_EXIT, result["output"]
        assert child.merged(), result["output"]
        return
    _assert_refused(child, result, before)
    output = result["output"]
    assert "\x1b" not in output, repr(output[-2000:])
    assert "\nnext" not in output, repr(output[-2000:])
    assert _flat("op\\x1b[31mred\\nnext") in _flat(output), repr(output[-2000:])


def test_control_a_usable_operator_config_merges(tmp_path):
    """The same location with a valid file, so a refusal above is about the file."""
    child = _Child(tmp_path)
    config = child.operator / "valid.yaml"
    config.write_text("project_name: operator\n", encoding="utf-8")

    result = child.merge(child.shards(), "--config", str(config), watch=config)

    assert result["exit_code"] != INVALID_CONFIG_EXIT, result["output"]
    assert child.merged(), result["output"]
    assert result["opens"] == 1, result


# ------------------------------------------------------------ unset env references

ENV_UNSET = {
    "yaml": (
        "operator-config.yaml",
        "project_name: !ENV ${" + UNSET_VARIABLE + "}\n",
    ),
    "toml": ("operator-config.toml", 'project_name = "${' + UNSET_VARIABLE + '}"\n'),
    "pyproject": (
        "pyproject.toml",
        '[tool.ash]\nproject_name = "${' + UNSET_VARIABLE + '}"\n',
    ),
}


@pytest.mark.parametrize("kind", sorted(ENV_UNSET))
def test_an_unset_env_reference_is_handled_as_ash_scan_handles_it(kind, tmp_path):
    """Whatever ``ash scan --config`` does with the file, ``ash merge --config`` does."""
    name, content = ENV_UNSET[kind]
    child = _Child(tmp_path)
    config = child.operator / name
    config.write_text(content, encoding="utf-8")
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "app.py").write_text("x = 1\n", encoding="utf-8")
    shard_paths = child.shards()

    scan = child.run(
        "scan",
        [
            "--source-dir",
            str(tree),
            "--output-dir",
            str(tmp_path / "scanned"),
            "--mode",
            "local",
            "--scanners",
            "detect-secrets",
            "--phases",
            "scan",
            "--no-progress",
            "--config",
            str(config),
        ],
    )
    merge = child.merge(shard_paths, "--config", str(config))

    unset = _flat(f"Environment variable {UNSET_VARIABLE} not set")
    if scan["exit_code"] == INVALID_CONFIG_EXIT:
        assert merge["exit_code"] == INVALID_CONFIG_EXIT, merge["output"]
        assert not child.output_dir.exists(), merge["output"]
    else:
        assert merge["exit_code"] != INVALID_CONFIG_EXIT, merge["output"]
        assert child.merged(), merge["output"]
        assert (unset in _flat(scan["output"])) == (unset in _flat(merge["output"])), (
            scan["output"][-2000:],
            merge["output"][-2000:],
        )
