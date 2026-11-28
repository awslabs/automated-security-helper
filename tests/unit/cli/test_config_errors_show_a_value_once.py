# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A value a config error quotes is shown once, by the sink that prints it.

Every sink shows the text it prints (utils/terminal_text.py): a control
character becomes its escape, ``\\x1b``, and a backslash run before text that
reads as an escape is doubled, so the escape cannot be forged. A message that
quoted a value with ``!r`` had escaped it already, and the sink then doubled
that escape's backslash: the operator read ``\\\\x1b`` for one ESC character.
The config code quotes a value as written, ``'...'``, and leaves the escaping
to the sink.

Each cell gives a value holding ESC and checks what is printed: the escape
once, the doubled escape nowhere, and no raw ESC.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tests.unit.cli.test_merge import build_shards, write_shards
from tests.utils.helpers import importing_this_checkout

ESC = "\x1b"
SHOWN_ONCE = "\\x1b"
SHOWN_TWICE = "\\\\x1b"


def _assert_shown_once(text: str) -> None:
    assert SHOWN_ONCE in text, text
    assert SHOWN_TWICE not in text, text
    assert ESC not in text, text


def _merge_with_config(tmp_path: Path, config_text: str) -> subprocess.CompletedProcess:
    """``ash merge --config`` over two shards, in a fresh interpreter, with the
    operator's file outside the collector's working directory."""
    operator = tmp_path / "operator" / "ash.yaml"
    operator.parent.mkdir(parents=True)
    operator.write_text(config_text, encoding="utf-8")
    shards = write_shards(tmp_path / "artifacts", build_shards(2))
    collector = tmp_path / "collector"
    collector.mkdir()
    argv = [
        sys.executable,
        "-c",
        importing_this_checkout(
            "from automated_security_helper.cli.main import app; app()"
        ),
        "merge",
    ]
    for shard in shards:
        argv += ["--results", shard]
    argv += [
        "--output-dir",
        str(tmp_path / "merged"),
        "--no-color",
        "--config",
        str(operator),
    ]
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=300,
        cwd=collector,
        check=False,
    )


@pytest.mark.integration
def test_the_merge_refusal_shows_a_patch_path_once(tmp_path: Path) -> None:
    """A patch operation of the operator's --config fails at a path holding ESC:
    the refusal names the path, shown once."""
    result = _merge_with_config(
        tmp_path,
        "project_name: demo\n"
        "patch:\n"
        "  - op: add\n"
        '    path: "/no\\x1bsuch/parent"\n'
        "    value: 1\n",
    )

    output = result.stdout + result.stderr
    assert result.returncode == 3, output
    assert "Invalid configuration" in output, output
    _assert_shown_once(output)
    assert "(add at '/no\\x1bsuch/parent') failed" in " ".join(output.split()), output


@pytest.mark.integration
def test_the_merge_refusal_shows_no_extends_value_twice(tmp_path: Path) -> None:
    """``extends`` holds a list with an entry that is not a path: the refusal
    names what it got without quoting an entry that holds ESC through a repr."""
    result = _merge_with_config(
        tmp_path,
        'project_name: demo\nextends:\n  - 1\n  - "a\\x1bb.yaml"\n',
    )

    output = result.stdout + result.stderr
    assert result.returncode == 3, output
    assert "must be a path or a list of paths, got a list" in " ".join(
        output.split()
    ), output
    assert SHOWN_TWICE not in output, output
    assert ESC not in output, output


@pytest.mark.unit
def test_an_invalid_override_is_shown_once(tmp_path: Path) -> None:
    """A --config-overrides key holding ESC is refused, naming the override as
    written, shown once by the report's sink."""
    from automated_security_helper.cli.main import app

    config = tmp_path / ".ash.yaml"
    config.write_text("project_name: demo\n", encoding="utf-8")

    result = CliRunner().invoke(
        app,
        [
            "report",
            "--output-dir",
            str(tmp_path / "out"),
            "--config",
            str(config),
            "--config-overrides",
            f"global{ESC}_settings.severity_threshold=LOW",
            "--no-color",
        ],
    )

    assert result.exit_code != 0, result.output
    assert "Invalid config override: 'global\\x1b_settings" in result.output, (
        result.output
    )
    _assert_shown_once(result.output)


@pytest.mark.unit
def test_the_lint_symbol_path_is_shown_once(tmp_path: Path) -> None:
    """The linter's warning for a symbol whose path matches no file it has a
    grammar for names the path as written, shown once by the lint sink."""
    from automated_security_helper.cli.config import config_app

    config = tmp_path / ".ash.yaml"
    config.write_text(
        "project_name: demo\n"
        "global_settings:\n"
        "  suppressions:\n"
        "    - rule_id: R1\n"
        '      path: "a\\x1bb.txt"\n'
        "      symbol: MyClass.my_method\n"
        "      reason: probe\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(config_app, ["lint", "--config", str(config)])

    assert "Suppression sets 'symbol' but its path 'a\\x1bb.txt'" in result.output, (
        result.output
    )
    _assert_shown_once(result.output)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("written", "shown"),
    [
        pytest.param("a\\x1bb.py", "'a\\x1bb.py' no longer exists", id="gone"),
        pytest.param("a\\x1bb*.py", "'a\\x1bb*.py' is a pattern", id="pattern"),
    ],
)
def test_the_lock_refusal_shows_the_path_once(
    tmp_path: Path, written: str, shown: str
) -> None:
    """The linter's refusal of a symbol suppression that ``.ash.lock`` does not
    record quotes its path as written, for a file that is gone and for a
    pattern, and the lint sink shows it once."""
    from automated_security_helper.cli.config import config_app

    config = tmp_path / ".ash.yaml"
    config.write_text(
        "project_name: demo\n"
        "global_settings:\n"
        "  suppressions:\n"
        "    - rule_id: R1\n"
        f'      path: "{written}"\n'
        "      symbol: MyClass.my_method\n"
        "      reason: probe\n",
        encoding="utf-8",
    )

    result = CliRunner().invoke(config_app, ["lint", "--config", str(config)])

    assert shown in result.output, result.output
    _assert_shown_once(result.output)


_SYMBOL_SUPPRESSION_CONFIG = (
    "project_name: demo\n"
    "global_settings:\n"
    "  suppressions:\n"
    "    - rule_id: R1\n"
    "      path: src/app.py\n"
    "      symbol: MyClass.my_method\n"
    "      reason: probe\n"
)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("lock", "shown"),
    [
        pytest.param(
            '{"version": 2, "files": {}, "a\\u001bb": 0}',
            "has an unknown key 'a\\x1bb' in the document",
            id="unknown-key",
        ),
        pytest.param(
            '{"version": 2, "files": {"a\\u001bb.py": {}, "a\\u001bb.py": {}}}',
            "key 'a\\x1bb.py' appears more than once in the object at /files",
            id="repeated-key",
        ),
        pytest.param(
            '{"version": 2, "files": {"a\\u001bb.py": '
            '{"created": "x", "created": "y"}}}',
            "key 'created' appears more than once in the object at /files/a\\x1bb.py",
            id="repeated-key-pointer",
        ),
    ],
)
def test_a_lock_file_key_is_shown_once(tmp_path: Path, lock: str, shown: str) -> None:
    """A committed .ash.lock that the linter cannot read for a symbol
    suppression is refused naming the lock's key as written, and the lint sink
    shows it once: an unknown key, a repeated key, and a repeated key inside an
    object whose pointer holds the character."""
    from automated_security_helper.cli.config import config_app
    from automated_security_helper.utils.ash_lock import LOCK_RELATIVE_PATH

    root = tmp_path / "repo"
    root.mkdir()
    (root / LOCK_RELATIVE_PATH).write_text(lock, encoding="utf-8")
    config = root / ".ash.yaml"
    config.write_text(_SYMBOL_SUPPRESSION_CONFIG, encoding="utf-8")

    result = CliRunner().invoke(
        config_app, ["lint", "--config", str(config), "--source-dir", str(root)]
    )

    assert shown in result.output, result.output
    _assert_shown_once(result.output)
