# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An error that quotes a bracket is printed and logged as the text it is.

The console log handler reads Rich markup, and a "[/" in a message is a
closing tag that raises MarkupError instead of printing. Config keys, paths
and error text are data, so a key or a message holding "[/bold]" has to reach
the operator, and the log file, unchanged; read as markup it would end the run
in a MarkupError traceback, exit 1, before the refusal was printed.
"""

from __future__ import annotations

from pathlib import Path

SCAN = ["scan", "--no-progress", "--scanners", "bandit"]
TAG = "[/bold]"


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _source(root: Path, config: str | None = None) -> Path:
    source = root / "src"
    _write(source / "app.py", "print('hello')\n")
    if config is not None:
        _write(source / ".ash" / ".ash.yaml", config)
    return source


def _assert_printed_as_text(seen: dict, exit_code: int) -> None:
    printed = f"{seen['stdout']}\n{seen['stderr']}"
    assert "uncaught_exception" not in seen, seen
    assert "MarkupError" not in printed, printed
    assert seen["exit_code"] == exit_code, seen
    assert TAG in printed, printed


def _logged(root: Path) -> str:
    log = root / "out" / "ash.log"
    assert log.is_file(), "the run wrote no ash.log"
    return log.read_text(encoding="utf-8", errors="replace")


def test_a_bracketed_key_in_the_repository_config(run_cli, in_tmp):
    """A key the entry does not declare is refused by name, so the name is in
    the refusal: exit 3, the config's own code, with the key printed."""
    _source(
        in_tmp,
        "project_name: probe\n"
        "global_settings:\n"
        "  ignore_paths:\n"
        "    - path: x\n"
        "      reason: probe\n"
        f'      "{TAG}": 1\n',
    )
    seen = run_cli([*SCAN, "--source-dir", "src", "--output-dir", "out"])
    _assert_printed_as_text(seen, 3)
    assert TAG in _logged(in_tmp)


def test_an_error_quoting_a_closing_tag_at_the_generic_exit(
    run_cli, in_tmp, monkeypatch
):
    """An error nothing expected is logged with its traceback and printed."""

    def raise_it(*args, **kwargs):
        raise RuntimeError(f"could not read /x{TAG}")

    monkeypatch.setattr(
        "automated_security_helper.core.orchestrator.ASHScanOrchestrator.create",
        raise_it,
    )
    _source(in_tmp)
    seen = run_cli([*SCAN, "--source-dir", "src", "--output-dir", "out"])
    _assert_printed_as_text(seen, 1)
    assert f"could not read /x{TAG}" in _logged(in_tmp)


def test_a_validation_error_naming_a_bracketed_key_at_the_generic_exit(
    run_cli, in_tmp, monkeypatch
):
    """A pydantic error is logged described, by its location, which holds the key."""
    from pydantic import ValidationError

    from automated_security_helper.config.ash_config import AshConfig

    try:
        AshConfig.model_validate(
            {
                "project_name": "x",
                "global_settings": {
                    "ignore_paths": [{"path": "x", "reason": "r", TAG: 1}]
                },
            }
        )
    except ValidationError as error:
        refused = error
    else:
        raise AssertionError("the unknown key was accepted")

    def raise_it(*args, **kwargs):
        raise refused

    monkeypatch.setattr(
        "automated_security_helper.core.orchestrator.ASHScanOrchestrator.create",
        raise_it,
    )
    _source(in_tmp)
    seen = run_cli([*SCAN, "--source-dir", "src", "--output-dir", "out"])
    _assert_printed_as_text(seen, 1)
    assert TAG in _logged(in_tmp)
