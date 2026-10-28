# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config check's messages show a value read from the environment as ``<value>``.

``ash config lint``, ``ash config validate``, the MCP ``validate_config`` and
``get_config`` tools, the warning for the ``ash_plugin_modules`` entries an
in-tree file may not add, the warnings that name the in-tree files a setting
was ignored from, and the errors of an ``extends`` chain report on a
config whose values can come from the environment, through ``${VAR}`` or
``!ENV ${VAR}``. Each check still reads the value; its message names the value
by its place in the file (``environment_record.with_environment_values_shown``),
so the text holds no value the environment supplied, while a value the file
wrote itself is shown as written. Every module of a list entry read from the
environment is shown that way, however the entry splits, and so is a short
value, which no search of the text for the value would find.

Each test sets distinct canary values and asserts that none of them is in what
the channel returns, that the placeholder is, and that a literal written beside
them still is.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, Iterator, List

import pytest
from typer.testing import CliRunner

from tests.utils.helpers import mark_git_checkout

#: How a message shows a value read from the environment
#: (``environment_record.ENVIRONMENT_VALUE_SHOWN``), written out so that the
#: tests read the same on a tree without it.
ENVIRONMENT_VALUE_SHOWN = "<value>"

MODULE = "probecanarymodule"
DIRECTORY = "probecanarydirectory"
EXPIRATION = "probecanaryexpiry"
SYMBOL = "probe canary symbol"
SHORT = "q7"
PAIR = ("probecanaryaa", "probecanarybb")
BASE_DIRECTORY = "probecanarybases"
NAME = "probecanaryname"
FIELD = "probecanaryfield"
SCANNER = "probecanaryscanner"

#: Values the file writes itself, which every message still shows.
LITERAL_MODULE = "literalprobemodule"
LITERAL_DIRECTORY = "literalprobedir"

CANARIES = (
    MODULE,
    DIRECTORY,
    EXPIRATION,
    SYMBOL,
    SHORT,
    *PAIR,
    BASE_DIRECTORY,
    NAME,
    FIELD,
    SCANNER,
)


@pytest.fixture(autouse=True)
def _environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    monkeypatch.setenv("ASH_PROBE_CANARY_MODULE", MODULE)
    monkeypatch.setenv("ASH_PROBE_CANARY_DIRECTORY", DIRECTORY)
    monkeypatch.setenv("ASH_PROBE_CANARY_EXPIRATION", EXPIRATION)
    monkeypatch.setenv("ASH_PROBE_CANARY_SYMBOL", SYMBOL)
    monkeypatch.setenv("ASH_PROBE_CANARY_SHORT", SHORT)
    monkeypatch.setenv("ASH_PROBE_CANARY_PAIR", ",".join(PAIR))
    monkeypatch.setenv("ASH_PROBE_CANARY_BASES", BASE_DIRECTORY)
    monkeypatch.setenv("ASH_PROBE_CANARY_NAME", NAME)
    monkeypatch.setenv("ASH_PROBE_CANARY_FIELD", FIELD)
    monkeypatch.setenv("ASH_PROBE_CANARY_SCANNER", SCANNER)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    for directory in (DIRECTORY, LITERAL_DIRECTORY):
        (tmp_path / directory).mkdir()
    from automated_security_helper.cli.mcp.profile_registry import (
        clear_profile_registry,
        clear_all_session_state,
    )

    clear_profile_registry()
    clear_all_session_state()
    yield
    clear_profile_registry()
    clear_all_session_state()


def _assert_hidden(text: str) -> None:
    for canary in CANARIES:
        assert canary not in text, (canary, text)


TOML = """\
project_name = "probe"
ash_plugin_modules = ["${ASH_PROBE_CANARY_MODULE}", "${ASH_PROBE_CANARY_PAIR}", "literalprobemodule"]

[[global_settings.suppressions]]
rule_id = "R1"
path = "${ASH_PROBE_CANARY_DIRECTORY}"
reason = "probe"
expiration = "${ASH_PROBE_CANARY_EXPIRATION}"
symbol = "${ASH_PROBE_CANARY_SYMBOL}"
line_start = "${ASH_PROBE_CANARY_SHORT}"

[[global_settings.suppressions]]
rule_id = "R2"
path = "literalprobedir"
reason = "probe"
expiration = "${ASH_PROBE_CANARY_SHORT}"

[[global_settings.ignore_paths]]
path = "${ASH_PROBE_CANARY_DIRECTORY}"
reason = "probe"

[[global_settings.ignore_paths]]
path = "literalprobedir"
reason = "probe"
"""

#: The same settings in YAML: each value read with a plain reference, or with
#: the explicit tag, in a base the root extends.
YAML_SETTINGS = """\
ash_plugin_modules:
  - {tag}${{ASH_PROBE_CANARY_MODULE}}
  - {tag}${{ASH_PROBE_CANARY_PAIR}}
  - literalprobemodule
global_settings:
  suppressions:
    - rule_id: R1
      path: {tag}${{ASH_PROBE_CANARY_DIRECTORY}}
      reason: probe
      expiration: {tag}${{ASH_PROBE_CANARY_EXPIRATION}}
      symbol: {tag}${{ASH_PROBE_CANARY_SYMBOL}}
    - rule_id: R2
      path: literalprobedir
      reason: probe
      expiration: {tag}${{ASH_PROBE_CANARY_SHORT}}
  ignore_paths:
    - path: {tag}${{ASH_PROBE_CANARY_DIRECTORY}}
      reason: probe
    - path: literalprobedir
      reason: probe
"""


def _toml(tmp_path: Path) -> Path:
    path = tmp_path / "ashrc.toml"
    path.write_text(TOML, encoding="utf-8")
    return path


def _yaml_root(tmp_path: Path, tag: str) -> Path:
    path = tmp_path / ".ash.yaml"
    path.write_text(
        "project_name: probe\n" + YAML_SETTINGS.format(tag=tag), encoding="utf-8"
    )
    return path


def _yaml_base(tmp_path: Path, tag: str) -> Path:
    (tmp_path / "base.yaml").write_text(YAML_SETTINGS.format(tag=tag), encoding="utf-8")
    path = tmp_path / ".ash.yaml"
    path.write_text("extends: base.yaml\nproject_name: probe\n", encoding="utf-8")
    return path


CONFIGS = {
    "toml": _toml,
    "yaml": lambda tmp: _yaml_root(tmp, ""),
    "yaml-tagged": lambda tmp: _yaml_root(tmp, "!ENV "),
    "base": lambda tmp: _yaml_base(tmp, ""),
    "base-tagged": lambda tmp: _yaml_base(tmp, "!ENV "),
}


def _validator_errors(path: Path) -> List[str]:
    from automated_security_helper.config.config_validator import ConfigValidator

    _valid, errors = ConfigValidator.validate_config_file(path)
    return errors


@pytest.mark.parametrize("shape", sorted(CONFIGS))
def test_validate_names_values_read_from_the_environment_by_place(
    tmp_path: Path, shape: str
) -> None:
    errors = _validator_errors(CONFIGS[shape](tmp_path))
    text = "\n".join(errors)
    _assert_hidden(text)
    # The model refuses both expirations, the one read from the environment
    # whole and the short one, each at its own field: the check read them.
    # Neither message quotes the value (_assert_hidden above).
    for index in (0, 1):
        assert any(
            e.startswith(
                f"Invalid value at 'global_settings.suppressions[{index}].expiration'"
            )
            for e in errors
        ), errors
    paths = [e for e in errors if "points to a directory" in e]
    assert any(f"'{ENVIRONMENT_VALUE_SHOWN}'" in e for e in paths), errors
    assert any(LITERAL_DIRECTORY in e for e in paths), errors


@pytest.mark.parametrize("tag", ["", "!ENV "])
def test_validate_names_keys_read_from_the_environment_by_place(
    tmp_path: Path, tag: str
) -> None:
    path = tmp_path / ".ash.yaml"
    path.write_text(
        "project_name: probe\n"
        f"{tag}${{ASH_PROBE_CANARY_FIELD}}: 1\n"
        "global_settings:\n"
        f"  {tag}${{ASH_PROBE_CANARY_FIELD}}: 1\n"
        "scanners:\n"
        f"  {tag}${{ASH_PROBE_CANARY_SCANNER}}:\n"
        "    name: probe\n",
        encoding="utf-8",
    )
    errors = _validator_errors(path)
    _assert_hidden("\n".join(errors))
    assert (
        f"Unknown top-level field '{ENVIRONMENT_VALUE_SHOWN}' - a scan ignores it"
        in errors
    ), errors
    assert any(
        e.startswith(
            f"Scanner '{ENVIRONMENT_VALUE_SHOWN}' contains internal-only field 'name'"
        )
        for e in errors
    ), errors
    assert any(
        e.startswith(f"Invalid value at 'global_settings.{ENVIRONMENT_VALUE_SHOWN}': ")
        for e in errors
    ), errors


def test_validate_names_a_short_key_read_from_the_environment_by_place(
    tmp_path: Path,
) -> None:
    """A key shorter than any redaction would replace, under a field: the model's
    location names it by its place, and its message does not quote it."""
    path = tmp_path / ".ash.yaml"
    path.write_text(
        "project_name: probe\n"
        "global_settings:\n"
        "  ${ASH_PROBE_CANARY_SHORT}: 1\n"
        "  literalprobefield: 1\n",
        encoding="utf-8",
    )
    errors = _validator_errors(path)
    _assert_hidden("\n".join(errors))
    assert any(
        e.startswith(f"Invalid value at 'global_settings.{ENVIRONMENT_VALUE_SHOWN}': ")
        for e in errors
    ), errors
    assert any(
        e.startswith("Invalid value at 'global_settings.literalprobefield': ")
        for e in errors
    ), errors


def test_lint_names_values_a_toml_file_read_from_the_environment_by_place(
    tmp_path: Path,
) -> None:
    from automated_security_helper.config.config_linter import ConfigLinter

    result = ConfigLinter.lint(_toml(tmp_path))
    messages = [issue.message for issue in result.issues]
    fixes = [issue.fix_description or "" for issue in result.issues]
    text = "\n".join(messages + fixes)
    _assert_hidden(text)
    # The model's refusals of the symbol and both expirations, each read from
    # the environment, as the scan words them, at their fields; the linter's
    # own line_start check, whose value is the short one; and the directory
    # paths. No message quotes a value read (_assert_hidden above).
    assert any(
        m.startswith("Invalid value at 'global_settings.suppressions[0].symbol'")
        for m in messages
    ), messages
    assert (
        sum(
            m.startswith("Invalid value at 'global_settings.suppressions[")
            and ".expiration'" in m
            for m in messages
        )
        == 2
    ), messages
    assert any(f"'line_start' ({ENVIRONMENT_VALUE_SHOWN})" in m for m in messages), (
        messages
    )
    assert any(f"line_end = {ENVIRONMENT_VALUE_SHOWN}" in f for f in fixes), fixes
    assert any(f"Path '{ENVIRONMENT_VALUE_SHOWN}'" in m for m in messages), messages
    assert any(f"Path '{LITERAL_DIRECTORY}'" in m for m in messages), messages


@pytest.mark.parametrize("shape", ["base", "base-tagged"])
def test_lint_names_values_a_base_read_from_the_environment_by_place(
    tmp_path: Path, shape: str
) -> None:
    from automated_security_helper.config.config_linter import ConfigLinter

    result = ConfigLinter.lint(CONFIGS[shape](tmp_path))
    text = "\n".join(issue.message for issue in result.issues)
    _assert_hidden(text)
    assert f"Path '{LITERAL_DIRECTORY}'" in text, text
    assert repr(ENVIRONMENT_VALUE_SHOWN) in text, text


def test_lint_reports_each_directory_read_from_the_environment_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two ignore paths read from the environment, both directories that match
    nothing: the file's own entry, and one a patch operation adds. Each message
    names its path ``<value>``, so the two read the same; lint reports both, as
    validate does, and still reports the file's literal directory once, though
    its own check and the validator's both find it."""
    from automated_security_helper.config.config_linter import (
        ConfigLinter,
        LintCategory,
    )

    other = "probecanaryotherdir"
    (tmp_path / other).mkdir()
    monkeypatch.setenv("ASH_PROBE_CANARY_OTHER_DIRECTORY", other)
    config = tmp_path / ".ash.yaml"
    config.write_text(
        "project_name: probe\n"
        "global_settings:\n"
        "  ignore_paths:\n"
        "    - path: ${ASH_PROBE_CANARY_DIRECTORY}\n"
        "      reason: probe\n"
        "    - path: literalprobedir\n"
        "      reason: probe\n"
        "patch:\n"
        "  - op: add\n"
        "    path: /global_settings/ignore_paths/-\n"
        "    value:\n"
        "      path: ${ASH_PROBE_CANARY_OTHER_DIRECTORY}\n"
        "      reason: patched\n",
        encoding="utf-8",
    )

    validated = [
        error
        for error in _validator_errors(config)
        if error.startswith(f"Path '{ENVIRONMENT_VALUE_SHOWN}'")
    ]
    result = ConfigLinter.lint(config)
    paths = [
        issue
        for issue in result.issues
        if issue.category == LintCategory.IGNORE_PATH_ISSUE
    ]
    text = "\n".join(issue.message for issue in result.issues)
    _assert_hidden(text)
    assert other not in text
    assert len(validated) == 2, validated
    read = [
        i for i in paths if i.message.startswith(f"Path '{ENVIRONMENT_VALUE_SHOWN}'")
    ]
    assert len(read) == 2, [(i.message, i.path) for i in paths]
    # The file's own entry at its place; the one the patch added, which no
    # entry of the file holds, unlocated.
    assert sorted(i.path for i in read) == ["", "global_settings.ignore_paths[0].path"]
    literal = [i for i in paths if i.message.startswith(f"Path '{LITERAL_DIRECTORY}'")]
    assert [i.path for i in literal] == ["global_settings.ignore_paths[1].path"]


def test_lint_names_an_unused_suppression_read_from_the_environment_by_place(
    tmp_path: Path,
) -> None:
    from automated_security_helper.config.config_linter import ConfigLinter

    config = tmp_path / "ashrc.toml"
    config.write_text(
        'project_name = "probe"\n\n'
        "[[global_settings.suppressions]]\n"
        'rule_id = "R1"\n'
        'path = "${ASH_PROBE_CANARY_DIRECTORY}/**"\n'
        'reason = "probe"\n\n'
        "[[global_settings.suppressions]]\n"
        'rule_id = "R2"\n'
        'path = "literalprobedir/**"\n'
        'reason = "probe"\n',
        encoding="utf-8",
    )
    # What the scan wrote: the suppressions as it read them.
    entries = [
        {"rule_id": "R1", "path": f"{DIRECTORY}/**", "reason": "probe"},
        {"rule_id": "R2", "path": f"{LITERAL_DIRECTORY}/**", "reason": "probe"},
    ]
    report = tmp_path / "out" / "reports" / "ash.unused-suppressions.json"
    report.parent.mkdir(parents=True)
    report.write_text(json.dumps({"unused_suppressions": entries}), encoding="utf-8")

    result = ConfigLinter.lint(config, output_dir=tmp_path / "out", check_unused=True)
    unused = [
        i.message for i in result.issues if i.message.startswith("Unused suppression")
    ]
    assert len(unused) == 2, unused
    _assert_hidden("\n".join(unused))
    # The whole field is the reference's, the text after it included.
    assert f"path='{ENVIRONMENT_VALUE_SHOWN}'" in unused[0], unused
    assert f"path='{LITERAL_DIRECTORY}/**'" in unused[1], unused


def test_lint_matches_an_unused_suppression_the_report_holds_as_written(
    tmp_path: Path,
) -> None:
    """Since the reference record, a scan's report lists an
    env-reading entry as the file wrote it (the ``${VAR}`` reference), while
    the check keyed its matches by resolved ids alone, so the entry fell into
    the free-text branch for suppressions the config no longer holds. Matched
    by either id, as --fix-unused already matches, the message quotes the
    shown copy."""
    from automated_security_helper.config.config_linter import ConfigLinter

    config = tmp_path / ".ash.yaml"
    config.write_text(
        "project_name: probe\n"
        "global_settings:\n"
        "  suppressions:\n"
        "    - rule_id: R1\n"
        "      path: ${ASH_PROBE_CANARY_DIRECTORY}/**\n"
        "      reason: probe\n",
        encoding="utf-8",
    )
    # What the scan wrote: the entry as the file wrote it, reference included.
    entries = [
        {"rule_id": "R1", "path": "${ASH_PROBE_CANARY_DIRECTORY}/**", "reason": "probe"}
    ]
    report = tmp_path / "out" / "reports" / "ash.unused-suppressions.json"
    report.parent.mkdir(parents=True)
    report.write_text(json.dumps({"unused_suppressions": entries}), encoding="utf-8")

    result = ConfigLinter.lint(config, output_dir=tmp_path / "out", check_unused=True)

    unused = [
        i.message for i in result.issues if i.message.startswith("Unused suppression")
    ]
    assert len(unused) == 1, unused
    _assert_hidden("\n".join(unused))
    # Matched, so the field is quoted from the shown copy, not echoed from the
    # report as text the config no longer holds.
    assert f"path='{ENVIRONMENT_VALUE_SHOWN}'" in unused[0], unused


def test_lint_matches_a_base_file_s_unused_suppression_as_written(
    tmp_path: Path,
) -> None:
    """An env-reading suppression an ``extends`` base holds: its reference is
    the base's, so the written-form id has to come from what the whole chain
    read, in the merged configuration's coordinates, not from the checked
    file's own references, which hold nothing here. The plain entry ahead of
    it pins the anchoring by place. The checked file adds no suppressions:
    a list it wrote would replace the base's."""
    from automated_security_helper.config.config_linter import ConfigLinter

    base = tmp_path / "base.yaml"
    base.write_text(
        "global_settings:\n"
        "  suppressions:\n"
        "    - rule_id: R0\n"
        "      path: plainbase/**\n"
        "      reason: probe\n"
        "    - rule_id: R1\n"
        "      path: ${ASH_PROBE_CANARY_DIRECTORY}/**\n"
        "      reason: probe\n",
        encoding="utf-8",
    )
    config = tmp_path / ".ash.yaml"
    config.write_text(
        "project_name: probe\nextends: base.yaml\n",
        encoding="utf-8",
    )
    # What the scan wrote: the base's entry as the base wrote it.
    entries = [
        {"rule_id": "R1", "path": "${ASH_PROBE_CANARY_DIRECTORY}/**", "reason": "probe"}
    ]
    report = tmp_path / "out" / "reports" / "ash.unused-suppressions.json"
    report.parent.mkdir(parents=True)
    report.write_text(json.dumps({"unused_suppressions": entries}), encoding="utf-8")

    result = ConfigLinter.lint(config, output_dir=tmp_path / "out", check_unused=True)

    unused = [
        i.message for i in result.issues if i.message.startswith("Unused suppression")
    ]
    assert len(unused) == 1, unused
    _assert_hidden("\n".join(unused))
    # Matched by the written-form id the chain's references give the entry, so
    # the field is quoted from the shown copy.
    assert f"path='{ENVIRONMENT_VALUE_SHOWN}'" in unused[0], unused


def test_lint_fix_unused_names_a_short_suppression_value_by_place(
    tmp_path: Path,
) -> None:
    """--fix-unused's own message about each entry it comments out: a rule_id
    shorter than any redaction would replace is <value> by its place."""
    from automated_security_helper.config.config_linter import ConfigLinter

    config = tmp_path / ".ash.yaml"
    config.write_text(
        "project_name: probe\n"
        "global_settings:\n"
        "  suppressions:\n"
        "    - rule_id: ${ASH_PROBE_CANARY_SHORT}\n"
        "      path: literalprobedir/**\n"
        "      reason: probe\n",
        encoding="utf-8",
    )
    entries = [{"rule_id": SHORT, "path": f"{LITERAL_DIRECTORY}/**", "reason": "probe"}]
    report = tmp_path / "out" / "reports" / "ash.unused-suppressions.json"
    report.parent.mkdir(parents=True)
    report.write_text(json.dumps({"unused_suppressions": entries}), encoding="utf-8")

    _content, issues, _when = ConfigLinter.fix_unused_suppressions(
        config, output_dir=tmp_path / "out"
    )
    messages = [issue.message for issue in issues]
    assert len(messages) == 1, messages
    _assert_hidden(messages[0])
    assert f"rule_id='{ENVIRONMENT_VALUE_SHOWN}'" in messages[0], messages
    assert f"path='{LITERAL_DIRECTORY}/**'" in messages[0], messages


def _cli(*args: str) -> str:
    from automated_security_helper.cli.config import config_app

    result = CliRunner().invoke(config_app, list(args))
    return result.output


@pytest.mark.parametrize("command", ["lint", "validate"])
def test_the_commands_show_no_value_read_from_the_environment(
    tmp_path: Path, command: str
) -> None:
    for shape in sorted(CONFIGS):
        work = tmp_path / shape
        work.mkdir()
        for directory in (DIRECTORY, LITERAL_DIRECTORY):
            (work / directory).mkdir()
        # The directories the paths name are under `work`, the scan root.
        output = _cli(
            command, "--config", str(CONFIGS[shape](work)), "--source-dir", str(work)
        )
        _assert_hidden(output)
        assert f"Path '{LITERAL_DIRECTORY}'" in output, (shape, output)
        assert ENVIRONMENT_VALUE_SHOWN in output, (shape, output)


def _chain_through_the_environment(tmp_path: Path) -> Path:
    bases = tmp_path / BASE_DIRECTORY
    bases.mkdir()
    (bases / "base.yaml").write_text("project_name: base\n", encoding="utf-8")
    root = tmp_path / ".ash.yaml"
    root.write_text(
        "extends: ${ASH_PROBE_CANARY_BASES}/base.yaml\nproject_name: probe\n",
        encoding="utf-8",
    )
    return root


@pytest.mark.parametrize("command", ["lint", "validate"])
def test_the_source_chain_names_a_base_the_environment_chose_by_place(
    tmp_path: Path, command: str
) -> None:
    output = _cli(command, "--config", str(_chain_through_the_environment(tmp_path)))
    _assert_hidden(output)
    assert "Resolved source chain" in output, output
    assert f"1. {ENVIRONMENT_VALUE_SHOWN}" in output, output


def test_the_source_chain_names_a_short_base_the_environment_chose_by_place(
    tmp_path: Path,
) -> None:
    """A base named by a short value, which a search of the path for the value
    left in place, is <value> as a whole."""
    (tmp_path / SHORT).mkdir()
    (tmp_path / SHORT / "base.yaml").write_text(
        "project_name: base\n", encoding="utf-8"
    )
    root = tmp_path / ".ash.yaml"
    root.write_text(
        "extends: ${ASH_PROBE_CANARY_SHORT}/base.yaml\nproject_name: probe\n",
        encoding="utf-8",
    )
    output = _cli("validate", "--config", str(root))
    chain = output.split("Resolved source chain", 1)[1].split("\n\n", 1)[0]
    _assert_hidden(chain)
    assert f"1. {ENVIRONMENT_VALUE_SHOWN}" in chain, output


def _missing_base(tmp_path: Path) -> Path:
    root = tmp_path / ".ash.yaml"
    root.write_text(
        "extends: ${ASH_PROBE_CANARY_BASES}/missing.yaml\nproject_name: probe\n",
        encoding="utf-8",
    )
    return root


def test_an_extends_error_names_a_base_the_environment_chose_by_place(
    tmp_path: Path,
) -> None:
    errors = _validator_errors(_missing_base(tmp_path))
    text = "\n".join(errors)
    _assert_hidden(text)
    assert f"'extends: {ENVIRONMENT_VALUE_SHOWN}'" in text, errors
    assert f"names {ENVIRONMENT_VALUE_SHOWN}, which does not exist" in text, errors


def test_the_scan_s_extends_error_names_a_base_the_environment_chose_by_place(
    tmp_path: Path,
) -> None:
    from automated_security_helper.config.config_sources import (
        resolve_config_document,
    )
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    with pytest.raises(ASHConfigSourceError) as raised:
        resolve_config_document(_missing_base(tmp_path), confine_to=tmp_path)
    _assert_hidden(str(raised.value))
    assert ENVIRONMENT_VALUE_SHOWN in str(raised.value)


def test_a_refused_base_the_environment_chose_is_named_by_place(
    tmp_path: Path,
) -> None:
    from automated_security_helper.config.config_sources import (
        resolve_config_document,
    )
    from automated_security_helper.core.exceptions import (
        ASHConfigInputNotPermittedError,
    )

    with pytest.raises(ASHConfigInputNotPermittedError) as raised:
        resolve_config_document(
            _chain_through_the_environment(tmp_path),
            confine_to=tmp_path,
            permit_base=lambda _path: False,
        )
    _assert_hidden(str(raised.value))
    assert f"'extends: {ENVIRONMENT_VALUE_SHOWN}'" in str(raised.value)


def test_an_extends_error_names_a_short_base_the_environment_chose_by_place(
    tmp_path: Path,
) -> None:
    """The extends chain's error for a base named by a short value."""
    root = tmp_path / ".ash.yaml"
    root.write_text(
        "extends: ${ASH_PROBE_CANARY_SHORT}/missing.yaml\nproject_name: probe\n",
        encoding="utf-8",
    )
    errors = _validator_errors(root)
    text = "\n".join(errors)
    _assert_hidden(text)
    assert f"names {ENVIRONMENT_VALUE_SHOWN}, which does not exist" in text, errors


@pytest.mark.parametrize("shape", sorted(CONFIGS))
def test_mcp_validate_config_names_values_read_from_the_environment_by_place(
    tmp_path: Path, shape: str
) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_validate_config

    result = mcp_validate_config(config_path=str(CONFIGS[shape](tmp_path)))
    text = json.dumps(result)
    _assert_hidden(text)
    messages = [
        entry["message"] for entry in [*result["errors"], *result.get("warnings", [])]
    ]
    assert any(LITERAL_DIRECTORY in m for m in messages), messages
    assert any(repr(ENVIRONMENT_VALUE_SHOWN) in m for m in messages), messages


def test_mcp_get_config_shows_no_value_read_from_the_environment(
    tmp_path: Path,
) -> None:
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    config = tmp_path / ".ash.yaml"
    config.write_text("project_name: ${ASH_PROBE_CANARY_NAME}\n", encoding="utf-8")
    shown: Dict[str, object] = mcp_get_config(config_path=str(config))
    _assert_hidden(json.dumps(shown, default=str))
    assert shown.get("project_name") == "<from ${ASH_PROBE_CANARY_NAME}>", shown


def test_mcp_get_config_shows_a_short_value_by_place(tmp_path: Path) -> None:
    """A short value at its place is the reference, and a value the file wrote
    itself is shown as written, even when the two are the same text."""
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    config = tmp_path / ".ash.yaml"
    config.write_text(
        "project_name: ${ASH_PROBE_CANARY_SHORT}\n"
        "global_settings:\n"
        "  suppressions:\n"
        "    - rule_id: R1\n"
        "      path: literalprobedir/**\n"
        "      reason: q7\n",
        encoding="utf-8",
    )
    shown: Dict[str, object] = mcp_get_config(config_path=str(config))
    assert shown.get("project_name") == "<from ${ASH_PROBE_CANARY_SHORT}>", shown
    settings = shown.get("global_settings")
    assert isinstance(settings, dict), shown
    assert settings["suppressions"][0]["reason"] == SHORT, settings


def test_the_in_tree_module_warning_names_a_module_read_from_the_environment_by_place(
    tmp_path: Path,
) -> None:
    """The warning for the ash_plugin_modules entries a file inside the scanned
    tree may not add: every module of an entry read from the environment, both
    pieces of the one that splits in two included, is <value>, and the module
    the file wrote is named."""
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.utils.log import ASH_LOGGER

    source = tmp_path / "src"
    (source / ".ash").mkdir(parents=True)
    (source / ".ash" / ".ash.yaml").write_text(
        "project_name: probe\n"
        "ash_plugin_modules:\n"
        "  - ${ASH_PROBE_CANARY_MODULE}\n"
        "  - ${ASH_PROBE_CANARY_PAIR}\n"
        "  - literalprobemodule\n",
        encoding="utf-8",
    )
    records: List[logging.LogRecord] = []

    class _Keep(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Keep(level=logging.DEBUG)
    ASH_LOGGER.addHandler(handler)
    try:
        config = resolve_config(source_dir=source)
    finally:
        ASH_LOGGER.removeHandler(handler)
    text = "\n".join(record.getMessage() for record in records)
    warning = [
        record.getMessage()
        for record in records
        if "Ignoring ash_plugin_modules entries" in record.getMessage()
    ]
    assert len(warning) == 1, text
    _assert_hidden(text)
    assert warning[0].count(f"'{ENVIRONMENT_VALUE_SHOWN}'") == 3, warning
    assert f"'{LITERAL_MODULE}'" in warning[0], warning
    # The check read the values: none of the refused modules is kept.
    assert not set(config.ash_plugin_modules) & {MODULE, *PAIR, LITERAL_MODULE}


#: The runtime policy's own entries, read from the environment by the profile's
#: file: a denied path, a short regex, and the path a regex is bound to.
DENIED = "/global_settings/probecanarydenied"
REGEX = "q[7]"
PATTERN_PATH = "/scanners/probecanarypatternpath"


@pytest.mark.parametrize(
    "op, expected",
    [
        pytest.param(
            {"op": "replace", "path": "/global_settings", "value": {}},
            "writes a subtree that contains denied_paths entry "
            f"'{ENVIRONMENT_VALUE_SHOWN}'",
            id="denied-path-read",
        ),
        pytest.param(
            {"op": "replace", "path": "/project_name", "value": "q7"},
            f"matches denied_value_patterns regex '{ENVIRONMENT_VALUE_SHOWN}' "
            "bound to '/project_name'",
            id="regex-read",
        ),
        pytest.param(
            {"op": "replace", "path": "/scanners", "value": {"x": "literalprobematch"}},
            "matches denied_value_patterns regex 'literalprobematch' bound to "
            f"'{ENVIRONMENT_VALUE_SHOWN}'",
            id="pattern-path-read",
        ),
        # The literal controls: what the file wrote is named.
        pytest.param(
            {"op": "replace", "path": "/literalprobedenied", "value": 1},
            "matches denied_paths entry '/literalprobedenied'",
            id="denied-path-written",
        ),
        pytest.param(
            {
                "op": "replace",
                "path": "/literalprobebound",
                "value": "literalproberegex",
            },
            "matches denied_value_patterns regex 'literalproberegex' bound to "
            "'/literalprobebound'",
            id="regex-and-path-written",
        ),
    ],
)
def test_the_runtime_policy_refusal_names_a_policy_entry_read_from_the_environment_by_place(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    op: Dict[str, object],
    expected: str,
) -> None:
    """The MCP server's refusal of a client's patch names the operator's policy
    entry that refused it. One the profile read from the environment is
    <value>: a denied path, a regex (a short one), and the path a regex is
    bound to. The entries the file wrote are named. The client's own op is
    quoted as the client wrote it, so no op here writes a canary."""
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )
    from automated_security_helper.config.runtime_patch import (
        RuntimePatchDeniedError,
        check_runtime_ops,
    )

    monkeypatch.setenv("ASH_PROBE_CANARY_DENIED", DENIED)
    monkeypatch.setenv("ASH_PROBE_CANARY_REGEX", REGEX)
    monkeypatch.setenv("ASH_PROBE_CANARY_PATTERN_PATH", PATTERN_PATH)
    profile = tmp_path / "profile.yaml"
    profile.write_text(
        "project_name: probe\n"
        "global_settings:\n"
        "  mcp:\n"
        "    runtime_overrides:\n"
        "      enabled: true\n"
        "      allowed_paths: ['/**']\n"
        "      denied_paths:\n"
        "        - ${ASH_PROBE_CANARY_DENIED}\n"
        "        - /literalprobedenied\n"
        "      denied_value_patterns:\n"
        "        /project_name: ${ASH_PROBE_CANARY_REGEX}\n"
        "        ${ASH_PROBE_CANARY_PATTERN_PATH}: literalprobematch\n"
        "        /literalprobebound: literalproberegex\n",
        encoding="utf-8",
    )
    config = load_config_file_for_run(profile)[1]
    assert config.global_settings.mcp is not None
    policy = config.global_settings.mcp.runtime_overrides
    # The policy holds the values: the check refuses by them.
    assert policy.denied_paths[0] == DENIED
    assert policy.denied_value_patterns["/project_name"] == REGEX
    assert policy.denied_value_patterns[PATTERN_PATH] == "literalprobematch"

    with pytest.raises(RuntimePatchDeniedError) as raised:
        check_runtime_ops([op], allowlist=policy, config=config)
    refusal = str(raised.value)
    assert "probecanarydenied" not in refusal, refusal
    assert "probecanarypatternpath" not in refusal, refusal
    assert REGEX not in refusal, refusal
    assert expected in refusal, refusal


@pytest.mark.parametrize(
    "override, expected",
    [
        pytest.param(
            "global_settings={}",
            "writes a subtree that contains denied_paths entry "
            f"'{ENVIRONMENT_VALUE_SHOWN}'",
            id="denied-path-read",
        ),
        pytest.param(
            "project_name=q7",
            f"matches denied_value_patterns regex '{ENVIRONMENT_VALUE_SHOWN}' "
            "bound to '/project_name'",
            id="regex-read",
        ),
        pytest.param(
            "scanners={x: literalprobematch}",
            "matches denied_value_patterns regex 'literalprobematch' bound to "
            f"'{ENVIRONMENT_VALUE_SHOWN}'",
            id="pattern-path-read",
        ),
        # The literal controls: what the file wrote is named.
        pytest.param(
            "literalprobedenied=1",
            "matches denied_paths entry '/literalprobedenied'",
            id="denied-path-written",
        ),
        pytest.param(
            "literalprobebound=literalproberegex",
            "matches denied_value_patterns regex 'literalproberegex' bound to "
            "'/literalprobebound'",
            id="regex-and-path-written",
        ),
    ],
)
def test_a_workspace_scans_override_refusal_names_a_policy_entry_read_from_the_environment_by_place(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    override: str,
    expected: str,
) -> None:
    """A workspace scan's config_overrides come from the MCP client, and are gated
    by the session config's runtime policy (cli/mcp/workspace._gate_client_overrides),
    whose refusal goes to the client as select_profile's does. The policy entry
    that refused one is named by place: <value> for one the session config read
    from the environment, as written for one it wrote."""
    from automated_security_helper.cli.mcp.workspace import _gate_client_overrides
    from automated_security_helper.config.runtime_patch import RuntimePatchDeniedError

    monkeypatch.setenv("ASH_PROBE_CANARY_DENIED", DENIED)
    monkeypatch.setenv("ASH_PROBE_CANARY_REGEX", REGEX)
    monkeypatch.setenv("ASH_PROBE_CANARY_PATTERN_PATH", PATTERN_PATH)
    session = tmp_path / "session.yaml"
    session.write_text(
        "project_name: probe\n"
        "global_settings:\n"
        "  mcp:\n"
        "    runtime_overrides:\n"
        "      enabled: true\n"
        "      allowed_paths: ['/**']\n"
        "      denied_paths:\n"
        "        - ${ASH_PROBE_CANARY_DENIED}\n"
        "        - /literalprobedenied\n"
        "      denied_value_patterns:\n"
        "        /project_name: ${ASH_PROBE_CANARY_REGEX}\n"
        "        ${ASH_PROBE_CANARY_PATTERN_PATH}: literalprobematch\n"
        "        /literalprobebound: literalproberegex\n",
        encoding="utf-8",
    )

    with pytest.raises(RuntimePatchDeniedError) as raised:
        _gate_client_overrides([override], str(session))
    refusal = str(raised.value)
    assert "probecanarydenied" not in refusal, refusal
    assert "probecanarypatternpath" not in refusal, refusal
    assert REGEX not in refusal, refusal
    assert expected in refusal, refusal


@pytest.mark.parametrize(
    "pattern, fragment, position",
    [
        pytest.param(
            "(?P<probesecretgroup>a)(?P<probesecretgroup>b)",
            "probesecretgroup",
            27,
            id="redefined-group",
        ),
        pytest.param(
            "(?P=probesecretgroup)", "probesecretgroup", 4, id="unknown-group"
        ),
        pytest.param("(?P<probe-secret>x)", "probe-secret", 4, id="bad-group-name"),
        pytest.param("[z-a]", "z-a", 1, id="bad-range"),
    ],
)
def test_an_invalid_policy_regex_read_from_the_environment_is_not_quoted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pattern: str,
    fragment: str,
    position: int,
) -> None:
    """re.error's text quotes a part of the pattern: a group name, a range. The
    refusal of a client's patch by a denied_value_patterns regex that does not
    compile goes to the client, so it says where the regex is invalid and not
    what is there."""
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )
    from automated_security_helper.config.runtime_patch import (
        RuntimePatchDeniedError,
        check_runtime_ops,
    )

    monkeypatch.setenv("ASH_PROBE_CANARY_BAD_REGEX", pattern)
    profile = tmp_path / "profile.yaml"
    profile.write_text(
        "project_name: probe\n"
        "global_settings:\n"
        "  mcp:\n"
        "    runtime_overrides:\n"
        "      enabled: true\n"
        "      allowed_paths: ['/**']\n"
        "      denied_value_patterns:\n"
        "        /project_name: ${ASH_PROBE_CANARY_BAD_REGEX}\n",
        encoding="utf-8",
    )
    config = load_config_file_for_run(profile)[1]
    assert config.global_settings.mcp is not None
    policy = config.global_settings.mcp.runtime_overrides
    assert policy.denied_value_patterns["/project_name"] == pattern

    op = {"op": "replace", "path": "/project_name", "value": "x"}
    with pytest.raises(RuntimePatchDeniedError) as raised:
        check_runtime_ops([op], allowlist=policy, config=config)
    refusal = str(raised.value)
    assert fragment not in refusal, refusal
    assert (
        f"denied_value_patterns regex for '/project_name' is invalid: re.error at "
        f"position {position}" in refusal
    ), refusal
    # Not chained either: a traceback of the refusal would print re.error's text.
    assert raised.value.__cause__ is None


@pytest.mark.parametrize(
    "written, reason",
    [
        pytest.param(
            "(?P=literalprobegroup)",
            "unknown group name 'literalprobegroup' at position 4",
            id="written",
        ),
        pytest.param(
            "${ASH_PROBE_CANARY_PART}(?P=literalprobegroup)",
            "re.error at position 19",
            id="part-read",
        ),
    ],
)
def test_an_invalid_policy_regex_the_file_wrote_keeps_its_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, written: str, reason: str
) -> None:
    """A regex the profile wrote whole is the operator's text, which the refusal
    may quote: it gives re.error's reason. One with a part read from the
    environment (a reference at its start) gives the position only."""
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )
    from automated_security_helper.config.runtime_patch import (
        RuntimePatchDeniedError,
        check_runtime_ops,
    )

    monkeypatch.setenv("ASH_PROBE_CANARY_PART", "probesecretpart")
    profile = tmp_path / "profile.yaml"
    profile.write_text(
        "project_name: probe\n"
        "global_settings:\n"
        "  mcp:\n"
        "    runtime_overrides:\n"
        "      enabled: true\n"
        "      allowed_paths: ['/**']\n"
        "      denied_value_patterns:\n"
        f"        /project_name: {written}\n",
        encoding="utf-8",
    )
    config = load_config_file_for_run(profile)[1]
    assert config.global_settings.mcp is not None
    policy = config.global_settings.mcp.runtime_overrides

    op = {"op": "replace", "path": "/project_name", "value": "x"}
    with pytest.raises(RuntimePatchDeniedError) as raised:
        check_runtime_ops([op], allowlist=policy, config=config)
    refusal = str(raised.value)
    prefix = "denied_value_patterns regex for '/project_name' is invalid: "
    assert f"{prefix}{reason}" in refusal, refusal
    assert "probesecretpart" not in refusal, refusal
    assert raised.value.__cause__ is None


def test_a_policy_entry_the_file_wrote_is_named_as_written_beside_one_read_from_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each denied_paths entry is shown by its own index. An entry the file wrote
    that holds the text of another entry, one read from the environment, is
    named as written, so the refusal never pairs `<value>/...` with the path the
    client's own op quotes."""
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )
    from automated_security_helper.config.runtime_patch import (
        RuntimePatchDeniedError,
        check_runtime_ops,
    )

    monkeypatch.setenv("ASH_PROBE_CANARY_PREFIX", "/probeqzprefix")
    profile = tmp_path / "profile.yaml"
    profile.write_text(
        "project_name: probe\n"
        "global_settings:\n"
        "  mcp:\n"
        "    runtime_overrides:\n"
        "      enabled: true\n"
        "      allowed_paths: ['/**']\n"
        "      denied_paths:\n"
        "        - /probeqzprefix/qzxi9lit\n"
        "        - ${ASH_PROBE_CANARY_PREFIX}\n",
        encoding="utf-8",
    )
    config = load_config_file_for_run(profile)[1]
    assert config.global_settings.mcp is not None
    policy = config.global_settings.mcp.runtime_overrides
    assert policy.denied_paths == ["/probeqzprefix/qzxi9lit", "/probeqzprefix"]

    refusals = []
    # The first only the entry the file wrote refuses (it is checked first), the
    # second only the one read from the environment.
    for path in ("/probeqzprefix/qzxi9lit", "/probeqzprefix/other"):
        op = {"op": "replace", "path": path, "value": 1}
        with pytest.raises(RuntimePatchDeniedError) as raised:
            check_runtime_ops([op], allowlist=policy, config=config)
        refusals.append(str(raised.value))
    # The entry the file wrote, as written; the one read from the environment,
    # by place.
    assert "matches denied_paths entry '/probeqzprefix/qzxi9lit'" in refusals[0], (
        refusals
    )
    assert f"{ENVIRONMENT_VALUE_SHOWN}/qzxi9lit" not in refusals[0], refusals
    assert f"denied_paths entry '{ENVIRONMENT_VALUE_SHOWN}'" in refusals[1], refusals


_DENIED_PATHS = "/global_settings/mcp/runtime_overrides/denied_paths"


@pytest.mark.parametrize(
    "denied, patch, written",
    [
        pytest.param(
            ["/probeqzlit/a"],
            f"  - op: add\n    path: {_DENIED_PATHS}/-\n"
            "    value: ${ASH_PROBE_CANARY_PREFIX}\n",
            ["/probeqzlit/a"],
            id="append",
        ),
        pytest.param(
            ["/probeqzlit/a", "${ASH_PROBE_CANARY_PREFIX}"],
            f"  - op: add\n    path: {_DENIED_PATHS}/0\n    value: /probeqzlit/i\n",
            ["/probeqzlit/i", "/probeqzlit/a"],
            id="insert-0",
        ),
        pytest.param(
            ["/probeqzlit/a", "${ASH_PROBE_CANARY_PREFIX}"],
            f"  - op: remove\n    path: {_DENIED_PATHS}/0\n",
            [],
            id="remove-0",
        ),
    ],
)
def test_a_policy_entry_a_patch_moves_is_named_by_its_place(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    denied: List[str],
    patch: str,
    written: List[str],
) -> None:
    """A patch operation of the profile's own appends an entry read from the
    environment, or inserts or removes one before it, so the entry ends at an
    index other than the one the file wrote it at. The refusal names it
    ``<value>`` at its new index, and each entry the file or the operation wrote
    as written."""
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )
    from automated_security_helper.config.runtime_patch import (
        RuntimePatchDeniedError,
        check_runtime_ops,
    )

    monkeypatch.setenv("ASH_PROBE_CANARY_PREFIX", "/probeqzprefix")
    profile = tmp_path / "profile.yaml"
    profile.write_text(
        "project_name: probe\n"
        "global_settings:\n"
        "  mcp:\n"
        "    runtime_overrides:\n"
        "      enabled: true\n"
        "      allowed_paths: ['/**']\n"
        "      denied_paths:\n"
        + "".join(f"        - {entry}\n" for entry in denied)
        + "patch:\n"
        + patch,
        encoding="utf-8",
    )
    config = load_config_file_for_run(profile)[1]
    assert config.global_settings.mcp is not None
    policy = config.global_settings.mcp.runtime_overrides
    # The check reads the value: the entry is where the operation left it.
    assert sorted(policy.denied_paths) == sorted([*written, "/probeqzprefix"])

    def refusal(path: str) -> str:
        op = {"op": "replace", "path": path, "value": 1}
        with pytest.raises(RuntimePatchDeniedError) as raised:
            check_runtime_ops([op], allowlist=policy, config=config)
        return str(raised.value)

    read = refusal("/probeqzprefix/other")
    assert f"denied_paths entry '{ENVIRONMENT_VALUE_SHOWN}'" in read, read
    assert "entry '/probeqzprefix" not in read, read
    for entry in written:
        shown = refusal(entry)
        assert f"denied_paths entry '{entry}'" in shown, shown


#: What an in-tree base the environment chose sets, and the start of the one
#: warning that names the files it was read from.
_IN_TREE_SETTINGS = {
    "plugin-modules": (
        "ash_plugin_modules:\n  - literalprobemodule\n",
        f"Ignoring ash_plugin_modules entries '{LITERAL_MODULE}'",
    ),
    "sandbox-grants": (
        "sandbox:\n  network_scanners:\n    - bandit\n",
        "Ignoring sandbox.network_scanners from ",
    ),
    "operator-only-option": (
        (
            "reporters:\n"
            "  aws-security-hub:\n"
            "    options:\n"
            "      archive_resolved_findings: true\n"
        ),
        "Ignoring reporters.aws-security-hub.options.archive_resolved_findings from ",
    ),
    "operator-only-section": (
        (
            "reporters:\n"
            "  aws-security-hub:\n"
            "    enabled: true\n"
            "    options:\n"
            "      archive_resolved_findings: true\n"
        ),
        (
            "Ignoring reporters.aws-security-hub.options.archive_resolved_findings "
            "and the rest of reporters.aws-security-hub from "
        ),
    ),
    "off-host-section": (
        (
            "reporters:\n"
            "  s3:\n"
            "    enabled: true\n"
            "    options:\n"
            "      bucket_name: literalprobebucket\n"
        ),
        "Ignoring reporters.s3 from ",
    ),
}


def _in_tree_chain(
    checkout: Path,
    root_name: str,
    settings: str,
    layout: str,
    monkeypatch: pytest.MonkeyPatch,
) -> Path:
    """A root config in *checkout* that extends a base the environment names,
    which extends one more: both are inside the tree, and the last sets
    *settings*.

    *layout* is how the variable names the bases' directory: as it is
    (``plain``), as ``<dir>/../<dir>`` (``dot-dot``), or as a link in the tree to
    a directory of another name (``symlink``). The last two give the base a name
    that is not its resolved path, which the warnings list beside it."""
    root = checkout / root_name
    root.parent.mkdir(parents=True, exist_ok=True)
    bases = root.parent / BASE_DIRECTORY
    if layout == "symlink":
        real = root.parent / "realbases"
        real.mkdir()
        try:
            bases.symlink_to("realbases", target_is_directory=True)
        except (OSError, NotImplementedError) as error:
            pytest.skip(f"symlinks unavailable: {error}")
    else:
        bases.mkdir()
    if layout == "dot-dot":
        monkeypatch.setenv(
            "ASH_PROBE_CANARY_BASES", f"{BASE_DIRECTORY}/../{BASE_DIRECTORY}"
        )
    (bases / "base.yaml").write_text("extends: deeper.yaml\n", encoding="utf-8")
    (bases / "deeper.yaml").write_text(settings, encoding="utf-8")
    root.write_text(
        "extends: ${ASH_PROBE_CANARY_BASES}/base.yaml\nproject_name: probe\n",
        encoding="utf-8",
    )
    return root


@pytest.mark.parametrize("layout", ["plain", "dot-dot", "symlink"])
@pytest.mark.parametrize("root_from", ["discovered", "ash-config"])
@pytest.mark.parametrize("setting", sorted(_IN_TREE_SETTINGS))
def test_an_in_tree_warning_names_a_base_the_environment_chose_by_place(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    setting: str,
    root_from: str,
    layout: str,
) -> None:
    """The warnings for what ASH ignores from a config file inside the scanned
    tree name the files the setting came from. A base an ``extends`` entry named
    with a value read from the environment, and the base it extends, are each
    named ``<value>``, in the record and in ash.log, as the source chain names
    them; the root file is named as written. The root is the file the scan
    discovered, or the one ASH_CONFIG names. A base the variable names by a path
    that is not its resolved one is listed by that name too, which is
    ``<value>`` as well."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
        S3Reporter,
    )
    from automated_security_helper.utils.log import (
        ASH_LOGGER,
        LogFileHandler,
        TextFileFormatter,
    )

    settings, start = _IN_TREE_SETTINGS[setting]
    checkout = tmp_path / "checkout"
    mark_git_checkout(checkout)
    if root_from == "discovered":
        root = _in_tree_chain(checkout, ".ash/.ash.yaml", settings, layout, monkeypatch)
    else:
        root = _in_tree_chain(
            checkout, "chosen-by-ash-config.yaml", settings, layout, monkeypatch
        )
        monkeypatch.setenv("ASH_CONFIG", str(root))
    # The operator's own file, outside the tree, sets the option the in-tree
    # file changes, so the option alone differs from the operator's section.
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        "reporters:\n"
        "  aws-security-hub:\n"
        "    options:\n"
        "      archive_resolved_findings: false\n",
        encoding="utf-8",
    )
    records: List[logging.LogRecord] = []

    class _Keep(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    log = tmp_path / "ash.log"
    log_file = LogFileHandler(log.as_posix())
    log_file.setLevel(logging.WARNING)
    log_file.setFormatter(TextFileFormatter(fmt="%(levelname)s\t%(message)s"))
    handlers = [_Keep(level=logging.WARNING), log_file]
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(logging.WARNING)
    for handler in handlers:
        ASH_LOGGER.addHandler(handler)
    try:
        config = resolve_config(source_dir=checkout, trusted_config_path=operator)
        reporter_section(config, S3Reporter)
    finally:
        for handler in handlers:
            ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)
        log_file.close()
    messages = [record.getMessage() for record in records]
    warning = [message for message in messages if message.startswith(start)]
    assert len(warning) == 1, messages
    _assert_hidden("\n".join(messages))
    _assert_hidden(log.read_text(encoding="utf-8"))
    # base.yaml and deeper.yaml, by place, and base.yaml's other name when it has
    # one; the root, as written.
    named_too = 0 if layout == "plain" else 1
    assert warning[0].count(ENVIRONMENT_VALUE_SHOWN) == 2 + named_too, warning
    assert root.resolve().as_posix() in warning[0], warning


def test_the_short_value_and_the_split_entry_are_shown_by_place() -> None:
    from automated_security_helper.config import environment_record
    from automated_security_helper.config.plugin_module_trust import (
        shown_module_names,
    )

    assert environment_record.ENVIRONMENT_VALUE_SHOWN == ENVIRONMENT_VALUE_SHOWN
    shown = shown_module_names(
        [",".join(PAIR), SHORT, LITERAL_MODULE],
        [ENVIRONMENT_VALUE_SHOWN, ENVIRONMENT_VALUE_SHOWN, LITERAL_MODULE],
    )
    assert shown == {
        PAIR[0]: ENVIRONMENT_VALUE_SHOWN,
        PAIR[1]: ENVIRONMENT_VALUE_SHOWN,
        SHORT: ENVIRONMENT_VALUE_SHOWN,
        LITERAL_MODULE: LITERAL_MODULE,
    }


def test_a_link_loop_beside_a_file_the_environment_chose_is_named_by_place(
    tmp_path: Path,
) -> None:
    """A name that resolves to no file (a link to itself) could name the file
    the environment chose, so it is shown as `<value>`, on every Python
    version: Path.resolve() raises on a loop on some and returns the name
    unresolved on others."""
    from automated_security_helper.config.sandbox_grants import described

    chosen = tmp_path / "chosen.yaml"
    chosen.write_text("project_name: probe\n", encoding="utf-8")
    loop = tmp_path / "loop.yaml"
    try:
        loop.symlink_to(loop.name)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"symlinks unavailable: {error}")

    shown = described([loop, chosen], [chosen.resolve()])

    assert shown == f"{ENVIRONMENT_VALUE_SHOWN}, {ENVIRONMENT_VALUE_SHOWN}", shown
    assert "loop.yaml" not in shown


def test_an_invalid_policy_regex_checked_without_its_config_gives_the_position_only() -> (
    None
):
    """Checked with no record of where the policy's entries came from, a regex
    could have any part read from the environment: the refusal gives re.error's
    type and position, not its reason, which quotes a part of the pattern."""
    from automated_security_helper.config.ash_config import RuntimeOverridesConfig
    from automated_security_helper.config.runtime_patch import (
        RuntimePatchDeniedError,
        _check_value_pattern,
        known_plugin_keys,
    )

    policy = RuntimeOverridesConfig(
        enabled=True,
        allowed_paths=["/**"],
        denied_value_patterns={"/project_name": "(?P=probecanarygroup)"},
    )
    op = {"op": "replace", "path": "/project_name", "value": "x"}

    with pytest.raises(RuntimePatchDeniedError) as raised:
        # The plugin keys check_runtime_ops computes for a caller with no config.
        _check_value_pattern(
            op, allowlist=policy, plugin_keys=known_plugin_keys(None), names=None
        )

    refusal = str(raised.value)
    assert "re.error at position" in refusal, refusal
    assert "probecanarygroup" not in refusal, refusal


def test_a_match_refusal_without_its_config_names_no_part_of_the_policy() -> None:
    """The same rule for a value that matches: with no record of where the
    policy's entries came from, the refusal names the regex and its key as
    `<value>`, and quotes neither. The op's own path is the client's text and
    stays."""
    from automated_security_helper.config.ash_config import RuntimeOverridesConfig
    from automated_security_helper.config.runtime_patch import (
        RuntimePatchDeniedError,
        _check_value_pattern,
        known_plugin_keys,
    )

    policy = RuntimeOverridesConfig(
        enabled=True,
        allowed_paths=["/**"],
        denied_value_patterns={"/project_name": "probecanaryzq[0-9]+"},
    )
    op = {"op": "replace", "path": "/project_name", "value": "probecanaryzq7"}

    with pytest.raises(RuntimePatchDeniedError) as raised:
        # The plugin keys check_runtime_ops computes for a caller with no config.
        _check_value_pattern(
            op, allowlist=policy, plugin_keys=known_plugin_keys(None), names=None
        )

    refusal = str(raised.value)
    assert "probecanaryzq" not in refusal, refusal
    assert f"regex '{ENVIRONMENT_VALUE_SHOWN}'" in refusal, refusal
    assert f"bound to '{ENVIRONMENT_VALUE_SHOWN}'" in refusal, refusal
    assert "'/project_name'" in refusal, refusal


def test_a_denied_path_refusal_without_its_config_names_no_entry() -> None:
    """A denied_paths refusal checked with no record of where the entry came
    from names the entry as `<value>`: the entry can be a value the policy's
    file read from the environment, and the refusal goes to the client."""
    from automated_security_helper.config.ash_config import RuntimeOverridesConfig
    from automated_security_helper.config.runtime_patch import (
        RuntimePatchDeniedError,
        _check_op_paths,
        known_plugin_keys,
    )

    policy = RuntimeOverridesConfig(
        enabled=True,
        allowed_paths=["/**"],
        denied_paths=["/probecanary*"],
    )
    op = {"op": "replace", "path": "/probecanarysection", "value": "x"}

    with pytest.raises(RuntimePatchDeniedError) as raised:
        # The plugin keys check_runtime_ops computes for config=None.
        _check_op_paths(
            op,
            allowlist=policy,
            plugin_keys=known_plugin_keys(None),
            config=None,
            names=None,
        )

    refusal = str(raised.value)
    assert "probecanary*" not in refusal, refusal
    assert f"entry '{ENVIRONMENT_VALUE_SHOWN}'" in refusal, refusal
    assert "'/probecanarysection'" in refusal, refusal


def test_check_runtime_ops_requires_a_config_argument() -> None:
    """``config`` has no default: a caller that has none says ``config=None``.

    Leaving ``config`` out used to select the degraded mode silently, and a
    refusal then named every policy entry ``<value>`` (the cells above), which
    an operator cannot act on. Every production caller has a config, so the
    degraded mode is only ever a deliberate choice."""
    from automated_security_helper.config.ash_config import RuntimeOverridesConfig
    from automated_security_helper.config.runtime_patch import check_runtime_ops

    policy = RuntimeOverridesConfig(enabled=True, allowed_paths=["/**"])

    with pytest.raises(TypeError, match="config"):
        check_runtime_ops([], allowlist=policy)


@pytest.mark.parametrize(
    ("helper", "given", "missing"),
    [
        pytest.param(
            "_check_op_paths", {"names": None}, "config", id="op-paths-without-config"
        ),
        pytest.param(
            "_check_op_paths", {"config": None}, "names", id="op-paths-without-names"
        ),
        pytest.param(
            "_check_value_pattern", {}, "names", id="value-pattern-without-names"
        ),
    ],
)
def test_the_checks_of_each_op_require_their_config_and_names(
    helper: str, given: Dict[str, Any], missing: str
) -> None:
    """The same for the two checks check_runtime_ops runs on each op: ``config``
    and ``names`` have no default either. Left out, they used to select the
    degraded mode silently, naming every policy entry ``<value>`` and, with no
    config, dropping the exemption for an op that turns an off-host reporter
    off."""
    from automated_security_helper.config import runtime_patch
    from automated_security_helper.config.ash_config import RuntimeOverridesConfig

    policy = RuntimeOverridesConfig(enabled=True, allowed_paths=["/**"])
    op = {"op": "replace", "path": "/project_name", "value": "x"}

    with pytest.raises(TypeError, match=missing):
        getattr(runtime_patch, helper)(op, allowlist=policy, **given)


def test_a_denied_path_refusal_without_a_config_names_a_shipped_default_entry() -> None:
    """A ``denied_paths`` entry equal to one of ``RuntimeOverridesConfig()``'s own
    defaults is the shipped policy's text, published in the docs and the schema,
    so naming it can reveal nothing: even checked with no config, the refusal
    names it as written. An entry the operator added stays ``<value>`` there
    (the cell above)."""
    from automated_security_helper.config.ash_config import RuntimeOverridesConfig
    from automated_security_helper.config.runtime_patch import (
        RuntimePatchDeniedError,
        check_runtime_ops,
    )

    policy = RuntimeOverridesConfig(enabled=True, allowed_paths=["/**"])
    assert "/fail_on_findings" in policy.denied_paths
    op = {"op": "replace", "path": "/fail_on_findings", "value": False}

    with pytest.raises(RuntimePatchDeniedError) as raised:
        check_runtime_ops([op], allowlist=policy, config=None)

    refusal = str(raised.value)
    assert "entry '/fail_on_findings'" in refusal, refusal
    assert f"entry '{ENVIRONMENT_VALUE_SHOWN}'" not in refusal, refusal


@pytest.mark.parametrize(
    "with_config", [False, True], ids=["without-its-config", "with-its-config"]
)
def test_a_shipped_default_entry_read_from_the_environment_is_named_in_both_modes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, with_config: bool
) -> None:
    """A ``denied_paths`` entry the environment gives that equals one of the
    shipped defaults is the shipped policy's text, published in the docs and the
    schema, in either mode: checked with the config that records it came from
    the environment, it is named as written, as it is checked without one. The
    mode that knows less names it no differently."""
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )
    from automated_security_helper.config.runtime_patch import (
        RuntimePatchDeniedError,
        check_runtime_ops,
    )

    monkeypatch.setenv("ASH_PROBE_DEFAULT_ENTRY", "/fail_on_findings")
    profile = tmp_path / "profile.yaml"
    profile.write_text(
        "project_name: probe\n"
        "global_settings:\n"
        "  mcp:\n"
        "    runtime_overrides:\n"
        "      enabled: true\n"
        "      allowed_paths: ['/**']\n"
        "      denied_paths:\n"
        "        - ${ASH_PROBE_DEFAULT_ENTRY}\n",
        encoding="utf-8",
    )
    config = load_config_file_for_run(profile)[1]
    assert config.global_settings.mcp is not None
    policy = config.global_settings.mcp.runtime_overrides
    assert policy.denied_paths == ["/fail_on_findings"]
    op = {"op": "replace", "path": "/fail_on_findings", "value": False}

    with pytest.raises(RuntimePatchDeniedError) as raised:
        check_runtime_ops(
            [op], allowlist=policy, config=config if with_config else None
        )

    refusal = str(raised.value)
    assert "entry '/fail_on_findings'" in refusal, refusal
    assert f"entry '{ENVIRONMENT_VALUE_SHOWN}'" not in refusal, refusal
