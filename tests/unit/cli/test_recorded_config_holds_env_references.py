# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What ASH writes of a configuration holds each value its files read from the
environment as the file wrote it, never the value.

A scan records its configuration in its results file, and ``ash merge`` and
``ash report`` read that record instead of the configuration's files. The
scan's config here reads a canary from the environment as a plain ``${VAR}``,
as ``!ENV ${VAR}``, as ``${VAR:default}`` with the variable set, and as a key
under ``scanners``. The canary is in the environment of every command, as it
would be for a collector holding the same secrets, and is asserted to appear in
no results file, no recorded configuration, and nothing a command prints or logs
(``ash scan --debug``, ``ash merge --debug``, ``ash report --debug``). The
record holds each reference as written instead.

The same config reads ``severity_threshold``, a fixed-choice field that cannot
hold a reference, from the environment: ``ash merge`` and ``ash report`` refuse
it (exit 3, naming the field and the reference) unless the operator supplies it.

Also covered: a reference whose variable is unset records the default the file
wrote, or null; an environment value equal to another field's value leaves that
field alone; a relative path the load anchored has only its environment part
replaced; a ``patch`` value, a base's value and a TOML value are recorded as
written; and the other writers of a resolved config (MCP ``get_config``,
``ash config get``, and the profile file the MCP server writes for a session)
hold the reference, while the config they load back still reads the value; and
``ash config update`` refuses a file with references rather than rewrite each
with its value.

The positive controls: the scan's in-run report, rendered from the live
config, holds the canary, so the scan did read the values; and each recorded
reference is asserted where the value would otherwise be.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Tuple

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

CANARY = "ash-canary-5b1d-9876543210"
SHARD_CONFIG = (
    "project_name: ${ASH_PROBE_CANARY}\n"
    "global_settings:\n"
    "  severity_threshold: ${ASH_PROBE_SEV}\n"
    "reporters:\n"
    "  gitlab-cyclonedx:\n"
    "    options:\n"
    "      language_override: !ENV ${ASH_PROBE_CANARY}\n"
    "      package_manager_override: ${ASH_PROBE_CANARY:fallback}\n"
    "scanners:\n"
    "  ${ASH_PROBE_CANARY}:\n"
    "    enabled: false\n"
)
DEFAULTS_CONFIG = (
    "project_name: probe-defaults\n"
    "global_settings:\n"
    "  severity_threshold: ${ASH_PROBE_UNSET:LOW}\n"
    "reporters:\n"
    "  gitlab-cyclonedx:\n"
    "    options:\n"
    "      package_manager_override: ${ASH_PROBE_UNSET:None}\n"
)
#: An override's value is the operator's, not the environment's, but it can be
#: a credential, so no debug line prints it either.
OVERRIDE_VALUE = "override-canary-31d7"
SEVERITY_OVERRIDE = [
    "--config-overrides",
    "global_settings.severity_threshold=MEDIUM",
    "--config-overrides",
    f"reporters.gitlab-cyclonedx.options.category={OVERRIDE_VALUE}",
]
SHOWN_SECTION = "Found config for reporter plugin gitlab-cyclonedx"
ENV = {
    "ASH_PROBE_CANARY": CANARY,
    "ASH_PROBE_SEV": "MEDIUM",
}


def _log_files(directory: Path) -> List[Path]:
    return sorted(
        path
        for path in directory.rglob("*")
        if path.is_file() and path.name.endswith((".log", ".log.jsonl"))
    )


def _scan_args(debug: bool) -> List[str]:
    return [
        "scan",
        "--no-progress",
        "--source-dir",
        "src",
        "--output-dir",
        "shard",
        "--scanners",
        "detect-secrets",
        "--no-fail-on-incomplete-scanners",
        "--shard-index",
        "0",
        "--shard-count",
        "1",
        *(["--debug"] if debug else []),
    ]


def _tree(root: Path, config: str) -> Path:
    (root / "src" / ".ash").mkdir(parents=True)
    (root / "src" / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (root / "src" / ".ash" / ".ash.yaml").write_text(config, encoding="utf-8")
    return root


def _logging_is_on() -> List[str]:
    """Turn ASH's logging back on if something earlier on this worker turned it off.

    ``logging.config.dictConfig`` with its default ``disable_existing_loggers``
    sets ``disabled`` on every logger that exists, and libraries call it when they
    are imported (tests/conftest.py, ``_restore_ash_logger_switches``). That
    fixture restores the switches after each test, but this module's ``runs`` is
    module scoped, so it runs outside that protection, and a disabled ``ash``
    logger drops every record before a handler sees it: the scan and the merge
    still succeed, nothing is printed or logged, and the checks that the canary is
    in no output pass without reading anything. A run here is only evidence if it
    could have logged. Returns what it had to turn back on, for the failure
    message of the check that the debug lines were written.
    """
    turned_on = []
    if logging.root.manager.disable:
        turned_on.append(f"logging.disable({logging.root.manager.disable})")
    logging.disable(logging.NOTSET)
    for name, logger in list(logging.root.manager.loggerDict.items()):
        if isinstance(logger, logging.Logger) and (
            name == "ash" or name.startswith(("ash.", "automated_security_helper"))
        ):
            if logger.disabled:
                turned_on.append(name)
            logger.disabled = False
    return turned_on


class _EnabledRunner(CliRunner):
    """A CliRunner that makes sure ASH's logging is on before each command."""

    turned_on: List[str]

    def invoke(self, *args, **kwargs):
        self.turned_on = [*getattr(self, "turned_on", []), *_logging_is_on()]
        return super().invoke(*args, **kwargs)


@pytest.fixture(scope="module")
def runs(tmp_path_factory: pytest.TempPathFactory):
    """One shard scan of each config, then ash merge and ash report over the first.

    The logger writes the JSONL log as well as ash.log in every run.
    """
    from automated_security_helper.utils import log

    root = _tree(tmp_path_factory.mktemp("env-record"), SHARD_CONFIG)
    defaults_root = _tree(tmp_path_factory.mktemp("env-defaults"), DEFAULTS_CONFIG)
    operator = root / "operator.yaml"
    operator.write_text("global_settings:\n  severity_threshold: MEDIUM\n", "utf-8")
    get_logger = log.get_logger

    def both(*args, **kwargs):
        kwargs["log_format"] = "BOTH"
        return get_logger(*args, **kwargs)

    runner = _EnabledRunner()
    found: Dict[str, object] = {"root": root, "defaults_root": defaults_root}
    with pytest.MonkeyPatch.context() as mp:
        for name, value in ENV.items():
            mp.setenv(name, value)
        mp.delenv("ASH_PROBE_UNSET", raising=False)
        mp.delenv("ASH_CONFIG", raising=False)
        mp.setattr(log, "get_logger", both)
        env = {"COLUMNS": "300"}
        mp.chdir(defaults_root)
        found["defaults_scan"] = runner.invoke(app, _scan_args(False), env=env)
        found["defaults_merge"] = runner.invoke(
            app,
            [
                "merge",
                "--results",
                str(defaults_root / "shard" / "ash_aggregated_results.json"),
                "--output-dir",
                "merged",
            ],
            env=env,
        )
        mp.chdir(root)
        found["scan"] = runner.invoke(app, _scan_args(True), env=env)
        shard_results = str(root / "shard" / "ash_aggregated_results.json")

        def merge(output: str, *extra: str):
            return runner.invoke(
                app,
                ["merge", "--results", shard_results, "--output-dir", output]
                + ["--debug", *extra],
                env=env,
            )

        def report(*extra: str):
            return runner.invoke(
                app,
                ["report", "--format", "gitlab-cyclonedx"]
                + ["--output-dir", str(root / "shard"), "--debug", *extra],
                env=env,
            )

        found["merge_refused"] = merge("merged-refused")
        found["merge"] = merge("merged", *SEVERITY_OVERRIDE)
        found["merge_config"] = merge("merged-config", "--config", str(operator))
        found["report_refused"] = report()
        found["report"] = report(*SEVERITY_OVERRIDE)
    found["logging turned back on"] = runner.turned_on
    return found


def _results(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _gitlab_options(config: dict) -> dict:
    reporters = config["reporters"]
    section = reporters.get("gitlab-cyclonedx") or reporters["gitlab_cyclonedx"]
    return section["options"]


def _channels(runs, command: str, directory: Path) -> Dict[str, str]:
    result = runs[command]
    return {
        f"{command} stdout": result.stdout,
        f"{command} stderr": result.stderr,
        **{
            f"{command} {path.relative_to(runs['root']).as_posix()}": path.read_text(
                encoding="utf-8", errors="replace"
            )
            for path in _log_files(directory)
        },
    }


def test_the_scan_ran_with_the_values(runs):
    """The control for every test here: the scan wrote its results, and its
    in-run report, rendered from the live config, holds the value it read."""
    assert runs["scan"].exit_code == 0, runs["scan"].output
    shard = runs["root"] / "shard"
    assert (shard / "ash_aggregated_results.json").is_file()
    assert CANARY in (shard / "reports" / "ash.html").read_text(encoding="utf-8")


def test_the_shard_records_each_reference_as_written(runs):
    data = _results(runs["root"] / "shard" / "ash_aggregated_results.json")
    config = data["ash_config"]
    assert config["project_name"] == "${ASH_PROBE_CANARY}"
    assert config["global_settings"]["severity_threshold"] == "${ASH_PROBE_SEV}"
    options = _gitlab_options(config)
    assert options["language_override"] == "!ENV ${ASH_PROBE_CANARY}"
    assert options["package_manager_override"] == "${ASH_PROBE_CANARY:fallback}"
    assert "${ASH_PROBE_CANARY}" in config["scanners"]
    # The section is disabled and still listed: the roster is what the
    # configuration declares, and the record holds the key as the file wrote it,
    # not as the environment resolved it.
    expected = data["metadata"]["expected_scanners"]
    assert "${ASH_PROBE_CANARY}" in expected
    assert CANARY not in expected


def test_the_results_files_hold_no_env_value(runs):
    root = runs["root"]
    files = [
        root / "shard" / "ash_aggregated_results.json",
        root / "merged" / "ash_aggregated_results.json",
        root / "merged-config" / "ash_aggregated_results.json",
    ]
    # The control: each merge that was given the field wrote its results.
    assert all(path.is_file() for path in files), files
    leaked = [
        path.relative_to(root).as_posix()
        for path in files
        if CANARY in path.read_text(encoding="utf-8")
    ]
    assert leaked == [], leaked


def test_the_merged_record_holds_the_references_and_the_supplied_field(runs):
    assert runs["merge"].exit_code == 0, runs["merge"].output
    config = _results(runs["root"] / "merged" / "ash_aggregated_results.json")[
        "ash_config"
    ]
    assert config["project_name"] == "${ASH_PROBE_CANARY}"
    assert config["global_settings"]["severity_threshold"] == "MEDIUM"
    assert _gitlab_options(config)["language_override"] == "!ENV ${ASH_PROBE_CANARY}"


def test_a_free_string_reference_loads_back_as_written(runs):
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    path = runs["root"] / "shard" / "ash_aggregated_results.json"
    model = AshAggregatedResults.model_validate_json(path.read_text(encoding="utf-8"))
    assert model.ash_config is not None
    assert model.ash_config.project_name == "${ASH_PROBE_CANARY}"
    assert [field for field, _ in model.ash_config._unreadable_references] == [
        "global_settings.severity_threshold"
    ]


@pytest.mark.parametrize("command", ["merge_refused", "report_refused"])
def test_a_field_that_cannot_hold_the_reference_is_refused(runs, command):
    result = runs[command]
    assert result.exit_code == 3, result.output
    output = " ".join(result.output.split())
    assert "global_settings.severity_threshold" in output, output
    assert "${ASH_PROBE_SEV}" in output, output
    assert "global_settings.severity_threshold=<value>" in output, output


@pytest.mark.parametrize("command", ["merge", "merge_config", "report"])
def test_the_operator_supplies_the_field(runs, command):
    result = runs[command]
    assert result.exit_code == 0, result.output


@pytest.mark.parametrize(
    "command, directory",
    [
        ("scan", "shard"),
        ("merge", "merged"),
        ("merge_refused", "merged-refused"),
        ("merge_config", "merged-config"),
        ("report", "shard/reports"),
        ("report_refused", "shard/reports"),
    ],
)
def test_no_output_holds_an_env_value(runs, command, directory):
    channels = _channels(runs, command, runs["root"] / directory)
    leaked = [name for name, text in channels.items() if CANARY in text]
    assert leaked == [], leaked


def _report_document(stdout: str) -> Tuple[dict, str]:
    """The JSON document ``ash report`` writes to stdout when no output file is
    asked for, and the rest of stdout around it.

    The document may be printed on one line or pretty-printed over many: it runs
    from the first line that opens an object to the last line that closes one,
    and a log line printed before it starts with its level, not with a brace."""
    lines = stdout.splitlines(keepends=True)
    opens = [index for index, line in enumerate(lines) if line.lstrip().startswith("{")]
    closes = [index for index, line in enumerate(lines) if line.rstrip().endswith("}")]
    assert opens and closes, stdout
    first, last = opens[0], closes[-1]
    document = json.loads("".join(lines[first : last + 1]))
    return document, "".join(lines[:first] + lines[last + 1 :])


@pytest.mark.parametrize(
    "command, directory", [("merge", "merged"), ("report", "shard/reports")]
)
def test_no_output_holds_an_override_value(runs, command, directory):
    channels = _channels(runs, command, runs["root"] / directory)
    if command == "report":
        # The report command prints the gitlab-cyclonedx document itself on
        # stdout, and the document carries the reporter's category option as
        # the GitLab property it is required to write, an empty inventory
        # included. The override's value may stand there, once, and nowhere
        # else on stdout.
        document, rest = _report_document(channels.pop("report stdout"))
        channels["report stdout outside the document"] = rest
        holders = [
            entry
            for entry in document["metadata"]["properties"]
            if OVERRIDE_VALUE in str(entry.get("value", ""))
        ]
        assert holders == [
            {"name": "gitlab:dependency_scanning:category", "value": OVERRIDE_VALUE}
        ], holders
        assert json.dumps(document).count(OVERRIDE_VALUE) == 1
    leaked = [name for name, text in channels.items() if OVERRIDE_VALUE in text]
    assert leaked == [], leaked
    # The control: the merge applied the override, so its value was there to
    # print.
    if command == "merge":
        merged = _results(runs["root"] / "merged" / "ash_aggregated_results.json")
        assert _gitlab_options(merged["ash_config"])["category"] == OVERRIDE_VALUE


@pytest.mark.parametrize(
    "command, directory",
    [("scan", "shard"), ("merge", "merged"), ("report", "shard/reports")],
)
def test_the_debug_line_showing_a_section_is_written(runs, command, directory):
    """The control for the test above: the line that shows a reporter's section,
    built from the config, is among what was checked."""
    channels = _channels(runs, command, runs["root"] / directory)
    assert any(SHOWN_SECTION in text for text in channels.values()), {
        "characters per channel": {n: len(t) for n, t in channels.items()},
        "logging turned back on before a run": runs["logging turned back on"],
    }


def test_the_scan_logs_were_written(runs):
    """The control for the scan's channels: both of its log files exist."""
    names = {path.name for path in _log_files(runs["root"] / "shard")}
    assert {"ash.log", "ash.log.jsonl"} <= names, names


def test_an_unset_reference_records_its_default_and_merge_reads_it(runs):
    assert runs["defaults_scan"].exit_code == 0, runs["defaults_scan"].output
    root = runs["defaults_root"]
    shard = _results(root / "shard" / "ash_aggregated_results.json")["ash_config"]
    assert shard["global_settings"]["severity_threshold"] == "LOW"
    assert _gitlab_options(shard)["package_manager_override"] is None
    assert runs["defaults_merge"].exit_code == 0, runs["defaults_merge"].output
    merged = _results(root / "merged" / "ash_aggregated_results.json")["ash_config"]
    assert merged["global_settings"]["severity_threshold"] == "LOW"


# ---------------------------------------------------------------------------
# Where in the record: the reference's own position
# ---------------------------------------------------------------------------


def _recorded(config) -> dict:
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    return json.loads(
        AshAggregatedResults(ash_config=config).model_dump_json(by_alias=True)
    )["ash_config"]


@pytest.fixture
def probe_env(monkeypatch):
    monkeypatch.setenv("ASH_PROBE_CANARY", CANARY)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    return monkeypatch


def _operator_config(tmp_path: Path, text: str, name: str = "operator.yaml") -> Path:
    (tmp_path / "op").mkdir(exist_ok=True)
    (tmp_path / "tree").mkdir(exist_ok=True)
    path = tmp_path / "op" / name
    path.write_text(text, encoding="utf-8")
    return path


def test_an_equal_value_in_an_unrelated_field_is_left_alone(tmp_path, probe_env):
    from automated_security_helper.config.resolve_config import resolve_config

    probe_env.setenv("ASH_PROBE_SAME", "production")
    path = _operator_config(
        tmp_path,
        "project_name: ${ASH_PROBE_SAME}\n"
        "reporters:\n"
        "  gitlab-cyclonedx:\n"
        "    options:\n"
        "      category: production\n",
    )
    config = resolve_config(config_path=path, source_dir=tmp_path / "tree")
    assert config.project_name == "production"
    recorded = _recorded(config)
    assert recorded["project_name"] == "${ASH_PROBE_SAME}"
    assert _gitlab_options(recorded)["category"] == "production"


def test_an_anchored_path_has_only_its_env_part_replaced(tmp_path, probe_env):
    from automated_security_helper.config.resolve_config import resolve_config

    probe_env.setenv("ASH_PROBE_RELATIVE", "cfg/bandit.yaml")
    path = _operator_config(
        tmp_path,
        "scanners:\n  bandit:\n    options:\n      config_file: ${ASH_PROBE_RELATIVE}\n",
    )
    config = resolve_config(config_path=path, source_dir=tmp_path / "tree")
    directory = path.parent.resolve()
    # The control: the load took the relative path from the file's directory.
    assert (
        Path(str(config.scanners.bandit.options.config_file))
        == directory / "cfg" / "bandit.yaml"
    )
    # The path is a Path once configured, so its prefix is written with this
    # platform's separators (backslashes on Windows) and only the part the
    # environment gave is put back.
    recorded = _recorded(config)["scanners"]["bandit"]["options"]["config_file"]
    assert recorded == f"{directory}{os.sep}${{ASH_PROBE_RELATIVE}}"


def test_a_patch_value_and_a_base_value_are_recorded_as_written(tmp_path, probe_env):
    from automated_security_helper.config.resolve_config import resolve_config

    _operator_config(tmp_path, "project_name: ${ASH_PROBE_CANARY}\n", "base.yaml")
    path = _operator_config(
        tmp_path,
        "extends: base.yaml\n"
        "patch:\n"
        "  - op: add\n"
        "    path: /reporters\n"
        "    value:\n"
        "      gitlab-cyclonedx:\n"
        "        options:\n"
        "          language_override: ${ASH_PROBE_CANARY}\n",
    )
    config = resolve_config(config_path=path, source_dir=tmp_path / "tree")
    assert config.project_name == CANARY
    assert config.reporters.gitlab_cyclonedx.options.language_override == CANARY
    recorded = _recorded(config)
    assert CANARY not in json.dumps(recorded)
    assert recorded["project_name"] == "${ASH_PROBE_CANARY}"
    assert _gitlab_options(recorded)["language_override"] == "${ASH_PROBE_CANARY}"


@pytest.mark.parametrize(
    "base_key, child_key",
    [("cloudwatch-logs", "cloudwatch_logs"), ("cloudwatch_logs", "cloudwatch-logs")],
)
def test_a_base_value_under_another_spelling_of_its_section_is_recorded(
    tmp_path, probe_env, base_key, child_key
):
    """A base reads a reporter's option from the environment under one spelling
    of the reporter's key, and the file extending it sets another option under
    the other spelling. The value is in neither the record nor the body an
    off-host reporter sends (to_simple_dict), and the record holds the
    reference where the merged config holds the option."""
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    _operator_config(
        tmp_path,
        f"reporters:\n  {base_key}:\n    options:\n"
        "      log_group_name: ${ASH_PROBE_CANARY}\n",
        "base.yaml",
    )
    path = _operator_config(
        tmp_path,
        "extends: base.yaml\n"
        f"reporters:\n  {child_key}:\n    options:\n      aws_region: us-east-1\n",
    )
    config = resolve_config(config_path=path, source_dir=tmp_path / "tree")
    live = json.dumps(config.model_dump(by_alias=True))
    # The control: the merged config holds the value the base read.
    assert CANARY in live
    recorded = _recorded(config)
    assert CANARY not in json.dumps(recorded), recorded
    sections = [
        section
        for key, section in recorded["reporters"].items()
        if key.replace("-", "_") == "cloudwatch_logs"
    ]
    assert [s["options"]["log_group_name"] for s in sections] == [
        "${ASH_PROBE_CANARY}"
    ], sections
    body = AshAggregatedResults(ash_config=config).to_simple_dict()
    assert CANARY not in json.dumps(body, default=str)


def test_a_toml_value_is_recorded_as_written(tmp_path, probe_env):
    from automated_security_helper.config.resolve_config import resolve_config

    path = _operator_config(
        tmp_path, 'project_name = "${ASH_PROBE_CANARY}"\n', ".ashrc.toml"
    )
    config = resolve_config(config_path=path, source_dir=tmp_path / "tree")
    assert config.project_name == CANARY
    assert _recorded(config)["project_name"] == "${ASH_PROBE_CANARY}"


# ---------------------------------------------------------------------------
# The other writers of a resolved config
# ---------------------------------------------------------------------------


def _as_written(text: str) -> dict:
    """``text``, a YAML config, with each reference as written, tag included."""
    import io

    from automated_security_helper.config.ash_config import load_yaml_config

    return load_yaml_config(io.StringIO(text), env="written")


READING_CONFIG = (
    "project_name: !ENV ${ASH_PROBE_CANARY}\n"
    "reporters:\n"
    "  gitlab-cyclonedx:\n"
    "    options:\n"
    "      language_override: ${ASH_PROBE_CANARY}\n"
)


def test_mcp_get_config_marks_each_value_read(tmp_path, probe_env):
    """A view, not a record: each value read is `<from ${VAR}>`, told apart from
    a reference left as written."""
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    path = _operator_config(tmp_path, READING_CONFIG)
    resolved = mcp_get_config(config_path=str(path))
    assert CANARY not in json.dumps(resolved), resolved
    assert resolved["project_name"] == "<from ${ASH_PROBE_CANARY}>"
    assert (
        _gitlab_options(resolved)["language_override"] == "<from ${ASH_PROBE_CANARY}>"
    )


def test_mcp_get_config_raw_shows_a_toml_reference(tmp_path, probe_env):
    from automated_security_helper.cli.mcp_tools import mcp_get_config

    path = _operator_config(
        tmp_path, 'project_name = "${ASH_PROBE_CANARY}"\n', ".ashrc.toml"
    )
    raw = mcp_get_config(config_path=str(path), raw=True)
    assert raw == {"project_name": "!ENV ${ASH_PROBE_CANARY}"}, raw


def test_ash_config_get_shows_the_reference(tmp_path, probe_env):
    path = _operator_config(tmp_path, READING_CONFIG)
    result = CliRunner().invoke(
        app, ["config", "get", str(path)], env={"COLUMNS": "300"}
    )
    assert result.exit_code == 0, result.output
    assert CANARY not in result.output
    assert "${ASH_PROBE_CANARY}" in result.output


def test_ash_config_update_refuses_a_file_with_references(tmp_path, probe_env):
    """``ash config update`` writes the whole resolved config back, which would
    replace each reference with its value, so a file with environment references
    is refused with exit 1 and left as written (cli/config.py, _rewrite_refusal);
    the refusal names no value, and the file still reads the values."""
    from automated_security_helper.config.ash_config import AshConfig

    path = _operator_config(tmp_path, READING_CONFIG)
    before = path.read_bytes()
    result = CliRunner().invoke(
        app,
        ["config", "update", str(path), "--set", "fail_on_findings=false"],
        env={"COLUMNS": "300"},
    )
    assert result.exit_code == 1, result.output
    assert CANARY not in result.output
    output = " ".join(result.output.split())
    assert "Cannot update" in output, output
    assert "environment references" in output, output
    assert "edit it by hand" in output, output
    assert path.read_bytes() == before
    as_written = _as_written(path.read_text(encoding="utf-8"))
    # The file is left exactly as written: the tagged reference keeps its tag and
    # the plain one stays plain.
    assert as_written["project_name"] == "!ENV ${ASH_PROBE_CANARY}"
    assert _gitlab_options(as_written)["language_override"] == "${ASH_PROBE_CANARY}"
    reloaded = AshConfig.from_file(path)
    assert reloaded.project_name == CANARY
    assert reloaded.reporters.gitlab_cyclonedx.options.language_override == CANARY
    # The --set was not applied: the field keeps its default.
    assert reloaded.fail_on_findings == AshConfig().fail_on_findings


def test_a_profile_session_copy_reads_the_value_at_load(tmp_path, probe_env):
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.config.resolve_config import (
        _load_single_config_file,
        resolve_config,
    )

    probe_env.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    probe_env.setenv("ASH_MCP_TRANSPORT", "stdio")
    profile = _operator_config(tmp_path, READING_CONFIG, "profile.ash.yaml")
    registry = profile_registry.register_profiles([f"probe={profile}"])
    written = Path(
        profile_registry.materialize_session_config(
            "session-env", registry["probe"].config
        )
    )
    text = written.read_text(encoding="utf-8")
    assert CANARY not in text
    assert _as_written(text)["project_name"] == "!ENV ${ASH_PROBE_CANARY}"
    # The scan still uses the value: the copy reads it when it is loaded.
    loaded = _load_single_config_file(written)
    assert loaded.project_name == CANARY
    assert loaded.reporters.gitlab_cyclonedx.options.language_override == CANARY
    # And a scan's record of it holds the reference.
    recorded = _recorded(resolve_config(config_path=written, source_dir=tmp_path))
    assert CANARY not in json.dumps(recorded)
    assert recorded["project_name"] == "!ENV ${ASH_PROBE_CANARY}"


PATCHABLE_PROFILE = (
    "project_name: patch-me\n"
    "global_settings:\n"
    "  mcp:\n"
    "    runtime_overrides:\n"
    "      enabled: true\n"
    "      allowed_paths:\n"
    "        - /project_name\n"
    "      denied_paths: []\n"
    "reporters:\n"
    "  gitlab-cyclonedx:\n"
    "    options:\n"
    "      language_override: !ENV ${ASH_PROBE_CANARY}\n"
)


def test_a_patched_profile_copy_holds_no_value_and_the_scan_reads_it(
    tmp_path, probe_env
):
    """The copy a client patched goes in client-config/, where !ENV is not
    resolved. It holds the reference as text, the scan fills it from the
    operator's copy, and no file under client-config/ holds the value."""
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.cli.mcp.sandbox import session_sandbox
    from automated_security_helper.cli.mcp_tools import mcp_select_profile
    from automated_security_helper.config.resolve_config import resolve_config

    probe_env.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    probe_env.setenv("ASH_MCP_TRANSPORT", "stdio")
    probe_env.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    probe_env.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()
    try:
        profile = _operator_config(tmp_path, PATCHABLE_PROFILE, "patch.ash.yaml")
        profile_registry.set_profile_registry(
            profile_registry.register_profiles([f"patchable={profile}"])
        )
        result = mcp_select_profile(
            "patchable",
            patch_ops=[{"op": "replace", "path": "/project_name", "value": "patched"}],
            session_id="session-env",
        )
        assert result["success"] is True, result
        client_copy = Path(profile_registry.resolve_session_config_path("session-env"))
        trusted = Path(
            profile_registry.resolve_session_trusted_config_path("session-env")
        )
        # The control: the client's copy is the one in client-config/.
        assert client_copy.parent == session_sandbox("session-env").client_config_dir
        files = [
            path
            for path in (tmp_path / "mcp-workspaces").rglob("*")
            if path.is_file() and "client-config" in path.parts
        ]
        assert client_copy in files, files
        leaked = [
            path.name for path in files if CANARY in path.read_text(encoding="utf-8")
        ]
        assert leaked == [], leaked

        config = resolve_config(
            config_path=client_copy,
            source_dir=tmp_path / "tree",
            trusted_config_path=trusted,
            untrusted_config=True,
        )
        # The scan uses the value, and the client's own change.
        assert config.project_name == "patched"
        assert config.reporters.gitlab_cyclonedx.options.language_override == CANARY
        recorded = _recorded(config)
        assert CANARY not in json.dumps(recorded)
        assert _gitlab_options(recorded)["language_override"] == (
            "!ENV ${ASH_PROBE_CANARY}"
        )
    finally:
        profile_registry.clear_profile_registry()
        profile_registry.clear_all_session_state()


def test_a_reference_the_client_writes_elsewhere_reads_nothing(tmp_path, probe_env):
    """Only the operator copy's own positions are filled: the same reference at
    another position stays text."""
    from automated_security_helper.config.environment_record import (
        environment_references,
        fill_environment_references,
    )

    written = {"a": "${ASH_PROBE_CANARY}"}
    references = environment_references(written, {"a": CANARY})
    filled = fill_environment_references(
        {"a": "${ASH_PROBE_CANARY}", "b": "${ASH_PROBE_CANARY}"}, references
    )
    assert filled == {"a": CANARY, "b": "${ASH_PROBE_CANARY}"}


def test_a_fill_reports_the_position_it_read_each_reference_at(tmp_path, probe_env):
    """The fill matches a list entry at any index, so a client that adds an
    entry ahead of one moves it. The positions the fill reports are the ones it
    read, so a record built from them names the entry that holds the value."""
    from automated_security_helper.config.environment_record import (
        environment_references,
        fill_environment_references,
    )

    references = environment_references(
        {"a": ["${ASH_PROBE_CANARY}"], "b": "!ENV ${ASH_PROBE_CANARY}"},
        {"a": [CANARY], "b": CANARY},
    )
    placed = []
    filled = fill_environment_references(
        {"a": ["the client's entry", "${ASH_PROBE_CANARY}"], "b": "changed"},
        references,
        placed=placed,
    )
    assert filled == {"a": ["the client's entry", CANARY], "b": "changed"}
    # Only the entry the fill read, at the index it is at now. The client's own
    # text at "b" was not a reference and is not reported.
    assert [reference.path for reference in placed] == [("a", 1)]
    assert placed[0].written == "${ASH_PROBE_CANARY}"
    assert placed[0].resolved == CANARY


def test_a_filled_reference_is_recorded_like_a_read_one(tmp_path, probe_env):
    """The record names each value by the rewrite its file's read gives. The
    references the fill read give the same rewrites and values, so a copy that
    holds the references as text is recorded as its operator's copy is."""
    from automated_security_helper.config.config_sources import (
        read_config_file_and_references,
    )
    from automated_security_helper.config.config_validator import (
        environment_record_of_references,
        environment_record_read,
    )

    path = _operator_config(tmp_path, READING_CONFIG)
    _, references = read_config_file_and_references(path)
    values, rewrites = environment_record_of_references(references)
    read_values, read_rewrites = environment_record_read([path], {})
    assert [(item.kind, item.written) for item in rewrites] == [
        ("value", "!ENV ${ASH_PROBE_CANARY}"),
        ("value", "${ASH_PROBE_CANARY}"),
    ]
    assert rewrites == read_rewrites
    assert values == read_values
    assert CANARY in values


def test_a_patch_error_names_no_value(tmp_path, probe_env):
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    _operator_config(tmp_path, "project_name: ${ASH_PROBE_CANARY}\n", "base.yaml")
    path = _operator_config(
        tmp_path,
        "extends: base.yaml\n"
        "patch:\n"
        "  - op: add\n"
        "    path: /reporters/missing/options/x\n"
        "    value: ${ASH_PROBE_CANARY}\n",
    )
    with pytest.raises(ASHConfigSourceError) as raised:
        resolve_config(config_path=path, source_dir=tmp_path / "tree")
    message = str(raised.value)
    assert CANARY not in message, message
    assert "add at '/reporters/missing/options/x'" in message, message
    assert raised.value.__cause__ is None


def test_a_scans_own_reports_show_the_value_and_its_record_the_reference(runs):
    """The in-run model is the live config, so a report the scan renders shows
    the project name it read, while the results file's ash_config and the body
    an off-host reporter sends hold the reference."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    shard = runs["root"] / "shard"
    assert CANARY in (shard / "reports" / "ash.html").read_text(encoding="utf-8")
    stored = _results(shard / "ash_aggregated_results.json")["ash_config"]
    assert stored["project_name"] == "${ASH_PROBE_CANARY}"
    body = AshAggregatedResults.model_validate_json(
        (shard / "ash_aggregated_results.json").read_text(encoding="utf-8")
    ).to_simple_dict()
    assert body["ash_config"]["project_name"] == "${ASH_PROBE_CANARY}"
    assert CANARY not in json.dumps(body, default=str)


def test_a_bedrock_model_read_from_the_environment_is_logged_as_its_reference(
    tmp_path, probe_env
):
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
        BedrockSummaryReporter,
    )

    path = _operator_config(
        tmp_path,
        "reporters:\n"
        "  bedrock-summary-reporter:\n"
        "    options:\n"
        "      model_id: ${ASH_PROBE_CANARY}\n",
    )
    config = resolve_config(config_path=path, source_dir=tmp_path / "tree")
    context = PluginContext(
        source_dir=tmp_path / "tree",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "work",
        config=config,
    )
    reporter = BedrockSummaryReporter(
        context=context,
        config=config.get_plugin_config("reporter", "bedrock-summary-reporter"),
    )
    # The control: the reporter uses the value it read.
    assert reporter.config.options.model_id == CANARY
    assert reporter._model_label(CANARY) == "${ASH_PROBE_CANARY}"
    assert reporter._model_label("a-fallback-model") == "a-fallback-model"
    client = reporter._make_model_client(object())
    assert client._model_id == CANARY
    assert client._model_label == "${ASH_PROBE_CANARY}"
