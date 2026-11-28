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
replaced, and one it folded a ``..`` or ``./`` out of is recorded as its
directory and the reference; a list the load made of one reference's text is
recorded as that reference; a ``patch`` value, a base's value and a TOML value
are recorded as written; and the other writers of a resolved config (MCP
``get_config``, ``ash config get``, and the profile file the MCP server writes
for a session) hold the reference, while the config they load back still reads
the value, except that a session copy refuses a profile whose relative path the
load folded; and ``ash config update`` refuses a file with references rather
than rewrite each with its value.

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
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (root / "src" / ".ash.yaml").write_text(config, encoding="utf-8")
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

    # Written with this platform's separator: the path is a Path once configured,
    # and on Windows a "/" in the environment's text comes back as "\", so the
    # text the environment gave is only found again when it is spelled that way.
    probe_env.setenv("ASH_PROBE_RELATIVE", os.path.join("cfg", "bandit.yaml"))
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


# ---------------------------------------------------------------------------
# A set member a file read from the environment
# ---------------------------------------------------------------------------

# The loader's own pairing walks mappings and lists, so a set member a file read
# from the environment has no reference, no rewrite and no redaction value of its
# own. Every load a run makes (load_config_file_for_run) describes it, so each
# writer that starts from such a configuration holds the reference and never the
# value. These cells guard:
#   - the load cell: the configuration's values hold the value, and the record of
#     its JSON-mode dump, the form every writer starts from, holds the reference
#     as a list of one entry and not the value.
#   - the session cell: a registered profile's copy, written by
#     materialize_session_config, holds the reference and not the value.
#   - the client's copy cell: the profile is the base a client's patch applies
#     to, and the copy written after an op elsewhere holds the reference too.
SET_MEMBER = "operator-set-member-read-from-the-environment"
SET_REFERENCE = "${ASH_TEST_SET_MEMBER}"
SET_PROFILE = (
    "project_name: set-profile\n"
    "global_settings:\n"
    "  mcp:\n"
    "    runtime_overrides:\n"
    "      enabled: true\n"
    "      allowed_paths:\n"
    "        - /project_name\n"
    "      denied_paths: []\n"
    "reporters:\n"
    "  aws-security-hub:\n"
    "    options:\n"
    "      custom_labels: !!set\n"
    "        ? ${ASH_TEST_SET_MEMBER}\n"
)


def _a_profile_with_a_set(tmp_path: Path, probe_env) -> Path:
    probe_env.setenv("ASH_TEST_SET_MEMBER", SET_MEMBER)
    probe_env.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    probe_env.setenv("ASH_MCP_TRANSPORT", "stdio")
    return _operator_config(tmp_path, SET_PROFILE, "set.ash.yaml")


def _security_hub_options(document: dict) -> dict:
    return document["reporters"]["aws-security-hub"]["options"]


def test_a_set_member_a_load_read_is_recorded_as_its_reference(tmp_path, probe_env):
    """The load of a file that writes ``custom_labels`` as a set with one member
    read from a variable: the configuration's values hold the value, so every
    message of a run redacts it, and the record of its JSON-mode dump holds the
    reference. The dump is read first (the control): it holds the value, so only
    a rewrite the load made puts the reference in its place."""
    from automated_security_helper.config.config_validator import record_of_config
    from automated_security_helper.config.config_writer import user_config_data
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )

    profile = _a_profile_with_a_set(tmp_path, probe_env)

    _document, config = load_config_file_for_run(profile)

    assert SET_MEMBER in config._environment_values, config._environment_values
    dumped = user_config_data(config)
    assert _security_hub_options(dumped)["custom_labels"] == [SET_MEMBER]
    recorded = record_of_config(config, dumped)
    assert _security_hub_options(recorded)["custom_labels"] == [SET_REFERENCE]
    assert SET_MEMBER not in json.dumps(recorded)


def test_a_registered_profiles_set_member_is_written_to_the_session_copy_by_its_reference(
    tmp_path, probe_env
):
    """The copy the MCP server writes into a session's sandbox for a registered
    profile whose file reads a set member from the environment holds the
    reference, and the text holds the value nowhere."""
    from automated_security_helper.cli.mcp import profile_registry

    profile = _a_profile_with_a_set(tmp_path, probe_env)
    registry = profile_registry.register_profiles([f"sets={profile}"])

    written = Path(
        profile_registry.materialize_session_config(
            "session-set", registry["sets"].config
        )
    )

    text = written.read_text(encoding="utf-8")
    assert SET_MEMBER not in text, text
    assert SET_REFERENCE in text, text


def test_a_patched_copy_of_a_profile_with_a_set_member_holds_its_reference(
    tmp_path, probe_env
):
    """The base a client's patch applies to is loaded as a run loads a file. An
    op elsewhere (the project's name) leaves the set alone, and the client's copy
    written from the patched configuration holds the reference, not the value."""
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.config.runtime_patch import apply_runtime_patch

    profile = _a_profile_with_a_set(tmp_path, probe_env)
    base = profile_registry.register_profiles([f"sets={profile}"])["sets"].config

    patched = apply_runtime_patch(
        base,
        [{"op": "replace", "path": "/project_name", "value": "patched"}],
        allowlist=base.global_settings.mcp.runtime_overrides,
    )
    written = Path(
        profile_registry.materialize_session_config(
            "session-set", patched, client_patched=True
        )
    )

    text = written.read_text(encoding="utf-8")
    assert patched.project_name == "patched"
    assert SET_MEMBER not in text, text
    assert SET_REFERENCE in text, text


# ---------------------------------------------------------------------------
# A later document of the chain writes a place a base read from the environment
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "held",
    [
        pytest.param("prod-7c1e", id="inside"),
        pytest.param("other-7c1e", id="control"),
    ],
)
def test_a_bases_reference_under_a_later_files_literal_is_not_recorded(
    tmp_path, probe_env, held
):
    """A base reads ``project_name`` from a variable and the file extending it
    writes ``acme-prod-7c1e``. The scan runs with the later file's text, so its
    record holds that text and no reference of the base: whatever the variable
    holds (``inside``: its value is part of the later text; ``control``: it is
    not), the record is the same."""
    from automated_security_helper.config.resolve_config import resolve_config

    probe_env.setenv("ASH_PROBE_PN", held)
    _operator_config(tmp_path, "project_name: ${ASH_PROBE_PN}\n", "base.yaml")
    path = _operator_config(
        tmp_path, "extends: base.yaml\nproject_name: acme-prod-7c1e\n"
    )

    config = resolve_config(config_path=path, source_dir=tmp_path / "tree")

    # The control: the scan holds the later file's text.
    assert config.project_name == "acme-prod-7c1e"
    assert _recorded(config)["project_name"] == "acme-prod-7c1e"


@pytest.mark.parametrize(
    "held",
    [
        pytest.param("prod-7c1e", id="inside"),
        pytest.param("other-7c1e", id="control"),
    ],
)
def test_a_replacing_override_of_a_value_read_from_the_environment_is_recorded_as_the_override(
    tmp_path, probe_env, held
):
    """A replacing ``--config-overrides`` sets ``project_name`` over a file that
    reads it from a variable. The scan runs with the override's text, so the
    record holds it and no reference of the file, whatever the variable holds."""
    from automated_security_helper.config.resolve_config import resolve_config

    probe_env.setenv("ASH_PROBE_PN", held)
    path = _operator_config(tmp_path, "project_name: ${ASH_PROBE_PN}\n")

    config = resolve_config(
        config_path=path,
        source_dir=tmp_path / "tree",
        config_overrides=["project_name=acme-prod-7c1e"],
    )

    # The control: the scan holds the override's text.
    assert config.project_name == "acme-prod-7c1e"
    assert _recorded(config)["project_name"] == "acme-prod-7c1e"


@pytest.mark.parametrize(
    "held",
    [
        pytest.param("acme-prod-7c1e", id="equal"),
        pytest.param("other-7c1e", id="control"),
    ],
)
def test_a_profiles_literal_over_its_bases_reference_is_written_to_a_session_as_the_literal(
    tmp_path, probe_env, held
):
    """A registered profile extends a base that reads ``project_name`` from a
    variable and writes ``acme-prod-7c1e`` itself. The session copy writes that
    text as the profile wrote it, and not as the base's reference, even where the
    variable holds that very text (``equal``)."""
    from automated_security_helper.cli.mcp import profile_registry

    probe_env.setenv("ASH_PROBE_PN", held)
    probe_env.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    probe_env.setenv("ASH_MCP_TRANSPORT", "stdio")
    _operator_config(tmp_path, "project_name: ${ASH_PROBE_PN}\n", "base.yaml")
    profile = _operator_config(
        tmp_path,
        "extends: base.yaml\nproject_name: acme-prod-7c1e\n",
        "profile.ash.yaml",
    )
    registry = profile_registry.register_profiles([f"probe={profile}"])

    written = Path(
        profile_registry.materialize_session_config(
            "session-literal", registry["probe"].config, client_patched=False
        )
    )

    text = written.read_text(encoding="utf-8")
    assert _as_written(text)["project_name"] == "acme-prod-7c1e", text


# ---------------------------------------------------------------------------
# What the load reshaped: a relative path it folded a ".." or "./" out of, and a
# list it made of one string
# ---------------------------------------------------------------------------

RELATIVE_CONFIG = (
    "scanners:\n  bandit:\n    options:\n      config_file: ${ASH_PROBE_RELATIVE}\n"
)

#: A relative path a variable gives, and a piece of it that no record, payload or
#: session copy may hold. The load takes the path from its file's directory and
#: folds a ``..`` or a ``./`` out of it (``parent-dir``, ``dot-dir``), so the text
#: the config holds no longer contains the text the variable gave; ``kept-whole``
#: keeps that text after the directory.
_RELATIVE_PATHS = pytest.mark.parametrize(
    "held, canary",
    [
        pytest.param("../shared-6d0a/x-6d0a.yaml", "shared-6d0a", id="parent-dir"),
        pytest.param("./conf-8e2b/x.yaml", "conf-8e2b", id="dot-dir"),
        pytest.param("conf-1f4c/x.yaml", "conf-1f4c", id="kept-whole"),
    ],
)


def _formats(config) -> List[str]:
    """The names ``output_formats`` holds."""
    return [getattr(entry, "value", entry) for entry in config.output_formats]


def _in_a_session_workspace(tmp_path: Path, probe_env) -> None:
    """The environment a session copy is written under, as the cells above set it."""
    probe_env.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    probe_env.setenv("ASH_MCP_TRANSPORT", "stdio")


def _files_holding(root: Path, text: str) -> List[str]:
    """The files under ``root`` whose bytes hold ``text``."""
    if not root.exists():
        return []
    return [
        str(path)
        for path in root.rglob("*")
        if path.is_file() and text.encode("utf-8") in path.read_bytes()
    ]


@_RELATIVE_PATHS
def test_a_relative_path_the_anchoring_folded_is_recorded_as_its_directory_and_the_reference(
    tmp_path, probe_env, held, canary
):
    """The load takes a relative path from its file's directory and folds a ``..``
    or a ``./`` out of it (``parent-dir``, ``dot-dir``), so the text the config
    holds no longer contains the text the variable gave. The record in the results
    file and the body an off-host reporter sends (to_simple_dict) hold that
    directory and the reference, as they do for a path the anchoring kept whole
    (``kept-whole``), and no text the variable gave."""
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    probe_env.setenv("ASH_PROBE_RELATIVE", held)
    path = _operator_config(tmp_path, RELATIVE_CONFIG)

    config = resolve_config(config_path=path, source_dir=tmp_path / "tree")

    # The control: the load took the path from the file's directory.
    assert os.path.isabs(str(config.scanners.bandit.options.config_file))
    expected = (
        os.path.join(os.path.realpath(tmp_path / "op"), "") + "${ASH_PROBE_RELATIVE}"
    )
    recorded = _recorded(config)
    assert recorded["scanners"]["bandit"]["options"]["config_file"] == expected
    assert canary not in json.dumps(recorded)
    body = AshAggregatedResults(ash_config=config).to_simple_dict()
    options = body["ash_config"]["scanners"]["bandit"]["options"]
    assert options["config_file"] == expected
    assert canary not in json.dumps(body, default=str)


def test_a_list_the_load_made_of_one_reference_is_recorded_as_the_reference(
    tmp_path, probe_env
):
    """``output_formats: ${VAR}`` holding ``sarif,html`` loads as two entries. The
    record holds the reference alone in their place: read back with nothing
    resolved, it is one entry the field refuses (listed as unreadable, so ``ash
    merge`` and ``ash report`` take the field from their operator), where the two
    names would be the value."""
    from automated_security_helper.config.recorded_config import unreadable_references
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    probe_env.setenv("ASH_PROBE_FMT", "sarif,html")
    path = _operator_config(tmp_path, "output_formats: ${ASH_PROBE_FMT}\n")

    config = resolve_config(config_path=path, source_dir=tmp_path / "tree")

    # The control: the field made two names of the variable's text.
    assert _formats(config) == ["sarif", "html"]
    results = AshAggregatedResults(ash_config=config)
    assert _recorded(config)["output_formats"] == ["${ASH_PROBE_FMT}"]
    assert results.to_simple_dict()["ash_config"]["output_formats"] == [
        "${ASH_PROBE_FMT}"
    ]
    read_back = AshAggregatedResults.model_validate_json(
        results.model_dump_json(by_alias=True)
    )
    assert unreadable_references(read_back.ash_config) == [
        ("output_formats", "${ASH_PROBE_FMT}")
    ]


def test_a_list_an_extending_file_wrote_over_a_bases_reference_is_recorded_as_written(
    tmp_path, probe_env
):
    """A base reads ``output_formats`` from a variable that holds ``sarif``, and
    the file extending it writes the list ``[sarif, html]`` itself. The scan runs
    with that list, so the record holds it as written: the base's reference is not
    put in its place, though its text made the first entry."""
    from automated_security_helper.config.resolve_config import resolve_config

    probe_env.setenv("ASH_PROBE_FMT", "sarif")
    _operator_config(tmp_path, "output_formats: ${ASH_PROBE_FMT}\n", "base.yaml")
    path = _operator_config(
        tmp_path, "extends: base.yaml\noutput_formats: [sarif, html]\n"
    )

    config = resolve_config(config_path=path, source_dir=tmp_path / "tree")

    # The control: the scan holds the later file's list.
    assert _formats(config) == ["sarif", "html"]
    assert _recorded(config)["output_formats"] == ["sarif", "html"]


def test_a_list_an_appending_override_extended_is_recorded_as_the_reference_and_the_added_entry(
    tmp_path, probe_env
):
    """An appending ``--config-overrides`` adds ``markdown`` to the list the load
    made of one reference's text. The record holds the reference where that text
    made its entries, and the added entry after it."""
    from automated_security_helper.config.resolve_config import resolve_config

    probe_env.setenv("ASH_PROBE_FMT", "sarif,html")
    path = _operator_config(tmp_path, "output_formats: ${ASH_PROBE_FMT}\n")

    config = resolve_config(
        config_path=path,
        source_dir=tmp_path / "tree",
        config_overrides=["output_formats+=[markdown]"],
    )

    # The control: the scan holds the entries the text made and the one added.
    assert _formats(config) == ["sarif", "html", "markdown"]
    assert _recorded(config)["output_formats"] == ["${ASH_PROBE_FMT}", "markdown"]


@pytest.mark.parametrize("client_patched", [False, True], ids=["operator", "client"])
@_RELATIVE_PATHS
def test_a_profile_whose_relative_path_the_anchoring_folded_is_not_written_to_a_session(
    tmp_path, probe_env, held, canary, client_patched
):
    """A registered profile reads a relative path from a variable, and the load
    folds a ``..`` or a ``./`` out of it (``parent-dir``, ``dot-dir``). Written as
    the path it now is, a session copy would hold the value, and written as the
    reference, the reference would resolve against the copy's directory, so the
    profile is refused for both copies, naming the variable and not its value.
    ``kept-whole``, which the anchoring keeps after its directory, is refused the
    same way."""
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.config.environment_record import (
        EnvironmentValueInPath,
    )

    probe_env.setenv("ASH_PROBE_RELATIVE", held)
    _in_a_session_workspace(tmp_path, probe_env)
    profile = _operator_config(tmp_path, RELATIVE_CONFIG, "profile.ash.yaml")
    config = profile_registry.register_profiles([f"probe={profile}"])["probe"].config
    # The control: the load took the path from the profile's directory.
    assert os.path.isabs(str(config.scanners.bandit.options.config_file))

    with pytest.raises(EnvironmentValueInPath) as raised:
        profile_registry.materialize_session_config(
            "session-folded", config, client_patched=client_patched
        )

    assert raised.value.variable == "ASH_PROBE_RELATIVE"
    assert raised.value.key_path == "scanners.bandit.options.config_file"
    assert canary not in str(raised.value)
    assert _files_holding(tmp_path / "mcp-workspaces", canary) == []


@_RELATIVE_PATHS
def test_select_profile_refuses_a_profile_whose_relative_path_the_anchoring_folded(
    tmp_path, probe_env, held, canary
):
    """The tool a client calls answers the refusal in the shape it answers every
    profile it cannot write to a session: a failed answer under the one error type
    a client branches on, naming no value."""
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.cli.mcp_tools import mcp_select_profile

    probe_env.setenv("ASH_PROBE_RELATIVE", held)
    _in_a_session_workspace(tmp_path, probe_env)
    probe_env.setenv("ASH_MCP_ALLOWED_ROOTS", str(tmp_path))
    probe_env.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    profile_registry.clear_profile_registry()
    profile_registry.clear_all_session_state()
    try:
        profile = _operator_config(tmp_path, RELATIVE_CONFIG, "profile.ash.yaml")
        profile_registry.set_profile_registry(
            profile_registry.register_profiles([f"probe={profile}"])
        )

        result = mcp_select_profile("probe", session_id="session-folded")

        assert result["success"] is False, result
        assert result["error_type"] == "environment_value_in_longer_string", result
        assert canary not in json.dumps(result)
        assert _files_holding(tmp_path / "mcp-workspaces", canary) == []
    finally:
        profile_registry.clear_profile_registry()
        profile_registry.clear_all_session_state()


@pytest.mark.parametrize(
    "client_patched, as_written",
    [
        pytest.param(False, "!ENV ${ASH_PROBE_FMT}", id="operator"),
        pytest.param(True, "${ASH_PROBE_FMT}", id="client"),
    ],
)
def test_a_profile_list_made_of_one_reference_is_written_to_a_session_as_the_reference(
    tmp_path, probe_env, client_patched, as_written
):
    """A registered profile reads ``output_formats`` from a variable that holds
    ``sarif,html``. Each session copy holds the reference where the text made two
    entries: the operator's copy tagged ``!ENV``, which a scan reads from the
    environment when it loads the copy and gets the list from, and the client's
    copy as text, which a scan fills from the operator's copy. Written as the
    names instead, the copy would hold the value."""
    from automated_security_helper.cli.mcp import profile_registry
    from automated_security_helper.config.resolve_config import _load_single_config_file

    probe_env.setenv("ASH_PROBE_FMT", "sarif,html")
    _in_a_session_workspace(tmp_path, probe_env)
    profile = _operator_config(
        tmp_path, "output_formats: ${ASH_PROBE_FMT}\n", "profile.ash.yaml"
    )
    config = profile_registry.register_profiles([f"probe={profile}"])["probe"].config
    # The control: the load made two names of the variable's text.
    assert _formats(config) == ["sarif", "html"]

    written = Path(
        profile_registry.materialize_session_config(
            "session-fmt", config, client_patched=client_patched
        )
    )

    text = written.read_text(encoding="utf-8")
    assert _as_written(text)["output_formats"] == as_written, text
    if not client_patched:
        # A scan reads the reference from the environment as it loads the copy.
        assert _formats(_load_single_config_file(written)) == ["sarif", "html"]


def test_a_profile_list_of_one_reference_entry_is_written_to_a_session_as_that_entry(
    tmp_path, probe_env
):
    """The control: a profile that writes the list itself, with a reference as its
    one entry, has the copy write the list with that entry as the reference. The
    reference stands where its file wrote it, not at the list. The list is
    written in block form: in a flow sequence the ``{`` of ``${`` opens a mapping
    and the file does not parse."""
    from automated_security_helper.cli.mcp import profile_registry

    probe_env.setenv("ASH_PROBE_FMT", "sarif")
    _in_a_session_workspace(tmp_path, probe_env)
    profile = _operator_config(
        tmp_path, "output_formats:\n  - ${ASH_PROBE_FMT}\n", "profile.ash.yaml"
    )
    config = profile_registry.register_profiles([f"probe={profile}"])["probe"].config

    written = Path(profile_registry.materialize_session_config("session-entry", config))

    text = written.read_text(encoding="utf-8")
    assert _as_written(text)["output_formats"] == ["!ENV ${ASH_PROBE_FMT}"], text


def test_a_profiles_list_over_its_bases_reference_is_written_to_a_session_as_the_list(
    tmp_path, probe_env
):
    """The control: a profile extends a base that reads ``output_formats`` from a
    variable that holds ``sarif`` and writes the list ``[sarif, html]`` itself. The
    copy writes the list the profile wrote, and not the base's reference."""
    from automated_security_helper.cli.mcp import profile_registry

    probe_env.setenv("ASH_PROBE_FMT", "sarif")
    _in_a_session_workspace(tmp_path, probe_env)
    _operator_config(tmp_path, "output_formats: ${ASH_PROBE_FMT}\n", "base.yaml")
    profile = _operator_config(
        tmp_path,
        "extends: base.yaml\noutput_formats: [sarif, html]\n",
        "profile.ash.yaml",
    )
    config = profile_registry.register_profiles([f"probe={profile}"])["probe"].config

    written = Path(profile_registry.materialize_session_config("session-list", config))

    text = written.read_text(encoding="utf-8")
    assert _as_written(text)["output_formats"] == ["sarif", "html"], text


# ---------------------------------------------------------------------------
# A checkout's config that the operator's file gave a path it read from a variable
# ---------------------------------------------------------------------------


def _a_checkout_given_the_operators_path(
    tmp_path: Path, probe_env, held: str
) -> Tuple[Path, Path]:
    """The operator's file reads bandit's ``config_file`` from a variable that
    holds ``held``, and ASH_CONFIG names it. ``tree/.ash.yaml`` sets no path, so
    its config is given the operator's for that option. Returns the operator's
    file and the checkout's."""
    probe_env.setenv("ASH_PROBE_RELATIVE", held)
    operator = _operator_config(tmp_path, RELATIVE_CONFIG)
    own = tmp_path / "tree" / ".ash.yaml"
    own.write_text("project_name: tree-own-3c8e\n", encoding="utf-8")
    probe_env.setenv("ASH_CONFIG", str(operator))
    return operator, own


def test_ash_config_get_shows_a_relative_path_the_trusted_base_gives_by_its_reference(
    tmp_path, probe_env
):
    """The file in the scanned tree sets no ``config_file``, and the operator's
    file, which ASH_CONFIG names, reads it from a variable. The load gives the
    tree's config the operator's path, so ``ash config get`` prints the operator's
    directory and the reference, as it does for the operator's own file, and none
    of the text the variable held."""
    _, own = _a_checkout_given_the_operators_path(
        tmp_path, probe_env, os.path.join("cfg-7a3d", "bandit.yaml")
    )

    result = CliRunner().invoke(
        app,
        ["config", "get", str(own), "--source-dir", str(tmp_path / "tree")],
        env={"COLUMNS": "300"},
    )

    assert result.exit_code == 0, result.output
    assert "cfg-7a3d" not in result.output
    assert "${ASH_PROBE_RELATIVE}" in result.output


@pytest.mark.parametrize(
    "held",
    [
        pytest.param(os.path.join("cfg-7a3d", "bandit.yaml"), id="kept-whole"),
        pytest.param("./cfg-7a3d/bandit.yaml", id="dot-dir"),
    ],
)
def test_a_relative_path_the_trusted_base_gives_a_checkouts_config_is_recorded_as_written(
    tmp_path, probe_env, held
):
    """The record of the tree's config holds the operator's directory and the
    reference where the operator's file read the path: for a path the anchoring
    kept whole and for one it folded a ``./`` out of."""
    from automated_security_helper.config.resolve_config import resolve_config

    operator, own = _a_checkout_given_the_operators_path(tmp_path, probe_env, held)

    config = resolve_config(config_path=own, source_dir=tmp_path / "tree")

    directory = operator.parent.resolve()
    # The control: the load gave the tree's config the operator's path.
    assert (
        Path(str(config.scanners.bandit.options.config_file))
        == directory / "cfg-7a3d" / "bandit.yaml"
    )
    recorded = _recorded(config)
    assert (
        recorded["scanners"]["bandit"]["options"]["config_file"]
        == f"{directory}{os.sep}${{ASH_PROBE_RELATIVE}}"
    )
    assert "cfg-7a3d" not in json.dumps(recorded)
