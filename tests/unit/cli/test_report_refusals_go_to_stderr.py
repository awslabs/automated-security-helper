# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""``ash report`` prints each refusal on stderr, with its markup rendered.

``ash report`` writes the report to stdout and nothing else. Its errors go
through ``_print_error`` and ``_print_refusal`` (cli/report.py), which render the
markup in ASH's own words and write to stderr. A refusal printed with the builtin
``print`` instead, which the module has once it stops importing rich's ``print``,
goes to stdout with its tags as written, ``[red]...[/red]``.

The tests below cover two refusals: an output directory that is a link, and an
off-host reporter that only a config file enabled. Each runs the command in this
process and reads the two streams apart. The last two check the module for a
``print`` it never binds, so another such call is found without a command that
reaches it.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path
from typing import List, Optional

import botocore.client
import botocore.exceptions
import pytest
import typer

from tests.utils.secret_bearing_scan import isolate_from_aws

AWS_PLUGIN_MODULE = "automated_security_helper.plugin_modules.ash_aws_plugins"

# A color code, which a variable that forces a terminal puts around styled text.
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
# A rich markup tag as rich reads one: [red], [/red], [bold green], [link=...].
_RICH_TAG = re.compile(r"\[([a-z#/@][^\[]*?)]")


def _plain(text: str) -> str:
    """*text* without color codes or whitespace.

    Rich may wrap a long line, so a message is compared as the characters it
    holds, not by where a line broke.
    """
    return "".join(_ANSI.sub("", text).split())


def _no_markup_shown(out: str, err: str) -> None:
    """Neither stream holds a markup tag as written; stdout holds none at all."""
    assert _RICH_TAG.search(out) is None, out
    assert "[red]" not in err and "[/red]" not in err, err


@pytest.fixture(autouse=True)
def _no_config_from_the_environment(monkeypatch):
    """The command reads these variables; a test sets the config it uses itself."""
    for name in ("ASH_CONFIG", "ASH_PLUGIN_MODULES", "ASH_S3_BUCKET_NAME"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def nothing_is_sent(monkeypatch, tmp_path) -> List[str]:
    """No credentials, a loopback endpoint, and every botocore request refused and recorded."""
    isolate_from_aws(monkeypatch, tmp_path)
    made: List[str] = []

    def refusing_request(client, operation_name, api_params):
        made.append(f"{client.meta.service_model.service_name}.{operation_name}")
        raise botocore.exceptions.ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "refused by the test"}},
            operation_name,
        )

    monkeypatch.setattr(botocore.client.BaseClient, "_make_api_call", refusing_request)
    return made


@pytest.fixture
def aws_reporters_registered() -> None:
    """The plugin registry offers the AWS reporters, whatever ran before this test.

    The command takes its reporters from the registry, for the modules the run
    names, and a plugin package registers its reporters once, when Python first
    imports it. A process in which the package was imported earlier and the
    registry holds none of its reporters now has no way to get them back: the
    run loads the module, finds no reporter named ``s3`` and exits 5, the usage
    error for an unknown ``--format``, where this test expects the refusal. Any
    AWS reporter the registry lacks is registered here as the package's own
    decorator registers it. The registry is rolled back after each test
    (tests/conftest.py), so a registration made here does not outlive the test.
    """
    from automated_security_helper.plugin_modules import ash_aws_plugins
    from automated_security_helper.plugins import ash_plugin_manager

    for reporter in ash_aws_plugins.ASH_REPORTERS:
        if reporter not in ash_plugin_manager.plugin_modules("reporter"):
            ash_plugin_manager.register_plugin_module(
                "reporter", reporter, reporter.__module__
            )
    offered = ash_plugin_manager.plugin_modules("reporter")
    missing = [r.__name__ for r in ash_aws_plugins.ASH_REPORTERS if r not in offered]
    assert not missing, missing


def _stored_results(base: Path) -> tuple:
    """A working directory holding the stored results of a scan, and their directory."""
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    work = base / "work"
    output_dir = work / ".ash" / "ash_output"
    output_dir.mkdir(parents=True)
    stored = AshAggregatedResults()
    stored.ash_config = get_default_config()
    (output_dir / "ash_aggregated_results.json").write_text(
        stored.model_dump_json(by_alias=True), encoding="utf-8"
    )
    return work, output_dir


def _report(
    report_format: str,
    output_dir: Path,
    config: Optional[str] = None,
    overrides: Optional[List[str]] = None,
) -> int:
    """Run ``ash report`` in this process and return its exit code.

    Called directly rather than through CliRunner, which joins the two streams
    these tests read apart.
    """
    from automated_security_helper.cli.report import report_command
    from automated_security_helper.core.enums import AshLogLevel

    try:
        report_command(
            report_format=report_format,
            output_dir=str(output_dir),
            log_level=AshLogLevel.ERROR,
            config=config,
            config_overrides=overrides,
            verbose=False,
            debug=False,
            color=False,
        )
    except typer.Exit as exit_:
        return int(exit_.exit_code)
    return 0


@pytest.mark.skipif(
    sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
)
def test_a_linked_output_directory_is_refused_on_stderr(tmp_path, monkeypatch, capfd):
    """The scan's refusal of a link at the output directory, in ``ash report``."""
    host = tmp_path / "host"
    host.mkdir()
    output_dir = tmp_path / "out"
    output_dir.symlink_to(host, target_is_directory=True)
    monkeypatch.chdir(tmp_path)

    code = _report("text", output_dir)

    out, err = capfd.readouterr()
    refusal = _plain(err)
    assert code == 3
    assert _plain("is a symlink") in refusal and "--output-dir" in refusal, err
    assert _plain("is a symlink") not in _plain(out), out
    _no_markup_shown(out, err)


def test_an_off_host_reporter_only_a_config_file_enabled_is_refused_on_stderr(
    tmp_path, monkeypatch, capfd, nothing_is_sent, aws_reporters_registered
):
    """The refusal made on the section as confined to ``--config-overrides``.

    The operator's file is outside every tree and extends a file inside the
    working directory, so the section the first check reads holds the file's
    ``enabled: true`` and passes, and only the second check, on the section as
    confined, refuses.
    """
    from automated_security_helper.base.reporter_plugin import (
        off_host_reporter_refused,
    )
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.reporter_trust import (
        confine_off_host_reporters_to_overrides,
    )
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.config.untrusted_source import REPORT_CONFIG_FILE
    from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
        S3Reporter,
    )

    work, output_dir = _stored_results(tmp_path)
    (work / ".ash" / ".ash.yaml").write_text(
        "project_name: from-the-repository\n", encoding="utf-8"
    )
    operator_file = tmp_path / "operator.yaml"
    operator_file.write_text(
        "extends: work/.ash/.ash.yaml\n"
        "reporters:\n"
        "  s3:\n"
        "    enabled: true\n"
        "    options:\n"
        "      bucket_name: operator-file-bucket\n"
        "      aws_region: us-west-2\n"
        "      max_retries: 0\n",
        encoding="utf-8",
    )
    holding = [operator_file, *operator_file.parents]
    assert not any((p / ".git").exists() for p in holding), holding
    monkeypatch.chdir(work)
    overrides = [f"ash_plugin_modules=[{AWS_PLUGIN_MODULE}]"]

    # The setup does what the test needs: the operator's view enables S3 and the
    # confined section does not, so the command reaches the second check. Without
    # these a pass would say nothing about it.
    resolved = resolve_config(
        config_path=str(operator_file),
        config_overrides=list(overrides),
        fallback_to_default=False,
        also_scanned=[output_dir],
    )
    scan_section = reporter_section(resolved, S3Reporter)
    confine_off_host_reporters_to_overrides(
        resolved, [operator_file], overrides, REPORT_CONFIG_FILE
    )
    confined_section = resolved.get_plugin_config(
        plugin_type="reporter", plugin_name="s3"
    )
    assert resolved._operator_reporters is not None
    assert not off_host_reporter_refused(S3Reporter, scan_section), scan_section
    assert off_host_reporter_refused(S3Reporter, confined_section), confined_section
    # What the setup logged is not the command's output.
    capfd.readouterr()

    code = _report("s3", output_dir, config=str(operator_file), overrides=overrides)

    out, err = capfd.readouterr()
    refusal = _plain(err)
    assert code == 1
    assert (
        _plain("reporter 's3' sends findings off the host and is not enabled")
        in refusal
    ), err
    assert _plain("--config-overrides reporters.s3.enabled=true") in refusal, err
    assert "sends findings off the host" not in " ".join(out.split()), out
    _no_markup_shown(out, err)
    assert nothing_is_sent == []


def _unbound_print_calls(source: str) -> List[int]:
    """The lines of *source* that call ``print``, when nothing in it binds that name.

    A module that imports or defines a ``print`` of its own (rich's, or the one in
    utils/console.py) is not calling the builtin.
    """
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if any(
                (alias.asname or alias.name.split(".")[0]) == "print"
                for alias in node.names
            ):
                return []
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == "print":
                return []
    return [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "print"
    ]


def test_the_scan_for_a_builtin_print_flags_one_and_passes_the_rest():
    """The two inputs the scan below depends on: one it must flag, three it must not."""
    assert _unbound_print_calls("print('x')\n") == [1]
    assert _unbound_print_calls("console.print('x')\n") == []
    assert _unbound_print_calls("from rich import print\nprint('x')\n") == []
    assert _unbound_print_calls("def print(*a):\n    pass\nprint('x')\n") == []


def test_the_report_command_calls_no_builtin_print():
    """Its stdout is the report, and its refusals are printed by its own helpers."""
    from automated_security_helper.cli import report as report_cli

    source = Path(report_cli.__file__).read_text(encoding="utf-8")

    assert _unbound_print_calls(source) == []
