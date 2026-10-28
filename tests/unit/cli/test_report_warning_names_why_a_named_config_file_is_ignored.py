# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""``ash report`` says why it ignores what a ``--config`` file sets for an off-host plugin reporter.

``ash report`` holds a ``--config`` file (or ``ASH_CONFIG``) to the rule that a
reporter sending findings off the host runs, and sends where it does, only as
``--config-overrides`` say, because stored results do not record which tree was
scanned. The warning that names what was ignored ends in a reason and a remedy. For
a file outside every tree, "the config is inside a git checkout or the scanned tree"
is untrue and "keep a setting in your config" sends the operator to the file the
command ignores; the reason has to be the one for a file the command cannot place
(``untrusted_source.REPORT_CONFIG_FILE``), whose remedy is the overrides. A
``--config`` file inside the working directory or a git checkout is different:
``resolve_config`` already placed it in the tree and holds it for that reason, so
its warning keeps ``IN_TREE_OR_DELIVERED``'s reason. Its remedy is still the
overrides, since ``ash report`` holds any file it is named and moving this one out
of the tree would not change that (``REPORT_CONFIG_FILE_IN_TREE``). Every source
fills a section the file leaves out alike, so the choice changes only what the
warning says.

The stand-in reporter is the one the other ``ash report`` plugin tests use
(``off_host_plugin_support``). The command runs in a subprocess, because importing
a plugin package registers its plugins for the rest of the process, and the
subprocess hands back the warnings ASH logged. The last two tests need no plugin,
so they call ``resolve_config`` in the test process.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional

import pytest

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.config.sandbox_grants import in_any_checkout
from automated_security_helper.config.untrusted_source import (
    IN_TREE_OR_DELIVERED,
    REPORT_CONFIG_FILE,
    REPORT_CONFIG_FILE_IN_TREE,
    UntrustedSource,
)
from tests.unit.cli.off_host_plugin_support import (
    COLLECT_WARNINGS,
    FILE_ENDPOINT,
    PLUGIN,
    REPORTER,
    outside_every_checkout,
    plugin_environment,
    write_results,
)
from tests.utils.helpers import importing_this_checkout, mark_git_checkout

FILE_BUCKET = "file-bucket"

_REPORT = (
    """
import json, os, sys

spec = json.loads(sys.argv[1])
os.chdir(spec["cwd"])

from typer.testing import CliRunner
from automated_security_helper.cli.main import app
"""
    + COLLECT_WARNINGS
    + """
result = CliRunner().invoke(app, spec["args"])
print(json.dumps({"exit": result.exit_code, "output": result.output, "warnings": warnings}))
"""
)


def _report(
    tmp_path: Path, site: Path, inside: bool = False, builtin: bool = False
) -> Dict:
    """``ash report --format quiet-offhost --config <file>``.

    The file enables the reporter and gives it an endpoint, and no override does.
    It is outside every tree (``tmp_path/operator``), or with ``inside`` in the
    working directory (``tmp_path/repo/settings``), where ``resolve_config`` places
    it in the tree. Neither directory is in a git checkout, so the working
    directory is the only thing that places the second. With ``builtin`` the file
    also gives the built-in ``s3`` reporter a bucket, a destination option
    ``resolve_config`` itself holds a file in a tree to.
    """
    repo = tmp_path / "repo"
    output = repo / ".ash" / "ash_output"
    write_results(output)
    outside_every_checkout(repo)
    operator = (repo / "settings" if inside else tmp_path / "operator") / ".ash.yaml"
    operator.parent.mkdir()
    s3_section = (
        f"  s3:\n    options:\n      bucket_name: {FILE_BUCKET}\n" if builtin else ""
    )
    operator.write_text(
        f"reporters:\n"
        f"  {REPORTER}:\n"
        f"    enabled: true\n"
        f"    options:\n"
        f"      endpoint: {FILE_ENDPOINT}\n{s3_section}",
        encoding="utf-8",
    )
    outside_every_checkout(operator)
    args = ["report", "--format", REPORTER, "--config", str(operator)]
    args += ["--output-dir", str(output)]
    args += ["--config-overrides", f"ash_plugin_modules=[{PLUGIN}]"]
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            importing_this_checkout(_REPORT),
            json.dumps({"cwd": str(repo), "args": args}),
        ],
        cwd=tmp_path,
        env=plugin_environment(site),
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert result.returncode == 0, result.stderr[-4000:]
    return json.loads(result.stdout.strip().splitlines()[-1])


def _warning_about(result: Dict) -> str:
    """The warnings that name the plugin reporter's section, joined, whitespace squeezed."""
    named = [w for w in result["warnings"] if f"reporters.{REPORTER}" in w]
    assert named, result["warnings"]
    return " ".join(" ".join(named).split())


def test_the_warning_gives_the_reason_for_a_file_the_command_cannot_place(
    tmp_path, plugin_site
):
    result = _report(tmp_path, plugin_site)

    warning = _warning_about(result)
    assert " ".join(REPORT_CONFIG_FILE.reason.split()) in warning, warning
    assert " ".join(REPORT_CONFIG_FILE.remedy.split()) in warning, warning


def test_the_warning_does_not_call_the_file_part_of_a_checkout(tmp_path, plugin_site):
    result = _report(tmp_path, plugin_site)

    warning = _warning_about(result)
    assert " ".join(IN_TREE_OR_DELIVERED.reason.split()) not in warning, warning
    assert " ".join(IN_TREE_OR_DELIVERED.remedy.split()) not in warning, warning


def test_the_refusal_itself_is_unchanged(tmp_path, plugin_site):
    """Control: the file enables nothing, as before; only the warning's words change."""
    result = _report(tmp_path, plugin_site)

    assert result["exit"] == 1, result["output"]
    printed = " ".join(result["output"].split())
    assert "sends findings off the host and is not enabled" in printed, printed
    assert FILE_ENDPOINT not in result["output"], result["output"]


def test_a_file_in_the_working_directory_keeps_the_reason_for_a_file_in_a_tree(
    tmp_path, plugin_site
):
    """The command could place this file, and ``resolve_config`` held it as in a tree."""
    result = _report(tmp_path, plugin_site, inside=True)

    warning = _warning_about(result)
    assert " ".join(IN_TREE_OR_DELIVERED.reason.split()) in warning, warning
    assert " ".join(REPORT_CONFIG_FILE.reason.split()) not in warning, warning


def test_a_file_in_the_working_directory_gets_the_remedy_that_works_in_this_command(
    tmp_path, plugin_site
):
    """Moving the file out of the tree does not help: ``ash report`` holds any named file.

    The warning has to send the operator to ``--config-overrides``, not to "move the
    file outside every git checkout".
    """
    result = _report(tmp_path, plugin_site, inside=True)

    warning = _warning_about(result)
    assert " ".join(REPORT_CONFIG_FILE.remedy.split()) in warning, warning
    assert " ".join(IN_TREE_OR_DELIVERED.remedy.split()) not in warning, warning


def test_the_source_for_a_named_file_in_a_tree_joins_the_reason_and_the_remedy():
    assert REPORT_CONFIG_FILE_IN_TREE.reason == IN_TREE_OR_DELIVERED.reason
    assert REPORT_CONFIG_FILE_IN_TREE.remedy == REPORT_CONFIG_FILE.remedy
    assert (
        REPORT_CONFIG_FILE_IN_TREE.modules_remedy == REPORT_CONFIG_FILE.modules_remedy
    )
    assert (
        REPORT_CONFIG_FILE_IN_TREE.fills_missing_sections
        is IN_TREE_OR_DELIVERED.fills_missing_sections
    )


def test_the_source_for_a_named_file_in_a_tree_differs_only_in_the_two_remedies():
    """Every other field follows ``IN_TREE_OR_DELIVERED``, whatever fields it gains."""
    differing = {
        field.name
        for field in dataclasses.fields(REPORT_CONFIG_FILE_IN_TREE)
        if getattr(REPORT_CONFIG_FILE_IN_TREE, field.name)
        != getattr(IN_TREE_OR_DELIVERED, field.name)
    }
    assert differing == {"remedy", "modules_remedy"}, differing


def test_a_file_in_the_working_directory_is_refused_the_same_way(tmp_path, plugin_site):
    """Control: only the warning's words depend on where the file is."""
    result = _report(tmp_path, plugin_site, inside=True)

    assert result["exit"] == 1, result["output"]
    printed = " ".join(result["output"].split())
    assert "sends findings off the host and is not enabled" in printed, printed
    assert FILE_ENDPOINT not in result["output"], result["output"]


def _warnings_about_the_two_reporters(result: Dict) -> list[str]:
    """The warnings that name the built-in ``s3`` section or the plugin's, squeezed."""
    named = [
        " ".join(w.split())
        for w in result["warnings"]
        if "reporters.s3" in w or f"reporters.{REPORTER}" in w
    ]
    assert any("reporters.s3" in w for w in named), result["warnings"]
    assert any(f"reporters.{REPORTER}" in w for w in named), result["warnings"]
    return named


def test_a_built_in_and_a_plugin_reporter_of_one_file_in_a_tree_share_one_remedy(
    tmp_path, plugin_site
):
    """``resolve_config`` holds ``s3`` to the rule, and ``ash report`` the plugin.

    Both warnings are about the same named file, so both end with the remedy that
    works in this command, ``--config-overrides``, and neither tells the operator
    to move the file out of the tree.
    """
    result = _report(tmp_path, plugin_site, inside=True, builtin=True)

    for warning in _warnings_about_the_two_reporters(result):
        assert " ".join(REPORT_CONFIG_FILE.remedy.split()) in warning, warning
        assert " ".join(IN_TREE_OR_DELIVERED.remedy.split()) not in warning, warning


def test_a_file_in_a_tree_keeps_the_reason_for_both_reporters(tmp_path, plugin_site):
    """Only the remedy changes: the file is still described as inside a tree."""
    result = _report(tmp_path, plugin_site, inside=True, builtin=True)

    for warning in _warnings_about_the_two_reporters(result):
        assert " ".join(IN_TREE_OR_DELIVERED.reason.split()) in warning, warning


def test_a_file_outside_every_tree_gets_one_remedy_for_both_reporters(
    tmp_path, plugin_site
):
    """Control: the command's own step names both, with the remedy for a file it cannot place."""
    result = _report(tmp_path, plugin_site, builtin=True)

    for warning in _warnings_about_the_two_reporters(result):
        assert " ".join(REPORT_CONFIG_FILE.remedy.split()) in warning, warning
        assert " ".join(IN_TREE_OR_DELIVERED.remedy.split()) not in warning, warning


def test_the_two_reasons_differ():
    """Control: the assertions above can tell the two reasons apart."""
    assert REPORT_CONFIG_FILE.reason != IN_TREE_OR_DELIVERED.reason
    assert REPORT_CONFIG_FILE.remedy != IN_TREE_OR_DELIVERED.remedy


def test_the_two_sources_fill_a_section_the_file_leaves_out_alike():
    """Choosing between them changes the warning's words and nothing else.

    ``source.fills_missing_sections`` is also what ``confine_reporter_destinations``
    reads to decide whether a config with no section for a reporter gets one.
    """
    assert (
        REPORT_CONFIG_FILE.fills_missing_sections
        is IN_TREE_OR_DELIVERED.fills_missing_sections
    )


def _s3_warning_for_a_file_outside_that_extends_one_inside(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    named_config_source: Optional[UntrustedSource],
) -> str:
    """What ``resolve_config`` says about the built-in ``s3`` section, squeezed.

    The ``--config`` file is outside every tree and extends a file inside one, and
    only the file inside sets a bucket. ``resolve_config`` holds the file inside to
    the rule and names it in the warning, but the named file is not one of the
    files it holds.
    """
    assert not in_any_checkout(tmp_path), (
        f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
    )
    repo = tmp_path / "repo"
    mark_git_checkout(repo)
    base = repo / ".ash" / "base.yaml"
    base.parent.mkdir(parents=True)
    base.write_text(
        f"reporters:\n  s3:\n    options:\n      bucket_name: {FILE_BUCKET}\n",
        encoding="utf-8",
    )
    named = tmp_path / "operator-root.yaml"
    named.write_text("extends: repo/.ash/base.yaml\n", encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        resolve_config(
            config_path=named,
            source_dir=repo,
            named_config_source=named_config_source,
        )

    warnings = [
        " ".join(record.getMessage().split())
        for record in caplog.records
        if "reporters.s3" in record.getMessage()
    ]
    assert warnings, [record.getMessage() for record in caplog.records]
    return " ".join(warnings)


def test_a_named_file_outside_every_tree_that_extends_one_inside_gets_one_remedy(
    tmp_path, caplog
):
    """``ash report`` holds the named file as well, so every warning ends alike."""
    warning = _s3_warning_for_a_file_outside_that_extends_one_inside(
        tmp_path, caplog, REPORT_CONFIG_FILE_IN_TREE
    )

    assert " ".join(REPORT_CONFIG_FILE.remedy.split()) in warning, warning
    assert " ".join(IN_TREE_OR_DELIVERED.remedy.split()) not in warning, warning


def test_without_a_named_source_the_warning_keeps_the_remedy_for_a_file_in_a_tree(
    tmp_path, caplog
):
    """Control: a scan names no file, so the file inside is held for being inside."""
    warning = _s3_warning_for_a_file_outside_that_extends_one_inside(
        tmp_path, caplog, None
    )

    assert " ".join(IN_TREE_OR_DELIVERED.remedy.split()) in warning, warning
    assert " ".join(REPORT_CONFIG_FILE.remedy.split()) not in warning, warning
