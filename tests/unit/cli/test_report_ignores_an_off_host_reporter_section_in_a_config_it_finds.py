# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""``ash report`` and an off-host plugin reporter's section in a config file it finds itself.

With no ``--config`` and no ``ASH_CONFIG``, ``ash report`` reads the config file it
finds in the working directory: ``.ash/.ash.yaml``, the file a scan of that
directory would also read. The file is in the tree, so ``resolve_config`` records
the operator's view of the configuration (``record_operator_reporters``), and
``reporter_section`` builds a reporter that sends findings off the host from that
view, whole: its ``enabled`` and every option. A section the file writes for such a
reporter therefore neither enables it nor aims it, whether or not the reporter
declares destination options, without ``ash report`` being told which file it read.

These tests pin that. ``ash report`` marks its config for the whole-section rule
(``confine_off_host_reporters_to_overrides``) only for a file it was told about, so
the cases below are what keep the found file from reaching the reporter if
``reporter_section`` stops answering from the operator's view.

The stand-in reporter is the one the other ``ash report`` plugin tests use
(``off_host_plugin_support``), and the command runs in a subprocess for the same
reason.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, List

from tests.unit.cli.off_host_plugin_support import (
    DEFAULT_ENDPOINT,
    FILE_ENDPOINT,
    OVERRIDE_ENDPOINT,
    PLUGIN,
    REPORT_DRIVER,
    REPORTER,
    outside_every_checkout,
    plugin_environment,
    write_results,
)
from tests.utils.helpers import importing_this_checkout


def _report(tmp_path: Path, site: Path, overrides: List[str]) -> Dict:
    """``ash report --format quiet-offhost``, with no ``--config``.

    The working directory holds ``.ash/.ash.yaml``, which enables the reporter and
    gives it an endpoint and a title. The directory is in no git checkout, so the
    working directory is what places the file in the tree.
    """
    repo = tmp_path / "repo"
    output = repo / ".ash" / "ash_output"
    write_results(output)
    outside_every_checkout(repo)
    found = repo / ".ash" / ".ash.yaml"
    found.write_text(
        f"reporters:\n"
        f"  {REPORTER}:\n"
        f"    enabled: true\n"
        f"    options:\n"
        f"      endpoint: {FILE_ENDPOINT}\n"
        f"      title: file title\n",
        encoding="utf-8",
    )
    args = ["report", "--format", REPORTER, "--output-dir", str(output)]
    for override in [f"ash_plugin_modules=[{PLUGIN}]", *overrides]:
        args += ["--config-overrides", override]
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            importing_this_checkout(REPORT_DRIVER),
            json.dumps({"cwd": str(repo), "args": args}),
        ],
        cwd=tmp_path,
        env=plugin_environment(site),
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, result.stderr[-4000:]
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_a_found_config_cannot_enable_it_or_supply_its_options(tmp_path, plugin_site):
    result = _report(tmp_path, plugin_site, [])

    assert result["exit"] == 1, result["output"]
    # Exit 1 alone would also be any other failure of the command: the refusal is
    # the one that says the reporter sends findings off the host and is not enabled.
    printed = " ".join(result["output"].split())
    assert "sends findings off the host and is not enabled" in printed, printed
    assert FILE_ENDPOINT not in result["output"], result["output"]
    assert "file title" not in result["output"], result["output"]


def test_an_override_that_enables_it_gives_it_the_overrides_options_alone(
    tmp_path, plugin_site
):
    result = _report(tmp_path, plugin_site, [f"reporters.{REPORTER}.enabled=true"])

    assert result["exit"] == 0, result["output"]
    assert DEFAULT_ENDPOINT in result["output"], result["output"]
    assert "default title" in result["output"], result["output"]
    assert FILE_ENDPOINT not in result["output"], result["output"]
    assert "file title" not in result["output"], result["output"]


def test_an_override_that_aims_it_is_used(tmp_path, plugin_site):
    result = _report(
        tmp_path,
        plugin_site,
        [
            f"reporters.{REPORTER}.enabled=true",
            f"reporters.{REPORTER}.options.endpoint={OVERRIDE_ENDPOINT}",
        ],
    )

    assert result["exit"] == 0, result["output"]
    assert OVERRIDE_ENDPOINT in result["output"], result["output"]
    assert FILE_ENDPOINT not in result["output"], result["output"]
    assert "file title" not in result["output"], result["output"]
