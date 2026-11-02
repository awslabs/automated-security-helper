# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The generated schemas are the same bytes whichever host generates them.

Why this file exists
--------------------
Three defaults come from the process that imports the models, not from the
models: ``project_name`` reads ``ASH_PROJECT_NAME``, ``global_settings
.severity_threshold`` reads ``ASH_DEFAULT_SEVERITY_LEVEL``, and opengrep and
semgrep are on unless the operating system is Windows. ``generate_schemas`` wrote
those values into the committed schemas, at the field and again wherever a whole
section is the default of a field above it (``global_settings``, ``scanners``),
and the severity threshold also into a description. A schema regenerated from a
shell with ``ASH_PROJECT_NAME`` set, or on a Windows machine, therefore differed
from the committed one for a reason that has nothing to do with the models, and
``test_committed_schemas_match_the_generator`` could pass in one environment and
fail in another.

The generator now writes the shipped value (``json_schema_extra={"default":
...}`` on the field, put back inside an embedded section by
``ShippedDefaultsJsonSchema``). The models still read the host: the first test
checks that the child process really had the host's values, so the equality
beside it is not two runs of the same environment.

Each run is a child process, because the defaults are fixed when the models are
imported. The child makes ``platform.system`` answer the given name to the opengrep
and semgrep modules, which is what their defaults read, and the real answer to
every other caller.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict

import pytest

pytestmark = pytest.mark.unit

REPOSITORY = Path(__file__).resolve().parents[3]

HOST_VARIABLES = ("ASH_PROJECT_NAME", "ASH_DEFAULT_SEVERITY_LEVEL")

#: Runs in the child: argv is the system name ``platform.system`` answers and
#: the file the answer is written to.
CHILD = """
import json, platform, sys
system, destination = sys.argv[1], sys.argv[2]
real_system = platform.system


def system_as_the_scanner_modules_see_it():
    caller = sys._getframe(1).f_globals.get("__name__", "")
    if caller.endswith(("opengrep_scanner", "semgrep_scanner")):
        return system
    return real_system()


platform.system = system_as_the_scanner_modules_see_it
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScannerConfig,
)
from automated_security_helper.schemas.generate_schemas import generate_schemas
answer = {
    "schemas": generate_schemas("json"),
    "models_read": {
        "project_name": AshConfig.model_fields["project_name"].default,
        "severity_threshold": type(AshConfig().global_settings)
        .model_fields["severity_threshold"]
        .default,
        "opengrep_enabled": OpengrepScannerConfig.model_fields["enabled"].default,
    },
}
with open(destination, "w", encoding="utf-8") as stream:
    json.dump(answer, stream)
"""


def _generate(
    tmp_path: Path, label: str, system: str, host: Dict[str, str]
) -> Dict[str, Any]:
    environment = {k: v for k, v in os.environ.items() if k not in HOST_VARIABLES}
    environment.update(host)
    environment["PYTHONPATH"] = str(REPOSITORY)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    destination = tmp_path / f"{label}.json"
    done = subprocess.run(
        [sys.executable, "-c", CHILD, system, str(destination)],
        cwd=REPOSITORY,
        env=environment,
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    return json.loads(destination.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def shipped(tmp_path_factory) -> Dict[str, Any]:
    return _generate(tmp_path_factory.mktemp("shipped"), "shipped", "Linux", {})


@pytest.fixture(scope="module")
def odd_host(tmp_path_factory) -> Dict[str, Any]:
    return _generate(
        tmp_path_factory.mktemp("odd-host"),
        "odd-host",
        "Windows",
        {
            "ASH_PROJECT_NAME": "a-project-the-host-named",
            "ASH_DEFAULT_SEVERITY_LEVEL": "CRITICAL",
        },
    )


def test_control_the_models_read_the_host_they_are_imported_under(shipped, odd_host):
    """Without this, equal schemas could mean the child never saw the host."""
    assert shipped["models_read"] == {
        "project_name": "ash-scan",
        "severity_threshold": "MEDIUM",
        "opengrep_enabled": True,
    }
    assert odd_host["models_read"] == {
        "project_name": "a-project-the-host-named",
        "severity_threshold": "CRITICAL",
        "opengrep_enabled": False,
    }


def test_the_generated_schemas_are_the_same_whatever_the_host_makes_of_the_defaults(
    shipped, odd_host
):
    assert sorted(shipped["schemas"]) == sorted(odd_host["schemas"])
    differing = [
        name
        for name in sorted(shipped["schemas"])
        if shipped["schemas"][name] != odd_host["schemas"][name]
    ]
    assert differing == [], (
        f"schemas that depend on the generating host: {', '.join(differing)}"
    )


def test_the_host_values_appear_nowhere_in_the_odd_hosts_schemas(odd_host):
    """The equality above holds trivially if a value is dropped everywhere; this
    pins the other side: the odd host's own values are in no schema text."""
    for name, text in odd_host["schemas"].items():
        assert "a-project-the-host-named" not in text, name
        assert '"severity_threshold": "CRITICAL"' not in text, name


def test_the_config_schema_says_the_shipped_defaults(odd_host):
    definitions = json.loads(odd_host["schemas"]["AshConfig"])["$defs"]
    config = definitions["AshConfig"]["properties"]

    assert config["project_name"]["default"] == "ash-scan"
    assert (
        definitions["AshConfigGlobalSettingsSection"]["properties"][
            "severity_threshold"
        ]["default"]
        == "MEDIUM"
    )
    # A section that is the default of a field above it is written whole.
    assert config["global_settings"]["default"]["severity_threshold"] == "MEDIUM"
    for scanner in ("OpengrepScannerConfig", "SemgrepScannerConfig"):
        assert definitions[scanner]["properties"]["enabled"]["default"] is True, scanner
    segment = definitions["ScannerConfigSegment"]["properties"]
    for name in ("opengrep", "semgrep"):
        assert segment[name]["default"]["enabled"] is True, name
        assert config["scanners"]["default"][name]["enabled"] is True, name
