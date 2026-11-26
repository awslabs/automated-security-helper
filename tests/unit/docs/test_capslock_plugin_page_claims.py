# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Capslock plugin page says what the plugin does, and what it says is true.

Each test pins a sentence of ``docs/plugins/alpha/capslock-plugin.md`` with
``assert_on_page`` and reads the code that makes it true: the pinned install
command, the argv, the environment, the severity, the exit codes, the directories
skipped and the license pin. A reworded sentence fails here with the page and the
heading named; a changed behavior fails the probe.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.plugin_modules.ash_capslock_plugins import (
    capslock_scanner as cs,
)
from automated_security_helper.plugin_modules.ash_capslock_plugins.capslock_scanner import (
    CapslockScanner,
    convert_capslock_output,
    find_go_modules,
)
from tests.unit.docs.test_page_claims import assert_on_page

pytestmark = pytest.mark.unit

PAGE = "docs/plugins/alpha/capslock-plugin.md"


def test_the_install_command_is_the_pinned_one():
    assert_on_page(PAGE, "go install github.com/google/capslock/cmd/capslock@v0.3.4")
    assert_on_page(
        PAGE, "The plugin is written against Capslock's `v0.3.4` module tag."
    )
    assert cs.INSTALL_COMMAND == (
        "go install github.com/google/capslock/cmd/capslock@v0.3.4"
    )
    assert cs.CAPSLOCK_VERSION == "v0.3.4"


def test_the_argv_and_the_environment_are_the_plugins():
    assert_on_page(PAGE, "capslock -packages=./... -output=json -force_local_module")
    assert_on_page(
        PAGE, "`GOFLAGS=-mod=readonly` is set so the run never rewrites `go.mod`."
    )
    argv = CapslockScanner._argv(SimpleNamespace(command="capslock"))
    assert " ".join(argv) == "capslock -packages=./... -output=json -force_local_module"
    assert CapslockScanner._subprocess_env()["GOFLAGS"] == "-mod=readonly"


def test_every_capability_is_info(tmp_path: Path):
    assert_on_page(
        PAGE,
        "Every capability is INFO, SARIF level `none`, kind `informational`.",
    )
    document = {
        "capabilityInfo": [
            {"capabilityName": "NETWORK", "packageDir": "example.com/app"},
        ]
    }
    (result,) = convert_capslock_output(document, tmp_path, tmp_path, "example.com/app")
    assert (result["properties"]["issue_severity"], result["level"]) == ("INFO", "none")
    assert result["kind"] == "informational"
    assert result["ruleId"] == "CAPSLOCK-NETWORK"


def test_only_a_zero_exit_is_a_completed_run():
    assert_on_page(PAGE, "The plugin accepts 0 only.")
    assert CapslockScanner.success_exit_codes == {0}


def test_the_skipped_directories_are_the_plugins(tmp_path: Path):
    assert_on_page(
        PAGE,
        "except under `vendor`, `node_modules`, `.git` and `testdata`",
    )
    assert cs._SKIPPED_DIRS == {"vendor", "node_modules", ".git", "testdata"}
    assert find_go_modules(tmp_path) == []


def test_the_license_is_named_with_its_pin():
    assert_on_page(
        PAGE,
        "Capslock is BSD-3-Clause: the `LICENSE` file at the commit the `v0.3.4` "
        "tag points to (`29ad626`).",
    )
    assert cs.CAPSLOCK_COMMIT.startswith("29ad626")
    assert cs.LICENSE_CITATION.startswith("BSD-3-Clause (source: ")
