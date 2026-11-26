# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The wrapper contract spec against values written down here by hand.

``automated_security_helper/interactions/wrapper_contract.py`` computes the tables the
two host wrappers carry from the real typer app. Comparing what it computed with the
typer app it read would pass under any bug in how it reads it: a dropped subcommand, a
mis-collected option. So these expectations are literals. A legitimate change to the CLI
(a new subcommand, a new option on one) changes the literals in the same commit; a
mistake in the spec's derivation fails against them.

``test_powershell_wrapper_tables.py`` stays the separate check of the rendered
PowerShell tables against the typer app.
"""

from __future__ import annotations

import inspect

import pytest

from automated_security_helper.interactions.wrapper_contract import (
    WRAPPER_FORWARDED_OPTIONS,
    WrapperContract,
    contract,
)

pytestmark = pytest.mark.unit


def test_subcommands():
    assert contract().subcommands == (
        "scan",
        "build-image",
        "report",
        "diff",
        "trend",
        "merge",
        "mcp",
        "get-genai-guide",
        "config",
        "dependencies",
        "inspect",
        "plugin",
        "suppress",
        "express",
    )


def test_only_scan_takes_sandbox():
    assert contract().sandbox_subcommands == ("scan",)


def test_root_value_options():
    assert contract().root_value_options == (
        "--add-scanners",
        "--ash-config-from-host",
        "--ash-plugin-modules",
        "--ash-revision-to-install",
        "--base-ref",
        "--baseline",
        "--build-target",
        "--config",
        "--config-file-from-another-checkout",
        "--config-file-from-scanned-repository",
        "--config-overrides",
        "--container-gid",
        "--container-uid",
        "--custom-build-arg",
        "--custom-containerfile",
        "--exclude-scanners",
        "--format",
        "--formats",
        "--image",
        "--image-archive",
        "--image-layout",
        "--log-level",
        "--min-severity",
        "--mode",
        "--oci",
        "--oci-runner",
        "--offline-semgrep-rulesets",
        "--only-scanners",
        "--output-dir",
        "--output-format",
        "--output-formats",
        "--phases",
        "--require-scanner-selection",
        "--runner",
        "--sandbox",
        "--scanners",
        "--shard-count",
        "--shard-index",
        "--source-dir",
        "--strategy",
        "--workspace",
        "--workspace-config",
        "-c",
        "-f",
        "-g",
        "-o",
        "-u",
    )


EXPECTED_OPTION_SUBCOMMANDS = {
    "--quiet": ("scan", "build-image", "mcp"),
    "--no-color": ("scan", "build-image", "report", "merge", "mcp"),
    "--progress": ("scan",),
    "--no-progress": ("scan",),
    "--show-summary": ("scan",),
    "--no-show-summary": ("scan",),
    "--fail-on-findings": ("scan", "merge"),
    "--no-fail-on-findings": ("scan", "merge"),
    "--verbose": ("scan", "build-image", "report", "merge", "mcp"),
    "--debug": ("scan", "build-image", "report", "merge", "mcp"),
    "--offline": ("scan", "build-image"),
    "--config": ("scan", "build-image", "report", "merge"),
    "--scanners": ("scan",),
    "--exclude-scanners": ("scan",),
    "--ignore-suppressions": ("scan", "merge"),
}


def test_which_subcommands_take_each_forwarded_option():
    assert dict(contract().option_subcommands) == EXPECTED_OPTION_SUBCOMMANDS


def test_the_forwarded_option_list_is_in_the_table_order():
    assert [name for name, _ in contract().option_subcommands] == list(
        WRAPPER_FORWARDED_OPTIONS
    )
    assert set(WRAPPER_FORWARDED_OPTIONS) == set(EXPECTED_OPTION_SUBCOMMANDS)


def test_the_subcommands_whose_own_dash_o_is_forwarded():
    assert contract().dash_o_subcommands == ("get-genai-guide", "config")


def test_runner_order_image_pattern_and_build_targets():
    spec = contract()
    assert spec.runner_order == ("finch", "docker", "nerdctl", "podman")
    assert spec.image_name_pattern == r"[A-Za-z0-9._:/@-]+"
    assert spec.build_targets == ("ci", "non-root")


def test_exit_codes():
    spec = contract()
    assert spec.refusal_exit == 3
    assert spec.usage_error_exit == 5


def test_ci_runner_markers():
    assert contract().ci_runner_markers == (
        "GITHUB_ACTIONS",
        "TF_BUILD",
        "TEAMCITY_VERSION",
    )


def test_every_contract_field_is_rendered_into_a_wrapper_block():
    """A field no generated block renders is a twin the wrappers keep by hand.

    The contract exists to stop the wrappers' written-out copies of the CLI's surface
    from drifting. A field computed but rendered nowhere stops nothing, so each one
    must be read by a renderer in the generator.
    """
    import dataclasses
    import importlib.util
    import sys
    from pathlib import Path

    script = (
        Path(__file__).resolve().parents[2] / "scripts" / "generate_wrapper_tables.py"
    )
    name = "wrapper_tables_for_fields"
    spec = importlib.util.spec_from_file_location(name, script)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    rendered = "\n".join(
        inspect.getsource(renderer)
        for blocks in module.BLOCKS.values()
        for _, renderer in blocks
    )

    def unrendered(field_names):
        return [n for n in field_names if f"contract.{n}" not in rendered]

    fields = [field.name for field in dataclasses.fields(WrapperContract)]
    assert unrendered(fields) == []
    # The control: a field no renderer reads is reported, so the empty list above is
    # not a check that passes anything.
    assert unrendered([*fields, "mount_destinations"]) == ["mount_destinations"]


def test_the_shared_refusal_texts_are_re_exported_not_copied():
    from automated_security_helper.interactions import wrapper_contract as spec
    from automated_security_helper.utils import directory_refusals as owner

    # The codes are pinned as literals; the functions must be the owner's own objects,
    # so a change to a refusal text in directory_refusals reaches the spec at once.
    assert spec.REFUSED_NOT_A_DIRECTORY == "not_a_directory"
    assert spec.REFUSED_CANNOT_BE_ENTERED == "cannot_be_entered"
    assert spec.REFUSED_CANNOT_BE_CREATED == "cannot_be_created"
    assert spec.REFUSED_CANNOT_BE_WRITTEN == "cannot_be_written"
    assert spec.REFUSED_NOT_A_VALID_PATH == "not_a_valid_path"
    for name in (
        "source_dir_refusal",
        "output_dir_refusal",
        "output_dir_invalid_path",
        "output_dir_unmakeable",
        "output_dir_unwritable",
    ):
        assert getattr(spec, name) is getattr(owner, name), name


def test_takers_names_an_unknown_option():
    with pytest.raises(KeyError):
        contract().takers("--not-an-option")
    assert contract().takers("--progress") == ("scan",)
