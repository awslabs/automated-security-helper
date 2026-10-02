# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A discovered grype config that removes matches from the report must say so.

``GrypeScanner._process_config_options`` discovers a grype config file and passes
it through as ``--config``, whatever it contains. Several grype settings are
output filters: they drop matches that grype found, so the scan reports fewer
vulnerabilities than it detected and nothing in the run says the report was
narrowed. ``only-fixed: true`` is the one this repository had set, and it
discards every vulnerability with no fix available.

The key names and their meanings are taken from grype's configuration reference
at https://oss.anchore.com/docs/reference/grype/configuration/ (generated for
grype 0.110.0), not from the flag list:

* ``only-fixed`` -- "ignore matches for vulnerabilities that are not fixed"
* ``only-notfixed`` -- "ignore matches for vulnerabilities that are fixed"
* ``ignore-wontfix`` -- "ignore matches for vulnerabilities with specified
  comma separated fix states"
* ``ignore`` -- "A list of vulnerability ignore rules"
* ``exclude`` -- "a list of globs to exclude from scanning"
* ``vex-add`` -- "VEX statuses to consider as ignored rules"

``fail-on-severity`` is deliberately not in that set. It changes the process
return code rather than removing rows from the report, so warning about it would
train the reader to ignore the warning.

This is the class fix rather than a fix to one config file: any adopter can point
ASH at a grype config that quietly narrows their own results.
"""

import logging
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
    OUTPUT_RESTRICTING_GRYPE_KEYS,
    GrypeScanner,
    GrypeScannerConfig,
    GrypeScannerConfigOptions,
)

REPO_ROOT = Path(__file__).resolve().parents[4]


def _scanner(source_dir: Path, output_dir: Path) -> GrypeScanner:
    return GrypeScanner(
        context=PluginContext(
            source_dir=source_dir,
            output_dir=output_dir,
            config=get_default_config(),
        ),
        config=GrypeScannerConfig(options=GrypeScannerConfigOptions()),
    )


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("only-fixed: true\n", ["only-fixed"]),
        ("only-notfixed: true\n", ["only-notfixed"]),
        ("ignore-wontfix: wont-fix\n", ["ignore-wontfix"]),
        ("ignore:\n  - vulnerability: CVE-2000-0001\n", ["ignore"]),
        ("exclude:\n  - './vendor/**'\n", ["exclude"]),
        ("vex-add:\n  - not_affected\n", ["vex-add"]),
        (
            "only-fixed: true\nexclude:\n  - './vendor/**'\n",
            ["exclude", "only-fixed"],
        ),
    ],
)
def test_each_documented_restricting_key_is_detected(tmp_path, body, expected):
    config = tmp_path / ".grype.yaml"
    config.write_text(body)

    assert GrypeScanner._output_restricting_keys(config) == expected


@pytest.mark.parametrize(
    "body",
    [
        "",
        "output: sarif\n",
        # Changes the exit code, not the report. Warning about it would make the
        # warning meaningless.
        "fail-on-severity: high\n",
        # The inverse of a filter: it reveals suppressed matches.
        "show-suppressed: true\n",
        # Present but switched off, so nothing is being dropped.
        "only-fixed: false\n",
    ],
)
def test_a_config_that_removes_nothing_is_not_reported(tmp_path, body):
    config = tmp_path / ".grype.yaml"
    config.write_text(body)

    assert GrypeScanner._output_restricting_keys(config) == []


@pytest.mark.parametrize(
    "body",
    [
        "this: [is: not: valid: yaml\n",
        # A scalar document, not a mapping.
        "just-a-string\n",
        # A list at the top level.
        "- one\n- two\n",
    ],
)
def test_an_unreadable_config_is_not_an_error_here(tmp_path, body):
    """Fail soft: grype owns the verdict on its own config file.

    Raising here would turn a scan that grype itself would have run, or rejected
    with a precise message, into an ASH-side failure with a worse one.
    """
    config = tmp_path / ".grype.yaml"
    config.write_text(body)

    assert GrypeScanner._output_restricting_keys(config) == []


def test_a_missing_config_is_not_an_error_here(tmp_path):
    assert GrypeScanner._output_restricting_keys(tmp_path / "absent.yaml") == []


def test_the_scanner_warns_when_the_discovered_config_restricts_output(
    tmp_path, caplog
):
    """The warning has to reach the run, which is the whole point.

    ``_process_config_options`` runs from ``model_post_init``, so constructing
    the scanner against a source directory holding the config is what emits it.
    """
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / ".grype.yaml").write_text("only-fixed: true\n")
    output_dir = tmp_path / "out"
    output_dir.mkdir()

    with caplog.at_level(logging.WARNING):
        _scanner(source_dir, output_dir)

    logged = " ".join(caplog.messages)
    assert "only-fixed" in logged, (
        "the run said nothing about a config key that removes matches from the "
        f"report: {logged!r}"
    )


def test_the_scanner_stays_quiet_for_a_config_that_removes_nothing(tmp_path, caplog):
    """Control: the warning must be about the key, not about having a config."""
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / ".grype.yaml").write_text("output: sarif\n")
    output_dir = tmp_path / "out"
    output_dir.mkdir()

    with caplog.at_level(logging.WARNING):
        _scanner(source_dir, output_dir)

    logged = " ".join(caplog.messages)
    assert "restrict" not in logged.lower(), (
        f"warned about a grype config that drops nothing: {logged!r}"
    )


def test_the_key_set_is_not_empty():
    """Guard against the detection silently becoming a no-op."""
    assert OUTPUT_RESTRICTING_GRYPE_KEYS, (
        "an empty key set would make the warning unreachable while every test "
        "above that asserts absence still passed"
    )


def test_this_repositorys_grype_config_documents_any_filter_it_sets():
    """The invariant behind this phase, asserted against the shipped config.

    A filter that removes a category of finding is a decision, and every other
    exclusion in ``.ash/`` carries a written reason. This does not require the
    filter to be absent -- that is a maintainer's call about ASH's own risk
    posture -- only that it cannot be present silently.
    """
    config = REPO_ROOT / ".ash" / ".grype.yaml"
    if not config.is_file():
        pytest.skip("this repository ships no grype config")

    restricting = GrypeScanner._output_restricting_keys(config)
    if not restricting:
        return

    commentary = [
        line
        for line in config.read_text().splitlines()
        if line.lstrip().startswith("#")
    ]
    assert commentary, (
        f"{config.name} sets {restricting}, which removes matches from grype's "
        "report, with no written reason anywhere in the file"
    )
