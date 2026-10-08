# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""checkov runs from the filesystem root, and its paths are put back as before.

checkov reads ``.checkov.yaml`` from its working directory, so ASH runs it from the
filesystem root and passes ``--directory=<target>`` as one token. checkov writes a
result's path as ``"/" + relpath(file, cwd)`` with every ``/..`` removed
(``checkov.common.output.record.Record._determine_repo_file_path``), so ASH
recomputes it with the source directory as the working directory. These tests pin
that shape; tests/integration/scanners/test_checkov_real_config_and_paths.py runs
the real checkov against it.
"""

import os
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
    CheckovScannerConfig,
    CheckovScannerConfigOptions,
    checkov_repo_file_path,
    rewrite_checkov_paths,
)
from automated_security_helper.utils.sandbox.policy import (
    SandboxRequirements,
    build_scanner_policy,
)

PluginContext.model_rebuild()

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX paths")


@pytest.mark.parametrize(
    "file_path,cwd,expected",
    [
        ("/repo/sub/a.yaml", "/repo", "/sub/a.yaml"),
        ("/repo/a.yaml", "/repo", "/a.yaml"),
        ("/repo/sub/a.yaml", "/", "/repo/sub/a.yaml"),
        # Outside the working directory: checkov strips the "/.." segments.
        ("/out/converted/x.yaml", "/repo", "/out/converted/x.yaml"),
        ("/repo/sub/a.yaml", "/repo/.ash/out", "/sub/a.yaml"),
    ],
)
def test_repo_file_path_has_checkovs_shape(file_path, cwd, expected):
    assert checkov_repo_file_path(file_path, cwd) == expected


def _sarif(*uris):
    return {
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "CKV_TEST",
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": uri}}}
                        ],
                    }
                    for uri in uris
                ]
            }
        ]
    }


def _uris(document):
    return [
        location["physicalLocation"]["artifactLocation"]["uri"]
        for run in document["runs"]
        for result in run["results"]
        for location in result["locations"]
    ]


def test_sarif_uris_from_a_root_run_become_source_relative(tmp_path):
    source = tmp_path / "repo"
    (source / "sub").mkdir(parents=True)
    root_relative = (source / "sub" / "a b.yaml").as_posix().lstrip("/")
    document = _sarif(root_relative.replace(" ", "%20"))
    rewrite_checkov_paths(document, ran_in="/", source_dir=str(source))
    assert _uris(document) == ["sub/a%20b.yaml"]


def test_sarif_uri_outside_the_source_keeps_checkovs_form(tmp_path):
    source = tmp_path / "repo"
    source.mkdir()
    outside = tmp_path / "out" / "converted" / "x.yaml"
    document = _sarif(outside.as_posix().lstrip("/"))
    rewrite_checkov_paths(document, ran_in="/", source_dir=str(source))
    expected = checkov_repo_file_path(outside.as_posix(), str(source)).lstrip("/")
    assert _uris(document) == [expected]


def test_json_repo_file_path_is_recomputed_from_file_abs_path(tmp_path):
    source = tmp_path / "repo"
    source.mkdir()
    absolute = (source / "sub" / "a.yaml").as_posix()
    document = [
        {
            "check_type": "cloudformation",
            "results": {
                "failed_checks": [
                    {"file_abs_path": absolute, "repo_file_path": absolute}
                ],
                "passed_checks": [],
            },
        }
    ]
    rewrite_checkov_paths(document, ran_in="/", source_dir=str(source))
    assert document[0]["results"]["failed_checks"][0]["repo_file_path"] == (
        "/sub/a.yaml"
    )


def _scanner(tmp_path) -> CheckovScanner:
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    return CheckovScanner(
        context=PluginContext(source_dir=source, output_dir=output, config=AshConfig()),
        config=CheckovScannerConfig(options=CheckovScannerConfigOptions()),
    )


def test_checkov_runs_from_the_root_with_the_directory_as_one_token(tmp_path):
    scanner = _scanner(tmp_path)
    argv, results_file, _ = scanner._execute_scan(
        scanner.context.source_dir, "source", []
    )
    assert "--directory" not in argv and "-d" not in argv
    assert f"--directory={Path(scanner.context.source_dir).as_posix()}" in argv
    assert scanner._subprocess_cwd(results_file.parent) == Path("/")


def test_a_root_cwd_is_not_a_sandbox_read_grant(tmp_path):
    results = tmp_path / "results"
    policy = build_scanner_policy(
        "checkov",
        SandboxRequirements(),
        argv0="/bin/true",
        source_dir=tmp_path,
        output_dir=tmp_path,
        results_dir=results,
        scan_target=None,
        cwd=Path("/"),
        offline=True,
        network_scanners=None,
    )
    assert Path("/") not in policy.read_only
    assert policy.cwd == Path("/")


@pytest.mark.parametrize("which", ["checkov", "ferret-scan"])
def test_the_scanner_cwd_is_never_inside_the_source_tree(tmp_path, which):
    from automated_security_helper.config.path_trust import in_scanned_tree
    from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
        FerretScanScanner,
    )

    source = tmp_path / "src"
    (source / ".git").mkdir(parents=True)
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    context = PluginContext(source_dir=source, output_dir=output, config=AshConfig())
    scanner = (
        CheckovScanner(context=context)
        if which == "checkov"
        else FerretScanScanner(context=context)
    )
    results_dir = Path(scanner.results_dir) / "source"
    cwd = scanner._subprocess_cwd(results_dir)
    assert cwd is not None
    assert not in_scanned_tree(cwd, source)


def test_ferret_scan_runs_its_subprocess_from_that_cwd(tmp_path):
    from unittest.mock import patch

    from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
        FerretScanScanner,
    )

    source = tmp_path / "src"
    source.mkdir()
    (source / "a.txt").write_text("x\n")
    output = tmp_path / "out"
    output.mkdir()
    scanner = FerretScanScanner(
        context=PluginContext(source_dir=source, output_dir=output, config=AshConfig())
    )
    scanner.dependencies_satisfied = True
    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_run_subprocess", return_value={}) as run,
    ):
        scanner.scan(target=source, target_type="source")
    assert run.call_args.kwargs["cwd"] == Path("/")
