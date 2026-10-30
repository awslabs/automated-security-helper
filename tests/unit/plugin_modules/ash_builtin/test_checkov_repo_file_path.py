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

import json
import os
from pathlib import Path
from urllib.parse import quote, unquote

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

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(os.name == "nt", reason="POSIX paths"),
]


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


def test_sarif_uri_outside_the_source_keeps_its_climb(tmp_path):
    """checkov's own form drops every ``/..``, which made ``../out/converted/x.yaml``
    read as ``out/converted/x.yaml``, a path inside the source that names nothing
    there; ASH keeps the climb so the path still leads to the file."""
    source = tmp_path / "repo"
    source.mkdir()
    outside = tmp_path / "out" / "converted" / "x.yaml"
    document = _sarif(outside.as_posix().lstrip("/"))
    rewrite_checkov_paths(document, ran_in="/", source_dir=str(source))
    expected = os.path.relpath(outside, os.path.realpath(source))
    assert expected.startswith("../")
    assert _uris(document) == [quote(expected)]
    assert _uris(document) != [
        checkov_repo_file_path(outside.as_posix(), str(source)).lstrip("/")
    ]


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
        patch.object(scanner, "_run_subprocess", return_value={"returncode": 0}) as run,
    ):
        scanner.scan(target=source, target_type="source")
    assert run.call_args.kwargs["cwd"] == Path("/")


def test_a_source_under_a_directory_starting_with_dots_maps_back(tmp_path):
    # checkov removes every "/.." from the whole path it writes, which changes
    # an ancestor named "..odd" too. The rewrite matches checkov's form of the
    # scanned directory instead of joining the URI to the root.
    source = tmp_path / "..odd" / "proj"
    source.mkdir(parents=True)
    file_path = (source / "main.tf").as_posix()
    written = checkov_repo_file_path(file_path, "/").lstrip("/")
    assert "..odd" not in written  # checkov's mangling, which the rewrite undoes
    document = _sarif(written)
    rewrite_checkov_paths(
        document,
        ran_in="/",
        source_dir=str(source),
        scanned_dirs=[source.as_posix()],
    )
    assert _uris(document) == ["main.tf"]


def _root_in_tree(monkeypatch, *, also=lambda path: False):
    """Make the filesystem root count as inside the tree, as for a drive-root source."""
    from automated_security_helper.config import path_trust

    real = path_trust.in_scanned_tree

    def fake(path, scan_root):
        return Path(path) == Path("/") or also(Path(path)) or real(path, scan_root)

    monkeypatch.setattr(path_trust, "in_scanned_tree", fake)
    monkeypatch.setattr(path_trust, "_FALLBACK_CWDS", {})
    return path_trust


def test_the_fallback_cwd_is_a_new_system_temp_dir_outside_the_tree(
    tmp_path, monkeypatch
):
    """A source directory that is a drive root (subst, mapped drive) on Windows."""
    path_trust = _root_in_tree(monkeypatch)
    source = tmp_path / "src"
    source.mkdir()
    results = tmp_path / "results"
    cwd = path_trust.cwd_outside_scanned_tree(
        source, results_dir=results, source_dir=source
    )
    assert cwd != Path("/") and not path_trust.in_scanned_tree(cwd, source)
    assert cwd.is_dir() and not any(cwd.iterdir())
    # Made once per root and process, and removed at exit while empty.
    again = path_trust.cwd_outside_scanned_tree(
        source, results_dir=results, source_dir=source
    )
    assert again == cwd
    path_trust._remove_fallback_cwds()
    assert not cwd.exists()


def test_the_fallback_cwd_goes_under_the_root_when_temp_is_in_the_tree(
    tmp_path, monkeypatch
):
    import tempfile

    fake_root = tmp_path / "root"
    fake_root.mkdir()
    path_trust = _root_in_tree(
        monkeypatch, also=lambda p: Path(tempfile.gettempdir()) in (p, *p.parents)
    )
    made = []

    def new_directory(parent):
        if parent is None:
            return Path(tempfile.mkdtemp(prefix="ash-tool-cwd-"))
        made.append(parent)
        return Path(tempfile.mkdtemp(prefix="ash-tool-cwd-", dir=fake_root))

    monkeypatch.setattr(path_trust, "_new_directory", new_directory)
    source = tmp_path / "src"
    source.mkdir()
    cwd = path_trust.cwd_outside_scanned_tree(
        source, results_dir=tmp_path / "results", source_dir=source
    )
    assert made == [Path("/")]
    assert cwd.parent == fake_root


def test_under_a_sandbox_the_fallback_cwd_is_under_the_results_dir(
    tmp_path, monkeypatch
):
    from automated_security_helper.utils.sandbox import scope

    path_trust = _root_in_tree(monkeypatch)
    monkeypatch.setattr(scope, "active_scope", lambda: object())
    source = tmp_path / "src"
    source.mkdir()
    results = tmp_path / "results"
    cwd = path_trust.cwd_outside_scanned_tree(
        source, results_dir=results, source_dir=source
    )
    assert cwd.parent == results
    assert cwd.is_dir() and not any(cwd.iterdir())


def test_a_cwd_one_level_below_a_common_ancestor_gives_the_same_paths(tmp_path):
    """Why a directory directly under the root maps exactly (fallback option 2)."""
    child = tmp_path / "ash-tool-cwd-x"
    for relative in ("main.tf", "a/b/c.tf", "..odd/d.tf"):
        file_path = (tmp_path / relative).as_posix()
        assert checkov_repo_file_path(file_path, str(child)) == checkov_repo_file_path(
            file_path, str(tmp_path)
        )


def _checkov_sarif_file(scanner: CheckovScanner, *files: Path) -> Path:
    """checkov's SARIF for a finding in each of *files*, run from the root."""
    results_file = Path(scanner.results_dir) / "source" / "results_sarif.sarif"
    results_file.parent.mkdir(parents=True, exist_ok=True)
    uris = [quote(checkov_repo_file_path(f.as_posix(), "/").lstrip("/")) for f in files]
    results_file.write_text(json.dumps(_sarif(*uris)), encoding="utf-8")
    return results_file


def test_a_name_holding_a_backslash_is_recovered_from_the_scan_set(tmp_path):
    """checkov writes every backslash as "/" (its convert_to_unix_path), so its
    URI for the POSIX file a\\b.tf names a/b.tf, which does not exist. The scan
    set holds the one file checkov spells that way."""
    scanner = _scanner(tmp_path)
    named = Path(scanner.context.source_dir) / "a\\b.tf"
    named.write_text('resource "x" "y" {}\n', encoding="utf-8")

    raw = scanner._read_results_file(_checkov_sarif_file(scanner, named))

    assert _uris(raw) == ["a%5Cb.tf"]
    assert (Path(scanner.context.source_dir) / unquote(_uris(raw)[0])).is_file()


def test_when_both_spellings_exist_checkovs_path_is_kept(tmp_path):
    """checkov's URI for a\\b.tf is a/b.tf, which exists here, so the two files
    cannot be told apart from checkov's output and its path is kept. A limit of
    checkov's spelling, not something the rewrite can recover."""
    scanner = _scanner(tmp_path)
    source = Path(scanner.context.source_dir)
    (source / "a\\b.tf").write_text("x\n", encoding="utf-8")
    (source / "a").mkdir()
    (source / "a" / "b.tf").write_text("y\n", encoding="utf-8")

    raw = scanner._read_results_file(_checkov_sarif_file(scanner, source / "a\\b.tf"))

    assert _uris(raw) == ["a/b.tf"]


def test_two_scanned_files_checkov_spells_alike_keep_checkovs_path(tmp_path):
    """checkov writes both a\\b\\c.tf and a/b\\c.tf as a/b/c.tf, which names
    neither of them. With two scanned files spelled that way the rewrite cannot
    tell which one checkov meant, so checkov's path is kept rather than one of
    them picked."""
    scanner = _scanner(tmp_path)
    source = Path(scanner.context.source_dir)
    (source / "a\\b\\c.tf").write_text("x\n", encoding="utf-8")
    (source / "a").mkdir()
    (source / "a" / "b\\c.tf").write_text("y\n", encoding="utf-8")
    assert not (source / "a" / "b" / "c.tf").exists()

    raw = scanner._read_results_file(
        _checkov_sarif_file(scanner, source / "a\\b\\c.tf")
    )

    assert _uris(raw) == ["a/b/c.tf"]


def test_a_uri_matching_no_scanned_file_keeps_checkovs_form(tmp_path):
    scanner = _scanner(tmp_path)
    gone = Path(scanner.context.source_dir) / "gone" / "x.tf"

    raw = scanner._read_results_file(_checkov_sarif_file(scanner, gone))

    assert _uris(raw) == ["gone/x.tf"]


def test_the_scan_set_is_read_only_after_a_uri_misses(tmp_path):
    source = tmp_path / "repo"
    source.mkdir()
    (source / "main.tf").write_text("x\n", encoding="utf-8")
    (source / "a\\b.tf").write_text("x\n", encoding="utf-8")
    calls = []

    def scanned_files():
        calls.append(1)
        return [str(source / "main.tf"), str(source / "a\\b.tf")]

    present = _sarif(
        checkov_repo_file_path((source / "main.tf").as_posix(), "/").lstrip("/")
    )
    rewrite_checkov_paths(
        present, ran_in="/", source_dir=str(source), scanned_files=scanned_files
    )
    assert _uris(present) == ["main.tf"]
    assert calls == []

    missing = checkov_repo_file_path((source / "a\\b.tf").as_posix(), "/")
    twice = _sarif(missing.lstrip("/"), missing.lstrip("/"))
    rewrite_checkov_paths(
        twice, ran_in="/", source_dir=str(source), scanned_files=scanned_files
    )
    assert _uris(twice) == ["a%5Cb.tf", "a%5Cb.tf"]
    assert calls == [1]


@pytest.mark.parametrize("which", ["checkov", "ferret-scan"])
def test_relative_source_and_output_paths_are_made_absolute(
    tmp_path, monkeypatch, which
):
    from unittest.mock import patch

    from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
        FerretScanScanner,
    )

    monkeypatch.chdir(tmp_path)
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.txt").write_text("x\n")
    (tmp_path / "out").mkdir()
    context = PluginContext(
        source_dir=Path("src"), output_dir=Path("out"), config=AshConfig()
    )
    if which == "checkov":
        scanner = CheckovScanner(context=context)
        argv, results_file, _ = scanner._execute_scan(Path("src"), "source", [])
        directory = [a for a in argv if a.startswith("--directory=")]
        assert directory == [f"--directory={(tmp_path / 'src').as_posix()}"]
        assert Path(results_file).is_absolute()
        return
    scanner = FerretScanScanner(context=context)
    scanner.dependencies_satisfied = True
    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_run_subprocess", return_value={"returncode": 0}) as run,
    ):
        scanner.scan(target=Path("src"), target_type="source")
    argv = run.call_args.kwargs["command"]
    assert (tmp_path / "src").as_posix() in argv or str(tmp_path / "src") in argv
