# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The builtin trivy scanner without the trivy binary.

Parsing is tested against REAL trivy output. ``trivy-0.69.3.vuln.sarif`` and
``trivy-0.69.3.all.sarif`` were written by the pinned trivy v0.69.3 scanning
the fixture repository as ``tests/utils/trivy_fixture.py`` materializes it (the
committed ``.fixture`` suffixes removed), from inside that directory::

    trivy fs --format sarif --scanners vuln --disable-telemetry --skip-db-update . \\
        --output trivy-0.69.3.vuln.sarif
    trivy fs --format sarif --scanners vuln,secret,misconfig,license \\
        --disable-telemetry --skip-db-update . --output trivy-0.69.3.all.sarif

against the vulnerability database published 2026-10-06T13:07:05Z. The only edit
is ``originalUriBaseIds.ROOTPATH``, rewritten to ``file:///src/`` so the capture
names no local path. The database grows daily, so the integration test
(``tests/integration/scanners/test_trivy_real_binary.py``) re-runs the binary
and checks the advisories this file is built around are still reported, rather
than an exact match.

Every parser assertion goes through ``_assert_expected``, and
``test_the_parser_assertions_fail_on_a_mutated_finding`` shows it fails when a
rule id, severity or location is wrong.

``trivy-0.75.0.shared-cve.sarif`` was written by trivy v0.75.0 for one CVE rated
differently in two packages. It scanned, from inside the directory, a Debian 11
tree whose ``var/lib/dpkg/status`` lists only ``binutils`` and ``gdb`` at version
``0.0.1-1``::

    trivy fs --format sarif --scanners vuln --skip-db-update --offline-scan . \
        --output trivy-0.75.0.shared-cve.sarif

against the database published 2026-10-10T18:59:50Z, and was trimmed to the two
rules both packages share (CVE-2014-9939, CVE-2014-8501) and their four results,
``ruleIndex`` renumbered and ``originalUriBaseIds.ROOTPATH`` rewritten as above.
Debian rates each CVE CRITICAL or HIGH for binutils and LOW for gdb; trivy writes
one rule per CVE, whose severity tag is the last result's (gdb's).
"""

from __future__ import annotations

import copy
import json
import os
import re
from pathlib import Path

import pytest

from tests.utils.trivy_fixture import materialize

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
    TrivyScanner,
    TrivyScannerConfig,
    TrivyScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
    TrivyRepoScannerConfig,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils import content_databases as cdb
from automated_security_helper.utils import content_db_staleness as staleness
from automated_security_helper.utils.config_trust import record_provenance
from automated_security_helper.utils.content_db_shared import EMPTY_TOOL_CONFIG
from automated_security_helper.utils.sarif_utils import (
    apply_suppressions_to_sarif,
    get_severity_metrics_from_sarif,
)
from automated_security_helper.utils.tool_config_dir import TOOL_CONFIG_DIR_PREFIX

pytestmark = pytest.mark.unit

PluginContext.model_rebuild()


def _ashs_own(scanner: TrivyScanner | TrivyRepoScanner, value: str) -> bool:
    """Whether ``value`` is a file, or empty directory, ASH made for this run's trivy.

    ``config/tool_config_trust.empty_tool_config`` and ``empty_tool_directory`` make
    it in a directory of the scanner run's own, outside the scanned tree.
    """
    path = Path(value)
    return not path.resolve().is_relative_to(
        Path(scanner.context.source_dir).resolve()
    ) and any(parent.name.startswith(TOOL_CONFIG_DIR_PREFIX) for parent in path.parents)


DATA = Path(__file__).parents[3] / "test_data" / "scanners" / "trivy"
VULN_SARIF = DATA / "trivy-0.69.3.vuln.sarif"
ALL_SARIF = DATA / "trivy-0.69.3.all.sarif"
SHARED_CVE_SARIF = DATA / "trivy-0.75.0.shared-cve.sarif"

#: What trivy v0.69.3 reports for the fixture's two manifests, as
#: (rule id, uri, start line, ASH severity, package, package_path). The negatives,
#: six 1.17.0 in requirements.txt and ms 2.1.3 in package-lock.json, are absent:
#: neither has a published advisory.
EXPECTED = {
    (
        "CVE-2021-23337",
        "package-lock.json",
        13,
        "HIGH",
        "lodash",
        "node_modules/lodash",
    ),
    ("CVE-2026-4800", "package-lock.json", 13, "HIGH", "lodash", "node_modules/lodash"),
    (
        "CVE-2020-28500",
        "package-lock.json",
        13,
        "MEDIUM",
        "lodash",
        "node_modules/lodash",
    ),
    (
        "CVE-2025-13465",
        "package-lock.json",
        13,
        "MEDIUM",
        "lodash",
        "node_modules/lodash",
    ),
    (
        "CVE-2026-2950",
        "package-lock.json",
        13,
        "MEDIUM",
        "lodash",
        "node_modules/lodash",
    ),
    ("CVE-2018-18074", "requirements.txt", 2, "HIGH", "requests", None),
    ("CVE-2023-32681", "requirements.txt", 2, "MEDIUM", "requests", None),
    ("CVE-2024-35195", "requirements.txt", 2, "MEDIUM", "requests", None),
    ("CVE-2024-47081", "requirements.txt", 2, "MEDIUM", "requests", None),
    ("CVE-2026-25645", "requirements.txt", 2, "MEDIUM", "requests", None),
}


def _raw(path: Path = VULN_SARIF) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _context(tmp_path: Path, config: AshConfig | None = None) -> PluginContext:
    source = tmp_path / "src"
    if not source.exists():
        # The lockfile is read to tie each npm result to its package copy.
        materialize(source)
    output = source / ".ash" / "ash_output"
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=config or AshConfig(),
    )


def _scanner(
    tmp_path: Path, *, operator: bool = False, overrides: tuple = (), **options
) -> TrivyScanner:
    """A scanner whose config came from the scanned tree unless ``operator`` is set."""
    options.setdefault("offline", False)
    context = _context(tmp_path)
    source = Path(context.source_dir)
    # operator=True: built from no file in the scanned tree. Otherwise from the
    # tree's .ash/.ash.yaml, judged against the defaults plus ``overrides``.
    record_provenance(
        context.config,
        in_tree=[] if operator else [source / ".ash" / ".ash.yaml"],
        trusted=AshConfig(),
        config_overrides=list(overrides),
    )
    # The config stands for the scan's own section, as a real scan builds it, so
    # a value the tree set is judged by the section and not as the caller's write.
    return TrivyScanner(
        context=context,
        config=TrivyScannerConfig(
            enabled=True, options=TrivyScannerConfigOptions(**options)
        ),
        config_from_context=True,
    )


def _parse(scanner: TrivyScanner, raw: dict) -> SarifReport:
    report = SarifReport.model_validate(raw)
    return scanner._post_process_sarif(report, [], scanner.context.source_dir)


def _findings(report: SarifReport) -> set:
    found = set()
    for result in report.get_all_results():
        physical = result.locations[0].physicalLocation.root
        props = result.properties
        found.add(
            (
                result.ruleId,
                physical.artifactLocation.uri,
                physical.region.startLine,
                getattr(props, "issue_severity", None),
                getattr(props, "package_name", None),
                getattr(props, "package_path", None),
            )
        )
    return found


def _assert_expected(report: SarifReport) -> None:
    assert _findings(report) == EXPECTED


@pytest.fixture(autouse=True)
def _online(monkeypatch):
    """No test here inherits ASH_OFFLINE, or a TRIVY_CONFIG, from the shell running it.

    This module is a probe subject (tests/unit/conftest.py PROBE_SUBJECT_MODULES) for
    trivy's version probe, which its staleness tests reach under their own doubles,
    so the unit guard's probe stand-ins are not installed here. No test here reads
    trivy's ``--help``, and building a trivy-repo scanner runs it (the default
    misconfig scanners, ``trivy_default_misconfig_scanners``), which the guard records
    as a tool start on a host without trivy. The memo it reads first is replaced
    the way the guard replaces it elsewhere, so no ``--help`` runs.
    """
    from tests.utils.tool_guard import _NoDefaultMisconfigScanners

    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        _trivy_scanner_base,
    )

    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.delenv("TRIVY_CONFIG", raising=False)
    monkeypatch.setattr(
        _trivy_scanner_base,
        "_DEFAULT_MISCONFIG_SCANNERS",
        _NoDefaultMisconfigScanners(),
    )


# --------------------------------------------------------------------------- #
# Defaults
# --------------------------------------------------------------------------- #


def test_trivy_is_a_builtin_on_by_default_beside_the_community_trivy_repo():
    assert TrivyScannerConfig().enabled is True
    assert TrivyRepoScannerConfig().enabled is True


def test_default_options_run_vuln_only_and_keep_unfixed():
    options = TrivyScannerConfigOptions(offline=False)
    assert options.scanners == ["vuln"]
    assert options.ignore_unfixed is False
    assert options.license_full is False
    assert options.disable_telemetry is True


def test_an_empty_scanner_list_is_refused():
    """trivy given no --scanners would run its own default set, not nothing."""
    with pytest.raises(ValueError):
        TrivyScannerConfigOptions(scanners=[])


# --------------------------------------------------------------------------- #
# The command line
# --------------------------------------------------------------------------- #


def _argv(scanner: TrivyScanner, target: Path) -> list[str]:
    final_args, results_file, env = scanner._execute_scan(target, "source", [])
    return final_args


def test_default_argv(tmp_path):
    scanner = _scanner(tmp_path)
    source = scanner.context.source_dir
    argv = _argv(scanner, source)
    results = scanner.results_dir / "source" / "results_sarif.sarif"
    written = {
        flag: next(a for a in argv if a.startswith(f"{flag}="))[len(flag) + 1 :]
        for flag in ("--module-dir", "--ignorefile", "--secret-config")
    }
    assert Path(written["--module-dir"]).name == "trivy-modules"
    assert Path(written["--ignorefile"]).name == "trivyignore-empty"
    assert Path(written["--secret-config"]).name == "trivy-secret-empty.yaml"
    assert all(_ashs_own(scanner, value) for value in written.values())
    assert argv == [
        "trivy",
        "fs",
        "--format",
        "sarif",
        "--scanners",
        "vuln",
        "--disable-telemetry",
        "--offline-scan",
        "--skip-version-check",
        "--timeout=1800s",
        "--skip-dirs=.ash/ash_output",
        f"--config={EMPTY_TOOL_CONFIG.as_posix()}",
        f"--module-dir={written['--module-dir']}",
        f"--ignorefile={written['--ignorefile']}",
        f"--secret-config={written['--secret-config']}",
        source.as_posix(),
        "--output",
        results.as_posix(),
    ]


def test_output_dir_outside_the_target_is_not_skipped(tmp_path):
    scanner = _scanner(tmp_path)
    elsewhere = tmp_path / "other"
    elsewhere.mkdir()
    assert not any(a.startswith("--skip-dirs") for a in _argv(scanner, elsewhere))


def test_an_unbounded_scan_timeout_is_unbounded_in_trivy_too(tmp_path):
    """null means unbounded in ASH. trivy has no "no deadline" value: it reads 0s as
    a deadline already passed, so ASH passes the longest duration trivy accepts."""
    scanner = _scanner(tmp_path, scan_timeout=None)
    argv = _argv(scanner, scanner.context.source_dir)
    assert [a for a in argv if a.startswith("--timeout")] == ["--timeout=2562047h"]


@pytest.mark.parametrize(
    "seconds, expected", [(1800, "1800s"), (0.4, "1s"), (1.5, "2s")]
)
def test_a_bounded_scan_timeout_never_becomes_trivys_zero(seconds, expected):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
        trivy_timeout,
    )

    assert trivy_timeout(seconds) == expected


def test_the_ash_config_and_ignore_files_are_empty(tmp_path):
    """The files ASH passes hold nothing, so the repository's own are simply unread."""
    scanner = _scanner(tmp_path)
    source = scanner.context.source_dir
    (source / "trivy.yaml").write_text("severity: [CRITICAL]\n", encoding="utf-8")
    (source / ".trivyignore").write_text("CVE-2018-18074\n", encoding="utf-8")
    argv = _argv(scanner, source)
    for flag, content in (
        ("--config=", ""),
        ("--ignorefile=", ""),
        # An empty secret config is a decode error in trivy; an empty mapping is not.
        ("--secret-config=", "{}\n"),
    ):
        value = next(a for a in argv if a.startswith(flag))[len(flag) :]
        assert Path(value).is_file() and Path(value).read_text() == content
        if flag == "--config=":
            # The empty config ASH ships, which no scanner can write.
            assert Path(value) == EMPTY_TOOL_CONFIG
        else:
            assert _ashs_own(scanner, value)


@pytest.mark.parametrize(
    "option, flag, name",
    [
        ("config_file", "--config", "trivy.yaml"),
        ("ignore_file", "--ignorefile", ".trivyignore"),
        ("secret_config_file", "--secret-config", "trivy-secret.yaml"),
    ],
)
def test_an_operator_chosen_trivy_file_is_passed(tmp_path, option, flag, name):
    chosen = tmp_path / "operator" / name
    chosen.parent.mkdir()
    chosen.write_text("", encoding="utf-8")
    scanner = _scanner(tmp_path, operator=True, **{option: str(chosen)})
    argv = _argv(scanner, scanner.context.source_dir)
    assert f"{flag}={chosen.resolve().as_posix()}" in argv


_INPUT_FILES = [
    ("ignore_file", "--ignorefile", ".trivyignore", "TRIVY_IGNOREFILE"),
    (
        "secret_config_file",
        "--secret-config",
        "trivy-secret.yaml",
        "TRIVY_SECRET_CONFIG",
    ),
]


@pytest.mark.parametrize("option, flag, name, env", _INPUT_FILES)
@pytest.mark.parametrize("operator", [False, True])
def test_an_ignore_or_secret_file_inside_the_tree_is_never_passed(
    tmp_path, caplog, monkeypatch, option, flag, name, env, operator
):
    """Either can drop findings, so one inside the scanned tree is refused whoever
    names it, as trivy-repo refuses it (TrivyScannerBase._trivy_input_file)."""
    from automated_security_helper.config.path_trust import (
        reset_path_refusal_warnings,
    )

    reset_path_refusal_warnings()
    monkeypatch.delenv(env, raising=False)
    probe = _scanner(tmp_path)
    (probe.context.source_dir / name).write_text("", encoding="utf-8")
    scanner = _scanner(tmp_path, operator=operator, **{option: name})
    with caplog.at_level("WARNING"):
        argv = _argv(scanner, scanner.context.source_dir)
    (value,) = [a[len(flag) + 1 :] for a in argv if a.startswith(f"{flag}=")]
    assert _ashs_own(scanner, value)
    assert f"scanners.trivy.options.{option}" in caplog.text


@pytest.mark.parametrize("option, flag, name, env", _INPUT_FILES)
def test_an_operator_ignore_or_secret_file_outside_the_tree_is_passed(
    tmp_path, monkeypatch, option, flag, name, env
):
    chosen = tmp_path / "outside" / name
    chosen.parent.mkdir()
    chosen.write_text("", encoding="utf-8")
    monkeypatch.delenv(env, raising=False)
    from_option = _scanner(tmp_path, operator=True, **{option: str(chosen)})
    assert f"{flag}={chosen.resolve().as_posix()}" in _argv(
        from_option, from_option.context.source_dir
    )
    # The same value from the scanned tree's config is not the operator's.
    from_tree = _scanner(tmp_path, **{option: str(chosen)})
    assert f"{flag}={chosen.resolve().as_posix()}" not in _argv(
        from_tree, from_tree.context.source_dir
    )
    monkeypatch.setenv(env, str(chosen))
    from_env = _scanner(tmp_path)
    assert f"{flag}={chosen.resolve().as_posix()}" in _argv(
        from_env, from_env.context.source_dir
    )


_MODULE_CONFIG = "module:\n  dir: ./trivy-modules\n  enable-modules: [planted]\n"


@pytest.mark.parametrize("spelling", ["relative", "absolute"])
def test_a_trivy_config_set_by_the_scanned_tree_is_not_passed(
    tmp_path, caplog, spelling
):
    probe = _scanner(tmp_path)
    planted = probe.context.source_dir / "trivy.yaml"
    planted.write_text(_MODULE_CONFIG, encoding="utf-8")
    value = "trivy.yaml" if spelling == "relative" else planted.as_posix()
    scanner = _scanner(tmp_path, config_file=value)

    with caplog.at_level("WARNING"):
        argv = _argv(scanner, scanner.context.source_dir)

    (config_arg,) = [a for a in argv if a.startswith("--config=")]
    assert config_arg == f"--config={EMPTY_TOOL_CONFIG.as_posix()}"
    assert planted.resolve().as_posix() not in " ".join(argv)
    assert "scanners.trivy.options.config_file" in caplog.text


def test_the_operator_cannot_name_a_trivy_config_inside_the_tree(tmp_path):
    probe = _scanner(tmp_path)
    planted = probe.context.source_dir / "trivy.yaml"
    planted.write_text(_MODULE_CONFIG, encoding="utf-8")
    scanner = _scanner(tmp_path, operator=True, config_file=planted.as_posix())

    argv = _argv(scanner, scanner.context.source_dir)

    assert planted.resolve().as_posix() not in " ".join(argv)


def test_an_operator_override_names_a_trivy_config_outside_the_tree(tmp_path):
    chosen = tmp_path / "operator" / "trivy.yaml"
    chosen.parent.mkdir()
    chosen.write_text("", encoding="utf-8")
    scanner = _scanner(
        tmp_path,
        overrides=(f"scanners.trivy.options.config_file={chosen}",),
        config_file=str(chosen),
    )

    argv = _argv(scanner, scanner.context.source_dir)

    assert f"--config={chosen.resolve().as_posix()}" in argv


@pytest.mark.skipif(os.name == "nt", reason="symlinks")
@pytest.mark.parametrize(
    "option, flag, ash_name",
    [
        ("config_file", "--config", EMPTY_TOOL_CONFIG.name),
        ("ignore_file", "--ignorefile", None),
        ("secret_config_file", "--secret-config", None),
    ],
)
@pytest.mark.parametrize("shape", ["file", "directory"])
def test_the_operator_cannot_name_a_path_in_the_tree_that_links_out_of_it(
    tmp_path, caplog, monkeypatch, option, flag, ash_name, shape
):
    """A path written in the tree goes where the tree's links send it, so the tree
    would choose which file trivy reads: a trivy.yaml that loads modules, or an
    ignore file that drops findings. trivy gets ASH's own file instead."""
    for env in ("TRIVY_CONFIG", "TRIVY_IGNOREFILE", "TRIVY_SECRET_CONFIG"):
        monkeypatch.delenv(env, raising=False)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "trivy.yaml").write_text(_MODULE_CONFIG, encoding="utf-8")
    source = _scanner(tmp_path).context.source_dir
    if shape == "file":
        (source / "ci").mkdir()
        (source / "ci" / "trivy.yaml").symlink_to(outside / "trivy.yaml")
    else:
        (source / "ci").symlink_to(outside, target_is_directory=True)
    scanner = _scanner(tmp_path, operator=True, **{option: "ci/trivy.yaml"})

    with caplog.at_level("WARNING"):
        argv = _argv(scanner, scanner.context.source_dir)

    assert (outside / "trivy.yaml").resolve().as_posix() not in " ".join(argv)
    (value,) = [a[len(flag) + 1 :] for a in argv if a.startswith(f"{flag}=")]
    if ash_name is not None:
        # The config ASH ships rather than one it writes for this run.
        assert Path(value) == EMPTY_TOOL_CONFIG and value.endswith(f"/{ash_name}")
    else:
        assert _ashs_own(scanner, value)
    assert f"Ignoring scanners.trivy.options.{option}" in caplog.text
    assert "symbolic link" in caplog.text


@pytest.mark.parametrize(
    ("option", "scanners"),
    [
        pytest.param("config_file", ["vuln"], id="config_file"),
        pytest.param("ignore_file", ["vuln"], id="ignore_file"),
        # Only a scan that runs the secret scanner reads the secret config; a
        # vulnerability-only scan gets ASH's empty file with a warning instead
        # (TrivyScannerBase._secret_config_file).
        pytest.param("secret_config_file", ["vuln", "secret"], id="secret_config_file"),
    ],
)
def test_a_configured_trivy_file_that_does_not_exist_fails_the_scan(
    tmp_path, option, scanners
):
    scanner = _scanner(
        tmp_path,
        operator=True,
        scanners=scanners,
        **{option: str(tmp_path / "operator" / "nope.yaml")},
    )
    with pytest.raises(ScannerError, match=option):
        _argv(scanner, scanner.context.source_dir)


def test_a_vulnerability_only_scan_warns_about_a_missing_secret_config_and_runs(
    tmp_path, caplog, monkeypatch
):
    """The other half of the ``secret_config_file`` case above: a scan without the
    ``secret`` scanner never opens the secret config, so a configured file that does
    not exist does not fail it. trivy gets ASH's own empty file and the key is named
    in a warning (``TrivyScannerBase._secret_config_file``, ``required`` false)."""
    monkeypatch.delenv("TRIVY_SECRET_CONFIG", raising=False)
    scanner = _scanner(
        tmp_path,
        operator=True,
        scanners=["vuln"],
        secret_config_file=str(tmp_path / "operator" / "nope.yaml"),
    )

    with caplog.at_level("WARNING"):
        argv = _argv(scanner, scanner.context.source_dir)

    (value,) = [
        a[len("--secret-config=") :] for a in argv if a.startswith("--secret-config=")
    ]
    assert _ashs_own(scanner, value)
    assert Path(value).name == "trivy-secret-empty.yaml"
    assert (
        "scanners.trivy.options.secret_config_file does not name a file" in caplog.text
    )
    assert "do not include secret" in caplog.text


@pytest.mark.parametrize("cls", [TrivyScanner, TrivyRepoScanner])
def test_both_scanners_install_the_pinned_trivy(tmp_path, cls):
    from automated_security_helper.utils.download_utils import (
        pinned_tool_install_commands,
    )

    expected = pinned_tool_install_commands("trivy")
    assert expected
    scanner = cls(context=_context(tmp_path))
    for key, value in expected.items():
        assert scanner.custom_install_commands[key] == value


def test_options_become_flags(tmp_path):
    scanner = _scanner(
        tmp_path,
        operator=True,
        scanners=["vuln", "license"],
        license_full=True,
        ignore_unfixed=True,
        disable_telemetry=False,
        severity_threshold="HIGH",
    )
    argv = _argv(scanner, scanner.context.source_dir)
    assert argv[argv.index("--scanners") + 1] == "vuln,license"
    assert "--license-full" in argv
    assert "--ignore-unfixed" in argv
    assert "--disable-telemetry" not in argv
    # The threshold gates the verdict after the scan; trivy reports everything.
    assert not [a for a in argv if a.startswith("--severity")]


@pytest.mark.parametrize("threshold", ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
@pytest.mark.parametrize("kind", ["trivy", "trivy-repo"])
def test_a_severity_threshold_is_never_a_trivy_filter(tmp_path, kind, threshold):
    """trivy --severity drops lower findings before ASH sees them, so they would be
    neither reported nor counted. ASH applies the threshold, as for every scanner."""
    if kind == "trivy":
        scanner = _scanner(tmp_path, operator=True, severity_threshold=threshold)
    else:
        scanner = _repo_scanner(tmp_path, severity_threshold=threshold)
    args = scanner._resolve_arguments(target="/t", results_file="/r.sarif")
    assert not [a for a in args if a.startswith("--severity")]


@pytest.mark.parametrize("chosen", [["license"], ["secret"], ["vuln", "secret"]])
def test_a_scanner_set_from_the_scanned_tree_is_ignored(tmp_path, caplog, chosen):
    """``scanners: [license]`` in the tree's config turned vuln off: no vulnerability
    findings and no database measured, with nothing in the report saying so."""
    caplog.set_level("WARNING")
    scanner = _scanner(tmp_path, scanners=chosen)
    argv = _argv(scanner, scanner.context.source_dir)
    assert argv[argv.index("--scanners") + 1] == "vuln"
    assert [e.name for e in scanner.content_databases_in_use()] == ["trivy-db"]
    assert "scanners.trivy.options.scanners" in caplog.text


@pytest.mark.parametrize("how", ["operator", "override"])
def test_the_operator_chooses_the_scanner_set(tmp_path, how):
    if how == "operator":
        scanner = _scanner(tmp_path, operator=True, scanners=["license"])
    else:
        scanner = _scanner(
            tmp_path,
            overrides=('scanners.trivy.options.scanners=["license"]',),
            scanners=["license"],
        )
    argv = _argv(scanner, scanner.context.source_dir)
    assert argv[argv.index("--scanners") + 1] == "license"
    assert scanner.content_databases_in_use() == []


def test_the_default_scanner_set_needs_no_operator(tmp_path, caplog):
    caplog.set_level("WARNING")
    scanner = _scanner(tmp_path, scanners=["vuln"])
    argv = _argv(scanner, scanner.context.source_dir)
    assert argv[argv.index("--scanners") + 1] == "vuln"
    assert "scanners.trivy.options.scanners" not in caplog.text


def test_ignore_unfixed_is_warned_about(tmp_path, caplog):
    caplog.set_level("WARNING")
    _scanner(tmp_path, ignore_unfixed=True)
    assert "withheld" in caplog.text


@pytest.mark.parametrize("how", ["option", "env"])
def test_offline_skips_every_update(tmp_path, monkeypatch, how):
    if how == "env":
        # The --offline CLI path: ASH_OFFLINE is set after the option's default
        # was computed, so the option alone still says online.
        monkeypatch.setenv("ASH_OFFLINE", "YES")
        scanner = _scanner(tmp_path, offline=False)
    else:
        scanner = _scanner(tmp_path, offline=True)
    argv = _argv(scanner, scanner.context.source_dir)
    for flag in (
        "--skip-db-update",
        "--skip-java-db-update",
        "--offline-scan",
        "--skip-check-update",
    ):
        assert flag in argv


def test_online_passes_no_update_flags(tmp_path):
    argv = _argv(_scanner(tmp_path), tmp_path / "src")
    assert "--skip-db-update" not in argv


@pytest.mark.parametrize("offline", [False, True])
@pytest.mark.parametrize("kind", ["trivy", "trivy-repo"])
def test_every_scan_is_offline_for_package_registries(tmp_path, offline, kind):
    """trivy scans never contact package registries (a pom.xml's <repositories>,
    Maven Central); the database refresh is a separate step."""
    if kind == "trivy":
        scanner = _scanner(tmp_path, offline=offline)
    else:
        scanner = _repo_scanner(tmp_path, offline=offline)
    args = scanner._resolve_arguments(target="/t", results_file="/r.sarif")
    assert args.count("--offline-scan") == 1


@pytest.mark.parametrize("offline", [False, True])
@pytest.mark.parametrize("kind", ["trivy", "trivy-repo"])
def test_every_scan_turns_trivys_version_check_off(
    tmp_path, monkeypatch, offline, kind
):
    """Online by --skip-version-check; offline by TRIVY_SKIP_VERSION_CHECK in trivy's
    environment (utils/offline_tool_env.py), which a trivy too old to know the flag
    ignores, where it would refuse the whole command over the flag."""
    if kind == "trivy":
        scanner = _scanner(tmp_path, offline=offline)
    else:
        scanner = _repo_scanner(tmp_path, offline=offline)
    args = scanner._resolve_arguments(target="/t", results_file="/r.sarif")
    assert args.count("--skip-version-check") == (0 if offline else 1)
    if not offline:
        return
    envs = []

    def run(*_args, **kwargs):
        envs.append(kwargs.get("env") or {})
        return {"returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(
        "automated_security_helper.utils.subprocess_utils."
        "run_command_with_output_handling",
        run,
    )
    scanner._run_subprocess(command=list(args), results_dir=tmp_path / "results")
    (env,) = envs
    assert env.get("TRIVY_SKIP_VERSION_CHECK") == "true"


def test_a_stale_report_is_removed_before_the_run(tmp_path):
    scanner = _scanner(tmp_path)
    stale = scanner.results_dir / "source" / "results_sarif.sarif"
    stale.parent.mkdir(parents=True)
    stale.write_text("{}")
    _argv(scanner, scanner.context.source_dir)
    assert not stale.exists()


def test_a_failing_exit_code_refuses_even_a_present_report(tmp_path):
    scanner = _scanner(tmp_path)
    report = tmp_path / "r.sarif"
    report.write_text(VULN_SARIF.read_text(encoding="utf-8"), encoding="utf-8")
    scanner.exit_code = 1
    with pytest.raises(ScannerError, match="trivy exited 1"):
        scanner._read_results_file(report)
    scanner.exit_code = 0
    assert scanner._read_results_file(report)["runs"]


def _runs_through_the_base_class(monkeypatch, codes: list) -> list:
    """Replace only the process call: one exit code per run, with a report written
    for a run that exits 0. ``_run_subprocess`` and the base class's exit-code
    accumulation (it keeps the worst code across calls) run for real."""
    remaining = iter(codes)
    commands = []

    def run(**kwargs):
        code = next(remaining)
        command = kwargs["command"]
        commands.append(command)
        if code == 0:
            out = Path(command[command.index("--output") + 1])
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(VULN_SARIF.read_text(encoding="utf-8"), encoding="utf-8")
        return {"returncode": code, "stdout": "", "stderr": ""}

    monkeypatch.setattr(
        "automated_security_helper.utils.subprocess_utils."
        "run_command_with_output_handling",
        run,
    )
    return commands


def _converted(scanner) -> Path:
    converted = Path(scanner.context.work_dir) / "archive.zip"
    converted.mkdir(parents=True)
    (converted / "requirements.txt").write_text("requests==2.19.0\n")
    return Path(scanner.context.work_dir)


def test_each_target_is_judged_by_its_own_exit_code(tmp_path, monkeypatch):
    """ScannerExecutor runs one instance over the source, then the converted target.
    A source run that fails (exit 1) must not make a clean converted run fail too.

    The binary and, offline, its database are supplied here, so the dependency
    check passes whatever $HOME holds: without them it looked for trivy under
    ``$HOME/.ash/bin`` and ran ``trivy version`` against the cache under $HOME.
    """
    _found_binary(monkeypatch)
    monkeypatch.setattr(staleness, "_built_from_trivy", lambda ctx: (None, "x"))
    scanner = _scanner(tmp_path, offline=True)
    converted = _converted(scanner)
    _runs_through_the_base_class(monkeypatch, [1, 0])

    # The shared grading refuses the run before its report is read
    # (success_exit_codes), as it does trivy-repo's below.
    with pytest.raises(ScannerError, match="exited with code 1"):
        scanner.scan(scanner.context.source_dir, "source", [])
    report = scanner.scan(converted, "converted", [])

    assert scanner.exit_code == 0
    assert report.runs[0].invocations[0].exitCode == 0
    assert report.get_all_results()


def test_trivy_repo_records_each_targets_own_exit_code(tmp_path, monkeypatch):
    from automated_security_helper.base import scanner_plugin

    monkeypatch.setattr(scanner_plugin, "find_executable", lambda name: f"/bin/{name}")
    scanner = _repo_scanner(tmp_path, offline=True)
    scanner.dependencies_satisfied = True
    monkeypatch.setattr(scanner, "_pre_scan", lambda **kw: True)
    converted = _converted(scanner)
    _runs_through_the_base_class(monkeypatch, [1, 0])

    # trivy-repo accepts only 0 (success_exit_codes): a run that exits 1 is an
    # error, and its results file is not read.
    with pytest.raises(ScannerError, match="exited with code 1"):
        scanner.scan(target=scanner.context.source_dir, target_type="source")
    report = scanner.scan(target=converted, target_type="converted")

    assert scanner.exit_code == 0
    assert report.runs[0].invocations[0].exitCode == 0


def test_the_community_plugin_command_line_is_unchanged(tmp_path):
    """trivy-repo's flags, in order, as before the shared base existed, plus
    --offline-scan, which every trivy scan gets, and --skip-version-check, which
    every online one gets."""
    scanner = TrivyRepoScanner(
        context=_context(tmp_path), config=TrivyRepoScannerConfig()
    )
    args = scanner._resolve_arguments(target="/t", results_file="/r.sarif")
    assert args == [
        "trivy",
        "repository",
        "--format",
        "sarif",
        "--scanners",
        "vuln,secret,misconfig,license",
        "--license-full",
        "--ignore-unfixed",
        "--disable-telemetry",
        "--offline-scan",
        "--skip-version-check",
        "/t",
        "--output",
        "/r.sarif",
    ]


# --------------------------------------------------------------------------- #
# Offline without a database, and the content database
# --------------------------------------------------------------------------- #


def _found_binary(monkeypatch):
    from automated_security_helper.base import scanner_plugin

    monkeypatch.setattr(scanner_plugin, "find_executable", lambda name: f"/bin/{name}")


def test_offline_without_a_database_is_missing_with_the_reason(tmp_path, monkeypatch):
    _found_binary(monkeypatch)

    def no_db(ctx):
        raise ValueError("no trivy database was found")

    monkeypatch.setattr(staleness, "_built_from_trivy", no_db)
    scanner = _scanner(tmp_path, offline=True)
    assert scanner.validate_plugin_dependencies() is False
    assert "no vulnerability database" in scanner.dependency_unavailable_reason
    assert "no trivy database was found" in scanner.dependency_unavailable_reason


def _offline_probe_config(tmp_path, monkeypatch, **scanner_kwargs):
    """The --config the offline database check would pass ``trivy version``."""
    _found_binary(monkeypatch)
    seen = []

    def probe(ctx):
        seen.append(ctx.config_file)
        return (None, "x")

    monkeypatch.setattr(staleness, "_built_from_trivy", probe)
    scanner = _scanner(tmp_path, offline=True, **scanner_kwargs)
    assert scanner.validate_plugin_dependencies() is True
    (config_file,) = seen
    return config_file


def test_the_offline_check_reads_through_the_operators_trivy_config(
    tmp_path, monkeypatch
):
    """The check runs before the scan chose its --config, so it asks for the file the
    scan will pass: the operator's, set by --config-overrides, outside the tree."""
    chosen = tmp_path / "operator" / "trivy.yaml"
    chosen.parent.mkdir()
    chosen.write_text("cache:\n  dir: /operator/cache\n", encoding="utf-8")
    config_file = _offline_probe_config(
        tmp_path,
        monkeypatch,
        overrides=(f"scanners.trivy.options.config_file={chosen}",),
        config_file=str(chosen),
    )
    assert config_file is not None and Path(config_file) == chosen.resolve()


def test_the_offline_check_ignores_a_trivy_config_the_tree_sets(tmp_path, monkeypatch):
    chosen = tmp_path / "elsewhere" / "trivy.yaml"
    chosen.parent.mkdir()
    chosen.write_text("cache:\n  dir: /tree/cache\n", encoding="utf-8")
    assert _offline_probe_config(tmp_path, monkeypatch, config_file=str(chosen)) is None


def test_the_offline_check_ignores_a_trivy_config_that_does_not_exist(
    tmp_path, monkeypatch
):
    """It falls back to the probe's own empty config; the scan itself then fails on
    the missing file, with the path."""
    missing = tmp_path / "operator" / "trivy.yaml"
    config_file = _offline_probe_config(
        tmp_path,
        monkeypatch,
        overrides=(f"scanners.trivy.options.config_file={missing}",),
        config_file=str(missing),
    )
    assert config_file is None


def test_offline_with_a_database_is_satisfied(tmp_path, monkeypatch):
    _found_binary(monkeypatch)
    monkeypatch.setattr(staleness, "_built_from_trivy", lambda ctx: (None, "x"))
    assert _scanner(tmp_path, offline=True).validate_plugin_dependencies() is True


def test_offline_without_vuln_needs_no_database(tmp_path, monkeypatch):
    _found_binary(monkeypatch)

    def boom(ctx):  # pragma: no cover - must not be reached
        raise AssertionError("probed a database the scan does not read")

    monkeypatch.setattr(staleness, "_built_from_trivy", boom)
    scanner = _scanner(tmp_path, operator=True, offline=True, scanners=["misconfig"])
    assert scanner.validate_plugin_dependencies() is True


def test_online_does_not_probe_the_database(tmp_path, monkeypatch):
    """Online, trivy downloads a database itself; there is nothing to require."""
    _found_binary(monkeypatch)

    def boom(ctx):  # pragma: no cover - must not be reached
        raise AssertionError("probed online")

    monkeypatch.setattr(staleness, "_built_from_trivy", boom)
    assert _scanner(tmp_path).validate_plugin_dependencies() is True


def test_missing_binary_is_reported_unavailable(tmp_path, monkeypatch):
    from automated_security_helper.base import scanner_plugin

    monkeypatch.setattr(scanner_plugin, "find_executable", lambda name: None)
    assert _scanner(tmp_path).validate_plugin_dependencies() is False


def test_the_vulnerability_database_is_measured_when_vuln_runs(tmp_path):
    assert [e.name for e in _scanner(tmp_path).content_databases_in_use()] == [
        "trivy-db"
    ]
    secret_only = _scanner(tmp_path, operator=True, scanners=["secret"])
    assert secret_only.content_databases_in_use() == []


def test_the_registry_declares_the_database_for_both_trivy_scanners():
    entry = cdb.get("trivy-db")
    # Declared for trivy-repo, the Trivy plugin's original scanner, so its messages
    # and attribution are unchanged; trivy reads the same database.
    assert entry.scanner == "trivy-repo"
    assert entry.readers == ("trivy-repo", "trivy")


@pytest.mark.parametrize(
    "reader, recorded",
    [("trivy", "trivy"), ("trivy-repo", "trivy-repo"), ("x", "trivy-repo")],
)
def test_a_measurement_is_recorded_under_the_scanner_that_read_it(reader, recorded):
    record = staleness.measure(
        cdb.get("trivy-db"),
        staleness.ProbeContext(env={}),
        cdb.STALENESS_FAIL,
        scanner=reader,
    )
    assert record.scanner == recorded


# --------------------------------------------------------------------------- #
# Parsing real output
# --------------------------------------------------------------------------- #


def test_captured_report_parses_to_the_expected_findings(tmp_path):
    _assert_expected(_parse(_scanner(tmp_path), _raw()))


def _set_rule_tag(raw: dict, rule_id: str, severity: str) -> None:
    for rule in raw["runs"][0]["tool"]["driver"]["rules"]:
        if rule["id"] == rule_id:
            tags = rule["properties"]["tags"]
            rule["properties"]["tags"] = [
                t
                for t in tags
                if t not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
            ] + [severity]


_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}


def _set_severity(raw: dict, rule_id: str, severity: str) -> None:
    """Rate *rule_id* as trivy would write it: each result's message line and level,
    and the rule's tag."""
    _set_rule_tag(raw, rule_id, severity)
    for result in raw["runs"][0]["results"]:
        if result["ruleId"] == rule_id:
            text = result["message"]["text"]
            result["message"]["text"] = re.sub(
                r"^Severity: \S+$", f"Severity: {severity}", text, flags=re.MULTILINE
            )
            result["level"] = _SARIF_LEVEL.get(severity, "note")


def _strip_result_severity(raw: dict, rule_id: str) -> None:
    """A result with no severity line of its own, leaving only its rule's tag."""
    for result in raw["runs"][0]["results"]:
        if result["ruleId"] == rule_id:
            text = result["message"]["text"]
            result["message"]["text"] = re.sub(
                r"^Severity: \S+\n", "", text, flags=re.MULTILINE
            )


def _mutate_rule_id(raw):
    raw["runs"][0]["results"][0]["ruleId"] = "CVE-0000-0000"


def _mutate_line(raw):
    loc = raw["runs"][0]["results"][-1]["locations"][0]["physicalLocation"]
    loc["region"]["startLine"] = 3


def _mutate_uri(raw):
    loc = raw["runs"][0]["results"][-1]["locations"][0]["physicalLocation"]
    loc["artifactLocation"]["uri"] = "other.txt"


def _mutate_severity(raw):
    _set_severity(raw, "CVE-2018-18074", "LOW")


@pytest.mark.parametrize(
    "mutate", [_mutate_rule_id, _mutate_line, _mutate_uri, _mutate_severity]
)
def test_the_parser_assertions_fail_on_a_mutated_finding(tmp_path, mutate):
    raw = copy.deepcopy(_raw())
    mutate(raw)
    with pytest.raises(AssertionError):
        _assert_expected(_parse(_scanner(tmp_path), raw))


def test_trivys_severity_wins_over_the_cvss_score(tmp_path):
    """CVE-2023-32681 has CVSS 6.1 (MEDIUM band); rated CRITICAL by trivy, it is CRITICAL."""
    raw = _raw()
    _set_severity(raw, "CVE-2023-32681", "CRITICAL")
    report = _parse(_scanner(tmp_path), raw)
    severities = {
        r.ruleId: r.properties.issue_severity for r in report.get_all_results()
    }
    assert severities["CVE-2023-32681"] == "CRITICAL"
    counts = get_severity_metrics_from_sarif(report, _scanner(tmp_path).context)
    assert (counts.critical, counts.high, counts.medium) == (1, 3, 6)


def test_unknown_severity_falls_back_to_the_generic_mapping(tmp_path):
    raw = _raw()
    _set_severity(raw, "CVE-2023-32681", "UNKNOWN")
    report = _parse(_scanner(tmp_path), raw)
    result = next(r for r in report.get_all_results() if r.ruleId == "CVE-2023-32681")
    assert getattr(result.properties, "issue_severity", None) is None
    counts = get_severity_metrics_from_sarif(report, _scanner(tmp_path).context)
    # CVSS 6.1 -> MEDIUM, as ASH maps any SARIF security-severity.
    assert (counts.high, counts.medium) == (3, 7)


def test_misconfiguration_results_take_trivys_severity_too(tmp_path):
    report = _parse(_scanner(tmp_path), _raw(ALL_SARIF))
    by_rule = {r.ruleId: r.properties.issue_severity for r in report.get_all_results()}
    assert (by_rule["DS-0001"], by_rule["DS-0002"], by_rule["DS-0026"]) == (
        "MEDIUM",
        "HIGH",
        "LOW",
    )


def test_each_result_takes_its_own_severity_not_its_rules(tmp_path):
    """One CVE, two packages, two ratings: trivy's rule carries only the last."""
    report = _parse(_scanner(tmp_path), _raw(SHARED_CVE_SARIF))
    rated = {
        (r.ruleId, r.properties.package_name): r.properties.issue_severity
        for r in report.get_all_results()
    }
    assert rated == {
        ("CVE-2014-9939", "binutils"): "CRITICAL",
        ("CVE-2014-9939", "gdb"): "LOW",
        ("CVE-2014-8501", "binutils"): "HIGH",
        ("CVE-2014-8501", "gdb"): "LOW",
    }
    rules = _raw(SHARED_CVE_SARIF)["runs"][0]["tool"]["driver"]["rules"]
    assert [r["properties"]["tags"][-1] for r in rules] == ["LOW", "LOW"]
    counts = get_severity_metrics_from_sarif(report, _scanner(tmp_path).context)
    assert (counts.critical, counts.high, counts.low) == (1, 1, 2)


def test_a_result_without_its_own_severity_takes_the_rules_tag(tmp_path):
    """License results carry no severity line; their rule is per package and license."""
    raw = _raw()
    _strip_result_severity(raw, "CVE-2018-18074")
    report = _parse(_scanner(tmp_path), raw)
    found = next(r for r in report.get_all_results() if r.ruleId == "CVE-2018-18074")
    assert found.properties.issue_severity == "HIGH"


def test_a_rule_tag_the_results_level_contradicts_gives_no_verdict(tmp_path):
    """The tag is the last result's rating; a result whose own level differs is not it."""
    raw = _raw(SHARED_CVE_SARIF)
    for result in raw["runs"][0]["results"]:
        _strip = re.sub(
            r"^Severity: \S+\n", "", result["message"]["text"], flags=re.MULTILINE
        )
        result["message"]["text"] = _strip
    report = _parse(_scanner(tmp_path), raw)
    rated = {
        (r.ruleId, r.properties.package_name): getattr(
            r.properties, "issue_severity", None
        )
        for r in report.get_all_results()
    }
    assert rated[("CVE-2014-9939", "gdb")] == "LOW"
    assert rated[("CVE-2014-9939", "binutils")] is None


def test_the_severity_counts_match_trivys_ratings(tmp_path):
    scanner = _scanner(tmp_path)
    counts = get_severity_metrics_from_sarif(_parse(scanner, _raw()), scanner.context)
    assert (counts.critical, counts.high, counts.medium, counts.low) == (0, 3, 7, 0)


# --------------------------------------------------------------------------- #
# Suppressions
# --------------------------------------------------------------------------- #


def _suppressed(tmp_path, suppressions) -> set:
    config = AshConfig(global_settings={"suppressions": suppressions})
    scanner = _scanner(tmp_path)
    context = _context(tmp_path, config)
    report = apply_suppressions_to_sarif(_parse(scanner, _raw()), context)
    return {r.ruleId for r in report.get_all_results() if r.suppressions}


def test_no_suppressions_suppresses_nothing(tmp_path):
    assert _suppressed(tmp_path, []) == set()


def test_a_rule_suppression_suppresses_that_advisory(tmp_path):
    assert _suppressed(
        tmp_path,
        [AshSuppression(rule_id="CVE-2018-18074", path="requirements.txt", reason="t")],
    ) == {"CVE-2018-18074"}


def test_a_line_pinned_suppression_on_the_wrong_line_suppresses_nothing(tmp_path):
    assert (
        _suppressed(
            tmp_path,
            [
                AshSuppression(
                    rule_id="CVE-2018-18074",
                    path="requirements.txt",
                    line_start=3,
                    line_end=3,
                    reason="t",
                )
            ],
        )
        == set()
    )


def test_a_path_suppression_suppresses_the_whole_manifest(tmp_path):
    assert _suppressed(
        tmp_path, [AshSuppression(path="package-lock.json", reason="t")]
    ) == {
        "CVE-2021-23337",
        "CVE-2026-4800",
        "CVE-2020-28500",
        "CVE-2025-13465",
        "CVE-2026-2950",
    }


def test_a_package_scoped_suppression_matches_only_that_copy(tmp_path):
    hit = _suppressed(
        tmp_path,
        [
            AshSuppression(
                rule_id="CVE-2021-23337",
                path="package-lock.json",
                package_name="lodash",
                package_version="4.17.20",
                package_path="node_modules/lodash",
                reason="t",
            )
        ],
    )
    assert hit == {"CVE-2021-23337"}
    miss = _suppressed(
        tmp_path,
        [
            AshSuppression(
                rule_id="CVE-2021-23337",
                path="package-lock.json",
                package_name="lodash",
                package_version="4.17.20",
                package_path="node_modules/other/node_modules/lodash",
                reason="t",
            )
        ],
    )
    assert miss == set()


# --------------------------------------------------------------------------- #
# trivy-repo through the shared base: what must not change
# --------------------------------------------------------------------------- #


def _repo_scanner(tmp_path: Path, **options) -> TrivyRepoScanner:
    from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
        TrivyRepoScannerConfigOptions,
    )

    return TrivyRepoScanner(
        context=_context(tmp_path),
        config=TrivyRepoScannerConfig(options=TrivyRepoScannerConfigOptions(**options)),
        config_from_context=True,
    )


def test_the_community_plugin_offline_command_line_is_unchanged(tmp_path):
    """Every flag trivy-repo can emit, in the order it always emitted them, with
    --offline-scan, which every trivy scan gets, ahead of the offline flags. Offline
    there is no --skip-version-check: TRIVY_SKIP_VERSION_CHECK turns that check off
    (test_every_scan_turns_trivys_version_check_off)."""
    scanner = _repo_scanner(tmp_path, offline=True, severity_threshold="MEDIUM")
    args = scanner._resolve_arguments(target="/t", results_file="/r.sarif")
    assert args == [
        "trivy",
        "repository",
        "--format",
        "sarif",
        "--scanners",
        "vuln,secret,misconfig,license",
        "--license-full",
        "--ignore-unfixed",
        "--disable-telemetry",
        "--offline-scan",
        "--skip-db-update",
        "--skip-java-db-update",
        "--skip-check-update",
        "/t",
        "--output",
        "/r.sarif",
    ]


def test_the_community_plugin_follows_ash_offline_mode(tmp_path, monkeypatch):
    """trivy-repo and trivy read offline the same way (_scanner_offline, #748).

    ``offline: false`` follows ASH: under ASH_OFFLINE trivy-repo skips its
    database update even though its own option says false, and with ASH online
    and the option false it does not.
    """
    monkeypatch.setenv("ASH_OFFLINE", "YES")
    scanner = _repo_scanner(tmp_path, offline=False)
    args = scanner._resolve_arguments(target="/t", results_file="/r.sarif")
    assert "--skip-db-update" in args

    monkeypatch.delenv("ASH_OFFLINE")
    scanner = _repo_scanner(tmp_path, offline=False)
    args = scanner._resolve_arguments(target="/t", results_file="/r.sarif")
    assert "--skip-db-update" not in args


def test_the_community_plugin_still_reads_the_trivy_database(tmp_path):
    scanner = _repo_scanner(tmp_path)
    assert [e.name for e in scanner.content_databases_in_use()] == ["trivy-db"]


def test_the_community_plugin_scan_still_ties_results_to_package_copies(
    tmp_path, monkeypatch
):
    """trivy-repo's own scan() path, with trivy replaced by the captured report."""
    from automated_security_helper.base import scanner_plugin

    monkeypatch.setattr(scanner_plugin, "find_executable", lambda name: f"/bin/{name}")
    scanner = _repo_scanner(tmp_path, offline=False)
    scanner.dependencies_satisfied = True
    source = scanner.context.source_dir

    def fake_run(command, results_dir, env=None, timeout=None, **kwargs):
        out = Path(command[command.index("--output") + 1])
        out.write_text(VULN_SARIF.read_text(encoding="utf-8"), encoding="utf-8")
        scanner.exit_code = 0
        return {"returncode": 0}

    monkeypatch.setattr(scanner, "_pre_scan", lambda **kw: True)
    monkeypatch.setattr(scanner, "_run_subprocess", fake_run)
    report = scanner.scan(target=source, target_type="source")
    lodash = [
        r for r in report.get_all_results() if r.properties.package_name == "lodash"
    ]
    assert len(lodash) == 5
    assert {r.properties.package_path for r in lodash} == {"node_modules/lodash"}
    assert {r.properties.scanner_name for r in report.get_all_results()} == {
        "trivy-repo"
    }


def test_an_assessment_that_cannot_ask_trivy_repo_still_records_trivy_db():
    """The fallback path names trivy-repo's database too, under trivy-repo."""

    class Broken:
        config = type("Config", (), {"name": "trivy-repo"})()

        def content_databases_in_use(self):
            raise RuntimeError("boom")

        def content_database_probe_context(self):  # pragma: no cover
            raise AssertionError("not reached")

    records = staleness.assess_scanner(
        Broken(), SarifReport(version="2.1.0", runs=[]), cdb.STALENESS_FAIL
    )
    assert [(r.name, r.scanner, r.stale) for r in records] == [
        ("trivy-db", "trivy-repo", True)
    ]


# --------------------------------------------------------------------------- #
# Defensive branches
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "name, expected",
    [
        (".ash/ash_output", ".ash/ash_output"),
        ("c,[d]", '"c,\\[d\\]"'),
        ('e"f', '"e""f"'),
        ("g\\h", "g\\\\h"),
        ("q{z}", "q\\{z\\}"),
    ],
)
def test_skip_dirs_values_are_escaped_as_trivy_reads_them(name, expected):
    """Each expected value was checked against trivy 0.69.3: it skips that directory."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
        skip_dirs_value,
    )

    assert skip_dirs_value(name) == expected


def test_a_rule_index_that_points_at_another_rule_falls_back_to_the_rule_id(
    tmp_path,
):
    raw = _raw()
    result = next(
        r for r in raw["runs"][0]["results"] if r["ruleId"] == "CVE-2018-18074"
    )
    rules = raw["runs"][0]["tool"]["driver"]["rules"]
    medium = next(i for i, r in enumerate(rules) if "MEDIUM" in r["properties"]["tags"])
    result["ruleIndex"] = medium
    _strip_result_severity(raw, "CVE-2018-18074")
    report = _parse(_scanner(tmp_path), raw)
    found = next(r for r in report.get_all_results() if r.ruleId == "CVE-2018-18074")
    assert found.properties.issue_severity == "HIGH"


def test_two_severity_tags_give_no_verdict(tmp_path):
    raw = _raw()
    for rule in raw["runs"][0]["tool"]["driver"]["rules"]:
        if rule["id"] == "CVE-2018-18074":
            rule["properties"]["tags"] = ["vulnerability", "LOW", "HIGH"]
    _strip_result_severity(raw, "CVE-2018-18074")
    report = _parse(_scanner(tmp_path), raw)
    found = next(r for r in report.get_all_results() if r.ruleId == "CVE-2018-18074")
    assert getattr(found.properties, "issue_severity", None) is None


# --------------------------------------------------------------------------- #
# trivy-repo always names its config file and modules directory, so trivy does
# not load a trivy.yaml from the directory it runs in.
# --------------------------------------------------------------------------- #

_PLANTED_TRIVY_YAML = "severity: [CRITICAL]\nmodule:\n  dir: ./trivy-modules-in-tree\n"


def _repo_scan_argv(
    tmp_path, monkeypatch, *, operator=False, overrides=(), **options
) -> tuple:
    from automated_security_helper.base import scanner_plugin

    monkeypatch.setattr(scanner_plugin, "find_executable", lambda name: f"/bin/{name}")
    scanner = _repo_scanner(tmp_path, offline=True, **options)
    source = Path(scanner.context.source_dir)
    record_provenance(
        scanner.context.config,
        in_tree=[] if operator else [source / ".ash" / ".ash.yaml"],
        trusted=AshConfig(),
        config_overrides=list(overrides),
    )
    scanner.dependencies_satisfied = True
    calls = []

    def fake_run(command, results_dir, env=None, timeout=None, **kwargs):
        calls.append(list(command))
        out = Path(command[command.index("--output") + 1])
        out.write_text(VULN_SARIF.read_text(encoding="utf-8"), encoding="utf-8")
        scanner.exit_code = 0
        return {"returncode": 0}

    monkeypatch.setattr(scanner, "_pre_scan", lambda **kw: True)
    monkeypatch.setattr(scanner, "_run_subprocess", fake_run)
    scanner.scan(target=source, target_type="source")
    (argv,) = calls
    return scanner, source, argv


def _flag(argv, name):
    (value,) = [a.split("=", 1)[1] for a in argv if a.startswith(f"{name}=")]
    return Path(value)


def test_trivy_repo_passes_its_own_config_and_an_empty_modules_dir(
    tmp_path, monkeypatch
):
    probe = _repo_scanner(tmp_path)
    planted = Path(probe.context.source_dir) / "trivy.yaml"
    planted.write_text(_PLANTED_TRIVY_YAML, encoding="utf-8")

    scanner, source, argv = _repo_scan_argv(tmp_path, monkeypatch)

    config = _flag(argv, "--config")
    modules = _flag(argv, "--module-dir")
    # The empty config ASH ships, as trivy gets (TrivyScannerBase._trivy_config_file).
    assert config == EMPTY_TOOL_CONFIG
    assert config.read_text() == ""
    assert modules.name == "trivy-modules" and _ashs_own(scanner, str(modules))
    assert list(modules.iterdir()) == []
    assert planted.resolve().as_posix() not in " ".join(argv)
    # Both flags precede the target, which trivy reads as its last positional. The
    # target is spelled as the scanner was given it or with forward slashes (Windows).
    target = next(t for t in (str(source), source.as_posix()) if t in argv)
    assert argv.index(f"--config={config.as_posix()}") < argv.index(target)
    assert argv.index(f"--module-dir={modules.as_posix()}") < argv.index(target)


def test_trivy_repo_does_not_use_a_modules_dir_left_in_the_output(
    tmp_path, monkeypatch
):
    """A directory at the name ASH once used, in the output inside the tree, is not
    the one passed: ASH's is new for each run, outside the tree."""
    probe = _repo_scanner(tmp_path)
    left = Path(probe.results_dir) / "source" / "trivy-modules"
    left.mkdir(parents=True)
    (left / "planted.wasm").write_bytes(b"\0asm")

    _, _, argv = _repo_scan_argv(tmp_path, monkeypatch)

    passed = _flag(argv, "--module-dir")
    assert passed.resolve() != left.resolve()
    assert list(passed.iterdir()) == []


def test_trivy_repo_ignores_a_config_file_the_scanned_tree_sets(
    tmp_path, monkeypatch, caplog
):
    probe = _repo_scanner(tmp_path)
    planted = Path(probe.context.source_dir) / "trivy.yaml"
    planted.write_text(_PLANTED_TRIVY_YAML, encoding="utf-8")

    with caplog.at_level("WARNING"):
        scanner, _, argv = _repo_scan_argv(
            tmp_path, monkeypatch, config_file="trivy.yaml", module_dir="."
        )

    assert _flag(argv, "--config") == EMPTY_TOOL_CONFIG
    assert _flag(argv, "--module-dir").name == "trivy-modules"
    assert planted.resolve().as_posix() not in " ".join(argv)
    assert "scanners.trivy-repo.options.config_file" in caplog.text
    assert "scanners.trivy-repo.options.module_dir" in caplog.text


def test_trivy_repo_uses_an_operator_config_and_modules_outside_the_tree(
    tmp_path, monkeypatch
):
    operator = tmp_path / "operator"
    (operator / "modules").mkdir(parents=True)
    (operator / "trivy.yaml").write_text("", encoding="utf-8")

    _, _, argv = _repo_scan_argv(
        tmp_path,
        monkeypatch,
        operator=True,
        config_file=str(operator / "trivy.yaml"),
        module_dir=str(operator / "modules"),
    )

    assert _flag(argv, "--config") == (operator / "trivy.yaml").resolve()
    assert _flag(argv, "--module-dir") == (operator / "modules").resolve()


@pytest.mark.skipif(os.name == "nt", reason="symlinks")
def test_trivy_repo_refuses_operator_paths_in_the_tree_that_link_out_of_it(
    tmp_path, monkeypatch, caplog
):
    """trivy-repo's config and modules directory, written in the tree, through
    links there to a config and a modules directory outside it."""
    outside = tmp_path / "outside"
    (outside / "modules").mkdir(parents=True)
    (outside / "trivy.yaml").write_text(_PLANTED_TRIVY_YAML, encoding="utf-8")
    source = Path(_repo_scanner(tmp_path).context.source_dir)
    (source / "ci").mkdir()
    (source / "ci" / "trivy.yaml").symlink_to(outside / "trivy.yaml")
    (source / "mods").symlink_to(outside / "modules", target_is_directory=True)

    with caplog.at_level("WARNING"):
        _, _, argv = _repo_scan_argv(
            tmp_path,
            monkeypatch,
            operator=True,
            config_file="ci/trivy.yaml",
            module_dir="mods",
        )

    assert _flag(argv, "--config") == EMPTY_TOOL_CONFIG
    assert _flag(argv, "--module-dir").name == "trivy-modules"
    assert outside.resolve().as_posix() not in " ".join(argv)
    for option in ("config_file", "module_dir"):
        assert f"Ignoring scanners.trivy-repo.options.{option}" in caplog.text
    assert "symbolic link" in caplog.text


def test_trivy_repo_honors_an_override_for_its_config(tmp_path, monkeypatch):
    chosen = tmp_path / "operator" / "trivy.yaml"
    chosen.parent.mkdir()
    chosen.write_text("", encoding="utf-8")

    _, _, argv = _repo_scan_argv(
        tmp_path,
        monkeypatch,
        overrides=(f"scanners.trivy-repo.options.config_file={chosen}",),
        config_file=str(chosen),
    )

    assert _flag(argv, "--config") == chosen.resolve()


# --------------------------------------------------------------------------- #
# trivy and trivy-repo share trivy's cache and run concurrently, so the database
# update happens once, under a lock (utils/content_db_refresh.prepare_content_db),
# and the scans skip it.
# --------------------------------------------------------------------------- #

import threading  # noqa: E402
import time  # noqa: E402

from automated_security_helper.plugin_modules.ash_builtin.scanners import (  # noqa: E402
    _trivy_scanner_base as trivy_base,
)
from automated_security_helper.utils import content_db_refresh as refresh  # noqa: E402


class _FakeTrivy:
    """Stands in for spawn_run (the update commands) and records overlaps."""

    def __init__(self, returncode=0, stderr="", hold=0.0):
        self.calls = []
        self.kwargs = []
        self.returncode = returncode
        self.stderr = stderr
        self.hold = hold
        self.active = 0
        self.max_active = 0
        self._lock = threading.Lock()

    def __call__(self, argv, **kwargs):
        with self._lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            self.calls.append(list(argv))
            self.kwargs.append(kwargs)
        time.sleep(self.hold)
        with self._lock:
            self.active -= 1
        import subprocess as sp  # nosec B404 - only builds a CompletedProcess for the fake run

        return sp.CompletedProcess(argv, self.returncode, "", self.stderr)


def _update_env(tmp_path, monkeypatch, fake):
    monkeypatch.setattr(refresh, "spawn_run", fake)
    monkeypatch.setattr(trivy_base, "find_executable", lambda name: f"/bin/{name}")
    monkeypatch.setenv("TRIVY_CACHE_DIR", str(tmp_path / "trivy-cache"))
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    for name in ("TRIVY_SKIP_DB_UPDATE", "TRIVY_SKIP_UPDATE", "TRIVY_EXIT_CODE"):
        monkeypatch.delenv(name, raising=False)
    refresh.forget_prepared()
    ran = []

    def fake_base_run(self, command, *args, **kwargs):
        ran.append(list(command))
        return {"returncode": 0}

    monkeypatch.setattr(
        trivy_base.ScannerPluginBase, "_run_subprocess", fake_base_run, raising=True
    )
    return ran


def _cache_flag(tmp_path) -> str:
    return f"--cache-dir={(tmp_path / 'trivy-cache').absolute().as_posix()}"


def _value(argv, flag):
    return argv[argv.index(flag) + 1]


def test_the_scan_skips_the_update_it_ran_first(tmp_path, monkeypatch):
    fake = _FakeTrivy()
    ran = _update_env(tmp_path, monkeypatch, fake)
    scanner = _scanner(tmp_path)
    command = ["trivy", "fs", "--config=/r/trivy-config.yaml", "/t"]

    scanner._run_subprocess(command=command, results_dir=tmp_path / "results")

    (update,) = fake.calls
    assert update[:4] == ["/bin/trivy", "image", "--download-db-only", "--no-progress"]
    assert Path(_value(update, "--cache-dir")) == (tmp_path / "trivy-cache").absolute()
    # The update gets the empty config ASH ships, not one from where ASH runs.
    assert Path(_value(update, "--config")) == refresh.EMPTY_TOOL_CONFIG
    (final,) = ran
    # The command built here carries no mode flag, so the scan-time reconciliation
    # adds the online one before the skip flags; a scanner's own command already
    # carries it from construction.
    assert final[: 6 + len(trivy_base.ONLINE_FLAGS)] == [
        "trivy",
        "fs",
        *trivy_base.ONLINE_FLAGS,
        "--skip-db-update",
        "--skip-java-db-update",
        _cache_flag(tmp_path),
        "--cache-backend=memory",
    ]
    assert "--skip-check-update" not in final
    # In place, so the invocation ASH records is the one that ran.
    assert command == final


@pytest.mark.parametrize("kind", ["trivy", "trivy-repo"])
def test_an_operators_opt_out_of_the_update_is_honored(tmp_path, monkeypatch, kind):
    """TRIVY_SKIP_DB_UPDATE makes trivy refuse --download-db-only, so ASH does not run
    it: the scan reads the cache as it is, and the post-scan check still measures it."""
    fake = _FakeTrivy()
    ran = _update_env(tmp_path, monkeypatch, fake)
    monkeypatch.setenv("TRIVY_SKIP_DB_UPDATE", "true")
    scanner = _scanner(tmp_path) if kind == "trivy" else _repo_scanner(tmp_path)
    command = ["trivy", "fs" if kind == "trivy" else "repository", "/t"]

    scanner._run_subprocess(command=command, results_dir=tmp_path / "results")

    assert not [c for c in fake.calls if "--download-db-only" in c]
    # trivy-repo runs misconfig, whose checks bundle has an opt-out of its own.
    assert [c[1] for c in fake.calls] == ([] if kind == "trivy" else ["config"])
    (final,) = ran
    assert "--skip-db-update" in final and _cache_flag(tmp_path) in final
    assert scanner.content_database_probe_context().cache_dir == (
        (tmp_path / "trivy-cache").absolute().as_posix()
    )


def test_the_operators_trivy_config_can_turn_the_update_off(tmp_path, monkeypatch):
    fake = _FakeTrivy()
    _update_env(tmp_path, monkeypatch, fake)
    chosen = tmp_path / "operator" / "trivy.yaml"
    chosen.parent.mkdir()
    chosen.write_text("db:\n  skip-update: true\n", encoding="utf-8")
    scanner = _scanner(tmp_path, operator=True, config_file=str(chosen))

    scanner._run_subprocess(command=["trivy", "fs", "/t"], results_dir=tmp_path)

    assert fake.calls == []


def test_a_tree_set_trivy_config_cannot_turn_the_update_off(tmp_path, monkeypatch):
    """Not honored, the file never reaches the update, so neither does its opt-out."""
    fake = _FakeTrivy()
    _update_env(tmp_path, monkeypatch, fake)
    chosen = tmp_path / "elsewhere" / "trivy.yaml"
    chosen.parent.mkdir()
    chosen.write_text("db:\n  skip-update: true\n", encoding="utf-8")
    scanner = _scanner(tmp_path, config_file=str(chosen))

    scanner._run_subprocess(command=["trivy", "fs", "/t"], results_dir=tmp_path)

    (update,) = fake.calls
    assert update[1:3] == ["image", "--download-db-only"]
    assert Path(_value(update, "--config")) == refresh.EMPTY_TOOL_CONFIG


def test_misconfig_also_fetches_the_checks_bundle_and_skips_it(tmp_path, monkeypatch):
    fake = _FakeTrivy()
    ran = _update_env(tmp_path, monkeypatch, fake)
    scanner = _repo_scanner(tmp_path)  # vuln, secret, misconfig, license
    command = ["trivy", "repository", "--config=/r/c.yaml", "/t"]

    scanner._run_subprocess(command=command, results_dir=tmp_path / "results")

    assert [c[1] for c in fake.calls] == ["image", "config"]
    assert Path(fake.calls[1][-1]).name == "empty-target"
    assert ran[0][2 : 6 + len(trivy_base.ONLINE_FLAGS)] == [
        *trivy_base.ONLINE_FLAGS,
        "--skip-db-update",
        "--skip-java-db-update",
        "--skip-check-update",
        _cache_flag(tmp_path),
    ]


def test_the_operators_trivy_config_reaches_the_update(tmp_path, monkeypatch):
    """A database mirror in the operator's trivy.yaml applies to the update too."""
    fake = _FakeTrivy()
    _update_env(tmp_path, monkeypatch, fake)
    chosen = tmp_path / "operator" / "trivy.yaml"
    chosen.parent.mkdir()
    chosen.write_text("db:\n  repository: mirror.example/trivy-db\n", encoding="utf-8")
    scanner = _scanner(tmp_path, operator=True, config_file=str(chosen))

    scanner._run_subprocess(command=["trivy", "fs", "/t"], results_dir=tmp_path)

    (update,) = fake.calls
    assert Path(_value(update, "--config")) == chosen.resolve()


def test_a_tree_set_trivy_config_does_not_reach_the_update(tmp_path, monkeypatch):
    fake = _FakeTrivy()
    _update_env(tmp_path, monkeypatch, fake)
    chosen = tmp_path / "elsewhere" / "trivy.yaml"
    chosen.parent.mkdir()
    chosen.write_text("db:\n  repository: sentinel.invalid/db\n", encoding="utf-8")
    scanner = _scanner(tmp_path, config_file=str(chosen))

    scanner._run_subprocess(command=["trivy", "fs", "/t"], results_dir=tmp_path)

    (update,) = fake.calls
    assert Path(_value(update, "--config")) == refresh.EMPTY_TOOL_CONFIG


def test_only_the_hosts_environment_chooses_the_updates_cache(tmp_path, monkeypatch):
    """The update runs unsandboxed: a TRIVY_CACHE_DIR a scanner layers on is ignored."""
    fake = _FakeTrivy()
    _update_env(tmp_path, monkeypatch, fake)  # host TRIVY_CACHE_DIR = trivy-cache
    scanner = _scanner(tmp_path)
    scanner.extra_env = {"TRIVY_CACHE_DIR": str(tmp_path / "steered")}

    scanner._run_subprocess(
        command=["trivy", "fs", "/t"],
        results_dir=tmp_path,
        env={"TRIVY_CACHE_DIR": str(tmp_path / "steered")},
    )

    (update,) = fake.calls
    assert Path(_value(update, "--cache-dir")) == (tmp_path / "trivy-cache").absolute()


@pytest.mark.parametrize("platform", ["linux", "darwin", "win32"])
@pytest.mark.parametrize("kind", ["trivy", "trivy-repo"])
def test_the_staleness_probe_reads_the_cache_the_scan_was_given(
    tmp_path, monkeypatch, platform, kind
):
    """trivy's own default is %LocalAppData%\\trivy on Windows, which is not the
    --cache-dir the scan gets; the post-scan probe must read the scan's cache."""
    fake = _FakeTrivy()
    _update_env(tmp_path, monkeypatch, fake)
    monkeypatch.delenv("TRIVY_CACHE_DIR")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    # The default cache reads XDG_CACHE_HOME before HOME (Go's os.UserCacheDir,
    # github.com/adrg/xdg), and the unit fixture points that variable into the
    # fixture's own home; left as is, the update's lock lands there and the
    # fixture's HOME-hygiene check reports it. The whole home moves together.
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "home" / ".cache"))
    monkeypatch.setattr(refresh.sys, "platform", platform)
    scanner = _scanner(tmp_path) if kind == "trivy" else _repo_scanner(tmp_path)
    command = ["trivy", "fs" if kind == "trivy" else "repository", "/t"]

    scanner._run_subprocess(command=command, results_dir=tmp_path / "results")

    (given,) = [a.split("=", 1)[1] for a in command if a.startswith("--cache-dir=")]
    probe = scanner.content_database_probe_context()
    assert probe.env["TRIVY_CACHE_DIR"] == given
    assert probe.cache_dir == given


def test_an_offline_probe_reads_the_cache_the_scan_is_given(tmp_path, monkeypatch):
    """Offline nothing is updated, but the scan is still given the cache, and the
    probe reads that one: before the scan (the offline dependency check) and
    after it."""
    _update_env(tmp_path, monkeypatch, _FakeTrivy())
    monkeypatch.delenv("TRIVY_CACHE_DIR")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    scanner = _scanner(tmp_path, offline=True)
    expected = refresh.default_cache_dir("trivy").as_posix()
    before = scanner.content_database_probe_context()
    command = ["trivy", "fs", "/t"]
    scanner._run_subprocess(command=command, results_dir=tmp_path)
    (given,) = [a.split("=", 1)[1] for a in command if a.startswith("--cache-dir=")]
    after = scanner.content_database_probe_context()
    assert given == expected
    for probe in (before, after):
        assert probe.cache_dir == given
        assert probe.env["TRIVY_CACHE_DIR"] == given


def test_two_concurrent_scanners_never_update_at_the_same_time(tmp_path, monkeypatch):
    fake = _FakeTrivy(hold=0.2)
    _update_env(tmp_path, monkeypatch, fake)
    scanners = [_scanner(tmp_path), _repo_scanner(tmp_path)]
    errors = []

    def run(scanner, name):
        try:
            scanner._run_subprocess(
                command=["trivy", name, "/t"], results_dir=tmp_path / name
            )
        except Exception as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [
        threading.Thread(target=run, args=(s, n))
        for s, n in zip(scanners, ("fs", "repository"))
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert len([c for c in fake.calls if c[1] == "image"]) == 2
    assert fake.max_active == 1, "two trivy updates overlapped"
    assert refresh.update_lock_path("trivy", tmp_path / "trivy-cache").exists()


def test_offline_runs_no_update(tmp_path, monkeypatch):
    fake = _FakeTrivy()
    ran = _update_env(tmp_path, monkeypatch, fake)
    scanner = _scanner(tmp_path, offline=True)

    scanner._run_subprocess(command=["trivy", "fs", "/t"], results_dir=tmp_path)

    assert fake.calls == []
    # Still pointed at the cache: the sandbox drops XDG_CACHE_HOME, so trivy left to
    # its own default could read another one. The command built here carries no
    # mode flag, so the scan-time reconciliation adds the offline ones, which an
    # offline scan never lacks.
    assert ran == [
        [
            "trivy",
            "fs",
            *trivy_base.OFFLINE_FLAGS,
            _cache_flag(tmp_path),
            "--cache-backend=memory",
            "--exit-code=0",
            "/t",
        ]
    ]


@pytest.mark.parametrize("offline", [False, True])
@pytest.mark.parametrize("kind", ["trivy", "trivy-repo"])
def test_every_scan_pins_trivys_exit_code_to_zero(tmp_path, monkeypatch, offline, kind):
    """TRIVY_EXIT_CODE, or exit-code in an operator's trivy.yaml, makes trivy exit
    nonzero on any finding; the flag outranks both (trivy 0.75.0), so a nonzero exit
    only ever means trivy failed."""
    ran = _update_env(tmp_path, monkeypatch, _FakeTrivy())
    monkeypatch.setenv("TRIVY_EXIT_CODE", "1")
    if kind == "trivy":
        scanner = _scanner(tmp_path, offline=offline)
    else:
        scanner = _repo_scanner(tmp_path, offline=offline)
    sub = "fs" if kind == "trivy" else "repository"

    scanner._run_subprocess(command=["trivy", sub, "/t"], results_dir=tmp_path)

    (final,) = ran
    assert [a for a in final if a.startswith("--exit-code")] == ["--exit-code=0"]
    assert final.index("--exit-code=0") < final.index("/t")


def test_the_update_runs_outside_the_scanner_sandbox(tmp_path, monkeypatch):
    """A sandbox may mount the cache read-only; the update must reach the host."""
    from automated_security_helper.utils.sandbox import scope as scope_module

    seen = []

    class Recording(_FakeTrivy):
        def __call__(self, argv, **kwargs):
            seen.append(scope_module.active_scope())
            return super().__call__(argv, **kwargs)

    fake = Recording()
    ran = _update_env(tmp_path, monkeypatch, fake)
    sandbox = object()
    token = scope_module._ACTIVE.set(sandbox)
    try:
        _scanner(tmp_path)._run_subprocess(
            command=["trivy", "fs", "/t"], results_dir=tmp_path
        )
        after = scope_module.active_scope()
    finally:
        scope_module._ACTIVE.reset(token)

    assert seen == [None]
    assert after is sandbox, "the scanner's own spawn runs back inside its sandbox"
    assert ran[0][2 : 3 + len(trivy_base.ONLINE_FLAGS)] == [
        *trivy_base.ONLINE_FLAGS,
        "--skip-db-update",
    ]


def test_a_failed_update_fails_the_scan_with_trivys_reason(tmp_path, monkeypatch):
    fake = _FakeTrivy(
        returncode=1, stderr="progress...\nFATAL could not reach the registry"
    )
    ran = _update_env(tmp_path, monkeypatch, fake)
    scanner = _scanner(tmp_path)

    with pytest.raises(ScannerError, match="could not reach the registry"):
        scanner._run_subprocess(command=["trivy", "fs", "/t"], results_dir=tmp_path)
    assert ran == []


# The operator rule on its own: a path outside the tree, set by the tree's config.
def test_an_outside_trivy_config_set_by_the_scanned_tree_is_not_passed(tmp_path):
    outside = tmp_path / "elsewhere" / "trivy.yaml"
    outside.parent.mkdir()
    outside.write_text(_MODULE_CONFIG, encoding="utf-8")
    scanner = _scanner(tmp_path, config_file=str(outside))

    argv = _argv(scanner, scanner.context.source_dir)

    assert outside.resolve().as_posix() not in " ".join(argv)


def test_outside_trivy_repo_paths_set_by_the_scanned_tree_are_not_passed(
    tmp_path, monkeypatch
):
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "modules").mkdir(parents=True)
    (elsewhere / "trivy.yaml").write_text("", encoding="utf-8")

    _, _, argv = _repo_scan_argv(
        tmp_path,
        monkeypatch,
        config_file=str(elsewhere / "trivy.yaml"),
        module_dir=str(elsewhere / "modules"),
    )

    assert _flag(argv, "--config") == EMPTY_TOOL_CONFIG
    assert _flag(argv, "--module-dir").name == "trivy-modules"
    assert elsewhere.resolve().as_posix() not in " ".join(argv)
