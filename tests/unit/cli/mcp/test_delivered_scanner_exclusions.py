# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A delivered config's scanner exclusions are reported, not applied.

An entry a client's delivered config adds to a scanner's own exclusion option
(bandit ``excluded_paths``, checkov ``skip_path``, opengrep and semgrep
``exclude``, syft ``exclude``, ferret-scan ``exclude_patterns``, trivy-repo
``ignore_file``) is moved out of the option before the scanner runs, so the
scanner sees the files, and each finding of that scanner it would have kept out
comes back suppressed and marked client-supplied. An entry the operator supplied
stays in the option. ``exclude_rule`` and detect-secrets ``baseline_file`` are
denied to a delivered config by default.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List
from unittest.mock import patch

import pytest
import yaml

from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_session_state,
)

SESSION = "client-1"


class _QuietLogger:
    def __getattr__(self, name: str) -> Callable[..., None]:
        return lambda *args, **kwargs: None


class _StopAfterResolution(Exception):
    pass


OPERATOR: Dict[str, Any] = {
    "project_name": "operator",
    "scanners": {
        "bandit": {
            "options": {"excluded_paths": [{"path": "operator-dir", "reason": "op"}]}
        },
        "checkov": {
            "options": {"skip_path": [{"path": "operator-dir", "reason": "op"}]}
        },
        "opengrep": {
            "options": {
                "exclude": ["*-converted.py", "*_report_result.txt", "operator-dir"]
            }
        },
        "semgrep": {
            "options": {
                "exclude": ["*-converted.py", "*_report_result.txt", "operator-dir"]
            }
        },
        "syft": {
            "options": {"exclude": [{"path": "./operator-dir/**", "reason": "op"}]}
        },
        "ferret-scan": {"options": {"exclude_patterns": ["operator-dir"]}},
    },
}


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    from automated_security_helper.config.path_trust import (
        reset_path_refusal_warnings,
    )

    workspace = tmp_path / "workspaces"
    scan_root = tmp_path / "scan-root"
    target = scan_root / "target"
    target.mkdir(parents=True)
    operator = tmp_path / "operator" / "ash.yaml"
    operator.parent.mkdir()
    operator.write_text(yaml.safe_dump(OPERATOR), encoding="utf-8")
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("ASH_MCP_ALLOWED_ROOTS", str(scan_root))
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("TRIVY_IGNOREFILE", raising=False)
    clear_profile_registry()
    clear_session_state()
    reset_path_refusal_warnings()
    yield {"workspace": workspace, "target": target, "tmp": tmp_path}
    clear_profile_registry()
    clear_session_state()
    reset_path_refusal_warnings()


def _upload(files: Dict[str, str]) -> Path:
    """Deliver ``files`` through the real chunked zip upload; return the source dir."""
    from automated_security_helper.cli.mcp.source_delivery import (
        set_source_zip_chunk,
        set_source_zip_finalize,
    )

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, text in files.items():
            archive.writestr(name, text)
    data = buffer.getvalue()
    set_source_zip_chunk(
        "u1", 0, base64.b64encode(data).decode("ascii"), True, session_id=SESSION
    )
    return set_source_zip_finalize(
        "u1", hashlib.sha256(data).hexdigest(), session_id=SESSION
    )


def _scan_resolution(target: Path) -> Any:
    """Start an MCP scan of ``target``; return the config it resolved, or the error."""
    from automated_security_helper.cli import mcp_tools
    from automated_security_helper.config import resolve_config as rc
    from automated_security_helper.core import orchestrator
    from automated_security_helper.core.resource_management.scan_registry import (
        ScanRegistry,
    )
    from automated_security_helper.interactions import run_ash_scan as ras

    outcomes: List[Any] = []
    real = rc.resolve_config

    def recording(*args: Any, **kwargs: Any) -> Any:
        try:
            outcomes.append(real(*args, **kwargs))
        except Exception as exc:  # noqa: BLE001 -- the outcome under test
            outcomes.append(exc)
        raise _StopAfterResolution

    output = target / ".ash" / "ash_output"
    output.mkdir(parents=True, exist_ok=True)
    registry = ScanRegistry()
    scan_id = registry.register_scan(
        directory_path=str(target), output_directory=str(output)
    )
    with (
        patch.object(ras, "_setup_logger", lambda opts: _QuietLogger()),
        patch.object(orchestrator, "resolve_config", recording),
        patch.object(mcp_tools, "get_scan_registry", return_value=registry),
    ):
        asyncio.run(
            mcp_tools._run_scan_async(
                scan_id=scan_id,
                directory_path=str(target),
                output_dir=str(output),
                severity_threshold="MEDIUM",
                config_path=None,
                session_id=SESSION,
            )
        )
    assert len(outcomes) == 1, "the scan never reached config resolution"
    return outcomes[0]


@dataclass(frozen=True)
class Case:
    scanner: str
    option: str
    operator_entry: Any
    client_entry: Any
    operator_pattern: str
    client_pattern: str


CASES = [
    Case(
        "bandit",
        "excluded_paths",
        {"path": "operator-dir", "reason": "op"},
        {"path": "client-dir", "reason": "client's reason"},
        "operator-dir",
        "client-dir",
    ),
    Case(
        "checkov",
        "skip_path",
        {"path": "operator-dir", "reason": "op"},
        {"path": "client-dir", "reason": "client's reason"},
        "operator-dir",
        "client-dir",
    ),
    Case(
        "opengrep",
        "exclude",
        "operator-dir",
        "client-dir",
        "operator-dir",
        "client-dir",
    ),
    Case(
        "semgrep", "exclude", "operator-dir", "client-dir", "operator-dir", "client-dir"
    ),
    Case(
        "syft",
        "exclude",
        {"path": "./operator-dir/**", "reason": "op"},
        {"path": "./client-dir/**", "reason": "client's reason"},
        "./operator-dir/**",
        "./client-dir/**",
    ),
    Case(
        "ferret-scan",
        "exclude_patterns",
        "operator-dir",
        "client-dir",
        "operator-dir",
        "client-dir",
    ),
]
#: The scanners whose findings are SARIF results.
SARIF_CASES = [case for case in CASES if case.scanner != "syft"]


def _delivered(case: Case) -> Path:
    document = {
        "project_name": "delivered",
        "scanners": {
            case.scanner: {
                "options": {case.option: [case.operator_entry, case.client_entry]}
            }
        },
    }
    return _upload(
        {
            ".ash/.ash.yaml": yaml.safe_dump(document),
            "client-dir/app.py": "x = 1\n",
            "other/app.py": "x = 1\n",
        }
    )


def _patterns(entries: Any) -> List[str]:
    return [entry["path"] if isinstance(entry, dict) else entry for entry in entries]


def _resolved(case: Case) -> Any:
    from automated_security_helper.config.ash_config import AshConfig

    source = _delivered(case)
    config = _scan_resolution(source)
    assert isinstance(config, AshConfig), config
    return source, config


# ---------------------------------------------------------------------------
# The entry leaves the option; the operator's stays
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.scanner)
def test_a_delivered_exclusion_is_moved_out_of_the_scanners_options(case: Case) -> None:
    _, config = _resolved(case)
    options = config.get_plugin_config("scanner", case.scanner)["options"]
    patterns = _patterns(options[case.option])
    assert case.operator_pattern in patterns
    assert case.client_pattern not in patterns
    moved = [
        (item.scanner, item.option, item.pattern)
        for item in config._client_scanner_exclusions
    ]
    assert moved == [(case.scanner, case.option, case.client_pattern)]
    assert any(
        f"scanners.{case.scanner}.options.{case.option}" in warning
        and case.client_pattern in warning
        for warning in config._resolution_warnings
    ), config._resolution_warnings


def _scanner_args(case: Case, config: Any, context: Any) -> List[str]:
    """Every argv token the scanner builds from ``config``'s section for it."""
    section = config.get_plugin_config("scanner", case.scanner)
    if case.scanner == "bandit":
        from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
            BanditScanner as cls,
            BanditScannerConfig as cfg,
        )
    elif case.scanner == "checkov":
        from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
            CheckovScanner as cls,  # type: ignore[assignment]
            CheckovScannerConfig as cfg,  # type: ignore[assignment]
        )
    elif case.scanner == "opengrep":
        from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
            OpengrepScanner as cls,  # type: ignore[assignment]
            OpengrepScannerConfig as cfg,  # type: ignore[assignment]
        )
    elif case.scanner == "semgrep":
        from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
            SemgrepScanner as cls,  # type: ignore[assignment]
            SemgrepScannerConfig as cfg,  # type: ignore[assignment]
        )
    elif case.scanner == "syft":
        from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
            SyftScanner as cls,  # type: ignore[assignment]
            SyftScannerConfig as cfg,  # type: ignore[assignment]
        )
    else:
        from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
            FerretScanScanner as cls,  # type: ignore[assignment]
            FerretScannerConfig as cfg,  # type: ignore[assignment]
        )
    scanner = cls(context=context, config=cfg.model_validate(section))
    scanner._process_config_options()
    tokens: List[str] = []
    for arg in scanner.args.extra_args:
        tokens.append(str(arg.key))
        if arg.value is not None:
            tokens.append(str(arg.value))
    return tokens


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.scanner)
def test_the_scanner_no_longer_excludes_what_the_delivered_config_listed(
    case: Case, test_plugin_context
) -> None:
    _, config = _resolved(case)
    tokens = " ".join(_scanner_args(case, config, test_plugin_context))
    assert "operator-dir" in tokens
    assert "client-dir" not in tokens


# ---------------------------------------------------------------------------
# The finding it would have hidden comes back suppressed and marked
# ---------------------------------------------------------------------------


def _sarif(results: List[Dict[str, Any]]) -> Any:
    from automated_security_helper.schemas.sarif_schema_model import SarifReport

    return SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {"name": "AWS Labs - Automated Security Helper"}
                    },
                    "results": [
                        {
                            "ruleId": rule,
                            "message": {"text": "finding"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": uri},
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                            "properties": {"scanner_name": scanner},
                        }
                        for scanner, uri, rule in (
                            (r["scanner"], r["uri"], r.get("rule", "RULE-1"))
                            for r in results
                        )
                    ],
                }
            ],
        }
    )


def _marks(result: Any) -> List[str]:
    return [
        item.justification
        for item in result.suppressions or []
        if item.properties is not None
        and getattr(item.properties, "clientSupplied", None) is True
    ]


def _apply(source: Path, config: Any, report: Any, tmp_path: Path) -> Any:
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.utils.sarif_utils import (
        apply_suppressions_to_sarif,
    )

    context = PluginContext(
        source_dir=source, output_dir=tmp_path / "results", config=config
    )
    return apply_suppressions_to_sarif(report, context)


@pytest.mark.parametrize("case", SARIF_CASES, ids=lambda case: case.scanner)
def test_a_finding_the_exclusion_would_have_hidden_is_reported_suppressed_and_marked(
    case: Case, tmp_path: Path
) -> None:
    source, config = _resolved(case)
    other = "trivy-repo" if case.scanner != "trivy-repo" else "bandit"
    report = _sarif(
        [
            {"scanner": case.scanner, "uri": "client-dir/app.py"},
            {"scanner": other, "uri": "client-dir/app.py"},
            {"scanner": case.scanner, "uri": "other/app.py"},
        ]
    )
    # Applied as ASH applies it: to the scanner's report and again to the
    # aggregated one. The second pass adds nothing.
    report = _apply(source, config, report, tmp_path)
    report = _apply(source, config, report, tmp_path)
    hidden, other_scanner, elsewhere = report.runs[0].results
    marks = _marks(hidden)
    assert len(marks) == 1, hidden.suppressions
    assert f"scanners.{case.scanner}.options.{case.option}" in marks[0]
    assert case.client_pattern in marks[0]
    assert not other_scanner.suppressions
    assert not elsewhere.suppressions


def test_a_client_ignore_path_is_marked_once_across_both_passes(tmp_path: Path) -> None:
    from automated_security_helper.config.ash_config import AshConfig

    source = _upload(
        {
            ".ash/.ash.yaml": yaml.safe_dump(
                {
                    "global_settings": {
                        "ignore_paths": [{"path": "client-dir/**", "reason": "client"}]
                    }
                }
            ),
            "client-dir/app.py": "x = 1\n",
        }
    )
    config = _scan_resolution(source)
    assert isinstance(config, AshConfig), config
    report = _sarif([{"scanner": "bandit", "uri": "client-dir/app.py"}])
    report = _apply(source, config, report, tmp_path)
    report = _apply(source, config, report, tmp_path)
    assert len(_marks(report.runs[0].results[0])) == 1


def test_a_syft_exclusion_marks_the_sbom_components_it_would_have_dropped() -> None:
    from automated_security_helper.config.client_scanner_exclusions import (
        SBOM_PROPERTY,
        mark_sbom_components,
    )
    from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import (
        CycloneDXReport,
    )

    _, config = _resolved(next(case for case in CASES if case.scanner == "syft"))
    report = CycloneDXReport.model_validate(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {
                    "type": "library",
                    "name": name,
                    "properties": [
                        {"name": "syft:location:0:path", "value": f"/{where}"}
                    ],
                }
                for name, where in (
                    ("hidden", "client-dir/requirements.txt"),
                    ("kept", "other/requirements.txt"),
                )
            ],
        }
    )
    assert mark_sbom_components(report, config._client_scanner_exclusions) == 1
    assert mark_sbom_components(report, config._client_scanner_exclusions) == 0
    marked = {
        component.name: [
            prop.value
            for prop in component.properties or []
            if prop.name == SBOM_PROPERTY
        ]
        for component in report.components or []
    }
    assert marked == {
        "hidden": ["scanners.syft.options.exclude: ./client-dir/**"],
        "kept": [],
    }


def test_the_result_processor_marks_the_sbom(tmp_path: Path) -> None:
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.client_scanner_exclusions import (
        SBOM_PROPERTY,
    )
    from automated_security_helper.core.phases.scan_result_processor import (
        ScanResultProcessor,
    )
    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.models.scan_results_container import (
        ScanResultsContainer,
    )
    from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import (
        CycloneDXReport,
    )

    source, config = _resolved(next(case for case in CASES if case.scanner == "syft"))
    context = PluginContext(source_dir=source, output_dir=tmp_path, config=config)
    report = CycloneDXReport.model_validate(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {
                    "type": "library",
                    "name": "hidden",
                    "properties": [
                        {
                            "name": "syft:location:0:path",
                            "value": "/client-dir/requirements.txt",
                        }
                    ],
                }
            ],
        }
    )
    results = ScanResultsContainer(
        scanner_name="syft", target_type="source", raw_results=report
    )
    aggregated = AshAggregatedResults()
    ScanResultProcessor(plugin_context=context).process_container(results, aggregated)
    (component,) = aggregated.cyclonedx.components
    assert SBOM_PROPERTY in [prop.name for prop in component.properties]


# ---------------------------------------------------------------------------
# trivy-repo ignore_file
# ---------------------------------------------------------------------------


def _trivy_delivered(files: Dict[str, str], ignore_file: str) -> Path:
    document = {
        "project_name": "delivered",
        "scanners": {"trivy-repo": {"options": {"ignore_file": ignore_file}}},
    }
    return _upload({".ash/.ash.yaml": yaml.safe_dump(document), **files})


def _trivy_options(config: Any) -> Dict[str, Any]:
    return config.get_plugin_config("scanner", "trivy-repo")["options"]


def test_a_delivered_trivy_ignore_file_is_applied_as_marked_suppressions(
    tmp_path: Path,
) -> None:
    from automated_security_helper.config.ash_config import AshConfig

    source = _trivy_delivered(
        {
            ".trivyignore": (
                "# comment\nCVE-2020-0001\nCVE-2020-0002 exp:2000-01-01\nAVD-AWS-0086\n"
            ),
            "app.py": "x = 1\n",
        },
        ".trivyignore",
    )
    config = _scan_resolution(source)
    assert isinstance(config, AshConfig), config
    assert not _trivy_options(config).get("ignore_file")
    assert [item.pattern for item in config._client_scanner_exclusions] == [
        "CVE-2020-0001",
        "AVD-AWS-0086",
    ]
    report = _sarif(
        [
            {"scanner": "trivy-repo", "uri": "app.py", "rule": "CVE-2020-0001"},
            {"scanner": "trivy-repo", "uri": "app.py", "rule": "AWS-0086"},
            {"scanner": "trivy-repo", "uri": "app.py", "rule": "CVE-2020-0002"},
            {"scanner": "trivy-repo", "uri": "app.py", "rule": "CVE-2020-0003"},
            {"scanner": "grype", "uri": "app.py", "rule": "CVE-2020-0001"},
        ]
    )
    results = _apply(source, config, report, tmp_path).runs[0].results
    assert [len(_marks(result)) for result in results] == [1, 1, 0, 0, 0]
    assert "scanners.trivy-repo.options.ignore_file" in _marks(results[0])[0]


def test_a_delivered_yaml_trivy_ignore_file_keeps_its_paths(tmp_path: Path) -> None:
    from automated_security_helper.config.ash_config import AshConfig

    source = _trivy_delivered(
        {
            ".trivyignore.yaml": yaml.safe_dump(
                {
                    "vulnerabilities": [
                        {"id": "CVE-2020-0001", "paths": ["vendor/**"]},
                        {"id": "CVE-2020-0009", "expired_at": "2000-01-01"},
                    ]
                }
            ),
            "app.py": "x = 1\n",
        },
        ".trivyignore.yaml",
    )
    config = _scan_resolution(source)
    assert isinstance(config, AshConfig), config
    report = _sarif(
        [
            {
                "scanner": "trivy-repo",
                "uri": "vendor/a/go.mod",
                "rule": "CVE-2020-0001",
            },
            {"scanner": "trivy-repo", "uri": "go.mod", "rule": "CVE-2020-0001"},
            {"scanner": "trivy-repo", "uri": "go.mod", "rule": "CVE-2020-0009"},
        ]
    )
    results = _apply(source, config, report, tmp_path).runs[0].results
    assert [len(_marks(result)) for result in results] == [1, 0, 0]


def test_a_trivy_ignore_file_outside_what_the_client_delivered_is_not_read(
    _server,
) -> None:
    from automated_security_helper.config.ash_config import AshConfig

    server_file = _server["tmp"] / "operator" / "elsewhere.trivyignore"
    server_file.write_text("CVE-2020-0001\n", encoding="utf-8")
    source = _trivy_delivered({"app.py": "x = 1\n"}, str(server_file))
    config = _scan_resolution(source)
    assert isinstance(config, AshConfig), config
    assert not _trivy_options(config).get("ignore_file")
    assert config._client_scanner_exclusions == []
    assert any(
        "only a regular file inside the scanned tree is read" in warning
        for warning in config._resolution_warnings
    ), config._resolution_warnings


SECRET_LINE = "CVE-2099-0001 host-only-marker-7f3a"


def _host_file(tmp: Path) -> Path:
    host = tmp / "host" / "ignore.txt"
    host.parent.mkdir(exist_ok=True)
    host.write_text(SECRET_LINE + "\n", encoding="utf-8")
    return host


def _no_trace_of_the_host_file(config: Any, tmp_path: Path) -> None:
    """Nothing the host file holds reached the config, its warnings, or the results."""
    assert config._client_scanner_exclusions == []
    assert "host-only-marker" not in " ".join(config._resolution_warnings)
    report = _sarif(
        [{"scanner": "trivy-repo", "uri": "app.py", "rule": "CVE-2099-0001"}]
    )
    source = Path(config._scanned_root or tmp_path)
    (result,) = _apply(source, config, report, tmp_path).runs[0].results
    assert not result.suppressions
    assert "host-only-marker" not in result.model_dump_json()


def test_a_symlinked_trivy_ignore_file_in_the_delivered_tree_is_not_read(
    _server, tmp_path: Path
) -> None:
    """A link inside the tree that points at a host file is refused, not followed."""
    from automated_security_helper.config.ash_config import AshConfig

    host = _host_file(_server["tmp"])
    source = _trivy_delivered({"app.py": "x = 1\n"}, ".trivyignore")
    (source / ".trivyignore").symlink_to(host)
    config = _scan_resolution(source)
    assert isinstance(config, AshConfig), config
    assert not _trivy_options(config).get("ignore_file")
    assert any(
        "it is a symbolic link" in warning for warning in config._resolution_warnings
    ), config._resolution_warnings
    _no_trace_of_the_host_file(config, tmp_path)


def test_a_trivy_ignore_file_above_the_delivered_tree_is_not_read(
    _server, tmp_path: Path
) -> None:
    """A checkout around the workspace does not widen what may be read."""
    from automated_security_helper.config.ash_config import AshConfig

    (_server["tmp"] / ".git").mkdir()
    host = _host_file(_server["tmp"])
    source = _trivy_delivered({"app.py": "x = 1\n"}, "placeholder")
    relative = Path(__import__("os").path.relpath(host, source)).as_posix()
    document = {
        "project_name": "delivered",
        "scanners": {"trivy-repo": {"options": {"ignore_file": relative}}},
    }
    (source / ".ash" / ".ash.yaml").write_text(
        yaml.safe_dump(document), encoding="utf-8"
    )
    config = _scan_resolution(source)
    assert isinstance(config, AshConfig), config
    assert not _trivy_options(config).get("ignore_file")
    _no_trace_of_the_host_file(config, tmp_path)


def test_an_unparsable_trivy_ignore_file_is_not_quoted(tmp_path: Path) -> None:
    from automated_security_helper.config.ash_config import AshConfig

    source = _trivy_delivered(
        {
            ".trivyignore.yaml": "vulnerabilities: [\n  quoted-marker-7f3a: : :\n",
            "app.py": "x = 1\n",
        },
        ".trivyignore.yaml",
    )
    config = _scan_resolution(source)
    assert isinstance(config, AshConfig), config
    warnings = " ".join(config._resolution_warnings)
    assert "could not be parsed" in warnings
    assert "quoted-marker" not in warnings


@pytest.mark.parametrize(
    ("pattern", "relative", "skipped"),
    [
        ("client-dir", "client-dir/main.tf", True),
        # A pattern anchored at a directory leaves out everything below it.
        ("client-dir$", "client-dir/main.tf", True),
        # Not a valid regular expression: still a substring.
        ("[weird", "[weird/main.tf", True),
        (".terraform", "x/.terraform/main.tf", True),
        (".terraform", "x/aterraform/main.tf", False),
        ("other-dir", "client-dir/main.tf", False),
    ],
)
def test_the_checkov_matcher_reads_skip_path_as_checkov_does(
    pattern: str, relative: str, skipped: bool
) -> None:
    from automated_security_helper.config.client_scanner_exclusions import (
        checkov_skips,
    )

    assert checkov_skips(pattern, f"/scan/{relative}", relative) is skipped


def test_the_trivy_scanner_gets_no_ignore_file_from_a_delivered_config(
    tmp_path: Path,
) -> None:
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
        TrivyRepoScanner,
        TrivyRepoScannerConfig,
    )

    server_file = tmp_path / "operator" / "elsewhere.trivyignore"
    server_file.write_text("CVE-2020-0001\n", encoding="utf-8")
    source = _trivy_delivered({"app.py": "x = 1\n"}, str(server_file))
    config = _scan_resolution(source)
    output = tmp_path / "trivy-out"
    output.mkdir()
    scanner = TrivyRepoScanner(
        context=PluginContext(source_dir=source, output_dir=output, config=config),
        config=TrivyRepoScannerConfig.model_validate(
            config.get_plugin_config("scanner", "trivy-repo")
        ),
    )
    assert Path(scanner._ignore_file()).resolve() != server_file.resolve()


# ---------------------------------------------------------------------------
# What stays as it was
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.scanner)
def test_the_operators_own_entries_are_not_moved(case: Case) -> None:
    from automated_security_helper.config.ash_config import AshConfig

    document = {
        "project_name": "delivered",
        "scanners": {case.scanner: {"options": {case.option: [case.operator_entry]}}},
    }
    source = _upload({".ash/.ash.yaml": yaml.safe_dump(document)})
    config = _scan_resolution(source)
    assert isinstance(config, AshConfig), config
    patterns = _patterns(
        config.get_plugin_config("scanner", case.scanner)["options"][case.option]
    )
    assert case.operator_pattern in patterns
    assert config._client_scanner_exclusions == []


def test_a_cli_config_outside_the_mcp_workspace_is_unchanged(tmp_path: Path) -> None:
    from automated_security_helper.config.resolve_config import resolve_config

    repo = tmp_path / "repo"
    (repo / ".ash").mkdir(parents=True)
    (repo / ".ash" / ".ash.yaml").write_text(
        yaml.safe_dump(
            {
                "scanners": {
                    "bandit": {
                        "options": {
                            "excluded_paths": [{"path": "client-dir", "reason": "x"}]
                        }
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    config = resolve_config(source_dir=repo)
    options = config.get_plugin_config("scanner", "bandit")["options"]
    assert _patterns(options["excluded_paths"]) == ["client-dir"]
    assert config._client_scanner_exclusions == []


# ---------------------------------------------------------------------------
# Options that do not exclude by path are denied to a delivered config
# ---------------------------------------------------------------------------


#: Each option a delivered config may not change, with a value that differs from
#: its default. They drop findings by rule ID, by a baseline, or by category.
NON_PATH_EXCLUSIONS = [
    ("opengrep", "exclude_rule", ["python.lang.security.audit.x"]),
    ("semgrep", "exclude_rule", ["python.lang.security.audit.x"]),
    ("detect-secrets", "baseline_file", ".secrets.baseline"),
    ("bandit", "confidence_level", "high"),
    ("checkov", "frameworks", ["terraform"]),
    ("checkov", "skip_frameworks", ["terraform"]),
    ("opengrep", "config", "p/default"),
    ("opengrep", "patterns", ["$X == $X"]),
    ("opengrep", "severity", ["ERROR"]),
    ("semgrep", "config", "p/default"),
    ("semgrep", "severity", ["ERROR"]),
    (
        "detect-secrets",
        "scan_settings",
        {"plugins_used": [{"name": "AWSKeyDetector"}]},
    ),
    ("cdk-nag", "nag_packs", {"AwsSolutionsChecks": False}),
    ("ferret-scan", "checks", "CREDIT_CARD"),
    ("ferret-scan", "confidence_levels", "high"),
    ("ferret-scan", "disable_ip_types", "private"),
    ("ferret-scan", "enable_preprocessors", False),
    ("ferret-scan", "finding_limit", 5),
    ("ferret-scan", "profile", "quick"),
    ("ferret-scan", "recursive", False),
    ("ferret-scan", "respect_gitignore", True),
    ("ferret-scan", "use_default_config", False),
    ("ferret-scan", "validator_budget", "all=1ms"),
    ("trivy-repo", "license_full", False),
    ("trivy-repo", "scanners", ["vuln"]),
]
_NON_PATH_IDS = [f"{scanner}.{option}" for scanner, option, _ in NON_PATH_EXCLUSIONS]


def _option_defaults() -> Dict[tuple, Any]:
    """Each NON_PATH_EXCLUSIONS option's default, from its scanner's own model."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
        BanditScannerConfigOptions,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.cdk_nag_scanner import (
        CdkNagScannerConfigOptions,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
        CheckovScannerConfigOptions,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScannerConfigOptions,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
        OpengrepScannerConfigOptions,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
        SemgrepScannerConfigOptions,
    )
    from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
        FerretScannerConfigOptions,
    )
    from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
        TrivyRepoScannerConfigOptions,
    )

    models = {
        "bandit": BanditScannerConfigOptions(),
        "cdk-nag": CdkNagScannerConfigOptions(),
        "checkov": CheckovScannerConfigOptions(),
        "detect-secrets": DetectSecretsScannerConfigOptions(),
        "opengrep": OpengrepScannerConfigOptions(),
        "semgrep": SemgrepScannerConfigOptions(),
        "ferret-scan": FerretScannerConfigOptions(),
        "trivy-repo": TrivyRepoScannerConfigOptions(),
    }
    defaults: Dict[tuple, Any] = {}
    for scanner, option, _ in NON_PATH_EXCLUSIONS:
        value = getattr(models[scanner], option)
        defaults[(scanner, option)] = (
            value.model_dump(mode="json") if hasattr(value, "model_dump") else value
        )
    return defaults


@pytest.mark.parametrize(
    ("scanner", "option", "value"), NON_PATH_EXCLUSIONS, ids=_NON_PATH_IDS
)
def test_a_delivered_config_may_not_change_a_non_path_exclusion(
    scanner: str, option: str, value: Any
) -> None:
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    assert value != _option_defaults()[(scanner, option)]
    document = {"scanners": {scanner: {"options": {option: value}}}}
    source = _upload({".ash/.ash.yaml": yaml.safe_dump(document)})
    outcome = _scan_resolution(source)
    assert isinstance(outcome, ASHConfigFieldDeniedError), outcome
    assert f"scanners.{scanner}.options.{option}" in str(outcome)


@pytest.mark.parametrize(
    ("scanner", "option", "value"), NON_PATH_EXCLUSIONS, ids=_NON_PATH_IDS
)
def test_a_delivered_non_path_option_at_its_default_scans(
    scanner: str, option: str, value: Any
) -> None:
    from automated_security_helper.config.ash_config import AshConfig

    default = _option_defaults()[(scanner, option)]
    document = {"scanners": {scanner: {"options": {option: default}}}}
    source = _upload({".ash/.ash.yaml": yaml.safe_dump(document)})
    outcome = _scan_resolution(source)
    assert isinstance(outcome, AshConfig), outcome


def test_every_non_path_exclusion_is_a_default_denial() -> None:
    from automated_security_helper.config.ash_config import RuntimeOverridesConfig

    denied = RuntimeOverridesConfig().denied_paths
    missing = [
        f"/scanners/{scanner}/options/{option}"
        for scanner, option, _ in NON_PATH_EXCLUSIONS
        if not _denied_at_or_below(f"/scanners/{scanner}/options/{option}", denied)
    ]
    assert missing == []


def _denied_at_or_below(pointer: str, denied: List[str]) -> bool:
    """Whether ``pointer``, or a key inside it, is a default ``denied_paths`` entry."""
    return any(entry == pointer or entry.startswith(pointer + "/") for entry in denied)


def test_a_delivered_config_may_turn_on_more_cdk_nag_packs() -> None:
    """Only turning off the pack that is on by default drops findings."""
    from automated_security_helper.config.ash_config import AshConfig

    packs = {
        "AwsSolutionsChecks": True,
        "HIPAASecurityChecks": True,
        "NIST80053R4Checks": True,
        "NIST80053R5Checks": True,
        "PCIDSS321Checks": True,
    }
    document = {"scanners": {"cdk-nag": {"options": {"nag_packs": packs}}}}
    source = _upload({".ash/.ash.yaml": yaml.safe_dump(document)})
    assert isinstance(_scan_resolution(source), AshConfig)


#: Scanner options whose names suggest they filter findings but that a
#: delivered config may still change, each with why.
_REVIEWED_NOT_HIDING = {
    ("bandit", "ignore_nosec"): "the default honors # nosec; True reports more",
    ("checkov", "skip_ash_output_dir"): "the default skips only ASH's own output",
    ("detect-secrets", "skip_generated_lockfiles"): "on by default; off reports more",
    ("trivy-repo", "ignore_unfixed"): "on by default; off reports more",
    ("cdk-nag", "include_compliant_checks"): "adds passing checks to the output",
    ("ferret-scan", "fail_on_incomplete"): "decides the verdict, hides nothing",
    ("ferret-scan", "skip_version_check"): "tool installation, not findings",
    ("trivy-repo", "disable_telemetry"): "telemetry, not findings",
}

#: Words in an option's name that mark it as one that may filter findings.
_FILTER_WORDS = (
    "skip",
    "exclude",
    "ignore",
    "disable",
    "framework",
    "severity",
    "confidence",
    "limit",
    "check",
    "pack",
    "baseline",
    "settings",
    "recursive",
    "profile",
    "pattern",
    "scanners",
    "budget",
    "preprocessor",
    "license",
    "config",
)


def test_every_option_that_may_filter_findings_is_classified() -> None:
    """Each such option is re-applied as a marked suppression, denied, or reviewed.

    Keeps a new scanner option that drops findings from reaching a delivered
    config unnoticed.
    """
    from automated_security_helper.config.ash_config import RuntimeOverridesConfig
    from automated_security_helper.config.client_scanner_exclusions import (
        SCANNER_EXCLUSION_OPTIONS,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        bandit_scanner,
        cdk_nag_scanner,
        cfn_nag_scanner,
        checkov_scanner,
        detect_secrets_scanner,
        grype_scanner,
        npm_audit_scanner,
        opengrep_scanner,
        semgrep_scanner,
        syft_scanner,
    )
    from automated_security_helper.plugin_modules.ash_ferret_plugins import (
        ferret_scanner,
    )
    from automated_security_helper.plugin_modules.ash_snyk_plugins import (
        snyk_code_scanner,
    )
    from automated_security_helper.plugin_modules.ash_trivy_plugins import (
        trivy_repo_scanner,
    )

    models = {
        "bandit": bandit_scanner.BanditScannerConfigOptions,
        "cdk-nag": cdk_nag_scanner.CdkNagScannerConfigOptions,
        "cfn-nag": cfn_nag_scanner.CfnNagScannerConfigOptions,
        "checkov": checkov_scanner.CheckovScannerConfigOptions,
        "detect-secrets": detect_secrets_scanner.DetectSecretsScannerConfigOptions,
        "grype": grype_scanner.GrypeScannerConfigOptions,
        "npm-audit": npm_audit_scanner.NpmAuditScannerConfigOptions,
        "opengrep": opengrep_scanner.OpengrepScannerConfigOptions,
        "semgrep": semgrep_scanner.SemgrepScannerConfigOptions,
        "syft": syft_scanner.SyftScannerConfigOptions,
        "ferret-scan": ferret_scanner.FerretScannerConfigOptions,
        "snyk-code": snyk_code_scanner.SnykCodeScannerConfigOptions,
        "trivy-repo": trivy_repo_scanner.TrivyRepoScannerConfigOptions,
    }
    denied = RuntimeOverridesConfig().denied_paths
    marked = {(spec.scanner, spec.option) for spec in SCANNER_EXCLUSION_OPTIONS}
    unclassified = []
    for scanner, model in models.items():
        for option in model.model_fields:
            if not any(word in option for word in _FILTER_WORDS):
                continue
            if option in ("config_file", "secret_config_file"):
                # A tool's own config file: honored only from outside the tree
                # (config/path_trust.py), whoever names it.
                continue
            if option == "severity_threshold":
                # Decides which reported findings fail the scan, as
                # global_settings.severity_threshold does; it reports no fewer.
                continue
            if (
                (scanner, option) in marked
                or _denied_at_or_below(f"/scanners/{scanner}/options/{option}", denied)
                or (scanner, option) in _REVIEWED_NOT_HIDING
            ):
                continue
            unclassified.append(f"{scanner}.{option}")
    assert unclassified == []


def test_the_plugin_option_defaults_are_the_plugins() -> None:
    """``PLUGIN_OPTION_DEFAULTS`` holds each denied plugin option's real default."""
    from automated_security_helper.config.client_config_policy import (
        PLUGIN_OPTION_DEFAULTS,
    )

    defaults = _option_defaults()
    plugins = {
        (scanner, option)
        for scanner, option, _ in NON_PATH_EXCLUSIONS
        if scanner in ("ferret-scan", "trivy-repo")
    }
    assert set(PLUGIN_OPTION_DEFAULTS) == plugins
    for key, value in PLUGIN_OPTION_DEFAULTS.items():
        assert value == defaults[key], key


def test_the_table_defaults_are_the_scanners_defaults() -> None:
    """``SCANNER_EXCLUSION_OPTIONS`` records each option's default as ASH's own."""
    from automated_security_helper.config.client_scanner_exclusions import (
        SCANNER_EXCLUSION_OPTIONS,
        _patterns_in,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
        BanditScannerConfigOptions,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
        CheckovScannerConfigOptions,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
        OpengrepScannerConfigOptions,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
        SemgrepScannerConfigOptions,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
        SyftScannerConfigOptions,
    )
    from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
        FerretScannerConfigOptions,
    )
    from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
        TrivyRepoScannerConfigOptions,
    )

    classes = {
        "bandit": BanditScannerConfigOptions,
        "checkov": CheckovScannerConfigOptions,
        "opengrep": OpengrepScannerConfigOptions,
        "semgrep": SemgrepScannerConfigOptions,
        "syft": SyftScannerConfigOptions,
        "ferret-scan": FerretScannerConfigOptions,
        "trivy-repo": TrivyRepoScannerConfigOptions,
    }
    assert {spec.scanner for spec in SCANNER_EXCLUSION_OPTIONS} == set(classes)
    for spec in SCANNER_EXCLUSION_OPTIONS:
        default = getattr(classes[spec.scanner](), spec.option)
        assert _patterns_in(default) == set(spec.default), spec


def test_the_exclusions_reach_the_scan_context() -> None:
    """The recorded exclusions are on the config the scan's suppression step reads."""
    from automated_security_helper.config.client_config_policy import rules_from
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    source = _delivered(CASES[0])
    orchestrator = ASHScanOrchestrator.create(
        source_dir=source,
        output_dir=source / ".ash" / "ash_output",
        config_path=None,
        no_cleanup=False,
        metadata=None,
        ash_plugin_modules=[],
        client_config_policy=rules_from(get_default_config()),
    )
    context_config = orchestrator.execution_engine._context.config
    assert [item.pattern for item in context_config._client_scanner_exclusions] == [
        "client-dir"
    ]
    json.dumps(
        [item.model_dump() for item in context_config._client_scanner_exclusions]
    )
