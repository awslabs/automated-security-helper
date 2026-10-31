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
    clear_all_session_state,
)

pytestmark = pytest.mark.unit

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
    clear_all_session_state()
    reset_path_refusal_warnings()
    yield {"workspace": workspace, "target": target, "tmp": tmp_path}
    clear_profile_registry()
    clear_all_session_state()
    reset_path_refusal_warnings()


@pytest.fixture
def opened_in_tree(monkeypatch: pytest.MonkeyPatch) -> List[Path]:
    """Every path ``open_in_scanned_tree`` handed back a handle for.

    The ignore-file reader opens a delivered config's ignore file through it and
    nothing else, so a test that says a file "is not read" proves it here: the
    file never appears, whatever the warnings say. The reader imports the
    function from its module at call time, so the module attribute is replaced.
    """
    from automated_security_helper.utils import scanned_tree

    opened: List[Path] = []
    real = scanned_tree.open_in_scanned_tree

    def _record(path: Any, root: Any, *args: Any, **kwargs: Any) -> Any:
        handle = real(path, root, *args, **kwargs)
        opened.append(Path(path))
        return handle

    monkeypatch.setattr(scanned_tree, "open_in_scanned_tree", _record)
    return opened


def _never_opened(opened: List[Path], host: Path) -> None:
    """``host`` got no handle: not read, not only unquoted."""
    assert host.resolve() not in [path.resolve() for path in opened], opened


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
# trivy's and trivy-repo's ignore_file
# ---------------------------------------------------------------------------

#: The builtin trivy scanner and the trivy-repo plugin read the same ignore
#: file format, and a delivered config's is handled the same way for each.
TRIVY_SCANNERS = ["trivy-repo", "trivy"]


def _trivy_delivered(
    files: Dict[str, str], ignore_file: str, scanner: str = "trivy-repo"
) -> Path:
    document = {
        "project_name": "delivered",
        "scanners": {scanner: {"options": {"ignore_file": ignore_file}}},
    }
    return _upload({".ash/.ash.yaml": yaml.safe_dump(document), **files})


def _trivy_options(config: Any, scanner: str = "trivy-repo") -> Dict[str, Any]:
    return config.get_plugin_config("scanner", scanner)["options"]


@pytest.mark.parametrize("scanner", TRIVY_SCANNERS)
def test_a_delivered_trivy_ignore_file_is_applied_as_marked_suppressions(
    tmp_path: Path, scanner: str, opened_in_tree: List[Path]
) -> None:
    from automated_security_helper.config.ash_config import AshConfig

    other = "trivy" if scanner == "trivy-repo" else "trivy-repo"
    source = _trivy_delivered(
        {
            ".trivyignore": (
                "# comment\nCVE-2020-0001\nCVE-2020-0002 exp:2000-01-01\nAVD-AWS-0086\n"
            ),
            "app.py": "x = 1\n",
        },
        ".trivyignore",
        scanner,
    )
    config = _scan_resolution(source)
    assert isinstance(config, AshConfig), config
    assert not _trivy_options(config, scanner).get("ignore_file")
    # The control for the "is not read" tests below: the file inside the tree
    # is the one the recorder sees opened, and nothing else is.
    assert {path.resolve() for path in opened_in_tree} == {
        (source / ".trivyignore").resolve()
    }, opened_in_tree
    assert [
        (item.scanner, item.pattern) for item in config._client_scanner_exclusions
    ] == [(scanner, "CVE-2020-0001"), (scanner, "AVD-AWS-0086")]
    report = _sarif(
        [
            {"scanner": scanner, "uri": "app.py", "rule": "CVE-2020-0001"},
            {"scanner": scanner, "uri": "app.py", "rule": "AWS-0086"},
            {"scanner": scanner, "uri": "app.py", "rule": "CVE-2020-0002"},
            {"scanner": scanner, "uri": "app.py", "rule": "CVE-2020-0003"},
            {"scanner": "grype", "uri": "app.py", "rule": "CVE-2020-0001"},
            # The other trivy scanner's finding: the file was delivered for one.
            {"scanner": other, "uri": "app.py", "rule": "CVE-2020-0001"},
        ]
    )
    results = _apply(source, config, report, tmp_path).runs[0].results
    assert [len(_marks(result)) for result in results] == [1, 1, 0, 0, 0, 0]
    assert f"scanners.{scanner}.options.ignore_file" in _marks(results[0])[0]


@pytest.mark.parametrize("scanner", TRIVY_SCANNERS)
def test_a_delivered_yaml_trivy_ignore_file_keeps_its_paths(
    tmp_path: Path, scanner: str
) -> None:
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
        scanner,
    )
    config = _scan_resolution(source)
    assert isinstance(config, AshConfig), config
    report = _sarif(
        [
            {
                "scanner": scanner,
                "uri": "vendor/a/go.mod",
                "rule": "CVE-2020-0001",
            },
            {"scanner": scanner, "uri": "go.mod", "rule": "CVE-2020-0001"},
            {"scanner": scanner, "uri": "go.mod", "rule": "CVE-2020-0009"},
        ]
    )
    results = _apply(source, config, report, tmp_path).runs[0].results
    assert [len(_marks(result)) for result in results] == [1, 0, 0]


@pytest.mark.parametrize("scanner", TRIVY_SCANNERS)
def test_a_trivy_ignore_file_outside_what_the_client_delivered_is_not_read(
    _server, scanner: str, opened_in_tree: List[Path]
) -> None:
    from automated_security_helper.config.ash_config import AshConfig

    server_file = _server["tmp"] / "operator" / "elsewhere.trivyignore"
    server_file.write_text("CVE-2020-0001\n", encoding="utf-8")
    source = _trivy_delivered({"app.py": "x = 1\n"}, str(server_file), scanner)
    config = _scan_resolution(source)
    assert isinstance(config, AshConfig), config
    assert not _trivy_options(config, scanner).get("ignore_file")
    assert config._client_scanner_exclusions == []
    assert any(
        "only a regular file inside the scanned tree is read" in warning
        for warning in config._resolution_warnings
    ), config._resolution_warnings
    _never_opened(opened_in_tree, server_file)


HOST_ONLY_LINE = "CVE-2099-0001 host-only-marker-7f3a"


def _host_file(tmp: Path) -> Path:
    host = tmp / "host" / "ignore.txt"
    host.parent.mkdir(exist_ok=True)
    host.write_text(HOST_ONLY_LINE + "\n", encoding="utf-8")
    return host


def _no_trace_of_the_host_file(
    config: Any, tmp_path: Path, scanner: str = "trivy-repo"
) -> None:
    """Nothing the host file holds reached the config, its warnings, or the results."""
    assert config._client_scanner_exclusions == []
    assert "host-only-marker" not in " ".join(config._resolution_warnings)
    report = _sarif([{"scanner": scanner, "uri": "app.py", "rule": "CVE-2099-0001"}])
    source = Path(config._scanned_root or tmp_path)
    (result,) = _apply(source, config, report, tmp_path).runs[0].results
    assert not result.suppressions
    assert "host-only-marker" not in result.model_dump_json()


@pytest.mark.parametrize("scanner", TRIVY_SCANNERS)
def test_a_symlinked_trivy_ignore_file_in_the_delivered_tree_is_not_read(
    _server, tmp_path: Path, scanner: str, opened_in_tree: List[Path]
) -> None:
    """A link inside the tree that points at a host file is refused, not followed."""
    from automated_security_helper.config.ash_config import AshConfig

    host = _host_file(_server["tmp"])
    source = _trivy_delivered({"app.py": "x = 1\n"}, ".trivyignore", scanner)
    (source / ".trivyignore").symlink_to(host)
    config = _scan_resolution(source)
    assert isinstance(config, AshConfig), config
    assert not _trivy_options(config, scanner).get("ignore_file")
    assert any(
        "it is a symbolic link" in warning for warning in config._resolution_warnings
    ), config._resolution_warnings
    _no_trace_of_the_host_file(config, tmp_path, scanner)
    _never_opened(opened_in_tree, host)


def test_a_trivy_ignore_file_above_the_delivered_tree_is_not_read(
    _server, tmp_path: Path, opened_in_tree: List[Path]
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
    _never_opened(opened_in_tree, host)


def test_a_trivy_ignore_file_in_another_sessions_source_is_not_read(
    _server, tmp_path: Path, opened_in_tree: List[Path]
) -> None:
    """Another session's delivered files are not this scan's tree."""
    from automated_security_helper.config.ash_config import AshConfig

    other = _server["workspace"] / "other-session" / "source" / "notes.txt"
    other.parent.mkdir(parents=True)
    other.write_text(HOST_ONLY_LINE + "\n", encoding="utf-8")
    source = _trivy_delivered({"app.py": "x = 1\n"}, str(other))
    config = _scan_resolution(source)
    assert isinstance(config, AshConfig), config
    assert not _trivy_options(config).get("ignore_file")
    _no_trace_of_the_host_file(config, tmp_path)
    _never_opened(opened_in_tree, other)


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


@pytest.mark.parametrize("name", TRIVY_SCANNERS)
def test_the_trivy_scanner_gets_no_ignore_file_from_a_delivered_config(
    tmp_path: Path, name: str
) -> None:
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
        TrivyScanner,
        TrivyScannerConfig,
    )
    from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
        TrivyRepoScanner,
        TrivyRepoScannerConfig,
    )

    classes: Dict[str, Any] = {
        "trivy-repo": (TrivyRepoScanner, TrivyRepoScannerConfig),
        "trivy": (TrivyScanner, TrivyScannerConfig),
    }
    cls, cfg = classes[name]
    server_file = tmp_path / "operator" / "elsewhere.trivyignore"
    server_file.write_text("CVE-2020-0001\n", encoding="utf-8")
    source = _trivy_delivered({"app.py": "x = 1\n"}, str(server_file), name)
    config = _scan_resolution(source)
    output = tmp_path / "trivy-out"
    output.mkdir()
    scanner = cls(
        context=PluginContext(source_dir=source, output_dir=output, config=config),
        config=cfg.model_validate(config.get_plugin_config("scanner", name)),
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


# ---------------------------------------------------------------------------
# A scanner whose whole section a client may not set
# ---------------------------------------------------------------------------
#
# opengrep, semgrep and trivy-repo are in the always-denied floor
# (ALWAYS_DENIED_PATHS) with every other scanner that sends something off the
# host. Their exclusion options are moved out of the options first, and the
# floor then checks whatever else the delivered section sets.


#: Each scanner the floor covers, an option of it that excludes nothing with a
#: value other than its default, and the exclusion it also delivers, if it has one.
OFF_HOST_SCANNERS = [
    ("detect-secrets", "baseline_file", ".secrets.baseline", None),
    ("npm-audit", "offline", True, None),
    ("opengrep", "config", "p/default", ("exclude", ["client-dir"])),
    ("semgrep", "config", "p/default", ("exclude", ["client-dir"])),
    ("snyk-code", "honor_tree_exclusions", True, None),
    ("trivy-repo", "scanners", ["vuln"], ("ignore_file", ".trivyignore")),
]


@pytest.mark.parametrize(
    ("scanner", "option", "value", "exclusion"),
    OFF_HOST_SCANNERS,
    ids=[scanner for scanner, *_ in OFF_HOST_SCANNERS],
)
def test_an_off_host_scanners_other_options_are_still_refused(
    scanner: str, option: str, value: Any, exclusion: Any
) -> None:
    """The refusal names the other option, not the exclusion that was moved."""
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    options = {option: value}
    if exclusion is not None:
        options[exclusion[0]] = exclusion[1]
    document = {"scanners": {scanner: {"options": options}}}
    source = _upload(
        {
            ".ash/.ash.yaml": yaml.safe_dump(document),
            ".trivyignore": "CVE-2020-0001\n",
        }
    )
    outcome = _scan_resolution(source)
    assert isinstance(outcome, ASHConfigFieldDeniedError), outcome
    assert f"scanners.{scanner}.options.{option}" in str(outcome)
    if exclusion is not None:
        assert f"scanners.{scanner}.options.{exclusion[0]}" not in str(outcome)


@pytest.mark.parametrize("scanner", ["opengrep", "semgrep", "trivy-repo"])
def test_a_moved_exclusion_leaves_no_client_value_in_an_off_host_scanners_options(
    scanner: str, tmp_path: Path
) -> None:
    """What is left in the option is the operator's, and the finding is marked the client's."""
    from automated_security_helper.config.ash_config import AshConfig

    if scanner == "trivy-repo":
        source = _trivy_delivered(
            {".trivyignore": "CVE-2020-0001\n", "client-dir/app.py": "x = 1\n"},
            ".trivyignore",
        )
        option, operators = "ignore_file", {None}
        finding = {
            "scanner": scanner,
            "uri": "client-dir/app.py",
            "rule": "CVE-2020-0001",
        }
    else:
        source = _delivered(next(case for case in CASES if case.scanner == scanner))
        option = "exclude"
        operators = set(OPERATOR["scanners"][scanner]["options"]["exclude"])
        finding = {"scanner": scanner, "uri": "client-dir/app.py"}
    config = _scan_resolution(source)
    assert isinstance(config, AshConfig), config

    value = config.get_plugin_config("scanner", scanner)["options"].get(option)
    left = set(_patterns(value)) if isinstance(value, list) else {value or None}
    assert left <= operators, f"a client value reached {scanner}: {left - operators}"
    (result,) = _apply(source, config, _sarif([finding]), tmp_path).runs[0].results
    (mark,) = _marks(result)
    assert f"scanners.{scanner}.options.{option}" in mark


#: Delivered values at an exclusion option that the move does not take out
#: whole, and values at an exclusion option's name under a scanner that has no
#: such option. The floor still refuses each.
NOT_MOVED = [
    pytest.param("semgrep", "exclude", [{"not_a_path": 1}], id="semgrep-dict-entry"),
    pytest.param("opengrep", "exclude", [5], id="opengrep-number-entry"),
    pytest.param("opengrep", "exclude", "client-dir", id="opengrep-not-a-list"),
    pytest.param("trivy-repo", "ignore_file", ["a", "b"], id="trivy-list"),
    pytest.param("npm-audit", "exclude", ["client-dir"], id="npm-audit-exclude"),
    pytest.param("snyk-code", "ignore_file", ".snyk", id="snyk-code-ignore-file"),
    pytest.param("detect-secrets", "exclude", ["client-dir"], id="detect-secrets"),
]


@pytest.mark.parametrize(("scanner", "option", "value"), NOT_MOVED)
def test_a_value_the_move_does_not_take_is_still_refused(
    scanner: str, option: str, value: Any
) -> None:
    from automated_security_helper.config.ash_config import AshConfig

    document = {"scanners": {scanner: {"options": {option: value}}}}
    source = _upload({".ash/.ash.yaml": yaml.safe_dump(document)})
    outcome = _scan_resolution(source)
    # Refused, by the floor or by the option's own type, before any scanner runs.
    assert not isinstance(outcome, AshConfig), outcome
    assert isinstance(outcome, Exception), outcome


#: Each spelling of the opengrep section a delivered config might write, and
#: whether the document loader folds it onto the declared ``opengrep`` section.
#: The fold drops ASCII case and the ``-``/``_`` separators and nothing else
#: (config/plugin_section_names.folded_section_name), so a spelling with an
#: extra word is not a spelling of the declared name: it stays an extra section
#: the scanner never reads.
OTHER_SPELLINGS = [
    pytest.param("OpenGrep", True, id="case"),
    pytest.param("open-grep", True, id="separator"),
    pytest.param("opengrep-scanner", False, id="extra-word"),
]


@pytest.mark.parametrize(("spelling", "folded_onto_declared"), OTHER_SPELLINGS)
def test_a_moved_exclusion_under_another_spelling_reaches_no_scanner(
    spelling: str, folded_onto_declared: bool
) -> None:
    """Every spelling of the section is moved, and each one's record is stated.

    A spelling the loader folds onto the scanner's own section is the scanner's:
    the exclusion is moved out and recorded, as it is under the declared name. A
    spelling it leaves as an extra section the scanner never reads
    (``get_plugin_config`` reads the section spelled with the scanner's own name)
    is still moved out, so no client value stays in the config, but is recorded
    as nothing and warned about: it excluded nothing, so there is nothing to
    mark. Each spelling's outcome is written here, not read off the result: a
    spelling that the loader stopped folding, or that it refused, fails the row
    instead of passing under whichever branch the result happened to take.
    """
    from automated_security_helper.config.ash_config import AshConfig

    document = {"scanners": {spelling: {"options": {"exclude": ["client-dir"]}}}}
    source = _upload(
        {".ash/.ash.yaml": yaml.safe_dump(document), "client-dir/app.py": "x = 1\n"}
    )
    outcome = _scan_resolution(source)

    assert isinstance(outcome, AshConfig), outcome
    scanners = json.dumps(outcome.model_dump(mode="json")["scanners"])
    assert "client-dir" not in scanners, scanners
    extra = outcome.scanners.__pydantic_extra__ or {}
    recorded = [
        (item.scanner, item.option, item.pattern)
        for item in outcome._client_scanner_exclusions
    ]
    if folded_onto_declared:
        assert spelling not in extra, sorted(extra)
        assert recorded == [("opengrep", "exclude", "client-dir")]
    else:
        assert spelling in extra, sorted(extra)
        assert recorded == []
        unread = [
            warning
            for warning in outcome._resolution_warnings
            if f"scanners.{spelling}" in warning and "does not read" in warning
        ]
        assert len(unread) == 1, outcome._resolution_warnings


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
    ("npm-audit", "offline", True),
    ("grype", "offline", True),
    ("trivy-repo", "offline", True),
    ("ferret-scan", "max_live_bytes", "1KB"),
    ("cfn-guard", "rule_sets", []),
    ("cfn-lint", "ignore_checks", ["W2001"]),
    ("cfn-lint", "regions", ["eu-west-1"]),
    ("gitleaks", "baseline_path", "gitleaks-baseline.json"),
    ("gitleaks", "max_target_megabytes", 1),
    ("trivy", "scanners", ["license"]),
    ("trivy", "ignore_unfixed", True),
    ("trivy", "offline", True),
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
    from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
        GrypeScannerConfigOptions,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
        NpmAuditScannerConfigOptions,
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
    from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_guard_scanner import (
        CfnGuardScannerConfigOptions,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_lint_scanner import (
        CfnLintScannerConfigOptions,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.gitleaks_scanner import (
        GitleaksScannerConfigOptions,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
        TrivyScannerConfigOptions,
    )

    models = {
        "bandit": BanditScannerConfigOptions(),
        "cdk-nag": CdkNagScannerConfigOptions(),
        "cfn-guard": CfnGuardScannerConfigOptions(),
        "cfn-lint": CfnLintScannerConfigOptions(),
        "checkov": CheckovScannerConfigOptions(),
        "gitleaks": GitleaksScannerConfigOptions(),
        "trivy": TrivyScannerConfigOptions(),
        "detect-secrets": DetectSecretsScannerConfigOptions(),
        "grype": GrypeScannerConfigOptions(),
        "npm-audit": NpmAuditScannerConfigOptions(),
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
    """Whether ``pointer``, or a key inside it, is a default ``denied_paths`` entry.

    A glob segment in an entry (``/scanners/*/options/offline``) matches the
    pointer's segment at the same place.
    """
    from fnmatch import fnmatchcase

    parts = pointer.split("/")
    for entry in denied:
        segments = entry.split("/")
        if len(segments) >= len(parts) and all(
            fnmatchcase(part, segment) for part, segment in zip(parts, segments)
        ):
            return True
    return False


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


#: Every scanner option a delivered config may change that is neither denied
#: by default nor re-applied as a marked suppression, and why changing it leaves
#: no finding out. ``"*"`` stands for every scanner with the option. Each option
#: of each shipped scanner is in one of the three, so a new option is classified
#: before it reaches a delivered config.
_REVIEWED_OPTIONS: Dict[tuple, str] = {
    ("*", "severity_threshold"): (
        "decides which reported findings fail the scan, as "
        "global_settings.severity_threshold does; it reports no fewer"
    ),
    ("*", "scan_timeout"): (
        "a scanner that runs out of time fails, and a failed scanner is reported "
        "incomplete (fail_on_incomplete_scanners is denied)"
    ),
    ("*", "install_timeout"): (
        "a tool that cannot be installed is reported missing, which counts as "
        "incomplete"
    ),
    ("bandit", "ignore_nosec"): "the default honors # nosec; True reports more",
    ("bandit", "additional_formats"): "extra report files; findings come from SARIF",
    ("checkov", "additional_formats"): "extra report files; findings come from SARIF",
    ("checkov", "skip_ash_output_dir"): "the default skips only ASH's own output",
    ("syft", "additional_outputs"): (
        "extra output files; components come from the CycloneDX report"
    ),
    ("detect-secrets", "skip_generated_lockfiles"): "on by default; off reports more",
    ("trivy-repo", "ignore_unfixed"): "on by default; off reports more",
    ("trivy-repo", "disable_telemetry"): "telemetry, not findings",
    ("cdk-nag", "include_compliant_checks"): "adds passing checks to the output",
    ("ferret-scan", "fail_on_incomplete"): "decides the verdict, hides nothing",
    ("ferret-scan", "skip_version_check"): "tool installation, not findings",
    ("ferret-scan", "show_match"): "shows matched text in findings; reports no fewer",
    ("ferret-scan", "explain"): "annotates findings; reports no fewer",
    ("ferret-scan", "ferret_debug"): "ferret-scan's own log level",
    ("ferret-scan", "ferret_verbose"): "ferret-scan's own log level",
    ("cfn-lint", "include_checks"): "enables rules beyond the defaults; reports more",
    ("trivy", "license_full"): "off by default; on reports more license findings",
    ("trivy", "disable_telemetry"): "telemetry, not findings",
    ("zizmor", "persona"): (
        "regular, the default, reports the fewest; pedantic and auditor report more"
    ),
}


def _scanner_option_models() -> Dict[str, Any]:
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        actionlint_scanner,
        bandit_scanner,
        cdk_nag_scanner,
        cfn_guard_scanner,
        cfn_lint_scanner,
        cfn_nag_scanner,
        checkov_scanner,
        detect_secrets_scanner,
        gitleaks_scanner,
        grype_scanner,
        npm_audit_scanner,
        opengrep_scanner,
        semgrep_scanner,
        syft_scanner,
        trivy_scanner,
        zizmor_scanner,
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

    return {
        "actionlint": actionlint_scanner.ActionlintScannerConfigOptions,
        "bandit": bandit_scanner.BanditScannerConfigOptions,
        "cdk-nag": cdk_nag_scanner.CdkNagScannerConfigOptions,
        "cfn-guard": cfn_guard_scanner.CfnGuardScannerConfigOptions,
        "cfn-lint": cfn_lint_scanner.CfnLintScannerConfigOptions,
        "cfn-nag": cfn_nag_scanner.CfnNagScannerConfigOptions,
        "checkov": checkov_scanner.CheckovScannerConfigOptions,
        "detect-secrets": detect_secrets_scanner.DetectSecretsScannerConfigOptions,
        "gitleaks": gitleaks_scanner.GitleaksScannerConfigOptions,
        "grype": grype_scanner.GrypeScannerConfigOptions,
        "npm-audit": npm_audit_scanner.NpmAuditScannerConfigOptions,
        "opengrep": opengrep_scanner.OpengrepScannerConfigOptions,
        "semgrep": semgrep_scanner.SemgrepScannerConfigOptions,
        "syft": syft_scanner.SyftScannerConfigOptions,
        "trivy": trivy_scanner.TrivyScannerConfigOptions,
        "zizmor": zizmor_scanner.ZizmorScannerConfigOptions,
        "ferret-scan": ferret_scanner.FerretScannerConfigOptions,
        "snyk-code": snyk_code_scanner.SnykCodeScannerConfigOptions,
        "trivy-repo": trivy_repo_scanner.TrivyRepoScannerConfigOptions,
    }


def test_every_scanner_option_is_classified() -> None:
    """Each option of each shipped scanner is denied, marked, operator-only, or reviewed.

    An explicit table rather than a guess from the option's name, so an option
    whose name says nothing about findings is classified too. An operator-only
    option (``config/operator_only_options.OPERATOR_ONLY_SCANNER_OPTIONS``) is
    classified by the product itself: a file inside the scanned tree or one a
    client delivered cannot set it, so it is neither denied nor reviewed here.
    """
    from automated_security_helper.config.ash_config import RuntimeOverridesConfig
    from automated_security_helper.config.client_scanner_exclusions import (
        SCANNER_EXCLUSION_OPTIONS,
    )
    from automated_security_helper.config.operator_only_options import (
        OPERATOR_ONLY_SCANNER_OPTIONS,
    )
    from automated_security_helper.config.runtime_patch import _SHIPPED_PLUGIN_KEYS

    models = _scanner_option_models()
    assert set(models) == set(_SHIPPED_PLUGIN_KEYS["scanners"])
    denied = RuntimeOverridesConfig().denied_paths
    marked = {(spec.scanner, spec.option) for spec in SCANNER_EXCLUSION_OPTIONS}
    unclassified = []
    for scanner, model in models.items():
        for option in model.model_fields:
            if (
                (scanner, option) in marked
                or _denied_at_or_below(f"/scanners/{scanner}/options/{option}", denied)
                or option in OPERATOR_ONLY_SCANNER_OPTIONS.get(scanner, ())
                or (scanner, option) in _REVIEWED_OPTIONS
                or ("*", option) in _REVIEWED_OPTIONS
            ):
                continue
            unclassified.append(f"{scanner}.{option}")
    assert unclassified == []


def test_every_reviewed_option_is_a_real_one() -> None:
    """A reviewed entry for an option that is gone, or now denied, is stale."""
    from automated_security_helper.config.ash_config import RuntimeOverridesConfig

    models = _scanner_option_models()
    denied = RuntimeOverridesConfig().denied_paths
    stale = []
    for scanner, option in _REVIEWED_OPTIONS:
        owners = list(models) if scanner == "*" else [scanner]
        having = [name for name in owners if option in models[name].model_fields]
        if not having or any(
            _denied_at_or_below(f"/scanners/{name}/options/{option}", denied)
            for name in having
        ):
            stale.append(f"{scanner}.{option}")
    assert stale == []


def _denied_plugin_option_defaults() -> Dict[tuple, Any]:
    """Each option of a plugin scanner that a default ``denied_paths`` entry covers.

    Mapped to the option's default from the plugin's own model. These scanners
    have no section in the trusted base, so nothing else says what their
    default is. Read with the runtime-override matcher, so a glob entry such as
    ``/scanners/*/options/tool_version`` counts.
    """
    from automated_security_helper.config.ash_config import RuntimeOverridesConfig
    from automated_security_helper.config.runtime_patch import (
        _denied_path_reason,
        known_plugin_keys,
    )
    from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
        FerretScannerConfigOptions,
    )
    from automated_security_helper.plugin_modules.ash_snyk_plugins.snyk_code_scanner import (
        SnykCodeScannerConfigOptions,
    )
    from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
        TrivyRepoScannerConfigOptions,
    )

    denied = RuntimeOverridesConfig().denied_paths
    keys = known_plugin_keys(None)
    found: Dict[tuple, Any] = {}
    for scanner, model in (
        ("ferret-scan", FerretScannerConfigOptions()),
        ("snyk-code", SnykCodeScannerConfigOptions()),
        ("trivy-repo", TrivyRepoScannerConfigOptions()),
    ):
        for option in type(model).model_fields:
            pointer = f"/scanners/{scanner}/options/{option}"
            if any(_denied_path_reason(e, pointer, keys) for e in denied):
                value = getattr(model, option)
                found[(scanner, option)] = (
                    value.model_dump(mode="json")
                    if hasattr(value, "model_dump")
                    else value
                )
    return found


def test_the_plugin_option_defaults_are_the_plugins() -> None:
    """``PLUGIN_OPTION_DEFAULTS`` holds every denied plugin option's real default."""
    from automated_security_helper.config.client_config_policy import (
        PLUGIN_OPTION_DEFAULTS,
    )

    expected = _denied_plugin_option_defaults()
    assert ("ferret-scan", "tool_version") in expected, "the glob entry is read"
    assert dict(PLUGIN_OPTION_DEFAULTS) == expected


@pytest.mark.parametrize(
    ("scanner", "option"),
    sorted(_denied_plugin_option_defaults()),
    ids=[f"{s}.{o}" for s, o in sorted(_denied_plugin_option_defaults())],
)
def test_a_delivered_plugin_option_at_its_default_scans(
    scanner: str, option: str
) -> None:
    from automated_security_helper.config.ash_config import AshConfig

    default = _denied_plugin_option_defaults()[(scanner, option)]
    document = {"scanners": {scanner: {"options": {option: default}}}}
    source = _upload({".ash/.ash.yaml": yaml.safe_dump(document)})
    outcome = _scan_resolution(source)
    assert isinstance(outcome, AshConfig), outcome


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
    from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
        TrivyScannerConfigOptions,
    )

    classes = {
        "trivy": TrivyScannerConfigOptions,
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
