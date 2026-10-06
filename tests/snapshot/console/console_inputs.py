# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Inputs for the scan-console snapshot tests, built explicitly so each row says why it is there.

The model below is small on purpose. Every scanner in it exists to put one row state on the
console, and the docstring of :func:`scan_results_model` lists which. A snapshot of this output
is only a useful contract if a reader can tell, from the input alone, what the output should
say; a model copied from a real scan would carry dozens of rows whose purpose nobody recorded.

Everything a run would otherwise choose is pinned here instead: durations, the time a content
database was built, the moment its age was measured. The shared normalizer would mask most of
those anyway, but a pinned input keeps the counts that sit next to them (``10d 3h old``) stable
too, and the normalizer cannot know which of those are wall-clock.

Rendering helpers live here as well, because every console test needs the same two things: a
rich ``Console`` that renders for a fixed terminal, and a way to point ASH's module-level
``rich.print`` at it. ``rich.print`` writes through ``rich.get_console()``, a process-wide
console whose width is fixed when it is first built, so without the swap the snapshot would
depend on which test in the worker happened to touch it first.
"""

from __future__ import annotations

import io
from datetime import datetime, timedelta, timezone
from typing import Optional

import rich
from rich.console import Console

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.config.resolve_config import apply_config_overrides
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ConverterStatusInfo,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Kind1,
    Location,
    Message,
    Message1,
    PhysicalLocation,
    PhysicalLocation2,
    PropertyBag,
    Region,
    Result,
    Suppression,
)
from automated_security_helper.utils import content_databases as cdb
from automated_security_helper.utils.content_db_staleness import (
    ContentDbAgeRecord,
    attach_records,
)

#: The widths every table snapshot is taken at: one either side of the 100-column cutoff at
#: which ``generate_metrics_table_from_unified_data`` switches to abbreviated headers.
WIDE = 120
NARROW = 80

#: When every content database in these inputs was measured. A fixed instant, so a record's
#: age is a property of the input rather than of the day the test ran.
MEASURED_AT = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)

UTC = timezone.utc


# --------------------------------------------------------------------------- rendering


def recording_console(width: int, height: int = 50, soft_wrap: bool = False) -> Console:
    """A Console that renders for a pinned terminal and keeps what it printed.

    ``soft_wrap=True`` stops rich folding long lines at ``width``. Use it only for output
    that prints an absolute temp path: the path's length is the machine's, so where rich
    folds it would differ between a laptop, a Linux runner and a Windows runner, and no
    normalizer can rejoin half a path.

    ``_environ={}`` is the load-bearing argument: without it rich reads COLUMNS, TERM and
    NO_COLOR from the process, which is the test runner's terminal rather than the one the
    snapshot claims to show. ``legacy_windows=False`` because the legacy renderer writes
    through the Win32 console API instead of the stream, so on a Windows host nothing would
    reach the buffer.
    """
    return Console(
        file=io.StringIO(),
        width=width,
        height=height,
        color_system=None,
        force_terminal=False,
        legacy_windows=False,
        emoji=True,
        soft_wrap=soft_wrap,
        _environ={},
    )


def stdout_console(width: int) -> Console:
    """A pinned Console that writes to whatever ``sys.stdout`` is when it prints.

    For commands run through ``CliRunner``, which swaps ``sys.stdout`` for the duration of
    the call; rich resolves ``file=None`` to ``sys.stdout`` on every write.
    """
    return Console(
        width=width,
        color_system=None,
        force_terminal=False,
        legacy_windows=False,
        _environ={},
    )


def rendered(console: Console) -> str:
    """Everything ``console`` printed."""
    return console.file.getvalue()


def route_rich_print(monkeypatch, console: Console) -> None:
    """Point every module-level ``rich.print`` / ``rich.print_json`` at ``console``.

    Both read ``rich.get_console()``, which returns ``rich._console`` once it is set, so one
    swap covers run_ash_scan, cli/report.py and cli/merge.py without patching their imports.
    """
    monkeypatch.setattr(rich, "_console", console)


# --------------------------------------------------------------------------- findings


def finding(
    scanner: str,
    rule_id: str,
    severity: str,
    path: str,
    line: int,
    text: str,
    *,
    suppressed: bool = False,
) -> Result:
    """One SARIF result attributed to ``scanner``, the way the aggregate stores it."""
    return Result(
        ruleId=rule_id,
        message=Message(root=Message1(text=text)),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    root=PhysicalLocation2(
                        artifactLocation=ArtifactLocation(uri=path),
                        region=Region(startLine=line, endLine=line),
                    )
                )
            )
        ],
        properties=PropertyBag.model_validate(
            {"scanner_name": scanner, "issue_severity": severity}
        ),
        suppressions=(
            [
                Suppression(
                    kind=Kind1.external,
                    justification="Accepted risk: test fixture",
                )
            ]
            if suppressed
            else None
        ),
    )


def _target(
    scanner: str,
    status: str,
    *,
    duration: Optional[float] = None,
    attempted: Optional[int] = None,
    failed: Optional[int] = None,
    excluded: bool = False,
) -> dict:
    """One serialized per-target container, shaped like ``ScanResultProcessor`` writes it.

    Keys are omitted rather than set to None or zero when the producer would not have set
    them (it dumps with ``exclude_unset``), because absence and zero mean different things
    to the coverage code: absent is "does not track targets", zero is "tracked, attempted
    none".
    """
    report: dict = {"scanner_name": scanner, "status": status}
    if duration is not None:
        report["duration"] = duration
    if attempted is not None:
        report["targets_attempted"] = attempted
    if failed is not None:
        report["targets_failed"] = failed
    if excluded:
        report["excluded"] = True
    return report


# --------------------------------------------------------------------------- content databases


def content_db_record(
    name: str,
    *,
    policy: str,
    age: Optional[timedelta],
    error: Optional[str] = None,
) -> ContentDbAgeRecord:
    """A measurement of the declared database ``name``, taken at :data:`MEASURED_AT`.

    ``age=None`` is the unreadable case: no build time, with ``error`` saying why. Every other
    field comes from the registry, so the refresh advice and the bound in the message are the
    ones ASH ships rather than test prose.
    """
    entry = cdb.get(name)
    return ContentDbAgeRecord(
        name=entry.name,
        scanner=entry.scanner,
        built=None if age is None else MEASURED_AT - age,
        measured_by=entry.age_source,
        max_age=entry.max_age,
        measured_at=MEASURED_AT,
        policy=policy,
        bound_source=entry.bound_source,
        bound_is_tool_default=entry.bound_is_tool_default,
        refresh=entry.refresh,
        error=error,
        timestamp_label=entry.timestamp_label,
    )


def stale_records() -> list[ContentDbAgeRecord]:
    """One enforced stale database, one warned, and one whose age could not be read."""
    return [
        content_db_record(
            "semgrep-offline-rules",
            policy=cdb.STALENESS_FAIL,
            age=cdb.get("semgrep-offline-rules").max_age + timedelta(days=3, hours=4),
        ),
        content_db_record(
            "opengrep-offline-rules",
            policy=cdb.STALENESS_WARN,
            age=cdb.get("opengrep-offline-rules").max_age + timedelta(hours=7),
        ),
        content_db_record(
            "grype-db",
            policy=cdb.STALENESS_FAIL,
            age=None,
            error="ValueError: grype executable not found",
        ),
    ]


# --------------------------------------------------------------------------- the model


def scan_results_model(
    *,
    with_stale_databases: bool = False,
    with_incomplete_scanners: bool = True,
) -> AshAggregatedResults:
    """Aggregated results whose rows cover every state the summary table can print.

    Default threshold MEDIUM (global). Row by row:

    ========================  ===================================================================
    bandit                    FAILED. 1 high, 2 medium, 1 low, 1 suppressed: 3 actionable.
    semgrep                   FAILED. 1 critical, 2 info, 2 suppressed: 1 actionable.
    checkov                   PASSED. 2 low and 1 info, all under the threshold.
    opengrep                  PASSED on a per-scanner threshold: 1 high under CRITICAL (config).
    cdk-nag                   PASSED, but evaluated 6 of 10 targets: "Incomplete coverage".
    detect-secrets            SKIPPED because it had nothing to evaluate (attempted 0).
    syft                      SKIPPED because the operator excluded it.
    grype                     MISSING: its dependencies were not available.
    npm-audit                 ERROR: it ran and produced no usable result.
    ========================  ===================================================================

    ``with_incomplete_scanners=False`` drops cdk-nag, grype and npm-audit, leaving a model that
    completes but has actionable findings (the exit-2 path). ``with_stale_databases`` attaches
    :func:`stale_records` to the SARIF.
    """
    config = apply_config_overrides(
        get_default_config(), ["scanners.opengrep.options.severity_threshold=CRITICAL"]
    )
    model = AshAggregatedResults(ash_config=config)

    results = [
        finding(
            "bandit",
            "B602",
            "HIGH",
            "src/app.py",
            12,
            "subprocess call with shell=True",
        ),
        finding(
            "bandit",
            "B105",
            "MEDIUM",
            "src/config.py",
            3,
            "Possible hardcoded password",
        ),
        finding(
            "bandit",
            "B108",
            "MEDIUM",
            "src/app.py",
            40,
            "Probable insecure usage of temp file",
        ),
        finding(
            "bandit", "B101", "LOW", "tests/test_app.py", 8, "Use of assert detected"
        ),
        finding(
            "bandit",
            "B311",
            "LOW",
            "src/util.py",
            5,
            "Standard pseudo-random generator",
            suppressed=True,
        ),
        finding(
            "semgrep",
            "python.lang.security.eval",
            "CRITICAL",
            "src/app.py",
            77,
            "Detected use of eval()",
        ),
        finding(
            "semgrep",
            "generic.secrets.gitleaks",
            "INFO",
            "README.md",
            1,
            "Example key in docs",
        ),
        finding(
            "semgrep",
            "python.lang.best-practice.open",
            "INFO",
            "src/util.py",
            9,
            "open() without encoding",
        ),
        finding(
            "semgrep",
            "python.flask.debug",
            "HIGH",
            "src/web.py",
            4,
            "Flask debug mode",
            suppressed=True,
        ),
        finding(
            "semgrep",
            "python.requests.no-timeout",
            "MEDIUM",
            "src/web.py",
            20,
            "Request without timeout",
            suppressed=True,
        ),
        finding(
            "checkov",
            "CKV_AWS_18",
            "LOW",
            "infra/bucket.yaml",
            6,
            "S3 access logging disabled",
        ),
        finding(
            "checkov",
            "CKV_AWS_21",
            "LOW",
            "infra/bucket.yaml",
            6,
            "S3 versioning disabled",
        ),
        finding(
            "checkov",
            "CKV_AWS_144",
            "INFO",
            "infra/bucket.yaml",
            6,
            "Cross-region replication off",
        ),
        finding(
            "opengrep",
            "javascript.express.xss",
            "HIGH",
            "web/server.js",
            31,
            "Unescaped user input",
        ),
    ]
    model.sarif.runs[0].results = results

    reports: dict[str, dict] = {
        "bandit": {"source": _target("bandit", "FAILED", duration=12.5)},
        "semgrep": {"source": _target("semgrep", "FAILED", duration=48.0)},
        "checkov": {"source": _target("checkov", "PASSED", duration=0.5)},
        "opengrep": {"source": _target("opengrep", "PASSED", duration=95.0)},
        "detect-secrets": {
            "source": _target("detect-secrets", "SKIPPED", duration=0.25, attempted=0)
        },
        "syft": {"None": _target("syft", "SKIPPED", excluded=True)},
    }
    if with_incomplete_scanners:
        reports["cdk-nag"] = {
            "source": _target("cdk-nag", "PASSED", duration=7.0, attempted=8, failed=4),
            "converted": _target("cdk-nag", "PASSED", attempted=2, failed=0),
        }
        reports["grype"] = {"None": _target("grype", "MISSING")}
        reports["npm-audit"] = {"source": _target("npm-audit", "ERROR", duration=1.0)}
    model.additional_reports = reports

    if with_stale_databases:
        attach_records(model.sarif, stale_records())
    return model


def incomplete_converter_rows_model() -> AshAggregatedResults:
    """A model whose only shortfall is conversion: one converter raised, one had no tool."""
    model = AshAggregatedResults(ash_config=get_default_config())
    model.converter_results = {
        "jupyter": ConverterStatusInfo(failure="RuntimeError: nbconvert exited 1"),
        "archive": ConverterStatusInfo(
            dependencies_satisfied=False, candidate_inputs=3
        ),
        "disabled-one": ConverterStatusInfo(excluded=True),
    }
    return model


__all__ = [
    "MEASURED_AT",
    "NARROW",
    "WIDE",
    "content_db_record",
    "finding",
    "incomplete_converter_rows_model",
    "recording_console",
    "rendered",
    "route_rich_print",
    "scan_results_model",
    "stale_records",
    "stdout_console",
]
