import json
from pathlib import Path
from stat import S_ISREG

from automated_security_helper.config.config_validator import describe_results_error
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.finding_diff import (
    ComparabilityRefusal,
    check_comparable,
)


class ScanResultsRefused(Exception):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def read_regular_file(path: Path) -> bytes:
    try:
        if not S_ISREG(path.stat().st_mode):
            raise ScanResultsRefused("expected a regular scan results file")
        return path.read_bytes()
    except OSError as exc:
        raise ScanResultsRefused(exc.strerror or type(exc).__name__) from exc
    except ValueError as exc:
        raise ScanResultsRefused("invalid path or JSON data") from exc


def parse_full_scan_results(data: bytes) -> AshAggregatedResults:
    try:
        parsed = json.loads(data.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ScanResultsRefused(
            f"invalid JSON at line {exc.lineno}, column {exc.colno}"
        ) from exc
    except UnicodeDecodeError as exc:
        raise ScanResultsRefused(describe_results_error(exc)) from exc
    except (ValueError, RecursionError) as exc:
        raise ScanResultsRefused("invalid path or JSON data") from exc
    if not isinstance(parsed, dict):
        raise ScanResultsRefused("expected scan results with metadata and SARIF runs")
    metadata, sarif = parsed.get("metadata"), parsed.get("sarif")
    if (
        not isinstance(metadata, dict)
        or not isinstance(sarif, dict)
        or not isinstance(sarif.get("runs"), list)
    ):
        raise ScanResultsRefused("expected scan results with metadata and SARIF runs")
    try:
        result = AshAggregatedResults.model_validate(parsed)
    except ValueError as exc:
        raise ScanResultsRefused(describe_results_error(exc)) from exc
    try:
        check_comparable(result)
    except ComparabilityRefusal as exc:
        raise ScanResultsRefused(str(exc)) from exc
    return result
