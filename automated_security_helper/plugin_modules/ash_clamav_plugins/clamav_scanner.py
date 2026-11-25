# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""ClamAV: malware detection over the scan target, as a community scanner plugin.

Shape: the template ``scan()`` flow (the same as the betterleaks plugin). Unlike
betterleaks, ``clamscan`` has no SARIF or JSON output at all, so this plugin writes
the tool's own report with ``--log=FILE`` and ``_read_results_file`` turns that text
into a SARIF document. The text is the documented stable output of ``clamscan``.

What was read from ClamAV's own documentation and source (see the plugin README):

* ``clamscan [options] [file/directory/-]``. Return codes: 0 no virus found, 1
  virus(es) found, 2 some error(s) occurred (``docs/man/clamscan.1.in``). The
  scan manager sets 1 whenever an infected file was counted, which overrides 2, and
  2 when there is no infection but an error was counted (``clamscan/manager.c``).
* A detection is the line ``<path>: <signature> FOUND``, a file it could not read is
  ``<path>: <message> ERROR`` and a clean one ``<path>: OK`` (``clamscan/manager.c``).
* The summary block that ends a scan unless ``--no-summary`` is given::

      ----------- SCAN SUMMARY -----------
      Known viruses: N
      Engine version: X
      Scanned files: N
      Infected files: N
      Data scanned: ...
      Time: ...

  (``clamscan/clamscan.c``). ASH requires this block: a log without it is a scan
  that did not finish and fails, so a truncated log is never read as clean.
* ``--recursive``, ``--follow-dir-symlinks=0`` and ``--follow-file-symlinks=0``
  (never follow a link), ``--log=FILE`` (``docs/man/clamscan.1.in``).

Flags ASH passes, and why:

* ``--recursive``: without it clamscan scans only the files directly in the directory.
* ``--follow-dir-symlinks=0 --follow-file-symlinks=0``: the defaults follow links
  given on the command line, and a link in the scanned tree must not lead the scan
  outside it.
* ``--log=<results>/<target_type>/clamav.log``: the report ASH reads.
* The scan path is the last argument and always starts with ``.`` or ``/``, so it
  can not be read as an option. ASH does not pass ``--``: the documented usage does
  not say clamscan accepts it.

Never passed: ``--database`` (a database chosen by the scanned tree could drop
signatures), ``--move``, ``--copy``, ``--remove`` (all change the scanned tree),
``--file-list`` and ``--include``/``--exclude`` (selecting files is ASH's job).

Severity: every detection is a signature match, which says the file is known
malware or a known-bad pattern. Each result is ``error`` in SARIF and HIGH in ASH.
It is HIGH and not CRITICAL, as hadolint's ``error`` is: a signature match says the
file matches, not that it ran or can be exploited, and signature sets include
potentially-unwanted-application and test (EICAR) signatures. With ASH's default
``severity_threshold`` of ``MEDIUM`` a detection still fails the scan.

Database: ClamAV needs its signature database (``freshclam``) before it can scan.
Without one clamscan exits 2 and the scan fails. A database file older than
``DATABASE_STALE_DAYS`` is noted at INFO in the scan log; it never changes the result.

Exit status: 0 and 1 mean the scan ran to completion. 2 fails the scan, even when
some files were read and some detections were logged, because an unreadable file may
be the malicious one.

Sandbox: the strict default. The database directory is outside the default read-only
paths, so a sandboxed run waits for the sandbox's grant gates; see the plugin README.
"""

from __future__ import annotations

import logging
import os
import re
import time
from pathlib import Path
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple

from pydantic import Field

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    Kind,
    Level,
    PropertyBag,
    SarifReport,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: Exit code clamscan returns when it found at least one infected file.
INFECTED_EXIT_CODE = 1

#: ASH severity and SARIF level of every detection. See "Severity" above.
DETECTION_SEVERITY = "HIGH"

#: Days after which a signature database file is noted as stale.
DATABASE_STALE_DAYS = 7

#: Where distributions and package managers put the database, searched in order.
DATABASE_DIRS = (
    "/var/lib/clamav",
    "/usr/local/share/clamav",
    "/usr/local/var/lib/clamav",
    "/opt/homebrew/var/lib/clamav",
)
DATABASE_FILES = ("daily.cvd", "daily.cld")

SUMMARY_HEADER = "----------- SCAN SUMMARY -----------"

_FOUND = re.compile(r"^(?P<path>.+): (?P<signature>\S+) FOUND$")
_ERROR = re.compile(r"^.+: .* ERROR$")
_INFECTED = re.compile(r"^Infected files: (?P<count>\d+)$")
_ENGINE = re.compile(r"^Engine version: (?P<version>\S+)$")

INSTALL_HINT = (
    "ClamAV is a system package, not downloaded by ASH: install clamav "
    "(for example `apt-get install clamav`, `dnf install clamav` or "
    "`brew install clamav`) and run `freshclam` once to fetch the signature database."
)


def parse_clamscan_log(text: str) -> Dict[str, Any]:
    """The detections, error count and engine version in a ``clamscan --log`` text.

    Raises ``ScannerError`` when the log has no summary block, has no
    ``Infected files:`` line, or when that count and the ``FOUND`` lines disagree: each
    is a log that does not describe a finished scan.
    """
    lines = [line.rstrip("\r") for line in text.split("\n")]
    if SUMMARY_HEADER not in lines:
        raise ScannerError(
            "the clamscan log has no SCAN SUMMARY block, so the scan did not finish"
        )
    summary_at = lines.index(SUMMARY_HEADER)
    infected: Optional[int] = None
    engine: Optional[str] = None
    for line in lines[summary_at + 1 :]:
        match = _INFECTED.match(line)
        if match:
            infected = int(match.group("count"))
        match = _ENGINE.match(line)
        if match:
            engine = match.group("version")
    if infected is None:
        raise ScannerError("the clamscan summary has no 'Infected files' line")
    detections: List[Tuple[str, str]] = []
    errors = 0
    for line in lines[:summary_at]:
        found = _FOUND.match(line)
        if found:
            detections.append((found.group("path"), found.group("signature")))
        elif _ERROR.match(line):
            errors += 1
    if (infected == 0) != (len(detections) == 0):
        raise ScannerError(
            f"the clamscan summary counts {infected} infected file(s) but the log "
            f"holds {len(detections)} detection line(s)"
        )
    return {"detections": detections, "errors": errors, "engine": engine}


def detections_to_sarif(parsed: Dict[str, Any]) -> Dict[str, Any]:
    """A SARIF 2.1.0 document with one result per detection."""
    rule_ids: List[str] = []
    results: List[Dict[str, Any]] = []
    for path, signature in parsed["detections"]:
        if signature not in rule_ids:
            rule_ids.append(signature)
        uri = path.removeprefix("./")
        results.append(
            {
                "ruleId": signature,
                "ruleIndex": rule_ids.index(signature),
                "level": "error",
                "kind": "fail",
                "message": {"text": f"ClamAV detected {signature}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {"startLine": 1},
                        }
                    }
                ],
            }
        )
    driver: Dict[str, Any] = {
        "name": "ClamAV",
        "informationUri": "https://www.clamav.net/",
        "rules": [
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": f"ClamAV signature {rule_id}"},
            }
            for rule_id in rule_ids
        ],
    }
    if parsed.get("engine"):
        driver["version"] = parsed["engine"]
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{"tool": {"driver": driver}, "results": results}],
    }


def database_age_days(dirs: Tuple[str, ...] = DATABASE_DIRS) -> Optional[float]:
    """Age in days of the newest ``daily`` database file in ``dirs``, or None."""
    newest: Optional[float] = None
    for directory in dirs:
        for name in DATABASE_FILES:
            try:
                mtime = os.stat(os.path.join(directory, name)).st_mtime
            except OSError:
                continue
            if newest is None or mtime > newest:
                newest = mtime
    if newest is None:
        return None
    return max(0.0, (time.time() - newest) / 86400.0)


class ClamAVScannerConfigOptions(ScannerOptionsBase):
    """No tool options: the base ``scan_timeout``, ``severity_threshold`` and ``offline``."""


class ClamAVScannerConfig(ScannerPluginConfigBase):
    name: Literal["clamav"] = "clamav"
    enabled: bool = True
    options: Annotated[
        ClamAVScannerConfigOptions,
        Field(description="Configure the clamav scanner"),
    ] = ClamAVScannerConfigOptions()


@ash_scanner_plugin
class ClamAVScanner(ScannerPluginBase[ClamAVScannerConfig]):
    """Malware detection over the scan target's files using ClamAV's clamscan."""

    #: Not Python-only: clamscan is a native system package.
    python_only: ClassVar[bool | None] = False

    # The signature database is read from disk; clamscan makes no network call.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    success_exit_codes: ClassVar[Set[int]] = {0, INFECTED_EXIT_CODE}
    # The strict default; see "Sandbox" in the module docstring.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = ClamAVScannerConfig()
        self.command = "clamscan"
        # CUSTOM: ASH has no malware tool type.
        self.tool_type = ScannerToolType.CUSTOM
        # The argv is assembled in _execute_scan; nothing from the base resolver is added.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("ClamAVScanner has no plugin context")
        return Path(self.context.source_dir)

    def nothing_to_scan_reason(self) -> Optional[str]:
        """None: any file can hold malware, ASH makes no selection of its own."""
        return None

    def _scan_path(self, target: Path) -> str:
        """``.`` for the source (the working directory), else an absolute path."""
        if Path(target).absolute() == self._source_dir().absolute():
            return "."
        return Path(target).absolute().as_posix()

    def _build_arguments(self, target: Path, results_file: Path) -> List[str]:
        return [
            self.command or "clamscan",
            "--recursive",
            "--follow-dir-symlinks=0",
            "--follow-file-symlinks=0",
            f"--log={results_file.as_posix()}",
            self._scan_path(target),
        ]

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        if self.results_dir is None:
            raise ScannerError("ClamAVScanner has no results directory")
        self.exit_code = 0
        results_file = (
            Path(self.results_dir).absolute().joinpath(target_type, "clamav.log")
        )
        results_file.parent.mkdir(exist_ok=True, parents=True)
        # A log left by an earlier run must not be read as this run's.
        results_file.unlink(missing_ok=True)
        age = database_age_days()
        if age is not None and age > DATABASE_STALE_DAYS:
            self._plugin_log(
                f"The ClamAV signature database is {int(age)} days old "
                f"(over {DATABASE_STALE_DAYS}); run `freshclam` to update it.",
                target_type=target_type,
                level=logging.INFO,
            )
        final_args = self._build_arguments(target, results_file)
        self._plugin_log(
            f"Running: {' '.join(final_args)}",
            target_type=target_type,
            level=logging.DEBUG,
        )
        return final_args, results_file, None

    def _read_results_file(self, results_file: Path) -> Optional[Dict[str, Any]]:
        """The clamscan log, as a SARIF document; refuses a run that did not finish."""
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"clamscan exited {self.exit_code}; it exits 0 when it finds nothing "
                f"and {INFECTED_EXIT_CODE} when it finds malware, and 2 when it hit an "
                "error (an unreadable file or no signature database), so this run failed"
            )
        from automated_security_helper.utils.sandbox.fs_guard import (
            read_bytes_at_most,
        )

        data = read_bytes_at_most(results_file, (1 << 30) + 1)
        text = data.decode("utf-8", errors="replace")
        if not text.strip():
            return None
        parsed = parse_clamscan_log(text)
        if parsed["errors"]:
            self._plugin_log(
                f"clamscan reported {parsed['errors']} file(s) it could not scan; "
                "see the clamav.log in the results directory.",
                level=logging.WARNING,
            )
        return detections_to_sarif(parsed)

    def _process_command_response(self, response: Dict[str, Any]) -> None:
        """Count the exit code; keep clamscan's stderr out of ``self.errors``.

        Its error lines quote file names from the scanned tree.
        """
        super()._process_command_response(
            {key: value for key, value in response.items() if key != "stderr"}
        )

    def _drop_results_under_output_dir(
        self, sarif_report: SarifReport, target: Path
    ) -> None:
        """Remove results under ASH's own output directory inside ``target``."""
        if self.context is None:
            return
        roots: List[Path] = []
        own = self._output_dir_inside(target)
        if own is not None:
            roots.append(own)
        for relative in self._ash_output_dirs_inside(target):
            if relative not in roots:
                roots.append(relative)
        if not roots:
            return
        target_abs = Path(target).absolute()
        output_roots = [Path(os.path.normpath(target_abs / r)) for r in roots]
        for run in sarif_report.runs or []:
            kept = []
            for result in run.results or []:
                uri = None
                for location in result.locations or []:
                    physical = location.physicalLocation
                    artifact = physical.root.artifactLocation if physical else None
                    uri = artifact.uri if artifact else None
                if uri and any(
                    Path(os.path.normpath(target_abs / uri)).is_relative_to(root)
                    for root in output_roots
                ):
                    continue
                kept.append(result)
            run.results = kept

    def _post_process_sarif(
        self,
        sarif_report: SarifReport,
        final_args: List[str],
        target: Path,
    ) -> SarifReport:
        """Drop ASH's own files, then rate every result (see "Severity")."""
        self._drop_results_under_output_dir(sarif_report, target)
        for result in sarif_report.get_all_results():
            result.level = Level.error
            result.kind = Kind.fail
            tags = list(getattr(result.properties, "tags", None) or [])
            for tag in ("malware", "security"):
                if tag not in tags:
                    tags.append(tag)
            if result.properties is None:
                result.properties = PropertyBag(tags=tags)
            else:
                result.properties.tags = tags
            setattr(result.properties, "issue_severity", DETECTION_SEVERITY)  # noqa: B010
        return sarif_report

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "clamscan")
        if not found:
            ASH_LOGGER.warning(f"clamscan executable not found in PATH. {INSTALL_HINT}")
        return found is not None


__all__ = [
    "ClamAVScanner",
    "ClamAVScannerConfig",
    "ClamAVScannerConfigOptions",
    "DATABASE_STALE_DAYS",
    "DETECTION_SEVERITY",
    "INFECTED_EXIT_CODE",
    "detections_to_sarif",
    "parse_clamscan_log",
]
