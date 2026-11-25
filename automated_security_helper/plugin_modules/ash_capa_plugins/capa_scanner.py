# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""CapaScanner: capability detection in executables using Mandiant's capa.

capa (https://github.com/mandiant/capa, Apache-2.0) reports what a compiled program
can DO ("create a process", "encrypt data using RC4", "persist via a Run key"), by
matching its rule set against the functions of a PE or ELF file. These are
capabilities, not vulnerabilities: most legitimate programs have many. The plugin
therefore never rates a result above LOW. See "Severity".

What it runs
------------
One ``capa`` process per executable the scan set holds, because capa analyzes exactly
one input file per run::

    capa -q -j -- <file>

* ``-j`` / ``--json``: "emit JSON instead of text"; the document is written to stdout.
* ``-q`` / ``--quiet``: "disable all output but errors", so stdout is the document.
* ``--`` ends option parsing, so a file whose name starts with a dash is a file.
* No ``-r`` and no ``-s``: capa's help says it uses "embedded rules by default" and
  "embedded signatures by default". The standalone release bundles both, so a scan
  makes no network call and reads no rule file from the scanned tree.
* No ``-f``, ``-b`` or ``--os``: capa auto-detects format, backend and OS.

Source: ``capa/main.py`` (``install_common_args`` and ``main``) and ``README.md`` at
the v10.0.0 tag. The flag text above is quoted from that source. The JSON document is
``capa.render.result_document.ResultDocument``: ``meta`` and ``rules``, where ``rules``
maps a rule name to ``{"meta": ..., "source": ..., "matches": [[address, match], ...]}``.

Targets
-------
A file is handed to capa only when its first bytes are a PE (``MZ``) or ELF
(``\\x7fELF``) header, the two static formats capa analyzes that can be told apart
without parsing. Shellcode, which capa also accepts, has no signature and is never
selected. Files over ``MAX_SAMPLE_BYTES`` are skipped with a warning. The files come
from ASH's scan set (so ``.gitignore`` and ``ignore_paths`` apply); a link resolving
outside the scanned tree is skipped, as hadolint does.

Exit status
-----------
capa exits 0 on success and a code from 10 to 26 when it did not analyze the file
(``E_CORRUPT_FILE`` 13, ``E_FILE_LIMITATION`` 14, ``E_INVALID_FILE_TYPE`` 16,
``E_INVALID_FILE_ARCH`` 17, ``E_INVALID_FILE_OS`` 18, and so on). Nothing in capa's
exit status means "found something", so ``success_exit_codes`` is ``{0}`` and any
other code makes that file a FAILED TARGET, not a finding: no rule was evaluated on it.
capa's stderr can quote the analyzed file, so it is never copied into ``errors``.

Severity
--------
Every result is a capability, reported at the lowest levels ASH has:

* a rule with an ATT&CK or MBC mapping: ``LOW`` / SARIF ``note``;
* a rule with neither: ``INFO`` / SARIF ``none``.

The mapping is a judgment about the tool: capa says a program is able to do something,
not that it is wrong to. Library rules (``meta.lib``) and sub-scope rules are
implementation detail of other rules and are not reported.

Offline
-------
capa's rules and signatures are embedded in the standalone release. No network at scan
time.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Set

from pydantic import AnyUrl, Field, model_validator

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.download_utils import (
    pinned_tool_install_commands,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: The clock the scan's time budget is measured on; a seam for tests.
_now = time.monotonic

#: First bytes of the two formats the scanner selects. See "Targets".
PE_MAGIC = b"MZ"
ELF_MAGIC = b"\x7fELF"

#: Largest file handed to capa, in bytes. capa reads the whole file into memory and
#: disassembles it; a larger file is skipped with a warning.
MAX_SAMPLE_BYTES = 256 * 1024 * 1024

#: Rating of a capability (ASH severity, SARIF level), by whether the rule maps to
#: ATT&CK or MBC. See "Severity" in the module docstring.
MAPPED_SEVERITY = ("LOW", "note")
UNMAPPED_SEVERITY = ("INFO", "none")

#: Why a capa run produced no analysis, by exit code (capa/main.py).
CAPA_EXIT_MEANINGS: Dict[int, str] = {
    10: "default rules missing",
    11: "input file missing",
    12: "invalid rule",
    13: "corrupt file",
    14: "file limitation (for example a packed file)",
    15: "invalid signature",
    16: "invalid file type",
    17: "unsupported architecture",
    18: "unsupported OS",
}


def is_supported_executable(path: Path) -> bool:
    """Whether *path* starts with a PE or ELF header."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(4)
    except OSError:
        return False
    return head.startswith((PE_MAGIC, ELF_MAGIC))


def _rule_ids(spec: Any) -> List[str]:
    """The ids of an ATT&CK or MBC list, whatever form capa serialized each in."""
    ids: List[str] = []
    for entry in spec or []:
        value = entry.get("id") if isinstance(entry, dict) else None
        if isinstance(value, str) and value:
            ids.append(value)
    return ids


def _addresses(matches: Any, limit: int = 5) -> List[Any]:
    """The first *limit* match addresses of a rule, as capa wrote them."""
    found: List[Any] = []
    for pair in matches or []:
        if isinstance(pair, (list, tuple)) and pair:
            address = pair[0]
            value = address.get("value") if isinstance(address, dict) else address
            if value is not None:
                found.append(value)
        if len(found) >= limit:
            break
    return found


def convert_capa_document(document: Dict[str, Any], uri: str) -> List[Dict[str, Any]]:
    """SARIF result dicts for one capa JSON document, one per capability.

    Raises ``ValueError`` when *document* is not a capa result document. Library and
    sub-scope rules are skipped. A rule with no matches is skipped: capa lists only
    rules that matched, so an empty list is not a capability.
    """
    if not isinstance(document, dict) or not isinstance(document.get("rules"), dict):
        raise ValueError("not a capa result document (no 'rules' object)")
    results: List[Dict[str, Any]] = []
    for name, rule in document["rules"].items():
        if not isinstance(rule, dict) or not isinstance(rule.get("meta"), dict):
            raise ValueError(f"rule {name!r} has no 'meta' object")
        meta = rule["meta"]
        if (
            meta.get("lib")
            or meta.get("is_subscope_rule")
            or meta.get("capa/subscope-rule")
        ):
            continue
        matches = rule.get("matches") or []
        if not matches:
            continue
        attack = _rule_ids(meta.get("attack") or meta.get("att&ck"))
        mbc = _rule_ids(meta.get("mbc"))
        severity, level = MAPPED_SEVERITY if (attack or mbc) else UNMAPPED_SEVERITY
        namespace = meta.get("namespace") or ""
        text = f"capa capability: {meta.get('name') or name}"
        if namespace:
            text += f" ({namespace})"
        text += f"; {len(matches)} match(es)."
        if attack or mbc:
            text += " Mapped to " + ", ".join(attack + mbc) + "."
        properties: Dict[str, Any] = {
            "issue_severity": severity,
            "tags": ["capability"],
            "match_count": len(matches),
            "match_addresses": _addresses(matches),
        }
        if namespace:
            properties["namespace"] = namespace
        if attack:
            properties["attack_ids"] = attack
        if mbc:
            properties["mbc_ids"] = mbc
        results.append(
            {
                "ruleId": str(meta.get("name") or name),
                "level": level,
                "message": {"text": text},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "properties": properties,
            }
        )
    return results


class CapaScannerConfigOptions(ScannerOptionsBase):
    """capa takes no scanner-specific options: ``severity_threshold``,
    ``scan_timeout`` and ``offline`` come from the base."""


class CapaScannerConfig(ScannerPluginConfigBase):
    name: Literal["capa"] = "capa"
    enabled: bool = True
    options: Annotated[
        CapaScannerConfigOptions,
        Field(description="Configure the capa scanner"),
    ] = CapaScannerConfigOptions()


@ash_scanner_plugin
class CapaScanner(ScannerPluginBase[CapaScannerConfig]):
    """Capability detection over the executables in the scan target using capa."""

    #: Not Python-only: capa is a native binary installed from its pinned release.
    python_only: ClassVar[bool | None] = False

    # Rules and signatures are embedded in the standalone release.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    success_exit_codes: ClassVar[Set[int]] = {0}
    # The strict default: no network, baseline environment. Option- or env-derived
    # grants wait for the sandbox grant gates; capa needs neither.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = CapaScannerConfig()
        self.command = "capa"
        self.tool_type = ScannerToolType.SAST
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "CapaScanner":
        """Install capa from the pinned release asset (see tool_downloads)."""
        self.custom_install_commands.update(pinned_tool_install_commands("capa"))
        return self

    def _execute_scan(
        self, target: Any, target_type: Any, global_ignore_paths: Any
    ) -> Any:
        """Abstract stub: capa analyzes one file per run, so scan() is overridden."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    @property
    def _ctx(self) -> PluginContext:
        if self.context is None:  # pragma: no cover - model_post_init raises first
            raise ScannerError("CapaScanner has no plugin context")
        return self.context

    def _executables(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> List[Path]:
        """The PE and ELF files under *target* to analyze, sorted."""
        from automated_security_helper.utils.scan_output_dirs import scan_set_of
        from automated_security_helper.utils.suppression_matcher import (
            file_path_matches,
        )

        if target_type == "converted":
            candidates = list(Path(self._ctx.work_dir).rglob("*"))
        else:
            candidates = [Path(p) for p in scan_set_of(self._ctx)]

        root = Path(target).resolve()
        absolute_output_dir = Path(self._ctx.output_dir).absolute()
        source_dir = Path(self._ctx.source_dir).resolve()

        selected: List[Path] = []
        for path in candidates:
            if target_type == "source" and path.absolute().is_relative_to(
                absolute_output_dir
            ):
                continue
            try:
                if not path.is_file():
                    continue
                resolved = path.resolve()
                size = resolved.stat().st_size
            except (OSError, RuntimeError):
                continue
            if not resolved.is_relative_to(root):
                self._plugin_log(
                    f"Skipping {path.as_posix()}: it resolves to "
                    f"{resolved.as_posix()}, outside the scanned tree.",
                    target_type=target_type,
                    level=logging.WARNING,
                )
                continue
            if global_ignore_paths:
                try:
                    relative = resolved.relative_to(source_dir).as_posix()
                except ValueError:
                    relative = path.as_posix()
                if any(
                    file_path_matches(relative, i.path) for i in global_ignore_paths
                ):
                    continue
            if not is_supported_executable(path):
                continue
            if size > MAX_SAMPLE_BYTES:
                self._plugin_log(
                    f"Skipping {path.as_posix()}: {size} bytes is over the "
                    f"{MAX_SAMPLE_BYTES}-byte limit.",
                    target_type=target_type,
                    level=logging.WARNING,
                )
                continue
            selected.append(path)
        return sorted(set(selected))

    def _argv_path(self, path: Path) -> str:
        """The path as spelled to capa and so in the report: source-relative when
        inside the source directory (the subprocess's working directory)."""
        source_dir = Path(self._ctx.source_dir).absolute()
        absolute = path.absolute()
        try:
            return PurePosixPath(absolute.relative_to(source_dir).as_posix()).as_posix()
        except ValueError:
            return absolute.as_posix()

    def _argv(self, spelled: str) -> List[str]:
        return [self.command or "capa", "-q", "-j", "--", spelled]

    # ------------------------------------------------------------------
    # The scan
    # ------------------------------------------------------------------

    def _empty_report(self) -> SarifReport:
        return SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name="capa",
                            version=self.tool_version,
                            informationUri=AnyUrl("https://github.com/mandiant/capa"),
                        )
                    ),
                    results=[],
                )
            ],
        )

    def _process_command_response(self, response: Dict[str, Any]) -> None:
        """Keep capa's stderr, which can quote the analyzed file, out of ``errors``."""
        super()._process_command_response(
            {key: value for key, value in response.items() if key != "stderr"}
        )

    def _run_one(
        self, argv: List[str], results_dir: Path, deadline: Optional[float]
    ) -> Dict[str, Any]:
        if deadline is None:
            remaining = None
        else:
            remaining = deadline - _now()
            if remaining <= 0:
                return {"timed_out": True}
        response = self._run_subprocess(
            command=argv,
            results_dir=results_dir,
            stdout_preference="return",
            stderr_preference="both",
            timeout=remaining,
        )
        return response if isinstance(response, dict) else {}

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: CapaScannerConfig | ScannerPluginConfigBase | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> SarifReport | bool:
        """Run capa once per PE or ELF file under *target* and merge the results."""
        if global_ignore_paths is None:
            global_ignore_paths = []

        # Per target, above every early return.
        self.targets_attempted = 0
        self.targets_failed = 0
        self.exit_code = 0

        if not target.exists() or not any(target.iterdir()):
            self._plugin_log(
                f"Target directory {target} is empty or doesn't exist. Skipping scan.",
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            self._post_scan(target=target, target_type=target_type)
            return self._empty_report()

        if not self._pre_scan(target=target, target_type=target_type, config=config):
            self._post_scan(target=target, target_type=target_type)
            return False

        results_file: Optional[Path] = None
        try:
            files = self._executables(target, target_type, global_ignore_paths)
            if not files:
                self._plugin_log(
                    f"No PE or ELF files found in {target_type} directory to scan.",
                    target_type=target_type,
                    level=logging.INFO,
                    append_to_stream="stderr",
                )
                self._post_scan(target=target, target_type=target_type)
                return self._empty_report()

            self.targets_attempted = len(files)
            results_dir = Path(self.results_dir or self._ctx.output_dir).joinpath(
                target_type
            )
            results_dir.mkdir(parents=True, exist_ok=True)
            results_file = results_dir.joinpath("capa.sarif")
            results_file.unlink(missing_ok=True)

            timeout = self._effective_scan_timeout()
            deadline = None if timeout is None else _now() + timeout

            results: List[Dict[str, Any]] = []
            final_args: List[str] = []
            for path in files:
                spelled = self._argv_path(path)
                final_args = self._argv(spelled)
                response = self._run_one(final_args, results_dir, deadline)
                if response.get("timed_out"):
                    self._post_scan(target=target, target_type=target_type)
                    raise ScannerError(
                        f"capa timed out after {timeout}s and was killed. Raise "
                        "scanners.capa.options.scan_timeout if these files "
                        "legitimately need longer."
                    )
                code = self.exit_code
                if code not in self.success_exit_codes:
                    self._fail_target(spelled, code, target_type)
                    continue
                results.extend(self._results_of(response, spelled))
            self._post_scan(target=target, target_type=target_type)

            if self.targets_failed == len(files):
                self.exit_code = 1

            report = self._empty_report()
            report.runs[0].results = [Result.model_validate(r) for r in results]
            with open_for_write(results_file) as handle:
                handle.write(
                    report.model_dump_json(
                        exclude_none=True, exclude_unset=True, by_alias=True
                    )
                )
            self._inject_invocation(report, final_args, target)
            return report
        except ScannerError:
            raise
        except Exception as e:
            raise ScannerError(self._describe_scan_failure(e, results_file))

    def _fail_target(self, spelled: str, code: Optional[int], target_type: str) -> None:
        self.targets_failed += 1
        meaning = CAPA_EXIT_MEANINGS.get(code or -1, "see capa's exit codes")
        self.errors.append(
            f"{spelled}: capa exited {code} ({meaning}), so it was not analyzed"
        )
        self._plugin_log(
            f"capa did not analyze {spelled}: exit {code} ({meaning}).",
            target_type=target_type,  # type: ignore[arg-type]
            level=logging.ERROR,
            append_to_stream="stderr",
        )

    def _results_of(self, response: Dict[str, Any], uri: str) -> List[Dict[str, Any]]:
        """SARIF result dicts from one run's stdout; ``ScannerError`` if unreadable."""
        stdout = response.get("stdout") or ""
        if not stdout.strip():
            raise ScannerError(f"capa exited 0 but wrote no JSON for {uri}")
        try:
            document = json.loads(stdout)
            meta = document.get("meta") if isinstance(document, dict) else None
            version = meta.get("version") if isinstance(meta, dict) else None
            if isinstance(version, str) and version and not self.tool_version:
                self.tool_version = version
            return convert_capa_document(document, uri)
        except ValueError as e:
            raise ScannerError(f"capa wrote output for {uri} that is not usable: {e}")

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        found = find_executable(self.command or "capa")
        if not found:
            ASH_LOGGER.warning(
                "capa executable not found in PATH. Install it with "
                "`ash dependencies install --config-overrides "
                "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                "ash_capa_plugins\"]' --tool capa`."
            )
        return found is not None


__all__ = [
    "CapaScanner",
    "CapaScannerConfig",
    "CapaScannerConfigOptions",
    "MAX_SAMPLE_BYTES",
    "convert_capa_document",
    "is_supported_executable",
]
