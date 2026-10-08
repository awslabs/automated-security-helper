# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""actionlint: a linter for GitHub Actions workflow files.

What ASH runs
-------------
actionlint (https://github.com/rhysd/actionlint, MIT) is one statically linked Go
binary. ASH installs a pinned release asset (``utils/tool_downloads.py``), finds the
workflow files itself, and runs::

    actionlint -no-color -shellcheck= -pyflakes= -config-file <file>
               -format <template> -- <workflow> [<workflow> ...]

with the scan target as the working directory.

A community plugin: it is loaded only when ``ash_actionlint_plugins`` is listed in
``ash_plugin_modules`` (or passed with ``--ash-plugin-modules``), so a scan that does
not list the module is unchanged by its existence. Listed, it runs by default.

Decisions, and why
------------------
1. Workflow files are passed explicitly. Run with no file arguments, actionlint looks
   for the nearest ``.github/workflows`` from its working directory and ignores ASH's
   ignore rules. ASH instead takes every ``*.yml``/``*.yaml`` file whose parent
   directory is ``.github/workflows`` from the scan set, which applies ``.gitignore``
   and ``.ignore`` files, then drops ``global_settings.ignore_paths`` matches and
   anything under ASH's own output directory. A workflow that is a symlink resolving
   outside the scan root is skipped with a warning, because actionlint follows it and
   copies its lines into the report. ``--`` ends the flags, so a path that
   begins with ``-`` is read as a file. A scan root with no workflow files does not
   run actionlint at all and reports SKIPPED ("evaluated nothing"), not PASSED.

2. shellcheck and pyflakes are OFF by default. actionlint runs ``shellcheck`` on
   every ``run:`` script and ``pyflakes`` on ``shell: python`` steps when it finds
   them on PATH, and silently skips them when it does not. That makes the result set
   depend on what happens to be installed on the host. ASH passes ``-shellcheck=``
   and ``-pyflakes=`` (the documented way to disable them) unless the operator sets
   ``options.shellcheck`` / ``options.pyflakes`` to a command name or path. When one
   is set and cannot be found or is not executable, the scanner reports MISSING
   instead of running
   without it, so an enabled integration is never skipped quietly either.

3. The config file is always explicit. actionlint discovers
   ``.github/actionlint.yaml`` by walking up to the nearest ``.git`` directory, so
   whether a config applied depended on whether the checkout had a ``.git`` (it is
   often absent in container builds and source archives), and a scan of a
   subdirectory could read a config from outside the scan root. ASH passes
   ``-config-file`` every time: ``options.config_file`` if set, else
   ``.github/actionlint.yaml`` or ``.github/actionlint.yml`` directly under the scan
   target, else an empty config ASH writes into its own results directory. An
   explicitly configured file that does not exist is an error, not a silent
   fallback. A config whose ``paths`` section has ``ignore`` patterns removes
   findings before ASH sees them, so ASH logs a warning naming the patterns.

4. Output is JSON, converted to SARIF here. actionlint 1.7.12 has no built-in SARIF
   writer; its documentation points at a Go template in its test data. ASH asks for
   ``{{json .}}`` instead, wrapped with ``getVersion``, and builds the SARIF in
   Python. JSON encoding is done by actionlint's own ``json`` template function, so
   escaping is not hand-written, and the severity mapping below needs per-finding
   logic a static template cannot express.

5. Exit codes are read, not assumed. actionlint exits 0 when clean, 1 when it found
   problems, 2 for a bad command line and 3 for a fatal error (for example an
   unreadable file). 0 and 1 are success. Anything else, a timeout, output that is not
   the expected JSON, or exit 1 with no findings raises ``ScannerError``, so a broken
   run is ERROR and never an empty PASSED.

Severity mapping
----------------
actionlint gives every finding the same weight; its upstream SARIF template marks all
of them ``error``. ASH maps by rule kind (``kind`` becomes the SARIF ``ruleId``) so the
severity gate separates exploitable workflow defects from lint:

* HIGH (SARIF ``error``): an ``expression`` finding whose message says the input is
  "potentially untrusted" -- script injection, an attacker-controlled
  ``${{ github.event.* }}`` value interpolated into a ``run:`` script -- and
  ``credentials`` (a password hard-coded in a ``container:``/``services:`` block).
* MEDIUM (SARIF ``warning``): ``if-cond`` (an ``if:`` that is always true because of
  text around ``${{ }}``, so a guard silently does nothing), ``permissions``
  (an invalid ``permissions:`` block), and a ``deprecated-commands`` finding for
  ``set-env`` or ``add-path``, which GitHub disabled because they let a step's
  output inject environment variables and PATH entries into later steps.
* LOW (SARIF ``note``): everything else, which is a correctness problem in the
  workflow rather than an exposure -- syntax, other expression type errors, unknown
  runner labels, undefined ``needs:``, bad globs, the ``set-output``/``save-state``
  deprecations, and shellcheck/pyflakes output when enabled. A kind this table does not name is also LOW, and is logged once, so a
  newer actionlint adding a kind does not change the gate silently.

With ASH's default threshold (MEDIUM) a workflow with only lint findings passes and one
with script injection fails.

A ``credentials`` finding's snippet is the hard-coded password, so it is left out of
the SARIF; the location still points at the line.

A binary whose reported version differs from the pin (a nix or PATH install) runs,
with a warning, since the kinds and messages the mapping keys on may differ.

Overlap with zizmor
-------------------
zizmor also audits workflows, including template injection. If ASH's zizmor scanner
is enabled too, the two are independent: neither reads the other's output or
configuration, and an injection is reported once by each.

Suppressions
------------
Findings go through ASH's normal suppression pass, so rule (``ruleId`` is the
actionlint kind), path and line suppressions apply. Suppressing ``expression`` also
suppresses its script-injection findings, because actionlint reports both under that
kind; a line-scoped suppression is the narrow form. Package- and symbol-scoped
suppressions do not apply: a workflow file has no package identity and no
function/class symbols.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Tuple

import yaml
from pydantic import Field, model_validator

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.download_utils import (
    pinned_tool_install_commands,
)
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.subprocess_utils import find_executable
from automated_security_helper.utils.tool_downloads import TOOL_VERSIONS

#: The version the severity mapping below was written against.
PINNED_VERSION = TOOL_VERSIONS["actionlint"]

#: The checks reference for the pinned release, used as every rule's helpUri.
ACTIONLINT_CHECKS_URL = (
    "https://github.com/rhysd/actionlint/blob/v1.7.12/docs/checks.md"
)

#: The ``-format`` template. ``{{json .}}`` is the error list as a JSON array, encoded
#: by actionlint; ``getVersion`` is the running binary's version. Passed as one argv
#: element, never through a shell.
ACTIONLINT_FORMAT = '{"version":{{getVersion | json}},"errors":{{json .}}}'

#: The substring in both of actionlint's untrusted-input messages, from
#: ``expr_insecure.go`` at v1.7.12: ``%q is potentially untrusted. avoid using it
#: directly in inline scripts...`` and ``object filter extracts potentially untrusted
#: properties %s...``.
UNTRUSTED_INPUT_MARKER = "potentially untrusted"

#: The two deprecated workflow commands GitHub disabled for injection, as actionlint
#: quotes them in its message (``workflow command %q was deprecated``).
INJECTABLE_DEPRECATED_COMMANDS = ('"set-env"', '"add-path"')

#: Severity for each actionlint rule kind, as listed by ``allKinds`` in v1.7.12.
#: ``expression`` and ``deprecated-commands`` are LOW here and raised per finding by
#: :func:`severity_for`.
KIND_SEVERITY: Dict[str, str] = {
    "action": "LOW",
    "credentials": "HIGH",
    "deprecated-commands": "LOW",
    "env-var": "LOW",
    "events": "LOW",
    "expression": "LOW",
    "glob": "LOW",
    "id": "LOW",
    "if-cond": "MEDIUM",
    "job-needs": "LOW",
    "matrix": "LOW",
    "permissions": "MEDIUM",
    "pyflakes": "LOW",
    "runner-label": "LOW",
    "shell-name": "LOW",
    "shellcheck": "LOW",
    "syntax-check": "LOW",
    "workflow-call": "LOW",
}

#: Severity for a kind KIND_SEVERITY does not list.
UNKNOWN_KIND_SEVERITY = "LOW"

_SEVERITY_TO_LEVEL: Dict[str, str] = {
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

#: Config files ASH looks for under the scan target, in this order.
_DEFAULT_CONFIG_CANDIDATES = (".github/actionlint.yaml", ".github/actionlint.yml")

_WORKFLOW_SUFFIXES = (".yml", ".yaml")


def severity_for(kind: str, message: str) -> str:
    """The ASH severity for one actionlint finding."""
    if kind == "expression" and UNTRUSTED_INPUT_MARKER in message:
        return "HIGH"
    if kind == "deprecated-commands" and any(
        command in message for command in INJECTABLE_DEPRECATED_COMMANDS
    ):
        return "MEDIUM"
    return KIND_SEVERITY.get(kind, UNKNOWN_KIND_SEVERITY)


def is_workflow_file(relative_path: str) -> bool:
    """Whether *relative_path* is a workflow file GitHub would load.

    GitHub reads ``*.yml``/``*.yaml`` directly inside ``.github/workflows`` and not
    in its subdirectories. Applied at any depth, so a nested project's workflows are
    linted too.
    """
    parts = Path(relative_path.replace("\\", "/")).parts
    return (
        len(parts) >= 3
        and parts[-3] == ".github"
        and parts[-2] == "workflows"
        and parts[-1].lower().endswith(_WORKFLOW_SUFFIXES)
    )


def config_ignore_patterns(config_path: Path) -> List[str]:
    """The ``paths.<glob>.ignore`` patterns in an actionlint config, sorted.

    Never raises: actionlint owns the verdict on its own config, and reports a
    malformed one itself with exit 3.
    """
    try:
        document = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return []
    paths = document.get("paths") if isinstance(document, dict) else None
    if not isinstance(paths, dict):
        return []
    found: set[str] = set()
    for section in paths.values():
        ignore = section.get("ignore") if isinstance(section, dict) else None
        if isinstance(ignore, list):
            found.update(str(item) for item in ignore if item)
    return sorted(found)


def redact_credentials(payload: Any) -> Any:
    """A copy of *payload* with the snippet of every ``credentials`` finding removed.

    That snippet is the hard-coded password, and the payload is written into the
    output directory.
    """
    if not isinstance(payload, dict) or not isinstance(payload.get("errors"), list):
        return payload
    errors = []
    for error in payload["errors"]:
        if isinstance(error, dict) and error.get("kind") == "credentials":
            error = {k: v for k, v in error.items() if k != "snippet"}
        errors.append(error)
    return {**payload, "errors": errors}


def build_sarif(payload: Any, exit_code: int) -> Dict[str, Any]:
    """Convert actionlint's ``ACTIONLINT_FORMAT`` output into a SARIF 2.1.0 dict.

    Raises:
        ScannerError: if the payload is not the shape the template produces, or if
            the exit code contradicts the findings (1 with none, 0 with some).
    """
    if not isinstance(payload, dict) or "errors" not in payload:
        raise ScannerError(
            "actionlint output is not the expected JSON object with an 'errors' key"
        )
    errors = payload["errors"]
    if errors is None:
        errors = []
    if not isinstance(errors, list):
        raise ScannerError("actionlint output 'errors' is not a JSON array")
    if exit_code == 1 and not errors:
        raise ScannerError(
            "actionlint exited 1, which means it found problems, but reported none"
        )
    if exit_code == 0 and errors:
        raise ScannerError(
            f"actionlint exited 0, which means clean, but reported {len(errors)} "
            "problem(s)"
        )

    results: List[Dict[str, Any]] = []
    kinds_seen: Dict[str, str] = {}
    for index, error in enumerate(errors):
        if not isinstance(error, dict):
            raise ScannerError(f"actionlint error #{index} is not a JSON object")
        kind = error.get("kind")
        message = error.get("message")
        filepath = error.get("filepath")
        line = error.get("line")
        column = error.get("column")
        if not (
            isinstance(kind, str)
            and kind
            and isinstance(message, str)
            and isinstance(filepath, str)
            and filepath
            and isinstance(line, int)
            and not isinstance(line, bool)
            and line >= 1
        ):
            raise ScannerError(
                f"actionlint error #{index} is missing kind, message, filepath or a "
                f"valid line: {error!r}"
            )
        if kind not in KIND_SEVERITY and kind not in kinds_seen:
            ASH_LOGGER.warning(
                f"actionlint reported rule kind {kind!r}, which ASH has no severity "
                f"for; reporting it as {UNKNOWN_KIND_SEVERITY}."
            )
        severity = severity_for(kind, message)
        kinds_seen.setdefault(kind, KIND_SEVERITY.get(kind, UNKNOWN_KIND_SEVERITY))

        region: Dict[str, Any] = {"startLine": line, "endLine": line}
        if isinstance(column, int) and not isinstance(column, bool) and column >= 1:
            region["startColumn"] = column
            end_column = error.get("end_column")
            if (
                isinstance(end_column, int)
                and not isinstance(end_column, bool)
                and end_column >= column
            ):
                # actionlint's end_column is inclusive; SARIF's endColumn is the
                # column after the last character.
                region["endColumn"] = end_column + 1
        snippet = error.get("snippet")
        # A credentials finding's snippet is the hard-coded password itself, so it
        # is not copied into the report.
        if isinstance(snippet, str) and snippet and kind != "credentials":
            region["snippet"] = {"text": snippet}

        results.append(
            {
                "ruleId": kind,
                "level": _SEVERITY_TO_LEVEL[severity],
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": filepath.replace("\\", "/")},
                            "region": region,
                        }
                    }
                ],
                "properties": {
                    "issue_severity": severity,
                    "actionlint_kind": kind,
                },
            }
        )

    rules = [
        {
            "id": kind,
            "name": kind,
            "shortDescription": {"text": f"actionlint {kind} check"},
            "helpUri": ACTIONLINT_CHECKS_URL,
            "defaultConfiguration": {"level": _SEVERITY_TO_LEVEL[default_severity]},
        }
        for kind, default_severity in sorted(kinds_seen.items())
    ]
    version = payload.get("version")
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "actionlint",
                        "version": str(version) if version else "unknown",
                        "informationUri": "https://github.com/rhysd/actionlint",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


class ActionlintScannerConfigOptions(ScannerOptionsBase):
    config_file: Annotated[
        str | None,
        Field(
            description=(
                "Path to an actionlint config file, relative to the source directory. "
                "Defaults to .github/actionlint.yaml or .github/actionlint.yml under "
                "the scan target, and to an empty config when neither exists. A path "
                "set here that does not exist fails the scan."
            ),
        ),
    ] = None
    shellcheck: Annotated[
        str | None,
        Field(
            description=(
                "Command name or path of shellcheck, which actionlint runs on every "
                "run: script. Unset (the default) disables the integration so results "
                "do not depend on what is installed on the host. When set and not "
                "found, the scanner reports MISSING."
            ),
        ),
    ] = None
    pyflakes: Annotated[
        str | None,
        Field(
            description=(
                "Command name or path of pyflakes, which actionlint runs on "
                "'shell: python' steps. Unset (the default) disables the integration. "
                "When set and not found, the scanner reports MISSING."
            ),
        ),
    ] = None


class ActionlintScannerConfig(ScannerPluginConfigBase):
    name: Literal["actionlint"] = "actionlint"
    enabled: bool = True
    options: Annotated[
        ActionlintScannerConfigOptions,
        Field(description="Configure the actionlint scanner"),
    ] = ActionlintScannerConfigOptions()


@ash_scanner_plugin
class ActionlintScanner(ScannerPluginBase[ActionlintScannerConfig]):
    """Lints GitHub Actions workflow files with actionlint."""

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = ActionlintScannerConfig()
        self.command = "actionlint"
        self.tool_type = ScannerToolType.IAC
        super().model_post_init(context)

    def _options(self) -> ActionlintScannerConfigOptions:
        """The scanner's options, typed. ``model_post_init`` guarantees a config."""
        options = getattr(self.config, "options", None)
        if isinstance(options, ActionlintScannerConfigOptions):
            return options
        return ActionlintScannerConfigOptions.model_validate(
            options.model_dump() if options is not None else {}
        )

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("ActionlintScanner has no plugin context")
        return Path(self.context.source_dir)

    def _output_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("ActionlintScanner has no plugin context")
        return Path(self.context.output_dir)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "ActionlintScanner":
        self.custom_install_commands.update(pinned_tool_install_commands("actionlint"))
        return self

    def _integration_executables(self) -> Dict[str, Optional[str]]:
        """Resolved paths for the enabled shellcheck/pyflakes integrations.

        A configured integration that cannot be found maps to None.
        """
        options = self._options()
        resolved: Dict[str, Optional[str]] = {}
        for flag in ("shellcheck", "pyflakes"):
            configured = getattr(options, flag, None)
            if configured is None or str(configured).strip() == "":
                continue
            configured = str(configured).strip()
            candidate = Path(configured)
            if candidate.is_absolute() or len(candidate.parts) > 1:
                # Relative to the source directory, and handed to actionlint as an
                # absolute path because actionlint runs with the scan target as
                # its working directory. A file that is not executable counts as
                # absent: actionlint would otherwise drop the integration silently.
                if not candidate.is_absolute():
                    candidate = self._source_dir() / candidate
                candidate = candidate.absolute()
                usable = candidate.is_file() and os.access(candidate, os.X_OK)
                resolved[flag] = candidate.as_posix() if usable else None
            else:
                resolved[flag] = find_executable(configured)
        return resolved

    def validate_plugin_dependencies(self) -> bool:
        self.dependency_unavailable_reason = None
        missing = [
            f"{flag} ({getattr(self._options(), flag)!s})"
            for flag, path in self._integration_executables().items()
            if path is None
        ]
        if missing:
            self.dependency_unavailable_reason = (
                f"actionlint is configured to use {', '.join(missing)}, which was not "
                "found. Install it, or unset the option to run actionlint without "
                "that integration."
            )
            self._plugin_log(self.dependency_unavailable_reason, level=logging.WARNING)
            return False
        found = find_executable(self.command or "actionlint")
        if not found:
            ASH_LOGGER.warning(
                "actionlint executable not found. Install it with "
                "`ash dependencies install --tool actionlint`."
            )
        return found is not None

    def _workflow_files(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> List[str]:
        """Workflow files under *target*, as POSIX paths relative to it, sorted."""
        if target_type == "converted":
            candidates = [str(p) for p in target.rglob("*") if p.is_file()]
        else:
            candidates = scan_set(
                source=str(self._source_dir()),
                output=str(self._output_dir()),
            )

        target_abs = Path(target).absolute()
        target_real = Path(target).resolve()
        output_abs = self._output_dir().absolute()
        relative: List[str] = []
        for item in candidates:
            path = Path(item)
            if not path.is_absolute():
                path = target_abs / path
            path = path.absolute()
            if not path.is_relative_to(target_abs):
                continue
            if target_type != "converted" and path.is_relative_to(output_abs):
                continue
            rel = path.relative_to(target_abs).as_posix()
            if not is_workflow_file(rel):
                continue
            # A symlinked workflow is followed by actionlint, which copies the
            # target's lines into the SARIF snippet. Only pass files whose real
            # path is inside the real scan root.
            if not path.resolve().is_relative_to(target_real):
                self._plugin_log(
                    f"Not linting {rel}: it resolves outside the scan root.",
                    level=logging.WARNING,
                )
                continue
            relative.append(rel)

        if global_ignore_paths:
            from automated_security_helper.utils.suppression_matcher import (
                file_path_matches,
            )

            relative = [
                rel
                for rel in relative
                if not any(
                    file_path_matches(rel, ignore.path)
                    for ignore in global_ignore_paths
                )
            ]
        return sorted(set(relative))

    def _resolve_config_file(self, target: Path, results_dir: Path) -> Path:
        """The config file actionlint is given, always explicitly. See decision 3."""
        configured = self._options().config_file
        if configured:
            candidate = Path(configured)
            if not candidate.is_absolute():
                candidate = self._source_dir() / candidate
            if not candidate.is_file():
                raise ScannerError(
                    f"scanners.actionlint.options.config_file is {configured!r}, "
                    f"which does not exist (resolved to {candidate.as_posix()})."
                )
            return candidate.absolute()
        for name in _DEFAULT_CONFIG_CANDIDATES:
            candidate = target / name
            if candidate.is_file():
                return candidate.absolute()
        empty = results_dir / "ash-default-actionlint.yaml"
        empty.write_text(
            "# Written by ASH so actionlint does not discover a config outside the "
            "scan root.\n",
            encoding="utf-8",
        )
        return empty.absolute()

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Abstract stub: ActionlintScanner overrides scan() directly."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: ActionlintScannerConfig | ScannerPluginConfigBase | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> SarifReport | bool:
        if global_ignore_paths is None:
            global_ignore_paths = []
        self.targets_attempted = 0
        self.targets_failed = 0

        if not target.exists() or not any(target.iterdir()):
            self._plugin_log(
                f"Target directory {target} is empty or doesn't exist. Skipping scan.",
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            self._post_scan(target=target, target_type=target_type)
            return True

        if not self._pre_scan(target=target, target_type=target_type, config=config):
            self._post_scan(target=target, target_type=target_type)
            return False
        if not self.dependencies_satisfied:
            self._post_scan(target=target, target_type=target_type)
            return False

        workflows = self._workflow_files(target, target_type, global_ignore_paths)
        if not workflows:
            self._plugin_log(
                f"No GitHub Actions workflow files (.github/workflows/*.yml or *.yaml) "
                f"in the {target_type} scan set; actionlint evaluated nothing.",
                target_type=target_type,
                level=logging.INFO,
            )
            self._post_scan(target=target, target_type=target_type)
            return SarifReport(version="2.1.0", runs=[])

        self.targets_attempted = len(workflows)
        if self.results_dir is None:
            raise ScannerError("ActionlintScanner has no results directory")
        results_dir = Path(self.results_dir).joinpath(target_type)
        results_dir.mkdir(parents=True, exist_ok=True)
        post_scanned = False

        try:
            config_file = self._resolve_config_file(target, results_dir)
            ignore_patterns = config_ignore_patterns(config_file)
            if ignore_patterns:
                self._plugin_log(
                    f"The actionlint config at {config_file.as_posix()} ignores "
                    f"findings matching {', '.join(repr(p) for p in ignore_patterns)}. "
                    "actionlint drops those before ASH sees them, so they cannot "
                    "appear in these results or be tracked as suppressions.",
                    target_type=target_type,
                    level=logging.WARNING,
                )

            integrations = self._integration_executables()
            final_args: List[str] = [
                self.command or "actionlint",
                "-no-color",
                f"-shellcheck={integrations.get('shellcheck') or ''}",
                f"-pyflakes={integrations.get('pyflakes') or ''}",
                "-config-file",
                config_file.as_posix(),
                "-format",
                ACTIONLINT_FORMAT,
                "--",
                *workflows,
            ]
            effective_timeout = self._effective_scan_timeout()
            response = self._run_subprocess(
                command=final_args,
                results_dir=results_dir,
                stdout_preference="return",
                stderr_preference="write",
                cwd=target,
                timeout=effective_timeout,
            )
            self._post_scan(target=target, target_type=target_type)
            post_scanned = True

            if isinstance(response, dict) and response.get("timed_out"):
                raise ScannerError(
                    f"actionlint timed out after {effective_timeout}s and was killed. "
                    "Raise scanners.actionlint.options.scan_timeout if this target "
                    "legitimately needs longer."
                )
            if self.exit_code not in self.success_exit_codes:
                raise ScannerError(
                    f"actionlint exited {self.exit_code} (2 is a bad command line, 3 "
                    "a fatal error such as an unreadable file or invalid config)"
                )

            stdout = (response or {}).get("stdout") or ""
            raw_output = results_dir / "actionlint.json"
            try:
                payload = json.loads(stdout)
            except json.JSONDecodeError as exc:
                # Kept verbatim for diagnosis: output that does not parse cannot
                # be redacted, and is not findings.
                raw_output.write_text(stdout, encoding="utf-8")
                raise ScannerError(
                    f"actionlint output is not JSON ({exc}); raw output kept at "
                    f"{raw_output.as_posix()}"
                ) from exc
            raw_output.write_text(
                json.dumps(redact_credentials(payload), indent=2), encoding="utf-8"
            )

            sarif_dict = build_sarif(payload, self.exit_code)
            self.tool_version = sarif_dict["runs"][0]["tool"]["driver"]["version"]
            if self.tool_version.lstrip("v") != PINNED_VERSION.lstrip("v"):
                self._plugin_log(
                    f"actionlint {self.tool_version} is not the pinned "
                    f"{PINNED_VERSION}. The severity mapping matches rule kinds and "
                    "message text from the pinned version, so findings from this "
                    "version may be classified differently.",
                    target_type=target_type,
                    level=logging.WARNING,
                )
            sarif_report = SarifReport.model_validate(sarif_dict)
            self._inject_invocation(sarif_report, final_args, target)
            (results_dir / "actionlint.sarif").write_text(
                sarif_report.model_dump_json(
                    by_alias=True, exclude_none=True, exclude_unset=True, indent=2
                ),
                encoding="utf-8",
            )
            return sarif_report
        except Exception as exc:
            self.targets_failed = self.targets_attempted
            if not post_scanned:
                self._post_scan(target=target, target_type=target_type)
            raise ScannerError(
                self._describe_scan_failure(exc, results_dir / "actionlint.json")
            ) from exc
