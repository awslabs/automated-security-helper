# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""BundlerAuditScanner: known-vulnerable gems in a Ruby project's Gemfile.lock.

What it runs
------------
``bundler-audit check`` (https://github.com/rubysec/bundler-audit, GPL-3.0-or-later,
run as a separate process and never imported) reads the ``Gemfile.lock`` at the root of
the scan target and matches every locked gem version against the ruby-advisory-db
advisory database. It also reports a gem source fetched over ``git://`` or ``http://``.
Only the root ``Gemfile.lock`` is read: a lockfile in a subdirectory is not found. A
target with no root ``Gemfile.lock`` (or one that is a symbolic link) is skipped, not
failed.

This is the template-scan shape of the betterleaks plugin. The tool writes JSON, not
SARIF, so ``_read_results_file`` converts its report into SARIF before the base class
validates it.

Invocation
----------
::

    bundler-audit check --format=json --quiet --output=<results>/bundler-audit.json \
        --config=<results>/bundler-audit-config.yml --gemfile-lock=Gemfile.lock \
        [--update] -- <target>

Measured on bundler-audit 0.9.3 (the version ASH installs) against a hand-written
Gemfile.lock and a fresh ruby-advisory-db clone, 2026-11-19:

* ``--format=json`` and ``--output=<file>`` write one JSON object,
  ``{"version", "created_at", "results"}``, to the file. Nothing but the report goes
  to the file; ``Download ruby-advisory-db ...`` and the statistics go to stdout.
  ``--quiet`` removes them.
* The exit status is 0 when there is nothing to report, and 1 for BOTH "the report
  holds vulnerabilities" and every failure (missing directory or lockfile, failed
  download or update, git absent). The report file settles which: a failure writes no
  file (the file is opened only after the scan succeeded), a finding writes one. So the
  exit codes ``{0, 1}`` are accepted, the stale report is removed before each run, a
  missing report fails the scan, and exit 1 with a report that holds no results fails
  it too.
* ``--config`` takes an absolute path (the tool joins it to the scanned directory with
  ``File.absolute_path``). Without it the tool reads ``.bundler-audit.yml`` from the
  scanned tree, whose ``ignore`` list drops advisories before ASH sees them, so they
  would be neither reported nor counted as suppressed. ASH always passes a file of its
  own, written to the results directory, holding ``ignore: []``. Suppress with ASH
  suppressions instead.
* ``--ignore`` and ``--database`` are never passed: the first would hide findings, the
  second names a path.
* ``--`` ends option parsing and the scan path follows it: ``.`` for the source target
  (the subprocess runs in the source directory, so reported paths are source-relative)
  and an absolute path otherwise.
* ``--update`` is passed unless ``options.update_database`` is off. It runs
  ``git pull`` in the advisory database. Without it, a missing database is downloaded
  anyway (a ``git clone`` of ruby-advisory-db), and an existing one is used as it is.

Severity
--------
Each unpatched-gem result carries the advisory's ``criticality`` that bundler-audit
derives from its CVSS score (v4 or v3 first, else v2):

=========  ========  ============  =======================================
criticality  ASH       SARIF level   bundler-audit's range
=========  ========  ============  =======================================
critical     CRITICAL  error         CVSS v3/v4 9.0 to 10.0
high         HIGH      error         7.0 to 8.9 (v2: 7.0 to 10.0)
medium       MEDIUM    warning       4.0 to 6.9
low          LOW       note          0.1 to 3.9
none         INFO      none          0.0
null         MEDIUM    warning       the advisory carries no CVSS score
=========  ========  ============  =======================================

``HIGH`` and ``CRITICAL`` share the SARIF level ``error`` (SARIF has no level between
``error`` and ``warning``); ``issue_severity`` keeps them apart. An advisory with no
score at all (10 of the 56 results in the measured run, the newest advisories among
them) is MEDIUM: it is a known vulnerable version, so it must not fall below the
default threshold, and with no score ASH has no ground to rate it higher. A
``criticality`` value this plugin does not know is MEDIUM for the same reason. An
insecure gem source is MEDIUM / ``warning``.

Offline, sandbox
----------------
The advisory database is a git repository that bundler-audit clones or pulls over the
network, so the scanner is ``SKIP_OFFLINE`` and declares a network need. It keeps the
database in ``~/.local/share/ruby-advisory-db``, declared as a cache path: writable
through the sandbox's throwaway overlay where the backend has one, read-only
elsewhere (set ``update_database: false`` and prepare the database before the scan
there).
"""

from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path
from typing import (
    Annotated,
    Any,
    ClassVar,
    Dict,
    List,
    Literal,
    Optional,
    Set,
    Tuple,
)

from pydantic import AnyUrl, Field, PrivateAttr, model_validator

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.plugin_base import (
    CustomCommand,
    install_story_is_declared,
)
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.utils.download_utils import (
    NO_BIN_DIRECTORY,
    current_bin_path,
    refusing_install_command,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.package_identity import identity_properties
from automated_security_helper.utils.sandbox.fs_guard import (
    open_for_write,
    read_bytes_at_most,
)
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: The bundler-audit release ASH installs (``gem install bundler-audit -v``).
BUNDLER_AUDIT_GEM_VERSION = "0.9.3"

#: The file bundler-audit reads at the root of the scan target.
LOCKFILE_NAME = "Gemfile.lock"

#: Why a target is skipped: the reason shown for a scan that attempted nothing.
NO_LOCKFILE_REASON = (
    "no Gemfile.lock at the root of the scan target (bundler-audit reads that one "
    "file; a lockfile in a subdirectory or a symbolic link is not read)"
)

#: Rule id of an insecure gem source, which has no advisory of its own.
INSECURE_SOURCE_RULE = "insecure-source"

#: Where bundler-audit keeps the advisory database unless told otherwise.
ADVISORY_DB_PATH = "~/.local/share/ruby-advisory-db"

_LOCKFILE_READ_LIMIT = 32 * 1024 * 1024

#: bundler-audit ``criticality`` -> (ASH severity, SARIF level). See "Severity".
CRITICALITY_MAP: Dict[str, Tuple[str, str]] = {
    "critical": ("CRITICAL", "error"),
    "high": ("HIGH", "error"),
    "medium": ("MEDIUM", "warning"),
    "low": ("LOW", "note"),
    "none": ("INFO", "none"),
}

#: What an advisory with no CVSS score, or a criticality not in the map, is rated.
UNSCORED_RATING: Tuple[str, str] = ("MEDIUM", "warning")

#: What an insecure gem source is rated.
INSECURE_SOURCE_RATING: Tuple[str, str] = ("MEDIUM", "warning")

_DRIVER_URI = "https://github.com/rubysec/bundler-audit"


def rate_criticality(criticality: Any) -> Tuple[str, str]:
    """(ASH severity, SARIF level) for an advisory's ``criticality``."""
    if isinstance(criticality, str):
        return CRITICALITY_MAP.get(criticality.strip().lower(), UNSCORED_RATING)
    return UNSCORED_RATING


def _fingerprint(*parts: Any) -> str:
    return hashlib.sha256(
        "\x1f".join(str(p) for p in parts).encode("utf-8")
    ).hexdigest()


def _help_uri(url: Any) -> Optional[str]:
    """The advisory URL when it is an http(s) URL SARIF can hold, else None."""
    if not isinstance(url, str) or not url.startswith(("http://", "https://")):
        return None
    try:
        AnyUrl(url)
    except ValueError:
        return None
    return url


def _lockfile_lines(lockfile: Path) -> List[str]:
    """The lockfile's lines, or none when it cannot be read (locations fall back to 1)."""
    try:
        data = read_bytes_at_most(lockfile, _LOCKFILE_READ_LIMIT)
    except OSError:
        return []
    return data.decode("utf-8", errors="replace").splitlines()


def _gem_line(lines: List[str], name: str, version: str) -> int:
    """The 1-based line of ``    name (version)`` in the lockfile's specs, else 1.

    A locked version can carry a platform (``nokogiri (1.15.0-x86_64-linux)``), which
    bundler-audit's ``gem.version`` leaves out.
    """
    pattern = re.compile(
        rf"^\s{{4}}{re.escape(name)} \({re.escape(version)}(?:-[^)\s]+)?\)\s*$"
    )
    for number, line in enumerate(lines, start=1):
        if pattern.match(line):
            return number
    return 1


def _source_line(lines: List[str], source: str) -> int:
    """The 1-based line of ``  remote: <source>``, else 1."""
    for number, line in enumerate(lines, start=1):
        if line.strip() == f"remote: {source}":
            return number
    return 1


def convert_bundler_audit_report(
    document: Dict[str, Any], *, lockfile_uri: str, lines: List[str]
) -> Dict[str, Any]:
    """Convert bundler-audit's JSON report into a SARIF log (as a dict).

    ``document`` is ``{"version", "created_at", "results": [...]}``; each result is
    ``{"type": "unpatched_gem", "gem": {"name", "version"}, "advisory": {...}}`` or
    ``{"type": "insecure_source", "source": "<uri>"}``. A result of another type is
    not graded, so it fails the conversion instead of being dropped. The advisory's
    ``path`` (a path in the database on the host that ran the tool) is not copied.
    """
    raw_results = document.get("results")
    if not isinstance(raw_results, list):
        raise ScannerError("its report has no results list, so it is not graded")
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    def add_rule(rule_id: str, text: str, url: Optional[str], tags: List[str]) -> None:
        if rule_id in rules:
            return
        rule: Dict[str, Any] = {
            "id": rule_id,
            "name": rule_id,
            "shortDescription": {"text": text},
            "properties": {"tags": tags},
        }
        if url:
            rule["helpUri"] = url
        rules[rule_id] = rule

    for entry in raw_results:
        if not isinstance(entry, dict):
            raise ScannerError("its report holds a result that is not an object")
        kind = entry.get("type")
        if kind == "unpatched_gem":
            gem = entry.get("gem") or {}
            advisory = entry.get("advisory") or {}
            name = str(gem.get("name") or "")
            version = str(gem.get("version") or "")
            rule_id = str(advisory.get("id") or "")
            if not (name and rule_id):
                raise ScannerError(
                    "its report holds an unpatched gem with no name or advisory id"
                )
            severity, level = rate_criticality(advisory.get("criticality"))
            title = str(advisory.get("title") or rule_id)
            patched = [str(v) for v in advisory.get("patched_versions") or []]
            fix = (
                f"Upgrade to a patched version: {' or '.join(patched)}."
                if patched
                else "The advisory lists no patched version."
            )
            url = _help_uri(advisory.get("url"))
            add_rule(
                rule_id, title, url, ["sca", "dependency", "ruby", "vulnerability"]
            )
            line = _gem_line(lines, name, version)
            properties: Dict[str, Any] = {
                "issue_severity": severity,
                "tags": ["sca", "dependency", "ruby", "vulnerability"],
                **identity_properties(name, version, lockfile_uri),
                "bundler_audit_criticality": advisory.get("criticality"),
                "bundler_audit_patched_versions": patched,
            }
            for key in ("cve", "ghsa", "osvdb", "cvss_v2", "cvss_v3", "cvss_v4"):
                if advisory.get(key) is not None:
                    properties[f"bundler_audit_{key}"] = advisory[key]
            results.append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "message": {
                        "text": f"{name} {version} is affected by {rule_id}: "
                        f"{title}. {fix}"
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": lockfile_uri},
                                "region": {"startLine": line},
                            }
                        }
                    ],
                    "partialFingerprints": {
                        "bundlerAudit/v1": _fingerprint(
                            rule_id, name, version, lockfile_uri
                        )
                    },
                    "properties": properties,
                }
            )
        elif kind == "insecure_source":
            source = str(entry.get("source") or "")
            if not source:
                raise ScannerError("its report holds an insecure source with no URI")
            severity, level = INSECURE_SOURCE_RATING
            add_rule(
                INSECURE_SOURCE_RULE,
                "Gem source fetched over an insecure protocol",
                "https://github.com/rubysec/bundler-audit#readme",
                ["sca", "dependency", "ruby", "supply-chain"],
            )
            results.append(
                {
                    "ruleId": INSECURE_SOURCE_RULE,
                    "level": level,
                    "message": {
                        "text": f"The Gemfile.lock fetches gems from {source}, which "
                        "is not protected against tampering in transit. Use an "
                        "https:// (or ssh) source."
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": lockfile_uri},
                                "region": {"startLine": _source_line(lines, source)},
                            }
                        }
                    ],
                    "partialFingerprints": {
                        "bundlerAudit/v1": _fingerprint(
                            INSECURE_SOURCE_RULE, source, lockfile_uri
                        )
                    },
                    "properties": {
                        "issue_severity": severity,
                        "tags": ["sca", "dependency", "ruby", "supply-chain"],
                        "bundler_audit_source": source,
                    },
                }
            )
        else:
            raise ScannerError(
                f"its report holds a result of type {kind!r}, which this scanner "
                "does not know how to grade"
            )

    driver: Dict[str, Any] = {
        "name": "bundler-audit",
        "informationUri": _DRIVER_URI,
        "rules": list(rules.values()),
    }
    tool_version = document.get("version")
    if isinstance(tool_version, str) and tool_version:
        driver["version"] = tool_version
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": driver}, "results": results}],
    }


class BundlerAuditScannerConfigOptions(ScannerOptionsBase):
    update_database: Annotated[
        bool,
        Field(
            description=(
                "Run `bundler-audit check --update`, which pulls the ruby-advisory-db "
                "advisories before the check. On by default so a scan does not match "
                "against stale advisories. Turn it off to use the database as it "
                "is, for a read-only cache or a database prepared before the scan. "
                "A missing database is downloaded either way. Needs a network."
            ),
        ),
    ] = True


class BundlerAuditScannerConfig(ScannerPluginConfigBase):
    name: Literal["bundler_audit"] = "bundler_audit"
    enabled: bool = True
    options: Annotated[
        BundlerAuditScannerConfigOptions,
        Field(description="Configure the bundler-audit scanner"),
    ] = BundlerAuditScannerConfigOptions()


@ash_scanner_plugin
class BundlerAuditScanner(ScannerPluginBase[BundlerAuditScannerConfig]):
    """Known-vulnerable gems in the scan target's Gemfile.lock using bundler-audit."""

    #: A Ruby gem, so a Python-only scan does not run it.
    python_only: ClassVar[bool | None] = False

    #: bundler-audit clones and pulls its advisory database over the network, and
    #: offline the scanner would match nothing against an empty or old database.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.SKIP_OFFLINE

    #: 0 clean, 1 vulnerable OR failed; the report file tells them apart
    #: (see the module docstring), so ``_read_results_file`` decides.
    success_exit_codes: ClassVar[Set[int]] = {0, 1}

    #: The strict default plus what the tool needs: the network for the advisory
    #: database, the database directory, and the user gem directories the gem and its
    #: dependencies are installed in (as cfn-nag's).
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        network=True,
        cache_paths=(ADVISORY_DB_PATH,),
        read_paths=("~/.local/share/gem", "~/.gem/ruby", "$GEM_HOME"),
    )

    #: For a target scan() found no Gemfile.lock in; see the base class.
    nothing_scanned_reason: ClassVar[Optional[str]] = NO_LOCKFILE_REASON

    # The target of the run in flight, which the report conversion reads the lockfile
    # lines from (the base reader is handed only the results file).
    _current_target: Optional[Path] = PrivateAttr(default=None)

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = BundlerAuditScannerConfig()
        self.command = "bundler-audit"
        self.subcommands = ["check"]
        self.tool_type = ScannerToolType.SCA
        # The argv is assembled in _execute_scan; ToolArgs stays empty so nothing
        # from the base resolver can add a token bundler-audit would misread.
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "BundlerAuditScanner":
        """``gem install bundler-audit`` for the current user, onto ASH's bin path.

        Declared the way cfn-nag's is: ``--user-install`` because a plain install
        writes to the interpreter's root-owned GEM_HOME, ``--bindir`` because ASH
        looks on PATH and in ASH_BIN_PATH, not in a user gem bin. A machine with no
        RubyGems declares no command, so ``ash dependencies install`` does not fail
        every other plugin for the want of Ruby.
        """
        declaring = install_story_is_declared()
        if not declaring and find_executable("gem") is None:
            ASH_LOGGER.debug(
                "bundler-audit cannot be installed here: RubyGems (`gem`) is not on "
                "PATH. It is reported as having no install path."
            )
            return self
        bin_dir = current_bin_path()
        if declaring and bin_dir is None:
            bin_dir = Path("ASH_BIN_PATH")
        command = (
            refusing_install_command(NO_BIN_DIRECTORY)
            if bin_dir is None
            else CustomCommand(
                args=[
                    "gem",
                    "install",
                    "bundler-audit",
                    "-v",
                    BUNDLER_AUDIT_GEM_VERSION,
                    "--no-document",
                    "--user-install",
                    "--bindir",
                    str(bin_dir),
                ],
                shell=False,
            )
        )
        for target_platform in ("linux", "darwin", "windows"):
            for arch in ("amd64", "arm64"):
                self.custom_install_commands.setdefault(target_platform, {})[arch] = [
                    command
                ]
        return self

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    def _options(self) -> BundlerAuditScannerConfigOptions:
        """The options, typed. ``config`` is a union on the base class."""
        options = getattr(self.config, "options", None)
        if isinstance(options, BundlerAuditScannerConfigOptions):
            return options
        return BundlerAuditScannerConfigOptions.model_validate(
            options.model_dump() if options is not None else {}
        )

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("BundlerAuditScanner has no plugin context")
        return Path(self.context.source_dir)

    @staticmethod
    def _has_lockfile(tree: Path) -> bool:
        """Whether ``tree`` holds a regular ``Gemfile.lock`` at its root."""
        lockfile = Path(tree) / LOCKFILE_NAME
        try:
            return lockfile.is_file() and not lockfile.is_symlink()
        except OSError:
            return False

    @staticmethod
    def _target_is_empty(target: Path) -> bool:
        """Empty, missing, or without a root Gemfile.lock: nothing for the tool to read."""
        if ScannerPluginBase._target_is_empty(target):
            return True
        return not BundlerAuditScanner._has_lockfile(target)

    def nothing_to_scan_reason(self) -> str | None:
        """None when the source or the converted tree has a root Gemfile.lock."""
        if self.context is None:
            return None
        for tree in (
            getattr(self.context, "source_dir", None),
            getattr(self.context, "work_dir", None),
        ):
            if tree is not None and self._has_lockfile(Path(tree)):
                return None
        return NO_LOCKFILE_REASON

    def _scan_path(self, target: Path) -> str:
        """``.`` for the source target (the working directory), else absolute."""
        if Path(target).absolute() == self._source_dir().absolute():
            return "."
        return Path(target).absolute().as_posix()

    def _lockfile_uri(self, target: Path) -> str:
        """The lockfile's path relative to the source directory, else its name."""
        lockfile = Path(target).absolute() / LOCKFILE_NAME
        try:
            return lockfile.relative_to(self._source_dir().absolute()).as_posix()
        except ValueError:
            return LOCKFILE_NAME

    def _write_config_stub(self, directory: Path) -> Path:
        """The config file passed as ``--config``: no ignored advisories.

        Without it bundler-audit reads ``.bundler-audit.yml`` from the scanned tree,
        and the tree could drop any advisory.
        """
        stub = directory / "bundler-audit-config.yml"
        with open_for_write(stub, encoding="utf-8") as handle:
            handle.write("ignore: []\n")
        return stub

    def _build_arguments(
        self, target: Path, results_file: Path, config_file: Path
    ) -> List[str]:
        """The full bundler-audit argv for one target (the scan path follows ``--``)."""
        args: List[str] = [
            self.command or "bundler-audit",
            *self.subcommands,
            "--format=json",
            "--quiet",
            f"--output={results_file.as_posix()}",
            f"--config={config_file.as_posix()}",
            f"--gemfile-lock={LOCKFILE_NAME}",
        ]
        if self._options().update_database:
            args.append("--update")
        args.extend(["--", self._scan_path(target)])
        return args

    # ------------------------------------------------------------------
    # The scan
    # ------------------------------------------------------------------

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Resolve the argv and results path for one bundler-audit run.

        ``global_ignore_paths`` is not translated into the tool's config: it is applied
        to every scanner's SARIF by ``apply_suppressions_to_sarif``.
        """
        if self.results_dir is None:
            raise ScannerError("BundlerAuditScanner has no results directory")
        # One instance scans source and then converted, and the base keeps the worst
        # exit code across runs; a failed source run (1) must not fail a clean
        # converted one.
        self.exit_code = 0
        self._current_target = Path(target)
        results_file = (
            Path(self.results_dir)
            .absolute()
            .joinpath(target_type, "bundler-audit.json")
        )
        results_file.parent.mkdir(exist_ok=True, parents=True)
        # A report left by an earlier run must not be read as this run's: exit 1
        # means "findings" only because a failed run writes none.
        results_file.unlink(missing_ok=True)
        config_file = self._write_config_stub(results_file.parent)
        final_args = self._build_arguments(target, results_file, config_file)
        self._plugin_log(
            f"Running: {' '.join(final_args)}",
            target_type=target_type,
            level=logging.DEBUG,
        )
        return final_args, results_file, None

    def _read_results_file(self, results_file: Path) -> Optional[Dict[str, Any]]:
        """Read bundler-audit's JSON report and return it as SARIF.

        Exit 1 covers both findings and failures, so a run that exited 1 with a report
        that lists nothing is a failure whose file cannot be trusted. Any other code
        outside 0 and 1 is not one the tool documents. A missing file raises in the
        base reader.
        """
        if self.exit_code not in self.success_exit_codes:
            raise ScannerError(
                f"bundler-audit exited {self.exit_code}; it exits 0 when it finds "
                "nothing and 1 when it finds vulnerabilities, so this run failed"
            )
        document = super()._read_results_file(results_file)
        if document is None:
            return None
        if not isinstance(document, dict):
            raise ScannerError("its report is not a JSON object, so it is not graded")
        if self.exit_code == 1 and not document.get("results"):
            raise ScannerError(
                "bundler-audit exited 1 but its report lists no vulnerabilities, so "
                "the run is treated as failed"
            )
        target = getattr(self, "_current_target", None) or self._source_dir()
        lockfile_uri = self._lockfile_uri(target)
        lines = _lockfile_lines(Path(target) / LOCKFILE_NAME)
        return convert_bundler_audit_report(
            document, lockfile_uri=lockfile_uri, lines=lines
        )

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        if self._scanner_offline():
            self.dependency_unavailable_reason = (
                "bundler-audit downloads the ruby-advisory-db advisories over the "
                "network, so it does not run offline"
            )
            return False
        found = find_executable(self.command or "bundler-audit")
        if not found:
            ASH_LOGGER.warning(
                "bundler-audit executable not found in PATH. Install it with "
                "`ash dependencies install --config-overrides "
                "'ash_plugin_modules+=[\"automated_security_helper.plugin_modules."
                "ash_bundler_audit_plugins\"]' --tool bundler_audit`."
            )
        return found is not None


__all__ = [
    "BUNDLER_AUDIT_GEM_VERSION",
    "BundlerAuditScanner",
    "BundlerAuditScannerConfig",
    "BundlerAuditScannerConfigOptions",
    "CRITICALITY_MAP",
    "LOCKFILE_NAME",
    "convert_bundler_audit_report",
    "rate_criticality",
]
