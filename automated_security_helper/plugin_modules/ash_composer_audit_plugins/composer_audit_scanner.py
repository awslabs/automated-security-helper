# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Composer Audit: known-vulnerable, abandoned and filter-listed PHP dependencies.

What it runs
------------
``composer audit`` (Composer 2.8 and later; ``--abandoned`` arrived in 2.8.0) over every
``composer.lock`` in the scan target, one run per lock file. Composer checks the locked
packages against the security advisories Packagist publishes (or those of the other
repositories the project's ``composer.json`` lists), reports packages their maintainers
abandoned, and reports locked versions that match a filter list: the ``malware`` list
repositories advertise, and any list the project's ``config.policy`` defines. Each
advisory and each filter-list match becomes one finding on the lock file, on the line
that names the package; each abandoned package is one more.

This is an alpha plugin. It is on once its module is listed in ``ash_plugin_modules``;
a scan that does not list it is unchanged. ASH pins Composer 2.11.3 in
``composer_install.py``, and ``ash dependencies install`` places that phar as
``composer`` on Linux and macOS, and on Windows as ``composer.phar`` with a
``composer.bat`` launcher beside it; a ``composer`` already on ``PATH`` is used as well.
ASH never installs PHP: the phar runs with the ``php`` on ``PATH``. The ASH container
image carries neither.

On Windows a ``composer`` found on ``PATH`` is usually a batch launcher (the one ASH
writes, or another install's), and Windows starts a batch file by running cmd.exe on it,
which reads the arguments again. When the launcher has ``composer.phar`` beside it, the
scanner runs that phar with the ``php`` on ``PATH`` instead (``_program``), so a lock
directory's path reaches Composer as written.

Invocation
----------
::

    composer audit --locked --format=json --abandoned=report --no-plugins \\
        --no-scripts --no-interaction --no-ansi --working-dir=<dir holding the lock>

Every option is one token, so no path or value is read as a flag. The flags were read
from the Composer command reference (https://getcomposer.org/doc/03-cli.md#audit) and
from ``src/Composer/Command/AuditCommand.php`` at the 2.11.3 tag (commit e4a580d4):

* ``--locked`` audits ``composer.lock`` whatever is in ``vendor/``, which a source
  checkout usually lacks. Without a valid lock file Composer throws instead of auditing.
* ``--format=json`` writes one JSON document to stdout; ``--abandoned=report`` lists
  abandoned packages without failing the run for them, whatever ``composer.json`` or
  ``COMPOSER_AUDIT_ABANDONED`` say.
* ``--no-plugins`` and ``--no-scripts`` keep code the scanned project declares from
  running during the audit.
* ``--working-dir`` is where Composer looks for ``composer.json`` and
  ``composer.lock``. The subprocess itself runs in the source directory.

``COMPOSER_POLICY`` and ``COMPOSER_AUDIT_ABANDONED`` are removed from Composer's
environment: ``COMPOSER_POLICY=0`` turns every dependency policy, the audit's included,
off (``Config::get('policy')`` at 2.11.3).

Network
-------
The advisories are fetched when the audit runs, so Composer needs the network and
there is no offline mode. ``offline_strategy`` is ``SKIP_OFFLINE``: an offline scan
skips this scanner rather than reporting a clean result. An unreachable repository is
a failed target, never a clean one.

Output and exit status
----------------------
The JSON document (``Composer\\Advisory\\Auditor::audit`` at 2.11.3) has these keys:

* ``advisories``: package name to a list of advisory objects with ``advisoryId``,
  ``packageName``, ``affectedVersions``, ``title``, ``cve``, ``link``, ``reportedAt``,
  ``sources`` and ``severity``. Composer leaves the key out when the project's policy
  turns the advisories audit off, so that no document reads as "checked, nothing
  found"; this plugin then fails the target.
* ``abandoned``: package name to its suggested replacement, or null.
* ``filter``: package name to the filter-list entries the locked version matches, each
  with ``packageName``, ``listName``, ``constraint`` (the versions the list names),
  ``url``, ``reason``, ``id`` and ``source``. The ``malware`` list is audited, and fails
  the audit, by default; so are the project's own lists.
* ``cooldown``: package name to ``prettyVersion``, ``releaseDate``, ``availableIn`` and
  ``source`` for a locked version newer than the project's ``policy.cooldown`` period.
  Composer fills it only when the project sets ``policy.cooldown.audit``.
* ``ignored-advisories`` and ``unreachable-repositories``, each only when non-empty.

PHP encodes an empty map as ``[]``, which is read as an empty map.

Exit status, read at 2.11.3: ``Auditor::audit`` returns ``STATUS_OK`` (0) or
``STATUS_FAILED`` (1), and 1 means a policy whose audit mode is ``fail`` matched: an
advisory, a filter-list entry, a cooldown entry, or an abandoned package (never with
``--abandoned=report``). ``AuditCommand`` adds two runs that write no JSON: a lock file
with no packages exits 0 (``No packages - skipping audit.`` on stderr) when
``composer.json`` requires nothing, and 1 when it requires something. An exception
exits non-zero with no document. Earlier 2.x releases may combine flags into 2 and 3
(not verified here). So 0 to 3 are accepted as "ran" and the verdict rests on the
document: a run whose stdout is not a JSON object with an ``advisories`` key fails the
target whatever its exit code, the two runs without a document included. Any other
exit code fails the scan. Composer's stderr is never copied into a message, because it
can quote text from the scanned project.

Severity
--------
Composer's advisory severities are ``critical``, ``high``, ``medium`` and ``low``
(the ``--ignore-severity`` values). ASH severity and the SARIF level are set together:

* critical: CRITICAL, ``error``
* high: HIGH, ``error``
* medium: MEDIUM, ``warning``
* low: LOW, ``note``
* no severity (Composer emits null for an advisory a source did not rate): MEDIUM,
  ``warning``. The advisory is still a known vulnerability, so it is not rated lower.
* a severity word Composer did not document: HIGH, ``error``, the more severe choice
  for a value that cannot be read.
* an abandoned package: LOW, ``note`` (rule ``COMPOSER-ABANDONED``). It is a
  maintenance finding with no known vulnerability.
* a match in the ``malware`` filter list: CRITICAL, ``error`` (rule
  ``COMPOSER-FILTER-malware``).
* a match in any other filter list: HIGH, ``error`` (rule ``COMPOSER-FILTER-<list>``),
  the more severe choice for a list whose meaning ASH cannot read.

Limits
------
* The scanned project's ``composer.json`` can carry ``config.policy`` settings, and the
  older ``config.audit`` ones, that Composer applies: ignore lists for advisories and
  filter lists, and ignored severities. Composer reads them from the project and no flag
  that turns them off was found, so a project can hide advisories from this scanner.
  Advisories it ignores appear under ``ignored-advisories`` in the JSON and are not
  reported by this plugin. A project that turns the advisories audit off altogether
  (``config.policy: false``, or an advisories audit mode of ``ignore``) gets no
  ``advisories`` key, and its target fails instead.
* ``cooldown`` entries are not reported: they are a release-age policy the project opts
  into, and say nothing about what the package contains.
* Locations are the package's line in ``composer.lock``, not the ``composer.json``
  line that required it.
* ``vendor/``, ``node_modules/`` and ``.git/`` are not searched for lock files.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import stat
import time
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, ClassVar, Dict, List, Literal, Optional, Set, Tuple

from pydantic import AnyUrl, Field, PrivateAttr, model_validator

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_facets import (
    FacetDecl,
    FacetState,
    ScannerFacets,
)
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolArgs
from automated_security_helper.plugin_modules.ash_composer_audit_plugins.composer_install import (
    COMPOSER_VERSION,
    WINDOWS_PHAR_NAME,
    composer_install_commands,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import (
    MultiformatMessageString,
    ReportingDescriptor,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.package_identity import identity_properties
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import find_executable

#: Composer advisory severity -> (ASH severity, SARIF level). See the module docstring.
COMPOSER_SEVERITY_MAP: Dict[str, Tuple[str, str]] = {
    "critical": ("CRITICAL", "error"),
    "high": ("HIGH", "error"),
    "medium": ("MEDIUM", "warning"),
    "low": ("LOW", "note"),
}

#: An advisory Composer gave no severity (JSON null).
NO_SEVERITY: Tuple[str, str] = ("MEDIUM", "warning")

#: A severity word that is not one of the four Composer documents.
UNKNOWN_SEVERITY: Tuple[str, str] = ("HIGH", "error")

#: Rule id and rating of an abandoned package.
ABANDONED_RULE_ID = "COMPOSER-ABANDONED"
ABANDONED_SEVERITY: Tuple[str, str] = ("LOW", "note")

#: A filter-list match is reported under ``COMPOSER-FILTER-<listName>``.
FILTER_RULE_PREFIX = "COMPOSER-FILTER-"

#: Filter list -> (ASH severity, SARIF level) for a match. ``malware`` is the list
#: Composer builds in; any other name is rated FILTER_UNKNOWN_SEVERITY.
FILTER_SEVERITY_MAP: Dict[str, Tuple[str, str]] = {
    "malware": ("CRITICAL", "error"),
}

#: A match in a filter list ASH cannot rate.
FILTER_UNKNOWN_SEVERITY: Tuple[str, str] = ("HIGH", "error")

LOCK_FILE_NAME = "composer.lock"

#: Directories never searched for lock files: installed dependencies carry their own
#: ``composer.lock`` files, which are not the project's.
SKIPPED_DIRECTORIES = frozenset({"vendor", "node_modules", ".git"})

#: Composer environment variables that change what the audit reports. Removed.
_INVOCATION_ENV_VARS = frozenset({"COMPOSER_POLICY", "COMPOSER_AUDIT_ABANDONED"})

#: Exit codes that mean Composer ran to completion (the verdict is the JSON).
COMPLETED_EXIT_CODES: Set[int] = {0, 1, 2, 3}

#: The most a lock file is read for line numbers and versions.
_LOCK_READ_LIMIT = 64 * 1024 * 1024

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_BINARY = getattr(os, "O_BINARY", 0)

#: The clock the scan's time budget is measured on; a seam for tests.
_now = time.monotonic

#: The suffixes Windows starts by running cmd.exe on the file.
_BATCH_SUFFIXES = (".bat", ".cmd")


def _windows() -> bool:
    """Whether this process runs on Windows; a seam for tests."""
    return platform.system().lower() == "windows"


def severity_for(raw: Any) -> Tuple[str, str]:
    """``(ASH severity, SARIF level)`` for a Composer advisory severity value."""
    if raw is None:
        return NO_SEVERITY
    if isinstance(raw, str):
        return COMPOSER_SEVERITY_MAP.get(raw.strip().lower(), UNKNOWN_SEVERITY)
    return UNKNOWN_SEVERITY


def filter_severity_for(list_name: str) -> Tuple[str, str]:
    """``(ASH severity, SARIF level)`` for a match in the filter list *list_name*."""
    return FILTER_SEVERITY_MAP.get(list_name, FILTER_UNKNOWN_SEVERITY)


def _as_mapping(value: Any) -> Dict[str, Any]:
    """A JSON object, or ``{}`` for PHP's empty array (``[]``) and for null."""
    if isinstance(value, dict):
        return value
    if value is None or value == []:
        return {}
    raise ValueError("expected an object")


def parse_audit_document(stdout: str) -> Dict[str, Any]:
    """Parse and check ``composer audit --format=json`` output.

    Raises ValueError for anything that is not a JSON object with an ``advisories``
    key holding an object (or ``[]``), or whose ``abandoned`` or ``filter`` entry is
    not one.
    """
    if not stdout or not stdout.strip():
        raise ValueError("it wrote no output")
    try:
        document = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(f"its output is not JSON ({exc.msg})") from None
    if not isinstance(document, dict) or "advisories" not in document:
        raise ValueError("its output is not an audit result (no advisories key)")
    try:
        _as_mapping(document["advisories"])
        _as_mapping(document.get("abandoned"))
        _as_mapping(document.get("filter"))
    except ValueError:
        raise ValueError(
            "its advisories, abandoned or filter entry is not an object"
        ) from None
    return document


def _read_lock(path: Path) -> Optional[str]:
    """The text of the regular file at ``path``, or None; no link is followed."""
    try:
        fd = os.open(path, os.O_RDONLY | _NOFOLLOW | _BINARY)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            return None
        data = handle.read(_LOCK_READ_LIMIT + 1)
    if len(data) > _LOCK_READ_LIMIT:
        return None
    return data.decode("utf-8", errors="replace")


def lock_versions(text: Optional[str]) -> Dict[str, str]:
    """``package -> version`` from the text of a ``composer.lock``."""
    if not text:
        return {}
    try:
        document = json.loads(text)
    except json.JSONDecodeError:
        return {}
    versions: Dict[str, str] = {}
    if not isinstance(document, dict):
        return versions
    for key in ("packages", "packages-dev"):
        for package in document.get(key) or []:
            if isinstance(package, dict) and package.get("name"):
                versions[str(package["name"])] = str(package.get("version") or "")
    return versions


def package_line(text: Optional[str], package: str) -> int:
    """The 1-based line of ``"name": "<package>"`` in a lock file; 1 when not found."""
    if not text:
        return 1
    needle = json.dumps(package)
    for index, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip().rstrip(",")
        if stripped.startswith('"name"') and stripped.split(":", 1)[-1].strip() == (
            needle
        ):
            return index
    return 1


def _help_uri(link: Any) -> Optional[AnyUrl]:
    """*link* as a rule ``helpUri``, or None when it is absent or not a URL."""
    if not isinstance(link, str) or not link.strip():
        return None
    try:
        return AnyUrl(link.strip())
    except ValueError:
        return None


def _rule_descriptor(rule_id: str, text: str, link: Any = None) -> ReportingDescriptor:
    """The rule for *rule_id*; ``helpUri`` is set only when *link* is a URL.

    Every field is passed by name (no ``**`` mapping), so the descriptor is built
    from values this module chose and never validated from a tool's own mapping.
    """
    description = MultiformatMessageString(text=text)
    help_uri = _help_uri(link)
    if help_uri is None:
        return ReportingDescriptor(
            id=rule_id, name=rule_id, shortDescription=description
        )
    return ReportingDescriptor(
        id=rule_id, name=rule_id, shortDescription=description, helpUri=help_uri
    )


def _fingerprint(*parts: str) -> Dict[str, str]:
    return {
        "composer-audit/v1": hashlib.sha256("\0".join(parts).encode()).hexdigest()[:32]
    }


def _location(uri: str, line: int) -> List[Dict[str, Any]]:
    return [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": line},
            }
        }
    ]


def _entries(value: Any) -> List[Any]:
    """A package's list of advisories or filter-list entries; a map is its values."""
    if isinstance(value, dict):
        return list(value.values())
    return list(value or [])


def convert_audit_document(
    document: Dict[str, Any],
    *,
    uri: str,
    lock_text: Optional[str],
) -> Tuple[List[Result], Dict[str, ReportingDescriptor]]:
    """SARIF results (and their rules) for one parsed ``composer audit`` document.

    ``uri`` is the lock file's path relative to the source directory.
    """
    versions = lock_versions(lock_text)
    results: List[Result] = []
    rules: Dict[str, ReportingDescriptor] = {}
    seen: Set[Tuple[str, ...]] = set()

    advisories = _as_mapping(document.get("advisories"))
    for package in sorted(advisories):
        for advisory in _entries(advisories[package]):
            if not isinstance(advisory, dict):
                continue
            name = str(advisory.get("packageName") or package)
            advisory_id = str(advisory.get("advisoryId") or "COMPOSER-ADVISORY")
            if (advisory_id, name) in seen:
                continue
            seen.add((advisory_id, name))
            severity, level = severity_for(advisory.get("severity"))
            title = str(advisory.get("title") or advisory_id)
            version = versions.get(name, "")
            cve = advisory.get("cve")
            affected = advisory.get("affectedVersions")
            link = advisory.get("link")
            text = f"{name}{f' {version}' if version else ''}: {title}"
            if cve:
                text += f" ({cve})"
            if affected:
                text += f". Affected versions: {affected}"
            if link:
                text += f". {link}"
            rules.setdefault(advisory_id, _rule_descriptor(advisory_id, title, link))
            results.append(
                Result.model_validate(
                    {
                        "ruleId": advisory_id,
                        "level": level,
                        "message": {"text": text},
                        "locations": _location(uri, package_line(lock_text, name)),
                        "partialFingerprints": _fingerprint(advisory_id, name, uri),
                        "properties": {
                            "issue_severity": severity,
                            "tags": ["sca", "dependency", "php"],
                            **identity_properties(name, version or None, None),
                            "composer_severity": advisory.get("severity"),
                            "advisory_id": advisory_id,
                            "cve": cve,
                            "affected_versions": affected,
                            "advisory_link": link,
                        },
                    }
                )
            )

    abandoned = _as_mapping(document.get("abandoned"))
    for package in sorted(abandoned):
        replacement = abandoned[package]
        severity, level = ABANDONED_SEVERITY
        version = versions.get(package, "")
        text = f"{package}{f' {version}' if version else ''} is abandoned"
        text += (
            f"; its maintainers suggest {replacement} instead"
            if replacement
            else " and no replacement is suggested"
        )
        rules.setdefault(
            ABANDONED_RULE_ID,
            _rule_descriptor(ABANDONED_RULE_ID, "A locked package is abandoned"),
        )
        results.append(
            Result.model_validate(
                {
                    "ruleId": ABANDONED_RULE_ID,
                    "level": level,
                    "message": {"text": text},
                    "locations": _location(uri, package_line(lock_text, package)),
                    "partialFingerprints": _fingerprint(
                        ABANDONED_RULE_ID, package, uri
                    ),
                    "properties": {
                        "issue_severity": severity,
                        "tags": ["sca", "dependency", "php", "abandoned"],
                        **identity_properties(package, version or None, None),
                        "replacement_package": replacement,
                    },
                }
            )
        )

    filtered = _as_mapping(document.get("filter"))
    for package in sorted(filtered):
        for entry in _entries(filtered[package]):
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("packageName") or package)
            list_name = str(entry.get("listName") or "unnamed")
            rule_id = f"{FILTER_RULE_PREFIX}{list_name}"
            entry_id = entry.get("id")
            constraint = entry.get("constraint")
            key = (rule_id, name, str(entry_id or constraint or ""))
            if key in seen:
                continue
            seen.add(key)
            severity, level = filter_severity_for(list_name)
            version = versions.get(name, "")
            reason = entry.get("reason")
            url = entry.get("url")
            text = (
                f"{name}{f' {version}' if version else ''} matches the "
                f"{list_name} filter list"
            )
            if entry_id:
                text += f" ({entry_id})"
            if reason:
                text += f": {reason}"
            if constraint:
                text += f". Listed versions: {constraint}"
            if url:
                text += f". {url}"
            rules.setdefault(
                rule_id,
                _rule_descriptor(
                    rule_id, f"A locked package matches the {list_name} filter list"
                ),
            )
            tags = ["sca", "dependency", "php", "filter-list"]
            if list_name == "malware":
                tags.append("malware")
            results.append(
                Result.model_validate(
                    {
                        "ruleId": rule_id,
                        "level": level,
                        "message": {"text": text},
                        "locations": _location(uri, package_line(lock_text, name)),
                        "partialFingerprints": _fingerprint(rule_id, *key[1:], uri),
                        "properties": {
                            "issue_severity": severity,
                            "tags": tags,
                            **identity_properties(name, version or None, None),
                            "filter_list": list_name,
                            "filter_id": entry_id,
                            "filter_reason": reason,
                            "filter_source": entry.get("source"),
                            "filter_constraint": constraint,
                            "advisory_link": url,
                        },
                    }
                )
            )
    return results, rules


class ComposerAuditScannerConfigOptions(ScannerOptionsBase):
    """No options of its own.

    The base options (``severity_threshold``, ``scan_timeout``, ``offline``) apply.
    Nothing that could drop findings (ignored severities, dev-package exclusion) is
    exposed, so a scanned tree cannot turn one on through ASH configuration.
    """


class ComposerAuditScannerConfig(ScannerPluginConfigBase):
    name: Literal["composer-audit"] = "composer-audit"
    enabled: bool = True
    options: Annotated[
        ComposerAuditScannerConfigOptions,
        Field(description="Configure the composer-audit scanner"),
    ] = ComposerAuditScannerConfigOptions()


@ash_scanner_plugin
class ComposerAuditScanner(ScannerPluginBase[ComposerAuditScannerConfig]):
    """Known-vulnerable, abandoned and filter-listed PHP dependencies, with ``composer audit``."""

    #: Composer is a PHP program on PATH, so a Python-only scan does not run it.
    python_only: ClassVar[bool | None] = False

    # Advisories are fetched from Packagist when the audit runs; offline there is
    # nothing to check against, so the scanner is skipped.
    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.SKIP_OFFLINE
    #: The facets register row (base/scanner_facets.py). Declaration only: no
    #: behavior changes. Native fields name the ``composer audit --format=json``
    #: document (captured fixture tests/test_data/scanners/composer_audit/captured/,
    #: written by Composer 2.11.3; see that directory's README for the capture run),
    #: and the corpus is the SARIF the adapter writes from it (captured/audit.sarif).
    facets: ClassVar[ScannerFacets] = ScannerFacets(
        rule_id=FacetDecl(
            state=FacetState.MAPPED,
            native_field='advisories.<package>[]."advisoryId"; abandoned packages '
            "get the adapter's COMPOSER-ABANDONED rule, and filter-list matches "
            'COMPOSER-FILTER-<filter.<package>[]."listName">',
        ),
        severity=FacetDecl(
            state=FacetState.MAPPED,
            native_field='advisories.<package>[]."severity" (critical, high, '
            'medium, low, or null); a filter-list match is rated by its "listName" '
            "(malware CRITICAL, any other list HIGH)",
        ),
        file_path=FacetDecl(
            state=FacetState.MAPPED,
            native_field="(synthesized) the composer.lock path relative to the "
            "source directory; the audit document names no file",
        ),
        line_range=FacetDecl(
            state=FacetState.MAPPED,
            native_field="(no native line) the 1-based line of the package's "
            '"name" in composer.lock, read by the adapter; a start line only',
            reason="a package the lock file does not name falls back to line 1",
        ),
        column=FacetDecl(
            state=FacetState.NA,
            reason="the audit document carries no column",
        ),
        message=FacetDecl(
            state=FacetState.MAPPED,
            native_field='advisories.<package>[]."title" composed with the '
            'package, its locked version, "cve", "affectedVersions" and "link"; a '
            'filter-list match composes "listName", "id", "reason", "constraint" '
            'and "url"',
        ),
        resource_id=FacetDecl(
            state=FacetState.NA,
            reason="LOCATOR-ONLY: findings are locked packages in composer.lock, "
            "not infrastructure resources",
        ),
        resource_type=FacetDecl(
            state=FacetState.NA,
            reason="composer audit names no resource; findings are packages",
        ),
        package_name=FacetDecl(
            state=FacetState.MAPPED,
            native_field='advisories.<package>[]."packageName"; abandoned.<package>; '
            'filter.<package>[]."packageName"; written as the package_name property',
        ),
        package_version=FacetDecl(
            state=FacetState.MAPPED,
            native_field="installed version read from composer.lock and written as "
            "the package_version property (the audit document gives only "
            '"affectedVersions", a range)',
        ),
        package_path=FacetDecl(
            state=FacetState.NA,
            reason="composer audit output names no install path",
        ),
        taxonomy_cve=FacetDecl(
            state=FacetState.DROPPED,
            native_field='advisories.<package>[]."cve" (null when the advisory '
            "has none)",
            reason="carried in the message and the result property cve; the flat "
            "CVE column reads CVE-shaped rule ids only, and the rule id is the "
            "Packagist advisory id",
        ),
        taxonomy_cwe=FacetDecl(
            state=FacetState.NA,
            reason="Packagist advisories carry no CWE field in the audit document",
        ),
        fingerprints=FacetDecl(
            state=FacetState.MAPPED,
            native_field="(no native fingerprint) result partialFingerprints "
            '"composer-audit/v1", ASH-composed: a hash of the rule id, the package '
            "(and a filter-list entry's id or constraint) and the lock path",
            reason="the findings of one lock file share a file and often a line",
        ),
        fix_available=FacetDecl(
            state=FacetState.NA,
            reason="the audit document carries no fixed version or fix flag",
        ),
        remediation_text=FacetDecl(
            state=FacetState.NA,
            reason="the audit document carries no remediation text; an abandoned "
            "package's replacement is a message detail, not a remediation field",
        ),
        snippet=FacetDecl(
            state=FacetState.NA,
            reason="a package advisory has no source code snippet",
        ),
        references=FacetDecl(
            state=FacetState.MAPPED,
            native_field='advisories.<package>[]."link" (rule helpUri), read into '
            "the flat references when the result carries no relatedLocations",
            reason="abandoned packages and filter-list matches carry none; a "
            'filter-list entry\'s "url" is in its message and its advisory_link '
            "property",
        ),
        tags=FacetDecl(
            state=FacetState.MAPPED,
            native_field="result properties tags (adapter-composed: sca, "
            "dependency, php, and abandoned, filter-list or malware)",
        ),
        extras=FacetDecl(
            state=FacetState.MAPPED,
            native_field="result properties bag (composer_severity, advisory_id, "
            "cve, affected_versions, advisory_link, replacement_package, "
            "filter_list, filter_id, filter_reason, filter_source, "
            "filter_constraint)",
        ),
    )

    #: The operational register row (base/scanner_operational_facets.py),
    #: checked against the production declarations it mirrors by
    #: tests/unit/plugin_modules/test_scanner_operational_facets_consistency.py.
    operational_facets: ClassVar[opsf.ScannerOperationalFacets] = (
        opsf.ScannerOperationalFacets(
            scanner_name="composer-audit",
            network=opsf.NetworkFacet(
                fetch_kind=opsf.FetchKind.CONTENT_FETCH,
                fetches=(opsf.Fetched.ADVISORY_FEED,),
                prefetch=(),
                offline_outcome=opsf.OfflineOutcome.NOT_RUN,
                offline_reason=(
                    "composer audit asks Packagist for advisories, so an offline "
                    "run would read every lock file as clean; the scanner does "
                    "not run"
                ),
                offline_strategy=OfflineStrategy.SKIP_OFFLINE,
                sandbox_network=opsf.SandboxNetwork.ONLINE,
                source=(
                    "composer_audit_scanner.py offline_strategy and "
                    "sandbox_requirements; module header (Network)"
                ),
            ),
            output=opsf.OutputFacet(
                native_formats=(opsf.OutputFormat.TOOL_JSON,),
                side_reports=(),
                non_finding_artifacts=(),
                note="Composer's own audit JSON, converted to SARIF by "
                "convert_audit_document",
            ),
            targets=opsf.TargetsFacet(
                kinds=(opsf.TargetKind.DEPENDENCY_LOCKFILES,),
                tool_type=ScannerToolType.SCA,
                selection="every composer.lock under the target (vendor, "
                "node_modules and .git skipped), one composer audit per lock "
                "(_lock_files)",
                covers_note="an alpha scanner; it declares no covers display string",
            ),
            runtime=opsf.RuntimeFacet(
                kind=opsf.RuntimeKind.USER_INSTALLED_CLI,
                external_programs=("php",),
                invocations=opsf.Invocations.PER_TARGET,
                invocation_note="one composer audit per composer.lock",
                python_only=False,
                use_uv_tool=False,
            ),
            # Honest-empty: the compat vocabulary covers python and node only.
            # Composer 2.11.3 needs PHP 7.2.5 or later (getcomposer.org/versions,
            # min-php 70205), which Composer itself checks when it starts.
            runtime_compat=opsf.RuntimeCompatFacet(rows=()),
            platforms=opsf.PlatformsFacet(
                provisionable=(),
                note="composer.phar 2.11.3 is installed by the plugin's own pinned "
                "installer (composer_install.py) on linux and darwin, amd64 and "
                "arm64, as composer, and on windows, amd64 and arm64, as "
                "composer.phar with a composer.bat launcher beside it; not by the "
                "shared tool_downloads table, so the register lists none. PHP is "
                "never installed, and the container image carries neither",
            ),
            severity=opsf.SeverityFacet(
                severity_class=opsf.SeverityClass.NATIVE,
                note="Composer's critical/high/medium/low scale is mapped; null is "
                "MEDIUM, an unknown word HIGH, abandoned LOW, a malware filter-list "
                "match CRITICAL and any other list HIGH (COMPOSER_SEVERITY_MAP, "
                "FILTER_SEVERITY_MAP)",
            ),
            silencing=opsf.SilencingFacet(
                tool_side=(
                    opsf.SilencingLayer(
                        layer=opsf.SilencingLayerKind.IGNORE_FILE,
                        writer=opsf.SilencingWriter.REPOSITORY,
                        honored=opsf.Honored.YES,
                        surface="the scanned project's composer.json config.policy "
                        "(advisory and filter-list ignore lists, ignore-severity) "
                        "and the older config.audit (ignore, ignore-severity)",
                        cite="composer_audit_scanner.py module header (Limits); "
                        "read at Composer 2.11.3: Policy/PolicyConfig::fromConfig "
                        "and Advisory/Auditor::audit, which Composer applies with "
                        "no flag to turn them off",
                    ),
                ),
            ),
            identity=opsf.IdentityFacet(
                fingerprint_class=opsf.FingerprintClass.STABLE_COMPUTED,
                note="composer-audit/v1 hashes the rule id, the package (and a "
                "filter-list entry's id or constraint) and the lock path",
            ),
            extensibility=opsf.ExtensibilityFacet(
                custom_rules=opsf.CustomRules.NONE,
                env_prefixes=(),
                options_surface="the base options only; COMPOSER_POLICY and "
                "COMPOSER_AUDIT_ABANDONED are removed from Composer's environment",
            ),
            exit_codes=opsf.ExitCodesFacet(
                success_exit_codes=(0, 1, 2, 3),
                semantics="Composer 2.11.3 exits 0 or 1 from the audit (1 when a "
                "failing policy matched); 0 to 3 mean Composer ran and the verdict "
                "is the JSON document, so output that is not an audit result fails "
                "the scan",
            ),
            provenance=opsf.ProvenanceFacet(
                source=opsf.ProvenanceSource.USER_INSTALLED,
                selection_surfaces=(
                    "ash_composer_audit_plugins in ash_plugin_modules",
                ),
                upstream_license="MIT (source: the LICENSE file at the 2.11.3 tag "
                "of github.com/composer/composer, commit e4a580d4, sha256 "
                "7855ac29, read 2026-11-26 and carried byte for byte inside the "
                "pinned composer.phar; downloaded at install time, never vendored)",
            ),
            prerequisites=opsf.PrerequisitesFacet(
                kinds=(opsf.Prerequisite.LOCKFILE, opsf.Prerequisite.MANIFEST),
                note="a composer.lock with a composer.json beside it, and PHP on "
                "PATH to run composer",
            ),
        )
    )

    success_exit_codes: ClassVar[Set[int]] = set(COMPLETED_EXIT_CODES)
    # Network only: Composer reads advisories from Packagist. Its cache and home
    # directories and COMPOSER_* variables wait for the sandbox grant gates.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        network=True,
    )

    #: The ignore list the last ``scan()`` call was handed, so
    #: ``nothing_to_scan_reason`` answers from the selection that scan made.
    _handed_ignore_paths: List[IgnorePathWithReason] = PrivateAttr(default_factory=list)

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = ComposerAuditScannerConfig()
        self.command = "composer"
        self.tool_type = ScannerToolType.SCA
        self.args = ToolArgs(extra_args=[])
        super().model_post_init(context)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "ComposerAuditScanner":
        """Install the pinned phar from ``composer_install.py`` (never PHP).

        The pin is module-local: ``utils/tool_downloads.py`` has no Composer entry.
        The table never raises.
        """
        self.custom_install_commands.update(composer_install_commands())
        return self

    def _execute_scan(
        self, target: Any, target_type: Any, global_ignore_paths: Any
    ) -> Any:
        """Abstract stub: composer audit overrides scan() directly."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    @property
    def _ctx(self) -> PluginContext:
        if self.context is None:  # pragma: no cover - model_post_init raises first
            raise ScannerError("ComposerAuditScanner has no plugin context")
        return self.context

    # ------------------------------------------------------------------
    # Inputs
    # ------------------------------------------------------------------

    def _lock_files(
        self,
        target: Path,
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> List[Path]:
        """Every ``composer.lock`` under *target*, sorted, links not followed."""
        from automated_security_helper.utils.suppression_matcher import (
            file_path_matches,
        )

        root = target.absolute()
        found: List[Path] = []
        for current, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = sorted(d for d in dirs if d not in SKIPPED_DIRECTORIES)
            if LOCK_FILE_NAME not in files:
                continue
            path = Path(current) / LOCK_FILE_NAME
            if path.is_symlink():
                ASH_LOGGER.warning(
                    f"composer-audit: {path} is a link and was not followed."
                )
                continue
            relative = PurePosixPath(path.relative_to(root).as_posix()).as_posix()
            if any(file_path_matches(relative, i.path) for i in global_ignore_paths):
                continue
            found.append(path)
        return sorted(found)

    @staticmethod
    def _subprocess_env() -> Dict[str, str]:
        """The process environment minus ``_INVOCATION_ENV_VARS``."""
        return {
            k: v for k, v in snapshot_environ().items() if k not in _INVOCATION_ENV_VARS
        }

    def _program(self) -> List[str]:
        """The argv prefix that starts Composer: ``[composer]``, or ``[php, phar]``.

        On Windows the ``composer`` found on ``PATH`` is usually a batch launcher (the
        one ``composer_install.py`` writes, or another install's), and Windows starts a
        batch file by running cmd.exe on it, which reads the arguments a second time.
        When the launcher has ``composer.phar`` beside it and ``php`` is found, the phar
        is run with that ``php`` instead, so the arguments (a lock directory's path is
        one) reach Composer as written. Anything else runs ``composer`` as found. Both
        lookups are the scan's own (``find_executable``), so neither program is ever one
        inside the scanned tree.
        """
        command = self.command or "composer"
        if not _windows():
            return [command]
        found = find_executable(command)
        if not found or not found.lower().endswith(_BATCH_SUFFIXES):
            return [command]
        phar = os.path.join(os.path.dirname(found), WINDOWS_PHAR_NAME)
        php = find_executable("php")
        if php is None or not os.path.isfile(phar):
            return [command]
        return [php, phar]

    def _argv(self, lock_dir: Path) -> List[str]:
        return [
            *self._program(),
            "audit",
            "--locked",
            "--format=json",
            "--abandoned=report",
            "--no-plugins",
            "--no-scripts",
            "--no-interaction",
            "--no-ansi",
            f"--working-dir={lock_dir.as_posix()}",
        ]

    def _uri(self, lock: Path) -> str:
        """The lock file's path as reported: relative to the source directory."""
        source_dir = Path(self._ctx.source_dir).absolute()
        absolute = lock.absolute()
        try:
            return PurePosixPath(absolute.relative_to(source_dir).as_posix()).as_posix()
        except ValueError:
            return absolute.as_posix()

    # ------------------------------------------------------------------
    # The scan
    # ------------------------------------------------------------------

    def _empty_report(
        self, results: Optional[List[Result]] = None, rules: Any = None
    ) -> SarifReport:
        return SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(
                        driver=ToolComponent(
                            name="Composer Audit",
                            version=self.tool_version,
                            informationUri=AnyUrl(
                                "https://getcomposer.org/doc/03-cli.md#audit"
                            ),
                            rules=[rules[k] for k in sorted(rules)] if rules else None,
                        )
                    ),
                    results=results or [],
                )
            ],
        )

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: ComposerAuditScannerConfig | ScannerPluginConfigBase | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> SarifReport | bool:
        """Audit every ``composer.lock`` under *target*."""
        if global_ignore_paths is None:
            global_ignore_paths = []
        self._handed_ignore_paths = global_ignore_paths

        # Reset above every early return so a second target never inherits counts.
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
            return self._empty_report()

        if not self._pre_scan(target=target, target_type=target_type, config=config):
            self._post_scan(target=target, target_type=target_type)
            return False

        results_file: Optional[Path] = None
        try:
            locks = self._lock_files(target, global_ignore_paths)
            if not locks:
                self._plugin_log(
                    f"No {LOCK_FILE_NAME} found in {target_type} directory to audit.",
                    target_type=target_type,
                    level=logging.INFO,
                    append_to_stream="stderr",
                )
                self._post_scan(target=target, target_type=target_type)
                return self._empty_report()

            self.targets_attempted = len(locks)
            results_dir = Path(self.results_dir or self._ctx.output_dir).joinpath(
                target_type
            )
            results_dir.mkdir(parents=True, exist_ok=True)
            results_file = results_dir.joinpath("composer-audit.sarif")
            results_file.unlink(missing_ok=True)

            # One budget for every run of this scan, so scan_timeout bounds the
            # scanner and not each process.
            timeout = self._effective_scan_timeout()
            deadline = None if timeout is None else _now() + timeout

            results: List[Result] = []
            rules: Dict[str, ReportingDescriptor] = {}
            failures: List[str] = []
            final_args: List[str] = []
            for lock in locks:
                uri = self._uri(lock)
                final_args = self._argv(lock.parent)
                if not (lock.parent / "composer.json").is_file():
                    failures.append(
                        f"{uri}: there is no composer.json beside it, so composer "
                        "audit cannot run"
                    )
                    continue
                if deadline is None:
                    remaining = None
                else:
                    remaining = deadline - _now()
                    if remaining <= 0:
                        failures.append(
                            f"{uri}: composer audit timed out after {timeout}s "
                            "before it started"
                        )
                        continue
                response = self._run_subprocess(
                    command=final_args,
                    results_dir=results_dir,
                    stdout_preference="return",
                    stderr_preference="write",
                    env=self._subprocess_env(),
                    timeout=remaining,
                )
                failure = self._check_response(
                    response if isinstance(response, dict) else {}, uri, timeout
                )
                if failure is not None:
                    failures.append(failure)
                    continue
                document = parse_audit_document(response.get("stdout") or "")
                unreachable = document.get("unreachable-repositories")
                if unreachable:
                    failures.append(
                        f"{uri}: composer could not reach {len(unreachable)} "
                        "advisory repository(ies), so the audit is incomplete"
                    )
                    continue
                found, found_rules = convert_audit_document(
                    document, uri=uri, lock_text=_read_lock(lock)
                )
                results.extend(found)
                for rule_id, rule in found_rules.items():
                    rules.setdefault(rule_id, rule)

            self._post_scan(target=target, target_type=target_type)
            self.targets_failed = len(failures)
            for failure in failures:
                self.errors.append(failure)
                self._plugin_log(failure, target_type=target_type, level=logging.ERROR)

            report = self._empty_report(results, rules)
            with open_for_write(results_file) as handle:
                handle.write(
                    report.model_dump_json(
                        exclude_none=True, exclude_unset=True, by_alias=True
                    )
                )
            self._inject_invocation(report, final_args, target)
        except ScannerError:
            raise
        except Exception as e:
            raise ScannerError(self._describe_scan_failure(e, results_file))

        if failures:
            raise ScannerError(
                f"composer audit did not complete for {self.targets_failed} of "
                f"{self.targets_attempted} lock file(s), so this run is not a clean "
                f"scan: {' | '.join(failures)}"
            )
        return report

    def _check_response(
        self, response: Dict[str, Any], uri: str, timeout: Optional[float]
    ) -> Optional[str]:
        """A failure message for a run that did not complete, else None.

        Composer's stderr is not quoted: it can hold text from the scanned project.
        """
        if response.get("timed_out"):
            return (
                f"{uri}: composer audit timed out after {timeout}s and was killed. "
                "Raise scanners.composer-audit.options.scan_timeout if the audit "
                "legitimately needs longer."
            )
        if response.get("spawn_failed"):
            return f"{uri}: composer could not be started"
        code = response.get("returncode", self.exit_code)
        if code not in self.success_exit_codes:
            return f"{uri}: composer audit exited {code}, so it did not complete"
        try:
            parse_audit_document(response.get("stdout") or "")
        except ValueError as exc:
            return f"{uri}: composer audit exited {code} but {exc}"
        return None

    def nothing_to_scan_reason(self) -> str | None:
        """None when a tree holds a composer.lock with a composer.json beside it.

        The same selection ``scan()`` makes (``_lock_files``), over the source tree
        and the converted tree, with the ignore list the last ``scan()`` call was
        handed. A lock file with no composer.json is not None: scan() reports it as
        a failed target, so it must not read as "nothing to scan".
        """
        trees = [Path(self._ctx.source_dir)]
        work_dir = self._ctx.work_dir
        if work_dir is not None and Path(work_dir).is_dir():
            trees.append(Path(work_dir))
        for tree in trees:
            if tree.is_dir() and self._lock_files(tree, self._handed_ignore_paths):
                return None
        return f"no {LOCK_FILE_NAME} in the scanned files"

    def validate_plugin_dependencies(self) -> bool:
        if self.dependency_unavailable_reason:
            return False
        if not find_executable("php"):
            ASH_LOGGER.warning(
                "php was not found in PATH. Composer is a PHP program, so the "
                "composer-audit scanner needs PHP 7.2.5 or later; ASH does not "
                "install it."
            )
            return False
        found = find_executable(self.command or "composer")
        if not found:
            ASH_LOGGER.warning(
                "composer executable not found in PATH. Run `ash dependencies "
                "install --tool composer-audit` with the module listed in "
                "ash_plugin_modules to install the pinned Composer "
                f"{COMPOSER_VERSION} on Linux, macOS or Windows, or install Composer "
                "from https://getcomposer.org/download/."
            )
        return found is not None


__all__ = [
    "ABANDONED_RULE_ID",
    "COMPOSER_SEVERITY_MAP",
    "ComposerAuditScanner",
    "ComposerAuditScannerConfig",
    "ComposerAuditScannerConfigOptions",
    "FILTER_RULE_PREFIX",
    "FILTER_SEVERITY_MAP",
    "convert_audit_document",
    "filter_severity_for",
    "parse_audit_document",
    "severity_for",
]
