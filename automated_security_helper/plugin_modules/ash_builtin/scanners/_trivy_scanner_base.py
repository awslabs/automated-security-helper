# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the builtin ``trivy`` scanner and the community ``trivy-repo`` scanner share.

Why this module exists
----------------------
trivy reached ASH first as the community plugin ``trivy-repo``
(``plugin_modules/ash_trivy_plugins``), which users enable through
``ash_plugin_modules``. The builtin ``trivy`` scanner runs the same binary, so the
logic that turns options into trivy flags, installs the pinned binary, and ties a
vulnerability result to one package copy lives here once instead of being copied
into a second module that would drift from the first.

Only behaviour is shared. Each scanner keeps its own config classes, because their
names and defaults differ (``trivy-repo`` runs all four trivy scanners and drops
unfixed vulnerabilities; ``trivy`` runs ``vuln`` only and keeps them), and its own
scan path: ``trivy-repo`` keeps the ``scan()`` override it has always had (its
names and output files are unchanged, while its results carry trivy's own
severity and its command ASH's scan timeout and the output-directory skips, as
the builtin scanner's do), and ``trivy`` uses the template-method ``scan()`` the
builtin scanners use.

The options are read by attribute (``scanners``, ``license_full``,
``ignore_unfixed``, ``disable_telemetry``, ``offline``), so both config classes
satisfy it without sharing a base.
"""

from __future__ import annotations

import logging
import math
import os
import re
import sys
import threading
from pathlib import Path
from typing import (
    Annotated,
    Any,
    ClassVar,
    Dict,
    Generic,
    List,
    Mapping,
    Optional,
    Set,
    Tuple,
    TypeVar,
)

import yaml
from pydantic import Field, PrivateAttr, model_validator

from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.core.enums import OfflineStrategy
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason, ToolExtraArg
from automated_security_helper.schemas.sarif_schema_model import (
    PropertyBag,
    SarifReport,
)
from automated_security_helper.utils.download_utils import (
    pinned_tool_install_commands,
)
from automated_security_helper.config.operator_paths import (
    anchored_environment_path,
)
from automated_security_helper.config.path_trust import honored_path
from automated_security_helper.config.tool_config_trust import empty_tool_config
from automated_security_helper.utils.config_trust import (
    operator_path,
    refusal_warning,
)
from automated_security_helper.utils.display_text import escape_controls
from automated_security_helper.utils.content_db_refresh import (
    default_cache_dir,
    prepare_content_db,
    scan_id_for,
)
from automated_security_helper.utils.content_db_shared import EMPTY_TOOL_CONFIG
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.link_exclusions import (
    trivy_skip_dirs,
    trivy_skip_files,
)
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.process_env import snapshot_environ
from automated_security_helper.utils.subprocess_utils import (
    COULD_NOT_STOP_ENDING,
    WAS_KILLED_ENDING,
    find_executable,
)
from automated_security_helper.utils.error_text import text_without_values
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.package_identity import (
    NpmLockIndex,
    identity_properties,
    install_path,
)

C = TypeVar("C", bound=ScannerPluginConfigBase)

#: Flags every trivy scan gets, online or offline. ``trivy --offline-scan``: trivy scans
#: never contact package registries; the database refresh is a separate step
#: (``_shared_update_flags``). Measured with trivy 0.75.0: an online ``trivy fs`` of a
#: pom.xml requested its parent and dependency POMs from the repository the pom.xml
#: declares and from Maven Central, and with the flag requested nothing. trivy then
#: resolves Maven dependencies from the scanned tree and the local Maven repository
#: (``~/.m2/repository``) only. The one fetch the flag does not stop is the
#: misconfiguration scanner's: its Terraform checks download the module sources a
#: .tf file names, online and offline alike. Offline ASH leaves those checks out
#: (``TrivyScannerBase._offline_misconfig_args``); online they run as trivy's own
#: defaults, so an online ``misconfig`` scan can reach registry.terraform.io, git
#: and the archive URLs the scanned repository's modules name.
SCAN_FLAGS = ("--offline-scan",)

#: The flag an online scan gets so trivy does not check for a new version. Without
#: it trivy asks check.trivy.dev about new versions and announcements (measured
#: through a proxy on 127.0.0.1, online), which a scan has no use for. Offline the
#: same check is turned off by ``TRIVY_SKIP_VERSION_CHECK`` in the environment
#: instead (``utils/offline_tool_env.py``, applied by ``PluginBase._run_subprocess``):
#: a trivy too old to know the flag refuses the whole command over it, and ignores
#: the variable.
ONLINE_FLAGS = ("--skip-version-check",)

#: The flags that skip trivy's own updates offline. ``trivy --skip-db-update`` makes trivy
#: use whatever vulnerability database is in its cache, of any age; ASH's scan-time
#: staleness check (``utils/content_db_staleness.py``) is what holds that database
#: to its declared bound.
OFFLINE_FLAGS = (
    "--skip-db-update",
    "--skip-java-db-update",
    "--skip-check-update",
)


#: ``trivy --timeout`` when ASH's ``scan_timeout`` is null (unbounded). trivy has no
#: value that means "no deadline": measured with 0.75.0, ``trivy --timeout=0s`` is a
#: deadline that has already passed, and a scan that analyzes files one at a time
#: (secret scanning, OS packages) exits 1 with "context deadline exceeded". This is
#: the largest whole number of hours a Go duration holds, about 292 years; one hour
#: more is refused as an invalid duration.
UNBOUNDED_TRIVY_TIMEOUT = "2562047h"

#: The same bound in seconds: a Go duration holds at most 2**63 - 1 nanoseconds,
#: so a ``--timeout`` of more whole seconds than this is refused as an invalid
#: duration and trivy exits 1 before it scans anything.
_MAX_GO_DURATION_SECONDS = (2**63 - 1) // 1_000_000_000


def trivy_timeout(seconds: Optional[float]) -> str:
    """ASH's scan timeout in seconds, or None for unbounded, as trivy's ``--timeout``.

    Rounded up to a whole second and never below one, so a bound is never ``0s``.
    trivy's own default deadline is five minutes, and a scan that passes it exits
    1 with "context deadline exceeded", so ``trivy`` and ``trivy-repo`` both pass
    the bound the operator set (``scan_timeout``) as trivy's. A bound past what a
    Go duration can hold is passed as the unbounded value instead: trivy would
    refuse the number as an invalid duration, and a deadline of 292 years is no
    deadline either way. So is a bound that is not a finite number (infinity, or
    not a number at all), which ``math.ceil`` would raise on before the bound
    above was ever compared.
    """
    if seconds is None or not math.isfinite(seconds):
        return UNBOUNDED_TRIVY_TIMEOUT
    whole = max(1, math.ceil(seconds))
    if whole > _MAX_GO_DURATION_SECONDS:
        return UNBOUNDED_TRIVY_TIMEOUT
    return f"{whole}s"


#: The trivy misconfiguration scanner that downloads the module sources a .tf file
#: names. See TrivyScannerBase._offline_misconfig_args.
_TERRAFORM_MISCONFIG_SCANNER = "terraform"

#: What trivy runs when nothing names its scanners: no ``--scanners`` flag, no
#: ``TRIVY_SCANNERS`` and no ``scan.scanners`` in its config file (pkg/flag/scan_flags.go,
#: trivy 0.75.0). See TrivyScannerBase._effective_scanners.
_TRIVY_DEFAULT_SCANNERS = ("vuln", "secret")

#: The other spellings trivy reads a scanner name in, and the name each means
#: (the value normalization of trivy's ``scanners`` flag definition; ``config`` is
#: the deprecated name of ``misconfig``). trivy applies it to ``--scanners``,
#: ``TRIVY_SCANNERS`` and ``scan.scanners`` alike, so a membership test on
#: ``_effective_scanners`` has to see the canonical name.
_TRIVY_SCANNER_ALIASES = {
    "vulnerability": "vuln",
    "misconf": "misconfig",
    "misconfiguration": "misconfig",
    "config": "misconfig",
}


def _split_list_string(value: str) -> List[str]:
    """``value`` split as trivy splits a list setting given as one string.

    A value that holds a comma is split on commas alone, one with no comma on
    whitespace; the two splits are never combined, and the entries are not trimmed
    (trivy's own rule, see ``TrivyScannerBase._environment_list``). The environment
    and the config file pass through the same conversion, so both use this.
    """
    return value.split(",") if "," in value else value.split()


#: trivy's severities that ASH reports as the same name. trivy's fifth, UNKNOWN,
#: is left to ASH's generic SARIF mapping.
TRIVY_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

#: The SARIF level trivy gives a result of each severity (``toSarifErrorLevel``).
_SARIF_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

#: ``_SARIF_LEVEL`` with trivy's fifth severity: ``toSarifErrorLevel`` gives
#: UNKNOWN the ``note`` level, LOW's. Read against a message's ``Severity:`` lines
#: (``trivy_severity``), so a line trivy wrote for an UNKNOWN rating still reads as
#: trivy's own, and the result is left to ASH's generic mapping as before.
_MESSAGE_LEVEL = {**_SARIF_LEVEL, "UNKNOWN": "note"}

#: trivy's severities from the highest down, UNKNOWN last. Between two
#: ``Severity:`` lines of one level, ``trivy_severity`` reads the higher.
_SEVERITY_ORDER = (*TRIVY_SEVERITIES, "UNKNOWN")

#: Characters ``trivy --skip-dirs`` reads as glob syntax.
_GLOB_SPECIAL = frozenset("*?[]{}\\")

#: The most bytes the ``--skip-files`` and ``--skip-dirs`` tokens for the ignored
#: paths may take together, and the whole budget where the host's own bound is not
#: read. Linux starts a program with about 2 MiB of arguments and environment
#: (ARG_MAX), so the ignore paths of a large tree, one token each, could otherwise
#: keep trivy from starting at all. ``skip_args_budget`` reads the host's bound
#: where it can and never answers more than this.
_SKIP_ARGS_BUDGET = 1_000_000

#: The budget on Windows, where CreateProcess holds the whole command line to
#: 32,767 characters and the rest of the argv needs its share. Nothing reaches it
#: today: ``trivy_skip_dirs`` and ``trivy_skip_files`` return no values when
#: ``os.sep`` is not ``/``, so no skip token is built there. It bounds the tokens
#: should that change.
_WINDOWS_SKIP_ARGS_BUDGET = 30_000

#: The least the budget is cut to, so a host with a very large environment still
#: gets the first ignored paths as skip flags.
_SKIP_ARGS_FLOOR = 16_384


def skip_args_budget(environment: Mapping[str, str]) -> int:
    """How many bytes the skip tokens for the ignored paths may take on this host.

    Windows: ``_WINDOWS_SKIP_ARGS_BUDGET`` (no skip token is built there today, see
    its comment, so this branch bounds nothing yet). Elsewhere half of the host's
    ARG_MAX
    (``os.sysconf``; about 2 MiB on Linux, about 1 MiB on macOS, where it covers
    the arguments, the environment and their pointers together) less the bytes
    ``environment`` takes, floored at ``_SKIP_ARGS_FLOOR`` and never above
    ``_SKIP_ARGS_BUDGET``; the ceiling alone where the host does not answer. One
    figure sized for Linux still kept trivy from starting on the other two.
    """
    if sys.platform == "win32":
        return _WINDOWS_SKIP_ARGS_BUDGET
    try:
        arg_max = int(os.sysconf("SC_ARG_MAX"))
    except (AttributeError, OSError, ValueError):
        return _SKIP_ARGS_BUDGET
    if arg_max <= 0:
        return _SKIP_ARGS_BUDGET
    environment_size = sum(
        len(os.fsencode(key)) + len(os.fsencode(value)) + 2
        for key, value in environment.items()
    )
    return max(
        _SKIP_ARGS_FLOOR, min(_SKIP_ARGS_BUDGET, arg_max // 2 - environment_size)
    )


#: Settings in trivy's environment that remove results from its report with
#: nothing in the run saying so, each the TRIVY_ form of a trivy flag: --severity,
#: --ignore-unfixed, --ignore-status, --ignore-policy, --skip-dirs, --skip-files,
#: --vex, --pkg-types (``os`` drops every library finding), --pkg-relationships
#: (``direct`` drops the transitive ones) and --ignored-licenses (pkg/flag, trivy
#: 0.75.0: every flag reads TRIVY_<FLAG> with the dashes as underscores). The
#: sandbox passes every TRIVY_ variable through (env_prefixes), so the operator's
#: filters apply to the scan; the scan names the variables it saw, never their
#: values. TRIVY_EXIT_CODE is pinned by --exit-code=0, so it is not here.
#: TRIVY_IGNOREFILE is not here for another reason: ASH reads it itself and passes
#: the file as --ignorefile only when it is honored (outside the scanned tree), so
#: its warning is given there (``_trivy_input_file``), where a refused value, which
#: restricts nothing, is not warned about.
OUTPUT_RESTRICTING_TRIVY_ENV = (
    "TRIVY_SEVERITY",
    "TRIVY_IGNORE_UNFIXED",
    "TRIVY_IGNORE_STATUS",
    "TRIVY_IGNORE_POLICY",
    "TRIVY_SKIP_DIRS",
    "TRIVY_SKIP_FILES",
    "TRIVY_VEX",
    "TRIVY_PKG_TYPES",
    "TRIVY_PKG_RELATIONSHIPS",
    "TRIVY_IGNORED_LICENSES",
)

#: The spellings Go's strconv.ParseBool reads as false, lowercased. A boolean
#: filtering variable set to one of them turns its filter off and restricts
#: nothing.
_FALSE_SPELLINGS = frozenset({"0", "f", "false"})

#: The filtering variables trivy reads as booleans, the only ones a spelling of
#: false turns off. The others are lists and paths, which trivy reads literally:
#: ``TRIVY_SKIP_DIRS=0`` skips a directory named ``0``.
_BOOLEAN_FILTER_VARIABLES = frozenset({"TRIVY_IGNORE_UNFIXED"})


def _restricting_value(name: str, value: Optional[str]) -> bool:
    """Whether ``value``, the filtering TRIVY_ variable ``name``'s, turns its filter on.

    Set and not blank; for a boolean variable, also not a spelling of false:
    ``TRIVY_IGNORE_UNFIXED=false`` is the default written out, and warning about
    it would train a reader to ignore the warning, as grype's config-key warning
    reads a falsy key. A list or path variable has no false spelling: ``0`` and
    ``false`` are values trivy matches literally.
    """
    if value is None:
        return False
    text = value.strip()
    if not text:
        return False
    if name in _BOOLEAN_FILTER_VARIABLES:
        return text.lower() not in _FALSE_SPELLINGS
    return True


def skip_dirs_value(path: str) -> str:
    """*path* as a ``--skip-dirs`` value trivy matches literally.

    trivy reads the value as a comma-separated list (CSV, so quotes group) of
    globs. Measured on 0.69.3: an unescaped ``a,b`` or ``x[1]`` left that directory
    scanned. Glob characters are backslash-escaped, then the value is CSV-quoted
    when it holds a comma, a quote or edge whitespace.
    """
    escaped = "".join("\\" + ch if ch in _GLOB_SPECIAL else ch for ch in path)
    return _csv_field(escaped)


def _csv_field(value: str) -> str:
    """``value`` as one field of the CSV trivy reads a list flag as.

    Quoted, with its quotes doubled, when it holds a comma, a double quote or
    edge whitespace; otherwise as written. Glob characters are left alone: the
    operator's own ``--skip-dirs`` entries are globs by intent, and
    ``skip_dirs_value`` escapes ASH's before it calls this. An unquoted ``"``
    is a bare-quote parse error that fails the whole trivy run.
    """
    if any(ch in value for ch in ',"') or value != value.strip():
        return '"' + value.replace('"', '""') + '"'
    return value


def trivy_severity(
    result: Any, rules: List[Any], by_id: Dict[str, Any]
) -> Optional[str]:
    """trivy's severity for *result*: its message's ``Severity:`` line, else its rule's tag.

    trivy writes the message as fixed lines around text from the scanned tree: the
    file's path (``Artifact:``) and the package name (``Package:``) come before
    its own ``Severity:`` line, and for a misconfiguration or secret finding the
    check's message (``Message:``, which quotes names from the manifest) and the
    matched text itself (``Match:``) come after it. Any of these can hold a line
    break followed by the prefix, so neither the first nor the last such line is
    trivy's by its position alone. What the tree cannot write is the result's
    SARIF ``level``, which trivy sets from the same severity (``_SARIF_LEVEL``,
    its ``toSarifErrorLevel``): the severity read is the highest ``Severity:``
    line whose level is the result's, a line that disagrees is tree text, and a
    message with no agreeing line falls through to the rule's tag. Within one
    level (CRITICAL and HIGH both read as ``error``; LOW and UNKNOWN both
    ``note``) the level cannot tell trivy's line from the tree's, so the higher
    name is read: a line the tree writes can raise the rating by one step inside
    trivy's own level and never lower it, and a result with no level at all
    (none of its lines can be checked) is read the same way. The lines are split
    on ``\\n`` alone, the separator trivy writes: ``str.splitlines`` also breaks
    on characters a file name or a matched line can hold (a carriage return, a
    form feed, a next-line or line-separator character), which would let
    tree-derived text supply the line.

    A result trivy rates UNKNOWN (a line agreeing with its ``note`` level) is left
    to ASH's generic mapping. A result with no severity line of its own takes its
    rule's single severity tag, and only when the result's own SARIF level agrees
    with it; see the builtin trivy scanner's module docstring, "Severity".
    """
    message = result.message.root.text if result.message else None
    level = getattr(result.level, "value", result.level)
    agreeing = set()
    for line in (message or "").split("\n"):
        if not line.startswith("Severity: "):
            continue
        named = line[len("Severity: ") :].strip()
        if named not in _MESSAGE_LEVEL:
            continue
        if level is None or _MESSAGE_LEVEL[named] == level:
            agreeing.add(named)
    for own in _SEVERITY_ORDER:
        if own in agreeing:
            return own if own in TRIVY_SEVERITIES else None
    rule = None
    if result.ruleIndex is not None and 0 <= result.ruleIndex < len(rules):
        rule = rules[result.ruleIndex]
    if rule is None or (result.ruleId and rule.id != result.ruleId):
        rule = by_id.get(result.ruleId)
    if rule is None or rule.properties is None:
        return None
    tags = getattr(rule.properties, "tags", None) or []
    found = [tag for tag in tags if tag in TRIVY_SEVERITIES]
    # Exactly one, or no rating: two severity tags would be a shape trivy
    # does not write, and guessing between them could under-rate a finding.
    if len(found) != 1:
        return None
    # The tag is the rating of the last result trivy wrote for the rule. A
    # result whose own level differs is rated otherwise, and is left to the
    # generic mapping rather than given another package's severity.
    if level is not None and level != _SARIF_LEVEL[found[0]]:
        return None
    return found[0]


_DEFAULT_MISCONFIG_SCANNERS: Dict[tuple[Any, ...], Optional[List[str]]] = {}
_DEFAULT_MISCONFIG_SCANNERS_LOCK = threading.Lock()


def _binary_identity(binary: str) -> str:
    """``binary``'s size and modification time, or "" when it cannot be stat'ed.

    What tells one release installed at a path from the next installed at the
    same path, for the per-binary caches here.
    """
    try:
        status = os.stat(binary)
    except (OSError, TypeError, ValueError):
        return ""
    return f"{status.st_size}:{status.st_mtime_ns}"


def reset_trivy_default_misconfig_scanners() -> None:
    """Forget the lists trivy_default_misconfig_scanners read (tests)."""
    with _DEFAULT_MISCONFIG_SCANNERS_LOCK:
        _DEFAULT_MISCONFIG_SCANNERS.clear()


def trivy_default_misconfig_scanners(
    binary: str, subcommands: List[str]
) -> Optional[List[str]]:
    """trivy's default ``--misconfig-scanners`` list, as the installed trivy prints it.

    Read from ``<binary> <subcommands> --help`` (the "(default [...])" of that flag)
    rather than written down here, because the list differs between trivy releases
    and trivy given a value it does not know runs every misconfiguration scanner
    instead (measured with trivy 0.74.0). None when the list cannot be read. A list
    that was read is kept per binary and subcommand; a failed read is not, so the next
    scan tries again rather than every later scan in the process (a long-running MCP
    server, a workspace's projects) leaving out every misconfiguration check.

    The binary is keyed by its path together with its size and modification time,
    so a trivy replaced in place (an upgrade under the same path) is read again:
    kept by the path alone, a long-running process would pass the old release's
    names to the new one, and a name trivy does not know makes it run every
    misconfiguration scanner, the Terraform checks included. A binary that cannot
    be stat'ed is keyed by its path alone.
    """
    key = (binary, _binary_identity(binary), *subcommands)
    with _DEFAULT_MISCONFIG_SCANNERS_LOCK:
        if key in _DEFAULT_MISCONFIG_SCANNERS:
            return _DEFAULT_MISCONFIG_SCANNERS[key]
    try:
        result = subprocess_utils.run_command(
            [binary, *subcommands, "--help"],
            capture_output=True,
            text=True,
            timeout=60,
            log_level=logging.DEBUG,
        )
        text = f"{result.stdout or ''}\n{result.stderr or ''}"
    except Exception as error:  # the list is unknown; the caller fails closed
        ASH_LOGGER.debug(
            f"Could not run {binary} {' '.join(subcommands)} --help: {error}"
        )
        text = ""
    match = re.search(r"--misconfig-scanners\b[^\n]*?\(default \[([^\]]*)\]\)", text)
    listed = (
        [name.strip() for name in match.group(1).split(",") if name.strip()]
        if match
        else None
    )
    listed = listed or None
    if listed is not None:
        with _DEFAULT_MISCONFIG_SCANNERS_LOCK:
            _DEFAULT_MISCONFIG_SCANNERS[key] = listed
    return listed


def _known_scanner_names(
    names: List[str], known: List[str]
) -> Tuple[List[str], List[str]]:
    """``names`` split into the ones ``known`` holds, in its spelling and without
    repeats, and the ones it does not.

    Matched case-insensitively, since a name trivy does not know (``Terraform``)
    makes it run every misconfiguration scanner rather than none; the spelling
    passed on is trivy's own.
    """
    by_lower = {name.lower(): name for name in known}
    chosen: List[str] = []
    unknown: List[str] = []
    for name in names:
        canonical = by_lower.get(name.lower())
        if canonical is None:
            unknown.append(name)
        elif canonical not in chosen:
            chosen.append(canonical)
    return chosen, unknown


def _same_package(entry: Any, name: str | None, version: str | None) -> bool:
    """Whether the lockfile ``entry`` is the package a result names.

    The names have to match. The versions have to match when both the entry and
    the result state one; a lockfile entry without a version (a link, a
    workspace member) is matched by name alone.

    ``entry`` is a ``utils.package_identity.NpmLockEntry``, whose ``name`` is the
    package's own name (an npm alias is named by the lockfile's ``name`` field,
    not by its ``node_modules`` path). The attributes are read plainly: an entry
    that lacks one is a schema change and raises, where a default of ``None``
    answered "no match" for every result and dropped ``package_path`` and the
    per-copy split without a sign.
    """
    if entry.name != name:
        return False
    entry_version = entry.version
    if entry_version is None or version is None:
        return True
    return entry_version == version


def _existing_file(key: str, value: Any, path: Path, show_value: bool = False) -> str:
    """``path`` as trivy is given it; a configured file that is missing fails.

    The refusal names ``key`` only unless ``show_value``: an option key, or an
    environment variable such as TRIVY_IGNOREFILE, whose value the scanner also
    redacts from every record, is never printed (config/path_trust.py: a value
    the environment chose is never printed). With ``show_value`` the value is
    quoted with ``repr`` and the resolved path with its control characters
    escaped, so a line break in either cannot forge a log line; TRIVY_CONFIG,
    the operator's config path, is shown that way, as its tests pin.
    """
    if not path.is_file():
        if show_value:
            raise ScannerError(
                f"{key} is {str(value)!r}, which is not a file (resolved to "
                f"{escape_controls(path.as_posix())}). Fix the path or unset "
                "it; trivy is not run without it."
            )
        raise ScannerError(
            f"{key} does not name a file: the path it is set to does not "
            "exist or is not a file. Fix the path or unset it; trivy is not "
            "run without it."
        )
    return path.as_posix()


class TrivyScannerBase(ScannerPluginBase[C], Generic[C]):
    """Shared trivy behaviour. Not registered: only its subclasses are scanners."""

    # Both subclasses run the same binary against the same vulnerability database,
    # and read TRIVY_* settings.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements(
        network=True,
        # Every place content_db_refresh.default_cache_dir can put trivy's cache:
        # ~/.cache or XDG_CACHE_HOME on Linux, ~/Library/Caches on macOS,
        # TRIVY_CACHE_DIR, and $TMPDIR/trivy, Go's os.TempDir fallback when
        # XDG_CACHE_HOME is set to a relative path (with TMPDIR unset that
        # fallback is /tmp/trivy, which the sandbox's own temporary directory
        # covers). Caches rather than read paths: a cache is read-only on
        # every backend but bwrap, whose overlay throws writes away, and
        # sandbox-exec runs no program from one, where it runs programs from read
        # paths. The database is updated outside the sandbox before an online scan
        # (utils/content_db_refresh.py), and trivy only reads it. The sandbox
        # expands these against ASH's own environment and mounts absolute paths
        # only (sandbox/policy._expand), while _trivy_cache_dir makes a relative
        # TRIVY_CACHE_DIR absolute against ASH's working directory for --cache-dir:
        # a relative value is therefore pointed at by the scan and not mounted,
        # which only the policy's expansion can close.
        cache_paths=(
            "~/.cache/trivy",
            "~/Library/Caches/trivy",
            "$XDG_CACHE_HOME/trivy",
            "$TRIVY_CACHE_DIR",
            "$TMPDIR/trivy",
        ),
        env_prefixes=("TRIVY_",),
    )

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.CACHE_FLAGS

    # Env vars ASH layers onto trivy's subprocess, kept on the instance so
    # concurrent scanners do not race on os.environ. Nothing fills it from config;
    # the cache directory comes from the host's environment only (_trivy_cache_dir).
    extra_env: Annotated[Dict[str, str], Field(default_factory=dict)]

    # The in-tree trivy input files already reported as ignored.
    _warned_inputs: Set[str] = PrivateAttr(default_factory=set)

    # The cache directory a scan is pointed at (--cache-dir) is kept in the base
    # class's _content_db_cache_dir, so the staleness probe reads the same one
    # (content_database_probe_context). The --config file the last scan passed
    # trivy (_trivy_config_file) is kept for the same reason: a trivy.yaml can name
    # the cache (``cache.dir``).
    _scan_config_file: Optional[str] = PrivateAttr(default=None)

    def _environment_values(self) -> Tuple[str, ...]:
        """The configuration's environment values, plus the two input-file variables
        both trivy scanners read straight from the environment (never through the
        configuration), so text that quotes one is redacted.

        ``TRIVY_IGNOREFILE`` and ``TRIVY_SECRET_CONFIG``. ``TRIVY_CONFIG`` is left
        out on purpose: its value is the operator's config path and is shown,
        escaped, in the refusal that names it (``_existing_file``), as its tests pin.
        """
        read = (
            os.environ.get("TRIVY_IGNOREFILE"),
            os.environ.get("TRIVY_SECRET_CONFIG"),
        )
        return (*super()._environment_values(), *(value for value in read if value))

    def validate_plugin_dependencies(self) -> bool:
        """The binary, and offline, a vulnerability database for it to read.

        The base check first (``ScannerPluginBase.validate_plugin_dependencies``:
        the binary on PATH, and the recorded reason when a copy inside the scanned
        tree was refused, so the MISSING row says so rather than "not installed").
        Then, offline, for a scan whose effective scanners read the vulnerability
        database: trivy refuses ``--skip-db-update`` when its cache holds no
        database ("cannot be specified on the first run"), so such a scan is
        reported MISSING with the reason before trivy runs, rather than as a tool
        error. Shared by ``trivy`` and ``trivy-repo``.
        """
        if not super().validate_plugin_dependencies():
            return False
        return self._offline_database_available()

    def _offline_database_available(self) -> bool:
        """Offline, whether trivy's cache holds a database for a scan that reads it.

        True online, and for a scan whose scanners never open the database. A
        failed probe records the reason (``dependency_unavailable_reason``) and
        answers False, so the scanner lands as MISSING with it.
        """
        if not (self._offline() and self._reads_vulnerability_db()):
            return True
        from automated_security_helper.utils.content_db_staleness import (
            _built_from_trivy,
        )

        try:
            _built_from_trivy(self.content_database_probe_context())
        except Exception as exc:  # noqa: BLE001 - every failure means "no usable database"
            self.dependency_unavailable_reason = (
                "trivy is in offline mode and has no vulnerability database to read "
                f"({exc}). Download one with network access (`trivy image "
                "--download-db-only`, with TRIVY_CACHE_DIR set to the cache this scan "
                "uses), or turn offline mode off."
            )
            self._plugin_log(self.dependency_unavailable_reason, level=logging.WARNING)
            return False
        return True

    def _reads_vulnerability_db(self) -> bool:
        """Whether this scan opens trivy's vulnerability database: ``vuln`` is among
        the scanners trivy will run (``_effective_scanners``, which before the
        first scan reads the operator's config file as the scan will)."""
        return "vuln" in self._effective_scanners()

    def _refuse_flagged_response(self, response: Any, timeout: float | None) -> None:
        """Raise for a run the subprocess layer flagged, before its file is read.

        For a ``scan()`` override that runs one tool per target (``trivy-repo``):
        the four readings ``ScannerPluginBase.scan`` makes for every template
        scanner. A killed tool writes no results file, so the error would otherwise
        be "No such file or directory" instead of the timeout; a tool that could
        not start the same; a tool that ran while ASH could not record its output
        (exit 0, a file that may be complete) is not graded on that file; a tool a
        signal ASH did not send ended did not finish. The exit code alone does not
        say any of this: a flagged response keeps the tool's own code, 0 included.
        """
        if not isinstance(response, dict):
            return
        name = self.__class__.__name__
        if response.get("timed_out"):
            limit = self._timeout_limit_token(timeout)
            if self.scan_could_not_stop is not None:
                ending = f"{COULD_NOT_STOP_ENDING}. It produced no"
            else:
                ending = f"{WAS_KILLED_ENDING}, so it produced no"
            raise ScannerError(
                text_without_values(
                    f"{name} timed out after {limit}{ending} results file. Raise "
                    f"scanners.{getattr(self.config, 'name', '<scanner>')}.options"
                    ".scan_timeout if this target legitimately needs longer, or set "
                    "it to null to leave this scanner unbounded.",
                    self._values_to_redact(),
                )
            )
        if response.get("spawn_failed"):
            raise ScannerError(
                f"{name} could not start its tool, so it produced no results file."
            )
        if response.get("post_run_error"):
            raise ScannerError(
                text_without_values(
                    f"{name} ran, but ASH could not record the scanner's output: "
                    f"{response.get('error')}",
                    self._values_to_redact(),
                )
            )
        if response.get("signaled"):
            raise ScannerError(
                text_without_values(
                    f"{name} did not finish: {response.get('error')}",
                    self._values_to_redact(),
                )
            )

    def _trivy_cache_dir(self) -> Path:
        """trivy's cache directory, resolved as trivy resolves it on this host.

        ``content_db_refresh.default_cache_dir`` (``TRIVY_CACHE_DIR``, else
        ``XDG_CACHE_HOME`` on Linux, else the platform default), from the host's
        environment only: the database update runs unsandboxed, so nothing a
        scanner layers on (``extra_env``) may choose where it writes, and the scan
        and the probe read where the update wrote. Named to every scan, online and
        offline (``_run_subprocess``), and to the staleness probe: the sandbox does
        not pass ``XDG_CACHE_HOME``, and a sandboxed trivy left to its own default
        would read another cache.
        """
        return Path(os.path.abspath(default_cache_dir("trivy", snapshot_environ())))

    def _trivy_config_file(self) -> str:
        """The trivy config file a scan passes as ``--config``, online and offline.

        Without the flag trivy reads ``trivy.yaml`` from its working directory, the
        scanned repository. A ``trivy.yaml`` there can drop findings with nothing in
        the report saying so (``severity``, ``scan.skip-files``), load WASM modules
        (``module.dir``), and turn on a VEX repository download or client/server
        mode, both of which reach the network whatever offline flags ASH passes
        (measured with trivy 0.75.0). So trivy always gets ``--config``:

        1. ``options.config_file``, when ``_operator_path`` accepts it;
        2. otherwise ``TRIVY_CONFIG``, which is the operator's environment, for a
           file outside the scanned tree (``config/path_trust.honored_path``); a
           relative path in it is taken from the working directory ASH runs in;
        3. otherwise ``EMPTY_TOOL_CONFIG``, the empty config ASH ships, which every
           sandbox backend mounts read-only and no scanner can write.

        A path from 1 or 2 that is not a file fails the scan. The choice is kept for
        the staleness probe (``content_database_probe_context``), and the database
        update reads through the same file (``_shared_update_flags``).
        """
        chosen = self._operator_config_choice()
        if chosen is not None:
            key, value, path = chosen
            # TRIVY_CONFIG's value is the operator's config path and is shown, escaped; the
            # options.config_file refusal stays key-only like the other option refusals.
            self._scan_config_file = _existing_file(
                key, value, path, show_value=(key == "TRIVY_CONFIG")
            )
            return self._scan_config_file
        if self.context is not None:
            in_tree = Path(self.context.source_dir) / "trivy.yaml"
            if in_tree.is_file() and in_tree.as_posix() not in self._warned_inputs:
                self._warned_inputs.add(in_tree.as_posix())
                name = self.config.name if self.config is not None else "trivy"
                self._plugin_log(
                    f"Ignoring {in_tree.as_posix()}: it is inside the scanned tree, "
                    "and its settings can reach the network or change what is "
                    f"reported. Set scanners.{name}.options.config_file or "
                    "TRIVY_CONFIG to a file outside the tree to use one.",
                    level=logging.WARNING,
                )
        self._scan_config_file = EMPTY_TOOL_CONFIG.as_posix()
        return self._scan_config_file

    def _operator_config_choice(self) -> Optional[tuple[str, Any, Path]]:
        """The operator's trivy config, as (where it was set, its value, its path).

        ``options.config_file`` when ``_operator_path`` accepts it, else
        ``TRIVY_CONFIG`` when ``honored_path`` does; None when neither names one.
        Whether the file exists is the caller's question.
        """
        if self.context is None:
            raise ScannerError(f"{self.__class__.__name__} has no plugin context")
        name = self.config.name if self.config is not None else "trivy"
        options = getattr(self.config, "options", None)
        value = getattr(options, "config_file", None)
        if value:
            path = self._operator_path(
                "config_file",
                value,
                "trivy gets TRIVY_CONFIG, if set, or ASH's empty config instead.",
            )
            if path is not None:
                return f"scanners.{name}.options.config_file", value, path
        # The variable is the operator's, set where ASH runs, so a relative path in
        # it is taken from the working directory as written, as TRIVY_IGNOREFILE's
        # is (_trivy_input_file), not from the scanned directory. The value is
        # quoted as set.
        variable = os.environ.get("TRIVY_CONFIG")
        from_env = self._environment_path(variable, "TRIVY_CONFIG")
        if from_env:
            path = honored_path(
                from_env,
                source_dir=Path(self.context.source_dir),
                key="TRIVY_CONFIG",
                config=getattr(self.context, "config", None),
                # The environment is the operator's own write, as for the input
                # files (_trivy_input_file).
                operator_written=True,
            )
            if path is not None:
                return "TRIVY_CONFIG", variable, path
        return None

    def _environment_path(self, value: Any, env: str) -> Any:
        """``value``, the operator's environment variable ``env``, as a path.

        A relative value is joined to the working directory ASH runs in
        (``config/operator_paths.anchored_environment_path``). The working
        directory is read only then: a value that is unset, absolute or starts
        with ``~`` needs no anchor, so a working directory that was deleted does
        not fail the scan's configuration for it. When the anchor is needed and
        the working directory cannot be read, the variable is ignored with a
        warning that names it (never its value, which the environment chose),
        and the caller's fallback stands.
        """
        if (
            not isinstance(value, str)
            or not value.strip()
            or value.startswith("~")
            or os.path.isabs(value)
        ):
            return anchored_environment_path(value, Path("."))
        try:
            cwd = Path.cwd()
        except OSError:
            refusal = f"{env}=relative:no-cwd"
            if refusal not in self._warned_inputs:
                self._warned_inputs.add(refusal)
                self._plugin_log(
                    f"Ignoring {env}: it names a relative path, and the working "
                    "directory ASH runs in cannot be read (it may have been "
                    "deleted), so the path cannot be resolved from it. Set the "
                    "variable to an absolute path.",
                    level=logging.WARNING,
                )
            return None
        return anchored_environment_path(value, cwd)

    def _effective_scanners(self, final_args: Optional[List[str]] = None) -> List[str]:
        """The trivy scanners this run turns on, as trivy will read them.

        ``options.scanners`` when it names any: ASH passes it as ``--scanners``, which
        trivy puts above every other source. With an empty list ASH passes no flag
        and trivy decides for itself, in its order: ``TRIVY_SCANNERS`` in its
        environment (the scan's, ``extra_env`` included), then ``scan.scanners`` in
        the config file the run passes as ``--config`` (read from ``final_args``
        when given, else the file this scanner chose), then trivy's own default,
        ``vuln`` and ``secret``. The offline Terraform-check removal and the
        checks-bundle update read this rather than the option alone, so a trivy
        setting that turns ``misconfig`` on gets the same handling as the option.
        A config file that cannot be read or parsed counts as setting nothing.

        Each name is returned as trivy reads it: ``config`` is ``misconfig``
        (``_TRIVY_SCANNER_ALIASES``), so a set written with the old name is still
        seen to turn the checks on.
        """
        options: Any = self.config.options  # type: ignore[union-attr]
        chosen = [name for name in (options.scanners or []) if name]
        if chosen:
            return self._canonical_scanners(chosen)
        from_env = self._environment_list("TRIVY_SCANNERS")
        if from_env:
            return self._canonical_scanners(from_env)
        names = self._config_file_list(final_args, "scan", "scanners")
        if names:
            return self._canonical_scanners(names)
        return list(_TRIVY_DEFAULT_SCANNERS)

    @staticmethod
    def _canonical_scanners(names: List[str]) -> List[str]:
        """``names`` with each alias trivy accepts replaced by the name it means."""
        return [_TRIVY_SCANNER_ALIASES.get(name, name) for name in names]

    def _scan_environment(self) -> Dict[str, str]:
        """The environment the scan runs with: the host's plus ``extra_env``."""
        return {**snapshot_environ(), **self.extra_env}

    def _config_file_list(
        self, final_args: Optional[List[str]], section: str, key: str
    ) -> List[str]:
        """``section.key`` of the trivy config file the run passes as ``--config``,
        as a list of names; empty when unset or unreadable.

        The file is read from ``final_args`` when given, else the one this scanner
        chose (``_scan_config_file``), else, before the first scan has chosen one,
        the operator's config file when it is honored and exists
        (``_operator_config_file``), as the staleness probe reads it
        (``content_database_probe_context``). Without that last step the offline
        dependency check, which runs before any scan, judged trivy's default
        scanners for a scan whose ``scan.scanners`` sends it elsewhere. trivy
        reads a list setting as a YAML list or as one string split the way it
        splits an environment variable (``_split_list_string``). A file
        that cannot be read or parsed, including one that is not UTF-8 (a
        ``UnicodeDecodeError`` is a ``ValueError``), counts as setting nothing.
        """
        config_file: Optional[str] = None
        for argument in final_args or []:
            if argument.startswith("--config="):
                config_file = argument[len("--config=") :]
        if config_file is None:
            config_file = self._scan_config_file or self._operator_config_file()
        if not config_file:
            return []
        try:
            with open(config_file, "r", encoding="utf-8") as handle:
                document = yaml.safe_load(handle)
        except (OSError, ValueError, yaml.YAMLError):
            return []
        table = document.get(section) if isinstance(document, dict) else None
        listed = table.get(key) if isinstance(table, dict) else None
        if isinstance(listed, str):
            listed = _split_list_string(listed)
        if not isinstance(listed, list):
            return []
        return [str(name).strip() for name in listed if str(name).strip()]

    def _environment_list(self, name: str) -> List[str]:
        """``name`` in the scan's environment as trivy reads a list flag from it.

        This copies trivy's own rule (``Flag.cast`` for a string-list flag, in
        trivy's ``pkg/flag/options`` source, the same at v0.69.3 and v0.75.0): a
        value that holds a comma is split on commas alone, and the entries are not
        trimmed, so ``"vendor,build dir"`` is ``vendor`` and ``build dir`` and
        ``"vendor, build"`` is ``vendor`` and `` build``; a value with no comma is
        split on whitespace, so ``"terraform dockerfile"`` is two names. The two
        splits are never combined. ASH passes these lists back as explicit flags
        (``_operator_skip_args``), which replace the variable, so a looser reading
        here would skip paths the operator's own trivy would not. The one
        departure is an entry with no characters at all (``"a,,b"``, a trailing
        comma), which names no path or scanner and is dropped. Empty when unset or
        blank.
        """
        value = self._scan_environment().get(name)
        if not value or not value.strip():
            return []
        return [entry for entry in _split_list_string(value) if entry]

    def _attach_trivy_severity(self, sarif_report: SarifReport) -> SarifReport:
        """Give each result trivy's own severity as its ASH severity.

        trivy rates each result itself (CRITICAL, HIGH, MEDIUM, LOW), per result:
        one CVE can be rated differently for two packages in one scan, and the
        rule's tag and ``security-severity`` carry the last result's. Without
        this ASH buckets the rule's CVSS score, so a finding trivy rates HIGH
        with a 6.5 score reads MEDIUM. See the builtin trivy scanner's module
        docstring, "Severity", and ``trivy_severity``.
        """
        for run in sarif_report.runs or []:
            rules = (
                (run.tool.driver.rules or []) if run.tool and run.tool.driver else []
            )
            by_id = {rule.id: rule for rule in rules}
            for result in run.results or []:
                severity = trivy_severity(result, rules, by_id)
                if severity is None:
                    continue
                if result.properties is None:
                    result.properties = PropertyBag()
                setattr(result.properties, "issue_severity", severity)  # noqa: B010
        return sarif_report

    def _ignore_file(self) -> str:
        """The file trivy reads finding IDs to ignore from (``--ignorefile``)."""
        return self._trivy_input_file(
            option="ignore_file",
            env="TRIVY_IGNOREFILE",
            default_name=".trivyignore",
            ash_name="trivyignore-empty",
            ash_content="",
        )

    def _secret_config_file(self, final_args: Optional[List[str]] = None) -> str:
        """The file trivy reads secret rules from (``--secret-config``).

        Only a scan that runs the ``secret`` scanner reads it, so a configured or
        environment-named file that is missing fails only such a scan
        (``required``); a vulnerability-only scan gets ASH's empty file with a
        warning instead of failing over a file trivy would never open.
        """
        return self._trivy_input_file(
            option="secret_config_file",
            env="TRIVY_SECRET_CONFIG",
            default_name="trivy-secret.yaml",
            ash_name="trivy-secret-empty.yaml",
            # An empty file is a decode error in trivy; an empty mapping is not.
            ash_content="{}\n",
            required="secret" in self._effective_scanners(final_args),
        )

    def _link_skip_args(
        self,
        target: Path | str,
        global_ignore_paths: Optional[List[IgnorePathWithReason]] = None,
    ) -> List[str]:
        """``--skip-files`` and ``--skip-dirs`` for ``target``.

        Each link leaving it, as a second guard (utils/link_exclusions.py): trivy
        follows no link and skips them on its own. And each path
        ``global_ignore_paths`` ignores, picked as ASH matches them below the source
        directory. In the joined form, since a path can start with "-".

        Bounded: the tokens together take at most ``skip_args_budget`` bytes for
        this host and the scan's environment, so a tree with thousands of ignored
        files cannot push trivy's argument list past the size the OS starts a
        program with. The ``--skip-dirs`` tokens come first: each prunes a whole
        subtree, where a ``--skip-files`` token covers one file, and the links among
        those trivy skips on its own in any case. An ignored path left out is read
        by trivy and ASH drops its findings after the scan, as for a path the
        option cannot carry.
        """
        if self.context is None:
            raise ScannerError(f"{self.__class__.__name__} has no plugin context")
        source_dir = self.context.source_dir
        wanted = [
            *(
                f"--skip-dirs={path}"
                for path in trivy_skip_dirs(target, source_dir, global_ignore_paths)
            ),
            *(
                f"--skip-files={path}"
                for path in trivy_skip_files(target, source_dir, global_ignore_paths)
            ),
        ]
        budget = skip_args_budget(self._scan_environment())
        kept: List[str] = []
        size = 0
        for token in wanted:
            size += len(os.fsencode(token)) + 1
            if size > budget:
                break
            kept.append(token)
        if len(kept) < len(wanted):
            self._plugin_log(
                f"{len(wanted) - len(kept)} ignored path(s) under "
                f"{Path(target).as_posix()} are not given to trivy as --skip-files "
                "or --skip-dirs: the arguments would exceed the size the OS starts a "
                "program with. trivy reads those paths and ASH drops their findings "
                "after the scan.",
                level=logging.WARNING,
            )
        return kept

    def _output_dir_skip_args(
        self, target: Path | str, target_type: Optional[str] = None
    ) -> List[str]:
        """``--skip-dirs`` for ASH's own output directories inside ``target``.

        The directories ``ScannerPluginBase._ash_output_dirs_inside`` names: this
        run's output directory and the default ``.ash/ash_output`` an earlier run
        can have left in the tree, each as its own value so a file the repository
        committed under one is still scanned. Without them trivy reads the
        converted copies of archives and notebooks (which the converted target
        scans already, so their findings come twice) and an earlier run's reports
        and scanner results as source. When the helper names nothing although this
        run's output directory sits inside the target (it answers [] when naming
        them raises), the output directory is skipped whole, with a warning, as the
        builtin trivy scanner does.
        """
        skipped = self._ash_output_dirs_inside(Path(target))
        if not skipped:
            whole = self._output_dir_inside(Path(target))
            if whole is not None:
                inside = Path(target).as_posix()
                self._plugin_log(
                    f"ASH named no output directory to skip inside {inside} although "
                    f"its output directory {whole.as_posix()} is there, so trivy is "
                    f"told to skip {whole.as_posix()} whole. A file the repository "
                    "committed to it is not scanned by trivy in this run.",
                    level=logging.WARNING,
                    target_type=target_type,
                )
                skipped = [whole]
        return [
            f"--skip-dirs={value}"
            for value in (
                self._skip_dirs_value(relative, target_type) for relative in skipped
            )
            if value is not None
        ]

    def _skip_dirs_value(
        self, relative: Path, target_type: Optional[str] = None
    ) -> Optional[str]:
        """``relative`` as a ``--skip-dirs`` value, or None for a path trivy's CSV
        read cannot carry.

        trivy reads the value as one line of CSV, so a line break in a path cuts the
        value at the break and trivy skips a different directory (the same reason
        ``utils/link_exclusions`` leaves such a path out of ``--skip-files``). The
        directory is then read by trivy, and ASH's drop of results located in its
        output directories removes what trivy reports there; said once, as a
        warning.
        """
        text = relative.as_posix()
        if "\n" not in text and "\r" not in text:
            return skip_dirs_value(text)
        refusal = f"skip-dirs:line-break:{text}"
        if refusal not in self._warned_inputs:
            self._warned_inputs.add(refusal)
            self._plugin_log(
                f"Not telling trivy to skip {escape_controls(text)}: a --skip-dirs "
                "value is read as one line, and the path holds a line break. trivy "
                "reads the directory, and ASH drops its findings there after the "
                "scan.",
                level=logging.WARNING,
                target_type=target_type,
            )
        return None

    def _operator_skip_args(self, final_args: List[str]) -> List[str]:
        """The operator's own ``--skip-dirs`` and ``--skip-files`` entries, as tokens.

        trivy reads a list flag from one source only: a flag on the command line
        replaces ``TRIVY_SKIP_DIRS`` / ``TRIVY_SKIP_FILES`` in its environment and
        ``scan.skip-dirs`` / ``scan.skip-files`` in its config file, it does not
        add to them. So when ASH passes a skip flag of its own (its output
        directories, the links leaving the tree, the ignored paths) the operator's
        entries would be dropped; this gives them back as tokens of their own, in
        the flag's own form, so trivy sees ASH's and the operator's together.
        Empty when ``final_args`` carries no skip flag of ASH's, since trivy then
        reads the operator's settings itself.

        As a flag the value goes through pflag's CSV reader, which the variable
        and the config file never did: each entry is passed as one CSV field
        (``_csv_field``: a ``"`` in it would otherwise fail the whole run as a
        bare quote), and an entry holding a line break is left out with a
        warning, since the reader takes one line and trivy would skip a different
        path (the reading ``_skip_dirs_value`` makes for ASH's own paths). The
        warning names the variable or key and the entry's position, never its
        text, which the environment or the operator's file chose.
        """
        if not any(
            argument.startswith(("--skip-dirs", "--skip-files"))
            for argument in final_args
        ):
            return []
        tokens: List[str] = []
        for flag, variable, key in (
            ("--skip-dirs", "TRIVY_SKIP_DIRS", "skip-dirs"),
            ("--skip-files", "TRIVY_SKIP_FILES", "skip-files"),
        ):
            entries = self._environment_list(variable)
            source = variable
            if not entries:
                entries = self._config_file_list(final_args, "scan", key)
                source = f"scan.{key} of the trivy config file"
            for position, entry in enumerate(entries, start=1):
                if "\n" in entry or "\r" in entry:
                    refusal = f"operator-skip:line-break:{source}:{position}"
                    if refusal not in self._warned_inputs:
                        self._warned_inputs.add(refusal)
                        self._plugin_log(
                            f"Not passing entry {position} of {source} to trivy as "
                            f"{flag}: the value is read as one line, and the entry "
                            "holds a line break, so trivy would skip a different "
                            "path. That entry does not apply to this scan.",
                            level=logging.WARNING,
                        )
                    continue
                token = f"{flag}={_csv_field(entry)}"
                if token not in final_args and token not in tokens:
                    tokens.append(token)
        return tokens

    def _trivy_input_file(
        self,
        *,
        option: str,
        env: str,
        default_name: str,
        ash_name: str,
        ash_content: str,
        required: bool = True,
    ) -> str:
        """A file to pass trivy for an input it would otherwise read from its cwd.

        Shared by ``trivy`` and ``trivy-repo``; both pass ``--ignorefile`` and
        ``--secret-config`` from here.

        Without the flag, trivy reads ``default_name`` (``.trivyignore``,
        ``trivy-secret.yaml``) from its working directory, the source directory,
        so the scanned repository could remove findings from its own report
        (measured with trivy 0.75.0). The option is used under the rule every
        trivy path option follows (``_operator_path``: set by the operator, for a
        file outside the scanned tree). A refused or unset option falls through to
        the environment variable, which is the operator's, used for a file outside
        the tree (config/path_trust.py); a relative path in it is taken from the
        working directory ASH runs in, as written
        (``config/operator_paths.anchored_environment_path``), not from the source
        directory. Otherwise trivy gets a file that sets
        nothing, which ASH writes outside the scanned tree (``empty_tool_config``).

        With ``required`` false the scan does not read the file (a secret config
        for a scan without the ``secret`` scanner): a configured or environment
        value that is not a file then gets ASH's empty file with a warning that
        names the key, instead of failing a scan over an input it never opens.
        """
        if self.context is None:
            raise ScannerError(f"{self.__class__.__name__} has no plugin context")
        source_dir = Path(self.context.source_dir)
        name = self.config.name if self.config is not None else "trivy"
        options: Any = self.config.options  # type: ignore[union-attr]
        value = getattr(options, option)
        if value:
            path = self._operator_path(
                option,
                value,
                f"trivy gets {env}, if set, or ASH's empty file instead.",
            )
            if path is not None:
                key = f"scanners.{name}.options.{option}"
                if required or path.is_file():
                    return self._honored_input(
                        option, key, _existing_file(key, value, path)
                    )
                self._warn_unread_input(key)
        # The variable is the operator's, set where ASH runs, so a relative path
        # in it names a file there, as written, not one at the root of the
        # scanned tree.
        from_env = self._environment_path(os.environ.get(env), env)
        if from_env:
            path = honored_path(
                from_env,
                source_dir=source_dir,
                key=env,
                config=getattr(self.context, "config", None),
                # The value is the environment's: the refusal names the variable
                # and shows the path as <value> (path_trust._named).
                env_named=True,
                # And the environment is the operator's own write, so a work
                # product the operator names there is not refused as one the
                # repository chose (path_trust.refused_derived_product).
                operator_written=True,
            )
            if path is not None:
                if required or path.is_file():
                    return self._honored_input(
                        option, env, _existing_file(env, from_env, path)
                    )
                self._warn_unread_input(env)
        in_tree = source_dir / default_name
        if in_tree.is_file() and in_tree.as_posix() not in self._warned_inputs:
            self._warned_inputs.add(in_tree.as_posix())
            self._plugin_log(
                f"Ignoring {in_tree.as_posix()}: it is inside the scanned tree. Set "
                f"scanners.{name}.options.{option} to a file outside the tree "
                "to use one.",
                level=logging.WARNING,
            )
        return empty_tool_config(ash_name, ash_content, context=self.context).as_posix()

    def _honored_input(self, option: str, key: str, path: str) -> str:
        """``path``, the input file ``key`` names, with the warning an ignore file earns.

        trivy drops every finding the ignore file lists with nothing else in the
        run saying so, as the filtering TRIVY_ variables do
        (``_warn_about_filtering_environment``); the file is named here, where it
        is known to be honored and to exist, rather than by its variable in the
        generic set, where a refused in-tree value, which restricts nothing, would
        have been warned about too. Named by key, never by path: the value can
        come from the environment. Once per key. The secret config narrows the
        secret rules, not the findings, and is not warned about.
        """
        if option == "ignore_file":
            refusal = f"ignore-file:restricts:{key}"
            if refusal not in self._warned_inputs:
                self._warned_inputs.add(refusal)
                self._plugin_log(
                    f"{key} names the ignore file trivy reads, which restricts which "
                    "results reach the report: every finding it lists is withheld, "
                    "and the scan can pass with findings withheld.",
                    level=logging.WARNING,
                )
        return path

    def _warn_unread_input(self, key: str) -> None:
        """Say once that ``key`` names no file, for an input this scan never reads."""
        refusal = f"{key}:unread-missing"
        if refusal in self._warned_inputs:
            return
        self._warned_inputs.add(refusal)
        self._plugin_log(
            f"{key} does not name a file. This scan does not read it (its scanners "
            "do not include secret), so trivy gets ASH's empty file instead; a scan "
            "that includes secret fails on it. Fix the path or unset it.",
            level=logging.WARNING,
        )

    def _run_subprocess(
        self, command: List[str], *args: Any, **kwargs: Any
    ) -> Dict[str, str]:
        """Bring trivy's shared caches up to date first, then run ``command``.

        ``command`` gains, in place so the invocation ASH records is the one that
        ran, the flags that skip the update (online), the cache directory
        (``_trivy_cache_dir``, online and offline, the one the update wrote),
        ``--cache-backend=memory`` and ``--exit-code=0``. trivy keeps its scan cache
        (``fanal/fanal.db``) in the cache directory unless told otherwise, ``trivy
        repository`` included, and a sandbox may mount that directory read-only:
        with the scan cache in memory the scan only reads the database and checks
        there. The scan cache only saves re-analysing an unchanged target, so
        results are the same either way.

        ``--exit-code`` is the code trivy exits with when it finds anything. The
        operator's ``TRIVY_EXIT_CODE``, which the sandbox passes through, and an
        ``exit-code`` in the operator's trivy.yaml both set it, and the flag outranks
        both (measured with trivy 0.75.0). Pinned to 0, a nonzero exit only ever
        means trivy failed: ``trivy`` refuses the report of any other run, and
        ``trivy-repo`` records the exit code in its SARIF invocation.
        """
        # The online or offline flags were chosen when the scanner was built
        # (_append_trivy_options); the update below reads the mode now. When the
        # two disagree (ASH_OFFLINE set or cleared between construction and the
        # scan), the scan-time reading decides both, so an offline scan never
        # carries --skip-version-check (a trivy too old to know the flag refuses
        # the command) and never lacks the skip flags, and an online scan does
        # not skip the update it is about to make. When they agree, as they do
        # in a normal run, the command is unchanged.
        if self._offline():
            stale, wanted = ONLINE_FLAGS, OFFLINE_FLAGS
        else:
            stale, wanted = OFFLINE_FLAGS, ONLINE_FLAGS
        command[:] = [arg for arg in command if arg not in stale]
        flags = [flag for flag in wanted if flag not in command]
        flags.extend(self._shared_update_flags(command))
        cache = self._trivy_cache_dir()
        self._content_db_cache_dir = cache
        flags.append(f"--cache-dir={cache.as_posix()}")
        if not any(a.startswith("--cache-backend") for a in command):
            flags.append("--cache-backend=memory")
        flags.append("--exit-code=0")
        command[2:2] = flags
        return super()._run_subprocess(command, *args, **kwargs)

    def _shared_update_flags(self, command: List[str]) -> List[str]:
        """Update trivy's database (and checks bundle) once, then skip it in the scan.

        Why: trivy and trivy-repo run concurrently and share trivy's cache. Each
        downloads the vulnerability database when it is out of date, and one can
        read ``metadata.json``, or the memory-mapped ``trivy.db``, while the other
        rewrites it. Seen in CI as ``failed to update downloaded_at: unable to get
        metadata: json decode error: unexpected EOF``, and reproduced locally as a
        SIGBUS inside bbolt, in 1 run of 5 against an empty shared cache. A
        sandbox may also mount the cache read-only, or through a throwaway
        overlay, so an update made inside it would not reach the cache the scan
        reads.

        So the update runs first, in ``utils/content_db_refresh.prepare_content_db``,
        sandboxed or not: outside the scanner sandbox, under a lock in the cache
        directory, once per scan, from a working directory outside the scanned tree
        (``config.path_trust.cwd_outside_scanned_tree``, given the scan's source and
        results directories and its config) and with an explicit ``--config``
        (``EMPTY_TOOL_CONFIG``, or the operator's file below), so nothing in the
        scanned tree (a ``trivy.yaml`` whose ``db.repository`` names another
        database, measured with trivy 0.75.0) reaches it. The scan is then told to
        skip it: ``--skip-db-update``, ``--skip-check-update`` when ``misconfig``
        needs the checks bundle, and ``--skip-java-db-update``, since fs and
        repository scans never open the Java database (trivy 0.75). It is pointed
        at the cache the update wrote (``--cache-dir``, ``_trivy_cache_dir``), which
        is also the one the sandbox mounts. The scan-time staleness check
        (``utils/content_db_staleness.py``) still measures the database after.
        An update the operator's own trivy settings turn off (``TRIVY_SKIP_DB_UPDATE``,
        or ``db.skip-update`` in the operator's config file) is left out, with a
        warning (``content_db_refresh.trivy_update_opt_outs``), and the scan reads
        the cache as it is.

        Not done offline, where ``OFFLINE_FLAGS`` already skip every update.
        """
        if self._offline():
            return []
        if self.context is None:
            raise ScannerError(f"{self.__class__.__name__} has no plugin context")
        effective = self._effective_scanners(command)
        wants_checks = "misconfig" in effective
        wants_vuln = "vuln" in effective
        skip_flags = [
            "--skip-db-update",
            "--skip-java-db-update",
            *(["--skip-check-update"] if wants_checks else []),
        ]
        if not wants_vuln and not wants_checks:
            # A scan of secrets or licenses alone opens neither the vulnerability
            # database nor the checks bundle (trivy initializes its database only
            # for the vulnerability scanner), so nothing is downloaded for it and
            # a registry that is unreachable cannot fail it. The skip flags still
            # go on the command, so trivy makes no update of its own either.
            return skip_flags
        cache = self._trivy_cache_dir()
        # The operator's trivy.yaml (options.config_file or TRIVY_CONFIG), under the
        # rule the scan's --config follows (_trivy_config_file), so a database
        # mirror it names applies to the update; otherwise prepare_content_db
        # passes EMPTY_TOOL_CONFIG.
        chosen = self._scan_config_file or self._operator_config_file()
        operator_config = (
            chosen if chosen and Path(chosen) != EMPTY_TOOL_CONFIG else None
        )
        prepare_content_db(
            "trivy",
            cache,
            offline=False,
            source_dir=self.context.source_dir,
            results_dir=self.results_dir or self.context.output_dir,
            config=getattr(self.context, "config", None),
            checks=wants_checks,
            scan_id=scan_id_for(self.context),
            executable=find_executable(command[0]),
            config_file=operator_config,
            # The scanner's env-read values, as grype passes its own: a failed
            # update's stderr excerpt is redacted with them before it is cut, so
            # the cut cannot leave a fragment the downstream redaction misses.
            values=self._values_to_redact(),
        )
        return skip_flags

    def content_database_probe_context(self):  # type: ignore[no-untyped-def]
        """The base's probe context, pointed at the cache the scan read.

        Every scan is given ``--cache-dir`` (``_run_subprocess``, from
        ``_trivy_cache_dir``), which is not where a sandboxed trivy looks on its
        own: the sandbox drops ``XDG_CACHE_HOME``. The ``trivy version`` probe gets
        the same directory, as ``--cache-dir`` (``content_db_staleness
        ._built_from_trivy``) and as ``TRIVY_CACHE_DIR``. A probe that runs before
        any scan, the offline dependency check, gets the directory the scan will
        be given. It also reads through the config file the scan passed, or the one
        it will pass.
        """
        context = super().content_database_probe_context()
        cache = (self._content_db_cache_dir or self._trivy_cache_dir()).as_posix()
        context.env = {**context.env, "TRIVY_CACHE_DIR": cache}
        context.cache_dir = cache
        context.config_file = self._scan_config_file or self._operator_config_file()
        return context

    def _operator_config_file(self) -> Optional[str]:
        """The operator's trivy config file, when it is honored and exists.

        ``_operator_config_choice``, for a probe that runs before the scan has chosen
        its ``--config`` (the offline dependency check), so it reads through the same
        file the scan will. A file that does not exist is not an error here: the
        scan itself then fails on it (``_trivy_config_file``).
        """
        if self.context is None:
            return None
        chosen = self._operator_config_choice()
        if chosen is None or not chosen[2].is_file():
            return None
        return chosen[2].as_posix()

    def _operator_path(
        self, option: str, value: Path | str, why: str
    ) -> Optional[Path]:
        """``value`` as a path, when the operator set ``option`` and it lies outside the tree.

        trivy reads a ``trivy.yaml`` that can name a directory of WASM modules
        (``module.dir``) and load them, and ``--module-dir`` names one directly. So
        a path for either is used only when the operator set the option
        (``--config-overrides`` or a config file outside every git checkout and the
        scanned directory, see ``utils/config_trust.py``) and it resolves outside the
        scanned tree, without a
        symbolic link in the tree leading it there. Otherwise this logs ``why``
        and returns None, and the caller uses ASH's own.
        """
        if self.context is None:
            raise ScannerError(f"{self.__class__.__name__} has no plugin context")
        name = self.config.name if self.config is not None else "trivy"
        key = f"scanners.{name}.options.{option}"
        # A configuration the embedding caller built is the operator's own write,
        # as for syft, bandit, checkov and grype (operator_wrote_value): the
        # repository cannot have written it. One read from the context is judged
        # by set_by_operator alone, as before.
        from automated_security_helper.config.operator_only_options import (
            operator_wrote_value,
        )

        caller_built = not self._config_from_context
        callers_own_write = caller_built and operator_wrote_value(
            self.context.config,
            "scanner",
            name,
            ("options", option),
            value,
            config_from_context=False,
        )
        chosen = operator_path(
            self.context.config,
            key,
            value,
            self.context.source_dir,
            operator_wrote=callers_own_write,
        )
        if chosen.path is not None:
            return chosen.path
        reason = chosen.refusal
        # Once per value: the scanners ask for each target and the update asks again.
        refusal = f"{key}={value}"
        if refusal not in self._warned_inputs:
            self._warned_inputs.add(refusal)
            self._plugin_log(
                refusal_warning(
                    f"Ignoring {key} ({str(value)!r}): {reason}. {why}", reason
                ),
                level=logging.WARNING,
            )
        return None

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "TrivyScannerBase[C]":
        """Set up custom installation commands for trivy.

        trivy had no install path inside ASH. It could only arrive from the
        container image, the nix toolchain or a package manager, so a
        ``python-local`` run on a machine without it scanned without it.
        """
        self.custom_install_commands.update(pinned_tool_install_commands("trivy"))
        return self

    def _offline(self) -> bool:
        """Whether this scan runs offline, for trivy and trivy-repo alike.

        ``ScannerPluginBase._scanner_offline``: ASH's offline mode, read when the
        scanner asks, or the scanner's own ``options.offline: true``. ``false``
        follows ASH and never turns the network back on under ``--offline``.
        """
        return self._scanner_offline()

    def _offline_misconfig_args(self, final_args: List[str]) -> List[str]:
        """``final_args`` without trivy's Terraform checks, for an offline scan.

        trivy's Terraform scanner fetches the source of every ``module`` block it
        evaluates, with every offline flag ASH passes and with
        ``--tf-exclude-downloaded-modules`` (measured with trivy 0.75.0): a registry
        source contacted registry.terraform.io, a ``git::`` source ran the host's
        git, with the operator's git configuration and credentials, against the URL
        the repository chose, and an ``https://`` archive was downloaded. trivy has
        no setting that stops it. So offline, trivy gets ``--misconfig-scanners``
        naming the list it would otherwise run without ``terraform``: the
        operator's own choice when one is set (``TRIVY_MISCONFIG_SCANNERS`` in the
        scan's environment, then ``misconfiguration.scanners`` in the config file
        the run passes, the order trivy reads them in), else trivy's own default
        list. An operator's narrower set is kept narrow.

        The operator's names are checked against the list trivy prints for the
        flag (``_default_misconfig_scanners``: the DEFAULT list, which is all the
        help text holds; trivy's flag declares no list of accepted values, so a
        name outside the default that trivy accepts is dropped like an unknown
        one) and passed in trivy's own spelling:
        trivy given a name it does not know runs every misconfiguration scanner,
        the Terraform checks included (measured, ``trivy_default_misconfig_scanners``),
        so a typo, a name an older release removed, or ``Terraform`` with a capital
        would have brought the module fetch back. A name trivy does not know is
        dropped with a warning that names the variable or key and counts the
        names, never their text (the environment chose them). When trivy's list
        cannot be read, the misconfiguration scanner is not run offline at all,
        rather than guessed at, whether or not the operator chose names: it is
        taken out of the ``--scanners`` value, or, when the set came from
        ``TRIVY_SCANNERS`` or the config file and the command carries no such
        token, a ``--scanners`` of that set without it is added, since trivy
        would otherwise read the set as before. A set of ``misconfig`` alone
        then leaves nothing to run, and the scan is refused. checkov still
        checks Terraform.

        Shared by ``trivy-repo``, which runs ``misconfig`` by default, and ``trivy``,
        which runs it when the operator adds it to ``scanners``.
        """
        if "misconfig" not in self._effective_scanners(final_args):
            return final_args
        command = self.command or "trivy"
        binary = find_executable(command) or command
        help_command = f"`{binary} {' '.join(self.subcommands)} --help`"
        known = self._default_misconfig_scanners(binary)
        operators_own, operators_key = self._operator_misconfig_scanners(final_args)
        unknown: List[str] = []
        if operators_own and known is None:
            chosen: List[str] = []
        elif operators_own:
            chosen, unknown = _known_scanner_names(operators_own, known or [])
        else:
            chosen = list(known or [])
        kept = [name for name in chosen if name != _TERRAFORM_MISCONFIG_SCANNER]
        args = list(final_args)
        if unknown and chosen:
            dropped = (
                f"{len(unknown)} of the {len(operators_own)} misconfiguration scanner "
                f"name(s) in {operators_key} are not in this trivy's default list "
                f"({help_command}) and are not passed to it: trivy given a name it "
                "does not know runs every misconfiguration scanner, the Terraform "
                "checks included, and its help prints the default list only, so "
                "ASH cannot tell a name outside it that trivy accepts from one it "
                "does not. The names in the default list are passed in trivy's "
                "spelling."
            )
            if dropped not in self._warned_inputs:
                self._warned_inputs.add(dropped)
                self._plugin_log(dropped, level=logging.WARNING)
        if kept:
            message = (
                "trivy's Terraform checks are skipped offline: trivy downloads the "
                "module sources a .tf file names, and has no setting that stops it. "
                "checkov still checks Terraform."
            )
            head = [command, *self.subcommands]
            insert_at = len(head) if args[: len(head)] == head else len(args)
            args[insert_at:insert_at] = [f"--misconfig-scanners={','.join(kept)}"]
        else:
            if operators_own and known is None:
                message = (
                    "trivy's misconfiguration checks are skipped offline: the "
                    f"operator chose misconfiguration scanners ({operators_key}), "
                    "and ASH could not read trivy's list of them from "
                    f"{help_command} to check the names against, so it cannot tell "
                    "which of them would leave out the Terraform checks, which "
                    "download module sources."
                )
            elif operators_own and not chosen:
                message = (
                    "trivy's misconfiguration checks are skipped offline: none of "
                    f"the {len(operators_own)} misconfiguration scanner name(s) in "
                    f"{operators_key} is in this trivy's default list "
                    f"({help_command}), and trivy given a name it does not know "
                    "runs every misconfiguration scanner, the Terraform checks "
                    "included; its help prints the default list only, so a name "
                    "outside it cannot be told from one trivy does not know."
                )
            elif operators_own:
                message = (
                    "trivy's misconfiguration checks are skipped offline: the "
                    "misconfiguration scanners the operator chose are only the "
                    "Terraform checks, which download module sources, and those are "
                    "not run offline."
                )
            else:
                message = (
                    "trivy's misconfiguration checks are skipped offline: ASH could "
                    f"not read trivy's list of them from {help_command}, so it "
                    "cannot leave out the Terraform checks, which download module "
                    "sources."
                )
            # Turning the misconfiguration scanner off has to reach trivy. With a
            # --scanners token in the command (the option named a set) its value
            # loses misconfig. Without one the set is trivy's own reading of
            # TRIVY_SCANNERS or the config file (_effective_scanners), which trivy
            # would read as before whatever this method decided, so the command
            # gets a --scanners of that set without misconfig: left as it was,
            # trivy ran the Terraform checks the warning said were skipped. A set
            # that was misconfig alone leaves nothing to run, and the scan is
            # refused with the reason, as the token form already was.
            index = args.index("--scanners") if "--scanners" in args else -1
            if index >= 0 and index + 1 < len(args):
                remaining = [
                    name for name in args[index + 1].split(",") if name != "misconfig"
                ]
                if not remaining:
                    raise ScannerError(message)
                args[index + 1] = ",".join(remaining)
            else:
                remaining = [
                    name
                    for name in self._effective_scanners(final_args)
                    if name != "misconfig"
                ]
                if not remaining:
                    raise ScannerError(message)
                head = [command, *self.subcommands]
                insert_at = len(head) if args[: len(head)] == head else len(args)
                args[insert_at:insert_at] = ["--scanners", ",".join(remaining)]
        if message not in self._warned_inputs:
            self._warned_inputs.add(message)
            self._plugin_log(message, level=logging.WARNING)
        return args

    def _default_misconfig_scanners(self, binary: str) -> Optional[List[str]]:
        """trivy's default misconfiguration scanners for this scanner's subcommand."""
        return trivy_default_misconfig_scanners(binary, list(self.subcommands))

    def _operator_misconfig_scanners(
        self, final_args: List[str]
    ) -> Tuple[List[str], str]:
        """The misconfiguration scanners the operator chose, and where.

        ``TRIVY_MISCONFIG_SCANNERS`` in the scan's environment first, then
        ``misconfiguration.scanners`` in the config file the run passes, the order
        trivy reads them in. The second value names the source for a warning, so
        the names themselves, which the environment or the operator's file chose,
        are never printed.
        """
        from_env = self._environment_list("TRIVY_MISCONFIG_SCANNERS")
        if from_env:
            return from_env, "TRIVY_MISCONFIG_SCANNERS"
        from_file = self._config_file_list(final_args, "misconfiguration", "scanners")
        return from_file, "misconfiguration.scanners of the trivy config file"

    def _append_trivy_options(self) -> None:
        """Turn the configured options into trivy flags on ``self.args.extra_args``.

        The order is the order ``trivy-repo`` has always used, so its command
        line is unchanged.
        """
        # Read by attribute: both trivy config classes declare these fields.
        options: Any = self.config.options  # type: ignore[union-attr]
        if len(options.scanners) > 0:
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--scanners",
                    value=",".join(options.scanners),
                )
            )

        if options.license_full:
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--license-full",
                    value=None,
                )
            )

        if options.ignore_unfixed:
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--ignore-unfixed",
                    value=None,
                )
            )

        if options.disable_telemetry:
            self.args.extra_args.append(
                ToolExtraArg(
                    key="--disable-telemetry",
                    value=None,
                )
            )

        # severity_threshold is not passed as --severity: trivy would drop the lower
        # findings before ASH saw them, so they would be neither reported nor
        # counted. ASH applies it after the scan, as for every scanner, to the
        # severity trivy gave each finding.

        for flag in SCAN_FLAGS:
            self.args.extra_args.append(ToolExtraArg(key=flag, value=None))

        if not self._offline():
            for flag in ONLINE_FLAGS:
                self.args.extra_args.append(ToolExtraArg(key=flag, value=None))
        else:
            # trivy's version check and telemetry are turned off by
            # TRIVY_SKIP_VERSION_CHECK and TRIVY_DISABLE_TELEMETRY, whatever
            # disable_telemetry says (utils/offline_tool_env.py); see ONLINE_FLAGS.
            for flag in OFFLINE_FLAGS:
                self.args.extra_args.append(ToolExtraArg(key=flag, value=None))

            self._check_offline_cache()

            ASH_LOGGER.info(
                "Running Trivy in offline mode - DB updates and check-update disabled"
            )

        self._warn_about_filtering_environment()

    def _check_offline_cache(self) -> None:
        """Offline: look at the cache the scan will read, before the scan.

        ``utils/offline_mode_validator.validate_trivy_offline_mode`` judges the
        cache ``TRIVY_CACHE_DIR`` names and nothing else, so with the variable unset
        it reported "TRIVY_CACHE_DIR environment variable not set" about every
        offline scan, including one whose default cache (``_trivy_cache_dir``, the
        XDG or platform directory) holds a current database. The validator runs
        only when the variable is set, where it reads the right directory; otherwise
        the resolved default cache is checked here, with the directory named, for
        its existence and for the two files trivy needs from it
        (``db/trivy.db`` and ``db/metadata.json``; trivy refuses an offline scan
        when either is missing): a cache directory that exists but holds no
        database (a fresh XDG directory, a cache another tool made) gave trivy
        nothing to read and was passed in silence. The authoritative checks stay the dependency
        probe (``validate_plugin_dependencies``) and the post-scan staleness check.

        Nothing is said for a scan whose scanners never open the vulnerability
        database (``_reads_vulnerability_db``): a missing database is no finding
        about a scan that does not read it.
        """
        if not self._reads_vulnerability_db():
            return
        if snapshot_environ().get("TRIVY_CACHE_DIR"):
            from automated_security_helper.utils.offline_mode_validator import (
                validate_trivy_offline_mode,
            )

            offline_valid, offline_messages = validate_trivy_offline_mode()
            if not offline_valid:
                for msg in offline_messages:
                    self._plugin_log(msg, level=logging.WARNING)
            return
        cache = self._trivy_cache_dir()
        if not cache.is_dir():
            self._plugin_log(
                f"Trivy offline mode: the cache directory {cache.as_posix()} does "
                "not exist, so trivy has no vulnerability database to read. Download "
                "one with network access, or set TRIVY_CACHE_DIR to a cache that "
                "holds one.",
                level=logging.WARNING,
            )
        elif missing := [
            name
            for name in ("trivy.db", "metadata.json")
            if not (cache / "db" / name).is_file()
        ]:
            # Both files: trivy refuses --skip-db-update when either is missing
            # ("We can't use the DB if either `trivy.db` or `metadata.json` is
            # missing", NeedsUpdate in trivy's db package at v0.69.3).
            self._plugin_log(
                f"Trivy offline mode: the cache directory {cache.as_posix()} holds "
                "no usable vulnerability database (missing "
                f"{', '.join('db/' + name for name in missing)}), so trivy has none "
                "to read. Download one with network access, or set TRIVY_CACHE_DIR "
                "to a cache that holds one.",
                level=logging.WARNING,
            )

    def _warn_about_filtering_environment(self) -> None:
        """Say so when a TRIVY_ setting that drops results is in trivy's environment.

        The sandbox passes every ``TRIVY_`` variable through, so the operator's
        ``TRIVY_SEVERITY``, ``TRIVY_IGNORE_UNFIXED`` and the others in
        ``OUTPUT_RESTRICTING_TRIVY_ENV`` narrow the report with nothing in the run
        saying so, where the option ``ignore_unfixed`` and the ``TRIVY_EXIT_CODE``
        pin each have their line. Named by variable, never by value: a value can
        be a path.
        """
        environment = self._scan_environment()
        found = [
            name
            for name in OUTPUT_RESTRICTING_TRIVY_ENV
            if _restricting_value(name, environment.get(name))
        ]
        if not found:
            return
        refusal = f"filtering-environment:{','.join(found)}"
        if refusal in self._warned_inputs:
            return
        self._warned_inputs.add(refusal)
        self._plugin_log(
            f"{', '.join(found)} {'is' if len(found) == 1 else 'are'} set in trivy's "
            "environment and restrict which results reach the report. Findings "
            "trivy detected may be absent from these results, and the scan can pass "
            "with findings withheld.",
            level=logging.WARNING,
        )

    @staticmethod
    def _package_from_message(message: str | None) -> tuple[str | None, str | None]:
        """Name and version from trivy's vulnerability message.

        trivy writes ``Package: <name>`` as the FIRST line of a vulnerability
        message and ``Installed Version: <version>`` as the second (its SARIF
        writer's fixed template); a misconfiguration, secret or license message
        starts with ``Artifact:`` instead and is not about a package. Read by
        position, not by scanning every line: the file path in an ``Artifact:``
        line can hold a line break, and a later line it supplied that starts with
        ``Package:`` would otherwise give a misconfiguration or secret result a
        package identity. Split on ``\\n`` alone, the separator trivy writes, for
        the reason ``trivy_severity`` gives.
        """
        lines = (message or "").split("\n")
        if not lines or not lines[0].startswith("Package: "):
            return None, None
        name = lines[0][len("Package: ") :].strip() or None
        version = None
        if len(lines) > 1 and lines[1].startswith("Installed Version: "):
            version = lines[1][len("Installed Version: ") :].strip() or None
        return name, version

    def _attach_package_identity(
        self, sarif_report: SarifReport, target: Path
    ) -> SarifReport:
        """Give each dependency result one package copy and say which it is.

        trivy groups packages by name and version before matching, so the same
        version installed at two places in one lockfile becomes ONE result with
        one location per copy. No suppression can then cover one copy and not
        the other. For npm lockfiles, each location's line is the line of that
        copy's ``packages`` key, so such a result is split into one result per
        location, each with ``package_path``. Results whose locations do not
        all resolve to a lockfile entry are left whole. An entry found at the
        reported line counts only when it is the package the result names (the
        same name, and the same version when both state one): trivy's line is the
        line of the copy's key in the lockfile, and a lockfile that moved since the
        scan, or a result trivy placed at line 1, would otherwise give the result
        another package's path.
        """
        lock_index = NpmLockIndex(target)
        for run in sarif_report.runs or []:
            new_results = []
            for result in run.results or []:
                message = result.message.root.text if result.message else None
                name, version = self._package_from_message(message)
                if name is None:
                    new_results.append(result)
                    continue

                resolved = []
                for location in result.locations or []:
                    physical = location.physicalLocation
                    root = physical.root if physical else None
                    uri = (
                        root.artifactLocation.uri
                        if root and root.artifactLocation
                        else None
                    )
                    line = root.region.startLine if root and root.region else None
                    # Relativized the same way as grype's, so package_path is
                    # POSIX and scan-root-relative whatever form trivy used.
                    lock_rel = lock_index.relative(uri) if uri else None
                    entry = (
                        lock_index.by_line(lock_rel, line)
                        if lock_rel and line
                        else None
                    )
                    if entry is not None and not _same_package(entry, name, version):
                        entry = None
                    resolved.append(
                        install_path(lock_rel, entry.key)
                        if lock_rel and entry is not None
                        else None
                    )

                if resolved and all(resolved):
                    for location, path in zip(result.locations or [], resolved):
                        copy = result.model_copy(deep=True)
                        copy.locations = [location.model_copy(deep=True)]
                        self._set_identity(copy, name, version, path)
                        new_results.append(copy)
                else:
                    path = resolved[0] if len(resolved) == 1 else None
                    self._set_identity(result, name, version, path)
                    new_results.append(result)
            run.results = new_results
        return sarif_report

    @staticmethod
    def _set_identity(
        result: Any, name: str | None, version: str | None, path: str | None
    ) -> None:
        identity = identity_properties(name, version, path)
        if result.properties is None:
            result.properties = PropertyBag.model_validate(identity)
        else:
            for key, value in identity.items():
                setattr(result.properties, key, value)
