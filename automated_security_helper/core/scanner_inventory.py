#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Shared scanner-inventory introspection for ASH.

This module is the single source of truth for "which scanners does this build
have, and what does each one report about itself" -- the tool version it detects,
whether its dependencies are satisfied, its offline strategy, and whether it is
enabled. Both the MCP ``list_scanners`` tool (``cli/mcp_tools.py``) and the
``ash plugin list`` CLI command consume it, so the two paths cannot drift: a fix
to the probe here is a fix to both surfaces at once (issues #606 and #626).

Everything here is read-only introspection. Scanners are instantiated in a
throwaway directory and asked about themselves; nothing writes to the working
tree and no scan is run.
"""

import logging
import re as _re
import tempfile
import time as _time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from automated_security_helper.utils.log import ASH_LOGGER


#: Scanner plugin packages that ship inside ASH but are not loaded by
#: ``load_internal_plugins()``, which imports ``ash_builtin`` only.
#:
#: These are package paths, not the module paths inside them, because
#: ``ASH_SCANNERS`` is declared in each package's ``__init__``. That list is what
#: ``load_additional_plugin_modules`` returns, and pointing at
#: ``ash_ferret_plugins.ferret_scanner`` instead imports the scanner but returns
#: nothing, since the leaf module declares no ``ASH_SCANNERS``. Measured: the leaf
#: paths yield 0 scanners, the package paths yield 3.
_VENDORED_SCANNER_PLUGIN_PACKAGES = (
    "automated_security_helper.plugin_modules.ash_ferret_plugins",
    "automated_security_helper.plugin_modules.ash_snyk_plugins",
    "automated_security_helper.plugin_modules.ash_trivy_plugins",
)


def _discover_external_scanner_plugin_packages() -> list:
    """Package paths for installed distributions matching the ash plugin namespace.

    Deliberately returns only what installed metadata claims. Loading the vendored
    packages as well is the caller's job: the two sources find different scanners,
    so treating either one as the complete set loses the other.
    """
    try:
        from importlib.metadata import packages_distributions

        pkg_dist = packages_distributions()
    except Exception:
        # packages_distributions() reads installed metadata, which can be missing
        # or unreadable in a frozen or vendored install. Discovery coming back
        # empty is not fatal, and must not be: the vendored packages are loaded
        # either way.
        pkg_dist = {}

    return [
        f"automated_security_helper.plugin_modules.{top_level}"
        for top_level, dists in pkg_dist.items()
        if any(d.startswith("ash_") and d.endswith("_plugins") for d in dists)
    ]


def _loaded_scanner_classes() -> list:
    """Every scanner class ASH ships, taken from what the loaders report loading.

    Why this does not call ``ash_plugin_manager.plugin_modules("scanner")``
    ---------------------------------------------------------------------
    That method memoises its resolved class list into ``_resolved_plugins`` and
    never invalidates it, so the first resolve in a process decides the answer for
    every later one. Registration is not what breaks: measured here, the registry
    held all 13 scanners while the memo, built before the vendored packages were
    loaded, kept serving the 10 it was created with. Any earlier resolve is
    enough -- a CLI command, another test, an in-flight scan -- which is how a
    caller asking an ASH server which scanners it has got an answer three short,
    with nothing logged and no error raised.

    Two alternatives were rejected. Clearing the memo breaks callers that depend
    on it holding still: ``workspace.execution.prewarm_plugin_registry`` exists so
    the resolved set is frozen once, up front, for a whole workspace run, and
    clearing it from an MCP tool can resize the registry under a scan thread that
    is mid-iteration -- the ``dictionary changed size during iteration`` failure
    prewarming was added to close. Reading ``plugin_library`` directly instead
    fails the sweep in ``tests/unit/workspace/test_project_isolation.py``, which
    forbids reaching into the manager's registry from outside the class that owns
    it, because that is the shape the original defect arrived in.

    What is left is the loaders' own return values. Both
    ``load_internal_plugins`` and ``load_additional_plugin_modules`` return the
    ``ASH_SCANNERS`` each package declares, which is a public result, is fixed per
    package rather than accumulated per process, and touches no shared state at
    all. Nothing here can be stale, and nothing here can perturb a running scan.
    """
    from automated_security_helper.plugins.loader import (
        load_additional_plugin_modules,
        load_internal_plugins,
    )

    # Load both sources rather than choosing between them. Metadata discovery and
    # the vendored list find different packages, so picking one on whether
    # discovery happened to return anything drops whatever the winner does not
    # cover: install any ash_*_plugins distribution and discovery wins, taking
    # ferret, snyk and trivy out of the answer. Loading both is safe because
    # import_module is cached and register_plugin_module skips names already
    # registered, so the result does not depend on the order either.
    package_paths = _discover_external_scanner_plugin_packages()
    package_paths.extend(_VENDORED_SCANNER_PLUGIN_PACKAGES)

    internal = load_internal_plugins()
    # load_additional_plugin_modules logs a warning when a package fails to
    # import, which the bare `except ImportError: pass` this replaces did not: a
    # scanner missing because its package is broken now leaves a trace.
    external = load_additional_plugin_modules(package_paths)

    scanner_classes: list = []
    for cls in list(internal.get("scanners", [])) + list(external.get("scanners", [])):
        if cls not in scanner_classes:
            scanner_classes.append(cls)

    return scanner_classes


#: Version strings a scanner reports when it could not detect one. Mapped to None
#: so "no version" has a single representation in the tool's output instead of
#: three that a consumer would each have to know about.
_ABSENT_VERSION_MARKERS = frozenset({"", "unavailable", "unknown", "none"})


def _declared_config_class(cls):
    """The scanner's own config class, read from its Pydantic ``model_fields``.

    Only consulted when the scanner itself cannot be instantiated. The preferred path reads
    ``plugin.config`` off a live instance, which reflects any config actually resolved for the
    run; this reads what the class *declares* instead, which is all that remains available
    when construction fails.

    Without it, a scanner that cannot be built reports ``enabled: True`` no matter what its
    config declares, because the optimistic default set before construction is never revised.
    A config saying ``enabled = False`` then reads to a caller as enabled -- wrong in the
    direction that matters, since it describes a scanner as participating when it is switched
    off.

    The ``config`` field's annotation is a Union of the concrete config, the shared base and
    None. The concrete one is identified by name rather than by position: relying on the first
    argument would break the moment the Union's order changed, and would do so silently by
    picking the base class, whose ``enabled`` default is the very value being corrected.
    """
    config_field = getattr(cls, "model_fields", {}).get("config")
    if config_field is None:
        return None
    annotation = getattr(config_field, "annotation", None)
    for arg in getattr(annotation, "__args__", None) or ():
        if isinstance(arg, type) and arg.__name__.endswith("ScannerConfig"):
            return arg
    return None


def _scanner_name_from_class(cls) -> str:
    """Derive a scanner's name from its class name.

    The fallback for when a scanner cannot be instantiated at all. Produces the
    same snake_case form the instantiated path produces -- ``CdkNagScanner``
    yields ``cdk_nag``, matching config name ``cdk-nag`` normalized -- so a
    scanner that fails to construct still appears under the name callers expect
    rather than vanishing or appearing twice under two spellings.
    """
    raw = _re.sub(r"Scanner$", "", cls.__name__)
    return _re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", raw).lower()


def _normalized_version(raw) -> Optional[str]:
    """Return a scanner's reported version, or None when it reports none.

    Whitespace is stripped because at least one scanner's ``tool_version`` carries
    a trailing newline from the subprocess it shells out to.

    Scanners disagree about the format: bandit reports "bandit 1.9.4" while
    checkov reports "3.3.19". Both land in one Version column, so reporting each
    verbatim rendered that column in two formats at once -- and bandit's entry
    was long enough to wrap onto a second line, which changed the height of the
    whole table row. The reason :func:`_extract_version_from_probe` extracts is
    that returning a whole line "would render a cluttered, inconsistent Version
    column"; the same argument applies to the values arriving through here, so
    the same token is taken.

    The direction chosen is to strip down to the bare token rather than to keep
    prefixes everywhere, because the other direction is not available: probe
    output is multi-line ("Application:   syft\\nVersion:    1.42.4") and has no
    verbatim form a table cell could hold.

    Extraction here cannot lose information the way a guessing parser would: a
    value with no version-shaped token is returned unchanged rather than dropped,
    so a scanner reporting something this module does not understand still shows
    what it said instead of "Unknown".
    """
    if raw is None:
        return None
    text = str(raw).strip()
    if text.lower() in _ABSENT_VERSION_MARKERS:
        return None
    # Token when there is one, the scanner's own string when there is not.
    return _version_token(text) or text


#: Arg forms to try when asking a binary for its version, in order.
#:
#: ``--version`` comes first because it is the form every scanner binary ASH
#: ships answers correctly. Measured across the ten reachable on one machine --
#: grype, syft, bandit, semgrep, checkov, npm, opengrep, cfn_nag_scan,
#: detect-secrets and the python cdk_nag uses -- all ten exit 0 and print a
#: parseable version for ``--version``. grype and syft also answer the
#: subcommand form, so putting the flag form first costs them nothing.
#:
#: The subcommand form is second, not gone: it stays as the fallback for a tool
#: that only knows ``version``. Nothing ASH ships needs it today, and keeping it
#: is cheap because a tool answering the flag form never reaches it.
#:
#: Order matters here in a way that is not obvious. ``version`` was first, and
#: for bandit that is actively wrong rather than merely redundant: ``bandit
#: version`` reads ``version`` as a path to scan, finds nothing, and still exits
#: 0 after printing ``Run started:<timestamp>``. A zero exit is the whole test
#: :func:`_probe_tool_version` applies before accepting output, so the flag form
#: never got its turn and bandit's reported version came out of the timestamp,
#: changing on every invocation. Any tool that treats an unknown argument as a
#: scan target rather than an error has this shape.
_VERSION_PROBE_ARG_FORMS = (("--version",), ("version",))

#: Total wall-clock budget for probing ONE scanner's version, shared across both
#: arg forms rather than applied to each. A binary that does not answer promptly
#: is treated as version-unknown rather than allowed to stall the inventory: the
#: whole point of the inventory is a quick "what is here", not a scan. Sharing the
#: budget bounds the worst case at this many seconds per scanner (not 2x it): the
#: second arg form only runs with whatever time the first left, so a hung tool
#: cannot cost ~20s. A floor keeps the last attempt from getting an unusably tiny
#: slice when the first nearly exhausted the budget.
_VERSION_PROBE_TOTAL_BUDGET_SECONDS = 10
_VERSION_PROBE_MIN_ATTEMPT_SECONDS = 2

#: First token shaped like a dotted version (``1.9.4``, ``0.79.0``, ``v3.2``).
#: Raw ``--version`` output mixes the number with the tool name and other words,
#: and so does at least one scanner's self-reported ``tool_version`` ("bandit
#: 1.9.4"), so both paths reach this through :func:`_version_token`. Matching is
#: necessary but not sufficient -- see :data:`_PROBE_DATETIME_SHAPES`.
_PROBE_VERSION_TOKEN = _re.compile(r"v?\d+(?:\.\d+)+(?:[.\-+][A-Za-z0-9.]+)?")

#: Date and time-of-day shapes, excised before the version token is looked for.
#:
#: A dotted-numeric run is not by itself a version, and a timestamp contains one:
#: in ``Run started:2026-09-22 18:15:34.653010+00:00`` the seconds-and-offset
#: tail ``34.653010+00`` matches :data:`_PROBE_VERSION_TOKEN` exactly. That is
#: how bandit's reported version became a number that changed every invocation.
#: Reordering the probe arg forms stopped bandit from reaching this path, but the
#: mechanism is not specific to bandit -- any tool that prints a date on a
#: successful exit hits it -- so the shape is rejected here too.
#:
#: Excising rather than rejecting the whole line keeps real output working: a
#: tool printing ``1.2.3 built at 10:30:00`` still reports 1.2.3. Matches are
#: replaced with a space so removal cannot splice two numbers into a third.
_PROBE_DATETIME_SHAPES = _re.compile(
    r"""
      \d{4}-\d{2}-\d{2}                 # ISO date: 2026-09-22
    | \d{1,2}:\d{2}(?::\d{2})?          # clock time: 18:15 or 18:15:34
      (?:\.\d+)?                        #   fractional seconds: .653010
      (?:\s*(?:[+-]\d{2}:?\d{2}|Z))?    #   UTC offset: +00:00, -0700, Z
    """,
    _re.VERBOSE,
)

#: Largest plausible first component of a version. CalVer legitimately uses a
#: four-digit year (``2024.1.1``), so the cap is four digits rather than fewer;
#: anything longer is not a version but a counter that happens to carry a dot,
#: epoch seconds (``1758628650.325994``) being the shape that motivates this.
_PROBE_VERSION_MAX_LEADING_DIGITS = 4


def _version_token(text: str) -> Optional[str]:
    """The first version-shaped token in ``text``, or None if it holds none.

    One definition of "looks like a version", shared by both paths that need it:
    :func:`_extract_version_from_probe`, which reports None when a probe's output
    holds no version, and :func:`_normalized_version`, which falls back to the
    scanner's own string. Splitting these would let the two surfaces disagree
    about the same value, which is the class of drift this module exists to
    prevent.
    """
    # Timestamps first: their seconds-and-offset tail matches the version token,
    # so searching before removing them returns the clock, not a version.
    cleaned = _PROBE_DATETIME_SHAPES.sub(" ", text)
    for match in _PROBE_VERSION_TOKEN.finditer(cleaned):
        token = match.group(0)
        leading = token.lstrip("v").split(".", 1)[0]
        if len(leading) > _PROBE_VERSION_MAX_LEADING_DIGITS:
            # A counter that happens to carry a dot (epoch seconds), not a
            # version. Keep scanning: a real version may follow it.
            continue
        return token
    return None


def _extract_version_from_probe(raw: Optional[str]) -> Optional[str]:
    """Pull a version string out of a binary's ``--version`` output.

    Unlike :func:`_normalized_version`, this DOES extract a token, because raw
    probe output is not a bare version -- ``grype 0.79.0`` and
    ``semgrep 1.177.0`` carry the tool name alongside the number, and returning
    the whole line would render a cluttered, inconsistent Version column. Only a
    dotted-numeric token is accepted; any real version contains one, so output
    with none is not an odd version format but a usage banner, an error line or
    other non-version text, and returning that verbatim would print garbage in
    the Version column. So output with no such token yields None (reported as
    ``Unknown``), consistent with the module's no-guess policy. Empty output also
    yields None.

    A dotted token is necessary but not sufficient. Timestamps contain one --
    ``Run started:2026-09-22 18:15:34.653010+00:00`` yields ``34.653010+00`` --
    so date and clock shapes are excised before the search, and a token with an
    implausibly long leading component is refused. Without that, a tool printing
    a date on a successful exit reports a version that changes every invocation,
    which is what bandit did.
    """
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    # No token means the output carries no version (a usage banner, an error line
    # or a bare timestamp): report Unknown rather than surface non-version text
    # verbatim. This is the one difference from _normalized_version, which keeps
    # the scanner's own string in that case because a scanner naming its version
    # in a format this module does not parse is still saying something true.
    return _version_token(text)


def _probe_tool_version(command: Optional[str]) -> Optional[str]:
    """Best-effort version for a reachable external binary, or None.

    Only called for a scanner whose dependency check passed but which never
    populated ``tool_version`` itself -- grype, syft and opengrep resolve their
    binary via ``find_executable`` but assign no version on their code path, so
    without this they read as reachable-but-versionless. Executing the tool is the
    only remaining source: this is the "what is actually available when running
    ASH" answer the inventory exists to give.

    Deliberately tolerant. A command that does not resolve, a probe that raises,
    times out, or prints nothing recognizable all yield None -- reported upstream
    as ``Unknown`` -- rather than a guess or an exception. Runs in a bounded
    subprocess against the resolved absolute path; no shell.
    """
    if not command:
        return None

    from automated_security_helper.utils.subprocess_utils import (
        find_executable,
        run_command,
    )

    resolved = find_executable(command)
    if not resolved:
        return None

    deadline = _time.monotonic() + _VERSION_PROBE_TOTAL_BUDGET_SECONDS
    for arg_form in _VERSION_PROBE_ARG_FORMS:
        remaining = deadline - _time.monotonic()
        if remaining < _VERSION_PROBE_MIN_ATTEMPT_SECONDS:
            # The prior form nearly spent the shared budget; do not start another
            # probe with a slice too small to give the tool a fair chance.
            break
        try:
            result = run_command(
                [resolved, *arg_form],
                capture_output=True,
                text=True,
                check=False,
                shell=False,
                timeout=remaining,
                # An inventory listing is not a scan, and the probe is an
                # implementation detail of answering "what version is on PATH".
                # run_command logs "Running command: ..." at its log_level, which
                # defaults to INFO, so leaving it unset printed one line per
                # probed scanner on a completely successful run.
                log_level=logging.DEBUG,
            )
        except Exception as exc:  # pragma: no cover - run_command swallows most
            ASH_LOGGER.debug(
                f"Version probe '{command} {' '.join(arg_form)}' raised "
                f"{type(exc).__name__}: {exc}"
            )
            continue

        if getattr(result, "returncode", 1) != 0:
            continue

        combined = (getattr(result, "stdout", "") or "") + (
            getattr(result, "stderr", "") or ""
        )
        extracted = _extract_version_from_probe(combined)
        if extracted:
            return extracted

    return None


def describe_scanner(cls, context, default_config) -> Dict[str, Any]:
    """Describe one scanner by instantiating it and asking it about itself.

    Every field here except ``offline_strategy`` needs an *instance*: the config
    name, the enabled flag, the detected tool version and the dependency check are
    all instance state. That is why the previous version of this function could
    report none of them -- it worked from classes only, reconstructed the config
    class by walking the ``config`` field's Union annotation to reach ``name``, and
    filled ``version`` and ``dependencies_satisfied`` with the literals None and
    False.

    ``dependencies_satisfied`` comes from calling ``validate_plugin_dependencies()``
    and not from reading ``plugin.dependencies_satisfied``. The two disagree, and
    reading the attribute is the trap: it is declared ``bool = False`` on
    ``ScannerPluginBase``, so before the method runs it holds False for every
    scanner including the working ones. ``ScanPhase`` does
    ``plugin.dependencies_satisfied = plugin.validate_plugin_dependencies()``,
    making the return value the authoritative signal, and this follows it.

    A scanner that cannot be constructed or whose check raises reports
    ``dependencies_satisfied: None``, meaning "could not determine", rather than
    False. Reporting False for an unmeasured scanner is the defect this function
    exists to remove: it under-reports capability, and an operator reading it
    concludes a working deployment is broken.
    """
    offline_strategy = getattr(cls, "offline_strategy", None)
    entry: Dict[str, Any] = {
        "name": _scanner_name_from_class(cls),
        "version": None,
        "dependencies_satisfied": None,
        "offline_strategy": (
            offline_strategy.value if offline_strategy is not None else "unknown"
        ),
        "enabled": True,
    }

    try:
        plugin = cls(context=context)
    except Exception as exc:
        # Listed with what is knowable rather than dropped. A scanner missing from
        # the list reads as "this build has 12 scanners", which is a wrong answer;
        # a scanner present with dependencies_satisfied None reads as "could not
        # determine", which is the true one.
        ASH_LOGGER.debug(f"Could not instantiate {cls.__name__} to describe it: {exc}")

        # The instance is gone, but the class still declares its config, and that declaration
        # is the only remaining source for `enabled`. Skipping this leaves the optimistic
        # default in place and reports a disabled scanner as enabled.
        declared_cls = _declared_config_class(cls)
        if declared_cls is not None:
            try:
                declared = declared_cls()
            except Exception:
                # A config class that cannot be built either tells us nothing, so the
                # optimistic default stands rather than being replaced by a guess.
                return entry
            entry["enabled"] = getattr(declared, "enabled", True)
        return entry

    config = getattr(plugin, "config", None)
    raw_name = getattr(config, "name", None)
    if raw_name:
        entry["name"] = str(raw_name).replace("-", "_")

    # Resolved whether or not the config carried a name.
    #
    # This used to sit inside the `if raw_name:` branch, which meant a config declaring
    # `enabled = False` was reported as enabled whenever its `name` was absent -- the entry
    # kept the optimistic default from above. That is a wrong answer in the dangerous
    # direction: it tells a caller a scanner is on when its own config says it is off.
    #
    # The name is still taken from the class in that case (set when the entry was built), so
    # the config lookup below has a key to search on either way.
    if config is not None:
        enabled_default = getattr(config, "enabled", True)
        found_cfg = default_config.get_plugin_config("scanner", entry["name"])
        if found_cfg is None:
            entry["enabled"] = enabled_default
        elif isinstance(found_cfg, dict):
            entry["enabled"] = found_cfg.get("enabled", enabled_default)
        else:
            entry["enabled"] = getattr(found_cfg, "enabled", enabled_default)

    try:
        entry["dependencies_satisfied"] = bool(plugin.validate_plugin_dependencies())
    except Exception as exc:
        # Left as None. Several scanners raise ScannerError from their dependency
        # check rather than returning False, and mapping that to False would put a
        # real failure and an unmeasurable one under the same value.
        ASH_LOGGER.debug(
            f"Dependency check for {entry['name']} raised {type(exc).__name__}: {exc}"
        )

    # Read AFTER the dependency check, which is not merely tidier -- it is the only
    # order that works. Some scanners populate tool_version as a side effect of
    # validating: npm-audit shells out to `npm --version` inside
    # validate_plugin_dependencies and assigns the result. Reading first reported
    # None for those scanners while the version was sitting there a moment later,
    # which is how this was found -- the reported set was missing npm-audit's
    # version even though a probe that validated first could see it.
    entry["version"] = _normalized_version(getattr(plugin, "tool_version", None))

    # Fallback for a reachable external tool that did not report its own version.
    # grype, syft and opengrep resolve their binary but never assign tool_version,
    # so they arrive here dependencies_satisfied True / version None. Only then is
    # a probe worth its cost: an unreachable tool (False) has no binary to ask, an
    # unmeasurable one (None) is not known to be present, and a bundled tool
    # already carries a version. Executing the resolved binary is the only way to
    # answer "which version is actually on PATH", which is the inventory's point.
    if entry["version"] is None and entry["dependencies_satisfied"] is True:
        command = getattr(plugin, "command", None)
        entry["version"] = _probe_tool_version(command)

    return entry


def list_scanner_inventory(
    scanner_classes_provider: Optional[Callable[[], list]] = None,
) -> List[Dict[str, Any]]:
    """Return per-scanner metadata for all registered ASH scanners.

    Each entry contains:
      name: scanner config name, snake_cased (e.g. "bandit", "cdk_nag")
      version: detected version string, or None when the scanner reports none
      dependencies_satisfied: True, False, or None when it could not be determined
      offline_strategy: OfflineStrategy enum value string
      enabled: whether the scanner is enabled in the default config

    Scanners are probed in a throwaway directory, not the working tree. Dependency
    checks ask the environment -- is this module importable, is that binary on PATH
    -- so no source tree is needed, and pointing them at one would let a file in
    the caller's directory change the answer to a question about the deployment.

    Args:
        scanner_classes_provider: Zero-arg callable returning the scanner classes
            to describe. Injectable so a caller (and the test suite) can control
            the scanner set; defaults to :func:`_loaded_scanner_classes`. The MCP
            wrapper passes its own module-level ``_loaded_scanner_classes`` so its
            existing monkeypatch target keeps intercepting.
    """
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.default_config import get_default_config

    provider = scanner_classes_provider or _loaded_scanner_classes
    scanner_classes = provider()
    default_config = get_default_config()

    with tempfile.TemporaryDirectory(prefix="ash-list-scanners-") as probe_root:
        source_dir = Path(probe_root) / "source"
        output_dir = Path(probe_root) / "output"
        source_dir.mkdir()
        output_dir.mkdir()
        context = PluginContext(
            source_dir=source_dir,
            output_dir=output_dir,
            config=AshConfig(),
        )
        return [
            describe_scanner(cls, context, default_config) for cls in scanner_classes
        ]
