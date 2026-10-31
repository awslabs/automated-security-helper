#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Shared scanner-inventory introspection for ASH.

This module is the single source of truth for what a scanner reports about
itself -- the tool version it detects, whether its dependencies are satisfied,
its offline strategy, and whether it is enabled. Both the MCP ``list_scanners``
tool (``cli/mcp_tools.py``) and the ``ash plugin list`` CLI command build their
entries by calling :func:`list_scanner_inventory` here, so a fix to the probe is
a fix to both surfaces at once (issues #606 and #626).

What the surfaces cannot drift on, and what they deliberately differ on
----------------------------------------------------------------------
They cannot drift on *how a scanner is described*. Given the same scanner, both
produce the same entry, because both reach it through the same
:func:`describe_scanner`.

They do differ on *which scanners exist*, and that difference is intentional.
Both call :func:`list_scanner_inventory`; they differ only in the provider they
hand it. MCP passes :func:`_loaded_scanner_classes`, which additionally loads
:data:`_VENDORED_SCANNER_PLUGIN_PACKAGES`, so it reports the set this build
*contains*. The CLI passes the classes ``load_plugins(plugin_context)`` resolved,
which is the set *active for this configuration*. Measured on one machine that is
13 and 10; the three the CLI does not list are ``ferret_scan``, ``snyk_code`` and
``trivy_repo``.

So the two answer different questions, and the CLI's answer is the one an
operator reads to decide what is configured. Loading the vendored packages
CLI-side was considered and rejected: it would name three scanners in that table
that a scan will not run unless they are separately enabled, trading a
documentation problem for a behavioral one.

The cost of that choice, stated plainly because it is a real limit rather than a
nicety: ``ash plugin list --show-versions`` cannot tell an operator whether
trivy, snyk or ferret are reachable, while ``list_scanners`` can. Anyone needing
that answer should use the MCP tool. Revisiting this means deciding what
``ash plugin list`` is for, not just adding a loader call.

Everything here is read-only introspection. Scanners are instantiated in a
throwaway directory and asked about themselves; nothing writes to the working
tree and no scan is run.
"""

import logging
import re as _re
import tempfile
import threading
from pathlib import Path
from time import monotonic as _monotonic
from typing import Any, Callable, Dict, List, Optional

from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.redacted_model import (
    EnvResolvedScalar,
    without_env_scalars,
)


#: Scanner plugin packages that ship inside ASH but are not loaded by
#: ``load_internal_plugins()``, which imports ``ash_builtin`` only.
#:
#: These are package paths, not the module paths inside them, because
#: ``ASH_SCANNERS`` is declared in each package's ``__init__``. That list is what
#: ``load_additional_plugin_modules`` returns, and pointing at
#: ``ash_ferret_plugins.ferret_scanner`` instead imports the scanner but returns
#: nothing, since the leaf module declares no ``ASH_SCANNERS``. Measured: the leaf
#: paths yield 0 scanners, the package paths yield every one of the modules'
#: scanners. tests/unit/cli/mcp/test_list_scanners_import_order.py keeps this list
#: equal to every in-tree community module.
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
        # The backport, as utils/ash_install.py reads it: on Python 3.10 the
        # standard library's packages_distributions() reads only top_level.txt,
        # which hatchling does not write, so a hatchling-built plugin
        # distribution was not found there. The backport is a declared
        # dependency and reads RECORD on every Python version; the standard
        # library stands in only where the backport is absent.
        try:
            from importlib_metadata import packages_distributions
        except ImportError:  # pragma: no cover - the backport is a dependency
            from importlib.metadata import packages_distributions

        pkg_dist = packages_distributions()
    except Exception:
        # packages_distributions() reads installed metadata, which can be missing
        # or unreadable in a frozen or vendored install. Discovery coming back
        # empty is not fatal, and must not be: the vendored packages are loaded
        # either way.
        pkg_dist = {}

    # A distribution whose metadata carries no readable Name appears here as
    # None (importlib.metadata records what the metadata says), and a str method
    # on it raised AttributeError outside the try above, failing the whole
    # inventory for one unrelated broken install. Such an entry names nothing.
    return [
        f"automated_security_helper.plugin_modules.{top_level}"
        for top_level, dists in pkg_dist.items()
        if any(
            isinstance(d, str) and d.startswith("ash_") and d.endswith("_plugins")
            for d in dists
        )
    ]


def _loaded_scanner_classes() -> list:
    """Every scanner class ASH ships, taken from what the loaders report loading.

    Why this does not call ``ash_plugin_manager.plugin_modules("scanner")``
    ---------------------------------------------------------------------
    That method's memo follows the registrations, but the registry is
    process-wide: it holds every module any caller in the process loaded, a
    session's own plugin modules included, so it answers "what is registered
    here", not "what ASH ships".

    Reading ``plugin_library`` directly instead fails the sweep in
    ``tests/unit/workspace/test_project_isolation.py``, which forbids reaching into
    the manager's registry from outside the class that owns it, because that is
    the shape the original defect arrived in.

    Loading the vendored packages registers their scanners in the process-wide
    registry. That does not make them part of a scan: a scan selects the built-in
    scanners plus those of the modules its own ``ash_plugin_modules`` names
    (``plugins.loader.scan_plugin_filter``).

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
    from automated_security_helper.plugins import ash_plugin_manager

    package_paths = _discover_external_scanner_plugin_packages()
    package_paths.extend(_VENDORED_SCANNER_PLUGIN_PACKAGES)

    internal = load_internal_plugins()
    # load_additional_plugin_modules logs a warning when a package fails to
    # import, which the bare `except ImportError: pass` this replaces did not: a
    # scanner missing because its package is broken now leaves a trace.
    #
    # Each inside untrusted_import: a client's request loads these packages, not
    # the operator. Their scanners register for the rest of the process, and
    # trivy-repo and ferret-scan are enabled by default, so without it a later
    # scan in the server would select and run them although neither it nor the
    # operator loads their package.
    external: list = []
    for package_path in package_paths:
        with ash_plugin_manager.untrusted_import(package_path):
            external.extend(
                load_additional_plugin_modules([package_path]).get("scanners", [])
            )

    scanner_classes: list = []
    for cls in list(internal.get("scanners", [])) + external:
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


def _probe_tool_version(
    command: Optional[str], cwd: Optional[Path] = None
) -> Optional[str]:
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

    ``cwd`` is the throwaway probe directory the inventory built. The tool used to
    run in the process's working directory, the one place the inventory promises
    to keep every probe out of: a tool that reads its configuration or a project
    file from where it runs then answered for the caller's tree.
    """
    if not command:
        return None

    from automated_security_helper.utils.subprocess_utils import (
        find_executable,
        run_command,
        run_succeeded,
    )

    resolved = find_executable(command)
    if not resolved:
        return None

    # The module's own reference to the clock, so a test can replace it here
    # without stopping time.monotonic() for the rest of the process.
    deadline = _monotonic() + _VERSION_PROBE_TOTAL_BUDGET_SECONDS
    for arg_form in _VERSION_PROBE_ARG_FORMS:
        remaining = deadline - _monotonic()
        if remaining < _VERSION_PROBE_MIN_ATTEMPT_SECONDS:
            # The prior form nearly spent the shared budget; do not start another
            # probe with a slice too small to give the tool a fair chance.
            break
        try:
            result = run_command(
                [resolved, *arg_form],
                cwd=cwd,
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

        # Flags first: a run whose output ASH could not record can exit 0, and
        # what it printed is no version.
        if not run_succeeded(result):
            continue

        # Joined on a line break, never run together: a version printed without
        # a trailing newline fused with the first characters of stderr, and
        # "1.2" + "3 warnings" read as 1.23.
        combined = "\n".join(
            part
            for part in (
                getattr(result, "stdout", "") or "",
                getattr(result, "stderr", "") or "",
            )
            if part
        )
        extracted = _extract_version_from_probe(combined)
        if extracted:
            return extracted

    return None


def _configured_enabled(default_config, name: str, enabled_default: Any) -> Any:
    """``enabled`` for scanner *name*: the operator's default configuration, else the default.

    The deployment's own section for the scanner wins over what the scanner's
    config declares, whether the scanner was constructed (the default is the
    instance's config value) or not (the default is its config class's). An
    external plugin's section is a dict the segment models keep as an extra and
    never validate: a value the file read from the environment is still the
    resolver's marker, and the entry is data a tool answer carries. The marker's
    TEXT came from the environment, so it is reported as its reference spelling,
    never by value; the downcast view (without_env_scalars) strips only the type
    and would keep the text.
    """
    found_cfg = default_config.get_plugin_config("scanner", name)
    if found_cfg is None:
        return enabled_default
    if isinstance(found_cfg, dict):
        raw_enabled = found_cfg.get("enabled", enabled_default)
        if isinstance(raw_enabled, EnvResolvedScalar):
            return "${" + raw_enabled.variable + "}"
        return _enabled_from_text(without_env_scalars(raw_enabled))
    return getattr(found_cfg, "enabled", enabled_default)


#: The spellings an unvalidated section's ``enabled`` can hold as text.
_ENABLED_WORDS = frozenset({"true", "yes", "on", "1"})
_DISABLED_WORDS = frozenset({"false", "no", "off", "0"})


def _enabled_from_text(value: Any) -> Any:
    """A boolean for an ``enabled`` an unvalidated section holds as text.

    An external plugin's section is a dict no model validated, so its
    ``enabled`` can be the string ``"false"``, which every truthiness consumer
    of the entry (and a reader of the MCP tool's answer) read as enabled. The
    words a YAML or JSON config spells a boolean with become the boolean; any
    other value is returned as it is, so a reader still sees what was written.
    """
    if isinstance(value, str):
        word = value.strip().lower()
        if word in _ENABLED_WORDS:
            return True
        if word in _DISABLED_WORDS:
            return False
    return value


def _offline_strategy_text(cls) -> str:
    """``cls.offline_strategy`` as the entry reports it: an enum's value, a
    string as it is, and ``"unknown"`` for anything else, never raising.

    Read before any try in :func:`describe_scanner`, so a class whose attribute
    was not an enum raised AttributeError on ``.value`` and failed the whole
    inventory for one scanner.
    """
    strategy = getattr(cls, "offline_strategy", None)
    if strategy is None:
        return "unknown"
    value = getattr(strategy, "value", strategy)
    return value if isinstance(value, str) else "unknown"


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
    entry: Dict[str, Any] = {
        "name": _scanner_name_from_class(cls),
        "version": None,
        "dependencies_satisfied": None,
        "offline_strategy": _offline_strategy_text(cls),
        "enabled": True,
        "installs_on_first_scan": False,
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
        # The class's declared default when it can be read; the optimistic
        # default when the class declares no config or its config class cannot
        # be built. Either way the operator's default configuration is read
        # over it, as for a constructed scanner below: the entry answers whether
        # this deployment has the scanner on, and a scanner the operator
        # switched off read as enabled whenever its construction failed and its
        # declaration could not be read.
        declared_default: Any = True
        declared_cls = _declared_config_class(cls)
        if declared_cls is not None:
            try:
                declared_default = getattr(declared_cls(), "enabled", True)
            except Exception:
                # A config class that cannot be built tells us nothing about the
                # class's own default; the operator's section still decides.
                pass
        entry["enabled"] = _configured_enabled(
            default_config, entry["name"], declared_default
        )
        return entry

    # Guarded like the construction above: the config reads run on a plugin
    # instance, whose attributes are plugin code, and one scanner raising here
    # aborted the whole inventory instead of being listed with what is knowable.
    try:
        config = getattr(plugin, "config", None)
        raw_name = getattr(config, "name", None)
        if raw_name:
            entry["name"] = str(raw_name).replace("-", "_")

        # Resolved whether or not the config carried a name.
        #
        # This used to sit inside the `if raw_name:` branch, which meant a config
        # declaring `enabled = False` was reported as enabled whenever its `name`
        # was absent -- the entry kept the optimistic default from above. That is
        # a wrong answer in the dangerous direction: it tells a caller a scanner
        # is on when its own config says it is off.
        #
        # The name is still taken from the class in that case (set when the entry
        # was built), so the config lookup below has a key to search on either way.
        #
        # And resolved when the instance has NO config: the operator's default
        # configuration is consulted all the same, over the default the class
        # declares, as for a scanner that could not be built. Skipped, the entry
        # kept the optimistic True whatever the operator switched off.
        if config is not None:
            enabled_default = getattr(config, "enabled", True)
        else:
            declared_cls = _declared_config_class(cls)
            enabled_default = True
            if declared_cls is not None:
                try:
                    enabled_default = getattr(declared_cls(), "enabled", True)
                except Exception:
                    enabled_default = True
        entry["enabled"] = _configured_enabled(
            default_config, entry["name"], enabled_default
        )
    except Exception as exc:
        ASH_LOGGER.debug(
            f"Could not read the config of {entry['name']} to describe it: "
            f"{type(exc).__name__}: {exc}"
        )

    try:
        entry["dependencies_satisfied"] = bool(plugin.validate_plugin_dependencies())
        # The check ran in check-only mode (list_scanner_inventory), and reached
        # the point where a scan installs the tool: not offline, uv present, the
        # tool not installed. So it is absent now and a scan installs it.
        entry["installs_on_first_scan"] = entry[
            "dependencies_satisfied"
        ] is False and bool(getattr(plugin, "_installs_on_first_scan", False))
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
    # version even though a probe that validated first could see it. A plugin that
    # deferred its uv version probe from construction (bandit, checkov, semgrep) runs
    # it from its dependency check too, and also here, so the version does not hang
    # on how a subclass, or a test, implements that check.
    resolve_version = getattr(plugin, "resolve_deferred_tool_version", None)
    if callable(resolve_version):
        try:
            resolve_version()
        except Exception as exc:  # A failed probe leaves the version unknown.
            ASH_LOGGER.debug(f"Version probe for {entry['name']} raised: {exc}")
    entry["version"] = _normalized_version(getattr(plugin, "tool_version", None))

    # Fallback for a reachable external tool that did not report its own version.
    # grype, syft and opengrep resolve their binary but never assign tool_version,
    # so they arrive here dependencies_satisfied True / version None. Only then is
    # a probe worth its cost: an unreachable tool (False) has no binary to ask, an
    # unmeasurable one (None) is not known to be present, and a bundled tool
    # already carries a version. Executing the resolved binary is the only way to
    # answer "which version is actually on PATH", which is the inventory's point.
    #
    # Not for a scanner that runs its tool through uv (use_uv_tool): its version
    # probe already ran above, and a same-named binary first on PATH is not the
    # tool uv runs, so its version would be reported for a scanner that never
    # executes it. The test is the flag, not the presence of
    # resolve_deferred_tool_version: that method is the uv mixin's, and the mixin
    # is a base of EVERY plugin, so testing for the method excluded every scanner
    # and no PATH tool was ever asked its version.
    if (
        entry["version"] is None
        and entry["dependencies_satisfied"] is True
        and not getattr(plugin, "use_uv_tool", False)
    ):
        command = getattr(plugin, "command", None)
        entry["version"] = _probe_tool_version(
            command, cwd=getattr(context, "source_dir", None)
        )

    return entry


def _describe_scanner_or_placeholder(cls, context, default_config) -> Dict[str, Any]:
    """:func:`describe_scanner`, or a placeholder entry when it raises.

    One scanner class whose description raises outside the guarded steps must
    not cost the inventory every other scanner: the placeholder names the
    scanner and reports every other field as unknown (``enabled`` None, "could
    not determine", as ``dependencies_satisfied`` already reads), and the cause
    is logged.
    """
    try:
        return describe_scanner(cls, context, default_config)
    except Exception as exc:  # noqa: BLE001 -- one plugin class cannot fail the list
        class_name = getattr(cls, "__name__", None)
        ASH_LOGGER.warning(
            f"Could not describe scanner {class_name or cls!r}: "
            f"{type(exc).__name__}: {exc}"
        )
        return {
            "name": (
                _scanner_name_from_class(cls)
                if isinstance(class_name, str)
                else "unknown"
            ),
            "version": None,
            "dependencies_satisfied": None,
            "offline_strategy": _offline_strategy_text(cls),
            "enabled": None,
            "installs_on_first_scan": False,
        }


#: Held while an inventory runs. Each one starts a probe per scanner (an import,
#: a ``--version`` run), on a thread each when ``concurrent``, and nothing bounded
#: how many ran at once: N MCP clients calling check_installation or
#: list_scanners together started N times that many processes. One inventory at a
#: time; a caller arriving meanwhile waits for it.
_INVENTORY_LOCK = threading.Lock()

#: How long a caller waits for the inventory lock before giving up. Bounded, so
#: one stalled inventory (the probes are bounded too, so a stall is a defect)
#: cannot block every later ``list_scanners`` and ``check_installation`` call
#: forever; generous, because a full inventory of a dozen scanners, each with a
#: version probe of up to _VERSION_PROBE_TOTAL_BUDGET_SECONDS, takes minutes.
_INVENTORY_LOCK_WAIT_SECONDS = 600.0


def list_scanner_inventory(
    scanner_classes_provider: Optional[Callable[[], list]] = None,
    concurrent: bool = False,
    config: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    """Return per-scanner metadata for all registered ASH scanners.

    Each entry contains:
      name: scanner config name, snake_cased (e.g. "bandit", "cdk_nag")
      version: detected version string, or None when the scanner reports none
      dependencies_satisfied: True, False, or None when it could not be determined
      offline_strategy: OfflineStrategy enum value string
      enabled: whether the scanner is enabled in the default config
      installs_on_first_scan: the tool is not installed, and a scan would
        install it with uv when it starts the scanner

    Nothing is installed or downloaded: the checks run in check-only mode
    (``utils.uv_tool_runner.checking_only``). A scanner's dependency check
    installs its tool when it is missing, and a uv version probe downloads it,
    so outside check-only mode describing the scanners would start minutes of
    package downloads.

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
        concurrent: Describe the scanners on a thread each, in the order given.
            The checks are slow ones (an import, a ``--version`` run: seconds
            for checkov and semgrep), and a scan already runs them on scanner
            threads, so they are safe side by side. Off by default.
        config: The configuration to describe the scanners under: the probe
            context's config and the operator's section each entry's ``enabled``
            is read from. None describes them under the default configuration of
            the tree the process runs in. A caller that resolved a configuration
            (``ash plugin list --config``) passes it, so a version probed under a
            pinned ``tool_version`` and a reachability judged under the options
            the command was given are what the table shows.

    One inventory runs at a time (``_INVENTORY_LOCK``); a concurrent caller
    waits for the one running and then runs its own, for at most
    ``_INVENTORY_LOCK_WAIT_SECONDS``, after which it raises rather than wait
    forever behind a stalled one.

    Raises:
        TimeoutError: Another inventory held the lock for the whole wait.
    """
    from automated_security_helper.utils.uv_tool_runner import checking_only

    if not _INVENTORY_LOCK.acquire(timeout=_INVENTORY_LOCK_WAIT_SECONDS):
        raise TimeoutError(
            "another scanner inventory has held the inventory lock for "
            f"{_INVENTORY_LOCK_WAIT_SECONDS:.0f} seconds; this one is not run"
        )
    try:
        with checking_only():
            return _describe_scanners(scanner_classes_provider, concurrent, config)
    finally:
        _INVENTORY_LOCK.release()


def _describe_scanners(
    scanner_classes_provider: Optional[Callable[[], list]],
    concurrent: bool,
    config: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    """list_scanner_inventory's body; it runs inside checking_only()."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.default_config import (
        default_config_for_tree,
    )

    provider = scanner_classes_provider or _loaded_scanner_classes
    scanner_classes = provider()
    # As a scan rooted here loads it: the inventory describes the scanners the
    # operator's default configuration enables, and an ASH_CONFIG file inside
    # this checkout stays loadable whatever it writes for an operator-only
    # option, as it is for the scan. A caller that resolved a configuration
    # describes them under that one instead.
    default_config = config if config is not None else default_config_for_tree()

    with tempfile.TemporaryDirectory(prefix="ash-list-scanners-") as probe_root:
        source_dir = Path(probe_root) / "source"
        output_dir = Path(probe_root) / "output"
        source_dir.mkdir()
        output_dir.mkdir()
        context = PluginContext(
            source_dir=source_dir,
            output_dir=output_dir,
            config=config if config is not None else AshConfig(),
        )
        if not concurrent or len(scanner_classes) < 2:
            return [
                _describe_scanner_or_placeholder(cls, context, default_config)
                for cls in scanner_classes
            ]
        import contextvars
        from concurrent.futures import ThreadPoolExecutor

        # Each check in a copy of this context, taken here: a pool thread inherits
        # none, and list_scanner_inventory's checking_only() must reach every
        # check.
        tasks = [(contextvars.copy_context(), cls) for cls in scanner_classes]
        with ThreadPoolExecutor(
            max_workers=len(scanner_classes), thread_name_prefix="ash-inventory"
        ) as pool:
            return list(
                pool.map(
                    lambda task: task[0].run(
                        _describe_scanner_or_placeholder,
                        task[1],
                        context,
                        default_config,
                    ),
                    tasks,
                )
            )
