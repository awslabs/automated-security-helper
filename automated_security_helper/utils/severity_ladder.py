# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Single source of truth for the severity-threshold gate.

Why this module exists
----------------------
ASH encoded the same threshold ladder in four places that had already drifted
apart: ``ScanResultsContainer.determine_status`` (severity counts), the
junitxml reporter (SARIF levels, missing two of the five threshold values),
and two tables inside ``run_ash_scan._compute_exit_code``. A finding could
therefore be counted as gate-failing by the exit code and reported as a
passing test in the same run.

``determine_status``, the junitxml reporter and
``ScannerStatisticsCalculator.calculate_actionable_count`` all call this module.
The two tables inside ``_compute_exit_code`` -- ``_THRESHOLD_QUALIFYING_LEVELS``
and the severity-rank pair beside it -- are still inline and are NOT consumed
from here, so this is not yet the single source of truth for the whole codebase.

Those two agree with this module for all five real threshold values, and diverge
off-table: an unrecognised threshold gates ``{error}`` here (CRITICAL, matching
the historical ``determine_status`` cascade) but ``{"error", "warning"}`` and
rank ``.get(..., 2)`` there -- MEDIUM.

An earlier revision of this docstring called those divergences latent, on the
grounds that ``global_settings.severity_threshold`` is a
``Literal["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]`` and so cannot hold an
off-table value. That premise was false, and the field is the reason: its default
was an unvalidated ``os.environ`` read, and ``pydantic`` does not validate a
default no caller supplied. With ``ASH_DEFAULT_SEVERITY_LEVEL=INFO`` set,
``AshConfig().global_settings.severity_threshold`` really was ``"INFO"`` while
passing the identical value explicitly raised ``ValidationError``. Reproduce
against a tree predating that fix with::

    ASH_DEFAULT_SEVERITY_LEVEL=INFO uv run python -c "import automated_security_helper.config.ash_config as c; c.AshConfig.model_rebuild(); print(c.AshConfig().global_settings.severity_threshold)"

Two changes now hold the premise up instead of assuming it. ``core.constants``
normalizes the environment value through :func:`normalize_threshold` before it
becomes a default, and ``AshConfigGlobalSettingsSection`` sets
``validate_default=True`` so a future off-table default fails where it is
written. The remaining off-table routes are a per-scanner
``options.severity_threshold`` and a workspace-level per-project threshold, so
the divergence above is still reachable and still worth closing -- what has
changed is that it can no longer arrive from the environment.

The direction is counter-intuitive: RAISING the threshold LOOSENS the gate
------------------------------------------------------------------------
The threshold names the *least severe* finding that still fails a scan, so a
higher threshold ignores more:

* ``ALL``      -- everything fails, down to informational findings.
* ``LOW``      -- low, medium, high and critical fail; info is ignored.
* ``MEDIUM``   -- medium and above fail.
* ``HIGH``     -- high and critical fail.
* ``CRITICAL`` -- only critical fails.

So the strictness order, strictest first, is
``ALL < LOW < MEDIUM < HIGH < CRITICAL``, and ``stricter_of`` returns whichever
argument sits earlier in it.

A falsy threshold (``None`` or ``""``) is looser still: nothing fails, not even
a critical finding. That is deliberate and predates this module -- it is how an
operator turns the gate off -- so the comparison functions preserve it exactly.
Note that this makes the falsy value *not* a synonym for ``CRITICAL``. The one
place that never returns a falsy value is :func:`resolve_scanner_threshold`: a
scanner's or the global settings' ``severity_threshold`` left blank is an unset
value there, not a request for no gate, and falls through to the next default.

Why the workspace field is called ``max_severity_threshold``
-----------------------------------------------------------
Because "max" refers to strictness-permissiveness, not to severity. A
workspace sets the LOOSEST value a project is allowed to configure; a project
may be stricter but not laxer. Combining a workspace ceiling with a project
setting is therefore ``stricter_of(project, workspace_ceiling)``. Naming it
after the severity would invert the meaning for every reader.

Two views of one ladder
-----------------------
``severity_fails_threshold`` works from ASH severity names. SARIF has only four
levels for ASH's five severities, so ``sarif_level_fails_threshold`` maps
``error/warning/note/none`` onto ``CRITICAL/MEDIUM/LOW/INFO`` and reuses the
same comparison. The mapping is lossy in exactly one place, and it is a
limitation of SARIF rather than a choice made here: ``error`` covers both
CRITICAL and HIGH, so under a ``CRITICAL`` threshold a HIGH finding still
qualifies when seen through SARIF levels. Callers that need the distinction
must work from severity counts, not levels.

Failure modes and known limitations
-----------------------------------
* An unrecognised threshold string gates like ``CRITICAL`` -- only critical
  findings fail. This is not a design preference; it is what the historical
  cascade in ``determine_status`` did, because its critical check was
  unconditional while every other check tested membership in a literal tuple.
  Threshold matching is consequently case-SENSITIVE: ``"low"`` is not ``"LOW"``
  and gates like ``CRITICAL``.
* An unrecognised *severity* name fails closed -- it fails every configured
  threshold -- so an unexpected value cannot silently slip past a gate. Both
  in-repo callers pass known names, so this path is defensive only.
* A missing or unrecognised SARIF level is read as :data:`MISSING_SARIF_LEVEL`,
  SARIF 2.1.0's own default (``warning``, MEDIUM), by every grader: the results
  model's default, :func:`result_severity`, :func:`sarif_level_fails_threshold`
  (and so the exit-code gate and workspace mode) and Bedrock, so one finding gets
  one grade everywhere.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Callable, Dict, Optional, Set, Tuple


def _ash_logger() -> logging.Logger:
    """ASH's logger, by name and at call time.

    By name, not through utils.log: that module imports the console, the thread
    wrapper and the process environment, and this module is imported by the
    models they build on, so the import would be a cycle. At call time, not at
    import: core.constants imports this module before utils.log has set ASHLogger
    as the logger class, and a ``getLogger("ash")`` run then makes the "ash"
    logger a plain ``logging.Logger`` for the whole process, which drops the
    run-scoped handler walk ASHLogger adds. The first warning is logged long
    after utils.log has run.
    """
    return logging.getLogger("ash")


#: The off-table threshold values warned about so far, one warning per value per
#: process: the gate runs once per finding, and a warning per finding would say
#: the same thing hundreds of times.
_WARNED_OFF_TABLE: Set[str] = set()

# The ladder, as data. Ordered strictest to loosest -- see the module docstring
# for why that is the opposite of the severity ordering.
SEVERITY_THRESHOLDS: Tuple[str, ...] = ("ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL")

# ASH severity names, most severe first.
SEVERITIES: Tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

# Severity rank and the minimum rank each threshold gates on. A finding fails
# when its rank is at or above its threshold's minimum, which is why the two
# tables run in opposite directions.
_SEVERITY_RANK: Dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

_THRESHOLD_MIN_RANK: Dict[str, int] = {
    "ALL": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

# An unrecognised threshold gates on critical only, preserving the historical
# cascade where `counts.critical > 0` was checked before any threshold test.
_UNKNOWN_THRESHOLD_MIN_RANK = _THRESHOLD_MIN_RANK["CRITICAL"]

# An unrecognised severity fails closed: it clears every threshold's minimum.
_UNKNOWN_SEVERITY_RANK = _SEVERITY_RANK["CRITICAL"]

# SARIF's four levels onto ASH's five severities. `error` maps to CRITICAL
# rather than HIGH so that a threshold of CRITICAL still gates on it, matching
# the qualifying-level table in run_ash_scan._compute_exit_code.
_SARIF_LEVEL_TO_SEVERITY: Dict[str, str] = {
    "error": "CRITICAL",
    "warning": "MEDIUM",
    "note": "LOW",
    "none": "INFO",
}

#: The level of a result that states none, and of one whose level is not a SARIF
#: level: SARIF 2.1.0 3.27.10, "IF level has not yet been set THEN SET level to
#: "warning"", which applies when kind is "fail" (its default) and the rule
#: gives no default level. ``resolve_missing_levels`` applies the rest of that
#: procedure at ingestion, where the rules are available. One constant for the
#: results model's default, the gate, ``result_severity`` and Bedrock, which
#: graded such a result CRITICAL, LOW and INFO. "note" (LOW) is the
#: alternative a maintainer may prefer; it would make the gate laxer for them.
MISSING_SARIF_LEVEL = "warning"


def effective_sarif_level(result: object) -> str:
    """The SARIF level of *result* (a ``Result`` or its JSON form), lower-case.

    Its own level when it is one of SARIF's four, else :data:`MISSING_SARIF_LEVEL`.
    Accepts a ``Level`` enum member as well as a string.
    """
    level = (
        result.get("level")
        if isinstance(result, dict)
        else getattr(result, "level", None)
    )
    # `.value` first: str(Level.error) is "Level.error" on Python 3.11+.
    raw = getattr(level, "value", level)
    normalized = str(raw).strip().lower() if raw else ""
    return normalized if normalized in _SARIF_LEVEL_TO_SEVERITY else MISSING_SARIF_LEVEL


def _rule_default_level(rule: object) -> Optional[str]:
    """The level a rule's ``defaultConfiguration`` states, or None when it states
    none."""
    configuration = getattr(rule, "defaultConfiguration", None)
    if configuration is None or "level" not in getattr(
        configuration, "model_fields_set", ()
    ):
        return None
    return effective_sarif_level(configuration)


def component_labels(component: object) -> frozenset:
    """The names a tool component answers to: its ``name`` and ``fullName``,
    lower-cased, empty when it states neither. Compared with
    :func:`result_scanner_labels` to find the component a result's scanner
    wrote."""
    labels = set()
    for field in ("name", "fullName"):
        value = getattr(component, field, None)
        if isinstance(value, str) and value.strip():
            labels.add(value.strip().lower())
    return frozenset(labels)


def result_scanner_labels(result: object) -> frozenset:
    """The names of the scanner that produced *result*, lower-cased:
    ``properties.scanner_name`` (an attribute or a ``model_extra`` key) and
    ``properties.scanner_details.tool_name`` (a mapping or an object). Empty when
    the result names none, or when a read raises: this runs on every result,
    stand-ins included."""
    labels = set()
    try:
        props = getattr(result, "properties", None)
        if props is None:
            return frozenset()
        extra = getattr(props, "model_extra", None)
        extra = extra if isinstance(extra, dict) else {}
        candidates = [getattr(props, "scanner_name", None), extra.get("scanner_name")]
        details = getattr(props, "scanner_details", None)
        if details is None:
            details = extra.get("scanner_details")
        if isinstance(details, dict):
            candidates.append(details.get("tool_name"))
        elif details is not None:
            candidates.append(getattr(details, "tool_name", None))
        for value in candidates:
            if isinstance(value, str) and value.strip():
                labels.add(value.strip().lower())
    except Exception:  # noqa: BLE001 -- see the docstring
        return frozenset()
    return frozenset(labels)


def _first_rule_with_id(rules: list, identifier: object) -> object:
    """The first rule in *rules* whose ``id`` is *identifier*, or None."""
    for rule in rules:
        if getattr(rule, "id", None) == identifier:
            return rule
    return None


def _rule_of(
    result: object,
    components: list,
    by_id: Dict[Any, object],
    component_names: Optional[list] = None,
) -> object:
    """The rule *result* names, read as SARIF 3.27.5 lets a result name one.

    In order: the ``rule`` reference (its ``toolComponent.index`` picks an
    extension, else the driver; its ``index`` picks the rule there; else its
    ``id``), ``ruleIndex`` into the driver's rules, then ``ruleId``. An indexed
    rule whose id disagrees with the id the result also states is passed over
    for the id. A hierarchical id (``CA1001/sub``) falls back to each shorter
    prefix at a ``/``, so the rule ``CA1001`` grades its sub-results.

    A lookup by id is scoped before it is global. *components* is the driver's
    rule list followed by the extensions'; *component_names* (optional) is the
    parallel list of each component's :func:`component_labels`. An id is looked
    for first in the component the reference names, then in the component whose
    labels share a name with the result's scanner (:func:`result_scanner_labels`),
    and only then across every component in order (*by_id*, first copy wins,
    which is SARIF's reading of a bare ``ruleId``: the driver's rule). Two
    scanners can share a rule id (grype and trivy both name a CVE), and the
    merge that aggregates their runs keeps each scanner's rules in its own
    extension while dropping the result's component reference; read across every
    component first-wins, a level-less copy of the id in one scanner's extension
    graded another scanner's result "warning" where its own rule said "error".
    """
    reference = getattr(result, "rule", None)
    body = getattr(reference, "root", reference)
    stated_id = getattr(result, "ruleId", None) or getattr(body, "id", None)
    named_rules: Optional[list] = None
    scanner = result_scanner_labels(result) if component_names else frozenset()

    def in_scope(candidate):
        if named_rules is not None:
            found = _first_rule_with_id(named_rules, candidate)
            if found is not None:
                return found
        if scanner:
            for rules, labels in zip(components, component_names or []):
                if labels and not labels.isdisjoint(scanner):
                    found = _first_rule_with_id(rules, candidate)
                    if found is not None:
                        return found
        return by_id.get(candidate)

    def by_stated_id():
        candidate = stated_id
        while candidate:
            found = in_scope(candidate)
            if found is not None:
                return found
            if "/" not in candidate:
                return None
            candidate = candidate.rsplit("/", 1)[0]
        return None

    if body is not None:
        component_ref = getattr(body, "toolComponent", None)
        component_index = getattr(component_ref, "index", -1)
        if component_index is None or component_index < 0:
            rules = components[0]
        elif component_index + 1 < len(components):
            rules = components[component_index + 1]
        else:
            rules = []
        named_rules = rules
        index = getattr(body, "index", -1)
        if index is not None and 0 <= index < len(rules):
            rule = rules[index]
            if not stated_id or getattr(rule, "id", None) == stated_id:
                return rule
        return by_stated_id()
    rule_index = getattr(result, "ruleIndex", None)
    if rule_index is not None and 0 <= rule_index < len(components[0]):
        rule = components[0][rule_index]
        if not stated_id or getattr(rule, "id", None) == stated_id:
            return rule
    return by_stated_id()


def resolve_missing_levels(sarif_report: object) -> None:
    """Give every result of *sarif_report* that states no level an explicit one.

    SARIF 2.1.0 3.27.10: with ``kind`` other than "fail", a missing level "SHALL
    default to "none""; with "fail" (the default) it is the rule's
    ``defaultConfiguration.level`` when the rule gives one, else "warning". The
    rule is the one the result names (:func:`_rule_of`): through its ``rule``
    reference, its ``ruleIndex`` or its ``ruleId``, in the run's driver and
    extensions. Reading ``ruleId`` and ``rule.id`` alone gave a result that
    names its rule by index the missing level, "warning", in place of the
    rule's own. Invocation-level rule overrides are not consulted. Results that
    state a level keep it. Run where a scanner's report enters the results, so
    the level is explicit in memory, in ``ash.sarif`` and in the saved results.
    """
    for run in getattr(sarif_report, "runs", None) or []:
        tool = getattr(run, "tool", None)
        tool_components = [getattr(tool, "driver", None)] + list(
            getattr(tool, "extensions", None) or []
        )
        components = [
            list(getattr(component, "rules", None) or [])
            for component in tool_components
        ]
        component_names = [component_labels(c) for c in tool_components]
        # First copy wins across components: the global fallback of _rule_of,
        # which looks in the named and the scanner's component before it.
        by_id: Dict[Any, object] = {}
        for rules in components:
            for rule in rules:
                by_id.setdefault(getattr(rule, "id", None), rule)
        for result in getattr(run, "results", None) or []:
            if "level" in getattr(result, "model_fields_set", ("level",)):
                continue
            kind = getattr(result, "kind", None)
            kind = str(getattr(kind, "value", kind) or "fail")
            if kind != "fail":
                result.level = "none"
                continue
            rule = _rule_of(result, components, by_id, component_names)
            level = _rule_default_level(rule) if rule is not None else None
            result.level = level or MISSING_SARIF_LEVEL


def result_severity(result: object) -> str:
    """The ASH severity of one SARIF result, as the summary counts and gate read it.

    ``properties.issue_severity`` decides when it names one of :data:`SEVERITIES`
    (any case); otherwise the level does: ``error`` CRITICAL, ``warning``
    MEDIUM, ``note`` LOW, ``none`` INFO. A result with no level, or one this
    table does not know, is read as :data:`MISSING_SARIF_LEVEL` (MEDIUM).

    The one rule for every consumer. Reporters and ``ash inspect`` each kept their
    own: flat-json, CSV, the HTML/Markdown/text finding lists and inspect graded
    ``error`` HIGH, GitLab SAST and inspect ignored ``issue_severity``, OCSF and
    GHAS mapped levels to their own scales. A finding could be CRITICAL in the
    summary and the verdict and HIGH in the report a reader triages from.

    Accepts a ``Result`` model or its JSON form (a dict), and a ``Level`` enum
    member as well as a string for the level.
    """
    if isinstance(result, dict):
        properties = result.get("properties")
    else:
        properties = getattr(result, "properties", None)
    if isinstance(properties, dict):
        declared = properties.get("issue_severity")
    else:
        declared = getattr(properties, "issue_severity", None)
    if isinstance(declared, str) and declared.strip().upper() in _SEVERITY_RANK:
        return declared.strip().upper()
    return _SARIF_LEVEL_TO_SEVERITY[effective_sarif_level(result)]


def normalize_threshold(value: object) -> Optional[str]:
    """Upper-case and strip *value* if it names a threshold, else return None.

    The predicate for every boundary where a threshold arrives as free text: an
    environment variable, a config file, a CLI argument. Returning None rather
    than a fallback is deliberate -- the caller is the only party that knows what
    to substitute and whether to warn -- so this function cannot hide the fact
    that it did not recognise the value.

    Normalising here and not inside :func:`severity_fails_threshold` is the whole
    design. Threshold matching stays case-sensitive in the comparison (see
    "Failure modes" above), so upper-casing in one consumer and not another is
    exactly how the same configured string comes to gate differently in the exit
    code and the report. Callers normalise once, at the edge, and pass a ladder
    value inward.

    ``plugin_modules.ash_builtin.reporters.junitxml_reporter._normalized_threshold``
    is this same predicate, written before this function existed; it is left in
    place here only because that file is outside this change's scope.
    """
    if not value:
        return None
    upper = str(value).strip().upper()
    return upper if upper in SEVERITY_THRESHOLDS else None


def _strictness_key(threshold: Optional[str]) -> Tuple[int, str]:
    """Sort key for threshold strictness; a lower key is stricter.

    The three tiers keep the ordering total and independent of argument order:
    recognised thresholds first (ordered by the ladder), then unrecognised
    values, then the absence of a threshold. Unrecognised values sort after
    ``CRITICAL`` even though they gate identically, so that a real ``CRITICAL``
    always wins the comparison rather than the tie being decided by which
    argument came first.
    """
    if not threshold:
        return (2, "")
    if threshold in _THRESHOLD_MIN_RANK:
        return (0, f"{SEVERITY_THRESHOLDS.index(threshold):02d}")
    return (1, threshold)


def stricter_of(a: Optional[str], b: Optional[str]) -> Optional[str]:
    """Return whichever of *a* and *b* gates more findings.

    Total and commutative over every input, including ``None`` and ``""``.
    Returns ``None`` when neither side configures a threshold, which is why the
    return type is optional: the absence of a threshold is a value in the
    domain, so it has to be a value in the range too.

    Used to combine a workspace-level ceiling with a project-level setting: the
    project may tighten the gate but never loosen it.
    """
    if not a and not b:
        return None
    return a if _strictness_key(a) <= _strictness_key(b) else b


def severity_fails_threshold(severity: str, threshold: Optional[str]) -> bool:
    """Return True when a finding of *severity* fails the gate at *threshold*.

    Args:
        severity: An ASH severity name, e.g. ``"HIGH"``. Case-insensitive.
        threshold: A configured threshold, or ``None``/``""`` for no gate at
            all. Case-SENSITIVE, for the reason given in the module docstring.

    Returns:
        True if the finding should fail the scan.
    """
    if not threshold:
        return False
    # A value that is not text (a number, a boolean, a list from an external
    # section) names no rung and gates like any other unrecognised value. It is
    # not looked up in the table: a list is unhashable, and the warning below
    # describes it without reading it as text.
    on_the_ladder = isinstance(threshold, str) and threshold in _THRESHOLD_MIN_RANK
    if not on_the_ladder:
        _warn_off_table_threshold(threshold)
    rank = _SEVERITY_RANK.get(severity.upper(), _UNKNOWN_SEVERITY_RANK)
    minimum = (
        _THRESHOLD_MIN_RANK[threshold] if on_the_ladder else _UNKNOWN_THRESHOLD_MIN_RANK
    )
    return rank >= minimum


#: The shape of a threshold worth quoting in the log: a ladder-like word (letters,
#: digits, ``_``, ``.``, ``-``), at most 32 characters. A misspelled or lower-case
#: ladder word is this shape; a free-text value an external plugin or an
#: environment reference passed through is not, and is described, not quoted.
_QUOTABLE_THRESHOLD = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


def _threshold_for_log(threshold: object) -> str:
    """*threshold* as the off-table warning shows it: quoted when it is a
    ladder-shaped word, else described by its length (or, for a value that is
    not text, by its type).

    The value is whatever an external plugin or caller passed straight through;
    a configuration that pointed the threshold at an environment variable would
    have put that variable's value in ash.log. The warning exists to name a typo
    or a case slip, which a ladder-shaped word shows in full; anything else is
    not the ladder's business to print.
    """
    if not isinstance(threshold, str):
        return f"a value of type {type(threshold).__name__} (not shown: not text)"
    if _QUOTABLE_THRESHOLD.match(threshold):
        return repr(threshold)
    return f"a {len(threshold)}-character value (not shown: not a ladder-shaped word)"


def _warn_off_table_threshold(threshold: object) -> None:
    """Log once per process that *threshold* is off the ladder and gates like CRITICAL.

    Every configured route normalizes at its edge (``normalize_threshold``, the
    Literal-typed config fields), so a value reaching here is a free-text one an
    external plugin or caller passed straight through; silently gating it like
    CRITICAL hid a loosened gate. The warning names the value
    (:func:`_threshold_for_log`: quoted when ladder-shaped, described otherwise)
    and the ladder, and says the matching is case-sensitive, which is the usual
    cause.
    """
    # The dedupe key is the text itself, or the type's name for a value that is
    # not text (a list cannot be a set member).
    key = threshold if isinstance(threshold, str) else f"<{type(threshold).__name__}>"
    if key in _WARNED_OFF_TABLE:
        return
    _WARNED_OFF_TABLE.add(key)
    _ash_logger().warning(
        f"Severity threshold {_threshold_for_log(threshold)} is not one of "
        f"{', '.join(SEVERITY_THRESHOLDS)} (case-sensitive); it gates like "
        "CRITICAL, so only critical findings fail against it"
    )


def sarif_level_fails_threshold(level: Optional[str], threshold: Optional[str]) -> bool:
    """Return True when a SARIF result at *level* fails the gate at *threshold*.

    The SARIF-level view of :func:`severity_fails_threshold`, for callers that
    only have a SARIF ``result.level`` to work from. Remember that ``error``
    covers both CRITICAL and HIGH, so this cannot distinguish the two.

    Args:
        level: A SARIF level -- ``error``, ``warning``, ``note`` or ``none``.
            Case-insensitive. A missing or unrecognised value is read as
            :data:`MISSING_SARIF_LEVEL`. Accepts the str-backed ``Level`` enum
            as well as a plain string.
        threshold: As for :func:`severity_fails_threshold`.

    Returns:
        True if the finding should be treated as actionable.
    """
    if not threshold:
        return False
    severity = _SARIF_LEVEL_TO_SEVERITY[effective_sarif_level({"level": level})]
    return severity_fails_threshold(severity, threshold)


#: Resolves the threshold governing one scanner's findings from the scanner's
#: name as ``properties.scanner_name`` records it, ``None`` for a result that
#: names none. The answer is the threshold the gate compares against: the
#: scanner's own ``options.severity_threshold`` when it has one, else the
#: scan's (``global_settings.severity_threshold``, or the workspace project's);
#: a falsy answer turns the gate off for that scanner.
ScannerThresholdResolver = Callable[[Optional[str]], Optional[str]]


def result_scanner_name(result: object) -> Optional[str]:
    """``properties.scanner_name`` of *result* (a ``Result`` or its JSON form), or None.

    None for a result that names no scanner, or whose name is not a string: the
    attribution ASH carries is this one property, and a resolver given None
    answers with the scan-wide threshold, as ``_compute_exit_code`` judges a
    finding it cannot attribute.
    """
    if isinstance(result, dict):
        properties = result.get("properties")
    else:
        properties = getattr(result, "properties", None)
    if isinstance(properties, dict):
        name = properties.get("scanner_name")
    else:
        name = getattr(properties, "scanner_name", None)
    return name if isinstance(name, str) and name else None


def result_fails_scanner_threshold(
    result: object, threshold_for: ScannerThresholdResolver
) -> bool:
    """Whether *result* fails the gate of the scanner that reported it.

    The per-result question ``_compute_exit_code`` asks when it counts actionable
    findings: the threshold is the one *threshold_for* resolves for the result's
    scanner (:func:`result_scanner_name`), and the severity is
    :func:`result_severity`'s one reading. Shared by the single scan's
    ``--min-severity`` gate and the workspace project verdict so a finding the
    scanner's own threshold made non-actionable is read alike on both sides: not
    counted, and not the finding that keeps the count standing. The same findings
    exited 0 in ``ash --source-dir P`` and 2 for P inside a workspace while the
    workspace's gate judged severity alone.

    Suppressions are the caller's to read (``sarif_utils.suppressions_in_effect``;
    this module cannot import it): a suppressed result never reaches the gate.
    """
    return severity_fails_threshold(
        result_severity(result), threshold_for(result_scanner_name(result))
    )


def resolve_scanner_threshold(
    scanner_threshold: Optional[str], ash_config: object
) -> Tuple[str, str]:
    """The threshold a scanner is graded against, and where it came from.

    The scanner's own ``options.severity_threshold`` when it is set (source
    ``"config"``); otherwise ``global_settings.severity_threshold`` of
    *ash_config*, or ``ASH_DEFAULT_SEVERITY_LEVEL`` without a config (source
    ``"global"``).

    Shared by ``ScannerExecutor``, which grades each target's container and so
    writes the status in ``scanners/<name>/<target>/ASH.ScanResults.json``, and by
    ``ScannerStatisticsCalculator``, which the summary table, the scanner rows and
    the exit code read. Both need the fallback because None turns the gate off: a
    scanner with no threshold of its own, given only its own value, would be
    PASSED in its own report and FAILED in the summary against the global MEDIUM.

    A global threshold that is not a string (None, or a test's mock config, neither
    of which a validated config holds) is read as no config at all: it cannot reach
    the ladder as an unrecognised value, and None, which turns the gate off, is
    never returned. A scanner threshold that is not a string (a number, a boolean
    or a list in an external section) is read as unset in the same way: returned
    as given, a falsy one (0, False, an empty list) would turn the gate off.

    Both values are free text at this edge (an external plugin's section; a config
    built without validation), so both are normalized once here
    (:func:`normalize_threshold`): ``"high"`` grades as ``HIGH`` rather than as an
    unrecognised value that fails only CRITICAL, and a blank value, which would
    turn the gate off, is read as an unset one: a blank scanner value falls through
    to the global threshold, a blank global value to ``ASH_DEFAULT_SEVERITY_LEVEL``.
    A non-blank value off the ladder is returned as written, from either side: the
    summary row shows it, and the ladder grades it at its unrecognised rank.
    """
    # Only text can be a threshold: a number, a boolean or a list from an external
    # section is read as unset, like the global value below. Returned as given it
    # could be falsy (0, False, []), which turns the gate off, or reach the ladder
    # as a value it cannot rank.
    if isinstance(scanner_threshold, str):
        normalized = normalize_threshold(scanner_threshold)
        if normalized is not None:
            return normalized, "config"
        if scanner_threshold.strip():
            return scanner_threshold, "config"
    global_settings = getattr(ash_config, "global_settings", None)
    if global_settings is not None and hasattr(global_settings, "severity_threshold"):
        configured = global_settings.severity_threshold
        if isinstance(configured, str):
            normalized = normalize_threshold(configured)
            if normalized is not None:
                return normalized, "global"
            if configured.strip():
                return configured, "global"
    from automated_security_helper.core.constants import ASH_DEFAULT_SEVERITY_LEVEL

    return ASH_DEFAULT_SEVERITY_LEVEL, "global"
