"""UV tool runner utility for managing UV-based tool execution and installation."""

import contextlib
import contextvars
import math
import ntpath
import os
import random
import re
import signal
import subprocess  # nosec B404 — uv_tool_runner is the subprocess orchestrator for tool execution
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import (
    TYPE_CHECKING,
    Dict,
    Iterable,
    Iterator,
    List,
    NamedTuple,
    Optional,
    Any,
    Callable,
    Set,
    Tuple,
    Union,
)
from automated_security_helper.utils.process_env import (
    environ_for_parsed_output,
    snapshot_environ,
)

# Escape sequences (the CSI set -- color codes included -- and OSC) are
# removed from uv-written text before the redaction layers match it, because
# a code inside a requirement splits the contiguous text they read. One regex
# for the package: error_text owns it.
from automated_security_helper.utils.error_text import ESCAPE_CODES as _ESCAPE_CODES
from automated_security_helper.utils.redacted_model import value_tuple

from automated_security_helper.utils.subprocess_utils import (
    _STARTED_CHILD_ATTRIBUTE,
    _timeout_token,
    signal_death,
    spawn_run,
    watched_launch,
)

if TYPE_CHECKING:
    # Typing only: at runtime _type_keeping_the_flag imports these inside its
    # body, as the rest of this module imports subprocess_utils names.
    from automated_security_helper.utils.subprocess_utils import (
        CancelledProcess,
        PostRunErrorProcess,
        ResultRejectedProcess,
        SignaledProcess,
        SpawnFailedProcess,
        TimedOutProcess,
    )

    #: The CompletedProcess subtypes that keep a response's flag, each carrying
    #: the ``error`` and ``could_not_stop`` fields run_tool's conversion sets.
    _FlaggedProcess = Union[
        TimedOutProcess,
        CancelledProcess,
        SignaledProcess,
        ResultRejectedProcess,
        PostRunErrorProcess,
        SpawnFailedProcess,
    ]


# How often the install progress monitor calls back while an attempt is running.
# Named rather than inline because it is the monitor's only cadence knob, and the
# tests that assert the monitor covers a retried run have to shorten it -- the
# smallest ``timeout`` that starts a monitor at all is 61 seconds, so at the
# production cadence a test could observe exactly one callback per attempt.
_PROGRESS_UPDATE_INTERVAL_SECONDS = 10

# Passed to the uv subcommands ASH runs that read project configuration, right
# after the subcommand's own words (``uv pip install --no-config ...``). Measured
# with uv 0.12, every uv subcommand but ``uv tool`` reads ``uv.toml`` and
# ``pyproject.toml``'s ``[tool.uv]`` from the working directory and its parents,
# and ASH runs from inside the repository it is about to scan: with ``no-index``
# and ``find-links`` there, ``uv pip install`` put the repository's own wheel into
# ASH's environment. Repository configuration must not choose what ASH installs or
# runs (#784).
#
# Not passed to ``uv tool run``, ``uv tool install``, ``uv tool list`` or the
# version probes: uv itself ignores project files for ``uv tool`` commands (the
# planted-repository tests in tests/unit/utils/test_uv_ignores_repository_config.py
# guard that), and they read the user's and the system ``uv.toml``, which is where
# an operator points uv at an index mirror. ``--no-config`` would drop those too.
# ``uv cache`` runs from the filesystem root instead (``_run_uv_cache``), so it
# names the cache those tools use. ``uv --version`` reads no configuration at all.
UV_NO_CONFIG = "--no-config"


class UVToolRunnerError(Exception):
    """Exception raised for UV tool runner errors."""


_CHECKING_ONLY: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "ash_dependency_check_only", default=False
)


@contextlib.contextmanager
def checking_only() -> Iterator[None]:
    """Answer dependency questions in the enclosed code without installing anything.

    A scanner's ``validate_plugin_dependencies`` installs its tool with
    ``uv tool install`` when it is missing (bandit, checkov and semgrep do), and
    the version probe and ``get_uv_tool_command`` run ``uv tool run <tool>
    --version``, which downloads the tool into uv's cache when it is not there.
    Inside this, nothing installs and nothing downloads: the install is skipped,
    every ``uv tool run`` probe runs ``--offline``, and a probe's result is not
    remembered, because an offline miss is not the answer a scan would get. The
    scanner inventory runs its checks inside this (core/scanner_inventory.py). A
    context variable: a thread pool's workers see it only when each task runs in
    a copy of the caller's context.
    """
    token = _CHECKING_ONLY.set(True)
    try:
        yield
    finally:
        _CHECKING_ONLY.reset(token)


def is_checking_only() -> bool:
    """Whether the calling code runs inside :func:`checking_only`."""
    return _CHECKING_ONLY.get()


def _offline_for(offline: Optional[bool]) -> bool:
    """The offline mode a uv call runs under: ASH's own, or the caller's on top.

    A scanner's own ``options.offline: true`` puts that scanner offline while
    the rest of the run stays online (``ScannerPluginBase._scanner_offline``);
    its uv calls pass that as ``offline``. ASH's mode (``ASH_OFFLINE``) can be
    added to, never switched off: a caller passing False under ``ASH_OFFLINE``
    stays offline, as ``_scanner_offline`` documents ("cannot be switched off
    for one of them"). None, the default, is ASH's mode alone, which was the
    only mode uv saw before the parameter existed.
    """
    from automated_security_helper.core.constants import is_offline_mode

    return bool(offline) or is_offline_mode()


@dataclass
class UVToolRetryConfig:
    """Configuration for UV tool operation retry logic."""

    max_retries: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter: bool = True
    network_check_timeout: float = 5.0

    def __post_init__(self) -> None:
        """Clamp the schedule into a range that can actually be slept on.

        These values arrive from scanner config by way of
        ``UVToolMixin._install_uv_tool``, which builds this from a plain dict
        with ``.get(key, default)`` and validates nothing. A negative
        ``max_delay`` makes the computed interval negative, and ``time.sleep``
        raises ``ValueError`` on a negative argument -- which, raised from inside
        the install path, is indistinguishable to the caller from the install
        itself having failed.

        Normalizing rather than raising keeps one nonsensical knob from aborting
        a scan, and because it mutates the fields in place, the mixin's existing
        ``[INSTALLATION_CONFIG]`` debug line reports the values that will
        actually be used instead of the ones that were asked for.

        ``exponential_base`` floors at 1.0 rather than above it: 1.0 is a
        deliberate fixed-interval retry, which is a legitimate choice. Below 1.0
        the backoff would *shrink* between attempts, which never is.

        Normalizing means never raising: a knob that is None, a non-numeric
        string, NaN or infinite takes the field's default (``int()`` and
        ``float()`` used to raise TypeError or ValueError out of here, against
        this docstring's own promise), and every delay is bounded from above
        too (``_MAX_RETRY_DELAY_SECONDS``, ``_MAX_EXPONENTIAL_BASE``), because a
        delay ``time.sleep`` cannot take, or a power that overflows a float, is
        as unsleepable as a negative one.
        """
        self.max_retries = _bounded_int(self.max_retries, 3, 0, _MAX_RETRIES)
        self.base_delay = _bounded_float(
            self.base_delay, 1.0, 0.0, _MAX_RETRY_DELAY_SECONDS
        )
        # Ordered after base_delay so the cap can never sit below the floor.
        self.max_delay = _bounded_float(
            self.max_delay, 60.0, self.base_delay, _MAX_RETRY_DELAY_SECONDS
        )
        self.exponential_base = _bounded_float(
            self.exponential_base, 2.0, 1.0, _MAX_EXPONENTIAL_BASE
        )
        self.jitter = bool(self.jitter)
        self.network_check_timeout = _bounded_float(
            self.network_check_timeout, 5.0, 0.0, _MAX_RETRY_DELAY_SECONDS
        )


#: The longest a retry waits between install attempts, whatever the knobs say:
#: an hour, far past any useful backoff and far below what time.sleep refuses.
_MAX_RETRY_DELAY_SECONDS = 3600.0
#: The largest exponential base: a power of it over the retry count stays a
#: finite float, and above this the first retry already hits the delay cap.
_MAX_EXPONENTIAL_BASE = 1e6
#: The most retries a config can ask for.
_MAX_RETRIES = 1000


def _bounded_float(value: Any, default: float, floor: float, ceiling: float) -> float:
    """``value`` as a finite float within ``[floor, ceiling]``; ``default`` for a
    value that is not a number, NaN or infinite. Never raises."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = default
    if math.isnan(number) or math.isinf(number):
        number = default
    return min(max(number, floor), ceiling)


def _bounded_int(value: Any, default: int, floor: int, ceiling: int) -> int:
    """``value`` as an int within ``[floor, ceiling]``; ``default`` for a value
    that is not a number, NaN or infinite. Never raises."""
    try:
        number = int(float(value)) if isinstance(value, str) else int(value)
    except (TypeError, ValueError, OverflowError):
        number = default
    return min(max(number, floor), ceiling)


def _refused_by_sandbox(error: BaseException) -> bool:
    """Whether ``error`` is the scanner sandbox refusing a spawn, not the spawn failing."""
    from automated_security_helper.utils.sandbox.policy import SandboxUnavailable

    return isinstance(error, SandboxUnavailable)


def _install_retry_delay(config: UVToolRetryConfig, attempt: int) -> float:
    """Seconds to wait after 0-based ``attempt`` before the next install try.

    Exponential growth, capped at ``max_delay``, optionally jittered, and
    clamped non-negative.

    The ``max(0.0, ...)`` overlaps with ``UVToolRetryConfig.__post_init__``,
    which already guarantees ``max_delay >= base_delay >= 0``, and that overlap
    is deliberate rather than sloppy: ``UVToolRetryConfig`` is a plain *mutable*
    dataclass, so ``config.max_delay = -1`` after construction re-opens the hole
    that normalization closed. This clamp sits closest to ``time.sleep``, which is
    the only place the value actually has to be safe. Both guards are covered by
    tests that distinguish them -- see ``TestRetryDelayIsAlwaysSleepable``.

    The power is computed under the same rule: a base assigned after
    construction can overflow a float for a late attempt (``OverflowError`` out
    of the retry loop, as a failed install), so an overflowing or infinite
    growth reads as the cap, and the result is always a finite number no larger
    than ``_MAX_RETRY_DELAY_SECONDS``. Unless ``base_delay`` is zero: zero
    times an infinite growth is NaN, which read as the cap too, so a config
    asking for no wait between attempts slept ``max_delay`` from the attempt
    the power overflowed. A zero base stays zero.
    """
    try:
        growth = config.exponential_base**attempt
    except OverflowError:
        growth = math.inf
    delay = config.base_delay * growth
    if math.isnan(delay) or math.isinf(delay):
        delay = 0.0 if config.base_delay <= 0 else config.max_delay
    if config.jitter:
        delay += random.uniform(0, 1)  # nosec B311 — retry jitter, not security
    bounded = max(0.0, min(delay, config.max_delay, _MAX_RETRY_DELAY_SECONDS))
    return bounded if math.isfinite(bounded) else 0.0


def _sleep_between_attempts(seconds: float) -> None:
    """Wait ``seconds`` before the next install attempt, stopping at a cancel.

    A plain ``time.sleep`` could not be interrupted: a scan cancelled between two
    attempts went on waiting out the backoff before the cancel reached it. The
    wait polls the scan's cancel at the same interval the probe locks use.

    The chunks are counted from ``seconds``, never from a clock read back after
    each sleep: a wait that re-read the clock spun for the whole delay when the
    sleep returned early (a stubbed or coarse ``time.sleep``), handing it one
    chunk per spin. So ``time.sleep`` is handed exactly ``ceil(seconds / poll)``
    chunks that add up to ``seconds``, whatever the sleep does with them.
    """
    from automated_security_helper.core.cancellation import raise_if_cancelled

    total = max(0.0, seconds) if math.isfinite(seconds) else 0.0
    poll = _UV_PROBE_CANCEL_POLL_SECONDS
    for index in range(math.ceil(total / poll)):
        raise_if_cancelled()
        # Clamped at zero: a count one too high (the division and the
        # multiplication rounding apart) must not hand the sleep a negative.
        time.sleep(max(0.0, min(total - index * poll, poll)))
    raise_if_cancelled()


def _exit_description(result: Any) -> str:
    """How a run ended, in value-free words, for the run errors.

    ``result`` is a result object or exception carrying ``returncode``, and
    its RESPONSE_FLAGS are read before the code (here by truthiness; the
    related run_succeeded applies no order, it asks whether ANY flag is
    exactly True): a flagged result's code is ASH's fixed one, never the
    tool's own, so "the command exited 124" misreads a timeout and a rejected
    result's code describes nothing the tool did. "exited None" would read as
    nonsense for a child the stop did not end. A negative code goes through
    signal_death, which carries the platform gate this helper used to
    re-implement without.
    """
    if getattr(result, "timed_out", False):
        return "the command timed out"
    if getattr(result, "cancelled", False):
        return "the run was cancelled"
    if getattr(result, "result_rejected", False):
        return "ASH rejected the tool's result"
    if getattr(result, "spawn_failed", False):
        return "the command never started"
    returncode = getattr(result, "returncode", None)
    if returncode is None:
        return "the command did not exit"
    death = signal_death(returncode, "the command")
    if death is not None:
        number, _ = death
        return f"the command was ended by signal {number}"
    return f"the command exited {returncode}"


#: The most characters of uv-written text one debug record carries. The
#: sibling sites bound tool text the same way (the scanner's stderr excerpt at
#: 2000, the mixin's offline quote at 800); a failed sdist build can write a
#: multi-megabyte stderr, and an unbounded record went to the handler whole,
#: once per attempt.
_UV_OUTPUT_LIMIT = 2000

#: PEP 503's name alphabet: a requirement name is letters, digits and ".-_".
#: A name-shaped token is replaced only where neither neighbor is one of
#: these, so a hidden "toml" leaves "pyproject.toml" and a hidden "py"
#: leaves "python" alone.
_NAME_CHARS = "A-Za-z0-9._-"

#: The private-use block shown_uv_output borrows its placeholder marks from.
_MARK_FIRST = 0xE000
_MARK_LAST = 0xF8FF


def _free_marks(count: int, taken: Set[str]) -> Optional[List[str]]:
    """``count`` private-use characters that are not in ``taken``, or None.

    shown_uv_output writes each placeholder as one of these while it replaces
    the tokens, and spells the placeholders out afterwards, so a later token
    cannot be found inside an earlier placeholder's own text. None when the
    block holds fewer free characters than that (a text built to use them all).
    """
    found: List[str] = []
    for code in range(_MARK_FIRST, _MARK_LAST + 1):
        if len(found) == count:
            break
        if chr(code) not in taken:
            found.append(chr(code))
    return found if len(found) == count else None


def _spelled_parts(raw: Optional[str]) -> Tuple[Set[str], Set[str], Set[str]]:
    """One parse of a requirement-shaped string: (forms, names, versions).

    ``forms`` is every spelling uv can print for it: the string
    space-stripped; its PEP 440 canonical form when it is a bare version
    ("9.9.9-RC777" prints as "9.9.9rc777"); each specifier piece as written,
    space-stripped, and canonical (operator plus the parsed version); for a
    requirement, its name as written, PEP 503 normalized ("Ruamel.YAML"
    prints as "ruamel-yaml") and in the "_" file-name respelling of PEP 427
    and 625 ("pkg_aqz4bb"), plus -- with extras -- the glued "name[extras]"
    uv quotes without its constraint. ``names`` is the requirement-NAME
    subset of those forms, and ``versions`` the bare version parts of its
    PINNING specifiers (==, ===, ~=) -- a range bound is not a pin.
    One parse decides the precedence for all three: a Version-parseable
    string is a VERSION -- it has no name, even though the PEP 508 name
    grammar also happens to accept it ("9.9.9rc777") -- otherwise the string
    is specifier pieces, otherwise a requirement. A string no parser reads
    contributes its stripped self as a form only. uv's canonical spelling
    here is inferred from the PEPs, not measured against a real uv.
    """
    from packaging.requirements import InvalidRequirement, Requirement
    from packaging.specifiers import InvalidSpecifier, SpecifierSet
    from packaging.utils import canonicalize_name
    from packaging.version import InvalidVersion, Version

    forms: Set[str] = set()
    names: Set[str] = set()
    versions: Set[str] = set()
    if not raw:
        return forms, names, versions
    stripped = raw.replace(" ", "")
    if stripped:
        forms.add(stripped)
    try:
        version: Optional[Version] = Version(raw)
    except InvalidVersion:
        version = None
    if version is not None:
        forms.add(str(version))
        versions.add(str(version))
        return forms, names, versions
    try:
        specs = SpecifierSet(raw)
    except InvalidSpecifier:
        try:
            requirement = Requirement(raw)
        except InvalidRequirement:
            return forms, names, versions
        specs = requirement.specifier
        names.add(requirement.name)
        canonical_name = canonicalize_name(requirement.name)
        names.add(canonical_name)
        # Wheel and sdist FILE names respell "." and "-" in a package name
        # as "_" (PEP 427, PEP 625): "pkg.aqz4bb" downloads as
        # "pkg_aqz4bb-1.0-py3-none-any.whl", and a value glued inside one
        # segment of the name survives both the as-written and the PEP 503
        # tokens. The "_" form is a NAME, so it takes the same boundary
        # rules ("pyproject.toml" around a hidden "toml" stays whole).
        names.add(canonical_name.replace("-", "_"))
        if requirement.extras:
            # uv quotes an extra without its constraint ("Because
            # stub-tool[sarifqz4b] depends on sarif-om"): the glued
            # "name[extras]" is a spelling of the requirement, added as
            # written and canonical so every record site gets it from this
            # one parse. ``requirement.extras`` is a set, so the order the
            # SPEC wrote them in is read from the spec's own text between the
            # brackets and added beside the sorted order; which of the two a
            # real uv prints is inferred from the PEPs, not measured, so both
            # are forms.
            orders = [sorted(requirement.extras)]
            bracket = re.search(r"\[([^\]]*)\]", raw)
            if bracket is not None:
                as_written = [
                    extra.strip()
                    for extra in bracket.group(1).split(",")
                    if extra.strip()
                ]
                if as_written and as_written not in orders:
                    orders.append(as_written)
            for order in orders:
                forms.add(f"{requirement.name}[{','.join(order)}]")
                forms.add(
                    f"{canonical_name}"
                    f"[{','.join(canonicalize_name(extra) for extra in order)}]"
                )
        forms |= names
    for spec in specs:
        piece = str(spec).replace(" ", "")
        if piece:
            forms.add(piece)
        # Only PINNING operators contribute version parts: a pin's version IS
        # the env-read value printed back, while a range bound equal to a
        # value (">=1.7.4,<2" against an env-read "2") is a coincidence, and
        # matching it would hide the very constraint a resolver conflict is
        # about.
        pinning = spec.operator in ("==", "===", "~=")
        if pinning:
            trimmed = spec.version.replace(" ", "")
            versions.add(trimmed)
            # A wildcard pin's version part ends in ".*" ("==1.8.*"), and the
            # env-read value it carries is the base: the wildcard is stripped
            # so the pin still matches a value "1.8".
            if trimmed.endswith(".*"):
                versions.add(trimmed[:-2])
        try:
            canonical = Version(spec.version)
        except InvalidVersion:
            continue
        forms.add(f"{spec.operator}{canonical}")
        if pinning:
            versions.add(str(canonical))
    return forms, names, versions


def _spelled_forms(raw: Optional[str]) -> Set[str]:
    """The spellings uv can print for *raw*: _spelled_parts' forms half."""
    return _spelled_parts(raw)[0]


#: The public name importers use for a value's printable spellings.
spelled_forms = _spelled_forms


class UVInstallInputs(NamedTuple):
    """What a ``uv tool install`` and every record about it share.

    ``spec`` is the requirement uv installs -- built HERE, so the argv's
    spec and the spec the records hide are one string, and a change to the
    assembly (sorted extras, normalized whitespace) cannot make the hidden
    set stop matching what uv prints back. ``inputs`` are the plugin-built
    parts a record's shower hides, ``spec`` included.
    """

    spec: str
    inputs: Tuple[str, ...]


def uv_install_inputs(
    tool_name: str,
    version_constraint: Optional[str] = None,
    package_extras: Optional[List[str]] = None,
    with_dependencies: Optional[List[str]] = None,
) -> UVInstallInputs:
    """The spec of a ``uv tool install``, with the record set that hides it.

    One builder for the install itself and for every record about it -- the
    runner's argv and stderr debug line, and the mixin's installation-attempt
    record -- as ``_uv_run_inputs`` is for records about a run. uv respells
    and reorders a requirement's parts, so the set names each part
    separately: the full spec, the base spec (the name with its extras,
    without the constraint), the bare constraint, and each ``--with`` entry.
    A site assembling its own subset drifts from its siblings; the mixin's
    record carried only the spec and the constraint, so the two install
    records disagreed about the ``--with`` entries.

    The install's spec is deliberately NOT ``_uv_run_inputs``'s first
    element: an install names ``uv_tool_package_name`` where a run's
    ``--from`` spec can differ, which is why the install records have their
    own builder rather than one builder for every record site.
    """
    if package_extras:
        base_spec = f"{tool_name}[{','.join(package_extras)}]"
    else:
        base_spec = tool_name
    tool_spec = f"{base_spec}{version_constraint}" if version_constraint else base_spec
    return UVInstallInputs(
        spec=tool_spec,
        inputs=(
            tool_spec,
            *((base_spec,) if base_spec != tool_spec else ()),
            *((version_constraint,) if version_constraint else ()),
            *(with_dependencies or ()),
        ),
    )


def _holds_value(entry: str, value_spellings: Iterable[str]) -> bool:
    """Whether a plugin-built *entry* holds one of the caller's values.

    Two arms, used by BOTH deciders in shown_uv_output -- which inputs are
    hidden, and which hidden name tokens lose the name-boundary readability
    rule -- so the two cannot drift: the value layer's own match (the value
    inside the entry, boundary rules included), and the substring arm (a
    value of MIN_REDACTED_LENGTH or more characters glued into the entry,
    "qz4b" inside "pkgqz4b==1.0"). The structure arm (a pinned version part)
    is the hidden-input decider's own third arm, not part of this test.
    """
    from automated_security_helper.utils.error_text import text_without_values
    from automated_security_helper.utils.numeric_text import MIN_REDACTED_LENGTH

    return text_without_values(entry, value_spellings) != entry or any(
        len(value) >= MIN_REDACTED_LENGTH and value in entry
        for value in value_spellings
    )


def shown_uv_output(
    text: str,
    values: Optional[Iterable[str]],
    plugin_inputs: Iterable[Optional[str]] = (),
    tool_name: str = "",
    limit: Optional[int] = _UV_OUTPUT_LIMIT,
    pinned_versions: bool = True,
) -> str:
    """uv-written *text*, redacted, for a caller that is about to show it.

    The caller's values are matched once against the text as written, then
    escape codes are removed -- a code inside a requirement breaks the
    contiguous text both layers match -- then each value's whitespace
    respelling is normalized back to the value's own spelling (uv wraps a
    clause at a space with an indented continuation, which no whole-spelling
    match can see), then the caller's environment-read values are hidden in
    every spelling uv prints them in (_spelled_forms), then the plugin-built
    inputs are hidden by ORIGIN: with
    ``values`` None (no caller checked where its inputs came from) every
    input is hidden with all of its spellings by RAW replacement -- no
    boundary rules, a mangled neighboring word is the accepted price of
    unknown provenance -- plus each input's PINNED version parts (at name
    boundaries, so a hidden "1.2" leaves "1.2.3" whole) and the
    "<name>-<version>" file stems, because an env-read pin otherwise shows
    through uv's wheel and sdist file names (``pinned_versions`` False leaves
    those two out, for a tool's own ``--version`` answer, where the version
    is the answer and no file name is printed) -- while with an explicit
    iterable only the inputs
    that hold one of the values are hidden, so a builtin constraint, the
    very thing a resolver conflict is about, stays diagnosable. A hidden
    input is matched as written AND as the value layer has just respelled it
    (its values replaced by that layer's placeholder): the layer ran first,
    so the input's own spelling is already gone from the text, and matching
    only that spelling left the rest of the input -- a repository path, an
    index URL -- in clear around the hidden value. The contract
    behind that: ``values`` is the run's COMPLETE env-read set (the same set
    redact_values is given), so a plugin that reads the environment itself
    must add the value through _environment_values(), or an input built from
    that read fails the holds-a-value filter and prints at DEBUG, value
    included. This function cannot enforce that contract; the builtin
    scanners' environment reads are pinned to a justified list by the audit
    in tests/unit/utils/test_uv_tool_runner.py. Whether an input holds a
    value is decided by the SAME matcher the value layer redacts with
    (text_without_values over the value's spellings), boundary rules
    included; OR by the substring arm, a value of MIN_REDACTED_LENGTH or more
    characters sitting anywhere inside the input, so "qz4b" glued into
    "pkgqz4b==1.0" still hides it; OR by the structure arm, a value of any
    length that equals or canonicalizes to a PINNED version part (==, ===,
    ~=) of one of the
    input's specifiers, so the env-read pin "1.8" hides "bandit==1.8".
    Below the substring floor an unstructured fragment decides nothing: a raw
    substring test with no floor let a short unrelated value such as "4" hide
    the builtin ">=1.7.4,<2", the visibility-flips-on-unrelated-config
    problem over again. A whole-constraint value is never a substring of its
    own pieces, which is why the filter reads the input, not the token. The
    tool's name is never replaced BY THE INPUT LAYER -- it is public and
    every anchor a reader searches for, so it is discarded from the input
    tokens -- but the value layer still redacts an env-read value that
    happens to spell it, because a value must not leak just because it
    collides with public text. The result keeps its TAIL at ``limit``
    characters
    (_UV_OUTPUT_LIMIT unless the caller bounds its own text and passes None)
    -- uv's conclusion and hints come last -- behind a marker counting what
    was dropped.

    This is redaction only. Display neutralization (one record, one line, no
    obeyed controls) belongs to the sink: a log call site wraps its whole
    record in shown_on_one_line once, and a report message keeps its own
    line breaks. A token a remaining control or line break splits is not
    matched; the install runs under environ_for_parsed_output so uv is not
    expected to produce either.
    """
    from automated_security_helper.utils.error_text import text_without_values
    from packaging.utils import canonicalize_name

    checked = None if values is None else value_tuple(values)
    value_spellings = list(checked or ())
    for value in checked or ():
        for form in _spelled_forms(value):
            if form and form not in value_spellings:
                value_spellings.append(form)
    # The text as written is matched BEFORE its codes are stripped, as
    # shown_tool_stderr does: a value that itself holds a code is matched in
    # its as-written spelling, which earns it the band its length and
    # characters give it. Stripping first would leave only the stripped
    # spelling to match, and a short word of that kind glued to word
    # characters would print.
    # Every complete escape code, not only color, is then stripped: a
    # non-color code inside a value splits the match the same way, and the
    # neutral layer strips the same set (error_text.shown_tool_stderr).
    shown: str = _ESCAPE_CODES.sub("", text_without_values(text, value_spellings))
    for spelling in value_spellings:
        words = spelling.split()
        if len(words) > 1:
            # uv wraps a clause at a SPACE with an indented continuation, so
            # a multi-word value can sit in the text with one of its spaces
            # respelled as a line break plus indent, which no whole-spelling
            # match can see. A wrapped NON-LAST cause of an error chain is
            # continued under a drawn column -- an indented U+2502, or its
            # ASCII bar fallback -- between the break and the next word, so
            # the separator admits one such glyph between whitespace runs.
            # Each such respelling is normalized back to the
            # value's OWN spelling (not a collapsed form): the layer matches
            # values as given, so a value that itself holds a line break must
            # come back with its break, not a space. This lives HERE so every
            # uv-text sink gets it, not only the cause extraction. A callable
            # replacement, so a backslash in the value is not read as a group
            # reference.
            def _own_spelling(
                _match: "re.Match[str]", _spelling: str = spelling
            ) -> str:
                return _spelling

            shown = re.sub(
                r"\s+(?:[│|]\s+)?".join(re.escape(word) for word in words),
                _own_spelling,
                shown,
            )
    shown = text_without_values(shown, value_spellings)
    inputs = [entry for entry in plugin_inputs if entry and entry != tool_name]
    if checked is None:
        hidden_inputs = inputs
    else:
        # Three arms decide whether an input is hidden. One matcher with the
        # value layer: an input holds a value where that layer would hide the
        # value inside it, boundary rules included. The substring arm: a
        # value of MIN_REDACTED_LENGTH or more characters glued into an input
        # ("qz4b" inside "pkgqz4b==1.0") hides it too -- the input is hidden
        # whole, so the arm costs only debug readability, and values below
        # the floor stay out, the same line the value layer draws. The
        # structure arm: a value of ANY length that equals, or PEP 440
        # canonicalizes to, a PINNED version part of one of the input's
        # specifiers (==, ===, ~= -- a range bound is not a pin)
        # hides it ("1.8" built into "bandit==1.8"), which separates an
        # env-read pin from an unrelated fragment such as "4" inside
        # ">=1.7.4,<2".
        hidden_inputs = []
        for entry in inputs:
            entry_versions = _spelled_parts(entry)[2]
            if _holds_value(entry, value_spellings) or entry_versions.intersection(
                value_spellings
            ):
                hidden_inputs.append(entry)
    tokens: Set[str] = set()
    name_tokens: Set[str] = set()
    for entry in hidden_inputs:
        tokens.add(entry)
        entry_forms, entry_names, entry_versions = _spelled_parts(entry)
        tokens |= entry_forms
        if checked is not None:
            # The name-boundary readability rule applies only where the
            # caller CHECKED provenance. With values None nobody did, so
            # hide-all means hide-all: raw replacement, mangled neighbors
            # accepted, because "-" in a dist file name and "." at a
            # sentence's end are name characters a boundary match skips.
            name_tokens |= entry_names
        elif pinned_versions:
            # With values None every plugin-built argument is hidden, and an
            # env-read pin shows through more than the entry's own spellings:
            # uv also prints the wheel or sdist FILE name, where the bare
            # pinned version sits between "-" separators
            # ("<name>-9.9.9-py3-none-any.whl"). So the PINNING version
            # parts of the entry are hidden too. A bare version is made of
            # name characters, and a raw replacement would mangle every
            # longer version that contains it ("1.2" inside "1.2.3"), so it
            # takes the name-boundary rule -- and the file names that rule
            # cannot see into (the version's neighbors there are name
            # characters) are covered by hiding the file stem,
            # "<name>-<version>" for each name spelling, as its own raw
            # token.
            tokens |= entry_versions
            name_tokens |= entry_versions
            for version in entry_versions:
                for name in entry_names:
                    tokens.add(f"{name}-{version}")
    if tool_name:
        # Every spelling of the tool's own name the input layer could have
        # gained from a hidden input, the wheel-name "_" respelling included:
        # a traceback's "No module named 'detect_secrets'" names the tool,
        # and replacing it both breaks the never-replace-the-tool's-name rule
        # and shifts the argument numbering.
        canonical_tool = canonicalize_name(tool_name)
        for spelling in (tool_name, canonical_tool, canonical_tool.replace("-", "_")):
            tokens.discard(spelling)
            name_tokens.discard(spelling)
    plugin_built = sorted(
        (token for token in tokens if token),
        # Longest first so one token cannot split another; lexicographic
        # second so the <argument N> numbering is the same in every process
        # (set order is not).
        key=lambda token: (-len(token), token),
    )
    # The value layer ran first, so a token that holds a value no longer reads
    # as written in ``shown``: the value inside it reads as the value layer's
    # placeholder, and a replace of the token's own spelling finds nothing,
    # leaving the REST of the input (a repository path, an index URL) in clear
    # around a hidden value. Each such token is therefore also matched in that
    # respelled form -- the token with its values hidden the way the layer hid
    # them in the text (the same function, the same spellings). A token the
    # layer eats whole (the input IS the value, or values glued together)
    # respells to the bare placeholder and is left out: replacing that would
    # re-label every hidden value in the text as an argument.
    respelled: Dict[str, str] = {}
    if value_spellings:
        from automated_security_helper.config.config_validator import REDACTED

        for token in plugin_built:
            hidden_form = text_without_values(token, value_spellings)
            if hidden_form != token and hidden_form.replace(REDACTED, ""):
                respelled[token] = hidden_form
    # Each placeholder is written as one private-use character that neither
    # the text nor a token holds, and spelled out after the last replacement.
    # A later token can then never be found inside an earlier placeholder's
    # own text: the bare pin "1" of "pk01==1" matched inside
    # "<argument 1 not shown>" and renumbered it. With every character of the
    # block taken (a text built to use them up) the placeholders are written
    # out as the tokens are replaced.
    marks = _free_marks(
        len(plugin_built), set(shown).union(*plugin_built, *respelled.values())
    )
    for position, token in enumerate(plugin_built, start=1):
        placeholder = (
            marks[position - 1] if marks else f"<argument {position} not shown>"
        )
        if token in respelled:
            # A token that holds a value is replaced wherever it appears (the
            # arm below), so its respelled form is too: the form holds the
            # value layer's placeholder, a spelling no name boundary applies to.
            shown = shown.replace(respelled[token], placeholder)
        if token in name_tokens and not _holds_value(token, value_spellings):
            # A name is made of word characters, so a raw substring replace
            # mangles every word that contains it ("toml" inside
            # "pyproject.toml"): names are replaced only at requirement-name
            # boundaries. EXCEPT a name that itself holds an env-read value
            # -- one the value layer would hide inside it (the same matcher
            # the holds-a-value arm uses), or one of the substring arm's
            # floor or more characters glued anywhere in it ("pkgqz4b" with
            # "qz4b" env-read): the boundary rule would leave that name in a
            # file name ("pkgqz4b-1.0.tar.gz", where "-" and "." are name
            # characters), value and all, so such a name is replaced
            # wherever it appears.
            shown = re.sub(
                f"(?<![{_NAME_CHARS}]){re.escape(token)}(?![{_NAME_CHARS}])",
                placeholder,
                shown,
            )
        else:
            shown = shown.replace(token, placeholder)
    if marks:
        shown = shown.translate(
            {
                ord(mark): f"<argument {position} not shown>"
                for position, mark in enumerate(marks, start=1)
            }
        )
    if limit is not None and len(shown) > limit:
        dropped = len(shown) - limit
        # Sliced from the front, not with a negative index: ``shown[-0:]`` is
        # the whole text, so ``limit=0`` kept everything behind a marker that
        # claimed every character was dropped.
        shown = f"(first {dropped} characters not shown) " + shown[len(shown) - limit :]
    return shown


def _canonical(name: str) -> str:
    """``name`` as PEP 503 compares package names (case and separator folded)."""
    from packaging.utils import canonicalize_name

    return canonicalize_name(name)


def _requirement_name(spec: str) -> Optional[str]:
    """The package ``spec`` names, read off the requirement; None when it is not one.

    A caller's ``package_name`` may be a bare name or carry its constraint and
    extras ("nbconvert>=7.16.0,<8.0.0"): the package the spec is held to is the
    name inside it, never the string whole. None leaves ``checked_requirement``
    to refuse the spec in its own words.
    """
    from packaging.requirements import InvalidRequirement, Requirement

    try:
        return Requirement(spec).name
    except InvalidRequirement:
        return None


def checked_requirement(
    spec: str, naming: str = "a tool requirement", *, package: Optional[str] = None
) -> str:
    """``spec`` if it names a package from an index; UVToolRunnerError otherwise.

    Every requirement uv installs or runs here is assembled from a package name, the
    plugin's extras and the plugin's ``tool_version``. The options validate
    ``tool_version`` already (``base/options.tool_version_constraint``); this is
    the check at the point of use, so a plugin that builds its constraint some
    other way still cannot hand uv a path, a URL or an environment marker.

    ``package`` is the name the caller assembled ``spec`` around, when it knows
    it. The parsed requirement must then still name that package: a constraint
    glued onto the name without an operator ("bandit" + "2") parses as a valid
    requirement for another package, ``bandit2``, and the specifier check alone
    lets it through to the index.

    ``naming`` is the caller's fixed, value-free words for WHICH requirement
    was refused ("the tool spec", "--with dependency 2", "the --from spec for
    bandit"): a refusal that names nothing leaves the operator with three
    candidate entries and no way to tell which to fix.
    """
    from packaging.requirements import InvalidRequirement, Requirement
    from packaging.utils import canonicalize_name

    from automated_security_helper.utils.pre_installed_tool import (
        validate_version_constraint,
    )

    try:
        requirement = Requirement(spec)
        if requirement.url or requirement.marker:
            raise ValueError("a direct reference or marker")
        if package is not None and canonicalize_name(
            requirement.name
        ) != canonicalize_name(package):
            raise ValueError("a requirement for another package")
        validate_version_constraint(str(requirement.specifier))
    except (InvalidRequirement, ValueError):
        # The message carries no part of the spec: a plugin-built constraint
        # can hold a value its config read from the environment, this error's
        # text reaches logs, and neither this function nor the runner holds
        # the values to redact it with. ``naming`` is the caller's own fixed
        # words, never the spec; callers that know the tool name it there.
        raise UVToolRunnerError(
            f"Refusing to pass {naming} to uv: it must be a package "
            "name with optional extras and a PEP 440 version specifier"
        ) from None
    return spec


def _type_keeping_the_flag(
    response: Dict[str, Any],
) -> Optional[Callable[..., "_FlaggedProcess"]]:
    """The CompletedProcess type that keeps a response's flag, with its error,
    through run_tool's conversion, or None for a response without one.

    A timeout or a cancel comes first: neither is ever turned into a post-run
    error, and a later failure only adds to its error. A rejected result comes
    next: its code is ASH's fixed one, never the code the result claimed, so a
    signal read from a code is no ending of the tool's there. A signal death
    comes after that: its code is negative, and no other type says why.
    """
    from automated_security_helper.utils.subprocess_utils import (
        CancelledProcess,
        PostRunErrorProcess,
        ResultRejectedProcess,
        SignaledProcess,
        SpawnFailedProcess,
        TimedOutProcess,
    )

    if response.get("timed_out"):
        return TimedOutProcess
    if response.get("cancelled"):
        return CancelledProcess
    if response.get("result_rejected"):
        return ResultRejectedProcess
    if response.get("post_run_error") and response.get("signaled"):
        # Both at once: the tool died by its own signal, and ASH then failed
        # after it. PostRunErrorProcess carries both flags; SignaledProcess
        # would drop the post-run error, and the mixin would read ASH's own
        # failure as the tool's ending alone. A timeout, a cancel or a rejected
        # result still comes first: none is ever turned into a post-run error.
        return PostRunErrorProcess
    for flag, kept in (
        ("signaled", SignaledProcess),
        ("post_run_error", PostRunErrorProcess),
        ("spawn_failed", SpawnFailedProcess),
    ):
        if response.get(flag):
            return kept
    return None


#: How long a probe failure that is not uv's own answer -- a timeout, or a
#: child killed by a signal; every other failure is retried on the very
#: next call -- suppresses re-probing. Long enough that a hung uv does not
#: cost the probe timeout on every call, short enough that a recovered uv
#: is noticed within the window. Kept per active sandbox scope (see
#: ``is_uv_available``), because the probe runs inside the scanner's scope
#: and one scope's hung wrapper is not another caller's answer.
_UV_PROBE_RETRY_SECONDS = 60.0

#: How often a thread parked on the probe lock looks for its own scan's
#: cancel. A scan cancelled while its thread waits behind another caller's
#: hung probe must stop within this interval, not after that probe's
#: timeout; between polls the wait costs nothing.
_UV_PROBE_CANCEL_POLL_SECONDS = 0.2


def _signal_name(number: int) -> str:
    """The signal's name when the platform knows it, else its number."""
    try:
        return signal.Signals(number).name
    except ValueError:
        return str(number)


def _probe_scope_key() -> Any:
    """The failure domain the availability probe runs in.

    None outside any sandbox scope. The backend's name under a
    SandboxScope: every scanner on one backend shares the wrapper whose
    hang or kill opened a retry window, and a caller outside that backend
    does not. A RefusingScope is keyed by its scanner's name, defensively:
    its probes are refused before anything spawns (the OSError arm, which
    opens no window), so no entry is expected under such a key.
    """
    from automated_security_helper.utils.sandbox.scope import active_scope

    scope = active_scope()
    if scope is None:
        return None
    backend = getattr(scope, "backend", None)
    if backend is not None:
        return ("backend", getattr(backend, "name", "") or type(backend).__name__)
    return ("refusing", getattr(scope, "scanner_name", ""))


def _probe_share_key() -> Any:
    """The identity under which a finished probe's PER-CALL answer is shared.

    Narrower than ``_probe_scope_key`` on purpose. The retry window is keyed
    by backend, because a wrapper's hang or kill is that backend's weather.
    A per-call failure is often one scanner's own -- a sandbox refusal names
    that scanner's results and output directories -- so the unmemoized,
    unwindowed answer is shared only between callers in the SAME scope (the
    same object), or callers equally outside any scope (None). A waiter from
    another scanner's scope on the same backend probes its own call instead
    of reporting a neighbor's refusal as its availability.
    """
    from automated_security_helper.utils.sandbox.scope import active_scope

    return active_scope()


class UVToolRunner:
    """UV tool runner for managing UV-based tool execution and installation."""

    def __init__(self, uv_executable: Optional[str] = None):
        """Initialize UV tool runner.

        Args:
            uv_executable: The uv to run. When omitted, the one ``find_uv_or_none``
                resolves, read when it is first needed: the uv installed with ASH,
                then one on PATH. A bare ``"uv"`` was the default until the runner
                looked beside the interpreter, and only PATH can resolve that.
        """
        self._uv_executable = uv_executable
        self._uv_available_cache: Optional[bool] = None
        # The sandbox's refusal of this thread's last check, which was not cached;
        # see unavailable_reason. Per thread: the runner is shared by the process,
        # and each scanner's checks run under that scanner's own scope.
        self._checks = threading.local()
        # The executable the memo above and the windows below were probed
        # from. The getter re-resolves uv on every call (find_uv_or_none),
        # and the production runner is built bare, so the answers must be
        # keyed to what was probed: a uv that appears in the ASH bin dir or
        # on PATH after a miss, or one that disappears after a hit, is a
        # different question, and the other executable's memory is then
        # forgotten and the current one probed.
        self._uv_probed_executable: Optional[str] = None
        # (monotonic deadline, the opening probe's failure text) before
        # which a costly failed probe is not repeated, keyed by
        # _probe_scope_key(); empty until a probe times out or dies on a
        # signal. Keyed because the probe runs inside the scanner's sandbox
        # scope: a wrapper's hang or kill is that scope's weather, not
        # uv's, and must not answer False for a caller probing outside it
        # (the same boundary the scope-refusal arm draws). The failure text
        # travels WITH the window, so an answer from it names the cause
        # that opened it, not whatever probe failed last anywhere.
        self._uv_probe_retry_windows: Dict[Any, Tuple[float, Optional[str]]] = {}
        # The count of completed probes, and the last probe's question and
        # answer ((share key, executable, answer); the share key is the
        # probing call's scope OBJECT, or None outside any scope, see
        # _probe_share_key). A thread that waited on the lock while another
        # caller probed takes that probe's answer when it asked the same
        # question, instead of re-probing in turn: a slowly failing probe
        # (one whose outcome is neither memoized nor windowed) would
        # otherwise make the k-th of k waiters pay for k probes.
        self._uv_probe_generation = 0
        # ... the tuple also carries the probe's failure text (None on
        # success or plain absence), so a waiter that takes the shared
        # answer is handed the failure that belongs to it.
        self._uv_last_probe: Optional[Tuple[Any, str, bool, Optional[str]]] = None
        # Scope keys whose open retry window has logged its warning: the
        # window answers every caller for its length, and one warning per
        # window names it without a line per answered call. A key is
        # discarded (re-armed) whenever its window is opened again.
        self._uv_probe_window_warned: Set[Any] = set()
        # Held across the availability probe, so a second thread arriving
        # while uv hangs waits for the first probe's answer instead of
        # starting its own hung probe. The memo is per instance, so the
        # lock is too; the keyed registry below serves the module caches.
        self._uv_probe_lock = threading.Lock()

    @property
    def uv_executable(self) -> str:
        if self._uv_executable:
            return self._uv_executable
        return find_uv_or_none() or "uv"

    @uv_executable.setter
    def uv_executable(self, value: Optional[str]) -> None:
        # A different executable is a different question: the memoized
        # answer and the retry windows belong to the one that was probed.
        # The keying by probed executable would catch a stale answer on the
        # next call anyway; resetting here keeps the state honest at once.
        # Taken under the probe lock, so an in-flight probe's answer for
        # the old executable cannot land after the reset.
        with self._uv_probe_lock:
            self._uv_executable = value
            self._uv_probed_executable = None
            self._uv_available_cache = None
            self._uv_probe_retry_windows.clear()
            self._uv_probe_window_warned.clear()
            self._uv_last_probe = None

    def unavailable_reason(self) -> str:
        """Why this thread's last availability check returned False, for a message.

        "UV is not available", unless a scanner-sandbox refusal was recorded on
        this thread; a caller that has to say why uv did not run reads
        :meth:`uv_availability`, whose answer carries the probe's own failure.
        """
        refusal = getattr(getattr(self, "_checks", None), "refusal", None)
        if refusal is not None:
            return f"The scanner sandbox refused to run uv ({refusal})"
        return "UV is not available"

    def _check_state(self) -> threading.local:
        checks = self.__dict__.get("_checks")
        if checks is None:  # an instance made without __init__, as some tests do
            checks = self._checks = threading.local()
        return checks

    def is_uv_available(self) -> bool:
        """Whether uv is available: the first element of :meth:`uv_availability`.

        Callers that only gate on availability use this. A caller that has to
        say why uv did not run reads :meth:`uv_availability`, which returns
        the answer and its reason from one probe.
        """
        return self.uv_availability()[0]

    def uv_availability(self) -> Tuple[bool, Optional[str]]:
        """Check if UV is available on the system, and why not when it is not.

        Returns ``(available, failure)``. ``failure`` is the probe's failure
        in words ("the probe timed out after 10 seconds"), for the caller that
        has to say why uv did not run: "uv is not available" alone reads as
        "uv is not installed", while the probe may have timed out, died on a
        signal, or been refused by the sandbox scope. It is None when the
        probe succeeded, and None when the executable is simply absent,
        because then "not available" is the whole truth. The text travels
        with the answer instead of being left in a slot to read afterward, so
        it belongs to the call that returned it on any thread: an answer from
        the retry window carries the failure that OPENED that window, and a
        shared answer carries the finished probe's own failure. A False that
        comes with a failure is a probe that failed, which is not the same
        as a uv that is absent.

        Memoized for the process only on uv's definite answers: the probe
        exited 0 (present), or the executable is not there to run (absent).
        One runner lives for the whole process (the MCP server's, for
        instance), so a cached no-answer failure would mark uv unavailable
        for the life of the process while uv works fine.

        The memo belongs to the executable that was probed. The getter
        re-resolves uv on every call, so when it names another executable
        (a uv installed into the ASH bin dir or onto PATH after a miss, or
        one that disappeared after a hit), the remembered answer and the
        windows are forgotten and the current executable is probed.

        Only the failures whose retry is expensive wait out
        ``_UV_PROBE_RETRY_SECONDS``: a timed out probe (retrying costs the
        probe timeout again) and one killed by a signal (its negative code
        is the signal's, never uv's; an OOM kill tends to repeat). The
        window is kept per active sandbox scope (``_probe_scope_key``):
        the probe runs inside the scanner's scope, so a sandbox wrapper
        that hangs or is killed opens the window for that scope's callers
        only, and a probe outside it still runs. An answer from the window
        logs a warning naming it, so the refusal does not read as "uv is
        not installed".

        Every other failure answers False for that call only and is probed
        again on the next one, because its retry is one short failed spawn
        rather than another probe timeout: a transient OS error from the
        spawn, a sandbox scope's refusal (``SandboxUnavailable``, the
        scope's answer rather than uv's), and any completed exit code that
        is not uv's answer (75 means "try again"; a sandbox wrapper's own
        exit is not uv's). None of these touch the cache or the window, so
        one EAGAIN during a parallel spawn burst does not answer
        "unavailable" for the window's length.

        The probe runs under a per-runner lock, with three waiting rules.
        A thread arriving while a probe is in flight waits for its answer
        instead of starting its own, so a hung uv costs one probe timeout,
        not one per caller. A waiter that asked the same question (same
        executable, same scope -- the same scope OBJECT, not merely the
        same backend, because a per-call failure is often one scanner's
        own refusal) takes the finished probe's answer even when
        that answer was neither memoized nor windowed, so a slowly failing
        probe costs its waiters one probe, not one each. And a waiter whose
        own scan is cancelled stops within ``_UV_PROBE_CANCEL_POLL_SECONDS``
        and raises ``ScanCancelled`` instead of waiting the probe out and
        answering as if the scan were still running.
        """
        from automated_security_helper.core.cancellation import raise_if_cancelled

        raise_if_cancelled()
        # This thread's last refusal belongs to its last check: unavailable_reason
        # names a refusal only when the check that answered False was refused.
        checks = self._check_state()
        checks.refusal = None
        # Read once per call: the getter re-resolves, and one call must ask
        # one executable one question.
        executable = self.uv_executable
        scope_key = _probe_scope_key()
        share_key = _probe_share_key()
        answer = self._uv_answer_without_a_probe(executable, scope_key)
        if answer is not None:
            return answer
        # Read before taking the lock: a change while this thread waited
        # means another caller's probe finished in between.
        generation_before = self._uv_probe_generation
        while not self._uv_probe_lock.acquire(timeout=_UV_PROBE_CANCEL_POLL_SECONDS):
            # Parked behind another caller's probe. This scan's cancel has
            # to reach the thread now, not after that probe's timeout.
            raise_if_cancelled()
        try:
            raise_if_cancelled()
            answer = self._uv_answer_without_a_probe(executable, scope_key)
            if answer is not None:
                return answer
            if self._uv_probe_generation != generation_before:
                last = self._uv_last_probe
                if last is not None and last[0] is share_key and last[1] == executable:
                    # The probe this thread waited behind asked the same
                    # question, so its per-call answer is this call's
                    # answer: re-probing here would make the k-th of k
                    # waiters pay for k probes. Its failure travels with
                    # it, so the waiter's caller quotes the probe it was
                    # answered by.
                    return last[2], last[3]
            if (
                self._uv_probed_executable is not None
                and self._uv_probed_executable != executable
            ):
                # Another executable's memo, windows and last answer are
                # not this one's: forget them before probing this one.
                self._uv_available_cache = None
                self._uv_probe_retry_windows.clear()
                self._uv_probe_window_warned.clear()
                self._uv_last_probe = None
            self._uv_probed_executable = executable

            def _answered(
                outcome: bool, failure: Optional[str] = None
            ) -> Tuple[bool, Optional[str]]:
                # Every completed probe is recorded for the waiters that
                # arrived during it; an exception that escapes (a cancel)
                # records nothing, so no waiter takes a non-answer. The
                # failure rides along in the returned pair and in the
                # record the waiters are answered from.
                self._uv_probe_generation += 1
                self._uv_last_probe = (share_key, executable, outcome, failure)
                return outcome, failure

            def _failed(failure: str, then: str) -> Tuple[bool, Optional[str]]:
                # The failing call itself says what happened: a bare False
                # surfaces downstream as "uv is not available", which reads
                # as "uv is not installed" when the real cause was a timeout,
                # a signal or a refused spawn. The failure text carries
                # exception text verbatim; its only input today is the
                # operator's own uv path (every production runner is built
                # bare, so nothing config- or environment-resolved reaches
                # the executable), so no third-party value can ride it. If a
                # production route ever sets uv_executable from a config or
                # the environment, this text needs the caller's redaction
                # before it is logged or remembered.
                from automated_security_helper.utils.log import ASH_LOGGER

                ASH_LOGGER.warning(
                    f"The uv availability probe failed: {failure}; {then}."
                )
                return _answered(False, failure)

            try:
                result = spawn_run(  # nosec B603 — list args, validated uv executable path
                    [executable, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                    env=snapshot_environ(),
                    encoding="utf-8",
                    errors="replace",
                )
            except FileNotFoundError:
                from automated_security_helper.utils.subprocess_utils import (
                    in_tree_refusal,
                )

                refusal = in_tree_refusal(executable)
                if refusal is not None:
                    # The spawn layer refused this uv for lying inside the
                    # scanned tree (subprocess_utils._resolve_for_spawn raises
                    # the FileNotFoundError subprocess raises for a missing
                    # program). That is this scan's refusal of this copy, not
                    # uv's absence: remembered as absence it answered False for
                    # the rest of the process, scans of other trees included.
                    # Answered for this call only; another scope probes again.
                    return _failed(
                        f"the probe's spawn was refused: {refusal}",
                        "the next call probes again",
                    )
                if scope_key is not None:
                    # Raised from inside a sandbox scope, where the wrapper's
                    # view of the filesystem decides what can be found: a uv
                    # the backend does not mount is absent THERE, not on the
                    # host, and remembering that as uv's absence answered False
                    # for the rest of the process to every caller outside the
                    # scope. Answered for this call only.
                    return _failed(
                        "the probe's program was not found from inside the "
                        "sandbox scope",
                        "the next call probes again",
                    )
                # "Not available" is the whole truth here: nothing to name.
                self._uv_available_cache = False
                return _answered(False)
            except subprocess.TimeoutExpired as error:
                failure = f"the probe timed out after {error.timeout} seconds"
                self._uv_probe_retry_windows[scope_key] = (
                    time.monotonic() + _UV_PROBE_RETRY_SECONDS,
                    failure,
                )
                self._uv_probe_window_warned.discard(scope_key)
                return _failed(
                    failure,
                    "callers in this scope answer from the retry window "
                    "until it passes",
                )
            except OSError as error:
                # A failed spawn, SandboxUnavailable (the active scope's
                # refusal) among them: not uv's answer, and its retry is one
                # short failed spawn, not a probe timeout. No cache, no
                # window.
                if _refused_by_sandbox(error):
                    checks.refusal = str(error)
                return _failed(
                    f"the probe's spawn failed with {type(error).__name__}: {error}",
                    "the next call probes again",
                )
            except Exception as error:
                return _failed(
                    f"the probe raised {type(error).__name__}: {error}",
                    "the next call probes again",
                )
            if result.returncode < 0:
                # The signal's answer, not uv's; its sender tends to repeat.
                failure = (
                    "the probe's child died on signal "
                    f"{_signal_name(-result.returncode)}"
                )
                self._uv_probe_retry_windows[scope_key] = (
                    time.monotonic() + _UV_PROBE_RETRY_SECONDS,
                    failure,
                )
                self._uv_probe_window_warned.discard(scope_key)
                return _failed(
                    failure,
                    "callers in this scope answer from the retry window "
                    "until it passes",
                )
            if result.returncode != 0:
                # A completed exit that is not uv's answer: probed again on
                # the next call.
                return _failed(
                    f"the probe exited {result.returncode}, which is not uv's answer",
                    "the next call probes again",
                )
            self._uv_available_cache = True
            return _answered(True)
        finally:
            self._uv_probe_lock.release()

    def _uv_answer_without_a_probe(
        self, executable: str, scope_key: Any
    ) -> Optional[Tuple[bool, Optional[str]]]:
        """The memoized answer, this scope's window's False, or None to probe.

        Both answers belong to the executable they were probed from: for any
        other *executable* there is no answer, and the caller probes (and,
        under the lock, forgets the other executable's memory first). Only a
        probe records the executable, so an answer written directly onto the
        memo (the test seam ``runner._uv_available_cache = True``) carries
        none and answers for whatever the getter resolves.
        """
        if (
            self._uv_probed_executable is not None
            and self._uv_probed_executable != executable
        ):
            return None
        if self._uv_available_cache is not None:
            # A memoized definite answer carries no failure: the probe
            # succeeded, or the executable is simply absent.
            return self._uv_available_cache, None
        window = self._uv_probe_retry_windows.get(scope_key)
        if window is not None and time.monotonic() < window[0]:
            # The window remembers the failure that OPENED it, so the
            # answer names its own cause even when a later probe failed
            # differently somewhere else.
            remembered = window[1]
            if scope_key not in self._uv_probe_window_warned:
                # One warning per window, not one per answered call: the
                # window answers every caller for its length, and a line
                # per call would bury the log. The membership test can race
                # an unlocked caller; a duplicated line is the accepted
                # cost of not taking the lock on the fast path.
                self._uv_probe_window_warned.add(scope_key)
                from automated_security_helper.utils.log import ASH_LOGGER

                ASH_LOGGER.warning(
                    "uv availability answered False from the retry window: "
                    "a recent probe timed out or died on a signal, which is "
                    "not uv's own answer. The probe runs again once the "
                    "window passes."
                    + (f" The failing probe: {remembered}." if remembered else "")
                )
            return False, remembered
        return None

    def list_available_tools(self) -> List[str]:
        """List all available UV tools."""
        if not self.is_uv_available():
            raise UVToolRunnerError(self.unavailable_reason())

        try:
            result = spawn_run(  # nosec B603 — list args, validated uv executable path
                [self.uv_executable, "tool", "list"],
                capture_output=True,
                text=True,
                timeout=30,
                check=True,
                env=environ_for_parsed_output(),
                encoding="utf-8",
                errors="replace",
            )

            tools = []
            for line in result.stdout.strip().split("\n"):
                if line.strip():
                    tool_name = line.strip().split()[0]
                    if tool_name == "-":
                        tool_name = line.strip().split()[1]  # Add sub-commands too
                    tools.append(tool_name)

            return tools

        except subprocess.CalledProcessError as e:
            raise UVToolRunnerError(f"Failed to list UV tools: {e}")
        except (subprocess.SubprocessError, OSError) as e:
            # A listing that timed out or whose spawn failed is this method's
            # failure like a non-zero exit, not an exception for its callers:
            # is_tool_installed answers False on UVToolRunnerError, and the
            # callers of install_tool_with_version and
            # get_tool_installation_info expect a value, not a raise.
            raise UVToolRunnerError(
                f"Failed to list UV tools: {type(e).__name__}: {e}"
            ) from e

    def is_tool_installed(self, tool_name: str) -> bool:
        """Check if a specific tool is installed via UV."""
        try:
            installed_tools = self.list_available_tools()
        except UVToolRunnerError:
            return False
        return tool_name in installed_tools

    def get_tool_version(
        self,
        tool_name: str,
        package_name: Optional[str] = None,
        *,
        refresh: bool = False,
        values: Optional[Iterable[str]] = None,
        python_request: Optional[str] = None,
        offline: Optional[bool] = None,
        package: Optional[str] = None,
        probe_outcome: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """Get version of a UV tool.

        ``package`` is the name the caller assembled ``package_name`` around,
        when it knows it (``checked_requirement``'s own meaning): a constraint
        glued onto the name ("bandit" + "2") then refuses here instead of
        probing, and installing, ``bandit2`` from the index.

        ``probe_outcome``, when a dict is given, is filled with how the answer
        was reached, for a caller that must tell a tool that failed from a
        probe that never ran: ``ran`` (the probe spawned and exited),
        ``returncode`` (its exit, when it ran), ``from_memo`` (answered from the
        memo, no probe) and ``error`` (why no probe ran, or what the spawn
        raised). ``validate_cached_tool`` reads it: a timeout, a sandbox
        refusal or a refused spec is not a broken tool.

        Memoized and serialized per ``(tool_name, package_name)``: concurrent
        callers asking about the same tool produce exactly ONE
        ``uv tool run <tool> --version`` subprocess, and every later caller
        reads the remembered answer.

        Probing once is load-bearing, not just faster. See the comment on
        ``_uv_tool_version_cache``: the probe imports the tool, a stevedore-based
        tool builds a shared per-user entry-point cache on first import, and
        stevedore writes that cache non-atomically and unlocked. N concurrent
        first-imports can leave behind a cache that parses but holds a
        wrong-arity entry, which breaks the tool for every later process on the
        machine. One probe means one writer.

        ``package_name`` is the ``--from`` specification. Passing the SAME spec
        the scan will use matters: ``uv tool run bandit`` and
        ``uv tool run --from 'bandit[sarif,toml]>=1.7.8,<2.0.0' bandit`` resolve
        to different environments, and stevedore's digest is over
        ``sys.executable`` and ``sys.prefix``, so they warm different cache
        files. A probe that warms the wrong file leaves the scan's file cold for
        N concurrent scanners. Callers should pass the scan's spec;
        ``UVToolMixin._get_uv_tool_version`` does this by default.

        Failures are memoized too, deliberately -- caching only successes would
        reopen the concurrent-probe window on exactly the path where a slow cold
        start makes it most likely. Because that means one transient failure is
        then served process-wide, ``refresh=True`` forces a re-probe and
        overwrites the memo; ``validate_cached_tool`` uses it so a probe that
        merely timed out cannot permanently declare a working tool broken.

        Each answer is keyed by the uv executable that gave it and whether
        the probe ran offline (see the cache's own note): a swapped or
        re-resolved uv is asked itself rather than answered from the other
        uv's memory.

        ``values`` are the caller's environment-read values, hidden from the
        carried version before its first-line cut. The DEFAULT, None, means no
        caller checked where its inputs came from, and every plugin-built
        argument (the ``--from`` spec) is hidden from the carried version. An
        explicit iterable -- the empty tuple included -- means the caller
        checked: only inputs holding one of these values are hidden. The
        memo stores the raw
        probe text and the redaction runs on every return, the cached ones
        included: callers share the ``tool::spec`` key but not their values,
        so a stored redaction would let whoever probed first decide what a
        later caller's SARIF ``scanner_version`` and DEBUG line hide.

        ``python_request`` is passed as ``uv tool run --python``, for a tool whose
        dependencies publish no wheels for the interpreter uv would otherwise
        pick (see ``UVToolMixin._get_tool_python_request``). It is part of the
        memo key because it selects a different environment.
        """
        outcome: Dict[str, Any] = {
            "ran": False,
            "returncode": None,
            "from_memo": False,
            "error": None,
        }
        if probe_outcome is not None:
            probe_outcome.update(outcome)
            outcome = probe_outcome

        if not self.is_uv_available():
            outcome["error"] = self.unavailable_reason()
            return None
        if package_name:
            try:
                checked_requirement(package_name, "the package spec", package=package)
            except UVToolRunnerError as error:
                from automated_security_helper.utils.log import ASH_LOGGER

                # The refusal's text carries no part of the spec (its message
                # is fixed), so a plugin-built constraint holding a value the
                # config read from the environment is never logged here. The
                # tool's name comes from this call's own argument, plugin
                # code, never the spec.
                ASH_LOGGER.warning(f"{tool_name}: {error}")
                outcome["error"] = str(error)
                return None

        cache_key = f"{tool_name}::{package_name or ''}"
        if python_request:
            cache_key += f"::python={python_request}"

        # One probe asks one executable one question, and an offline probe
        # (--offline) is not an online one's answer. Each memoized answer is
        # keyed by (executable, offline) under the tool::spec key, so a uv
        # resolved or assigned after the probe is asked itself instead of
        # answered from the other uv's memory, while invalidation by tool
        # name still drops every environment's answer at once. ``offline`` is
        # the caller's mode when given (a scanner's own options.offline), else
        # ASH's; see run_tool.
        executable = self.uv_executable
        offline = bool(_offline_for(offline) or is_checking_only())
        environment_key = (executable, offline)

        # A hit copies the remembered answer under the lock and redacts it
        # after the lock is released: the redaction is not cheap, and this
        # lock is shared with every executable and command lookup.
        # A failed probe is remembered as None, so a hit is tracked apart
        # from the value.
        hit: Optional[str] = None
        found = False
        with _uv_tool_runner_cache_lock:
            if not refresh:
                remembered = _uv_tool_version_cache.get(cache_key)
                if isinstance(remembered, dict) and environment_key in remembered:
                    hit = remembered[environment_key]
                    found = True
            if not found:
                # Bind to a local and keep it alive until after the acquire
                # below; the registry holds locks weakly. See
                # _get_or_create_probe_lock. Keyed by the TOOL, not by the
                # tool::spec key: two spec keys of one tool can resolve to one
                # environment (``bandit`` and ``--from bandit bandit`` both run
                # the installed bandit), and probing them concurrently reopened
                # the first-import race the lock exists to close.
                probe_lock = _get_or_create_probe_lock(f"version::{tool_name}")
        if found:
            outcome["from_memo"] = True
            return _version_shown(
                hit, values, tool_name=tool_name, package_name=package_name
            )

        # Held across the subprocess so a second thread on this tool waits for
        # the first probe rather than starting its own. The coarse cache lock is
        # deliberately NOT held here, so probes for *different* tools still run
        # in parallel. Held through the polling helper, so a waiter whose scan
        # is cancelled stops instead of waiting the probe out.
        with _probe_lock_held(probe_lock):
            with _uv_tool_runner_cache_lock:
                if not refresh:
                    remembered = _uv_tool_version_cache.get(cache_key)
                    if isinstance(remembered, dict) and environment_key in remembered:
                        hit = remembered[environment_key]
                        found = True
                # Read before the probe starts: an invalidation of this tool
                # that lands while the subprocess runs moves the count, and
                # the store below is skipped rather than remembering an
                # answer from before the drop.
                generation = _uv_tool_version_generations.setdefault(cache_key, 0)
            if found:
                outcome["from_memo"] = True
                return _version_shown(
                    hit, values, tool_name=tool_name, package_name=package_name
                )

            raw: Optional[str] = None
            try:
                command = [executable, "tool", "run"]
                if python_request:
                    command.extend(["--python", python_request])

                # Offline, the probe must be offline too, exactly as run_tool is.
                # It used to be the one uv call that ignored ASH_OFFLINE: under
                # `ash scan --mode nix` it resolved the newest semgrep on PyPI,
                # downloaded it, and was killed at the 15s timeout whenever the
                # download was slow. A killed probe leaves uv's cache holding the
                # index entry but not the wheel, so the scan's own
                # `uv tool run --offline` then failed with "the requested data
                # wasn't found in the cache" (nix arm64 CI, 2026-10-06). A probe
                # that finished was no better: the scan then ran that PyPI
                # semgrep, not the one Nix pinned.
                probe_env: Optional[Dict[str, str]] = None
                # Offline in check-only mode too, which must not download;
                # the flag was read once above, with the executable.
                if offline:
                    probe_env = snapshot_environ()
                    probe_env["UV_OFFLINE"] = "1"
                    command.append("--offline")

                # Build command with --from parameter if extras specified
                if package_name:
                    # Build the --from specification
                    command.extend(
                        [
                            "--from",
                            package_name,
                        ]
                    )

                command.extend([tool_name, "--version"])
                result = spawn_run(  # nosec B603 — list args, validated uv executable path
                    command,
                    capture_output=True,
                    text=True,
                    # Its first line is read as the version.
                    env=environ_for_parsed_output(probe_env),
                    timeout=_UV_TOOL_VERSION_PROBE_TIMEOUT,
                    check=False,
                    encoding="utf-8",
                    errors="replace",
                )
                outcome["ran"] = True
                outcome["returncode"] = result.returncode

                if result.returncode == 0 and result.stdout.strip():
                    # Unstripped: the strip runs in _version_shown, after the
                    # redaction. A whole-text strip here shaves the edge off a
                    # value that ends in a whitespace-class character, and the
                    # whole-value redaction then misses it and prints the
                    # piece.
                    raw = result.stdout

            except Exception as error:  # nosec B110 - version check failure is non-critical
                raw = None
                outcome["error"] = f"{type(error).__name__}: {error}"
                # A probe the active sandbox scope refused never ran, so it says
                # nothing about the tool: not remembered for later callers.
                refused = _refused_by_sandbox(error)
            else:
                refused = False

            # A check-only probe ran offline; a scan's would not. Not remembered.
            # Nor is a probe that FAILED inside a sandbox scope: the scope's
            # wrapper decides what the probe can see and run, so its failure is
            # that scope's and not an answer for every later caller process-wide
            # (a probe that answered a version is a version wherever it ran).
            failed_in_scope = raw is None and _probe_scope_key() is not None
            if not refused and not failed_in_scope and not is_checking_only():
                with _uv_tool_runner_cache_lock:
                    # Only while no invalidation landed since the pre-probe
                    # read. The answer is still returned to this caller --
                    # it is the probe this caller asked for -- but it is not
                    # remembered across the drop.
                    if _uv_tool_version_generations.get(cache_key, 0) == generation:
                        remembered = _uv_tool_version_cache.get(cache_key)
                        if not isinstance(remembered, dict):
                            remembered = {}
                            _uv_tool_version_cache[cache_key] = remembered
                        remembered[environment_key] = raw
            return _version_shown(
                raw, values, tool_name=tool_name, package_name=package_name
            )

    def get_installed_tool_version(
        self,
        tool_name: str,
        package_name: Optional[str] = None,
        *,
        values: Optional[Iterable[str]] = None,
        python_request: Optional[str] = None,
    ) -> Optional[str]:
        """Get version of an installed UV tool.

        ``values`` and ``python_request`` have the meaning they have for
        ``get_tool_version``.
        """
        if not self.is_tool_installed(tool_name):
            return None
        if python_request:
            return self.get_tool_version(
                tool_name, package_name, values=values, python_request=python_request
            )
        return self.get_tool_version(tool_name, package_name, values=values)

    def install_tool_with_version(
        self,
        tool_name: str,
        version_constraint: Optional[str] = None,
        timeout: int = 300,
        retry_config: Optional[UVToolRetryConfig] = None,
        package_extras: Optional[List[str]] = None,
        with_dependencies: Optional[List[str]] = None,
        progress_callback: Optional[Callable] = None,
        values: Optional[Iterable[str]] = None,
        python_request: Optional[str] = None,
        reinstall: bool = False,
        offline: Optional[bool] = None,
    ) -> bool:
        """Install a UV tool with optional version constraint, extras, and retry logic.

        Args:
            tool_name: Name of the tool to install
            reinstall: Install even when uv already lists the tool, with
                ``uv tool install --reinstall``, so the environment is rebuilt
                against this call's spec, extras and ``--with`` entries. The
                default answers True without running anything for a tool uv
                lists; the mixin's "installed but not functional, proceeding
                with reinstallation" path used to call this and get exactly
                that: a True and no install.
            offline: Whether this install runs offline (nothing is installed
                then). None follows ASH's own mode; see ``run_tool``.
            version_constraint: Optional version constraint (e.g., ">=1.7.0,<2.0.0")
            values: The caller's environment-read values, for redacting uv's
                stderr before the debug log. The raised texts never need them:
                they are fixed-shape and carry no argv. The DEFAULT, None,
                means no caller checked where its inputs came from, and every
                plugin-built argument is hidden from the debug line. An
                explicit iterable -- the empty tuple included -- means the
                caller checked: only inputs holding one of these values are
                hidden, and a builtin constraint stays diagnosable. Without
                the distinction, the constraint's visibility flipped on
                unrelated config.
            timeout: Timeout in seconds for installation
            retry_config: Optional retry policy. ``None`` (the default) means a
                single attempt. When supplied, a non-zero exit from
                ``uv tool install`` is retried up to ``max_retries`` further
                times, waiting an exponentially growing, capped, optionally
                jittered interval between attempts. A timeout and an
                OSError-shaped failure are both terminal either way -- see the
                handlers below for why.
            package_extras: Optional list of package extras (e.g., ["sarif", "toml"])
            with_dependencies: Optional list of additional dependencies to install with --with flag
            progress_callback: Optional callback for progress updates, invoked
                only when ``timeout`` exceeds 60 seconds. Called from a monitor
                thread started and stopped around each individual attempt, so the
                elapsed figure it reports is measured from the start of the
                attempt in flight rather than from the start of the call, and no
                callback arrives once this function has returned. With a
                ``retry_config`` in play the message also names the attempt.
            python_request: Optional interpreter request passed as
                ``uv tool install --python``. None, the default, leaves the
                interpreter to uv, which is what every caller did before it
                existed.

        Returns:
            True if installation succeeded, or the tool was already listed and
            no reinstall was asked for. False when NOTHING was installed and
            that is the answer: uv absent, offline, a dependency question
            (``checking_only``), a sandboxed scan, or a refused spec.

        Raises:
            UVToolRunnerError: every attempt exited non-zero, an attempt timed
                out, or uv could not be started. A failed install is a raise,
                never a False; the False arm says nothing was tried.
        """

        if not self.is_uv_available():
            return False

        # Check if tool is already installed - skip installation if it exists,
        # unless the caller asked for a reinstall of a listed tool.
        if not reinstall and self.is_tool_installed(tool_name):
            # Tool already exists, no need to reinstall
            return True

        from automated_security_helper.utils.sandbox.scope import active_scope

        if active_scope() is not None:
            # Installing runs the package's build code and writes uv's tool
            # directory, which a sandboxed scanner may only read. Refused rather
            # than run outside the sandbox the operator asked for.
            from automated_security_helper.utils.log import ASH_LOGGER

            if reinstall:
                # The tool is listed; its probe failed, and a sandboxed scan
                # does not rebuild it either. "Is not installed" misread that.
                ASH_LOGGER.error(
                    f"{tool_name} is installed but its version probe failed, and a "
                    "sandboxed scan does not reinstall tools. Run "
                    "`ash dependencies install` first."
                )
            else:
                ASH_LOGGER.error(
                    f"{tool_name} is not installed, and a sandboxed scan does not "
                    "install tools. Run `ash dependencies install` first."
                )
            return False

        # Check if tool executable exists but is broken (e.g., broken symlink)
        # This can happen if UV tool was uninstalled but symlinks remain
        # ASH_LOGGER rather than the root logger. These two were the only logging
        # calls in this module and both went to the root logger, so they bypassed
        # the "ash" logger entirely -- meaning they ignored ASH's configured level
        # and handlers, and skipped the WindowsSafeFilter that log.py attaches.
        # That filter matters here specifically: both messages interpolate a
        # filesystem path. Imported inside the function, matching the two imports
        # below; log.py pulls in only stdlib and rich, so there is no cycle.
        from automated_security_helper.utils.log import ASH_LOGGER
        from automated_security_helper.utils.subprocess_utils import find_executable

        # Once, at entry, as run_command_with_output_handling does: passed
        # straight into the retry loop, a generator would be used up by the
        # first attempt and leave every later attempt's debug line unredacted.
        # None stays None -- it is the no-caller-checked sentinel the debug
        # line's token filter reads, distinct from a checked empty tuple.
        values = None if values is None else value_tuple(values)

        # Check for offline mode: the caller's own when given, else ASH's.
        offline_mode = _offline_for(offline)
        if offline_mode:
            # In offline mode, skip installation attempts and rely on pre-installed tools
            return False
        if is_checking_only():
            # A dependency question, not a scan: nothing is installed.
            return False

        # find_executable answers only an executable file, found by a search or
        # re-tested when a remembered path is given again, so a link whose target is
        # gone is never the answer (test_a_dangling_link_is_never_the_tool_found).
        # This branch therefore runs only when the file is removed between that
        # lookup and the next line; it does not find a dangling link that is
        # already there. AFTER the offline and check-only returns: both are
        # documented to change nothing, and this removal ran before them.
        tool_path = find_executable(tool_name)
        if tool_path and not os.path.exists(tool_path):
            # Broken symlink detected - remove it so UV can recreate
            try:
                os.remove(tool_path)
                ASH_LOGGER.debug(
                    f"Removed broken symlink for {tool_name} at {tool_path}"
                )
            except Exception as e:
                ASH_LOGGER.warning(
                    f"Failed to remove broken symlink for {tool_name}: {e}"
                )

        # The spec uv installs and the record set that hides it come from
        # ONE builder: the string appended to the argv below is the same
        # object the stderr debug line and the mixin's installation record
        # hide, so the installed spec and the hidden spec cannot drift.
        install_inputs = uv_install_inputs(
            tool_name, version_constraint, package_extras, with_dependencies
        )
        tool_spec = install_inputs.spec
        try:
            checked_requirement(tool_spec, "the tool spec", package=tool_name)
            for position, dep in enumerate(with_dependencies or [], start=1):
                checked_requirement(dep, f"--with dependency {position}")
        except UVToolRunnerError as error:
            # As get_tool_version's refusal: the error's text is fixed and
            # carries no part of the spec, and the tool's name comes from
            # this call's own argument.
            ASH_LOGGER.warning(f"{tool_name}: {error}")
            return False

        # Build command with offline support
        cmd = [self.uv_executable, "tool", "install"]

        # UV_OFFLINE set by hand in the environment while _offline_for read
        # online (the offline mode itself returned above): uv's own flag is
        # passed along. Named apart from the ``offline`` parameter, which the
        # return above has already consumed.
        env_offline = os.environ.get("UV_OFFLINE") == "1"
        if env_offline:
            cmd.append("--offline")

        if reinstall:
            cmd.append("--reinstall")

        if python_request:
            cmd.extend(["--python", python_request])

        # Add --with dependencies if provided
        if with_dependencies:
            for dep in with_dependencies:
                cmd.extend(["--with", dep])

        cmd.append(tool_spec)

        # How this command's errors name it: the spec and the --with entries
        # are plugin-built and can hold a value their config read from the
        # environment, and nothing here holds the values to redact them with,
        # so the errors carry the parts that cannot hold one -- the offline
        # flag, the --with count, an extras list, a version constraint --
        # never the assembled argv. Each fact is read from the input that set
        # it, not back out of the argument list.
        described = [f"uv tool install {tool_name}"]
        # The flag the argv carries (env_offline above), not the parameter: the
        # parameter was consumed by the offline return, and a UV_OFFLINE=1 run
        # that failed used to describe itself without the --offline it passed.
        if env_offline:
            described.append("--offline")
        if with_dependencies:
            count = len(with_dependencies)
            noun = "dependency" if count == 1 else "dependencies"
            described.append(f"{count} --with {noun}")
        if package_extras:
            described.append("an extras list")
        if version_constraint:
            described.append("a version constraint")
        described.append("arguments not shown")
        shown_command = f"({'; '.join(described)})"

        # ``retry_config`` was accepted here and then silently dropped: there was
        # no retry loop in this function at all, so a caller asking for
        # ``max_retries=3`` got exactly one attempt. BanditScanner asks for
        # exactly that (``ash_builtin/scanners/bandit_scanner.py``), and
        # ``UVToolMixin._install_uv_tool`` logs "[INSTALLATION_CONFIG] Using
        # custom retry configuration / max_retries=3, base_delay=1.0s" *before*
        # calling in -- so the only observable anybody had announced a retry
        # policy that did not exist. The tests around this asserted that log
        # line, or that the config dict was passed through, or the bool this
        # returns; none of the three moves when the retry is missing, which is
        # why it survived. The regression tests added alongside this fix assert
        # the attempt count and the sleep intervals instead.
        #
        # ``retry_config=None`` still means a single attempt, so every caller
        # that never asked for retries keeps its behaviour exactly.
        #
        # ``max(1, ...)`` doubles up on the ``max(0, ...)`` in
        # ``UVToolRetryConfig.__post_init__``, and for the same reason
        # ``_install_retry_delay`` doubles up on its clamp of ``max_delay``: this
        # is a plain *mutable* dataclass, so ``config.max_retries = -1`` after
        # construction walks straight past normalization. The consequence is worse
        # here than it is for a delay. ``attempts <= 0`` makes ``range`` empty, so
        # the loop body never runs, ``last_error`` is never assigned, and this
        # function ends at ``raise UVToolRunnerError(None)`` -- an install that
        # never happened, reported as a failure whose message is the literal
        # "None". ``with-retry.sh`` guards the identical case with
        # ``if [ "$max" -lt 1 ]`` and gives the identical reason.
        attempts = max(1, 1 + retry_config.max_retries) if retry_config else 1
        last_error: str | None = None

        # Progress monitoring for long installations: one monitor per attempt, not
        # one for the whole call.
        #
        # ``timeout`` is a *per-attempt* budget -- it is what ``subprocess.run``
        # below enforces -- so an elapsed figure anchored anywhere else reports
        # progress against a limit nothing applies. A single monitor started
        # before the loop broke that twice over. It self-terminated at
        # ``elapsed > timeout`` measured from before the first attempt, so once
        # ``retry_config`` let the install run for ``attempts * timeout`` plus
        # backoff -- roughly fifteen minutes for BanditScanner's max_retries=3 at
        # the default 300s -- callbacks stopped after the first 300 seconds and
        # the caller heard nothing for the remaining ten. And the figures it did
        # emit before that described the first attempt rather than the running
        # one.
        #
        # The stop Event is what actually stops it. The previous code set
        # ``progress_thread = None`` under a comment reading "Stop progress
        # monitoring", which drops a reference and stops nothing: the thread is a
        # daemon polling a fixed sleep, so it went on calling back for up to
        # ``timeout`` after the install had returned, into a callback whose owner
        # has every reason to have torn down what it writes to. It also ran only
        # on the success path, so a failed attempt left its monitor reporting
        # elapsed time against an attempt that had already ended.
        #
        # The alternative shape -- keep one monitor and give it the whole budget --
        # would have to invent that budget: ``attempts * timeout`` plus a sum of
        # jittered backoffs is not a limit anything enforces and differs run to
        # run.
        monitor_attempts = callable(progress_callback) and timeout > 60

        def start_progress_monitor(attempt_index: int):
            """Report on one attempt. Returns ``(stop_event, thread)``."""
            if not monitor_attempts:
                return None, None

            stop = threading.Event()
            # Numbered only when there is more than one attempt, so callers that
            # never asked for retries see the message they saw before, unchanged.
            prefix = f"attempt {attempt_index + 1}/{attempts}, " if attempts > 1 else ""

            def progress_monitor():
                start_time = time.time()
                while True:
                    elapsed = time.time() - start_time
                    if elapsed > timeout:
                        break
                    # The attempt can end while this thread sleeps or waits
                    # for the scheduler: the stop flag is read right before
                    # each callback, so an attempt that has ended gets no
                    # further "in progress" line. The attempt's finally joins
                    # this thread (bounded) before the install returns.
                    if stop.is_set():
                        break
                    if callable(progress_callback):
                        progress_callback(
                            f"Installation in progress... "
                            f"({prefix}{elapsed:.0f}s elapsed)"
                        )
                    if stop.wait(_PROGRESS_UPDATE_INTERVAL_SECONDS):
                        break

            # In this context, copied, so a callback that logs does so as the
            # scan whose install this is (utils/threads.py).
            from automated_security_helper.utils.threads import ash_thread

            thread = ash_thread(progress_monitor, daemon=True)
            thread.start()
            return stop, thread

        for attempt in range(attempts):
            progress_stop, progress_thread = start_progress_monitor(attempt)
            try:
                spawn_run(  # nosec B603 — list args, validated uv executable path
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=True,
                    # Not snapshot_environ: the install's stderr is parsed by
                    # the redaction layers, which read contiguous text, so it
                    # runs without the caller's display variables (no COLUMNS
                    # wrapping, NO_COLOR=1), as the module's other parsed uv
                    # calls do. The install's behavior does not depend on
                    # display.
                    env=environ_for_parsed_output(),
                    encoding="utf-8",
                    errors="replace",
                )
            except subprocess.TimeoutExpired:
                # Deliberately terminal, not retried. This attempt already spent
                # the whole ``timeout`` budget, so retrying would multiply wall
                # clock by the attempt count -- three 300s timeouts is fifteen
                # minutes of a scan phase spent waiting on a tool that is not
                # coming. A timeout is also the one failure the caller can
                # already see in its own elapsed time.
                #
                # Without the TimeoutExpired's own text: it repeats the limit in
                # its spelling ("timed out after 300 seconds"), outside the token.
                # The install limits ASH passes come from builtin sections, which
                # a config file cannot read from the environment (the strict
                # load refuses a reference there), so no values are passed.
                # The command is named by its fixed shape, never the assembled
                # argv: the spec and --with dependencies are plugin-built and
                # can hold a value their config read from the environment. The
                # caller's ``values`` redact uv's stderr for the debug log
                # below, but a raised text travels wider than a log line, so
                # it leans on no redaction at all (checked_requirement's rule;
                # the run path's timeout names "uv tool run <tool>" for the
                # same reason). The chain is disavowed too: TimeoutExpired's
                # own text quotes the assembled argv, and every traceback
                # printer renders a kept cause, so ``from e`` undid what the
                # fixed-shape text left out. The env-blind raises elsewhere
                # already use ``from None``.
                #
                # The stop leaves the install's completion state unknown: uv
                # can finish installing right before the deadline lands, so a
                # version answer memoized before this call (None for a tool
                # that was not installed yet) may no longer describe the
                # environment. Dropped exactly as the success path drops it;
                # the next probe asks uv again. A CalledProcessError below is
                # different: that is uv's own answer that it did not install.
                # The lookup memos drop too, as the mixin's success arm drops
                # them: get_uv_tool_command's remembered None otherwise keeps
                # answering for a tool the timed-out install did put there.
                invalidate_tool_version_cache(tool_name)
                from automated_security_helper.utils.subprocess_utils import (
                    clear_find_executable_cache,
                )

                clear_find_executable_cache()
                raise UVToolRunnerError(
                    f"Tool installation timed out after {_timeout_token(timeout)} "
                    f"for {tool_name} {shown_command}"
                ) from None
            except subprocess.CalledProcessError as e:
                # A non-zero exit from ``uv tool install`` is the transient shape
                # worth retrying: a reset connection, a 5xx from the index, a DNS
                # blip. Remember the message and fall through to the backoff.
                # Without uv's stderr in the RAISED text: a resolver error
                # quotes the requirement it could not satisfy, and the spec
                # and --with dependencies are plugin-built and can hold a
                # value their config read from the environment -- the same
                # rule as the timeout arm above. The stderr goes to the debug
                # log below instead, redacted. The exit code carries no argv
                # and is kept.
                last_error = (
                    f"Tool installation failed for {tool_name} with exit code "
                    f"{e.returncode} {shown_command}"
                )
                if e.stderr:
                    # At debug level, through shown_uv_output: one plain line,
                    # the caller's environment-read values hidden in every
                    # spelling uv prints them in, and the plugin-built inputs
                    # -- the spec, base_spec (the name with its extras,
                    # without the constraint), the bare constraint and each
                    # --with entry -- hidden by ORIGIN with every spelling of
                    # each hidden input, because uv respells and reorders a
                    # requirement's parts. uv's stderr is the only clue to a
                    # 5xx, a DNS failure or a resolver conflict -- the shapes
                    # the retry exists for. A plugin-built literal uv
                    # respells, with no value behind it and ``values`` passed,
                    # stays shown by design (it is builtin, and hiding it cost
                    # this line its purpose); that bound is why this is a
                    # debug line and the raised text stays value-free. One
                    # record, one console line, as every sibling that logs
                    # tool-written text.
                    from automated_security_helper.utils.log import NO_MARKUP

                    shown_stderr = shown_uv_output(
                        str(e.stderr),
                        values,
                        # The one install-input builder's set, computed once
                        # above and shared with the mixin's installation
                        # record, so the two records cannot drift about
                        # which parts are hidden.
                        plugin_inputs=install_inputs.inputs,
                        tool_name=tool_name,
                    )
                    from automated_security_helper.utils.terminal_text import (
                        shown_on_one_line,
                    )

                    ASH_LOGGER.debug(
                        shown_on_one_line(
                            f"uv tool install for {tool_name} exited "
                            f"{e.returncode}; stderr (redacted, plugin-built "
                            f"arguments replaced): {shown_stderr}"
                        ),
                        extra=NO_MARKUP,
                    )
            except Exception as e:
                # Not retried: this is the OSError shape -- ``uv`` itself missing,
                # not executable, or a bad cwd -- and no amount of waiting fixes
                # any of them. Two cases, told apart by the record spawn_run
                # attaches to what it raises: a child that never started, and a
                # child that STARTED and whose wait then failed. The second
                # leaves the install's completion state unknown, exactly as a
                # timeout does, so the memos drop as the timeout arm drops them;
                # this arm used to keep them, and a remembered None then answered
                # for a tool the failed wait had in fact installed.
                started = getattr(e, _STARTED_CHILD_ATTRIBUTE, None)
                if getattr(started, "process", None) is not None:
                    invalidate_tool_version_cache(tool_name)
                    from automated_security_helper.utils.subprocess_utils import (
                        clear_find_executable_cache,
                    )

                    clear_find_executable_cache()
                    raise UVToolRunnerError(
                        f"Tool installation for {tool_name} started but its result "
                        f"could not be read ({type(e).__name__}: {e}); whether the "
                        f"tool is installed is unknown {shown_command}"
                    )
                raise UVToolRunnerError(
                    f"Unexpected error during tool installation for {tool_name}: {e}"
                )
            except BaseException:
                # A stop that is not an error: the scan's cancel
                # (ScanCancelled is a BaseException, so every arm above lets
                # it pass), a KeyboardInterrupt. The stop lands with the
                # install's completion state exactly as unknown as a timeout
                # leaves it -- uv can finish installing right before the
                # cancel -- so the memos drop as the timeout arm drops them,
                # version and lookups both, and the stop is re-raised
                # unchanged: it belongs to the caller, not this function.
                invalidate_tool_version_cache(tool_name)
                from automated_security_helper.utils.subprocess_utils import (
                    clear_find_executable_cache,
                )

                clear_find_executable_cache()
                raise
            else:
                # Installing is exactly the event that makes a remembered version
                # wrong, so drop this tool's memoized probe result. Without this, a
                # caller that probed before installing (converters re-read
                # tool_version afterwards) would keep seeing the pre-install answer.
                invalidate_tool_version_cache(tool_name)

                return True
            finally:
                # Every exit from an attempt comes through here: the success
                # ``return``, both terminal ``raise``es, and falling through to the
                # backoff. Joining rather than only signalling means no callback
                # can arrive after this function has returned. Bounded because the
                # callback is caller-supplied code.
                # Both halves named, though ``start_progress_monitor`` returns the
                # two together or neither: a type checker cannot see that
                # correlation, and the same reasoning is already written out for
                # ``retry_config is not None`` below.
                if progress_stop is not None and progress_thread is not None:
                    progress_stop.set()
                    progress_thread.join(timeout=5)

            # ``retry_config is not None`` is redundant with ``attempt + 1 <
            # attempts`` today: ``attempts`` is 1 whenever ``retry_config`` is
            # falsy, so this line is reachable only when a real config exists.
            # It is written out anyway for two reasons. A type checker cannot see
            # that correlation and reports ``UVToolRetryConfig | None`` against
            # ``_install_retry_delay``'s non-optional parameter. More to the
            # point, if a later change to how ``attempts`` is derived ever broke
            # the correlation, the failure would be an AttributeError raised
            # *from inside the retry path* -- code that runs only once something
            # has already gone wrong, and that no test exercising a successful
            # install would ever reach. That is the same invisible-on-the-error-
            # path shape as the missing retry this function was fixed for, so the
            # invariant is stated in the condition rather than left implicit.
            if retry_config is not None and attempt + 1 < attempts:
                _sleep_between_attempts(_install_retry_delay(retry_config, attempt))

        raise UVToolRunnerError(last_error)

    def run_tool(
        self,
        tool_name: str,
        package_name: None | str = None,
        args: List[str] | None = None,
        cwd: Optional[Path] = None,
        capture_output: bool = True,
        text: bool = True,
        check: bool = False,
        timeout: Optional[int] = None,
        package_extras: Optional[List[str]] = None,
        version_constraint: Optional[str] = None,
        results_dir: Optional[Path] = None,
        stdout_preference: str = "write",
        stderr_preference: str = "write",
        class_name: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        quiet: bool = False,
        values: Iterable[str] = (),
        python_request: Optional[str] = None,
        offline: Optional[bool] = None,
        with_dependencies: Optional[List[str]] = None,
    ) -> subprocess.CompletedProcess:
        """Run a UV tool with specified arguments and output handling support.

        Args:
            tool_name: Name of the tool to run: the executable uv starts.
            package_name: The package that provides ``tool_name``, when its name
                differs (``jupyter-nbconvert`` comes from ``nbconvert``). It is
                the base of the ``--from`` spec the extras and the constraint are
                built on; without them it is passed as the ``--from`` spec
                itself. A plugin that names its package only on the install
                used to run ``uv tool run <tool_name>``, which resolves a
                package named after the executable.
            args: Arguments to pass to the tool
            cwd: Working directory for the command
            capture_output: Whether to capture stdout/stderr
            text: Whether to return text output
            check: Whether to raise exception on non-zero exit. A run that
                timed out is a failed run under ``check`` on both branches
                (with and without ``results_dir``); without ``check`` it is
                returned as a ``TimedOutProcess``.
            timeout: Timeout in seconds
            package_extras: Optional list of package extras for --from parameter
            version_constraint: Optional version constraint for --from parameter
            results_dir: Directory to write output files to
            stdout_preference: How to handle stdout ("return", "write", "both", "none")
            stderr_preference: How to handle stderr ("return", "write", "both", "none")
            class_name: Optional class name for log file naming
            env: Environment variables for the child process. When supplied,
                offline-mode additions are layered on top; when ``None``,
                the child inherits the parent env.
            quiet: Pass uv's ``--quiet``, which silences uv's own resolver and
                installer lines on stderr while keeping its error diagnostics.
                For a caller that reads the run's stderr to tell uv's failures
                from the tool's.
            values: The scan config's environment values, which the timeout
                text prints its limit with (and the subprocess layer's own
                timeout line is redacted of).
            python_request: Optional interpreter request passed as
                ``uv tool run --python``; None leaves the choice to uv.
            offline: Whether this run is offline. None, the default, follows
                ASH's own mode (``ASH_OFFLINE``). A scanner whose
                ``options.offline: true`` runs offline while ASH is online passes
                True, so its uv run resolves from the cache alone, as its own
                mode says; the module-wide mode used to be the only one uv saw.
            with_dependencies: The plugin's extra dependencies, passed as
                ``uv tool run --with <dep>`` each, the same entries the install
                passes with ``--with`` and the mixin counts among a run's inputs.
                A run that resolves an ephemeral environment (the tool not
                installed, or installed under another spec) lacked them, and a
                tool whose plugin needs one (``jupyter`` beside nbconvert) ran
                without it. Each is checked as the install checks its own.

        Returns:
            CompletedProcess result with enhanced output handling
        """
        from automated_security_helper.utils.subprocess_utils import (
            TIMEOUT_RETURNCODE,
            PostRunErrorProcess,
            SignaledProcess,
            TimedOutProcess,
            run_command_with_output_handling,
        )

        if not self.is_uv_available():
            raise UVToolRunnerError(self.unavailable_reason())

        values = value_tuple(values)
        if args is None:
            args = []

        command = [self.uv_executable, "tool", "run"]
        if quiet:
            command.append("--quiet")

        # Set up environment for offline mode if needed. If the caller
        # passed an explicit env, start from it; otherwise start from
        # os.environ when we need to set offline flags.
        if _offline_for(offline) or is_checking_only():
            env = dict(env) if env is not None else snapshot_environ()
            env["UV_OFFLINE"] = "1"
            command.append("--offline")

        if python_request:
            command.extend(["--python", python_request])

        # Build command with --from parameter if extras or version constraint specified
        base_name = package_name or tool_name
        # The package the --from spec is held to is the NAME inside
        # ``package_name``, not the string whole: a caller passes the package
        # with its constraint glued on ("nbconvert>=7.16.0,<8.0.0", the jupyter
        # converter's), and the whole string compared against the parsed name
        # never matched, so every such run was refused as a requirement for
        # another package.
        package = _requirement_name(base_name)
        if package_extras or version_constraint:
            # Build the --from specification
            if package_extras:
                extras_str = ",".join(package_extras)
                base_spec = f"{base_name}[{extras_str}]"
            else:
                base_spec = base_name

            from_spec = checked_requirement(
                f"{base_spec}{version_constraint}" if version_constraint else base_spec,
                f"the --from spec for {tool_name}",
                package=package,
            )

            command.extend(
                [
                    "--from",
                    from_spec,
                ]
            )

        elif package_name and _canonical(package_name) != _canonical(tool_name):
            # A package named apart from its command is always a --from (the
            # bare run would resolve a package named after the executable); one
            # named like the command passes none, exactly as the probes'
            # UVToolMixin._uv_from_spec reads it, so the two argvs match. A
            # package named like the command WITH a constraint is a --from too:
            # the constraint is what the caller asked for.
            command.extend(
                [
                    "--from",
                    checked_requirement(
                        package_name,
                        f"the --from spec for {tool_name}",
                        package=package,
                    ),
                ]
            )

        for position, dependency in enumerate(with_dependencies or [], start=1):
            command.extend(
                [
                    "--with",
                    checked_requirement(
                        dependency, f"--with dependency {position} for {tool_name}"
                    ),
                ]
            )

        command.extend([tool_name, *args])

        # Use the centralized output handling if results_dir is provided
        if results_dir is not None:
            # It answers every failure with a response, it does not raise one.
            # watched_launch: this spawn, and only it, is the launch a caller's
            # StartWatch answers for -- the probes and installs above are not.
            with watched_launch():
                response = run_command_with_output_handling(
                    command=command,
                    results_dir=results_dir,
                    stdout_preference=stdout_preference,
                    stderr_preference=stderr_preference,
                    cwd=cwd,
                    env=env,
                    shell=False,
                    class_name=class_name or f"UVTool_{tool_name}",
                    encoding="utf-8" if text else None,
                    errors="replace" if text else None,
                    # Every scanner passes results_dir, so this is the branch
                    # they take. Omitting timeout here meant the parameter was
                    # honoured only on the fallback below, i.e. only for callers
                    # that do not want output files -- which is none of the
                    # scanners.
                    timeout=timeout,
                    values=values,
                )
            try:
                # TimedOutProcess keeps the timeout through this conversion. The
                # dict says timed_out and CompletedProcess has no field for it, so
                # rebuilding a plain one made a killed scanner indistinguishable
                # from one that exited 124 by itself.
                # SpawnFailedProcess does the same for a uv that never started,
                # so the mixin can tell it from a uv that ran and exited 127.
                # PostRunErrorProcess keeps a run whose output ASH could not
                # record, with the error, so the mixin does not read it as a clean
                # run with the tool's exit code. CancelledProcess keeps a cancel.
                # A timeout or a cancel is never turned into a post-run error.
                result: subprocess.CompletedProcess
                flagged = _type_keeping_the_flag(response)
                if flagged is not None:
                    # With the response's error, as the run_command path gives it.
                    result = flagged(
                        args=command,
                        returncode=response.get("returncode", 0),
                        stdout=response.get("stdout", ""),
                        stderr=response.get("stderr", ""),
                        error=str(response.get("error") or ""),
                    )
                    # The recorded could-not-stop state rides the conversion as
                    # the typed result's own field, never as text in the error;
                    # the pid it names rides beside it as data.
                    if response.get("could_not_stop") is True:
                        result.could_not_stop = True
                        pid = response.get("could_not_stop_pid")
                        if isinstance(pid, int) and not isinstance(pid, bool):
                            result.could_not_stop_pid = pid
                    # The recorded signal ending rides the same way: the flag and
                    # the number as the typed result's own fields, so a both-flags
                    # response keeps the signal beside the post-run error. Only
                    # the types that carry an ending take the copy: a timed-out
                    # or cancelled child was stopped by ASH and has none.
                    if response.get("signaled") is True and isinstance(
                        result, (PostRunErrorProcess, SignaledProcess)
                    ):
                        result.signaled = True
                        number = response.get("signal")
                        if isinstance(number, int) and not isinstance(number, bool):
                            result.signal = number
                else:
                    result = subprocess.CompletedProcess(
                        args=command,
                        returncode=response.get("returncode", 0),
                        stdout=response.get("stdout", ""),
                        stderr=response.get("stderr", ""),
                    )

            except Exception as e:
                if response.get("spawn_failed"):
                    # uv never started: the mixin reports a tool that could not start.
                    raise UVToolRunnerError(f"UV tool run failed for {tool_name}: {e}")
                # The tool ran, and converting its response failed: a failure after
                # it exited. Raising would make the mixin read it as a uv run that
                # never started. Built
                # from the response already assembled: its exit code, and its
                # timeout or cancel if it had one, never turned into a post-run
                # error; the conversion's error is added to the response's own.
                from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP
                from automated_security_helper.utils.terminal_text import (
                    shown_on_one_line,
                )

                ASH_LOGGER.error(
                    shown_on_one_line(
                        f"ASH could not record the output of uv tool run {tool_name}: "
                        f"{e}"
                    ),
                    extra=NO_MARKUP,
                )
                try:
                    earlier = str(response.get("error") or "")
                except Exception:
                    # The response's own error is what could not be converted.
                    earlier = ""
                kept = _type_keeping_the_flag(response) or PostRunErrorProcess
                rebuilt = kept(
                    args=command,
                    returncode=response.get("returncode"),
                    stdout=response.get("stdout", ""),
                    stderr=response.get("stderr", ""),
                    error=f"{earlier}; {e}" if earlier else str(e),
                )
                if response.get("could_not_stop") is True:
                    rebuilt.could_not_stop = True
                    rebuilt_pid = response.get("could_not_stop_pid")
                    if isinstance(rebuilt_pid, int) and not isinstance(
                        rebuilt_pid, bool
                    ):
                        rebuilt.could_not_stop_pid = rebuilt_pid
                if response.get("signaled") is True and isinstance(
                    rebuilt, (PostRunErrorProcess, SignaledProcess)
                ):
                    rebuilt.signaled = True
                    rebuilt_signal = response.get("signal")
                    if isinstance(rebuilt_signal, int) and not isinstance(
                        rebuilt_signal, bool
                    ):
                        rebuilt.signal = rebuilt_signal
                return rebuilt

            # A post-run result is returned, not raised as a failed run: the flag
            # is read before the code, which ASH's stop leaves None.
            if (
                check
                and result.returncode != 0
                and not getattr(result, "post_run_error", False)
            ):
                # Without CalledProcessError's own str, which quotes the whole
                # argv including the --from spec and --with entries -- plugin-
                # built values a config can read from the environment. This
                # call's ``values`` covers only what its caller chose to pass
                # (the default is empty), so the error does not lean on it:
                # the fixed shape needs no redaction at all. The streams the
                # caller may need already ride in the result.
                raise UVToolRunnerError(
                    f"UV tool run failed for {tool_name}: "
                    f"{_exit_description(result)} "
                    f"(uv tool run {tool_name}, arguments not shown)"
                )
            return result

        # Fallback to original subprocess.run for backward compatibility
        try:
            # watched_launch, as on the branch above: the launch alone.
            with watched_launch():
                result = spawn_run(  # nosec B603 — list args, validated uv executable path
                    command,
                    cwd=cwd,
                    capture_output=capture_output,
                    text=text,
                    check=check,
                    timeout=timeout,
                    env=env if env is not None else snapshot_environ(),
                    encoding="utf-8" if text else None,
                    errors="replace" if text else None,
                )
            return result
        except subprocess.CalledProcessError as e:
            # The same rule as the branch above: neither the exception's str
            # nor its stderr, which repeats the requirement uv could not
            # satisfy, may ride -- only how the command ended, in the fixed
            # shape (a negative code is a signal death, never an exit). The
            # chain is disavowed too: CalledProcessError's own text quotes the
            # whole argv, and every traceback printer renders a kept context,
            # so the fixed shape alone did not keep the argv out of a log.
            raise UVToolRunnerError(
                f"UV tool run failed for {tool_name}: "
                f"{_exit_description(e)} "
                f"(uv tool run {tool_name}, arguments not shown)"
            ) from None
        except subprocess.TimeoutExpired as e:
            # Returned, not raised: a raise reaches the mixin's catch-all, which
            # reads it as a uv run that never started.
            def _text(captured) -> str:
                if isinstance(captured, bytes):
                    return captured.decode("utf-8", errors="replace")
                return captured or ""

            # The record spawn_run attached says whether the stop ended the
            # child: one it did not end has no exit code of its own, which
            # TimedOutProcess's contract keeps as returncode None, with an
            # error that says so rather than reading as an ordinary timeout.
            # The record's own reading (``not_stopped``) decides, as the
            # results_dir branch's response does: it honors a stop the sandbox
            # refused, where a bare poll of the process read the child as ended
            # once closing the pipes ended it. A record without that method (an
            # older stub) is read by its process's poll.
            started = getattr(e, _STARTED_CHILD_ATTRIBUTE, None)
            process = getattr(started, "process", None)
            read_not_stopped = getattr(started, "not_stopped", None)
            if callable(read_not_stopped):
                not_stopped = read_not_stopped()
                still_running = not_stopped is not None
            else:
                still_running = process is not None and process.poll() is None
            timed_out = TimedOutProcess(
                args=command,
                returncode=None if still_running else TIMEOUT_RETURNCODE,
                stdout=_text(e.stdout),
                stderr=(
                    f"{_text(e.stderr)}\n"
                    f"Command timed out after {_timeout_token(timeout, values)}"
                ).strip(),
                error=(
                    f"Command timed out after {_timeout_token(timeout, values)}: "
                    f"uv tool run {tool_name}"
                    + (", and the stop did not end it" if still_running else "")
                ),
            )
            if still_running:
                # The recorded state rides as the result's own fields, as the
                # results_dir branch carries it: the mixin reads the fact from
                # them, never from the error's text.
                timed_out.could_not_stop = True
                read_pid = getattr(started, "not_stopped_pid", None)
                pid = (
                    read_pid() if callable(read_pid) else getattr(process, "pid", None)
                )
                if isinstance(pid, int) and not isinstance(pid, bool):
                    timed_out.could_not_stop_pid = pid
            if check:
                # The caller asked for a raise on anything but a clean exit, as
                # the results_dir branch gives it for a timed-out run: a timeout
                # returned as a result here read as a run that completed. The
                # fixed shape, as for a non-zero exit above, with the chain
                # disavowed for the same reason: TimeoutExpired's text quotes
                # the argv.
                raise UVToolRunnerError(
                    f"UV tool run failed for {tool_name}: "
                    f"{_exit_description(timed_out)} "
                    f"(uv tool run {tool_name}, arguments not shown)"
                ) from None
            return timed_out
        except Exception as e:
            from automated_security_helper.utils.subprocess_utils import (
                spawn_run_failure_after_the_start,
            )

            # The tool started, and waiting on it raised: a failure after the start,
            # with its exit code, never a uv run that could not start.
            after_the_start = spawn_run_failure_after_the_start(command, e)
            if after_the_start is None:
                # uv never started: the mixin reports a tool that could not start,
                # as for the response branch above.
                raise UVToolRunnerError(
                    f"UV tool run failed for {tool_name}: {e}"
                ) from e
            return after_the_start

    def get_tool_installation_info(
        self,
        tool_name: str,
        package_name: Optional[str] = None,
        *,
        offline: Optional[bool] = None,
        package: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get comprehensive installation information for a tool.

        ``offline`` and ``package`` have the meaning they have for
        ``get_tool_version``: the caller's own offline mode reaches the version
        probe (a scanner offline by its options probed online here), and the
        package the spec was built around is checked before the probe.
        """
        is_uv_installed = (
            self.is_tool_installed(tool_name) if self.is_uv_available() else False
        )
        uv_version = (
            self.get_tool_version(
                tool_name, package_name, offline=offline, package=package
            )
            if is_uv_installed
            else None
        )

        # Simple pre-installed check
        from automated_security_helper.utils.subprocess_utils import (
            find_executable as _find_exec,
        )

        pre_installed_path = _find_exec(tool_name)
        is_pre_installed = pre_installed_path is not None

        if is_uv_installed:
            preferred_source = "uv"
            available = True
        elif is_pre_installed:
            preferred_source = "pre_installed"
            available = True
        else:
            preferred_source = "none"
            available = False

        return {
            "tool_name": tool_name,
            "is_uv_installed": is_uv_installed,
            "is_pre_installed": is_pre_installed,
            "uv_version": uv_version,
            # Not probed: the PATH copy is not run here (a dependency check
            # starts no tool it may not use), so the field is always None and a
            # caller that prints it says "unknown", not "None".
            "pre_installed_version": None,
            "pre_installed_path": pre_installed_path,
            "preferred_source": preferred_source,
            "available": available,
        }

    def should_install_tool(self, tool_name: str, prefer_cached: bool = True) -> bool:
        """Determine if a tool should be installed via UV."""
        if not self.is_uv_available():
            return False

        info = self.get_tool_installation_info(tool_name)

        if info["is_uv_installed"]:
            return False

        if prefer_cached and info["is_pre_installed"]:
            return False

        return True

    def _run_uv_cache(
        self, subcommand: str, timeout: int, check: bool
    ) -> subprocess.CompletedProcess:
        """``uv cache <subcommand>`` for the cache ``uv tool`` commands use.

        ``uv cache`` reads ``cache-dir`` from a ``uv.toml`` or ``pyproject.toml`` in
        the working directory and its parents. ASH's working directory is usually
        the repository being scanned, and a temporary directory is no better: on a
        host where another user or job can write /tmp, a ``uv.toml`` there or above
        it chose the directory. ``uv tool`` commands ignore project files but honor
        ``cache-dir`` in the operator's own and the system ``uv.toml``, and
        ``--no-config`` would drop those as well, naming a cache the tools do not
        use. So this runs without ``--no-config`` from the filesystem root
        (:func:`_uv_cache_cwd`), where only an administrator can put such a file,
        and without ``UV_PROJECT`` and ``UV_WORKING_DIR`` (``--project`` and
        ``--directory``), either of which, pointed at the scanned repository,
        brought its ``uv.toml`` back from there. ``uv cache dir`` prints the path
        colored under the caller's FORCE_COLOR, so the output is read without the
        caller's display variables (``environ_for_parsed_output``).
        """
        env = environ_for_parsed_output()
        for variable in _UV_PROJECT_LOCATORS:
            env.pop(variable, None)
        return spawn_run(  # nosec B603 — list args, validated uv executable path
            [self.uv_executable, "cache", subcommand],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=check,
            cwd=_uv_cache_cwd(),
            env=env,
            encoding="utf-8",
            errors="replace",
        )

    def get_cache_info(self) -> Dict[str, Any]:
        """Get UV cache information for optimization purposes."""
        try:
            result = self._run_uv_cache("dir", timeout=30, check=False)

            if result.returncode == 0:
                # Parse cache info from output
                cache_info = {
                    "cache_available": True,
                    "cache_output": result.stdout.strip(),
                }

                # Try to extract cache size and location if available
                lines = result.stdout.strip().split("\n")
                # The command returns only the cache path
                for line in lines:
                    cache_info["details"] = line.strip()
                    break

                return cache_info
            else:
                return {
                    "cache_available": False,
                    "error": (
                        result.stderr.strip()
                        if result.stderr
                        else "Unknown cache error"
                    ),
                }

        except Exception as e:
            return {"cache_available": False, "error": str(e)}

    def validate_cached_tool(
        self,
        tool_name: str,
        package_name: Optional[str] = None,
        *,
        offline: Optional[bool] = None,
        package: Optional[str] = None,
        values: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        """Validate that a cached tool is still functional.

        ``offline`` and ``package`` have the meaning they have for
        ``get_tool_version``. ``values`` has the meaning it has there too: the
        caller's environment-read values, hidden from the carried version. The
        mixin's [INSTALLATION_SKIP] line prints that version, and without the
        plugin's values the probe answered under the no-caller-checked rule,
        which hides the plugin-built spec but not an env-read value the tool
        printed.

        The answer tells a tool that failed from a probe that never ran:
        ``probed`` is True only when the version probe spawned and exited, and
        ``is_functional`` is True when it exited 0 (a version on stdout or not:
        a tool that prints its version on stderr still runs). A probe that
        timed out, that the sandbox refused, that could not spawn, or whose spec
        the requirement check refused answers ``probed`` False with the cause in
        ``error``; the caller decides whether that is grounds for a reinstall
        (``UVToolMixin._install_uv_tool`` says it is not).
        """
        validation_result: Dict[str, Any] = {
            "tool_name": tool_name,
            "is_functional": False,
            "probed": False,
            "version": None,
            "error": None,
        }

        outcome: Dict[str, Any] = {}
        try:
            # Try to get version to validate functionality
            # refresh=True: this is the caller that decides whether a tool is
            # broken, so it must not inherit a memoized failure. A probe that
            # merely timed out would otherwise make every later caller report
            # is_functional=False for a tool that works.
            version = self.get_tool_version(
                tool_name,
                package_name,
                refresh=True,
                offline=offline,
                package=package,
                values=values,
                probe_outcome=outcome,
            )
            validation_result["probed"] = bool(outcome.get("ran"))
            validation_result["version"] = version
            if version or (outcome.get("ran") and outcome.get("returncode") == 0):
                validation_result["is_functional"] = True
            elif outcome.get("ran"):
                validation_result["error"] = (
                    f"the version probe exited {outcome.get('returncode')}"
                )
            else:
                validation_result["error"] = (
                    "the version probe did not run: "
                    f"{outcome.get('error') or 'no probe was started'}"
                )

        except Exception as e:
            validation_result["error"] = str(e)

        return validation_result


# Global instance
_uv_tool_runner: UVToolRunner = UVToolRunner()


def get_uv_tool_runner() -> UVToolRunner:
    """Get the global UV tool runner instance."""
    global _uv_tool_runner
    if _uv_tool_runner is None:
        _uv_tool_runner = UVToolRunner()
    return _uv_tool_runner


def reset_uv_tool_runner() -> None:
    """Reset the global UV tool runner instance (mainly for testing)."""
    global _uv_tool_runner
    _uv_tool_runner = UVToolRunner()


# ---------------------------------------------------------------------------
# Module-level fallback helpers
#
# Small, dependency-free API that scanners can use to resolve how to invoke a
# tool: prefer ``uv tool run <tool>`` when both ``uv`` and the tool are
# reachable, otherwise fall back to the directly installed binary.  Results
# are memoized per process so the version probe runs only once.
# ---------------------------------------------------------------------------


_uv_command_cache: Dict[str, Optional[List[str]]] = {}
# The file each command in ``_uv_command_cache`` starts, under the same key: the
# uv its version probe ran, or the tool's own executable. A remembered command is
# answered only while that file is still an executable file.
_uv_command_binary: Dict[str, str] = {}
# Whether ``uv tool run [--from <spec>] <tool> --version`` exited 0, keyed by
# the tool, the spec, the offline mode and the uv that ran it -- NOT by the
# scanned-tree scope the command memo above is keyed by. The probe's answer
# does not depend on which tree is being scanned, only the lookups around it
# do, so a workspace scan of N projects used to run N concurrent probes of one
# tool (the first-import race ``_uv_tool_version_cache`` describes); with the
# probe remembered here, the second project's lookup reuses the first's answer
# and runs only its own tree-scoped lookups. Cleared with the other lookups.
_uv_probe_answers: Dict[str, bool] = {}
#: The retry window a timed-out ``get_uv_tool_command`` probe opened for its key:
#: the monotonic time until which the uv probe is skipped for that key. Guarded
#: by ``_uv_tool_runner_cache_lock``; cleared with the caches.
_uv_command_probe_windows: Dict[str, float] = {}
# Keyed by _lookup_key: the name, PATH and ASH_BIN_PATH. Found paths only: a miss
# is looked up again on the next call.
_uv_executable_cache: Dict[Any, str] = {}
_executable_cache: Dict[Any, str] = {}
# How many times _forget_lookups has run. get_uv_tool_command probes without the
# cache lock held, so a clear can come and go while it probes; it remembers what it
# found only if none did, since its probe may predate an install.
_lookup_generation = 0

# ``uv tool run <tool> --version`` results, keyed by ``tool::package``.
#
# Memoizing this is not only a speed-up. The probe *runs the tool*, and a tool
# that loads plugins through ``stevedore`` populates a per-user entry-point
# cache at ``$XDG_CACHE_HOME/python-entrypoints/<digest>`` on first import.
# stevedore writes that file with a plain truncating ``open(path, 'w')`` and no
# lock, and the JSON it writes orders groups by iterating a *set*, so two
# processes emit byte streams of the SAME length but DIFFERENT content. Two
# concurrent first-imports therefore interleave at the 8 KiB buffer flush
# boundary and can leave a file that still parses as JSON but holds an entry
# whose tuple arity is not 3 -- at which point every later reader of that cache
# dies in ``stevedore/_cache.py`` with ``TypeError: EntryPoint.__init__()``.
#
# ASH constructs one scanner per project, and each construction probed the
# version, so an N-project workspace scan fired N concurrent cold-start
# imports of the same tool. Probing once per key means exactly one process ever
# populates that cache and every other reads it. See #542.
#
# Under each "tool::spec" key, one answer per (uv executable, offline) pair:
# a version read through one uv is not another uv's answer, and an offline
# probe is not an online one's. invalidate_tool_version_cache matches the
# outer key, so dropping a tool drops every environment's answer at once.
#
# The stored answer is the probe's RAW unstripped stdout (or None for a
# failed probe), never a redacted or stripped form: callers share the key but
# not their values, so `_version_shown` runs the caller's own redaction on
# every return, and it strips only after redacting, so a value that ends in
# a whitespace-class character still matches whole.
_uv_tool_version_cache: Dict[str, Dict[Tuple[str, bool], Optional[str]]] = {}

#: How many times each "tool::spec" key has been invalidated, for the probe
#: that is mid-flight when an invalidation lands. A probe registers its key
#: here before its subprocess starts and stores its answer only while the
#: count has not moved. The probe lock is deliberately not held by
#: invalidation (an install or uninstall must not wait out a slow probe), so
#: a drop can land while the probe runs, and an unguarded store would then
#: write the pre-drop answer back over the drop. Read and written only under
#: the coarse cache lock, like the caches.
_uv_tool_version_generations: Dict[str, int] = {}


def _version_shown(
    raw: Optional[str],
    values: Optional[Iterable[str]],
    tool_name: str = "",
    package_name: Optional[str] = None,
) -> Optional[str]:
    """The version a caller may carry: *raw* redacted whole, then first line.

    Redacted whole BEFORE the first-line cut: a value with a line break
    printed into the answer would otherwise leave its first half in the
    carried version (the SARIF's ``scanner_version`` and the DEBUG line), a
    piece the downstream whole-value redaction cannot match. And before ANY
    strip: *raw* is the probe's unstripped stdout, because a whole-text strip
    ahead of the redaction shaves the edge off a value that ends in a
    whitespace-class character, and the whole-value match then misses it and
    prints the piece. The carried version is the first line with content of
    the redacted text, stripped -- the line a pre-redaction whole-text strip
    used to select. ``values`` are the calling plugin's own; running this on
    every return, cache hits included, is what keeps one caller's redaction
    from deciding another's.

    The redaction is shown_uv_output's, the one every other reader of uv's
    output uses: uv respells a version ("9.9.9-RC777" prints as
    "9.9.9rc777"), which a match on the value as written never sees. *values*
    keeps its meaning there: None hides every plugin-built input, an explicit
    iterable (the empty one included) hides only the inputs holding one of its
    values. The probe's line is the tool's own ``--version`` answer, so the
    version it prints is the answer and not an argument uv echoed back: a
    caller that checked nothing has the spec hidden from the line, and the
    tool's version, which is also the spec's pin, stays in it
    (``pinned_versions`` False).
    """
    if raw is None:
        return None
    shown = shown_uv_output(
        raw,
        values,
        plugin_inputs=(package_name,),
        tool_name=tool_name,
        limit=None,
        pinned_versions=False,
    )
    for line in shown.splitlines():
        line = line.strip()
        if line:
            return line
    return None


# Coarse lock guarding the four module-level cache dicts above. This lock
# is only held across in-memory reads/writes; it is NOT held across the
# subprocess probe. See `_get_or_create_probe_lock` below for the per-key
# lock used to dedupe concurrent probes for the same `(tool, fallback)`
# pair without serializing distinct pairs.
#
# RLock (reentrant) so callers can call `find_uv_or_none` / `find_executable`
# from inside another lock-holding helper without deadlock.
_uv_tool_runner_cache_lock = threading.RLock()

# Per-cache-key probe locks. Lazily created the first time a thread asks
# about a particular `(tool_name, fallback)` key. Stored in a
# `WeakValueDictionary` so the lock is garbage-collected once no thread is
# blocked on it AND no thread holds a strong reference. This means cold-
# cache lookups for two different tools probe in parallel; only threads
# racing on the *same* key serialize. Settled in an earlier review.
import weakref as _weakref

_uv_tool_probe_locks: "_weakref.WeakValueDictionary[str, threading.Lock]" = (
    _weakref.WeakValueDictionary()
)

# Timeout (seconds) for the ``uv tool run <tool> --version`` probe. Five
# seconds is plenty for ``--version`` on any reasonable host; the previous
# 30s value could stack to ~150s of phase blockage across five cold-cache
# scanners with no progress reporting (an earlier review finding).
_UV_VERSION_PROBE_TIMEOUT = 5

# Timeout for ``UVToolRunner.get_tool_version``, and for ``get_uv_tool_command``'s
# probe when it is given a ``--from`` spec. Higher than the constant above on
# purpose, and the two are not merged. A probe of a bare tool name starts a tool
# uv already has; a probe of a full ``--from`` spec with extras and a version
# constraint, on a cold uv cache, means materializing an environment. Under the
# 5 s budget that probe was killed on every dependency check (a timed-out probe
# is never remembered), each kill leaving the half-written cache the resolver's
# docstring warns about.
#
# Kept at its historical 15s rather than lowered now that the probe is
# serialized. It is true that this is now the whole workspace's stall budget
# instead of one project's -- but it is one 15s worst case for the workspace
# where it used to be N of them, so serializing already improved the bound.
# Lowering it would trade that for a higher rate of memoized failures, and a
# memoized failure is now served process-wide (see ``refresh``), which costs the
# tool version in every project's report.
_UV_TOOL_VERSION_PROBE_TIMEOUT = 15


def _get_or_create_probe_lock(cache_key: str) -> threading.Lock:
    """Return the per-key probe lock for ``cache_key``, creating it if needed.

    ``cache_key`` must be namespaced by caller (``version::``, ``command::``).
    Two callers building the same string share a lock, and these are plain
    non-reentrant ``threading.Lock``, so an accidental collision between two
    probes that can call into each other is a deadlock rather than a slowdown.

    STRONG-REF CONTRACT: ``_uv_tool_probe_locks`` holds its values weakly, so
    the caller must keep a reference to the returned lock alive until it has
    acquired it -- binding it to a local, as both callers here do, is enough. If
    the only reference were dropped before the acquire, a concurrent thread on
    the same key could create a *different* lock object and the per-key
    serialization would silently stop working. This contract is asserted by
    inspection, not by a test: a test written in the obvious way holds a strong
    reference itself and so cannot fail.

    Must be called with ``_uv_tool_runner_cache_lock`` held, so that two
    threads racing on the same key agree on one lock object.
    """
    probe_lock = _uv_tool_probe_locks.get(cache_key)
    if probe_lock is None:
        probe_lock = threading.Lock()
        _uv_tool_probe_locks[cache_key] = probe_lock
    return probe_lock


@contextlib.contextmanager
def _probe_lock_held(probe_lock: threading.Lock):
    """Hold *probe_lock* for the block, polling cancellation while parked.

    A plain ``with probe_lock`` blocks uninterruptibly: a caller whose scan is
    cancelled while another caller's slow probe holds the key would wait that
    probe out (up to its subprocess timeout) and then answer as if the scan
    were still running. The acquire polls instead, the same shape as the
    availability probe's own lock, so a cancel reaches the parked thread
    within one poll interval; the post-acquire check covers a cancel that
    landed in the instant the lock was handed over.
    """
    from automated_security_helper.core.cancellation import raise_if_cancelled

    raise_if_cancelled()
    while not probe_lock.acquire(timeout=_UV_PROBE_CANCEL_POLL_SECONDS):
        raise_if_cancelled()
    try:
        raise_if_cancelled()
        yield
    finally:
        probe_lock.release()


def _requirement_base_name(spec: str) -> str:
    """The bare package name at the front of a requirement spec.

    ``bandit[sarif,toml]>=1.7.0,<2.0.0`` -> ``bandit``. Used so an invalidation
    naming a package still matches memo keys whose ``--from`` segment carries
    extras and a version constraint.
    """
    for index, char in enumerate(spec):
        if char in "[]<>=!~;, ":
            return spec[:index].strip()
    return spec.strip()


def invalidate_tool_version_cache(name: str) -> None:
    """Forget memoized ``--version`` answers for a tool, by either of its names.

    Matching on a single spelling is not enough. A memo key is
    ``"<command>::<from-spec>"``, but the name reaching
    ``install_tool_with_version`` is ``uv_tool_package_name or command``
    (``UVToolMixin._install_uv_tool``), so the installer often knows the tool by
    its *package* name while the probe keyed on its *command* name. For
    JupyterConverter those differ -- command ``jupyter-nbconvert``, package
    ``nbconvert`` -- so a prefix match on the package name cleared nothing and
    the pre-install ``None`` survived the install it was supposed to be
    invalidated by.

    So compare against both segments of the key, and against the bare package
    name of each, since the ``--from`` segment carries extras and constraints.

    A probe for a matched key can be mid-flight right now (the probe lock is
    not held here, so an install never waits out a slow probe). Deleting the
    memo alone would not stop that probe's own store from writing its
    pre-drop answer back once it finishes, so the key's generation moves
    too, which turns that store into a no-op; the keys a probe has
    registered but never stored are matched as well.
    """
    with _uv_tool_runner_cache_lock:
        doomed = []
        for key in set(_uv_tool_version_cache) | set(_uv_tool_version_generations):
            command_segment, _, from_segment = key.partition("::")
            candidates = {
                command_segment,
                from_segment,
                _requirement_base_name(command_segment),
                _requirement_base_name(from_segment),
            }
            if name in candidates or _requirement_base_name(name) in candidates:
                doomed.append(key)
        for key in doomed:
            _uv_tool_version_cache.pop(key, None)
            _uv_tool_version_generations[key] = (
                _uv_tool_version_generations.get(key, 0) + 1
            )


def _reset_uv_tool_runner_caches() -> None:
    """Reset module-level caches (mainly for testing)."""
    global _lookup_generation
    with _uv_tool_runner_cache_lock:
        _lookup_generation += 1
        _uv_command_cache.clear()
        _uv_command_binary.clear()
        _uv_probe_answers.clear()
        _uv_command_probe_windows.clear()
        _uv_executable_cache.clear()
        _executable_cache.clear()
        _uv_tool_version_cache.clear()
        # Advanced, not cleared, exactly as invalidate_tool_version_cache moves
        # a key it drops: a probe that read generation 0 before this reset and
        # finishes after it would find a cleared dict answering 0 again, pass
        # its store check and write its pre-reset answer into the fresh memo.
        # Every registered key moves, so a mid-flight probe's store is skipped.
        for key in list(_uv_tool_version_generations):
            _uv_tool_version_generations[key] += 1


def _forget_lookups() -> None:
    """Forget the paths and commands looked up through find_executable, for
    ``subprocess_utils.clear_find_executable_cache`` after an install: each is
    looked up again. The tool versions probed are kept. A get_uv_tool_command
    still probing when this runs answers what it found and does not remember it."""
    global _lookup_generation
    with _uv_tool_runner_cache_lock:
        _lookup_generation += 1
        _uv_command_cache.clear()
        _uv_command_binary.clear()
        # An install is exactly what changes a probe's answer.
        _uv_probe_answers.clear()
        _uv_command_probe_windows.clear()
        _uv_executable_cache.clear()
        _executable_cache.clear()


def _still_usable(path: Optional[str]) -> bool:
    """Whether a remembered path may be given again: it is still an executable
    file. None, for a remembered command whose file is not known, passes."""
    from automated_security_helper.utils.subprocess_utils import _is_executable_file

    return path is None or _is_executable_file(path)


def _remembered_path(memo: Dict[Any, str], key: Any) -> Optional[str]:
    """``memo[key]`` while it is still an executable file, else None."""
    path = memo.get(key)
    return path if path is not None and _still_usable(path) else None


def _remember_path(memo: Dict[Any, str], key: Any, path: Optional[str]) -> None:
    """Remember a found path; a miss is never remembered, so the next lookup
    searches again and finds a tool installed in between."""
    if path is not None:
        memo[key] = path
    else:
        memo.pop(key, None)


#: Environment variables that send uv to another project directory: ``--project``
#: and ``--directory``. ``uv cache`` runs without them (see ``_run_uv_cache``).
_UV_PROJECT_LOCATORS = ("UV_PROJECT", "UV_WORKING_DIR")


def _uv_cache_cwd() -> str:
    r"""The working directory ``uv cache`` runs from: the filesystem root.

    On POSIX that is ``/``, where only root can create the ``uv.toml`` or
    ``pyproject.toml`` uv would read. On Windows it is the system drive's root
    (``%SystemDrive%\``, normally ``C:\``), not the current drive's: by default
    Windows lets ordinary users create folders there but not files, so a
    ``uv.toml`` file there needs an administrator, while another drive's root (the
    one holding the scanned repository, say) may be writable by anyone. That
    Windows default comes from its documented root ACL and was not measured here.
    Any user can create a *folder* named ``C:\uv.toml``; uv then fails to read it
    and ``uv cache dir`` exits non-zero (measured on Linux with a directory named
    ``uv.toml``: exit 2, "Is a directory"), so the check fails closed.

    Without ``SystemDrive`` the drive comes from ``SystemRoot``, and without either
    it is ``C:``. Only a drive letter counts: the drive of ``sys.executable`` was
    a share's root for an interpreter on a UNC path, and ``\`` (the current
    drive's root) for an empty one.
    """
    if sys.platform == "win32":
        return _windows_system_drive_root()
    return os.path.abspath(os.sep)


def _windows_system_drive_root() -> str:
    r"""``%SystemDrive%\``, else the drive of ``%SystemRoot%``, else ``C:\``."""
    for variable in ("SystemDrive", "SystemRoot"):
        # ntpath, so the parsing is Windows' wherever this runs.
        drive = ntpath.splitdrive(os.environ.get(variable) or "")[0]
        if len(drive) == 2 and drive[1] == ":" and drive[0].isalpha():
            return drive + "\\"
    return "C:\\"


def _uv_package_directory() -> Optional[Path]:
    """Where the ``uv`` package ASH depends on is installed, without importing it."""
    import importlib.util

    try:
        spec = importlib.util.find_spec("uv")
    except (ImportError, ValueError):
        return None
    origin = getattr(spec, "origin", None) if spec is not None else None
    if not origin or not os.path.isabs(origin):
        return None
    return Path(origin).parent


def _uv_package_layout_dirs(package: PurePath, windows: bool) -> List[PurePath]:
    """Where the uv package's own layout puts its executable, given its directory.

    The layouts pip installs into outside a virtual environment, as sysconfig
    defines them: ``<prefix>/lib/pythonX.Y/site-packages/uv`` (``pip install
    --prefix``, and ``--user`` on POSIX, where the prefix is ``~/.local`` or the
    macOS framework's user base) has it in ``<prefix>/bin``. The uv wheel is
    platform-specific, so it goes to platlib, which is ``lib64`` on Fedora, RHEL
    and Amazon Linux (``sys.platlibdir``). On Windows
    ``<prefix>\\Lib\\site-packages\\uv`` has it in ``<prefix>\\Scripts``, and the
    ``--user`` layout ``%APPDATA%\\Python\\Python3XY\\site-packages\\uv`` in
    ``%APPDATA%\\Python\\Python3XY\\Scripts``. ``<target>/uv`` (``pip install
    --target``) has it in ``<target>/bin``.
    """
    parts = [part.lower() for part in package.parts]
    if len(parts) >= 2 and parts[-2] == "site-packages":
        if windows:
            if len(parts) >= 3 and parts[-3] == "lib":
                return [package.parents[2] / "Scripts"]
            return [package.parents[1] / "Scripts"]
        if len(parts) >= 4 and parts[-4] in {"lib", "lib64", sys.platlibdir.lower()}:
            return [package.parents[3] / "bin"]
        return []
    return [package.parent / "bin"]


def _bundled_uv_candidates() -> List[Path]:
    """Every place the uv installed with ASH can be, in the order to try them."""
    import sysconfig

    from automated_security_helper.utils.subprocess_utils import own_environment_dirs

    directories: List[PurePath] = list(own_environment_dirs())
    package = _uv_package_directory()
    if package is not None:
        directories.extend(_uv_package_layout_dirs(package, sys.platform == "win32"))
    name = f"uv{sysconfig.get_config_var('EXE') or ''}"
    return [
        Path(directory) / name
        for directory in dict.fromkeys(directories)
        if os.path.isabs(directory)
    ]


def bundled_uv_executable() -> Optional[str]:
    """The uv installed together with ASH, or None.

    ASH depends on the ``uv`` package, whose wheel puts a uv executable in the
    scripts directory of the environment it is installed into. pipx links only
    ``ash`` onto PATH, a uv tool or an unactivated venv keeps its bin directory off
    PATH, so a lookup on PATH alone left those installs without the uv they
    already have.

    Looked for, in order: beside ``sys.executable``; in the interpreter's scripts
    directory, which on a Windows Python outside a virtual environment is
    ``<prefix>\\Scripts`` rather than the interpreter's own directory; and where
    the ``uv`` package's own layout puts its executable for a ``pip install
    --prefix``, ``--user`` or ``--target`` install. The first that is a file and
    executable wins: a uv on a noexec mount is skipped rather than chosen over a
    later one that runs.

    Trust. These are ASH's own install: the environment ``sys.executable`` runs
    from, and the uv package ASH imports, located through the same ``sys.path``
    its other imports use. The uv found here is trusted as the interpreter is.
    When that environment is inside the tree being scanned (ASH started from a
    repository's ``.venv``), the spawn layer refuses this uv as it refuses every
    program inside the tree (only the running interpreter is exempt), so this
    function's answer is not always one that can run: :func:`find_uv_or_none`
    applies that rule before choosing it and falls through to a uv outside the
    tree. ``find_uv_bin`` also looks in the base interpreter's scripts directory and in
    the user's (``~/.local/bin``) whatever the package's own location; those are
    not searched here unless the package itself was installed there (``pip
    install --user``). A uv anywhere else is a program like any other, found by
    ``find_executable`` and subject to whatever it refuses.
    """
    for candidate in _bundled_uv_candidates():
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def _lookup_key(name: str) -> Any:
    """Cache key for a lookup: the name, the scanned-tree scope it was made in,
    and PATH and ASH_BIN_PATH.

    The answer depends on the trees being scanned and the in-tree opt-in (see
    subprocess_utils.scanning_tree), and on the directories searched, so one
    scan's or environment's answer is not another's. An unset PATH (the system's
    default directories) is told apart from an empty one (none).
    """
    from automated_security_helper.utils.subprocess_utils import tree_scope_key

    return (
        name,
        tree_scope_key(),
        os.environ.get("PATH"),
        os.environ.get("ASH_BIN_PATH", ""),
    )


def _refused_inside_scanned_tree(path: str) -> Optional[str]:
    """The scanned tree ``path`` lies in when the spawn layer would refuse it.

    The same rule ``subprocess_utils._first_usable`` applies to a program it
    is asked to start: inside one of the active scan's trees, and in-tree tools
    not allowed. None outside a scan, when the operator allowed in-tree tools,
    or when ``path`` is outside every tree. Decided here, before a candidate is
    chosen, so a refusal is never the chosen uv's fate: the spawn of a refused
    uv raises ``FileNotFoundError`` for every caller, and
    ``UVToolRunner.uv_availability`` used to remember that as "uv absent" for
    the rest of the process.
    """
    from automated_security_helper.utils.scanned_tree import is_inside_tree
    from automated_security_helper.utils.subprocess_utils import (
        in_tree_tools_allowed,
        scanned_trees,
    )

    roots = scanned_trees()
    if not roots or in_tree_tools_allowed():
        return None
    for root in roots:
        if is_inside_tree(path, root):
            return root
    return None


def find_uv_or_none() -> Optional[str]:
    """Return the path to the ``uv`` binary, or ``None`` if it is missing.

    The uv installed with ASH (:func:`bundled_uv_executable`) comes first, then
    ``find_executable``'s search: PATH, the ASH bin directory, /usr/local/bin.
    ASH's own copy is preferred over PATH's because it is the version ASH's
    dependency bounds were resolved against.

    The bundled uv is skipped when it lies inside a tree the active scan is
    scanning and in-tree tools are not allowed: the spawn layer refuses such a
    program, so choosing it would make every uv call fail as if uv were absent.
    The search falls through to a uv outside the tree, and the answer is
    remembered per scan scope (:func:`_lookup_key`), so a scan of another tree
    looks again.
    """
    key = _lookup_key("uv")
    with _uv_tool_runner_cache_lock:
        remembered = _remembered_path(_uv_executable_cache, key)
        if remembered is not None:
            return remembered

        from automated_security_helper.utils.subprocess_utils import (
            find_executable as _find_executable,
        )

        bundled = bundled_uv_executable()
        if bundled is not None:
            refused_in = _refused_inside_scanned_tree(bundled)
            if refused_in is not None:
                from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP

                ASH_LOGGER.debug(
                    f"The uv installed with ASH, {bundled}, lies inside the "
                    f"scanned tree {refused_in}, where ASH does not run tools; "
                    "looking for a uv outside the tree instead.",
                    extra=NO_MARKUP,
                )
                bundled = None
        resolved = bundled or _find_executable("uv")
        _remember_path(_uv_executable_cache, key, resolved)
        return resolved


def find_executable(name: str) -> Optional[str]:
    """Find an executable by direct path, then PATH lookup."""
    key = _lookup_key(name)
    with _uv_tool_runner_cache_lock:
        remembered = _remembered_path(_executable_cache, key)
        if remembered is not None:
            return remembered

        from automated_security_helper.utils.subprocess_utils import (
            find_executable as _find_executable,
        )

        resolved = _find_executable(name)
        _remember_path(_executable_cache, key, resolved)
        return resolved


def get_uv_tool_command(
    tool_name: str,
    *,
    fallback_binary: Optional[str] = None,
    from_spec: Optional[str] = None,
    offline: Optional[bool] = None,
    package: Optional[str] = None,
) -> Optional[List[str]]:
    """Resolve the command list to invoke ``tool_name``.

    Resolution order:

    1. If ``uv`` exists and ``uv tool run [--from <from_spec>] <tool_name>
       --version`` succeeds, return ``["uv", "tool", "run", tool_name]``, with
       ``"--from", from_spec`` before the tool name when a spec was given: the
       command carries the environment it was probed under.
    2. Else if ``fallback_binary`` (default: ``tool_name``) is found on PATH,
       return ``[<fallback_path>]``.
    3. Else return ``None`` (caller marks deps unsatisfied).

    ``from_spec`` is the ``--from`` requirement the scan itself runs under
    (``UVToolMixin._uv_from_spec``): ``uv tool run --from 'bandit[sarif]' bandit``
    resolves a different environment than the bare ``uv tool run bandit``, so a
    probe without it answers for an environment the scan never uses. With it the
    probe runs ``uv tool run --from <from_spec> <tool_name> --version``. The spec
    is checked first (``checked_requirement``, against ``package`` when the
    caller names the package it built the spec around): a spec uv must not see,
    a glued constraint naming another package among them, answers None with a
    warning and no probe, so the dependency check never installs it.

    ``offline`` is the caller's own offline mode (a scanner's
    ``options.offline``); None follows ASH's (``_offline_for``).

    Memoized per process so the version probe runs only once per
    ``(tool_name, fallback_binary, from_spec)`` triple in each environment (PATH,
    ASH_BIN_PATH, and whether the probe is offline: an offline probe resolves
    from uv's cache alone, so its miss is not an online probe's answer, nor the
    reverse).
    Thread-safe: a single shared lock guards reads, writes, and
    the underlying probe so concurrent threads racing on the same cache key see
    exactly one probe and a consistent result.

    A probe that timed out opens a retry window of ``_UV_PROBE_RETRY_SECONDS``
    for its key, as ``uv_availability`` does: callers in the window skip the uv
    probe and take the PATH binary or None for that call, nothing is remembered,
    and the probe runs again once the window has passed. Without it every
    waiter on the key paid the probe's timeout in turn, each killed probe adding
    to the half-written-cache risk the offline comment below describes.

    A remembered command is answered only while the file it starts, the uv the
    probe ran or the tool's own executable, is still an executable file. When it
    is gone the answer is None and an error names the file; the probe is not run
    again in the same environment.

    A None is remembered only when the probe ran to an exit and neither it nor
    the direct lookup found the tool. Probing again on every call would start
    the tool once per caller, the concurrent first runs ``_uv_tool_version_cache``
    explains, and cost the probe's time again. With no uv found nothing was
    probed, so a None is looked up again on the next call and a tool installed
    in between is found. A probe that did not run to an exit, one that timed out
    or whose spawn failed or was refused by the sandbox scope, is not uv's answer
    about the tool: its None is answered for that call and looked up again on the
    next, as a missing uv's is.

    The uv branch names ``uv`` bare while the probe ran ``find_uv_or_none``'s copy,
    which prefers the uv installed with ASH over PATH's. A spawn of the bare name
    would look it up on PATH instead, so the two can be different files. No caller
    spawns this command: the scanners test it for None. A caller that starts it must run the uv the probe ran
    (``find_uv_or_none()``), not the name.
    """
    # Offline, probe offline, for the reason given in
    # UVToolRunner.get_tool_version: an online probe here resolved and
    # downloaded the tool from PyPI under ASH_OFFLINE, and the 5s timeout
    # could leave a half-written uv cache behind. Read once, with the key: the
    # offline answer and the online one are different questions. The caller's
    # own mode when given, else ASH's.
    offline = _offline_for(offline)
    if from_spec:
        try:
            checked_requirement(
                from_spec, f"the --from spec for {tool_name}", package=package
            )
        except UVToolRunnerError as error:
            from automated_security_helper.utils.log import ASH_LOGGER

            # The refusal's text carries no part of the spec (see
            # checked_requirement); the tool's name is this call's own argument.
            ASH_LOGGER.warning(f"{tool_name}: {error}")
            return None
    binary = fallback_binary or tool_name
    lookup = _lookup_key(binary)
    cache_key = (
        f"{tool_name}::{binary}::{from_spec or ''}::offline={int(offline)}"
        f"::{lookup[1:]!r}"
    )

    # Fast-path: cache hit under the coarse lock.
    with _uv_tool_runner_cache_lock:
        if cache_key in _uv_command_cache:
            return _remembered_command(cache_key)
        # Get-or-create the per-key probe lock under the coarse lock so two
        # threads racing here see the same lock object. STRONG-REF CONTRACT
        # (from an earlier review): `probe_lock` must stay in scope until after the acquire
        # below -- see _get_or_create_probe_lock. The `command::` prefix keeps
        # these keys disjoint from get_tool_version's; without it,
        # get_tool_version("bandit", "bandit") and get_uv_tool_command("bandit")
        # both produce "bandit::bandit" and share a non-reentrant lock.
        probe_lock = _get_or_create_probe_lock(f"command::{cache_key}")

    # Per-key lock: serialize probes for THIS cache key without blocking
    # probes for other cache keys. The coarse cache lock is NOT held here,
    # so the slow `uv tool run --version` subprocess does not serialize all
    # parallel scanner cold-cache lookups. Held through the polling helper,
    # so a waiter whose scan is cancelled stops instead of waiting the
    # probe out.
    with _probe_lock_held(probe_lock):
        # Re-check under the probe lock — another thread may have populated
        # the cache while we waited.
        with _uv_tool_runner_cache_lock:
            if cache_key in _uv_command_cache:
                return _remembered_command(cache_key)
            generation = _lookup_generation

        uv_path = find_uv_or_none()
        command: Optional[List[str]] = None
        started: Optional[str] = None
        # Whether the probe ran to an exit. A probe that timed out, or whose
        # spawn failed or was refused, answered nothing about the tool, and its
        # None is not remembered (see above).
        probe_exited = False
        if uv_path is not None:
            probe_offline = offline or is_checking_only()
            probe_key = (
                f"{tool_name}::{from_spec or ''}::offline={int(probe_offline)}"
                f"::{uv_path}"
            )
            with _uv_tool_runner_cache_lock:
                remembered_probe = _uv_probe_answers.get(probe_key)
            if remembered_probe is not None:
                # The same question was answered for another scanned tree in
                # this process: uv's answer about its copy of the tool does not
                # depend on the tree, so the tool is not started again.
                probe_exited = True
                if remembered_probe:
                    # With the --from it was probed under, as the probe below
                    # answers: the bare command resolves another environment.
                    command = ["uv", "tool", "run"]
                    if from_spec:
                        command.extend(["--from", from_spec])
                    command.append(tool_name)
                    started = uv_path
        # A timed-out probe's retry window (see the docstring): while it is
        # open the uv probe is skipped, and the call is answered as an
        # inconclusive probe's is, from the PATH lookup and without a memo.
        with _uv_tool_runner_cache_lock:
            window_until = _uv_command_probe_windows.get(cache_key)
            if window_until is not None and time.monotonic() >= window_until:
                _uv_command_probe_windows.pop(cache_key, None)
                window_until = None
        if uv_path is not None and not probe_exited and window_until is None:
            probe_command = [uv_path, "tool", "run"]
            probe_env: Optional[Dict[str, str]] = None
            # Offline in check-only mode too, which must not download.
            if probe_offline:
                probe_command.append("--offline")
                probe_env = snapshot_environ()
                probe_env["UV_OFFLINE"] = "1"
            if from_spec:
                probe_command.extend(["--from", from_spec])
            probe_command.extend([tool_name, "--version"])
            try:
                probe = spawn_run(  # nosec B603 — fixed list of trusted strings
                    probe_command,
                    capture_output=True,
                    text=True,
                    check=False,
                    env=probe_env if probe_env is not None else snapshot_environ(),
                    # A --from spec may have to build its environment first;
                    # the bare name keeps the short budget (see the constants).
                    timeout=(
                        _UV_TOOL_VERSION_PROBE_TIMEOUT
                        if from_spec
                        else _UV_VERSION_PROBE_TIMEOUT
                    ),
                    # As every other probe in this module decodes: the locale
                    # codec in strict mode raised UnicodeDecodeError, which is
                    # neither a SubprocessError nor an OSError, out of this
                    # resolver instead of falling back to the direct binary.
                    encoding="utf-8",
                    errors="replace",
                )
                # Neither memo has a scope in its key, on purpose: uv's answer
                # about its copy of the tool does not depend on the tree. A
                # non-zero exit from inside a sandbox scope is not that answer,
                # though: the wrapper's view of the filesystem and network
                # decides what the probe could reach there (as uv_availability
                # and get_tool_version already read it), so remembered it
                # would serve one backend's refusal to every caller on the
                # host for the rest of the process. It counts as a probe that
                # did not answer: this call falls back to the PATH binary and
                # nothing is remembered. A success is uv's own, in any scope.
                probe_exited = probe.returncode == 0 or _probe_scope_key() is None
                if probe.returncode == 0:
                    # With the --from it was probed under: the bare command
                    # resolves another environment than the one that answered.
                    command = ["uv", "tool", "run"]
                    if from_spec:
                        command.extend(["--from", from_spec])
                    command.append(tool_name)
                    started = uv_path
                if probe_exited and not is_checking_only():
                    with _uv_tool_runner_cache_lock:
                        if _lookup_generation == generation:
                            _uv_probe_answers[probe_key] = probe.returncode == 0
            except subprocess.TimeoutExpired:
                with _uv_tool_runner_cache_lock:
                    _uv_command_probe_windows[cache_key] = (
                        time.monotonic() + _UV_PROBE_RETRY_SECONDS
                    )
            except (subprocess.SubprocessError, OSError):
                pass

        if command is None:
            direct = find_executable(binary)
            if direct is not None:
                command = [direct]
                started = direct

        # A check-only probe ran offline, so a miss there is not the scan's
        # answer: remembered, it would tell the next scan the tool is absent. Nor
        # is an answer remembered past a clear that ran while it was looked for.
        if not is_checking_only():
            with _uv_tool_runner_cache_lock:
                if _lookup_generation != generation:
                    return command
                # A probe that never exited (a timeout, a refused or failed
                # spawn) answered nothing about uv's copy of the tool: this
                # call runs the PATH binary it found, if any, and nothing is
                # remembered, so the next call probes uv again. Remembered,
                # one slow probe pinned the tool to its PATH binary for the
                # rest of the process. A None is remembered only after a probe
                # ran to an exit: probing again on each call is what the memo
                # is for (see above). With no uv to probe, the lookups behind a
                # None are searched again on the next call.
                probe_inconclusive = uv_path is not None and not probe_exited
                if probe_inconclusive:
                    _uv_command_cache.pop(cache_key, None)
                    _uv_command_binary.pop(cache_key, None)
                    return command
                if command is not None or probe_exited:
                    _uv_command_cache[cache_key] = command
                else:
                    _uv_command_cache.pop(cache_key, None)
                if started is not None:
                    _uv_command_binary[cache_key] = started
                else:
                    _uv_command_binary.pop(cache_key, None)
        return command


def _remembered_command(cache_key: str) -> Optional[List[str]]:
    """``_uv_command_cache[cache_key]``, or None when the file it starts is gone.

    Called with ``_uv_tool_runner_cache_lock`` held. Nothing is probed again: in an
    unchanged environment a uv or a tool that disappeared is reported, not quietly
    replaced by whatever another probe would find.
    """
    command = _uv_command_cache[cache_key]
    if command is None:
        return None
    started = _uv_command_binary.get(cache_key)
    if started is None and os.path.isabs(command[0]):
        started = command[0]
    if _still_usable(started):
        return command
    from automated_security_helper.utils.log import ASH_LOGGER, NO_MARKUP

    ASH_LOGGER.error(
        f"{started} is no longer an executable file, so `{' '.join(command)}` "
        "cannot run. It was found earlier in this run; reinstall it there, or "
        "put another on PATH.",
        extra=NO_MARKUP,
    )
    return None
