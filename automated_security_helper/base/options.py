import re
import threading
from typing import Annotated, Any, ClassVar, FrozenSet, Literal, Set, Tuple

from pydantic import BaseModel, ConfigDict, Field, ValidatorFunctionWrapHandler
from pydantic import ValidationError, ValidationInfo, WrapValidator, model_validator
from pydantic_core import PydanticUseDefault

from automated_security_helper.core.constants import ASH_DEFAULT_SEVERITY_LEVEL
from automated_security_helper.utils.redacted_model import RedactedSection
from automated_security_helper.utils.unknown_keys import (
    refuse_unknown_keys,
    tolerated_notes,
)

# (key, value) pairs already warned about. A plugin's options are validated several
# times per scan (the config, its dump, each plugin instance), and one refusal
# should produce one warning.
_REFUSED_TOOL_VERSIONS: Set[Tuple[str, str]] = set()
_REFUSED_TOOL_VERSIONS_LOCK = threading.Lock()


def reset_refused_tool_version_warnings() -> None:
    """Forget which refusals were already logged (tests)."""
    with _REFUSED_TOOL_VERSIONS_LOCK:
        _REFUSED_TOOL_VERSIONS.clear()


#: A release tag: an optional ``v``, a number, then any run of ``-`` or ``.``
#: separated alphanumeric parts (``v1.15.1``, ``1.2.0-rc1``). Nothing that can
#: change the path of the URL the tag is put into. ONE repeated group: with a
#: dot-number group followed by a separator-alphanumeric group, a ``.1`` part
#: matched under either, and a long string that fails at its end (a value that is
#: not a tag) backtracked through every split of the two, quadratic in its length,
#: during config validation. Each part here starts at its separator and runs to the
#: next, so a failing match is linear.
_RELEASE_TAG = re.compile(r"v?[0-9]+(?:[-.][0-9A-Za-z]+)*")


def release_tag(key: str) -> WrapValidator:
    """Validator for a version that names a release to download, named ``key``.

    The value is put into a download URL (opengrep's ``version``), so only a
    release tag is accepted, from any source. Anything else is replaced by the
    option's default, with one warning naming ``key``.
    """

    def _validate(value: Any, handler: ValidatorFunctionWrapHandler, _info: Any) -> Any:
        try:
            typed = handler(value)
        except ValidationError:
            # A value of the wrong type (a YAML number) is refused like any other.
            typed = None
        if isinstance(typed, str) and _RELEASE_TAG.fullmatch(typed):
            return typed
        # The key and the rule, not the value: a value can be one read from the
        # environment, and the warning goes to the console and ash.log.
        _warn_once(
            key,
            str(value),
            f"Ignoring {key}: the value is not a release tag such as 'v1.2.3'. "
            "Using the pinned version instead.",
        )
        raise PydanticUseDefault from None

    return WrapValidator(_validate)


def _warn_once(key: str, value: str, message: str) -> None:
    with _REFUSED_TOOL_VERSIONS_LOCK:
        first = (key, value) not in _REFUSED_TOOL_VERSIONS
        _REFUSED_TOOL_VERSIONS.add((key, value))
    if first:
        from automated_security_helper.utils.log import ASH_LOGGER

        ASH_LOGGER.warning(message)


def tool_version_constraint(key: str) -> WrapValidator:
    """Validator for a plugin's ``tool_version`` option, named ``key`` in warnings.

    The value becomes part of the requirement that uv or pip installs, so only a
    PEP 440 version specifier set is accepted (see
    ``utils/pre_installed_tool.validate_version_constraint``). Anything else is
    replaced by the option's default, with one warning naming ``key``, wherever the
    value came from: a config file, ``--config-overrides`` or Python.
    """

    def _validate(value: Any, handler: ValidatorFunctionWrapHandler, _info: Any) -> Any:
        from automated_security_helper.utils.pre_installed_tool import (
            validate_version_constraint,
        )

        try:
            return validate_version_constraint(handler(value))
        except ValueError:
            # The handler's ValidationError is a ValueError too: a value of the
            # wrong type (a YAML number) is refused like any other.
            # Not the check's message, which quotes the value; see release_tag.
            _warn_once(
                key,
                str(value),
                f"Ignoring {key}: the value is not a version constraint; use PEP 440 "
                "specifiers such as '>=1.2.0,<2.0.0' or '==1.4.1'. Using the default "
                "constraint instead.",
            )
            raise PydanticUseDefault from None

    return WrapValidator(_validate)


def report_file_name(key: str) -> WrapValidator:
    """Validator for an option that names a file in the reports directory, named ``key``.

    A reporter writes such a file directly inside the reports directory, so only a
    single path component is accepted, from any source: a value with ``/``, ``\\``,
    ``:`` (an NTFS stream of another file) or NUL, or one that is ``.`` or ``..``,
    is replaced by the option's default, with one warning naming ``key`` and
    every refused character, so the operator can see which one the value held.
    """

    def _validate(value: Any, handler: ValidatorFunctionWrapHandler, _info: Any) -> Any:
        from automated_security_helper.utils.report_path_links import (
            is_report_file_name,
        )

        try:
            typed = handler(value)
        except ValidationError:
            # A value of the wrong type is refused like any other; see release_tag.
            typed = None
        if is_report_file_name(typed):
            return typed
        # The key and the rule, not the value; see release_tag.
        _warn_once(
            key,
            str(value),
            f"Ignoring {key}: the value is not a file name such as 'summary.md'. "
            "The file is written directly inside the reports directory, so the name "
            "cannot contain '/', '\\', ':' or NUL, or be '.' or '..'. Using the "
            "default instead.",
        )
        raise PydanticUseDefault from None

    return WrapValidator(_validate)


class BuilderOptionsBase(BaseModel):
    """Base class for builder options."""

    model_config = ConfigDict(
        extra="allow", arbitrary_types_allowed=True, hide_input_in_errors=True
    )


class PluginOptionsBase(RedactedSection):
    """Base class for plugin options."""

    # Unknown keys are refused by _refuse_unknown_options. Extras are allowed only
    # so that a results file holding one keeps it (utils/unknown_keys.py); the
    # schema says what a config file may contain.
    model_config = ConfigDict(
        extra="allow",
        arbitrary_types_allowed=True,
        # A refused value can be a secret read from the environment, and an
        # error's text goes wherever the error is shown. Every options class
        # inherits this, as pydantic merges a subclass's settings with its base's.
        hide_input_in_errors=True,
        json_schema_extra={"additionalProperties": False},
    )

    @model_validator(mode="before")
    @classmethod
    def _refuse_unknown_options(cls, data: Any, info: ValidationInfo) -> Any:
        """Refuse an option the plugin does not declare, rather than keep it unread.

        Kept, ``severity_level: HIGH`` under bandit (the option is
        ``severity_threshold``) left bandit gating at the global threshold and
        said nothing. A built-in plugin's options are validated when the config
        loads, so the error names the plugin by its location
        (``scanners.bandit.options``). A plugin loaded from ``ash_plugin_modules``
        is checked once it is loaded (config/plugin_option_check.py).

        The generic bases themselves record nothing when a results file is read
        (utils/unknown_keys.py). They stand in for a plugin's own options model
        wherever that model cannot be known: a community plugin's section in the
        config segments is validated against ``ScannerPluginConfigBase`` as one
        branch of a union, which then keeps the plain mapping. Its declared
        options are unknown only to the stand-in, and a note recorded there
        survived the discarded branch, so every results load warned about them.
        Outside a results file the bases still refuse, so a plugin whose own
        config fails cannot fall back to the generic one and run with defaults.
        """
        if cls in _GENERIC_OPTION_BASES and tolerated_notes(info) is not None:
            return data
        return refuse_unknown_keys(cls, data, info, "these plugin options")


class ConverterOptionsBase(PluginOptionsBase):
    """Base class for converter options."""


class ScannerOptionsBase(PluginOptionsBase):
    """Base class for scanner options."""

    #: scan_timeout may be set from an environment reference: the field's own
    #: validation types the resolved text (a lax plugin model reads "67" as
    #: 67; a config-file load raises the named environment-reference refusal,
    #: as at every other typed slot that cannot keep the text).
    #: Opted in because every line that shows the limit is measured to show
    #: it by reference, never by value: the timeout record and the pre-scan
    #: dumps redact the recorded text
    #: (tests/unit/base/test_failure_lines_carry_no_environment_value.py),
    #: and the section's own repr shows the typed number as ``<value>``
    #: (RedactedSection.__repr_args__, which the text needle cannot cover:
    #: the typed number is not the text the environment wrote).
    _env_scalar_typed_fields: ClassVar[FrozenSet[str]] = frozenset({"scan_timeout"})

    severity_threshold: Annotated[
        Literal["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None,
        Field(
            description=f"Minimum severity level to consider findings as failures. This is a scanner-level override of the default severity-level within ASH of {ASH_DEFAULT_SEVERITY_LEVEL}."
        ),
    ] = None

    # Lives on the base rather than on individual scanners because the hang it
    # prevents is a property of the shared subprocess path, not of any one tool.
    # detect-secrets previously carried its own copy of this option, which is why
    # it was the only scanner that timed out cleanly while the rest could run
    # unbounded. 300 matches the default it chose.
    scan_timeout: Annotated[
        int | None,
        Field(
            description=(
                "Maximum time in seconds to allow this scanner's tool invocation "
                "to run before it is killed. Set to null to leave the scanner "
                "unbounded, which risks a scan that never completes."
            ),
            ge=1,
        ),
    ] = 1800

    # Declared here because ScannerPluginBase._scanner_offline reads it for every
    # scanner. Scanners whose tool can go online redeclare it with their own
    # description; the rest take this declaration, so a config that sets it on any
    # scanner is accepted.
    offline: Annotated[
        bool,
        Field(
            description=(
                "Run this scanner offline even when ASH runs online. False follows "
                "ASH's own mode; it never puts a scanner online under --offline."
            ),
        ),
    ] = False


class ReporterOptionsBase(PluginOptionsBase):
    """Base class for reporter options."""


# The options bases a plugin's own options model subclasses. See
# PluginOptionsBase._refuse_unknown_options.
_GENERIC_OPTION_BASES = (
    PluginOptionsBase,
    ConverterOptionsBase,
    ScannerOptionsBase,
    ReporterOptionsBase,
)
